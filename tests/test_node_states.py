"""Each node's state row and its agents' sign-ins and device-bound sessions:
ledger step 0030-node-states and the store tier's helpers that write and read
them."""

from __future__ import annotations

import time

import pytest

from capabilities_contract.capability import store as store_tier
from capabilities_contract.db import connect, disconnect, migrate

NODE = "0a0b0c0d0e0f"
OTHER = "0f0e0d0c0b0a"
AGENT = "prj_000000000001"
PEER = "prj_000000000002"
GONE = "prj_000000000003"


def _migrate(steps, major, minor):
    with connect(application_name="setup", transaction=True) as conn:
        result = migrate(conn, store_tier.STORE_OWNER, steps, major=major, minor=minor)
        conn.commit()
    disconnect()
    return result


@pytest.fixture()
def nodes(store):
    major, minor = store_tier.STORE_TABLES_VERSION
    _migrate(store_tier.record_table_steps(), major, minor)
    with connect(application_name="setup", transaction=True) as conn, conn.transaction():
        for node in (NODE, OTHER):
            conn.execute("INSERT INTO capabilities_nodes (id, label, kind)"
                         " VALUES (%s, %s, 'server')", (node, node))
        for agent in (AGENT, PEER, GONE):
            conn.execute("INSERT INTO capabilities_agents (id) VALUES (%s)", (agent,))
        for agent in (AGENT, PEER):
            conn.execute("INSERT INTO capabilities_agent_nodes (agent_id, node)"
                         " VALUES (%s, %s)", (agent, NODE))
    disconnect()
    return store


def _conn():
    return connect(application_name="test", transaction=True)


def test_a_store_at_the_last_step_takes_only_the_node_states_step(store):
    steps = store_tier.record_table_steps()
    assert steps[-1][0] == "0030-node-states"
    assert store_tier.STORE_TABLES_VERSION == (1, 15)
    _migrate(steps[:-1], 1, 14)
    result = _migrate(steps, *store_tier.STORE_TABLES_VERSION)
    assert result.applied == ["0030-node-states"]
    with _conn() as conn:
        for table in ("capabilities_node_states", "capabilities_node_logins",
                      "capabilities_node_sessions"):
            [(comment,)] = conn.execute("SELECT obj_description(to_regclass(%s))",
                                        (table,)).fetchall()
            assert comment
        uncommented = conn.execute(
            "SELECT a.attname FROM pg_attribute a WHERE a.attrelid = ANY (ARRAY["
            " to_regclass('capabilities_node_states'), to_regclass('capabilities_node_logins')])"
            " AND a.attnum > 0 AND col_description(a.attrelid, a.attnum) IS NULL").fetchall()
        assert uncommented == []


def test_a_node_writes_its_whole_row_and_reads_reachable_until_it_goes_stale(nodes):
    with _conn() as conn:
        with conn.transaction():
            first = store_tier.node_state_put(
                conn, NODE, load=(0.5, 0.25, 0.125), cpu_count=4,
                memory_used_bytes=1 << 30, memory_limit_bytes=3 << 30,
                disk_used_bytes=10 << 30, disk_total_bytes=70 << 30,
                booted_at="2026-10-27T00:00:00+00:00", boot_line="running agent x\n",
                image_version="0.0.12")
        assert (first["fresh_until"] - first["reported_at"]).total_seconds() == \
            store_tier.NODE_STATE_FRESH_SECONDS
        [row] = store_tier.node_states(conn, [NODE, OTHER])
    assert row["node"] == NODE and row["reachable"] is True
    assert (row["load_1"], row["load_15"], row["cpu_count"]) == (0.5, 0.125, 4)
    assert (row["memory_limit_bytes"], row["disk_total_bytes"]) == (3 << 30, 70 << 30)
    assert row["boot_line"] == "running agent x" and row["image_version"] == "0.0.12"
    assert row["uptime_seconds"] > 0

    # A write replaces the row whole.
    with _conn() as conn:
        with conn.transaction():
            store_tier.node_state_put(conn, NODE, cpu_count=2, fresh_seconds=0.5)
        time.sleep(1.0)
        [row] = store_tier.node_states(conn, [NODE])
        count = conn.execute("SELECT count(*) FROM capabilities_node_states").fetchone()[0]
    assert count == 1
    assert (row["cpu_count"], row["load_1"], row["boot_line"]) == (2, None, None)
    assert row["reachable"] is False


def test_each_agent_keeps_its_own_sign_ins_on_a_node(nodes):
    with _conn() as conn:
        with conn.transaction():
            store_tier.node_logins_put(conn, AGENT, NODE, {
                "claude": ("signed_in", "someone@example.test"),
                "codex": ("signed_out", "ignored"), "gh": ("absent", None)})
            store_tier.node_logins_put(conn, PEER, NODE, {
                "claude": ("signed_in", "another@example.test")})
        [mine] = store_tier.node_logins(conn, AGENT, [NODE, OTHER])
        [theirs] = store_tier.node_logins(conn, PEER, [NODE])
    assert (mine["claude_login"], mine["claude_account"]) == ("signed_in", "someone@example.test")
    assert (mine["codex_login"], mine["codex_account"]) == ("signed_out", None)
    assert (mine["gh_login"], mine["gh_account"]) == ("absent", None)
    assert mine["checked_at"] is not None
    # A write replaces the agent's row whole; a tool it leaves out is unknown.
    assert (theirs["claude_account"], theirs["gh_login"]) == ("another@example.test", "unknown")
    with _conn() as conn:
        with conn.transaction():
            store_tier.node_logins_put(conn, AGENT, NODE, {})
        [mine] = store_tier.node_logins(conn, AGENT, [NODE])
        [theirs] = store_tier.node_logins(conn, PEER, [NODE])
    assert (mine["claude_login"], mine["claude_account"]) == ("unknown", None)
    assert theirs["claude_account"] == "another@example.test"


def test_the_helper_and_the_store_refuse_what_the_row_cannot_say(nodes):
    with _conn() as conn:
        for bad in ({"load": (1.0, 2.0)}, {"fresh_seconds": 0}):
            with pytest.raises(store_tier.StoreError) as raised:
                store_tier.node_state_put(conn, NODE, **bad)
            assert raised.value.slug == "bad_state"
        for bad in ({"claude": ("logged_in", None)}, {"vim": ("signed_in", None)}):
            with pytest.raises(store_tier.StoreError) as raised:
                store_tier.node_logins_put(conn, AGENT, NODE, bad)
            assert raised.value.slug == "bad_state"
    import psycopg
    for column, value in (("load_1", -1), ("cpu_count", 0), ("memory_limit_bytes", 0),
                          ("boot_line", ""), ("image_version", "")):
        with _conn() as conn, pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(f"INSERT INTO capabilities_node_states (node, fresh_until, {column})"
                         " VALUES (%s, now() + interval '1 minute', %s)", (NODE, value))
    for column, value in (("claude_login", "logged_in"), ("gh_login", ""),
                          ("codex_account", "x")):
        with _conn() as conn, pytest.raises(psycopg.errors.CheckViolation):
            conn.execute(f"INSERT INTO capabilities_node_logins (project_id, node, {column})"
                         " VALUES (%s, %s, %s)", (AGENT, NODE, value))
    with _conn() as conn, pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("INSERT INTO capabilities_node_states (node, fresh_until)"
                     " VALUES (%s, now() - interval '1 second')", (NODE,))
    with _conn() as conn, pytest.raises(psycopg.errors.ForeignKeyViolation):
        conn.execute("INSERT INTO capabilities_node_states (node, fresh_until)"
                     " VALUES ('nowhere', now() + interval '1 minute')")
    with _conn() as conn, pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("INSERT INTO capabilities_node_sessions (project_id, node, capability,"
                     " connection, live) VALUES ('', %s, 'whatsapp', 'main', true)", (NODE,))


def test_a_write_replaces_one_capabilitys_sessions_and_a_prune_drops_only_its_own(nodes):
    with _conn() as conn:
        with conn.transaction():
            store_tier.node_sessions_put(conn, AGENT, NODE, "whatsapp",
                                         [("main", True, "+10000000000"), ("spare", False, None)])
            store_tier.node_sessions_put(conn, AGENT, NODE, "telegram", [("main", True, None)])
            store_tier.node_sessions_put(conn, PEER, NODE, "whatsapp", [("main", True, None)])
            store_tier.node_sessions_put(conn, GONE, NODE, "whatsapp", [("main", True, None)])
            for agent in (AGENT, PEER, GONE):
                store_tier.node_logins_put(conn, agent, NODE, {})
        rows = store_tier.node_sessions(conn, AGENT, [NODE])
    assert [(r["capability"], r["connection"], r["live"], r["account"]) for r in rows] == [
        ("telegram", "main", True, None), ("whatsapp", "main", True, "+10000000000"),
        ("whatsapp", "spare", False, None)]
    with _conn() as conn:
        with conn.transaction():
            store_tier.node_sessions_put(conn, AGENT, NODE, "whatsapp", [("main", False, None)])
            gone = store_tier.node_agents_prune(conn, NODE, [AGENT], [(AGENT, "whatsapp")])
        # This agent's telegram, and the unlinked agent's session and sign-ins;
        # the other agent linked here is another manager's and keeps its own.
        assert gone == 3
        rows = store_tier.node_sessions(conn, AGENT, [NODE, OTHER])
        peer = store_tier.node_sessions(conn, PEER, [NODE])
        assert store_tier.node_sessions(conn, GONE, [NODE]) == []
        assert [r["node"] for r in store_tier.node_logins(conn, PEER, [NODE])] == [NODE]
        assert store_tier.node_logins(conn, GONE, [NODE]) == []
    assert [(r["capability"], r["connection"], r["live"]) for r in rows] == [
        ("whatsapp", "main", False)]
    assert [(r["capability"], r["live"]) for r in peer] == [("whatsapp", True)]


def test_both_tables_follow_the_registry_id_and_go_with_the_node(nodes):
    with _conn() as conn:
        with conn.transaction():
            store_tier.node_state_put(conn, NODE, cpu_count=1)
            store_tier.node_logins_put(conn, AGENT, NODE, {})
            store_tier.node_sessions_put(conn, AGENT, NODE, "whatsapp", [("main", True, None)])
            conn.execute("UPDATE capabilities_nodes SET id = 'aaaaaaaaaaaa' WHERE id = %s",
                         (NODE,))
        assert [r["node"] for r in store_tier.node_states(conn, ["aaaaaaaaaaaa"])] == [
            "aaaaaaaaaaaa"]
        assert [r["node"] for r in store_tier.node_logins(conn, AGENT, ["aaaaaaaaaaaa"])] == [
            "aaaaaaaaaaaa"]
        assert [r["node"] for r in store_tier.node_sessions(conn, AGENT, ["aaaaaaaaaaaa"])] \
            == ["aaaaaaaaaaaa"]
        with conn.transaction():
            conn.execute("DELETE FROM capabilities_nodes WHERE id = 'aaaaaaaaaaaa'")
        assert conn.execute("SELECT (SELECT count(*) FROM capabilities_node_states)"
                            " + (SELECT count(*) FROM capabilities_node_logins)"
                            " + (SELECT count(*) FROM capabilities_node_sessions)"
                            ).fetchone()[0] == 0
