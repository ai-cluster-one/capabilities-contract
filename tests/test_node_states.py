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


def test_a_store_at_the_step_before_takes_the_node_states_step(store):
    steps = store_tier.record_table_steps()
    at = [step[0] for step in steps].index("0030-node-states")
    _migrate(steps[:at], 1, 14)
    result = _migrate(steps[:at + 1], 1, 15)
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


def test_a_store_at_the_node_states_step_takes_only_the_expectations_step(store):
    steps = store_tier.record_table_steps()
    at = [step[0] for step in steps].index("0031-node-expectations")
    _migrate(steps[:at], 1, 15)
    result = _migrate(steps[:at + 1], 1, 16)
    assert result.applied == ["0031-node-expectations"]
    with _conn() as conn:
        uncommented = conn.execute(
            "SELECT a.attrelid::regclass::text, a.attname FROM pg_attribute a"
            " WHERE a.attrelid = ANY (ARRAY["
            " to_regclass('capabilities_node_login_expectations'),"
            " to_regclass('capabilities_node_session_expectations'),"
            " to_regclass('capabilities_node_logins')])"
            " AND a.attnum > 0 AND NOT a.attisdropped"
            " AND col_description(a.attrelid, a.attnum) IS NULL").fetchall()
        assert uncommented == []


def test_a_sign_in_row_says_what_the_placed_services_need(nodes):
    with _conn() as conn:
        with conn.transaction():
            store_tier.node_logins_put(conn, AGENT, NODE, {}, needed=["claude", "gh"])
        [row] = store_tier.node_logins(conn, AGENT, [NODE])
        assert (row["claude_needed"], row["codex_needed"], row["gh_needed"]) == (
            True, False, True)
        with conn.transaction():
            store_tier.node_logins_put(conn, AGENT, NODE, {"gh": ("signed_out", None)})
        [row] = store_tier.node_logins(conn, AGENT, [NODE])
        assert (row["gh_login"], row["claude_needed"], row["gh_needed"]) == (
            "signed_out", True, True)
        with conn.transaction():
            store_tier.node_logins_put(conn, AGENT, NODE, {}, needed=[])
        [row] = store_tier.node_logins(conn, AGENT, [NODE])
        assert not (row["claude_needed"] or row["codex_needed"] or row["gh_needed"])
        with pytest.raises(store_tier.StoreError):
            store_tier.node_logins_put(conn, AGENT, NODE, {}, needed=["stub"])


def test_the_owners_word_is_set_changed_and_taken_back_per_agent_and_node(nodes):
    with _conn() as conn:
        with conn.transaction():
            on = store_tier.node_expectation_set(conn, AGENT, NODE, tool="gh",
                                                 expected=True, by="owner")
            again = store_tier.node_expectation_set(conn, AGENT, NODE, tool="gh",
                                                    expected=True)
            off = store_tier.node_expectation_set(conn, AGENT, NODE, capability="whatsapp",
                                                  connection="main", expected=False)
            store_tier.node_expectation_set(conn, PEER, NODE, tool="claude", expected=False)
        assert (on, again["changed"], off["before"]) == (
            {"before": None, "after": True, "changed": True}, False, None)
        mine = store_tier.node_expectations(conn, AGENT, [NODE, OTHER])
        assert [(r["node"], r["tool"], r["expected"], r["updated_by"])
                for r in mine["sign_ins"]] == [(NODE, "gh", True, "owner")]
        assert [(r["capability"], r["connection"], r["expected"])
                for r in mine["sessions"]] == [("whatsapp", "main", False)]
        with conn.transaction():
            back = store_tier.node_expectation_set(conn, AGENT, NODE, tool="gh", expected=None)
            none = store_tier.node_expectation_set(conn, AGENT, NODE, tool="codex",
                                                   expected=None)
        assert (back["before"], back["changed"], none["changed"]) == (True, True, False)
        assert store_tier.node_expectations(conn, AGENT, [NODE])["sign_ins"] == []
        for bad in ({"tool": "stub"}, {"tool": "gh", "capability": "whatsapp"},
                    {"capability": "whatsapp"}):
            with pytest.raises(store_tier.StoreError):
                store_tier.node_expectation_set(conn, AGENT, NODE, expected=True, **bad)


def test_the_owners_words_follow_the_registry_id_and_go_with_the_node(nodes):
    with _conn() as conn:
        with conn.transaction():
            store_tier.node_expectation_set(conn, AGENT, NODE, tool="gh", expected=True)
            store_tier.node_expectation_set(conn, AGENT, NODE, capability="telegram",
                                            connection="main", expected=True)
            conn.execute("UPDATE capabilities_nodes SET id = 'aaaaaaaaaaaa' WHERE id = %s",
                         (NODE,))
        moved = store_tier.node_expectations(conn, AGENT, ["aaaaaaaaaaaa"])
        assert [len(moved["sign_ins"]), len(moved["sessions"])] == [1, 1]
        with conn.transaction():
            conn.execute("DELETE FROM capabilities_nodes WHERE id = 'aaaaaaaaaaaa'")
        assert conn.execute(
            "SELECT (SELECT count(*) FROM capabilities_node_login_expectations)"
            " + (SELECT count(*) FROM capabilities_node_session_expectations)"
            ).fetchone()[0] == 0


def test_a_store_at_the_expectations_step_takes_only_the_updates_step(store):
    steps = store_tier.record_table_steps()
    at = [step[0] for step in steps].index("0032-node-updates")
    _migrate(steps[:at], 1, 16)
    result = _migrate(steps[:at + 1], 1, 17)
    assert result.applied == ["0032-node-updates"]
    with _conn() as conn:
        [(comment,)] = conn.execute("SELECT obj_description("
                                    "to_regclass('capabilities_node_updates'))").fetchall()
        assert comment
        uncommented = conn.execute(
            "SELECT a.attrelid::regclass::text, a.attname FROM pg_attribute a"
            " WHERE a.attrelid = ANY (ARRAY[to_regclass('capabilities_node_updates'),"
            " to_regclass('capabilities_node_states')])"
            " AND a.attnum > 0 AND NOT a.attisdropped"
            " AND col_description(a.attrelid, a.attnum) IS NULL").fetchall()
        assert uncommented == []


def _channel(conn, node: str) -> int:
    found = conn.execute("SELECT version FROM schema_channel WHERE channel = %s"
                         " AND scope = %s", (store_tier.NODE_UPDATE_CHANNEL, node)).fetchone()
    return found[0] if found else 0


def test_a_nodes_update_availability_stays_through_its_state_writes(nodes):
    offer = {"components": [{"kind": "manager", "installed": "a", "available": "b"}]}
    with _conn() as conn:
        with conn.transaction():
            assert store_tier.node_update_offer_put(conn, NODE, available=True,
                                                    offer=offer) is None
            store_tier.node_state_put(conn, NODE, cpu_count=2)
        [row] = store_tier.node_states(conn, [NODE])
        assert (row["update_available"], row["update_offer"], row["update_checked_at"]) == (
            None, None, None)
        with conn.transaction():
            said = store_tier.node_update_offer_put(conn, NODE, available=True, offer=offer)
            store_tier.node_state_put(conn, NODE, cpu_count=4)
        [row] = store_tier.node_states(conn, [NODE])
        assert (row["cpu_count"], row["update_available"], row["update_offer"]) == (
            4, True, offer)
        assert row["update_checked_at"] == said["update_checked_at"]
        with pytest.raises(store_tier.StoreError):
            store_tier.node_update_offer_put(conn, NODE, available="yes")


def test_an_update_run_is_asked_taken_up_and_ended_one_at_a_time_per_node(nodes):
    import psycopg
    with _conn() as conn:
        start = _channel(conn, NODE)
        with conn.transaction():
            asked = store_tier.node_update_request(conn, NODE, by="owner@desk")
        assert (asked["state"], asked["requested_by"], asked["started_at"]) == (
            "requested", "owner@desk", None)
        assert _channel(conn, NODE) == start + 1
        with pytest.raises(store_tier.StoreError) as refused, conn.transaction():
            store_tier.node_update_request(conn, NODE)
        assert refused.value.slug == "update_pending"
        with pytest.raises(psycopg.errors.UniqueViolation), conn.transaction():
            conn.execute("INSERT INTO capabilities_node_updates (node) VALUES (%s)", (NODE,))
        with conn.transaction():
            store_tier.node_update_request(conn, OTHER)
        with conn.transaction():
            taken = store_tier.node_update_claim(conn, NODE, by="node")
        assert taken["interrupted"] == [] and taken["run"]["id"] == asked["id"]
        assert taken["run"]["state"] == "running" and taken["run"]["started_at"]
        assert _channel(conn, NODE) == start + 2
        with pytest.raises(store_tier.StoreError), conn.transaction():
            store_tier.node_update_finish(conn, asked["id"], state="rolled_back")
        with pytest.raises(store_tier.StoreError), conn.transaction():
            store_tier.node_update_finish(conn, asked["id"], state="running")
        with conn.transaction():
            done = store_tier.node_update_finish(
                conn, asked["id"], state="rolled_back", reason="doctor of x: red\n",
                versions_before={"manager": "a"}, versions_after={"manager": "a"},
                doctors={"after_update": [{"capability": "x", "state": "unusable"}]})
        assert (done["state"], done["reason"], done["versions_before"]) == (
            "rolled_back", "doctor of x: red", {"manager": "a"})
        assert done["finished_at"] is not None
        with conn.transaction():
            assert store_tier.node_update_finish(conn, asked["id"], state="updated") is None
        # With none requested, the node's own run makes its row; a run left
        # running is closed as interrupted by the next.
        with conn.transaction():
            mine = store_tier.node_update_claim(conn, NODE)["run"]
        assert mine["id"] != asked["id"] and mine["state"] == "running"
        with conn.transaction():
            later = store_tier.node_update_claim(conn, NODE)
        assert later["interrupted"] == [mine["id"]]
        [last] = store_tier.node_updates(conn, [NODE])
        assert last["id"] == later["run"]["id"] and last["state"] == "running"
        [(state, reason)] = conn.execute(
            "SELECT state, reason FROM capabilities_node_updates WHERE id = %s",
            (mine["id"],)).fetchall()
        assert state == "failed" and reason.startswith("interrupted")
        assert {r["node"] for r in store_tier.node_updates(conn, [NODE, OTHER])} == {
            NODE, OTHER}
        # The runs follow the registry's id and go with the node.
        with conn.transaction():
            conn.execute("UPDATE capabilities_nodes SET id = 'aaaaaaaaaaaa' WHERE id = %s",
                         (NODE,))
        assert [r["state"] for r in store_tier.node_updates(conn, ["aaaaaaaaaaaa"])] == [
            "running"]
        with conn.transaction():
            conn.execute("DELETE FROM capabilities_nodes WHERE id = 'aaaaaaaaaaaa'")
        assert conn.execute("SELECT count(*) FROM capabilities_node_updates"
                            " WHERE node <> %s", (OTHER,)).fetchone()[0] == 0


def test_a_store_at_the_updates_step_takes_only_the_logs_step(store):
    steps = store_tier.record_table_steps()
    at = [step[0] for step in steps].index("0033-node-logs")
    _migrate(steps[:at], 1, 17)
    result = _migrate(steps[:at + 1], 1, 18)
    assert result.applied == ["0033-node-logs"]
    with _conn() as conn:
        [(comment,)] = conn.execute("SELECT obj_description("
                                    "to_regclass('capabilities_node_logs'))").fetchall()
        assert comment
        uncommented = conn.execute(
            "SELECT a.attname FROM pg_attribute a"
            " WHERE a.attrelid = to_regclass('capabilities_node_logs')"
            " AND a.attnum > 0 AND NOT a.attisdropped"
            " AND col_description(a.attrelid, a.attnum) IS NULL").fetchall()
        assert uncommented == []


def test_a_sources_last_lines_are_kept_bounded_and_without_secrets(nodes):
    lines = [f"line {n}" for n in range(store_tier.NODE_LOG_LINES + 20)]
    lines[-1] = "x" * (store_tier.NODE_LOG_LINE_CHARS + 50)
    lines[-2] = "cannot reach postgresql://agent:hunter2pass@db:5432/agent"
    lines[-3] = ("export TELEGRAM_BOT_TOKEN=123456:AAbbCCdd"
                 " and Authorization: Bearer abcdef0123456789")
    lines[-4] = "said the one value it holds: plainvalue-77 and a key sk-ant-api03-abcdefghijklmnop"
    lines[-5] = "two\nlines"
    with _conn() as conn:
        with conn.transaction():
            wrote = store_tier.node_log_put(conn, AGENT, NODE, "telegram", lines,
                                            secrets=["plainvalue-77"])
            store_tier.node_log_put(conn, AGENT, NODE, store_tier.NODE_LOG_MANAGER,
                                    ["[capabilities node] reconciled"])
        assert wrote["lines"] == store_tier.NODE_LOG_LINES
        rows = store_tier.node_logs(conn, AGENT, [NODE, OTHER])
        assert [(r["node"], r["source"]) for r in rows] == [(NODE, "manager"),
                                                             (NODE, "telegram")]
        kept = rows[1]["lines"]
        assert len(kept) == store_tier.NODE_LOG_LINES and kept[0] == "line 20"
        assert len(kept[-1]) == store_tier.NODE_LOG_LINE_CHARS
        assert kept[-5] == "two lines"
        text = "\n".join(kept)
        for secret in ("hunter2pass", "123456:AAbbCCdd", "abcdef0123456789", "plainvalue-77",
                       "sk-ant-api03"):
            assert secret not in text
        assert "postgresql://agent:***@db:5432/agent" in text
        # A later write replaces the source's lines; another agent sees none of them.
        with conn.transaction():
            store_tier.node_log_put(conn, AGENT, NODE, "telegram", ["restarted"])
        assert [r["lines"] for r in store_tier.node_logs(conn, AGENT, [NODE])] == [
            ["[capabilities node] reconciled"], ["restarted"]]
        assert store_tier.node_logs(conn, PEER, [NODE]) == []
        with pytest.raises(store_tier.StoreError):
            store_tier.node_log_put(conn, AGENT, NODE, "Not A Source", ["x"])


def test_log_lines_go_with_their_service_their_agents_link_and_their_node(nodes):
    with _conn() as conn:
        with conn.transaction():
            for agent in (AGENT, PEER, GONE):
                for source in ("manager", "telegram", "tasks"):
                    store_tier.node_log_put(conn, agent, NODE, source, ["said"])
            store_tier.node_log_put(conn, AGENT, OTHER, "tasks", ["said"])
        with conn.transaction():
            assert store_tier.node_logs_prune(conn, AGENT, NODE, ["manager", "tasks"]) == 1
        assert [r["source"] for r in store_tier.node_logs(conn, AGENT, [NODE])] == [
            "manager", "tasks"]
        # An agent no longer linked to the node loses its lines there; a linked
        # agent another manager writes for keeps its own.
        with conn.transaction():
            store_tier.node_agents_prune(conn, NODE, [AGENT], [])
        assert store_tier.node_logs(conn, GONE, [NODE]) == []
        assert len(store_tier.node_logs(conn, PEER, [NODE])) == 3
        with conn.transaction():
            conn.execute("UPDATE capabilities_nodes SET id = 'aaaaaaaaaaaa' WHERE id = %s",
                         (OTHER,))
        assert [r["node"] for r in store_tier.node_logs(conn, AGENT, ["aaaaaaaaaaaa"])] == [
            "aaaaaaaaaaaa"]
        with conn.transaction():
            conn.execute("DELETE FROM capabilities_nodes WHERE id = 'aaaaaaaaaaaa'")
        assert store_tier.node_logs(conn, AGENT, ["aaaaaaaaaaaa"]) == []


def test_a_store_at_the_logs_step_takes_only_the_session_reasons_step(store):
    steps = store_tier.record_table_steps()
    at = [step[0] for step in steps].index("0034-node-session-reasons")
    _migrate(steps[:at], 1, 18)
    result = _migrate(steps[:at + 1], 1, 19)
    assert result.applied == ["0034-node-session-reasons"]
    with _conn() as conn:
        uncommented = conn.execute(
            "SELECT a.attname FROM pg_attribute a"
            " WHERE a.attrelid = to_regclass('capabilities_node_sessions')"
            " AND a.attnum > 0 AND NOT a.attisdropped"
            " AND col_description(a.attrelid, a.attnum) IS NULL").fetchall()
    assert {"reason", "reason_keys"}.isdisjoint(name for (name,) in uncommented)


def test_a_session_that_is_down_says_why_and_a_row_without_a_reason_reads_as_before(nodes):
    with _conn() as conn:
        with conn.transaction():
            store_tier.node_sessions_put(conn, AGENT, NODE, "telegram", [
                ("personal", False, None, "key_missing", ["TELEGRAM_API_HASH"]),
                ("spare", False, None, "not_signed_in", None),
                ("third", False, None, "session_missing", None),
                ("work", True, "100", None, None)])
            store_tier.node_sessions_put(conn, AGENT, NODE, "whatsapp", [("main", False, None)])
        rows = store_tier.node_sessions(conn, AGENT, [NODE])
    assert [(r["capability"], r["connection"], r["live"], r["account"], r["reason"],
             r["reason_keys"]) for r in rows] == [
        ("telegram", "personal", False, None, "key_missing", ["TELEGRAM_API_HASH"]),
        ("telegram", "spare", False, None, "not_signed_in", None),
        ("telegram", "third", False, None, "session_missing", None),
        ("telegram", "work", True, "100", None, None),
        ("whatsapp", "main", False, None, None, None)]
    for bad in (("main", True, None, "not_signed_in", None),
                ("main", False, None, "logged_out", None),
                ("main", False, None, "key_missing", None),
                ("main", False, None, "not_signed_in", ["TELEGRAM_API_HASH"])):
        with _conn() as conn, pytest.raises(store_tier.StoreError) as raised:
            store_tier.node_sessions_put(conn, AGENT, NODE, "telegram", [bad])
        assert raised.value.slug == "bad_state"
    import psycopg
    for live, reason, keys in ((True, "not_signed_in", None), (False, "logged_out", None),
                               (False, "key_missing", None), (False, "key_missing", []),
                               (False, "key_missing", [""]),
                               (False, "not_signed_in", ["TELEGRAM_API_HASH"])):
        with _conn() as conn, pytest.raises(psycopg.errors.CheckViolation):
            conn.execute("INSERT INTO capabilities_node_sessions (project_id, node,"
                         " capability, connection, live, reason, reason_keys)"
                         " VALUES (%s, %s, 'telegram', 'main', %s, %s, %s)",
                         (AGENT, NODE, live, reason, keys))


def test_a_store_at_the_session_reasons_step_takes_only_the_node_disabled_step(store):
    steps = store_tier.record_table_steps()
    at = [step[0] for step in steps].index("0035-node-disabled")
    _migrate(steps[:at], 1, 19)
    result = _migrate(steps[:at + 1], 1, 20)
    assert result.applied == ["0035-node-disabled"]
    with _conn() as conn:
        [(comment,)] = conn.execute(
            "SELECT col_description(to_regclass('capabilities_nodes'), a.attnum)"
            " FROM pg_attribute a WHERE a.attrelid = to_regclass('capabilities_nodes')"
            " AND a.attname = 'disabled_at'").fetchall()
    assert comment


def test_nothing_is_placed_on_a_disabled_node_and_what_is_there_can_be_taken_off(nodes):
    def policy(conn, node, enabled):
        store_tier._upsert_policy(conn, AGENT, "tasks", node, enabled)

    with _conn() as conn, conn.transaction():
        conn.execute("UPDATE capabilities_nodes SET disabled_at = now() WHERE id = %s",
                     (NODE,))
    refused = pytest.raises(store_tier.StoreError)
    with _conn() as conn, refused as raised, conn.transaction():
        policy(conn, NODE, True)
    assert raised.value.slug == "node_disabled"
    assert "capabilities node enable" in raised.value.hint
    with _conn() as conn:
        with conn.transaction():
            policy(conn, NODE, False)
            policy(conn, OTHER, True)
        rows = conn.execute("SELECT node, enabled, service FROM capabilities_policy"
                            " WHERE agent_id = %s ORDER BY node", (AGENT,)).fetchall()
    assert rows == [(NODE, False, False), (OTHER, True, True)]
    with _conn() as conn, conn.transaction():
        conn.execute("UPDATE capabilities_nodes SET disabled_at = NULL WHERE id = %s",
                     (NODE,))
    with _conn() as conn, conn.transaction():
        policy(conn, NODE, True)
