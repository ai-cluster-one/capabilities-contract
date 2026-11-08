"""The core's step 0041-keys: every core agent and node column a foreign key in
its class, ids that never change, a parent deleted only on purpose, history
guards that admit that cascade and nothing else, and a reference to a missing
agent or node settled by its class with its pre-image."""

from __future__ import annotations

import psycopg
import pytest

from capabilities_contract.db import UPGRADE_ENV, _migrate, connect, deleting, migrate

AGENT, OTHER = "aaaaaaaaaaaa", "bbbbbbbbbbbb"
NODE, GONE_NODE = "111111111111", "b38021200000"
GONE_AGENT = "cccccccccccc"
CORE_3 = _migrate.CORE_STEPS[:2]


@pytest.fixture()
def conn(store):
    """A connection to the test's schema, closed before the schema is dropped."""
    found = connect(application_name="capabilities-contract-tests")
    yield found
    found.close()


def _seed(conn):
    with conn.transaction():
        conn.execute("INSERT INTO agents (id, kind) VALUES (%s, 'agent'), (%s, 'agent')",
                     (AGENT, OTHER))
        conn.execute("INSERT INTO nodes (id, label, kind) VALUES (%s, 'n1', 'mac')", (NODE,))
        conn.execute("INSERT INTO agent_nodes (agent_id, node) VALUES (%s, %s)", (AGENT, NODE))


def _refused(conn, *statements):
    with pytest.raises(psycopg.Error) as caught:
        with conn.transaction():
            for statement in statements:
                conn.execute(statement)
    return str(caught.value)


def test_no_key_cascades_an_update_and_every_core_reference_is_keyed(conn):
    migrate(conn, "core", _migrate.CORE_STEPS, major=4, minor=0)
    keys = {(t, c): (d, u) for t, c, d, u in conn.execute(
        "SELECT k.conrelid::regclass::text, a.attname, k.confdeltype, k.confupdtype "
        "FROM pg_constraint k JOIN pg_attribute a ON a.attrelid = k.conrelid "
        "AND a.attnum = k.conkey[1] WHERE k.contype = 'f' "
        "AND k.connamespace = current_schema()::regnamespace").fetchall()}
    assert all(update == "a" for _delete, update in keys.values())
    assert keys[("policies", "agent_id")][0] == "c"
    assert keys[("policies", "node")][0] == "c"
    assert keys[("agent_nodes", "node")][0] == "c"
    assert keys[("settings_changes", "node")][0] == "n"
    assert not conn.execute("SELECT count(*) FROM pg_constraint WHERE contype = 'f' "
                            "AND NOT convalidated").fetchone()[0]


def test_an_id_never_changes_and_a_parent_goes_only_when_named(conn):
    migrate(conn, "core", _migrate.CORE_STEPS, major=4, minor=0)
    _seed(conn)
    assert "keeps its id" in _refused(conn, f"UPDATE agents SET id = 'dddddddddddd' "
                                            f"WHERE id = '{OTHER}'")
    assert "keeps its id" in _refused(conn, f"UPDATE nodes SET id = '222222222222' "
                                            f"WHERE id = '{NODE}'")
    assert "store.deleting_agent" in _refused(conn, f"DELETE FROM agents WHERE id = '{OTHER}'")
    assert "store.deleting_node" in _refused(conn, f"DELETE FROM nodes WHERE id = '{NODE}'")
    # A setting naming another row admits nothing.
    with pytest.raises(psycopg.Error):
        with conn.transaction():
            deleting(conn, "agents", OTHER)
            conn.execute("DELETE FROM agents WHERE id = %s", (AGENT,))
    with conn.transaction():
        conn.execute("INSERT INTO connections (id, capability, label, owner_agent_id, spec) "
                     "VALUES ('c0c0c0c0c0c0', 'demo', 'mine', %s, '{}')", (AGENT,))
        conn.execute("INSERT INTO grants (agent_id, capability, connection_id) "
                     "VALUES (%s, 'demo', 'c0c0c0c0c0c0')", (AGENT,))
        conn.execute("INSERT INTO policies (agent_id, capability, node, enabled) "
                     "VALUES (%s, 'demo', %s, true)", (AGENT, NODE))
    assert "store.deleting_connection" in _refused(
        conn, "DELETE FROM connections WHERE id = 'c0c0c0c0c0c0'")
    # The agent named: its links, policy, its own connection and that
    # connection's grant go with it.
    with conn.transaction():
        deleting(conn, "agents", AGENT)
        conn.execute("DELETE FROM agents WHERE id = %s", (AGENT,))
    assert conn.execute("SELECT (SELECT count(*) FROM agent_nodes), (SELECT count(*) FROM "
                        "policies), (SELECT count(*) FROM connections), (SELECT count(*) "
                        "FROM grants)").fetchone() == (0, 0, 0, 0)


def test_a_history_guard_admits_the_cascade_and_nothing_else(conn):
    migrate(conn, "core", _migrate.CORE_STEPS, major=4, minor=0)
    _seed(conn)
    with conn.transaction():
        conn.execute("INSERT INTO nodes (id, label, kind) VALUES ('222222222222', 'n2', 'mac')")
        conn.execute("INSERT INTO settings_changes (agent_id, capability, node, action, path, "
                     "changed_by) VALUES (%s, 'demo', '222222222222', 'set', ARRAY['a'], 'me')",
                     (AGENT,))
    statement = "UPDATE settings_changes SET node = NULL"
    assert "append-only" in _refused(conn, statement)
    with pytest.raises(psycopg.Error, match="append-only"):
        with conn.transaction():
            deleting(conn, "nodes", "222222222222")
            conn.execute("DELETE FROM settings_changes")
    with conn.transaction():
        deleting(conn, "nodes", "222222222222")
        conn.execute("DELETE FROM nodes WHERE id = '222222222222'")
    assert conn.execute("SELECT agent_id, node FROM settings_changes").fetchall() == [
        (AGENT, None)]


def test_the_step_settles_what_names_a_missing_agent_or_node(conn, monkeypatch):
    with monkeypatch.context() as patched:
        patched.setattr(_migrate, "CORE_STEPS", CORE_3)
        patched.setattr(_migrate, "CORE_VERSION", (3, 0))
        migrate(conn, "core", CORE_3, major=3, minor=0)
    _seed(conn)
    with conn.transaction():
        conn.execute("INSERT INTO policies (agent_id, capability, node, enabled) VALUES "
                     "(%s, 'kept', %s, true), (%s, 'gone_node', %s, true), "
                     "(%s, 'gone_agent', NULL, true)",
                     (AGENT, NODE, AGENT, GONE_NODE, GONE_AGENT))
        conn.execute("INSERT INTO settings_changes (agent_id, capability, node, action, path, "
                     "changed_by) VALUES (%s, 'demo', %s, 'set', ARRAY['a'], 'me')",
                     (AGENT, GONE_NODE))
        conn.execute("INSERT INTO connections (id, capability, label, owner_agent_id, spec) "
                     "VALUES ('c1c1c1c1c1c1', 'demo', 'orphan', %s, '{}')", (GONE_AGENT,))
        conn.execute("INSERT INTO grants (agent_id, capability, connection_id) "
                     "VALUES (%s, 'demo', 'c1c1c1c1c1c1')", (GONE_AGENT,))
    monkeypatch.setenv(UPGRADE_ENV, "1")
    migrate(conn, "core", _migrate.CORE_STEPS, major=4, minor=0)
    assert conn.execute("SELECT capability FROM policies").fetchall() == [("kept",)]
    assert conn.execute("SELECT node FROM settings_changes").fetchall() == [(None,)]
    saved = conn.execute("SELECT source, op FROM core_premig_m9 ORDER BY 1, 2").fetchall()
    assert saved == [("connections", "delete"), ("grants", "delete"), ("policies", "delete"),
                     ("policies", "delete"), ("settings_changes", "update")]
    assert conn.execute("SELECT row ->> 'node' FROM core_premig_m9 WHERE source = "
                        "'settings_changes'").fetchone() == (GONE_NODE,)
    assert not conn.execute("SELECT count(*) FROM pg_trigger "
                            "WHERE tgname = 'store_state_capture'").fetchone()[0]
    assert not conn.execute("SELECT count(*) FROM pg_constraint WHERE contype = 'f' "
                            "AND NOT convalidated").fetchone()[0]
