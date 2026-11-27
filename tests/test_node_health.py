"""The core's step 0047-node-health: each agent's health on each of its nodes
is read through the view `agent_nodes_health`, which holds the colour rule;
every change of state of a node's sign-ins, sessions and services is
announced on `agent_nodes_health`, and a rewrite of the same state
never is; a service names the settings it takes only on a start; and an exit
for refused credentials records the connection it resolved as not signed in
on this node. A minor step, applied outside the store upgrade, that a reader
of core 4.5 still reads."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import NoReturn

import pytest

from capabilities_contract.capability import bind
from capabilities_contract.capability import store as S
from capabilities_contract.db import _migrate, connect, disconnect, migrate

CORE_4_5 = _migrate.CORE_STEPS[:8]
AGENT = "prj_00000000a001"
NODE = "00000000ee01"
OTHER = "00000000ee02"


@pytest.fixture
def excepthook():
    saved = sys.excepthook
    yield
    sys.excepthook = saved


def _core(steps=None, minor=6):
    with connect(application_name="setup", transaction=True) as conn:
        result = migrate(conn, "core", steps or _migrate.CORE_STEPS, major=4, minor=minor)
        conn.commit()
    disconnect()
    return result


def _sql(query: str, params: tuple = ()):
    with connect(application_name="capabilities-contract-tests") as conn:
        cursor = conn.execute(query, params)
        rows = cursor.fetchall() if cursor.description else None
        conn.commit()
        return rows


def _agent_on(*nodes: str) -> None:
    _sql("INSERT INTO agents (id, name) VALUES (%s, 'a') ON CONFLICT DO NOTHING", (AGENT,))
    for node in nodes:
        _sql("INSERT INTO nodes (id, label, kind) VALUES (%s, %s, 'server')", (node, node))
        _sql("INSERT INTO agent_nodes (agent_id, node) VALUES (%s, %s)", (AGENT, node))


def _health(node: str = NODE) -> dict:
    with connect(application_name="test", transaction=True) as conn:
        [row] = S.node_health(conn, AGENT, [node])
        conn.rollback()
    return row


def _items(row: dict) -> list:
    return [(i["kind"], i["level"], i["action"], i["reason"]) for i in row["items"]]


def _reported(node: str = NODE, **facts) -> None:
    with connect(application_name="test", transaction=True) as conn, conn.transaction():
        S.node_state_put(conn, node, **facts)


def test_a_store_at_core_4_5_takes_the_step_without_the_upgrade_and_a_4_5_reader_reads_it(
        store, monkeypatch):
    _core(CORE_4_5, 5)
    _agent_on(NODE)
    _sql("INSERT INTO service_instances (agent_id, capability, node, state) "
         "VALUES (%s, 'demo', %s, 'ready')", (AGENT, NODE))
    monkeypatch.delenv(_migrate.UPGRADE_ENV, raising=False)
    result = _core()
    assert result.applied == ["0047-node-health"]
    assert (result.major, result.minor) == (4, 6) == _migrate.CORE_VERSION
    assert S.STORE_TABLES_VERSION == (4, 6)
    assert _sql("SELECT restart_settings FROM service_instances") == [(None,)]
    [(view, column)] = _sql(
        "SELECT obj_description('agent_nodes_health'::regclass, 'pg_class'), "
        "col_description('service_instances'::regclass, a.attnum) FROM pg_attribute a "
        "WHERE a.attrelid = 'service_instances'::regclass AND a.attname = 'restart_settings'")
    assert "colour rule" in view and "restart" in column
    # A reader that knows core 4.5 settles on the store at 4.6, with a warning,
    # and writes what it wrote before.
    with monkeypatch.context() as patched:
        patched.setattr(_migrate, "CORE_STEPS", CORE_4_5)
        patched.setattr(_migrate, "CORE_VERSION", (4, 5))
        older = _core(CORE_4_5, 5)
    assert older.applied == [] and (older.major, older.minor) == (4, 5 + 1)
    assert any("newer minor" in warning for warning in older.warnings)
    _sql("INSERT INTO service_instances AS i (agent_id, capability, node, state, problem) "
         "VALUES (%s, 'demo', %s, 'unusable', 'p') ON CONFLICT (agent_id, capability, node) "
         "DO UPDATE SET state = EXCLUDED.state, problem = EXCLUDED.problem", (AGENT, NODE))
    assert _sql("SELECT state FROM service_instances") == [("unusable",)]


def test_the_view_says_each_node_s_colour_and_what_needs_action_with_when_it_was_checked(
        store):
    _core()
    _agent_on(NODE, OTHER)
    # Never reported: red, as a node silent past its fresh_until is.
    row = _health()
    assert (row["health"], row["reachable"], _items(row)) == (
        "red", False, [("node", "red", "restart_node", "not_reported")])
    _reported(memory_used_bytes=10, memory_limit_bytes=100)
    row = _health()
    assert (row["health"], row["reachable"], row["items"]) == ("green", True, [])
    _reported(fresh_seconds=0.001)
    row = _health()
    assert (row["health"], _items(row)) == ("red", [("node", "red", "restart_node", "silent")])
    assert datetime.fromisoformat(row["items"][0]["checked_at"]) == row["reported_at"]

    # Memory or disk nearly full, and an update not taken: yellow.
    _reported(memory_used_bytes=95, memory_limit_bytes=100, disk_used_bytes=9,
              disk_total_bytes=10)
    with connect(application_name="test", transaction=True) as conn, conn.transaction():
        S.node_update_offer_put(conn, NODE, available=True, offer={"to": "x"})
    row = _health()
    assert (row["health"], _items(row)) == ("yellow", [
        ("node", "yellow", "update", "behind"),
        ("node", "yellow", "free_memory", "memory_nearly_full"),
        ("node", "yellow", "free_disk", "disk_nearly_full")])
    _reported()
    with connect(application_name="test", transaction=True) as conn, conn.transaction():
        S.node_update_offer_put(conn, NODE, available=False)

    # The sign-ins the placed services need: Claude or Codex gone is red, the
    # GitHub CLI yellow; one not needed raises nothing, and the owner's word
    # stands over the need.
    with connect(application_name="test", transaction=True) as conn, conn.transaction():
        S.node_logins_put(conn, AGENT, NODE, {"claude": ("signed_in", "a@example.test"),
                                              "codex": ("absent", None),
                                              "gh": ("signed_out", None)},
                          needed=["claude", "gh"])
    row = _health()
    assert (row["health"], _items(row)) == ("yellow", [
        ("sign_in", "yellow", "sign_in", "signed_out")])
    assert [(s["tool"], s["needed"], s["override"], s["expected"])
            for s in row["sign_ins"]] == [("claude", True, None, True),
                                          ("codex", False, None, False),
                                          ("gh", True, None, True)]
    with connect(application_name="test", transaction=True) as conn, conn.transaction():
        S.node_expectation_set(conn, AGENT, NODE, tool="codex", expected=True)
        S.node_expectation_set(conn, AGENT, NODE, tool="gh", expected=False)
    row = _health()
    assert (row["health"], _items(row)) == ("red", [("sign_in", "red", "sign_in", "absent")])
    with connect(application_name="test", transaction=True) as conn, conn.transaction():
        S.node_expectation_set(conn, AGENT, NODE, tool="codex", expected=None)

    # Sessions: one a placed service runs on that is down is red; a connection
    # used now and then that is refused is yellow; a device session merely
    # missing on a node where nothing needs it raises nothing.
    _sql("INSERT INTO policies (agent_id, capability, node, enabled, service) "
         "VALUES (%s, 'phonelink', %s, true, true)", (AGENT, NODE))
    with connect(application_name="test", transaction=True) as conn, conn.transaction():
        S.node_sessions_put(conn, AGENT, NODE, "phonelink", [("main", False, None)])
        S.node_sessions_put(conn, AGENT, NODE, "clicker", [
            ("work", False, None, "not_signed_in"), ("spare", False, None, "session_missing")])
    row = _health()
    assert (row["health"], _items(row)) == ("red", [
        ("session", "yellow", "sign_in", "not_live"),
        ("session", "red", "check", "not_live")])
    assert [(i["capability"], i["connection"], i["expected"]) for i in row["items"]] == [
        ("clicker", "work", False), ("phonelink", "main", True)]
    assert [(s["connection"], s["needed"], s["expected"]) for s in row["sessions"]] == [
        ("spare", False, False), ("work", False, False), ("main", True, True)]
    with connect(application_name="test", transaction=True) as conn, conn.transaction():
        S.node_sessions_put(conn, AGENT, NODE, "phonelink", [("main", True, "+1")])
        S.node_expectation_set(conn, AGENT, NODE, capability="clicker", connection="work",
                               expected=False)
    assert _health()["health"] == "green"

    # Services: failing, unusable or held is red; starting, stopping or
    # degraded yellow; waiting on another node's lease is no matter.
    for state, extra, item in (
            ("failing", {"last_error": "boom"}, ("service", "red", "restart", "failing")),
            ("unusable", {"problem": "p", "problem_code": "agent_not_raised"},
             ("service", "red", "raise_agent", "agent_not_raised")),
            ("held", {"problem_code": "restart_policy"},
             ("service", "red", "restart", "restart_policy")),
            ("starting", {}, ("service", "yellow", "wait", "starting")),
            ("degraded", {"skipped_settings": ["x"]},
             ("service", "yellow", "check_settings", "skipped_settings")),
            ("waiting", {"problem_code": "lease_held_elsewhere"}, None)):
        with connect(application_name="test", transaction=True) as conn, conn.transaction():
            S.service_instance_put(conn, AGENT, "phonelink", NODE, state=state, **extra)
        row = _health()
        assert _items(row) == ([item] if item else []), state
        assert row["health"] == (item[1] if item else "green")

    # A setting the service takes only on a start, changed since it started:
    # yellow until it starts again; a change of another setting is no matter.
    with connect(application_name="test", transaction=True) as conn, conn.transaction():
        S.service_instance_put(conn, AGENT, "phonelink", NODE, state="ready",
                               started_at="2026-01-01T00:00:00+00:00",
                               restart_settings=["engine.model", ""])
    assert _sql("SELECT restart_settings FROM service_instances") == [(["engine.model"],)]
    _sql("INSERT INTO settings_changes (agent_id, capability, action, path, changed_by) "
         "VALUES (%s, 'phonelink', 'set', ARRAY['reply', 'tone'], 't')", (AGENT,))
    assert _health()["health"] == "green"
    _sql("INSERT INTO settings_changes (agent_id, capability, node, action, path, changed_by) "
         "VALUES (%s, 'phonelink', %s, 'set', ARRAY['engine', 'model'], 't')", (AGENT, NODE))
    assert _items(_health()) == [("service", "yellow", "restart", "settings_changed")]
    with connect(application_name="test", transaction=True) as conn, conn.transaction():
        S.service_instance_put(conn, AGENT, "phonelink", NODE, state="ready",
                               started_at="2099-01-01T00:00:00+00:00",
                               restart_settings=["engine.model"])
    assert _health()["health"] == "green"

    # A disabled node expects nothing and reads disabled.
    _sql("UPDATE nodes SET disabled_at = now() WHERE id = %s", (NODE,))
    row = _health()
    assert (row["health"], row["items"]) == ("disabled", [])
    assert all(s["expected"] is False for s in row["sign_ins"] + row["sessions"])


def test_a_node_last_seen_before_the_store_moved_to_its_major_cannot_read_it(store):
    _core()
    _agent_on(NODE)
    _reported()
    assert _health()["cannot_read_store"] is False
    # The store reaches its major after the node was registered and last seen.
    _sql("UPDATE nodes SET created_at = now() - interval '2 days', "
         "last_seen_at = now() - interval '1 day'")
    _sql("UPDATE node_states SET reported_at = now() - interval '1 day', "
         "fresh_until = now() + interval '1 minute'")
    _sql("UPDATE schema_ledger SET applied_at = now() - interval '1 hour' "
         "WHERE owner = 'core' AND step = '0041-keys'")
    row = _health()
    assert (row["health"], row["reachable"], row["cannot_read_store"], row["store_major"]) == (
        "red", False, True, 4)
    assert _items(row) == [("node", "red", "update_node", "cannot_read_store")]
    assert row["store_since"] is not None and row["last_seen_at"] < row["store_since"]
    # A node registered since the move reads it until it shows a sign of life.
    _sql("UPDATE nodes SET created_at = now()")
    assert _health()["cannot_read_store"] is False


def test_a_change_of_state_is_announced_once_and_a_rewrite_of_the_same_state_never(store):
    _core()
    _agent_on(NODE)
    with connect(application_name="test") as conn:
        schema = conn.execute("SELECT current_schema()").fetchone()[0]
        conn.execute(f"LISTEN {S.NODE_HEALTH_CHANNEL}")
        conn.commit()

        def write(work) -> list:
            with conn.transaction():
                work(conn)
            conn.commit()
            return [json.loads(n.payload) for n in conn.notifies(timeout=0.3)]

        said = {"schema": schema, "agent_id": AGENT, "node": NODE}
        logins = {"claude": ("signed_in", "a@example.test")}
        # The node's beat announces nothing.
        assert write(lambda c: S.node_state_put(c, NODE)) == []
        assert write(lambda c: S.node_logins_put(c, AGENT, NODE, logins)) == [said]
        assert write(lambda c: S.node_logins_put(c, AGENT, NODE, logins)) == []
        assert write(lambda c: S.node_logins_put(c, AGENT, NODE, logins, needed=["claude"])) \
            == [said]
        # A node replaces its sessions: the same set written again is silent.
        sessions = [("main", True, "+1"), ("spare", False, None)]
        assert write(lambda c: S.node_sessions_put(c, AGENT, NODE, "phonelink", sessions)) \
            == [said]
        assert write(lambda c: S.node_sessions_put(c, AGENT, NODE, "phonelink", sessions)) \
            == []
        assert write(lambda c: S.node_sessions_put(
            c, AGENT, NODE, "phonelink", [("main", True, "+2"), ("spare", False, None)])) == []
        assert write(lambda c: S.node_sessions_put(
            c, AGENT, NODE, "phonelink", [("main", False, None, "not_signed_in")])) == [said]
        assert write(lambda c: S.node_session_put(
            c, AGENT, NODE, "phonelink", "main", False, reason="not_signed_in")) == []
        assert write(lambda c: S.node_session_put(c, AGENT, NODE, "phonelink", "main", True)) \
            == [said]
        assert write(lambda c: S.node_sessions_put(c, AGENT, NODE, "phonelink", [])) == [said]
        # A service: a new state is announced, the same one again is not.
        row = {"state": "ready", "pid": 10}
        assert write(lambda c: S.service_instance_put(c, AGENT, "demo", NODE, **row)) == [said]
        assert write(lambda c: S.service_instance_put(c, AGENT, "demo", NODE, state="ready",
                                                      pid=11)) == []
        assert write(lambda c: S.service_instance_put(c, AGENT, "demo", NODE, state="failing",
                                                      last_error="boom")) == [said]
        assert write(lambda c: S.service_instance_drop(c, AGENT, "demo", NODE)) == [said]
        # A writer whose search path does not reach the schema announces too.
        conn.execute("SET search_path TO public")
        assert write(lambda c: c.execute(
            f'INSERT INTO "{schema}".service_instances (agent_id, capability, node, state)'
            " VALUES (%s, 'other', %s, 'starting')", (AGENT, NODE))) == [said]
        assert write(lambda c: c.execute(
            f'DELETE FROM "{schema}".node_logins WHERE agent_id = %s', (AGENT,))) == [said]
        conn.execute(f'SET search_path TO "{schema}"')
        conn.commit()
        # A rolled-back change announces nothing and raises no version.
        before = conn.execute("SELECT version FROM schema_channel WHERE channel = %s "
                              "AND scope = %s", (S.NODE_HEALTH_CHANNEL, AGENT)).fetchone()[0]
        conn.commit()
        with pytest.raises(RuntimeError), conn.transaction():
            S.service_instance_put(conn, AGENT, "demo", NODE, state="ready")
            raise RuntimeError
        conn.commit()
        assert [n for n in conn.notifies(timeout=0.3)] == []
        after = conn.execute("SELECT version FROM schema_channel WHERE channel = %s "
                             "AND scope = %s", (S.NODE_HEALTH_CHANNEL, AGENT)).fetchone()[0]
        conn.commit()
    assert after == before


def test_one_session_is_written_beside_the_others_and_a_bad_one_refused(store):
    _core()
    _agent_on(NODE)
    with connect(application_name="test", transaction=True) as conn:
        with conn.transaction():
            S.node_sessions_put(conn, AGENT, NODE, "clicker", [("work", True, "me"),
                                                               ("spare", True, None)])
            S.node_session_put(conn, AGENT, NODE, "clicker", "work", False,
                               reason="not_signed_in")
            S.node_session_put(conn, AGENT, NODE, "clicker", "new", False,
                               reason="key_missing", reason_keys=["A_KEY"])
        rows = sorted((s["connection_id"] or s["file_connection"], s["live"], s["account"],
                       s["reason"], s["reason_keys"])
                      for s in S.node_sessions(conn, AGENT, [NODE]))
        for bad in ({"live": True, "reason": "not_signed_in"},
                    {"live": False, "reason": "logged_out"},
                    {"live": False, "reason": "key_missing"}):
            with pytest.raises(S.StoreError):
                S.node_session_put(conn, AGENT, NODE, "clicker", "work", **bad)
    assert rows == [("new", False, None, "key_missing", ["A_KEY"]),
                    ("spare", True, None, None, None),
                    ("work", False, "me", "not_signed_in", None)]


def _probe(store, tmp_path, monkeypatch):
    """A probe capability of agent AGENT on node NODE whose records are in the
    store, bound outside any project folder: its namespace."""
    home = store.config_home
    (home / "probe").mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv(S.NODE_ID_ENV, NODE)
    for key in [k for k in os.environ if k.startswith("CAPABILITIES_")]:
        monkeypatch.delenv(key)
    namespace = {
        "__name__": "probe", "os": os, "sys": sys, "json": json, "Path": Path,
        "NoReturn": NoReturn, "NAME": "probe", "SUMMARY": "a probe", "SCOPE": "user",
        "DOCS_BASE": "", "STATE": False, "INVENTORY": None, "POST_INSTALL": [],
        "_CONFIG_HOME": home, "_STATE_HOME": tmp_path / "state",
        "CREDENTIALS_ENV": home / "probe" / "credentials.env", "CRED_KEYS": [],
        "WRITE_VERBS": set(), "WRITE_DEFAULT": False,
        "CONN_FIELDS": [{"key": "base_url", "help": "where it answers"}],
        "__file__": str(tmp_path / "probe"),
    }
    bind(namespace, "core", "store", "connections")
    envelope = tmp_path / "agent" / "capabilities"
    envelope.mkdir(parents=True)
    namespace["_RECORDS"] = S.StoreRecords(envelope, home, project_id=AGENT,
                                           project_root=envelope.parent,
                                           application_name="probe")
    return namespace


def test_an_exit_for_refused_credentials_records_the_resolved_connection_on_this_node(
        store, tmp_path, monkeypatch, excepthook, capsys):
    _core()
    _agent_on(NODE)
    [(cid,)] = _sql("INSERT INTO connections (capability, label, spec) "
                    "VALUES ('probe', 'work', '{}') RETURNING id")
    namespace = _probe(store, tmp_path, monkeypatch)
    namespace["_select_connection"]({"connections": {cid: {}}, "labels": {cid: "work"}},
                                    "work")
    # Another exit records nothing.
    with pytest.raises(SystemExit) as done:
        namespace["_die"](5, "unreachable", "the service did not answer")
    assert done.value.code == 5
    assert _sql("SELECT count(*) FROM node_sessions") == [(0,)]
    with pytest.raises(SystemExit) as done:
        namespace["_die"](2, "auth_failed", "the key was refused")
    assert done.value.code == 2
    assert json.loads(capsys.readouterr().err.splitlines()[-1])["error"]["code"] == "auth_failed"
    assert _sql("SELECT agent_id, node, capability, connection_id, live, reason "
                "FROM node_sessions") == [(AGENT, NODE, "probe", cid, False, "not_signed_in")]
    assert [(i["capability"], i["level"], i["detail"]) for i in _health()["items"]
            if i["kind"] == "session"] == [("probe", "yellow", "not_signed_in")]

    # Under the read-only switch, or where the record cannot be written - a
    # node the store does not hold - the exit is the same and nothing is said.
    _sql("DELETE FROM node_sessions")
    monkeypatch.setenv(S.READ_ONLY_ENV, "1")
    with pytest.raises(SystemExit) as done:
        namespace["_die"](2, "auth_failed", "the key was refused")
    assert done.value.code == 2 and _sql("SELECT count(*) FROM node_sessions") == [(0,)]
    monkeypatch.delenv(S.READ_ONLY_ENV)
    monkeypatch.setenv(S.NODE_ID_ENV, "00000000ffff")
    namespace["_RECORDS"].node = "00000000ffff"
    capsys.readouterr()
    with pytest.raises(SystemExit) as done:
        namespace["_die"](2, "auth_failed", "the key was refused")
    err = capsys.readouterr().err.splitlines()
    assert done.value.code == 2 and len(err) == 1 and "auth_failed" in err[0]
    assert _sql("SELECT count(*) FROM node_sessions") == [(0,)]
