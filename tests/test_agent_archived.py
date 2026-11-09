"""The core's step 0043-agent-archived: an agent carries an archive mark, a
system agent never; the one guard function every owner calls refuses an
archived agent recognisably and locks the agent's row against an archive's
check and stamp; the core's own tables refuse starting anything for it and
leave stopping alone; and a capability refuses a write of an archived agent,
exit 4 agent_archived, while a store without the mark refuses nothing."""

from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path
from typing import NoReturn

import psycopg
import pytest

from capabilities_contract.capability import bind
from capabilities_contract.capability import store as store_tier
from capabilities_contract.db import (
    AGENT_ARCHIVED_CODE,
    AGENT_ARCHIVED_SQLSTATE,
    _migrate,
    connect,
    disconnect,
    migrate,
)

CORE_4_1 = _migrate.CORE_STEPS[:4]
AGENT = "000000000a01"
OTHER = "000000000a02"
KEEPER = "000000000a03"
NODE = "00000000ee01"


def _core(major=4, minor=2, steps=None):
    with connect(application_name="setup", transaction=True) as conn:
        result = migrate(conn, "core", steps or _migrate.CORE_STEPS, major=major, minor=minor)
        conn.commit()
    disconnect()
    return result


def _sql(query, params=()):
    with connect(application_name="test", transaction=True) as conn, conn.transaction():
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _session():
    """A session connection of its own, outside the process's working one."""
    return connect(application_name="session")


def _agents():
    _sql("INSERT INTO nodes (id, label, kind) VALUES (%s, 'box', 'server')", (NODE,))
    for agent in (AGENT, OTHER):
        _sql("INSERT INTO agents (id) VALUES (%s)", (agent,))


def _archive(agent=AGENT):
    _sql("UPDATE agents SET archived_at = now(), archived_by = 'user@box' WHERE id = %s",
         (agent,))


def _refused(query, params=()):
    with pytest.raises(psycopg.errors.IntegrityError) as caught:
        _sql(query, params)
    assert caught.value.sqlstate == AGENT_ARCHIVED_SQLSTATE == "23R01"
    assert caught.value.diag.message_primary.startswith(f"{AGENT_ARCHIVED_CODE}:")
    assert "user@box" in caught.value.diag.message_detail


PLACE = ("INSERT INTO policies (agent_id, capability, node, enabled, service) "
         "VALUES (%s, 'probe', %s, true, true)")
LEASE = ("INSERT INTO service_leases AS l (agent_id, capability, node, mode, expires_at) "
         "VALUES (%s, 'probe', %s, 'own', now() + interval '60 seconds') "
         "ON CONFLICT (agent_id, capability, node) DO UPDATE SET expires_at = "
         "EXCLUDED.expires_at, renewed_at = now()")
INSTANCE = ("INSERT INTO service_instances AS i (agent_id, capability, node, state) "
            "VALUES (%s, 'probe', %s, %s) ON CONFLICT (agent_id, capability, node) "
            "DO UPDATE SET state = EXCLUDED.state, checked_at = now()")


def test_a_store_at_core_4_1_takes_the_step_without_the_upgrade_and_a_4_1_reader_settles(
        store, monkeypatch):
    with monkeypatch.context() as patched:
        patched.setattr(_migrate, "CORE_STEPS", CORE_4_1)
        patched.setattr(_migrate, "CORE_VERSION", (4, 1))
        _core(4, 1, CORE_4_1)
    _sql("INSERT INTO agents (id) VALUES (%s)", (AGENT,))
    monkeypatch.delenv(_migrate.UPGRADE_ENV, raising=False)
    result = _core()
    assert result.applied == ["0043-agent-archived"]
    assert (result.major, result.minor) == (4, 2) == _migrate.CORE_VERSION
    assert _sql("SELECT archived_at, archived_by FROM agents") == [(None, None)]
    with monkeypatch.context() as patched:
        patched.setattr(_migrate, "CORE_STEPS", CORE_4_1)
        patched.setattr(_migrate, "CORE_VERSION", (4, 1))
        older = _core(4, 1, CORE_4_1)
    assert older.applied == [] and (older.major, older.minor) == (4, 2)
    assert any("newer minor" in warning for warning in older.warnings)
    comments = dict(_sql(
        "SELECT a.attname, col_description(a.attrelid, a.attnum) FROM pg_attribute a "
        "WHERE a.attrelid = 'agents'::regclass AND a.attname IN ('archived_at', 'archived_by')"))
    assert "user@node" in comments["archived_by"] and "restore" in comments["archived_at"]
    [(doc,)] = _sql("SELECT obj_description('agents_archived_refuse(text)'::regprocedure)")
    assert "23R01" in doc and "FOR SHARE" in doc


def test_the_mark_refuses_an_empty_actor_and_a_system_agent(store):
    _core()
    _agents()
    with pytest.raises(psycopg.errors.CheckViolation):
        _sql("UPDATE agents SET archived_at = now(), archived_by = '' WHERE id = %s",
             (AGENT,))
    _sql("INSERT INTO agents (id, kind) VALUES (%s, 'system')", (KEEPER,))
    with pytest.raises(psycopg.errors.CheckViolation):
        _sql("UPDATE agents SET archived_at = now(), archived_by = 'user@box' WHERE id = %s",
             (KEEPER,))
    _archive()
    with pytest.raises(psycopg.errors.CheckViolation):
        _sql("UPDATE agents SET kind = 'system' WHERE id = %s", (AGENT,))
    with pytest.raises(psycopg.errors.CheckViolation):
        _sql("INSERT INTO agents (id, kind, archived_at) VALUES ('000000000a09', 'system', "
             "now())")


def test_the_guard_function_refuses_an_archived_agent_and_passes_the_rest(store):
    _core()
    _agents()
    _archive()
    _refused("SELECT agents_archived_refuse(%s)", (AGENT,))
    for agent in (OTHER, None, "000000000fff"):
        assert _sql("SELECT 1 FROM agents_archived_refuse(%s)", (agent,)) == [(1,)]
    # Restoring clears the mark, and the agent is guarded no more.
    _sql("UPDATE agents SET archived_at = NULL, archived_by = NULL WHERE id = %s", (AGENT,))
    assert _sql("SELECT 1 FROM agents_archived_refuse(%s)", (AGENT,)) == [(1,)]


def test_the_core_tables_refuse_starting_for_an_archived_agent_and_allow_stopping(store):
    _core()
    _agents()
    # What the agent had before it was archived, and the same for another agent.
    for agent in (AGENT, OTHER):
        _sql(PLACE, (agent, NODE))
        _sql(LEASE, (agent, NODE))
        _sql(INSTANCE, (agent, NODE, "ready"))
    _archive()
    # Placing - explicitly, by an enable the service follows, or by an update - is refused.
    _sql("DELETE FROM policies WHERE agent_id = %s", (AGENT,))
    _refused(PLACE, (AGENT, NODE))
    _refused("INSERT INTO policies (agent_id, capability, node, enabled) "
             "VALUES (%s, 'probe', %s, true)", (AGENT, NODE))
    _sql("INSERT INTO policies (agent_id, capability, node, enabled, service) "
         "VALUES (%s, 'probe', %s, true, false)", (AGENT, NODE))
    _refused("UPDATE policies SET service = true WHERE agent_id = %s", (AGENT,))
    # A lease is neither taken nor renewed; an instance is not recorded running.
    _refused(LEASE, (AGENT, NODE))
    for state in ("starting", "ready", "failing", "held"):
        _refused(INSTANCE, (AGENT, NODE, state))
    # Stopping and removing stay allowed.
    _sql("UPDATE policies SET service = false, updated_at = now() WHERE agent_id = %s",
         (AGENT,))
    _sql("UPDATE policies SET enabled = false WHERE agent_id = %s", (AGENT,))
    _sql(INSTANCE, (AGENT, NODE, "stopping"))
    _sql("DELETE FROM service_instances WHERE agent_id = %s", (AGENT,))
    _sql("DELETE FROM service_leases WHERE agent_id = %s", (AGENT,))
    _sql("DELETE FROM policies WHERE agent_id = %s", (AGENT,))
    # A global row and another agent are not touched by the mark.
    _sql("INSERT INTO policies (agent_id, capability, enabled) VALUES (NULL, 'probe', true)")
    _sql(LEASE, (OTHER, NODE))
    _sql(INSTANCE, (OTHER, NODE, "ready"))
    _sql("UPDATE policies SET mode = 'own' WHERE agent_id = %s", (OTHER,))
    assert _sql("SELECT agent_id, service FROM policies WHERE agent_id IS NOT NULL") == [
        (OTHER, True)]


def test_an_owner_guards_its_own_table_by_the_documented_trigger_in_a_core_4_2_step(store):
    from capabilities_contract.db import Step
    _core()
    _agents()
    _archive()
    step = Step("0001-runs", """\
CREATE TABLE demo_runs (id serial PRIMARY KEY, agent_id text NOT NULL REFERENCES agents (id));
CREATE FUNCTION demo_runs_unarchived() RETURNS trigger
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $guard$
BEGIN
 PERFORM agents_archived_refuse(NEW.agent_id);
 RETURN NEW;
END $guard$;
CREATE TRIGGER demo_runs_unarchived BEFORE INSERT ON demo_runs
 FOR EACH ROW EXECUTE FUNCTION demo_runs_unarchived();""", core=(4, 2))
    with connect(application_name="setup", transaction=True) as conn:
        assert migrate(conn, "demo", [step], major=1, minor=0).applied == ["0001-runs"]
        conn.commit()
    disconnect()
    _refused("INSERT INTO demo_runs (agent_id) VALUES (%s)", (AGENT,))
    _sql("INSERT INTO demo_runs (agent_id) VALUES (%s)", (OTHER,))

def _blocked(session, query, params=()):
    """Whether `query` on `session` waits on a lock: it is refused as such
    once a short lock_timeout passes, and rolled back."""
    try:
        with session.transaction():
            session.execute("SET LOCAL lock_timeout = '300ms'")
            session.execute(query, params)
    except psycopg.errors.LockNotAvailable:
        return True
    return False


def test_the_guard_lock_conflicts_with_an_archive_s_row_lock_both_ways(store):
    _core()
    _agents()
    archive, guarded = _session(), _session()
    try:
        # An archive holds its lock from its check to its stamp - FOR UPDATE,
        # or the lock its UPDATE takes: a guarded insert waits for either.
        for lock in ("SELECT 1 FROM agents WHERE id = %s FOR UPDATE",
                     "UPDATE agents SET archived_at = now(), archived_by = 'user@box' "
                     "WHERE id = %s"):
            archive.execute(lock, (AGENT,))
            assert _blocked(guarded, LEASE, (AGENT, NODE))
            assert _blocked(guarded, INSTANCE, (AGENT, NODE, "starting"))
            assert _blocked(guarded, PLACE, (AGENT, NODE))
            archive.rollback()
        # A foreign key's FOR KEY SHARE alone does not wait for the stamp.
        archive.execute("UPDATE agents SET archived_at = now(), archived_by = 'user@box' "
                        "WHERE id = %s", (AGENT,))
        assert not _blocked(guarded, "INSERT INTO identifiers (agent_id, capability, label, "
                            "value) VALUES (%s, 'probe', 'x', '\"y\"')", (AGENT,))
        archive.rollback()
        # A guarded insert not yet committed holds the archive's lock back.
        guarded.execute(LEASE, (AGENT, NODE))
        assert _blocked(archive, "SELECT 1 FROM agents WHERE id = %s FOR UPDATE", (AGENT,))
        guarded.commit()
        # Once it commits, the archive's check sees what it started.
        with archive.transaction():
            archive.execute("SELECT 1 FROM agents WHERE id = %s FOR UPDATE", (AGENT,))
            assert archive.execute("SELECT count(*) FROM service_leases WHERE agent_id = %s",
                                   (AGENT,)).fetchone() == (1,)
    finally:
        archive.close()
        guarded.close()


def test_a_guarded_insert_that_waited_on_an_archive_is_refused_once_it_commits(store):
    _core()
    _agents()
    archive, guarded = _session(), _session()
    caught = []

    def insert():
        try:
            with guarded.transaction():
                guarded.execute(LEASE, (AGENT, NODE))
        except psycopg.Error as exc:
            caught.append(exc)
    try:
        archive.execute("SELECT 1 FROM agents WHERE id = %s FOR UPDATE", (AGENT,))
        waiting = threading.Thread(target=insert)
        waiting.start()
        waiting.join(1.0)
        assert waiting.is_alive()  # it waits for the archive
        archive.execute("UPDATE agents SET archived_at = now(), archived_by = 'user@box' "
                        "WHERE id = %s", (AGENT,))
        archive.commit()
        waiting.join(10)
        assert not waiting.is_alive()
        [exc] = caught
        assert exc.sqlstate == AGENT_ARCHIVED_SQLSTATE
        assert _sql("SELECT count(*) FROM service_leases") == [(0,)]
    finally:
        archive.close()
        guarded.close()


# The gate: a capability bound in a project whose agent the store holds.

def _capability(tmp_path, monkeypatch, **extra) -> tuple[dict, Path]:
    root = tmp_path / "project"
    (root / "capabilities").mkdir(parents=True)
    (root / ".env.local").write_text(f"CAPABILITIES_PROJECT_ID={AGENT}\n")
    for key in ("CAPABILITIES_PROJECT_ID", "CAPABILITIES_PROJECT_ID_ROOT",
                "CAPABILITIES_AUTH_CONTEXT", "CAPABILITIES_READ_ONLY",
                "CAPABILITIES_STORE_UPGRADE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(root))
    monkeypatch.setenv("CAPABILITIES_PROJECT_ENVELOPE", str(root / "capabilities"))
    monkeypatch.setenv("CAPABILITIES_PROJECT_ENVELOPE_ROOT", str(root))
    home = tmp_path / "home"
    namespace = {
        "__name__": "probe", "__file__": str(tmp_path / "probe"), "os": os, "sys": sys,
        "json": json, "Path": Path, "NoReturn": NoReturn,
        "NAME": "probe", "SUMMARY": "a probe", "SCOPE": "project", "DOCS_BASE": "",
        "STATE": False, "INVENTORY": None, "POST_INSTALL": [],
        "_CONFIG_HOME": home, "_STATE_HOME": home,
        "CREDENTIALS_ENV": home / "probe" / "credentials.env", "CRED_KEYS": [],
        "WRITE_VERBS": {"post"}, "WRITE_DEFAULT": False,
        "SERVICE": {"deploy": {}},
    }
    namespace.update(extra)
    bind(namespace, "core", "store")
    return namespace, root


@pytest.fixture
def excepthook():
    saved = sys.excepthook
    yield
    sys.excepthook = saved


def _exit(call) -> int | None:
    try:
        call()
    except SystemExit as stop:
        return stop.code
    return None


def _gate(namespace, monkeypatch, *argv) -> int | None:
    monkeypatch.setattr(sys, "argv", ["probe", *argv])
    return _exit(namespace["_gate"])


def _enabled_store_project():
    with connect(application_name="setup", transaction=True) as conn:
        migrate(conn, store_tier.STORE_OWNER, store_tier.record_table_steps(),
                major=store_tier.STORE_TABLES_VERSION[0],
                minor=store_tier.STORE_TABLES_VERSION[1])
        conn.commit()
    disconnect()
    _sql("INSERT INTO agents (id) VALUES (%s)", (AGENT,))
    _sql("INSERT INTO policies (agent_id, capability, enabled, service) "
         "VALUES (%s, 'probe', true, false)", (AGENT,))


def test_a_capability_refuses_a_write_of_an_archived_agent_and_still_reads(
        store, tmp_path, monkeypatch, excepthook, capsys):
    _enabled_store_project()
    namespace, _root = _capability(tmp_path, monkeypatch)
    for argv in (["help"], ["ids", "list"], ["doctor"], ["service", "start"],
                 ["service", "stop"]):
        assert _gate(namespace, monkeypatch, *argv) is None, argv
    assert _exit(lambda: namespace["_read_only_gate"]("`probe post`")) is None
    _archive()
    capsys.readouterr()
    for argv in (["service", "start"], ["service", "run"], ["service", "init"],
                 ["service", "reload"]):
        assert _gate(namespace, monkeypatch, *argv) == 4, argv
        envelope = json.loads(capsys.readouterr().err)
        assert envelope["error"]["code"] == "agent_archived"
        assert AGENT in envelope["error"]["message"]
    # Every writer that consults the read-only switch is refused the same way.
    assert _exit(lambda: namespace["_read_only_gate"]("`probe post`")) == 4
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "agent_archived"
    # Reading, help, doctor, discovery and stopping a service still pass.
    for argv in (["help"], ["manifest"], ["ids", "list"], ["doctor"], ["service", "stop"],
                 ["service", "status"], ["service", "logs"]):
        assert _gate(namespace, monkeypatch, *argv) is None, argv
    # The read-only switch keeps its own refusal first.
    monkeypatch.setenv("CAPABILITIES_READ_ONLY", "1")
    assert _exit(lambda: namespace["_read_only_gate"]("`probe post`")) == 4
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "read_only_switch"


def test_a_write_verb_through_a_connection_is_refused_for_an_archived_agent(
        store, tmp_path, monkeypatch, excepthook, capsys):
    _enabled_store_project()
    namespace, _root = _capability(tmp_path, monkeypatch)
    bind(namespace, "connections")
    assert _exit(lambda: namespace["_write_gate"]("c1", True, "post")) is None
    _archive()
    assert _exit(lambda: namespace["_write_gate"]("c1", True, "read")) is None
    assert _exit(lambda: namespace["_write_gate"]("c1", True, "post")) == 4
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "agent_archived"


def test_a_store_without_the_mark_or_not_answering_refuses_nothing(
        store, tmp_path, monkeypatch, excepthook):
    with monkeypatch.context() as patched:
        patched.setattr(_migrate, "CORE_STEPS", CORE_4_1)
        patched.setattr(_migrate, "CORE_VERSION", (4, 1))
        _core(4, 1, CORE_4_1)
    _sql("INSERT INTO agents (id) VALUES (%s)", (AGENT,))
    namespace, _root = _capability(tmp_path, monkeypatch)
    with connect(application_name="test", transaction=True) as conn:
        assert namespace["agent_archived"](conn, AGENT) is None
    assert _exit(lambda: namespace["_read_only_gate"]("`probe post`")) is None
    store.write(port=1)
    disconnect(every=True)
    assert _exit(lambda: namespace["_read_only_gate"]("`probe post`")) is None
