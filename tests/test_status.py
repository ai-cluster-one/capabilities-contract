"""status reports where an owner's tables stand without changing them or locking;
connections bound their connect and probe an idle peer."""

from __future__ import annotations

import time

import pytest

from capabilities_contract.db import DbError, connect, migrate, status
from capabilities_contract.db._setting import Setting

STEPS = [("0001", "CREATE TABLE stat_items (id int)"),
         ("0002", "ALTER TABLE stat_items ADD COLUMN name text")]


def _connect():
    return connect(application_name="capabilities-contract-tests")


def _advisory_locks(server) -> int:
    with server.admin() as admin:
        return admin.execute("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory'"
                             ).fetchone()[0]


def test_status_on_an_empty_schema_is_pending_and_creates_nothing(store, server):
    conn = _connect()
    report = status(conn, "stat", STEPS, major=1, minor=0)
    assert report.state == "pending"
    assert report.pending == ["0001", "0002"] and report.applied == []
    assert report.stored_major is None
    with server.admin() as admin:
        assert admin.execute("SELECT 1 FROM pg_namespace WHERE nspname = %s",
                             (store.schema,)).fetchone() is None


def test_status_after_migrate_is_current(store):
    conn = _connect()
    migrate(conn, "stat", STEPS, major=1, minor=0)
    report = status(conn, "stat", STEPS, major=1, minor=0)
    assert report.state == "current"
    assert report.applied == ["0001", "0002"] and report.pending == []
    assert (report.stored_major, report.stored_minor) == (1, 0)


def test_status_names_a_new_step_and_an_older_stored_version_as_pending(store):
    conn = _connect()
    migrate(conn, "stat", STEPS[:1], major=1, minor=0)
    report = status(conn, "stat", STEPS, major=1, minor=1)
    assert report.state == "pending" and report.pending == ["0002"]
    migrate(conn, "stat", STEPS, major=1, minor=0)
    assert status(conn, "stat", STEPS, major=1, minor=1).state == "pending"


def test_status_reports_what_migrate_would_refuse(store):
    conn = _connect()
    migrate(conn, "stat", STEPS, major=2, minor=0)
    assert status(conn, "stat", STEPS, major=1, minor=0).state == "schema_too_new"
    changed = [STEPS[0], ("0002", "ALTER TABLE stat_items ADD COLUMN label text")]
    report = status(conn, "stat", changed, major=2, minor=0)
    assert report.state == "checksum_mismatch" and report.changed == ["0002"]


def test_status_warns_on_a_newer_stored_minor(store):
    conn = _connect()
    migrate(conn, "stat", STEPS, major=1, minor=3)
    report = status(conn, "stat", STEPS, major=1, minor=0)
    assert report.state == "current" and report.warnings


def test_status_takes_no_lock_while_another_session_holds_them(store, server):
    conn = _connect()
    migrate(conn, "stat", STEPS, major=1, minor=0)
    with server.admin() as holder:
        holder.execute("BEGIN")
        for key in (f"capabilities_contract:{store.schema}",
                    f"capabilities_contract:{store.schema}:stat"):
            holder.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (key,))
        held = _advisory_locks(server)
        started = time.monotonic()
        report = status(conn, "stat", STEPS, major=1, minor=1)
        assert time.monotonic() - started < 2
        assert report.state == "pending"
        assert _advisory_locks(server) == held
        holder.execute("ROLLBACK")


def test_status_needs_an_idle_connection(store):
    conn = _connect()
    conn.execute("SELECT 1")
    with pytest.raises(DbError) as caught:
        status(conn, "stat", STEPS, major=1, minor=0)
    assert caught.value.slug == "connection_busy"


def test_a_connection_asks_both_ends_for_keepalives(store, server):
    conn = _connect()
    assert conn.info.get_parameters().get("keepalives") == "1"
    values = conn.execute("SELECT current_setting('tcp_keepalives_idle'), "
                          "current_setting('tcp_keepalives_interval'), "
                          "current_setting('tcp_keepalives_count')").fetchone()
    conn.commit()
    assert values == ("30", "10", "3")


def test_an_unanswering_store_is_refused_within_the_connect_bound(store):
    # A listening socket that never answers: the connect waits on the handshake.
    import socket
    silent = socket.socket()
    silent.bind(("127.0.0.1", 0))
    silent.listen(1)
    port = silent.getsockname()[1]
    try:
        setting = Setting(level="machine", sources=("test",), host="127.0.0.1", port=port,
                          database="x", user="x", sslmode="disable", schema="agentkit")
        started = time.monotonic()
        with pytest.raises(DbError) as caught:
            connect(application_name="capabilities-contract-tests", setting=setting,
                    connect_timeout=2)
        elapsed = time.monotonic() - started
    finally:
        silent.close()
    assert caught.value.slug == "store_unreachable"
    assert elapsed < 6
