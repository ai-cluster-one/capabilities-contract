"""The working connection: one transaction connection serves every operation of a
process, is replaced when the store or the network lost it, and a connect that fails
before the store answers is tried again. A statement runs a second time only when
nothing of its transaction reached the store; a commit is never sent twice."""

from __future__ import annotations

import os
import time

import psycopg
import pytest
from _proxy import Proxy

from capabilities_contract.db import DbError, connect, disconnect, migrate
from capabilities_contract.db import _connect as connect_module


def _pid(conn) -> int:
    return conn.execute("SELECT pg_backend_pid()").fetchone()[0]


def _backends(server, name: str) -> int:
    with server.admin() as admin:
        return admin.execute(
            "SELECT count(*) FROM pg_stat_activity WHERE application_name = %s "
            "AND backend_type = 'client backend'", (name,)).fetchone()[0]


@pytest.fixture()
def proxy(server):
    found = Proxy(server.host, server.port)
    yield found
    disconnect(every=True)
    found.close()


@pytest.fixture()
def table(store):
    with connect(application_name="setup", transaction=True) as conn:
        migrate(conn, "demo", [("0001", "CREATE TABLE demo_rows (id int)")],
                major=1, minor=0)
    disconnect()
    return store


# --- one connection serves the process -------------------------------------------

def test_each_connect_after_a_close_is_lent_the_same_connection(store, server):
    pids = set()
    for _ in range(5):
        conn = connect(application_name="working", transaction=True)
        pids.add(_pid(conn))
        conn.close()
    with connect(application_name="working", transaction=True) as conn:
        pids.add(_pid(conn))
    assert len(pids) == 1
    assert _backends(server, "working") == 1


def test_a_loan_binds_its_own_schema_settings_and_name(store, server):
    with connect(application_name="first", transaction=True,
                 local_settings={"statement_timeout": "1234"}) as conn:
        pid = _pid(conn)
        assert conn.execute("SHOW statement_timeout").fetchone() == ("1234ms",)
    other = connect(application_name="second", transaction=True,
                    setting=store_setting(store, "t_other_schema"))
    try:
        assert _pid(other) == pid
        assert other.execute("SHOW search_path").fetchone() == ("t_other_schema",)
        assert other.execute("SHOW statement_timeout").fetchone() == ("0",)
        assert other.execute("SHOW application_name").fetchone() == ("second",)
    finally:
        other.close()
    with connect(application_name="first", transaction=True) as conn:
        assert conn.execute("SHOW search_path").fetchone() == (store.schema,)
        assert conn.execute("SHOW application_name").fetchone() == ("first",)


def store_setting(store, schema):
    import dataclasses

    from capabilities_contract.db import resolve_setting
    return dataclasses.replace(resolve_setting(None), schema=schema)


def test_a_loan_taken_while_another_is_out_gets_its_own(store, server, monkeypatch):
    outer = connect(application_name="nested", transaction=True)
    inner = connect(application_name="nested", transaction=True)
    assert _pid(outer) != _pid(inner)
    inner.close()
    outer.close()
    assert _backends(server, "nested") == 2
    # Both are kept for a while; the spare is closed once it sat idle long enough.
    monkeypatch.setattr(connect_module, "SPARE_IDLE_SECONDS", 0)
    with connect(application_name="nested", transaction=True):
        pass
    assert _backends(server, "nested") == 1


def test_closing_ends_the_loan_and_what_it_left(table, server):
    conn = connect(application_name="loan", transaction=True)
    conn.execute("INSERT INTO demo_rows VALUES (1)")  # never committed
    conn.close()
    conn = connect(application_name="loan", transaction=True)
    conn.autocommit = True
    conn.close()
    assert conn.closed
    with pytest.raises(psycopg.OperationalError, match="closed"):
        conn.execute("SELECT 1")
    conn.close()  # a second close is nothing
    again = connect(application_name="loan", transaction=True)
    try:
        assert again is conn and not again.closed
        assert again.autocommit is False
        assert again.execute("SELECT count(*) FROM demo_rows").fetchone() == (0,)
    finally:
        again.close()


def test_disconnect_closes_the_idle_working_connections(store, server):
    with connect(application_name="idle", transaction=True) as conn:
        conn.execute("SELECT 1")
    assert _backends(server, "idle") == 1
    assert disconnect() == 1
    assert _backends(server, "idle") == 0


def test_a_session_connection_is_never_lent(store, server):
    first = connect(application_name="session")
    second = connect(application_name="session")
    try:
        assert _pid(first) != _pid(second)
    finally:
        first.close()
        second.close()
    assert first.closed and _backends(server, "session") == 0


def test_a_fork_leaves_its_parents_connection_alone(store, server):
    conn = connect(application_name="forked", transaction=True)
    pid = _pid(conn)
    conn.close()
    child = os.fork()
    if child == 0:  # pragma: no cover - runs in the child
        try:
            with connect(application_name="forked", transaction=True) as mine:
                ok = _pid(mine) != pid
        except BaseException:
            ok = False
        os._exit(0 if ok else 1)
    _done, status = os.waitpid(child, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    with connect(application_name="forked", transaction=True) as conn:
        assert _pid(conn) == pid


# --- a connection that is gone is replaced ---------------------------------------

def _terminate(server, pid: int) -> None:
    with server.admin() as admin:
        admin.execute("SELECT pg_terminate_backend(%s)", (pid,))
    time.sleep(0.2)


def test_an_idle_connection_the_store_closed_is_replaced_when_lent(store, server):
    with connect(application_name="replaced", transaction=True) as conn:
        pid = _pid(conn)
    _terminate(server, pid)
    with connect(application_name="replaced", transaction=True) as conn:
        assert _pid(conn) != pid


def test_a_statement_that_opens_its_transaction_runs_on_a_new_connection(table, server):
    conn = connect(application_name="renewed", transaction=True)
    try:
        pid = _pid(conn)
        conn.commit()
        _terminate(server, pid)
        conn.execute("INSERT INTO demo_rows VALUES (1)")
        conn.commit()
        assert _pid(conn) != pid
        assert conn.execute("SELECT count(*) FROM demo_rows").fetchone() == (1,)
    finally:
        conn.close()


def test_an_autocommit_statement_runs_once_on_a_new_connection(table, server):
    conn = connect(application_name="renewed", transaction=True)
    try:
        conn.autocommit = True
        pid = _pid(conn)
        _terminate(server, pid)
        conn.execute("INSERT INTO demo_rows VALUES (1)")
        assert conn.execute("SELECT count(*) FROM demo_rows").fetchone() == (1,)
    finally:
        conn.close()


def test_a_transaction_block_starts_on_a_new_connection(table, server):
    conn = connect(application_name="renewed", transaction=True)
    try:
        pid = _pid(conn)
        conn.commit()
        _terminate(server, pid)
        with conn.transaction():
            conn.execute("INSERT INTO demo_rows VALUES (1)")
        assert conn.execute("SELECT count(*) FROM demo_rows").fetchone() == (1,)
    finally:
        conn.close()


def test_a_transaction_that_lost_work_is_not_run_again(table, server):
    conn = connect(application_name="lost", transaction=True)
    try:
        conn.execute("INSERT INTO demo_rows VALUES (1)")
        _terminate(server, _pid(conn))
        with pytest.raises(psycopg.OperationalError):
            conn.execute("INSERT INTO demo_rows VALUES (2)")
    finally:
        conn.close()
    with connect(application_name="lost", transaction=True) as conn:
        assert conn.execute("SELECT count(*) FROM demo_rows").fetchone() == (0,)


def test_a_read_in_a_transaction_that_has_only_read_runs_on_a_new_connection(
        table, server):
    with connect(application_name="reader", transaction=True) as conn:
        assert conn.execute("SELECT count(*) FROM demo_rows").fetchone() == (0,)
        first = _pid(conn)
        _terminate(server, first)
        assert conn.execute("SELECT count(*) FROM demo_rows").fetchone() == (0,)
        assert _pid(conn) != first
        _terminate(server, _pid(conn))
    # Its commit has nothing to commit: the connection being gone is not refused.
    with connect(application_name="reader", transaction=True) as conn:
        assert conn.execute("SELECT count(*) FROM demo_rows").fetchone() == (0,)


def test_a_read_after_a_write_is_not_run_again(table, server):
    conn = connect(application_name="writer", transaction=True)
    try:
        conn.execute("INSERT INTO demo_rows VALUES (1)")
        _terminate(server, _pid(conn))
        with pytest.raises(psycopg.OperationalError):
            conn.execute("SELECT count(*) FROM demo_rows")
    finally:
        conn.close()
    conn = connect(application_name="locker", transaction=True)
    try:
        conn.execute("SELECT id FROM demo_rows FOR UPDATE")
        _terminate(server, _pid(conn))
        with pytest.raises(psycopg.OperationalError):
            conn.execute("SELECT count(*) FROM demo_rows")
    finally:
        conn.close()


def test_a_migration_whose_check_lost_its_connection_asks_again(table, server,
                                                                monkeypatch):
    from capabilities_contract.db import _migrate
    real = _migrate._check_version
    cut = []

    def lose_it_once(conn, *args, **kwargs):
        if not cut:
            cut.append(_pid(conn))
            _terminate(server, cut[0])
        return real(conn, *args, **kwargs)

    monkeypatch.setattr(_migrate, "_check_version", lose_it_once)
    with connect(application_name="migrating", transaction=True) as conn:
        done = migrate(conn, "demo", [("0001", "CREATE TABLE demo_rows (id int)")],
                       major=1, minor=0)
        assert done.applied == [] and _pid(conn) != cut[0]


def test_a_rollback_on_a_connection_that_is_gone_is_not_refused(table, server):
    conn = connect(application_name="rolled", transaction=True)
    try:
        conn.execute("INSERT INTO demo_rows VALUES (1)")
        _terminate(server, _pid(conn))
        with pytest.raises(psycopg.OperationalError):
            conn.execute("SELECT 1")
        conn.rollback()  # the store rolled it back with the connection
        assert conn.execute("SELECT count(*) FROM demo_rows").fetchone() == (0,)
    finally:
        conn.close()


def test_a_commit_whose_answer_was_lost_is_never_sent_again(table, server, monkeypatch):
    kind = connect_module._transaction_class()
    real = kind._exec_command

    def lose_the_answer(self, command, *args, **kwargs):
        result = yield from real(self, command, *args, **kwargs)
        if command == b"COMMIT":
            self.pgconn.finish()  # the commit reached the store; its answer did not
            raise psycopg.OperationalError("server closed the connection unexpectedly")
        return result

    monkeypatch.setattr(kind, "_exec_command", lose_the_answer)
    conn = connect(application_name="committed", transaction=True)
    conn.autocommit = True
    with pytest.raises(psycopg.OperationalError):
        conn.execute("INSERT INTO demo_rows VALUES (1)")
    conn.close()
    with pytest.raises(psycopg.OperationalError), \
            connect(application_name="committed", transaction=True) as block, \
            block.transaction():
        block.execute("INSERT INTO demo_rows VALUES (2)")
    monkeypatch.setattr(kind, "_exec_command", real)
    with connect(application_name="committed", transaction=True) as conn:
        assert conn.execute("SELECT id FROM demo_rows ORDER BY id").fetchall() == [(1,), (2,)]


def test_a_cut_network_mid_command_is_crossed(table, proxy):
    table.write(port=proxy.port)
    with connect(application_name="cut", transaction=True) as conn:
        conn.execute("INSERT INTO demo_rows VALUES (1)")
    proxy.cut()
    time.sleep(0.2)
    # A commit that cannot be sent fails: whether it reached the store is unknown.
    with pytest.raises(psycopg.OperationalError), \
            connect(application_name="cut", transaction=True) as conn:
        conn.execute("INSERT INTO demo_rows VALUES (2)")
        proxy.cut()
        time.sleep(0.2)
    with connect(application_name="cut", transaction=True) as conn:
        # The second insert was never committed: the store rolled it back.
        assert conn.execute("SELECT id FROM demo_rows").fetchall() == [(1,)]
        conn.commit()
        proxy.cut()
        time.sleep(0.2)
        assert conn.execute("SELECT count(*) FROM demo_rows").fetchone() == (1,)


def test_a_connection_that_stopped_answering_is_replaced_when_lent(store, proxy,
                                                                  monkeypatch):
    store.write(port=proxy.port)
    with connect(application_name="stalled", transaction=True) as conn:
        first = _pid(conn)
    monkeypatch.setattr(connect_module, "PING_AFTER_SECONDS", 0)
    proxy.stalled.set()
    began = time.monotonic()
    accepted = proxy.accepted

    def answer():
        while proxy.accepted == accepted:
            time.sleep(0.05)
        proxy.stalled.clear()

    import threading
    threading.Thread(target=answer, daemon=True).start()
    with connect(application_name="stalled", transaction=True, connect_timeout=2) as conn:
        assert _pid(conn) != first
    assert time.monotonic() - began < 8


# --- a connect is tried again ----------------------------------------------------

def test_a_refused_connect_is_tried_again(store, proxy):
    store.write(port=proxy.port)
    proxy.refuse = 2
    with connect(application_name="flap", transaction=True) as conn:
        conn.execute("SELECT 1")
    assert proxy.accepted == 3
    proxy.refuse = 1
    session = connect(application_name="flap")
    session.close()
    assert proxy.accepted == 5


def test_a_store_that_keeps_refusing_is_unreachable_after_the_tries(store, proxy):
    store.write(port=proxy.port)
    proxy.refuse = 99
    with pytest.raises(DbError) as caught:
        connect(application_name="down", transaction=True)
    assert caught.value.slug == "store_unreachable"
    assert proxy.accepted == connect_module.CONNECT_ATTEMPTS


def test_a_refusal_the_store_answers_is_not_tried_again(store, proxy):
    store.write(port=proxy.port, password="not-the-password")
    with pytest.raises(DbError) as caught:
        connect(application_name="denied", transaction=True)
    assert caught.value.slug == "store_unreachable"
    assert proxy.accepted == 1


def test_a_connect_that_hangs_stays_within_the_connect_timeout(store, proxy):
    store.write(port=proxy.port)
    proxy.stalled.set()
    began = time.monotonic()
    with pytest.raises(DbError) as caught:
        connect(application_name="hangs", transaction=True, connect_timeout=4)
    spent = time.monotonic() - began
    assert caught.value.slug == "store_unreachable"
    assert proxy.accepted == 2  # two tries of half the timeout each
    assert spent < 4 + 1.5
