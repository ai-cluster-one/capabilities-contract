"""A statement that runs as a transaction of its own - a plain read that would open
a transaction, any statement in autocommit - reaches the store in one round trip
and leaves the connection idle; `batch` sends independent statements as one
pipeline; a store that does not answer is not dialled again on every statement."""

from __future__ import annotations

import os
import re
import time

import psycopg
import pytest
from _proxy import Proxy

from capabilities_contract.db import DbError, connect, disconnect, migrate
from capabilities_contract.db import _connect as connect_module

IDLE = psycopg.pq.TransactionStatus.IDLE
INTRANS = psycopg.pq.TransactionStatus.INTRANS


@pytest.fixture()
def table(store):
    with connect(application_name="setup", transaction=True) as conn:
        migrate(conn, "demo", [("0001", "CREATE TABLE demo_rows (id int)")],
                major=1, minor=0)
    disconnect()
    return store


@pytest.fixture()
def proxy(server):
    found = Proxy(server.host, server.port)
    yield found
    disconnect(every=True)
    found.close()


def _pid(conn) -> int:
    return conn.execute("SELECT pg_backend_pid()").fetchone()[0]


def _state(server, pid: int) -> str:
    with server.admin() as admin:
        return admin.execute("SELECT state FROM pg_stat_activity WHERE pid = %s",
                             (pid,)).fetchone()[0]


class _Trace:
    """The frontend messages libpq sends on `conn` while the block runs. The
    client waits for the store once per Query and once per Sync it sends."""

    def __init__(self, conn, path):
        self.conn, self.path = conn, path

    def __enter__(self):
        self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        self.conn.pgconn.trace(self.fd)
        return self

    def __exit__(self, *exc):
        self.conn.pgconn.untrace()
        os.close(self.fd)
        lines = [line.split("\t") for line in self.path.read_text().splitlines()
                 if re.match(r"\d{4}-", line)]
        self.sent = [line[3] for line in lines if line[1] == "F"]

    @property
    def round_trips(self) -> int:
        return sum(1 for message in self.sent if message in ("Query", "Sync"))


# --- a plain read is a transaction of its own ----------------------------------------

@pytest.mark.parametrize("autocommit", [False, True])
@pytest.mark.parametrize("params", [None, (1,)])
def test_a_plain_read_leaves_the_connection_idle(table, server, autocommit, params):
    with connect(application_name="alone", transaction=True) as conn:
        conn.autocommit = autocommit
        pid = _pid(conn)
        query = "SELECT count(*) FROM demo_rows" + ("" if params is None else
                                                     " WHERE id <> %s")
        assert conn.execute(query, params).fetchone() == (0,)
        assert conn.info.transaction_status == IDLE
        assert _state(server, pid) == "idle"


def test_a_read_in_an_open_transaction_stays_in_it(table, server):
    with connect(application_name="alone", transaction=True) as conn:
        pid = _pid(conn)
        conn.execute("INSERT INTO demo_rows VALUES (1)")
        # The read sees the write it follows: it runs in the same transaction.
        assert conn.execute("SELECT count(*) FROM demo_rows").fetchone() == (1,)
        assert conn.info.transaction_status == INTRANS
        assert _state(server, pid) == "idle in transaction"
        conn.rollback()
        with conn.transaction():
            conn.execute("INSERT INTO demo_rows VALUES (2)")
            assert conn.execute("SELECT count(*) FROM demo_rows").fetchone() == (1,)
            assert _state(server, pid) == "idle in transaction"
        conn.autocommit = True
        with conn.transaction():
            assert conn.execute("SELECT count(*) FROM demo_rows").fetchone() == (1,)
            assert conn.info.transaction_status == INTRANS
        assert conn.execute("SELECT count(*) FROM demo_rows").fetchone() == (1,)


def test_another_isolation_level_keeps_its_transaction(table, server):
    with connect(application_name="alone", transaction=True) as conn:
        conn.isolation_level = psycopg.IsolationLevel.REPEATABLE_READ
        conn.execute("SELECT count(*) FROM demo_rows").fetchone()
        assert conn.info.transaction_status == INTRANS
        conn.commit()


def test_a_write_still_opens_a_transaction_its_commit_closes(table, server):
    with connect(application_name="alone", transaction=True) as conn:
        conn.execute("INSERT INTO demo_rows VALUES (%s)", (1,))
        assert conn.info.transaction_status == INTRANS
        conn.rollback()
        conn.execute("INSERT INTO demo_rows VALUES (2)")
        conn.commit()
    with connect(application_name="alone", transaction=True) as conn:
        assert conn.execute("SELECT id FROM demo_rows").fetchall() == [(2,)]


# --- one round trip --------------------------------------------------------------

@pytest.mark.parametrize("autocommit", [False, True])
@pytest.mark.parametrize("params", [None, (1,)])
def test_a_read_alone_is_one_round_trip_bound(table, tmp_path, autocommit, params):
    with connect(application_name="alone", transaction=True,
                 local_settings={"statement_timeout": "4321"}) as conn:
        conn.autocommit = autocommit
        query = ("SELECT current_setting('search_path'), "
                 "current_setting('statement_timeout')"
                 + ("" if params is None else ", %s::int"))
        with _Trace(conn, tmp_path / "trace") as trace:
            row = conn.execute(query, params).fetchone()
        assert row[:2] == (table.schema, "4321ms")
        assert trace.round_trips == 1, trace.sent
        assert "Query" not in trace.sent[1:] and trace.sent.count("Sync") <= 1


@pytest.mark.parametrize("params", [None, (1,)])
def test_an_autocommit_write_is_one_round_trip(table, tmp_path, params):
    with connect(application_name="alone", transaction=True) as conn:
        conn.autocommit = True
        query = "INSERT INTO demo_rows VALUES (" + ("1" if params is None else "%s") + ")"
        with _Trace(conn, tmp_path / "trace") as trace:
            conn.execute(query, params)
        assert trace.round_trips == 1, trace.sent
        conn.autocommit = False
        assert conn.execute("SELECT count(*) FROM demo_rows").fetchone() == (1,)


def test_an_autocommit_write_whose_answer_was_lost_is_never_run_again(table, monkeypatch):
    kind = connect_module._transaction_class()
    real_wait = kind.wait
    armed = [True]

    def lose_the_answer(self, gen, *args, **kwargs):
        # The pipeline's end sends its sync, which commits, and reads the answer.
        ending = getattr(gen, "__name__", "") == "_exit_gen"
        result = real_wait(self, gen, *args, **kwargs)
        if ending and armed and armed.pop():
            self.pgconn.finish()
            raise psycopg.OperationalError("server closed the connection unexpectedly")
        return result

    conn = connect(application_name="lost", transaction=True)
    conn.autocommit = True
    monkeypatch.setattr(kind, "wait", lose_the_answer)
    with pytest.raises(psycopg.OperationalError):
        conn.execute("INSERT INTO demo_rows VALUES (%s)", (1,))
    monkeypatch.setattr(kind, "wait", real_wait)
    conn.close()
    with connect(application_name="lost", transaction=True) as conn:
        assert conn.execute("SELECT id FROM demo_rows").fetchall() == [(1,)]


def test_a_read_alone_whose_answer_was_lost_runs_again(table, monkeypatch):
    kind = connect_module._transaction_class()
    real_wait = kind.wait
    armed = [True]

    def lose_the_answer(self, gen, *args, **kwargs):
        # The pipeline's end sends its sync, which commits, and reads the answer.
        ending = getattr(gen, "__name__", "") == "_exit_gen"
        result = real_wait(self, gen, *args, **kwargs)
        if ending and armed and armed.pop():
            self.pgconn.finish()
            raise psycopg.OperationalError("server closed the connection unexpectedly")
        return result

    with connect(application_name="lost", transaction=True) as conn:
        first = _pid(conn)
        monkeypatch.setattr(kind, "wait", lose_the_answer)
        assert conn.execute("SELECT count(*) FROM demo_rows WHERE id <> %s",
                            (1,)).fetchone() == (0,)
        monkeypatch.setattr(kind, "wait", real_wait)
        assert _pid(conn) != first


# --- batch --------------------------------------------------------------------------

def batch(conn, statements):
    from capabilities_contract.db import batch as sent_together
    return sent_together(conn, statements)


@pytest.mark.parametrize("autocommit", [False, True])
def test_a_batch_of_reads_is_one_round_trip_and_leaves_the_connection_idle(
        table, server, tmp_path, autocommit):
    with connect(application_name="batch", transaction=True) as conn:
        conn.autocommit = autocommit
        pid = _pid(conn)
        with _Trace(conn, tmp_path / "trace") as trace:
            got = batch(conn, ["SELECT count(*) FROM demo_rows",
                               ("SELECT %s::int, %s::text", (7, "seven")),
                               "SHOW search_path"])
        assert got == [[(0,)], [(7, "seven")], [(table.schema,)]]
        assert trace.round_trips == 1, trace.sent
        assert conn.info.transaction_status == IDLE
        assert _state(server, pid) == "idle"


def test_a_batch_that_writes_opens_a_transaction_for_the_callers_commit(table, tmp_path):
    with connect(application_name="batch", transaction=True) as conn:
        with _Trace(conn, tmp_path / "trace") as trace:
            got = batch(conn, [("INSERT INTO demo_rows VALUES (%s)", (1,)),
                               "SELECT count(*) FROM demo_rows"])
        assert got == [[], [(1,)]]
        assert trace.round_trips == 1, trace.sent
        assert conn.info.transaction_status == INTRANS
        conn.rollback()
        batch(conn, [("INSERT INTO demo_rows VALUES (%s)", (2,))])
        # Inside the open transaction, a second batch stays in it.
        assert batch(conn, ["SELECT count(*) FROM demo_rows"]) == [[(1,)]]
        assert conn.info.transaction_status == INTRANS
        conn.commit()
        conn.autocommit = True
        batch(conn, [("INSERT INTO demo_rows VALUES (%s)", (3,))])
        assert conn.info.transaction_status == IDLE
    with connect(application_name="batch", transaction=True) as conn:
        assert conn.execute("SELECT id FROM demo_rows ORDER BY id").fetchall() == [(2,), (3,)]


def test_a_batch_whose_statement_fails_raises_it(table):
    with connect(application_name="batch", transaction=True) as conn:
        with pytest.raises(psycopg.errors.UndefinedTable):
            batch(conn, ["SELECT 1", "SELECT * FROM demo_missing"])
        assert conn.info.transaction_status == IDLE
        assert batch(conn, ["SELECT 1"]) == [[(1,)]]
        with pytest.raises(DbError) as caught:
            batch(conn, ["SELECT 1", "LISTEN demo_changed"])
        assert caught.value.slug == "session_state"


def test_a_batch_of_reads_runs_again_on_a_new_connection(table, server):
    with connect(application_name="batch", transaction=True) as conn:
        first = _pid(conn)
        with server.admin() as admin:
            admin.execute("SELECT pg_terminate_backend(%s)", (first,))
        time.sleep(0.2)
        assert batch(conn, ["SELECT 1", ("SELECT %s::int", (2,))]) == [[(1,)], [(2,)]]
        assert _pid(conn) != first


def test_a_batch_on_a_session_connection_is_one_round_trip(table, tmp_path):
    with connect(application_name="batch") as conn:
        with _Trace(conn, tmp_path / "trace") as trace:
            got = batch(conn, ["SHOW search_path", ("SELECT %s::int", (2,))])
        assert got == [[(table.schema,)], [(2,)]]
        assert trace.round_trips == 1, trace.sent
        conn.rollback()


# --- a store that does not answer is not dialled on every connect ----------------------

def test_the_pauses_between_connect_tries_are_jittered_and_doubling(store, proxy,
                                                                    monkeypatch):
    store.write(port=proxy.port)
    proxy.refuse = 99
    slept = []
    monkeypatch.setattr(connect_module.time, "sleep", slept.append)
    with pytest.raises(DbError):
        connect(application_name="down", transaction=True)
    assert len(slept) == connect_module.CONNECT_ATTEMPTS - 1
    for attempt, pause in enumerate(slept):
        most = connect_module.CONNECT_PAUSE_SECONDS * 2 ** attempt
        assert most / 2 <= pause <= most
    drawn = set()
    for _ in range(20):
        drawn.add(connect_module._jittered(1.0))
    assert len(drawn) > 1 and all(0.5 <= x <= 1.0 for x in drawn)


def test_a_store_that_did_not_answer_is_not_dialled_again_within_the_pause(
        store, proxy, monkeypatch):
    store.write(port=proxy.port)
    monkeypatch.setattr(connect_module, "RECONNECT_FIRST_SECONDS", 1.0)
    proxy.refuse = connect_module.CONNECT_ATTEMPTS
    # The first connect of the process dials, and says when the next one will.
    with pytest.raises(DbError) as first:
        connect(application_name="down", transaction=True)
    dialled = proxy.accepted
    assert dialled == connect_module.CONNECT_ATTEMPTS
    (_n, until, _why), = connect_module._PAUSED.values()
    assert first.value.dials_again_at == until
    assert 0.5 - 0.05 <= until - time.monotonic() <= 1.0
    began = time.monotonic()
    with pytest.raises(DbError) as caught:
        connect(application_name="down", transaction=True)
    assert caught.value.slug == "store_unreachable"
    assert "not dialled again" in caught.value.message
    assert caught.value.dials_again_at == until
    assert isinstance(caught.value.__cause__, psycopg.OperationalError)
    assert time.monotonic() - began < 0.2
    assert proxy.accepted == dialled
    # A session connection is not paused.
    connect(application_name="down").close()
    assert proxy.accepted == dialled + 1
    # After the pause the next connect dials again, and an answer ends the pause.
    time.sleep(1.05)
    with connect(application_name="down", transaction=True) as conn:
        assert conn.execute("SELECT 1").fetchone() == (1,)
    assert proxy.accepted == dialled + 2
    assert not connect_module._PAUSED


def test_the_pause_grows_with_each_failure_and_is_bounded(store, proxy, monkeypatch):
    store.write(port=proxy.port)
    proxy.refuse = 999
    monkeypatch.setattr(connect_module.time, "sleep", lambda _s: None)
    pauses = []
    for _ in range(8):
        connect_module._PAUSED.update({key: (n, 0.0, why) for key, (n, _u, why)
                                       in connect_module._PAUSED.items()})
        before = time.monotonic()
        with pytest.raises(DbError):
            connect(application_name="down", transaction=True)
        (failures, until, _why), = connect_module._PAUSED.values()
        pauses.append((failures, until - before))
    assert [n for n, _p in pauses] == list(range(1, 9))
    for n, pause in pauses:
        most = min(connect_module.RECONNECT_LONGEST_SECONDS,
                   connect_module.RECONNECT_FIRST_SECONDS * 2 ** (n - 1))
        assert most / 2 - 0.05 <= pause <= most + 0.05
    assert pauses[-1][1] <= connect_module.RECONNECT_LONGEST_SECONDS + 0.05


def test_a_statement_on_a_lost_connection_does_not_dial_within_the_pause(
        table, proxy, monkeypatch):
    table.write(port=proxy.port)
    with connect(application_name="away", transaction=True) as conn:
        conn.execute("SELECT 1").fetchone()
        proxy.refuse = 999
        proxy.cut()
        time.sleep(0.2)
        with pytest.raises(psycopg.OperationalError):
            conn.execute("SELECT 2").fetchone()
        dialled = proxy.accepted
        began = time.monotonic()
        for _ in range(5):
            with pytest.raises(psycopg.OperationalError):
                conn.execute("SELECT 3").fetchone()
        assert proxy.accepted == dialled
        assert time.monotonic() - began < 1
