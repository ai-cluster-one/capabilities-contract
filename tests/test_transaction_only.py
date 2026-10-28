"""A store reached through a transaction pooler alone, and a follower that wakes at once
where a session address is named apart.

A store whose one address is Supabase's transaction pooler is transaction-only: its
transaction connections dial the pooler, proven to answer behind it, and a session
connection is refused before anything is sent. A follower listens on its channels only
where the setting names the store's two addresses apart, and a listener it cannot open
or loses costs nothing but the early wake."""

from __future__ import annotations

import threading
import time
import uuid

import psycopg
import pytest

from capabilities_contract.db import (
    DbError,
    Follower,
    Setting,
    _changes,
    _connect,
    announce,
    connect,
    disconnect,
    migrate,
)

POOLER = "aws-0-region.pooler.supabase.com"
PASSWORD = "not-a-real-secret"


def _fields(host, port, **more):
    return Setting(level="environment", host=host, port=port, database="postgres",
                   user="postgres.ref", sslmode="require", password=PASSWORD, **more)


# --- a transaction-only store -----------------------------------------------------

@pytest.fixture
def opened(monkeypatch):
    """Each transaction connect's arguments and whether its answer is proven; the
    driver itself is never reached."""
    calls = []

    def fake_open(kwargs, proven, budget):
        calls.append((kwargs, proven))
        raise DbError("store_unreachable", "not dialled in this test")

    def no_session(*args, **kwargs):
        raise AssertionError("a session connect reached the driver")

    monkeypatch.setattr(_connect, "_open_transaction", fake_open)
    monkeypatch.setattr(psycopg, "connect", no_session)
    return calls


@pytest.mark.parametrize("setting", [
    _fields(POOLER, 6543),
    Setting(level="environment",
            url=f"postgresql://postgres.ref:{PASSWORD}@{POOLER}:6543/postgres"),
], ids=["fields", "url"])
def test_a_transaction_only_store_takes_transaction_connections_and_refuses_session_ones(
        opened, setting):
    assert not setting.has_transaction_address and not setting.has_session_address
    with pytest.raises(DbError) as caught:
        connect(application_name="test", setting=setting, transaction=True)
    assert caught.value.slug == "store_unreachable"
    [(kwargs, proven)] = opened
    assert proven is True
    assert "options" in kwargs and kwargs.get("port", 6543) == 6543

    with pytest.raises(DbError) as caught:
        connect(application_name="test", setting=setting)
    error = caught.value
    assert error.slug == "transaction_pooler"
    assert "only address" in error.message and f"{POOLER}:6543" in error.message
    assert "keeps no session" in error.message
    assert POOLER in error.hint and "5432" in error.hint
    assert "--session-port 5432" in error.hint
    assert PASSWORD not in error.message + error.hint
    assert len(opened) == 1


def test_which_stores_have_a_session_address():
    assert not _fields(POOLER, 6543).has_session_address
    assert not _fields(POOLER.upper(), 6543).has_session_address
    split = _fields(POOLER, 5432, transaction_port=6543)
    assert split.has_session_address and split.has_transaction_address
    assert _fields(POOLER, 5432).has_session_address
    assert _fields("db.example.test", 6543).has_session_address
    assert _fields("db.example.test", 5432).has_session_address
    assert not _fields("db.example.test", 5432).has_transaction_address
    assert Setting(level="environment",
                   url=f"postgresql://u@{POOLER}/postgres").has_session_address


def test_the_report_names_the_address_each_kind_of_connection_dials():
    assert _fields(POOLER, 6543).report()["addresses"] == {
        "transaction": {"host": POOLER, "port": 6543}, "session": None}
    assert _fields(POOLER, 5432, transaction_port=6543).report()["addresses"] == {
        "transaction": {"host": POOLER, "port": 6543},
        "session": {"host": POOLER, "port": 5432}}
    assert _fields("db.example.test", 5432, transaction_host="pool.example.test",
                   transaction_port=6432).report()["addresses"] == {
        "transaction": {"host": "pool.example.test", "port": 6432},
        "session": {"host": "db.example.test", "port": 5432}}
    url = Setting(level="environment", transaction_port=6543,
                  url=f"postgresql://postgres.ref:{PASSWORD}@{POOLER}/postgres")
    report = url.report()
    assert report["addresses"] == {"transaction": {"host": POOLER, "port": 6543},
                                   "session": {"host": POOLER, "port": 5432}}
    assert PASSWORD not in repr(report)
    only = Setting(level="environment",
                   url=f"postgresql://postgres.ref:{PASSWORD}@{POOLER}:6543/postgres")
    assert only.report()["addresses"] == {"transaction": {"host": POOLER, "port": 6543},
                                          "session": None}


# --- a follower that wakes at once ------------------------------------------------

@pytest.fixture()
def migrated(store):
    with connect(application_name="setup", transaction=True) as conn:
        migrate(conn, "demo", [("0001", "CREATE TABLE demo_rows (id int)")],
                major=1, minor=0)
    disconnect()
    return store


@pytest.fixture()
def apart(migrated, server):
    """The test server named as both addresses, apart."""
    migrated.write(transaction_host=server.host, transaction_port=server.port)
    return migrated


def _raise_soon(channel: str, scope: str, after: float = 0.3) -> threading.Thread:
    def run():
        time.sleep(after)
        with connect(application_name="writer", transaction=True) as conn:
            conn.execute("INSERT INTO demo_rows VALUES (1)")
            announce(conn, channel, scope)
            conn.commit()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def _sessions(server, name: str) -> int:
    with server.admin() as admin:
        return admin.execute("SELECT count(*) FROM pg_stat_activity "
                             "WHERE application_name = %s", (name,)).fetchone()[0]


def test_a_follower_wakes_at_once_where_the_addresses_are_named_apart(apart, server):
    name = f"follower_{uuid.uuid4().hex[:8]}"
    with Follower([("demo_rows", "p1")], application_name=name) as follower:
        follower.poll()
        writer = _raise_soon("demo_rows", "p1")
        began = time.monotonic()
        assert follower.wait(10) is True
        assert time.monotonic() - began < 3
        writer.join(5)
        assert follower.poll() == {("demo_rows", "p1"): 1}
        disconnect()  # the working connection the polls were lent
        assert _sessions(server, name) == 1  # the listener
        began = time.monotonic()
        assert follower.wait(0.5) is False  # nothing announced
        assert time.monotonic() - began >= 0.45
    assert _sessions(server, name) == 0


def test_run_polls_as_soon_as_a_followed_channel_is_notified(apart):
    calls: list[tuple[float, dict]] = []
    called = threading.Event()

    def on_change(moved):
        calls.append((time.monotonic(), moved))
        called.set()

    follower = Follower(["demo_rows"], application_name="follower")
    stop = threading.Event()
    thread = threading.Thread(target=follower.run, args=(on_change,),
                              kwargs={"interval": 30, "stop": stop}, daemon=True)
    thread.start()
    try:
        assert called.wait(10)
        called.clear()
        writer = _raise_soon("demo_rows", "p9")
        raised = time.monotonic()
        assert called.wait(5)
        writer.join(5)
        at, moved = calls[-1]
        assert moved == {("demo_rows", "p9"): 1} and at - raised < 3
    finally:
        stop.set()
        thread.join(5)
    assert not thread.is_alive()


def test_with_one_address_a_follower_waits_out_the_time_and_opens_nothing(
        migrated, server):
    name = f"follower_{uuid.uuid4().hex[:8]}"
    follower = Follower([("demo_rows", "p1")], application_name=name)
    writer = _raise_soon("demo_rows", "p1", after=0.1)
    began = time.monotonic()
    assert follower.wait(1.0) is False
    assert time.monotonic() - began >= 0.95
    writer.join(5)
    assert _sessions(server, name) == 0
    stop = threading.Event()
    stop.set()
    began = time.monotonic()
    assert follower.wait(10, stop) is False
    assert time.monotonic() - began < 1


def test_a_listener_that_cannot_open_costs_only_the_wake(apart, server, monkeypatch):
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        closed = sock.getsockname()[1]
    # The session address answers nothing; the transaction address is the server.
    apart.write(port=closed, transaction_host=server.host, transaction_port=server.port)
    tries = []
    real = _changes.connect

    def counted(**kwargs):
        if not kwargs.get("transaction"):
            tries.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(_changes, "connect", counted)
    follower = Follower([("demo_rows", "p1")], application_name="follower")
    assert follower.poll() == {("demo_rows", "p1"): 0}  # through the transaction address
    began = time.monotonic()
    assert follower.wait(1.0) is False
    assert 0.95 <= time.monotonic() - began < 6
    assert len(tries) == 1
    began = time.monotonic()
    assert follower.wait(0.3) is False  # not tried again within LISTEN_RETRY_SECONDS
    assert 0.25 <= time.monotonic() - began < 1
    assert len(tries) == 1
    monkeypatch.setattr(_changes, "LISTEN_RETRY_SECONDS", 0.0)
    assert follower.wait(0.3) is False
    assert len(tries) == 2
    follower.close()


def test_a_lost_listener_costs_only_the_wake_and_is_opened_again(apart, server,
                                                                 monkeypatch):
    name = f"follower_{uuid.uuid4().hex[:8]}"
    follower = Follower([("demo_rows", "p1")], application_name=name)
    try:
        assert follower.wait(0.1) is False
        assert _sessions(server, name) == 1
        with server.admin() as admin:
            admin.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                          "WHERE application_name = %s", (name,))
        began = time.monotonic()
        assert follower.wait(1.0) is False
        assert time.monotonic() - began >= 0.95
        assert follower.wait(0.2) is False  # not opened again within the retry pause
        assert _sessions(server, name) == 0
        monkeypatch.setattr(_changes, "LISTEN_RETRY_SECONDS", 0.0)
        writer = _raise_soon("demo_rows", "p1", after=1.0)
        assert follower.wait(10) is True
        writer.join(5)
    finally:
        follower.close()
