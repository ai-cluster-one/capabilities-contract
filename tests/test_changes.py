"""Changes followed by polling: a writer raises a channel's version inside its own
transaction, and a follower reads the versions it follows in one round trip and
reports only those that moved."""

from __future__ import annotations

import os
import re
import threading
import time
import uuid

import pytest
from _proxy import Proxy

from capabilities_contract.db import (
    DbError,
    Follower,
    announce,
    connect,
    disconnect,
    migrate,
    resolve_setting,
)


@pytest.fixture()
def migrated(store):
    with connect(application_name="setup", transaction=True) as conn:
        migrate(conn, "demo", [("0001", "CREATE TABLE demo_rows (id int)")],
                major=1, minor=0)
    disconnect()
    return store


def _raise(channel: str, scope: str, *, setting=None) -> int:
    with connect(application_name="writer", transaction=True, setting=setting) as conn:
        conn.execute("INSERT INTO demo_rows VALUES (1)")
        version = announce(conn, channel, scope)
        conn.commit()
    return version


class _Calls:
    def __init__(self):
        self.calls: list[tuple[float, dict]] = []
        self.event = threading.Event()

    def __call__(self, moved: dict) -> None:
        self.calls.append((time.monotonic(), moved))
        self.event.set()

    def wait(self, timeout: float) -> tuple[float, dict]:
        assert self.event.wait(timeout), "no call came"
        self.event.clear()
        return self.calls[-1]


def _running(follower: Follower, calls: _Calls, interval: float = 1.0):
    stop = threading.Event()
    thread = threading.Thread(target=follower.run, args=(calls,),
                              kwargs={"interval": interval, "stop": stop}, daemon=True)
    thread.start()
    return stop, thread


def test_migrate_creates_the_versions_table_also_on_a_store_made_before_it(migrated, server):
    with server.admin() as admin:
        admin.execute(f'DROP TABLE "{migrated.schema}".schema_channel')
    with connect(application_name="again", transaction=True) as conn:
        result = migrate(conn, "demo", [("0001", "CREATE TABLE demo_rows (id int)")],
                         major=1, minor=0)
        assert result.skipped == ["0001"] and result.applied == []
        assert announce(conn, "demo_rows", "p1") == 1
        conn.commit()


@pytest.mark.parametrize("limit", ["no_create", "read_only"])
def test_a_role_that_may_not_create_migrates_a_store_made_before_the_versions_table(
        migrated, server, limit):
    steps = [("0001", "CREATE TABLE demo_rows (id int)")]
    schema, role = migrated.schema, f"tool_{uuid.uuid4().hex[:12]}"
    with server.admin() as admin:
        admin.execute(f'DROP TABLE "{schema}".schema_channel')
        admin.execute(f"CREATE ROLE {role} LOGIN PASSWORD 'tool-pw'")
        admin.execute(f'GRANT USAGE ON SCHEMA "{schema}" TO {role}')
        admin.execute(f'GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA "{schema}" TO {role}')
        if limit == "read_only":
            admin.execute(f'GRANT CREATE ON SCHEMA "{schema}" TO {role}')
            admin.execute(f"ALTER ROLE {role} SET default_transaction_read_only = on")
    try:
        migrated.write(user=role, password="tool-pw")
        with connect(application_name="tool", transaction=True) as conn:
            result = migrate(conn, "demo", steps, major=1, minor=0)
            assert result.skipped == ["0001"] and result.applied == []
            if limit == "no_create":
                assert migrate(conn, "demo", steps, major=1, minor=1).minor == 1
                with pytest.raises(DbError) as refused:
                    announce(conn, "demo_rows", "p1")
                assert refused.value.slug == "not_migrated"
                conn.rollback()
        disconnect()
        migrated.write()
        with connect(application_name="owner", transaction=True) as conn:
            migrate(conn, "demo", steps, major=1, minor=1)
        disconnect()
        if limit == "no_create":
            with server.admin() as admin:
                admin.execute(f'GRANT SELECT, INSERT, UPDATE ON "{schema}".schema_channel '
                              f"TO {role}")
            migrated.write(user=role, password="tool-pw")
            with connect(application_name="tool", transaction=True) as conn:
                assert announce(conn, "demo_rows", "p1") == 1
                conn.commit()
            disconnect()
    finally:
        disconnect(every=True)
        with server.admin() as admin:
            admin.execute(f'DROP OWNED BY {role}')
            admin.execute(f"DROP ROLE {role}")


def test_a_raise_is_seen_by_a_follower_within_two_seconds(migrated):
    calls = _Calls()
    stop, thread = _running(Follower([("demo_rows", "p1")], application_name="follower"),
                            calls)
    try:
        _at, moved = calls.wait(5)
        assert moved == {("demo_rows", "p1"): 0}
        raised = time.monotonic()
        assert _raise("demo_rows", "p1") == 1
        at, moved = calls.wait(5)
        assert moved == {("demo_rows", "p1"): 1}
        assert at - raised < 2.0
    finally:
        stop.set()
        thread.join(5)


def test_a_raise_in_a_transaction_that_rolls_back_is_never_seen(migrated):
    follower = Follower([("demo_rows", "p1"), "demo_rows"], application_name="follower")
    assert follower.poll() == {("demo_rows", "p1"): 0}
    with connect(application_name="writer", transaction=True) as conn:
        conn.execute("INSERT INTO demo_rows VALUES (1)")
        assert announce(conn, "demo_rows", "p1") == 1
        assert announce(conn, "demo_rows", "p2") == 1
        assert follower.poll() == {}  # not yet committed
        conn.rollback()
    for _ in range(3):
        assert follower.poll() == {}
        time.sleep(0.5)
    assert follower.read() == {("demo_rows", "p1"): 0}
    assert _raise("demo_rows", "p1") == 1  # the rolled-back raise left no trace


def test_a_follower_that_was_down_sees_every_channel_that_moved_on_its_first_poll(migrated):
    follow = [("demo_rows", "p1"), ("demo_rows", "p2"), ("demo_runs", "p1"),
              ("demo_quiet", "p1"), "demo_jobs"]
    follower = Follower(follow, application_name="follower")
    _raise("demo_quiet", "p1")
    first = follower.poll()
    assert first == {("demo_rows", "p1"): 0, ("demo_rows", "p2"): 0,
                     ("demo_runs", "p1"): 0, ("demo_quiet", "p1"): 1}
    saved = follower.seen
    # Down: nobody polls while these are raised.
    _raise("demo_rows", "p1")
    _raise("demo_runs", "p1")
    _raise("demo_runs", "p1")
    _raise("demo_jobs", "p7")
    _raise("demo_other", "p1")  # not followed
    moved = {("demo_rows", "p1"): 1, ("demo_runs", "p1"): 2, ("demo_jobs", "p7"): 1}
    assert follower.poll() == moved
    assert follower.poll() == {}
    # A new follower carrying the versions the old one had seen.
    assert Follower(follow, application_name="later", seen=saved).poll() == moved
    # A new follower carrying nothing reports every version on its first poll.
    assert Follower(follow, application_name="fresh").poll() == {
        **first, **moved, ("demo_quiet", "p1"): 1}


def test_a_follower_whose_store_went_away_reports_what_moved_meanwhile(migrated, server):
    direct = resolve_setting(None)
    proxy = Proxy(server.host, server.port)
    try:
        migrated.write(port=proxy.port)
        calls = _Calls()
        follower = Follower([("demo_rows", "p1"), ("demo_runs", "p1")],
                            application_name="follower")
        stop, thread = _running(follower, calls, interval=0.2)
        try:
            calls.wait(5)
            proxy.refuse = 10**6
            proxy.cut()
            time.sleep(1.0)
            _raise("demo_rows", "p1", setting=direct)
            _raise("demo_runs", "p1", setting=direct)
            _raise("demo_runs", "p1", setting=direct)
            time.sleep(1.0)
            assert len(calls.calls) == 1
            proxy.refuse = 0
            _at, moved = calls.wait(40)
            assert moved == {("demo_rows", "p1"): 1, ("demo_runs", "p1"): 2}
        finally:
            stop.set()
            thread.join(10)
    finally:
        disconnect(every=True)
        proxy.close()


def _round_trips(conn, path, run) -> int:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    conn.pgconn.trace(fd)
    try:
        run()
    finally:
        conn.pgconn.untrace()
        os.close(fd)
    sent = [line.split("\t")[3] for line in path.read_text().splitlines()
            if re.match(r"\d{4}-", line) and line.split("\t")[1] == "F"]
    return sum(1 for message in sent if message in ("Query", "Sync"))


@pytest.mark.parametrize("count", [1, 10, 500])
def test_one_poll_is_one_round_trip_whatever_the_number_of_channels(migrated, tmp_path,
                                                                    count):
    follow = [(f"demo_c{n}", f"p{n % 7}") for n in range(count)] + ["demo_jobs"]
    for channel, scope in follow[: min(count, 20)]:
        _raise(channel, scope)
    follower = Follower(follow, application_name="follower")
    with connect(application_name="follower", transaction=True) as conn:
        pass  # the working connection every later poll is lent
    assert _round_trips(conn, tmp_path / "first.trace", follower.poll) == 1
    _raise(*follow[0])
    moved = {}
    assert _round_trips(conn, tmp_path / "next.trace",
                        lambda: moved.update(follower.poll())) == 1
    assert moved == {follow[0]: 2}


def test_a_follower_given_the_connection_its_process_holds_polls_on_it_and_opens_no_other(
        migrated, server, tmp_path):
    follower = Follower([("demo_rows", "p1")], application_name="follower")
    moved = {}
    with connect(application_name="held", transaction=True) as conn:
        conn.autocommit = True
        assert _round_trips(conn, tmp_path / "first.trace",
                            lambda: moved.update(follower.poll(conn))) == 1
        assert moved == {("demo_rows", "p1"): 0}
        _raise("demo_rows", "p1")
        disconnect()  # the writer's loan, so only what the follower opens is left
        moved.clear()
        assert _round_trips(conn, tmp_path / "next.trace",
                            lambda: moved.update(follower.poll(conn))) == 1
        assert moved == {("demo_rows", "p1"): 1}
        assert not conn.closed
        with server.admin() as admin:
            assert admin.execute(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = %s "
                "AND backend_type = 'client backend' AND pid <> pg_backend_pid()",
                (conn.info.dbname,)).fetchone()[0] == 1


def test_announce_and_follow_refuse_what_they_cannot_name(migrated):
    with connect(application_name="writer", transaction=True) as conn:
        for channel, scope in (("Demo", "p1"), ("", "p1"), ("demo_rows", ""),
                               ("demo_rows", None)):
            with pytest.raises(DbError) as caught:
                announce(conn, channel, scope)
            assert caught.value.slug in ("bad_channel", "bad_scope")
    for follow in ([], [("demo_rows",)], ["Demo"]):
        with pytest.raises(DbError) as caught:
            Follower(follow, application_name="follower")
        assert caught.value.slug in ("bad_follow", "bad_channel")


def test_a_store_without_the_table_is_refused_as_not_migrated(store):
    follower = Follower(["demo_rows"], application_name="follower")
    with connect(application_name="bare", transaction=True) as conn:
        conn.execute(f'CREATE SCHEMA "{store.schema}"')
        conn.commit()
    with pytest.raises(DbError) as caught:
        follower.poll()
    assert caught.value.slug == "not_migrated"
