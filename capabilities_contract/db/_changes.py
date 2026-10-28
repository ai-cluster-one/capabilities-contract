"""Changes a process follows by polling, with no session needed for it.

A change is announced as a version: the platform table `schema_channel` keeps one
row per channel and scope, and a writer raises that row's version inside its own
transaction, so the raise is seen exactly when the change it announces is
committed, and never when the transaction rolls back. A follower reads the
versions it follows in one query, on the process's working connection, and
reports only those that moved since it last read them. Neither side needs state
in the session, so both work through a transaction-mode pooler.

The raise also notifies the channel, in the same transaction, so it is sent when
the change commits. Where the setting names the store's two addresses apart, a
follower listens on the followed channels on a session connection of its own and
polls as soon as one is notified rather than at its next interval; the listener
only hastens a poll, so one that cannot be opened or is lost costs nothing but
that, and it is tried again no more often than every LISTEN_RETRY_SECONDS. With
one address, a follower polls only.
"""

from __future__ import annotations

import contextlib
import math
import re
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from capabilities_contract.db._connect import (
    CONNECT_TIMEOUT_SECONDS,
    _psycopg,
    bound_schema,
    connect,
)
from capabilities_contract.db._errors import DbError
from capabilities_contract.db._setting import Setting, check_schema_name, resolve_setting

CHANNEL_TABLE = "schema_channel"

# A follower's run polls this often unless told otherwise.
FOLLOW_INTERVAL_SECONDS = 1.0

# A follower's listener that could not be opened, or was lost, is not tried again
# before this many seconds have passed.
LISTEN_RETRY_SECONDS = 30.0

# A follower waiting on its listener looks at its stop event this often.
_STOP_CHECK_SECONDS = 0.2

# The longest payload a notification carries, in bytes; a longer scope is sent as
# an empty payload, since only the channel wakes a follower.
_PAYLOAD_LIMIT = 7999

_CHANNEL = re.compile(r"[a-z][a-z0-9_]{0,62}")

Key = tuple[str, str]


def check_channel(channel: object) -> str:
    if not isinstance(channel, str) or not _CHANNEL.fullmatch(channel):
        raise DbError("bad_channel", f"channel {channel!r} is not a lowercase identifier",
                      "use lowercase letters, digits and '_', starting with a letter, "
                      "at most 63 characters, such as <owner>_<event>")
    return channel


def check_scope(scope: object) -> str:
    if not isinstance(scope, str) or not scope:
        raise DbError("bad_scope", f"scope {scope!r} is not a non-empty string",
                      "name what the change is about, such as a project id")
    return scope


def _table(conn: Any) -> Any:
    _, sql = _psycopg()
    schema = check_schema_name(bound_schema(conn))
    return sql.SQL("{}.{}").format(sql.Identifier(schema), sql.Identifier(CHANNEL_TABLE))


def _missing() -> DbError:
    return DbError("not_migrated", f"the store has no {CHANNEL_TABLE} table",
                   "run migrate with this library version once, as a role that may create "
                   "in the schema; it creates the table")


def announce(conn: Any, channel: str, scope: str) -> int:
    """Raise the version of `channel` for `scope` and return the new version.

    Call it inside the writer's own transaction, on a connection from `connect`,
    after the change it announces: the raise is committed with that change and
    rolled back with it. The same statement notifies `channel` with `scope` as
    the payload (`pg_notify`), which the store sends when the transaction
    commits and never when it rolls back. The row stays locked until the
    transaction ends, so writers that announce one channel and scope take turns
    at that row; announce last, just before the commit, to hold it for the
    shortest time."""
    psycopg, sql = _psycopg()
    channel, scope = check_channel(channel), check_scope(scope)
    payload = scope if len(scope.encode()) <= _PAYLOAD_LIMIT else ""
    query = sql.SQL(
        "WITH raised AS (INSERT INTO {t} AS c (channel, scope, version) VALUES (%s, %s, 1) "
        "ON CONFLICT (channel, scope) DO UPDATE SET version = c.version + 1 "
        "RETURNING version) "
        "SELECT version, pg_notify(%s, %s) FROM raised").format(t=_table(conn))
    try:
        return conn.execute(query, (channel, scope, channel, payload)).fetchone()[0]
    except psycopg.errors.UndefinedTable as exc:
        raise _missing() from exc


class Follower:
    """Follows the versions of some channels and reports those that moved.

    `follow` names what is followed: each item a `(channel, scope)` pair, or a
    channel alone, meaning every scope of it. A pair that was never announced
    reads as version 0. Each `poll` is one query on the process's working
    connection, whatever the number of channels, or on the connection the
    caller passes, so a process that holds its own needs no second one.

    `seen`, the versions a previous follower held (its `seen`), makes the first
    poll report only what moved since then; without it the first poll reports
    every version it reads.

    `wait` waits between polls, and returns early when a followed channel is
    notified, where the setting names the store's two addresses apart; then the
    follower holds a session connection of its own for listening until `close()`
    or the end of a `with` block."""

    def __init__(self, follow: Iterable[Key | str], *, application_name: str,
                 project_root: Path | str | None = None, setting: Setting | None = None,
                 seen: Mapping[Key, int] | None = None):
        pairs: list[Key] = []
        channels: list[str] = []
        for item in follow:
            if isinstance(item, str):
                channels.append(check_channel(item))
            elif isinstance(item, (tuple, list)) and len(item) == 2:
                pairs.append((check_channel(item[0]), check_scope(item[1])))
            else:
                raise DbError("bad_follow",
                              f"a followed item is a channel or a (channel, scope) pair, "
                              f"not {item!r}")
        if not pairs and not channels:
            raise DbError("bad_follow", "a follower follows at least one channel")
        self._pairs = list(dict.fromkeys(pairs))
        self._channels = list(dict.fromkeys(channels))
        self._application_name = application_name
        self._setting = setting if setting is not None else resolve_setting(project_root)
        self._seen: dict[Key, int] | None = dict(seen) if seen is not None else None
        self._listener: Any = None
        self._listen_tried = -math.inf

    def __enter__(self) -> Follower:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the listener, if one is open. A later `wait` may open it again."""
        listener, self._listener = self._listener, None
        if listener is not None:
            with contextlib.suppress(Exception):
                listener.close()

    def _listen(self, budget: float) -> Any:
        """The listener: a session connection listening on every followed
        channel, opened within about `budget` seconds where the setting names the
        store's two addresses apart; None where it does not, or where it cannot be
        opened now or was tried within LISTEN_RETRY_SECONDS."""
        if self._listener is not None:
            return self._listener
        if not self._setting.has_transaction_address:
            return None
        now = time.monotonic()
        if now - self._listen_tried < LISTEN_RETRY_SECONDS:
            return None
        self._listen_tried = now
        conn = None
        try:
            _, sql = _psycopg()
            conn = connect(application_name=self._application_name, setting=self._setting,
                           connect_timeout=max(2, min(CONNECT_TIMEOUT_SECONDS,
                                                      math.ceil(budget))))
            conn.autocommit = True
            for channel in dict.fromkeys([c for c, _ in self._pairs] + self._channels):
                conn.execute(sql.SQL("LISTEN {}").format(sql.Identifier(channel)))
        except Exception:
            if conn is not None:
                with contextlib.suppress(Exception):
                    conn.close()
            return None
        self._listener = conn
        return conn

    def wait(self, seconds: float, stop: threading.Event | None = None) -> bool:
        """Wait `seconds`, or until `stop` is set; return True as soon as the store
        notifies a followed channel, else False.

        Only where the setting names the store's two addresses apart does it
        listen, on a session connection of its own, opened at the first wait;
        otherwise it waits out the time. A listener that cannot be opened or is
        lost never fails the wait: it waits out the time, and the listener is
        tried again no more often than every LISTEN_RETRY_SECONDS. A
        notification sent before the listener was open is not seen; the next
        poll sees its change."""
        deadline = time.monotonic() + max(0.0, seconds)

        def stopped() -> bool:
            return stop is not None and stop.is_set()

        def rest() -> bool:
            left = deadline - time.monotonic()
            if left > 0:
                if stop is not None:
                    stop.wait(left)
                else:
                    time.sleep(left)
            return False

        if stopped():
            return False
        listener = self._listen(seconds)
        if listener is None:
            return rest()
        try:
            while not stopped():
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                step = min(left, _STOP_CHECK_SECONDS) if stop is not None else left
                if list(listener.notifies(timeout=step, stop_after=1)):
                    # Those already come wake the same poll.
                    list(listener.notifies(timeout=0))
                    return True
            return False
        except Exception:
            self.close()
            return rest()

    @property
    def seen(self) -> dict[Key, int]:
        """The versions as last read, to hand to a later follower."""
        return dict(self._seen or {})

    def read(self, conn: Any = None) -> dict[Key, int]:
        """Every followed version as the store holds it now, in one round trip.

        With `conn`, a connection from `connect` that the caller already works
        on, the query runs on it and it is left open, in whatever transaction it
        was in; without it, on a loan of the process's working connection."""
        psycopg, sql = _psycopg()
        with contextlib.ExitStack() as stack:
            if conn is None:
                conn = stack.enter_context(connect(
                    application_name=self._application_name, setting=self._setting,
                    transaction=True))
            query = sql.SQL(
                "SELECT channel, scope, version FROM {t} "
                "WHERE (channel, scope) IN (SELECT * FROM unnest(%s::text[], %s::text[])) "
                "OR channel = ANY(%s::text[])").format(t=_table(conn))
            try:
                rows = conn.execute(query, ([c for c, _ in self._pairs],
                                            [s for _, s in self._pairs],
                                            self._channels)).fetchall()
            except psycopg.errors.UndefinedTable as exc:
                raise _missing() from exc
        current = dict.fromkeys(self._pairs, 0)
        current.update({(channel, scope): version for channel, scope, version in rows})
        return current

    def poll(self, conn: Any = None) -> dict[Key, int]:
        """The followed versions that moved since the last poll, with their new
        versions; on the first poll without `seen`, every version read. `conn`
        is polled on as `read` takes it."""
        current = self.read(conn)
        if self._seen is None:
            moved = current
        else:
            moved = {key: version for key, version in current.items()
                     if self._seen.get(key, 0) != version}
        self._seen = {**(self._seen or {}), **current}
        return moved

    def run(self, on_change: Callable[[dict[Key, int]], Any], *,
            interval: float = FOLLOW_INTERVAL_SECONDS,
            stop: threading.Event | None = None) -> None:
        """Poll every `interval` seconds until `stop` is set, calling `on_change`
        with what moved: always once for the first poll, even when nothing
        moved, so the caller reads its state after the versions it starts from
        and misses nothing that follows; afterwards only when something moved.
        A poll that finds the store unreachable is tried again at the next
        interval, and the first poll that reaches it reports everything that
        moved meanwhile. Between polls it waits with `wait`, so where the store's
        two addresses are named apart a notified channel is polled at once; the
        listener opens before the first poll and is closed when `run` returns."""
        psycopg, _ = _psycopg()
        if not interval > 0:
            raise DbError("bad_interval", f"interval {interval!r} is not a positive number")
        stop = stop if stop is not None else threading.Event()
        first = True
        try:
            # Listening before the first poll, a change after it wakes the next.
            self._listen(interval)
            while not stop.is_set():
                started = time.monotonic()
                try:
                    moved = self.poll()
                except DbError as exc:
                    if exc.slug != "store_unreachable":
                        raise
                except psycopg.OperationalError:
                    pass
                else:
                    if moved or first:
                        on_change(moved)
                    first = False
                self.wait(max(0.0, interval - (time.monotonic() - started)), stop)
        finally:
            self.close()
