"""Changes a process follows by polling, with no session held for it.

A change is announced as a version: the platform table `schema_channel` keeps one
row per channel and scope, and a writer raises that row's version inside its own
transaction, so the raise is seen exactly when the change it announces is
committed, and never when the transaction rolls back. A follower reads the
versions it follows in one query, on the process's working connection, and
reports only those that moved since it last read them. Neither side holds state
in the session, so both work through a transaction-mode pooler.
"""

from __future__ import annotations

import contextlib
import re
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

from capabilities_contract.db._connect import _psycopg, bound_schema, connect
from capabilities_contract.db._errors import DbError
from capabilities_contract.db._setting import Setting, check_schema_name, resolve_setting

CHANNEL_TABLE = "schema_channel"

# A follower's run polls this often unless told otherwise.
FOLLOW_INTERVAL_SECONDS = 1.0

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
    rolled back with it. The row stays locked until the transaction ends, so
    writers that announce one channel and scope take turns at that row; announce
    last, just before the commit, to hold it for the shortest time."""
    psycopg, sql = _psycopg()
    channel, scope = check_channel(channel), check_scope(scope)
    query = sql.SQL(
        "INSERT INTO {t} AS c (channel, scope, version) VALUES (%s, %s, 1) "
        "ON CONFLICT (channel, scope) DO UPDATE SET version = c.version + 1 "
        "RETURNING version").format(t=_table(conn))
    try:
        return conn.execute(query, (channel, scope)).fetchone()[0]
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
    every version it reads."""

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
        moved meanwhile."""
        psycopg, _ = _psycopg()
        if not interval > 0:
            raise DbError("bad_interval", f"interval {interval!r} is not a positive number")
        stop = stop if stop is not None else threading.Event()
        first = True
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
            stop.wait(max(0.0, interval - (time.monotonic() - started)))
