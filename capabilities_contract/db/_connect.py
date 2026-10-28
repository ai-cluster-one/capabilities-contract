"""A connection bound to the configured schema. psycopg is imported here, lazily.

A store has a transaction address and, unless it is transaction-only - its one address
a known transaction pooler - a session address; the two are one address unless its
setting names a transaction address apart.
A session connection binds the schema for its session and may hold session state:
`LISTEN`, session advisory locks, session settings. A transaction connection carries no
session state at all, so it works through a transaction-mode pooler: psycopg prepares
no statement on it, and the schema is bound with `SET LOCAL` at the start of every
transaction rather than once for the session.

Because a transaction connection carries no session state, one serves every operation
of a process: it is the process's working connection. It is opened on the first
`connect(..., transaction=True)` and lent to each later one; `close()` ends the loan
and keeps it for the next, and it is closed when the process exits. A loan taken while
another is still out gets a working connection of its own. A connect that fails is
tried again after a short jittered pause, a store that still did not answer is not
dialled again before a doubling pause has passed, and a statement that finds its
connection gone before anything of its transaction reached the store runs again on a
new one.

A statement that would open a transaction and is one of its own - any statement in
autocommit, a plain read otherwise - reaches the store in one round trip, its
transaction's start, binding and commit with it, and leaves the connection idle; a
transaction-mode pooler then hands the server session on as soon as it answers.
`batch` sends independent statements as one pipeline, answered in one round trip."""

from __future__ import annotations

import contextlib
import functools
import math
import os
import random
import re
import sys
import threading
import time
import weakref
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from capabilities_contract.db._errors import DbError
from capabilities_contract.db._setting import (
    SESSION_POOLER_PORT,
    SUPABASE_POOLER_DOMAIN,  # noqa: F401 - kept importable here, where it was defined
    TRANSACTION_POOLER_PORT,
    Setting,
    check_schema_name,
    resolve_setting,
)

# The schema each connection from `connect` is bound to, so `migrate` needs no
# second argument naming it.
_BOUND: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()

# A connect that gets no answer gives up after CONNECT_TIMEOUT_SECONDS. Both ends
# probe an idle connection: after KEEPALIVE_IDLE_SECONDS without traffic, every
# KEEPALIVE_INTERVAL_SECONDS, giving up after KEEPALIVE_COUNT unanswered probes,
# so the store drops a client that died without closing and the client learns
# of a store that went away. Probes never go out while sent data waits for its
# acknowledgement, so the client also gives the connection up once what it sent
# has gone unacknowledged for TCP_USER_TIMEOUT_MILLISECONDS: a flow that stopped
# carrying packets fails in that time rather than when the store ends the session.
CONNECT_TIMEOUT_SECONDS = 10
KEEPALIVE_IDLE_SECONDS = 15
KEEPALIVE_INTERVAL_SECONDS = 5
KEEPALIVE_COUNT = 3
TCP_USER_TIMEOUT_MILLISECONDS = 20000

# A connect that fails before the store answers - refused, reset, timed out - is tried
# again after a short pause, at most CONNECT_ATTEMPTS times, while CONNECT_TIMEOUT
# seconds are not spent: each try waits at most half of them, so a try that hangs
# leaves time for one more. A store that answers with a refusal of its own - a
# password, a database that is not there - is not tried again.
CONNECT_ATTEMPTS = 3
CONNECT_PAUSE_SECONDS = 0.25

# After a connect to an address that no store answered, a further connect to it
# is refused at once as `store_unreachable` for a pause drawn between half and
# all of RECONNECT_FIRST_SECONDS, doubling with each failure in a row up to
# RECONNECT_LONGEST_SECONDS; the first connect after the pause dials again.
RECONNECT_FIRST_SECONDS = 1.0
RECONNECT_LONGEST_SECONDS = 30.0

# The working connection: a loan of one that sat idle for PING_AFTER_SECONDS proves it
# still answers with one round trip, cut at the connect timeout. Each working
# connection beyond the first kept for the same address is closed once it sits idle
# for SPARE_IDLE_SECONDS.
PING_AFTER_SECONDS = 10
SPARE_IDLE_SECONDS = 30


def _psycopg():
    try:
        import psycopg
        from psycopg import sql
    except ImportError as exc:  # pragma: no cover - depends on the installed wheels
        raise DbError("driver_missing", "psycopg is not installed",
                      "depend on capabilities-contract, which brings psycopg[binary]") from exc
    return psycopg, sql


def bind_search_path(conn: Any, schema: str) -> None:
    """Set the session's search_path to `schema` alone. On a transaction connection,
    which keeps no session state, the open transaction's search_path is set instead,
    and outside a transaction nothing is sent: the next transaction binds it."""
    if isinstance(conn, _transaction_class()):
        conn._bind_now(schema)
        return
    _, sql = _psycopg()
    conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))


# Statements that leave state in the session, refused on a transaction connection: a
# pooler in transaction mode hands the session to another client after the transaction.
_SESSION_STATE = re.compile(
    r"^\s*(?:LISTEN|UNLISTEN|PREPARE)\b"
    r"|^\s*DECLARE\b.*\bWITH\s+HOLD\b"
    r"|^\s*SET\s+(?!LOCAL\b|TRANSACTION\b|CONSTRAINTS\b)"
    r"|^\s*RESET\b"
    r"|\bpg_(?:try_)?advisory_lock(?:_shared)?\s*\("
    r"|\bset_config\s*\([^;]*,\s*(?:false|'f'|'false')\s*\)",
    re.IGNORECASE | re.DOTALL)

# A plain read: a statement that only reads, under READ COMMITTED, where every
# statement sees the store as it is when it starts. A transaction that has run
# nothing else leaves nothing a later statement depends on, so a read it loses
# with its connection runs on a new one in a transaction of its own.
_READS = re.compile(r"^\s*(?:SELECT|WITH|VALUES|TABLE|SHOW)\b", re.IGNORECASE)
_NOT_ONLY_READS = re.compile(
    r"\b(?:INSERT|UPDATE|DELETE|MERGE|INTO|SHARE)\b"
    r"|nextval|setval|advisory|set_config|notify|lo_\w+|txid_current|xact_id|pg_sleep",
    re.IGNORECASE)


# The errors the store sends as it ends a session: an administrator ended it, the
# server is shutting down or crashed.
_SESSION_ENDED = ("57P01", "57P02", "57P03")


def _plain_read(text: str) -> bool:
    return bool(_READS.match(text)) and not _NOT_ONLY_READS.search(text)


_TRANSACTION_CLASS = None

# Startup options - libpq's `options`, from the setting or PGOPTIONS - reach a
# transaction connection as settings of each of its transactions, since a
# transaction-mode pooler refuses them at startup. A session default that only
# a new transaction reads also sets that transaction itself.
_FOR_THIS_TRANSACTION = {"default_transaction_read_only": "transaction_read_only",
                         "default_transaction_isolation": None,
                         "default_transaction_deferrable": None}


def _startup_settings(setting: Setting) -> tuple[tuple[str, str], ...]:
    """The run-time parameters the startup options of `setting` and PGOPTIONS
    name, as (name, value): `-c name=value`, `-cname=value` or `--name=value`.
    Any other startup option is refused, since a transaction connection could
    not carry it."""
    import os
    import shlex

    from psycopg.conninfo import conninfo_to_dict

    texts = []
    try:
        named = conninfo_to_dict(**setting.connect_kwargs()).get("options")
    except Exception:
        named = None
    for text in (os.environ.get("PGOPTIONS"), named):
        if text:
            texts.append(str(text))
    out: list[tuple[str, str]] = []
    for text in texts:
        words = shlex.split(text)
        i = 0
        while i < len(words):
            word = words[i]
            if word == "-c" and i + 1 < len(words):
                pair, i = words[i + 1], i + 2
            elif (word.startswith("-c") and len(word) > 2) or \
                    (word.startswith("--") and "=" in word):
                pair, i = word[2:], i + 1
            else:
                raise DbError("session_state",
                              f"the startup option {word!r} cannot reach a transaction "
                              "connection, which a transaction-mode pooler serves",
                              "name run-time parameters as -c name=value")
            name, eq, value = pair.partition("=")
            if not eq or not name:
                raise DbError("session_state", f"the startup option {pair!r} names no value")
            out.append((name.replace("-", "_"), value))
            target = _FOR_THIS_TRANSACTION.get(name.replace("-", "_"))
            if target is not None:
                out.append((target, value))
    return tuple(out)


def _transaction_class():
    """The connection class of the transaction path, made once psycopg is imported."""
    global _TRANSACTION_CLASS
    if _TRANSACTION_CLASS is not None:
        return _TRANSACTION_CLASS
    psycopg, sql = _psycopg()
    from psycopg import pq
    from psycopg.rows import tuple_row

    idle = pq.TransactionStatus.IDLE
    failed = pq.TransactionStatus.INERROR
    read_committed = psycopg.IsolationLevel.READ_COMMITTED

    def text_of(conn: Any, query: Any) -> str:
        if isinstance(query, bytes):
            return query.decode(errors="replace")
        if isinstance(query, str):
            return query
        try:
            return query.as_string(conn)
        except Exception:
            return ""

    class BindingCursor(psycopg.Cursor):
        """A cursor whose statements run with the connection's schema bound for the
        transaction they run in, and never leave state in the session."""

        def _check(self, query: Any) -> None:
            """Refuse, before anything is sent, a statement on a connection whose
            loan ended or one that would leave state in the session."""
            conn = self.connection
            if not conn._lent:
                raise psycopg.OperationalError("the connection is closed")
            if _SESSION_STATE.search(text_of(conn, query)):
                raise DbError("session_state",
                              "a transaction connection keeps no session state: LISTEN, "
                              "PREPARE, a session SET or set_config and a session advisory "
                              "lock belong on a session connection",
                              "open it with connect(..., transaction=False), or take a "
                              "transaction-level lock (pg_advisory_xact_lock)")

        def _ready(self, query: Any) -> None:
            self._check(query)
            self.connection._bind_transaction()

        def _again(self, conn: Any, err: BaseException) -> bool:
            """Whether a statement that failed with `err` runs again: its
            connection is gone, so nothing of its transaction stays in the
            store, and a new connection replaces it. Once per statement."""
            if not isinstance(err, psycopg.OperationalError) or not conn._gone(err):
                return False
            if not conn._renew():
                return False
            self._pgconn = conn.pgconn
            return True

        def _run(self, query: Any, call: Any, alone: Any = None) -> Any:
            conn = self.connection
            text = text_of(conn, query)
            plain = _plain_read(text)
            # A statement that would open a transaction and runs as one of its
            # own - any statement in autocommit, a plain read otherwise - goes
            # to the store with the transaction's start, its binding and its
            # commit in one round trip, and leaves the connection idle.
            if alone is not None and conn._stands_alone(plain):
                self._check(query)
                kind, run = alone
                return conn._alone([(self, run)], plain, pipelined=kind == "pipeline")
            for attempt in (0, 1):
                if conn.autocommit and conn.info.transaction_status == idle:
                    # Autocommit runs each statement as its own transaction, which a
                    # SET LOCAL cannot reach; run it in one that binds the schema
                    # first. Its commit may have reached the store when the
                    # connection breaks, so a failed commit never runs it again.
                    sent = False
                    try:
                        with conn.transaction():
                            self._ready(query)
                            if not plain:
                                conn._reads_only = False
                            # The block may have begun on a new connection.
                            self._pgconn = conn.pgconn
                            out = call()
                            sent = True
                        return out
                    except psycopg.OperationalError as err:
                        if attempt or sent or not self._again(conn, err):
                            raise
                    continue
                # A statement that opens its transaction runs again on a new
                # connection when the old one is gone: the store rolls back a
                # transaction that never committed. So does a plain read in a
                # transaction that has only read, inside `transaction()` blocks
                # too: the new connection opens the blocks again before it.
                opens = conn.info.transaction_status == idle
                reads = (not opens and plain and conn._reads_only
                         and conn.isolation_level in (None, read_committed))
                try:
                    self._ready(query)
                    if not plain:
                        conn._reads_only = False
                    return call()
                except psycopg.OperationalError as err:
                    if attempt or not (opens or reads) or not self._again(conn, err):
                        raise
            raise AssertionError("unreachable")

        def execute(self, query, params=None, **kwargs):
            sup = super()
            alone = None
            if isinstance(query, (str, bytes, sql.Composable)) and text_of(
                    self.connection, query).strip():
                if not kwargs.get("binary") and self.format != pq.Format.BINARY and (
                        params is None or (not params and "%" not in text_of(
                            self.connection, query))):
                    # Sent as a simple query behind the binding: one message.
                    alone = ("simple", functools.partial(
                        self._simple_behind_binding, query, kwargs))
                elif psycopg.Pipeline.is_supported():
                    alone = ("pipeline", lambda: sup.execute(query, params, **kwargs))
            return self._run(query, lambda: sup.execute(query, params, **kwargs), alone)

        def _simple_behind_binding(self, query: Any, kwargs: dict) -> None:
            """Run `query`, which takes no parameter, as one simple query behind
            the binding, so the store answers both in one round trip as one
            implicit transaction; the cursor then stands on the query's own
            first result."""
            conn = self.connection
            if isinstance(query, bytes):
                body = query
            elif isinstance(query, str):
                body = sql.SQL(query).as_bytes(conn)
            else:
                body = query.as_bytes(conn)
            psycopg.Cursor.execute(self, conn._binding().as_bytes(conn) + b";\n" + body,
                                   None, **kwargs)
            self.nextset()
            return self

        def executemany(self, query, params_seq, **kwargs):
            sup = super()
            params_seq = list(params_seq)
            alone = None
            if psycopg.Pipeline.is_supported():
                alone = ("pipeline", lambda: sup.executemany(query, params_seq, **kwargs))
            return self._run(query, lambda: sup.executemany(query, params_seq, **kwargs),
                             alone)

        def stream(self, query, params=None, **kwargs):
            self._ready(query)
            return super().stream(query, params, **kwargs)

        def copy(self, statement, params=None, **kwargs):
            self._ready(statement)
            return super().copy(statement, params, **kwargs)

    class TransactionConnection(psycopg.Connection):
        """A connection of the transaction path: the schema bound with SET LOCAL at
        the start of each transaction, no prepared statements, no session state."""

        _bound_schema: str = ""
        _bound_now: bool = False
        _local_settings: tuple = ()
        # Whether the open transaction has run only plain reads.
        _reads_only: bool = False
        # The open `transaction()` blocks, outermost first.
        _blocks: list | None = None  # set per connection when it is opened

        def _binding(self) -> Any:
            """One statement setting, for the open transaction only, the
            search_path to the schema and each of the connection's local
            settings."""
            # The schema is a checked lowercase identifier, which search_path
            # reads as itself without quotes.
            parts = [sql.SQL("set_config('search_path', {}, true)").format(
                sql.Literal(self._bound_schema))]
            parts += [sql.SQL("set_config({}, {}, true)").format(
                sql.Literal(name), sql.Literal(value))
                for name, value in self._local_settings]
            return sql.SQL("SELECT ") + sql.SQL(", ").join(parts)

        def _bind_now(self, schema: str | None = None) -> None:
            if schema is not None:
                self._bound_schema = schema
            if self.info.transaction_status == idle:
                self._bound_now = False
                return
            psycopg.Cursor(self).execute(self._binding())
            self._bound_now = True

        def _bind_transaction(self) -> None:
            status = self.info.transaction_status
            if status == idle:
                self._bound_now = False
                if self.autocommit:
                    return
                # The statement about to run opens the transaction: open it here,
                # bound, so the statement runs inside it.
                psycopg.Cursor(self).execute(self._binding())
                self._bound_now = True
                self._reads_only = True
                return
            if status == failed or self._bound_now:
                return
            self._bind_now()

        # -- a statement as a transaction of its own -------------------------------

        def _stands_alone(self, plain: bool) -> bool:
            """Whether a statement runs as a transaction of its own, in one round
            trip: it would open a transaction, and either autocommit asks for one
            per statement or it is a plain read at READ COMMITTED, which sees the
            store as it is when it starts whatever transaction it runs in."""
            return (self._pipeline is None
                    and self.info.transaction_status == idle
                    and (self.autocommit or plain)
                    and self.isolation_level in (None, read_committed)
                    and self.read_only is None and self.deferrable is None)

        def _lost_unasked(self) -> bool:
            """Whether the idle connection is gone already, known without a round
            trip: the store or the network closed it, or the store said something
            unasked, which on an idle connection that listens to nothing is its
            farewell - the error it sends as it ends the session."""
            if self.pgconn.status == psycopg.pq.ConnStatus.BAD:
                return True
            try:
                return _readable(self.pgconn.socket)
            except Exception:
                return True

        def _alone(self, runs: list, plain: bool, *, pipelined: bool) -> Any:
            """Run each `(cursor, send)` of `runs` as one transaction of its own:
            the schema bound, the statements and the commit reach the store
            together and the store answers once, leaving the connection idle.
            `pipelined` sends them as a pipeline behind the binding; otherwise
            the one `send` carries the binding itself, as one simple query.

            A connection found gone before anything is sent is replaced first.
            A plain read that loses its connection runs once more on a new one;
            anything else does once only when its commit was never sent, since a
            commit that reached the store is never sent twice."""
            for attempt in (0, 1):
                self._take_due()
                if self._lost_unasked():
                    self._renew()
                was, self._autocommit = self._autocommit, True
                committed = False
                out = None
                try:
                    if not pipelined:
                        cursor, send = runs[0]
                        cursor._pgconn = self.pgconn
                        committed = True  # one message: its commit goes with it
                        return send()
                    block = self.pipeline()
                    block.__enter__()
                    try:
                        psycopg.Cursor(self).execute(self._binding())
                        for cursor, send in runs:
                            cursor._pgconn = self.pgconn
                            got = send()
                            out = got if out is None else out
                    except BaseException:
                        with contextlib.suppress(Exception):
                            block.__exit__(None, None, None)
                        raise
                    committed = True  # the sync commits what the pipeline ran
                    block.__exit__(None, None, None)
                    return out
                except psycopg.OperationalError as err:
                    if attempt or (committed and not plain) or not self._gone(err) \
                            or not self._renew():
                        raise
                finally:
                    self._autocommit = was
                    self._bound_now = False
            raise AssertionError("unreachable")

        def _together(self, statements: list) -> list:
            """The rows of each `(query, params)` of `statements`, sent as one
            pipeline and answered in one round trip, with the schema bound: as a
            transaction of its own where each would open one alone, else inside
            the transaction that is open, or that the first of them opens."""
            cursors = [self.cursor() for _ in statements]
            for cursor, (query, _params) in zip(cursors, statements, strict=True):
                cursor._check(query)
            plain = all(_plain_read(text_of(self, query)) for query, _p in statements)

            def sender(cursor: Any, query: Any, params: Any) -> Any:
                return lambda: psycopg.Cursor.execute(cursor, query, params)

            runs = [(cursor, sender(cursor, query, params))
                    for cursor, (query, params) in zip(cursors, statements, strict=True)]
            if self._stands_alone(plain):
                self._alone(runs, plain, pipelined=True)
            elif self.info.transaction_status == idle and self.autocommit:
                # Autocommit at another isolation level: one transaction each.
                for cursor, (query, params) in zip(cursors, statements, strict=True):
                    cursor.execute(query, params)
            else:
                self._in_pipeline(runs)
            return [cursor.fetchall() if cursor.description is not None else []
                    for cursor in cursors]

        def _in_pipeline(self, runs: list) -> None:
            """Send `runs` as one pipeline inside the open transaction, or
            inside the one it opens, bound, which stays open for the caller's
            commit. Opening it runs again on a new connection when this one is
            gone, since nothing of it was committed."""
            for attempt in (0, 1):
                opens = self.info.transaction_status == idle
                if opens:
                    self._take_due()
                    if self._lost_unasked():
                        self._renew()
                was, self._autocommit = self._autocommit, True
                try:
                    block = self.pipeline()
                    block.__enter__()
                    try:
                        if opens:
                            self._bound_now = False
                            self.wait(self._exec_command(self._get_tx_start_command()))
                        if not self._bound_now:
                            psycopg.Cursor(self).execute(self._binding())
                            self._bound_now = True
                        for cursor, send in runs:
                            cursor._pgconn = self.pgconn
                            send()
                    except BaseException:
                        with contextlib.suppress(Exception):
                            block.__exit__(None, None, None)
                        raise
                    block.__exit__(None, None, None)
                    if opens:
                        self._reads_only = False
                    return
                except psycopg.OperationalError as err:
                    if attempt or not opens or not self._gone(err) or not self._renew():
                        raise
                finally:
                    self._autocommit = was
            raise AssertionError("unreachable")

        @contextmanager
        def transaction(self, savepoint_name=None, force_rollback=False):
            # The block reads the connection as it opens: take a due new one first.
            self._take_due()
            outer = self.info.transaction_status == idle
            for attempt in (0, 1):
                if outer:
                    self._bound_now = False
                block = super().transaction(savepoint_name, force_rollback)
                try:
                    tx = block.__enter__()
                except psycopg.OperationalError as err:
                    # Nothing of the block reached the store: run it on a new
                    # connection when this one is gone.
                    if attempt or not outer or not self._gone(err) or not self._renew():
                        raise
                    continue
                try:
                    if outer:
                        self._bind_now()
                        self._reads_only = True
                except psycopg.OperationalError as err:
                    with contextlib.suppress(Exception):
                        block.__exit__(type(err), err, err.__traceback__)
                    if attempt or not self._gone(err) or not self._renew():
                        raise
                    continue
                break
            # The block, as a new connection would open it again: the outer one
            # with BEGIN, an inner one with its savepoint.
            self._blocks.append(tx)
            try:
                yield tx
            except BaseException:
                self._blocks.pop()
                if not block.__exit__(*sys.exc_info()):
                    raise
            else:
                self._blocks.pop()
                try:
                    block.__exit__(None, None, None)
                except psycopg.OperationalError as err:
                    # A transaction that has only read has nothing to commit.
                    if not (self._gone(err) and self._reads_only):
                        raise
                    self._renew_now()
            finally:
                if self.info.transaction_status == idle:
                    self._bound_now = False

        def commit(self) -> None:
            """Commit the open transaction. One that has only read has nothing
            to commit, so its connection being gone is not refused."""
            try:
                super().commit()
            except psycopg.OperationalError as err:
                if not (self._gone(err) and self._reads_only):
                    raise
                self._renew_now()
            finally:
                self._bound_now = False

        def rollback(self) -> None:
            """Roll back the open transaction. On a connection that is gone the
            store has rolled it back already, so there is nothing to refuse, and
            a new connection takes its place when the next statement comes."""
            ended = False
            try:
                super().rollback()
            except psycopg.OperationalError as err:
                if not self._gone(err):
                    raise
                ended = True
            finally:
                self._bound_now = False
            self._renew_due = ended or self._gone()

        # -- the working connection ------------------------------------------------

        # Whether the connection is lent: between its `connect` and its `close`.
        _lent: bool = False
        # The address it is kept under, the arguments it was opened with, the
        # process that opened it, and since when it sits idle.
        _key: str = ""
        _opened_with: tuple = ()
        _pid: int = 0
        _idle_since: float = 0.0
        _startup_name: str = ""

        @property
        def closed(self) -> bool:
            """True once `close()` ended the loan, as for any closed connection."""
            return not self._lent or super().closed

        # Set by a rollback on a connection that is gone: nothing of a
        # transaction is pending, so the next statement may take a new one.
        _renew_due: bool = False

        def _renew_now(self) -> None:
            """After a read-only transaction's commit on a lost connection: the
            caller carries on, so the new connection is taken at once, idle as
            after any commit; when the store does not answer, at the next
            statement."""
            if not self._renew():
                self._renew_due = True

        def _take_due(self) -> None:
            if self._renew_due and self._lent:
                self._renew_due = False
                self._renew()

        def _check_connection_ok(self) -> None:
            if not self._lent:
                raise psycopg.OperationalError("the connection is closed")
            self._take_due()
            super()._check_connection_ok()

        def _gone(self, err: BaseException | None = None) -> bool:
            """Whether the connection is lost: broken, ended by the store with
            `err`, the error it sends as it closes the session, or failed with
            `err` below any answer of the store's - the network gave way under
            the driver before libpq marked the connection broken."""
            if err is not None and isinstance(err, psycopg.OperationalError):
                state = getattr(err, "sqlstate", None)
                if state in _SESSION_ENDED or not state:
                    return True
            return self.pgconn.status == psycopg.pq.ConnStatus.BAD

        def _renew(self) -> bool:
            """Take a new connection to the same address in place of this one,
            which is gone. False, and this one left as it is, when the store
            cannot be reached."""
            kwargs, own_address, budget = self._opened_with
            try:
                fresh = _open_transaction(kwargs, own_address, budget)
            except DbError:
                return False
            old = self.pgconn
            pgconn = fresh.pgconn
            mine = weakref.ref(self)
            pgconn.notice_handler = functools.partial(psycopg.Connection._notice_handler, mine)
            pgconn.notify_handler = functools.partial(psycopg.Connection._notify_handler, mine)
            # The fresh object no longer owns the link it opened.
            fresh._pool = None
            self.pgconn = pgconn
            self._num_transactions = 0
            self._prepared = type(self._prepared)()
            self._bound_now = False
            with contextlib.suppress(Exception):
                old.finish()
            if not self._blocks:
                return True
            # Open again the blocks the caller is inside: its transaction, bound,
            # and each savepoint, so the blocks end on this connection as they
            # would have on the old one.
            try:
                with self.lock:
                    self.wait(self._exec_command(self._get_tx_start_command()))
                psycopg.Cursor(self).execute(self._binding())
                self._bound_now = True
                for block in self._blocks:
                    # Each block ends on the connection it now runs on.
                    block.pgconn = pgconn
                    if block.savepoint_name:
                        with self.lock:
                            self.wait(self._exec_command(sql.SQL("SAVEPOINT {}").format(
                                sql.Identifier(block.savepoint_name))))
            except psycopg.Error:
                return False
            self._num_transactions = len(self._blocks)
            return True

        def close(self) -> None:
            """End the loan. The connection is kept, idle and outside any
            transaction, for the next loan in this process; one that broke is
            closed instead."""
            if not self._lent:
                return
            keep = self._pid == os.getpid() and not self._gone()
            if keep:
                try:
                    if self.info.transaction_status != idle:
                        self.rollback()
                    self.autocommit = False
                    self.read_only = None
                    self.isolation_level = None
                    self.deferrable = None
                    self.row_factory = tuple_row
                    self.cursor_factory = BindingCursor
                    self.prepare_threshold = None
                    self._adapters = None
                    self._notice_handlers.clear()
                    self._notify_handlers.clear()
                    keep = self.info.transaction_status == idle
                except Exception:
                    keep = False
            self._lent = False
            self._renew_due = False
            self._blocks = []
            _BOUND.pop(self, None)
            if keep:
                _keep(self)
            else:
                _finish(self)

    TransactionConnection.BindingCursor = BindingCursor
    _TRANSACTION_CLASS = TransactionConnection
    return TransactionConnection


def _readable(fd: int) -> bool:
    """Whether `fd` has something to read now, without waiting."""
    import select

    if hasattr(select, "poll"):
        poller = select.poll()
        poller.register(fd, select.POLLIN | select.POLLERR | select.POLLHUP)
        return bool(poller.poll(0))
    ready, _w, _x = select.select([fd], [], [], 0)
    return bool(ready)


def _keepalives(conn: Any) -> None:
    """Ask the server to probe this client as the client probes the server. Over a
    Unix socket the server ignores the settings."""
    for name, value in (("tcp_keepalives_idle", KEEPALIVE_IDLE_SECONDS),
                        ("tcp_keepalives_interval", KEEPALIVE_INTERVAL_SECONDS),
                        ("tcp_keepalives_count", KEEPALIVE_COUNT)):
        conn.execute("SELECT set_config(%s, %s, false)", (name, str(value)))


def _refuse_transaction_pooler(setting: Setting) -> None:
    """Refuse, before anything is sent, a session connection to a known transaction
    pooler, which keeps no session between transactions: the store's session address
    is one, or the store's only address is, so it has no session address at all. A
    transaction connection may reach one."""
    found = setting._transaction_pooler_endpoint()
    if found is None:
        return
    host, port = found
    if not setting.has_transaction_address:
        raise DbError(
            "transaction_pooler",
            f"the store's only address, {host}:{port}, is Supabase's transaction pooler, "
            "which keeps no session between transactions, so a session connection - "
            "LISTEN, a session lock, a session setting - cannot be served there; the "
            "store serves transaction connections only",
            f"give the store a session address apart: Supabase's session pooler, the same "
            f"host, {host}, on port {SESSION_POOLER_PORT}, as its address, keeping port "
            f"{TRANSACTION_POOLER_PORT} as its transaction port (`capabilities store set "
            f"... --session-port {SESSION_POOLER_PORT}`)")
    raise DbError(
        "transaction_pooler",
        f"the store at {host}:{port} is Supabase's transaction pooler, which keeps "
        "no session between transactions, so the schema binding, prepared statements "
        "and notifications a session connection relies on are lost; it serves only "
        "as the store's transaction address",
        f"use Supabase's session pooler as the store's address: the same host, "
        f"{host}, on port {SESSION_POOLER_PORT}, and name port "
        f"{TRANSACTION_POOLER_PORT} as its transaction port")


def connect(*, application_name: str, project_root: Path | str | None = None,
            setting: Setting | None = None,
            connect_timeout: int = CONNECT_TIMEOUT_SECONDS,
            transaction: bool = False,
            local_settings: dict[str, str] | None = None) -> Any:
    """A psycopg connection to the database `resolve_setting(project_root)` names, or
    `setting` when given, with search_path set to its schema only (never `public`).
    The schema need not exist yet: `migrate` creates it. The connection is returned
    idle, outside any transaction.

    By default it is a session connection to the store's session address, its schema
    bound for the session. With `transaction` True it is a transaction connection to
    the store's transaction address, or to its one address when the setting names no
    transaction address, also when that address is a transaction pooler: psycopg
    prepares no statement on it, the schema is bound with `SET LOCAL` at the start
    of every transaction, and a statement that would leave
    state in the session (LISTEN, PREPARE, a session SET or set_config, a session
    advisory lock) is refused as `session_state` before it is sent.
    `local_settings`, run-time parameters such as `statement_timeout`, are set
    beside the schema for every transaction of a transaction connection, and
    once for the session of a session connection. A transaction connection
    sends no startup option: the run-time parameters the setting's `options`
    and PGOPTIONS name are set for each of its transactions instead, and
    `default_transaction_read_only` makes each of them read-only. A
    transaction connection at a transaction address of its own proves the
    store answers behind it within `connect_timeout`.

    On a transaction connection, a statement that would open a transaction and
    is one of its own - any statement in autocommit, or a plain read (a
    `SELECT`, `WITH`, `VALUES`, `TABLE` or `SHOW` naming no write, lock,
    sequence or setting) at READ COMMITTED - is sent with the schema binding
    and its commit as one message, or one pipeline where it takes parameters,
    so the store answers it in one round trip and the connection is idle after
    it, never left inside a transaction. A read inside a transaction that is
    open - a `transaction()` block, or after a write not yet committed - runs
    in that transaction, and a write that opens one leaves it open for
    `commit()`. A connection set to another isolation level, or to read-only
    or deferrable, opens a transaction for a read as before.

    A transaction connection is the process's working connection for that address,
    lent: the first `connect` opens it, `close()` (or leaving `with`) ends the loan,
    rolling back what was not committed, and the next `connect` is lent the same
    connection rather than opening one, its schema, local settings and
    application_name bound for each of its transactions as this call names them. A
    loan taken while another is out gets one of its own, and each working
    connection is closed when the process exits or `disconnect()` closes it. One the
    store closed, or that sat idle for PING_AFTER_SECONDS and does not answer, is
    replaced as it is lent, and one the store or the network closed while it
    was lent is replaced before a statement that is a transaction of its own is
    sent on it; a statement that finds it gone before anything of its
    transaction reached the store - the statement that opens the transaction, or
    one in autocommit before it is sent - runs once more on a new connection,
    and a commit is never sent twice; so does a plain read that is a
    transaction of its own, and a plain read in a transaction that has only
    read. A rollback on a connection that is gone is not refused, nor the
    commit of a transaction that has only read, and the next statement takes a
    new connection.

    A connect that fails before the store answers is tried again, at most
    CONNECT_ATTEMPTS times with a short jittered, doubling pause, while
    `connect_timeout` seconds are not spent; a store that still does not answer
    is refused as `store_unreachable`. Then a further transaction connection to
    that address - a `connect` or a lost connection's replacement - is refused
    at once as `store_unreachable` for a pause of between half and all of
    RECONNECT_FIRST_SECONDS, doubling with each failure in a row up to
    RECONNECT_LONGEST_SECONDS, and the first after the pause dials again; the
    first connect of a process always dials. Each such refusal, and the one of
    the connect that began the pause, carries the `time.monotonic()` moment the
    pause ends as `DbError.dials_again_at`, so a caller that asks again waits
    for that one schedule rather than keeping its own. Both ends send TCP keepalives on a
    session connection; a transaction connection sends them from the client only.
    The client gives either kind up once data it sent has gone unacknowledged for
    TCP_USER_TIMEOUT_MILLISECONDS, which keepalives, never sent meanwhile, cannot
    notice: the statement fails as a lost connection, and a plain read that may
    run again does so on a new one.
    A session connection to Supabase's transaction pooler - the store's session
    address, or its only address, when the store is transaction-only - is refused as
    `transaction_pooler` before anything is sent to it. A transaction connection to
    a transaction-only store is proven to answer as at a transaction address of its
    own."""
    if not isinstance(application_name, str) or not application_name:
        raise DbError("bad_application_name", "application_name must be a non-empty string")
    setting = setting if setting is not None else resolve_setting(project_root)
    schema = check_schema_name(setting.schema)
    psycopg, _ = _psycopg()
    if not transaction:
        _refuse_transaction_pooler(setting)
    options = dict(application_name=application_name,
                   keepalives=1, keepalives_idle=KEEPALIVE_IDLE_SECONDS,
                   keepalives_interval=KEEPALIVE_INTERVAL_SECONDS,
                   keepalives_count=KEEPALIVE_COUNT,
                   tcp_user_timeout=TCP_USER_TIMEOUT_MILLISECONDS)
    settings = tuple((str(name), str(value))
                     for name, value in (local_settings or {}).items())
    if transaction:
        startup = _startup_settings(setting)
        # No startup option is sent: each one is set for every transaction.
        kwargs = {**setting.transaction_kwargs(), "options": "", **options}
        key = _address_key(kwargs)
        conn = _lend(key, connect_timeout)
        if conn is None:
            # Behind a pooler - a transaction address of its own, or a store that
            # is transaction-only - the store's answer is proven as it connects.
            behind = setting.has_transaction_address or not setting.has_session_address
            conn = _open_transaction(kwargs, behind, connect_timeout)
            conn._key = key
            conn._lent = True
        named = ()
        if application_name != conn._startup_name:
            named = (("application_name", application_name),)
        conn._bound_schema = schema
        conn._local_settings = startup + settings + named
        _BOUND[conn] = schema
        return conn
    try:
        conn = _attempts(lambda seconds: psycopg.connect(
            **setting.connect_kwargs(), **options, connect_timeout=seconds), connect_timeout)
    except psycopg.OperationalError as exc:
        raise DbError("store_unreachable", f"cannot reach the store: {exc}",
                      "check the database setting with `capabilities store doctor`") from exc
    try:
        _keepalives(conn)
        bind_search_path(conn, schema)
        for name, value in settings:
            conn.execute("SELECT set_config(%s, %s, false)", (name, value))
        conn.commit()
    except Exception:
        conn.close()
        raise
    _BOUND[conn] = schema
    return conn


def _transient(exc: BaseException) -> bool:
    """Whether a failed connect may succeed when tried again: the store gave no
    answer of its own - refused, reset, timed out - or said it cannot take one now."""
    state = getattr(exc, "sqlstate", None)
    if state:
        return state.startswith(("08", "57P"))
    text = str(exc).lower()
    return not any(word in text for word in ("password", "certificate", "pg_hba"))


def _attempts(open_one: Any, budget: float) -> Any:
    """`open_one(seconds)` tried up to CONNECT_ATTEMPTS times, pausing between
    tries, while `budget` seconds are not spent; each try may take at most half of
    them, and never less than libpq's least timeout of 2 seconds."""
    psycopg, _ = _psycopg()
    began = time.monotonic()
    last: BaseException | None = None
    for attempt in range(CONNECT_ATTEMPTS):
        left = budget - (time.monotonic() - began)
        if attempt and left < 1:
            break
        seconds = max(2, min(math.ceil(budget / 2), math.ceil(left)))
        try:
            return open_one(seconds)
        except psycopg.OperationalError as exc:
            if not _transient(exc):
                raise
            last = exc
        if attempt + 1 < CONNECT_ATTEMPTS:
            time.sleep(_jittered(CONNECT_PAUSE_SECONDS * (2 ** attempt)))
    assert last is not None
    raise last


def _jittered(seconds: float) -> float:
    """A pause of at most `seconds` and at least half of it, drawn at random, so
    processes that lost one store together do not dial it again in step."""
    return random.uniform(seconds / 2, seconds)


# The addresses whose last connect found no store answering, each with how many
# connects in a row failed, until when no new one is dialled, and why the last
# failed. Kept per process, so the first connect of a process always dials.
_PAUSED: dict[str, tuple[int, float, BaseException]] = {}


def _address_key(kwargs: dict) -> str:
    """The address a transaction connection opened with `kwargs` is kept under."""
    return repr(sorted((name, str(value)) for name, value in kwargs.items()
                       if name != "application_name"))


def _paused(key: str) -> None:
    """Refuse at once a connect to an address within the pause that followed its
    last failed connect."""
    with _LOCK:
        held = _PAUSED.get(key)
    if held is None:
        return
    failures, until, why = held
    left = until - time.monotonic()
    if left <= 0:
        return
    raise DbError("store_unreachable",
                  f"cannot reach the store: {why}".rstrip() +
                  f" (no answer to {failures} connect(s) in a row; not dialled again "
                  f"for {left:.1f}s)",
                  "check the database setting with `capabilities store doctor`",
                  dials_again_at=until) from why


def _note_connect(key: str, failure: BaseException | None) -> float | None:
    """Record how a connect to `key` ended: a store that did not answer pauses
    the next connects for a doubling, jittered while, at most
    RECONNECT_LONGEST_SECONDS, and the moment the pause ends is returned; one
    that answered ends the pause."""
    with _LOCK:
        if failure is None:
            _PAUSED.pop(key, None)
            return None
        failures = (_PAUSED.get(key) or (0, 0.0, failure))[0] + 1
        pause = min(RECONNECT_LONGEST_SECONDS,
                    RECONNECT_FIRST_SECONDS * (2 ** min(failures - 1, 16)))
        until = time.monotonic() + _jittered(pause)
        _PAUSED[key] = (failures, until, failure)
        return until


def _open_transaction(kwargs: dict, own_address: bool, budget: float) -> Any:
    """A new working connection: a transaction connection opened with `kwargs`,
    proven to answer behind a transaction address of its own. Raises DbError."""
    psycopg, _ = _psycopg()
    kind = _transaction_class()
    key = _address_key(kwargs)
    _paused(key)

    def open_one(seconds: int) -> Any:
        conn = kind.connect(**kwargs, connect_timeout=seconds, prepare_threshold=None,
                            cursor_factory=kind.BindingCursor)
        conn._lent = True
        if own_address:
            failure = _round_trip(conn, seconds)
            if failure is not None:
                _finish(conn)
                if isinstance(failure, psycopg.OperationalError):
                    raise failure
                raise psycopg.OperationalError(str(failure)) from failure
        return conn

    try:
        conn = _attempts(open_one, budget)
    except psycopg.OperationalError as exc:
        unanswered = isinstance(exc, _unanswered())
        until = None
        if unanswered or _transient(exc):
            until = _note_connect(key, exc)
        why = str(exc) if unanswered else f"cannot reach the store: {exc}"
        raise DbError("store_unreachable", why,
                      "check the database setting with `capabilities store doctor`",
                      dials_again_at=until) from exc
    _note_connect(key, None)
    conn._opened_with = (kwargs, own_address, budget)
    conn._blocks = []
    conn._startup_name = str(kwargs.get("application_name") or "")
    conn._pid = os.getpid()
    _track(conn)
    return conn


_UNANSWERED = None


def _unanswered() -> type:
    """The failure of a round trip severed for want of an answer: a pooler took the
    connection while the store behind it did not answer in time."""
    global _UNANSWERED
    if _UNANSWERED is None:
        psycopg, _ = _psycopg()

        class Unanswered(psycopg.OperationalError):
            pass

        _UNANSWERED = Unanswered
    return _UNANSWERED


def _round_trip(conn: Any, seconds: float) -> BaseException | None:
    """One round trip on `conn`, severed when it is not back within `seconds`:
    None when it came back, else the failure, so a pooler holding the client while
    the store behind it does not answer is known in that time rather than after
    the pooler's own wait."""
    import socket

    psycopg, _ = _psycopg()
    held = socket.socket(fileno=os.dup(conn.pgconn.socket))
    cut = threading.Event()

    def sever() -> None:
        cut.set()
        with contextlib.suppress(OSError):
            held.shutdown(socket.SHUT_RDWR)

    timer = threading.Timer(seconds, sever)
    timer.daemon = True
    timer.start()
    try:
        conn.autocommit = True
        psycopg.Cursor(conn).execute("SELECT 1")
        conn.autocommit = False
        return None
    except psycopg.Error as exc:
        if cut.is_set():
            return _unanswered()(
                f"the store did not answer at its transaction address within {seconds:g}s")
        return exc
    finally:
        timer.cancel()
        held.close()


# The working connections of this process: those idle, by address, newest last, and
# every one open, so each is closed when the process exits. A child of a fork never
# uses or closes its parent's: they are only held, so the child's exit leaves them.
_LOCK = threading.Lock()
_IDLE: dict[str, list] = {}
_OPEN: weakref.WeakSet = weakref.WeakSet()
_INHERITED: list = []
_HOOKED = False


def _track(conn: Any) -> None:
    global _HOOKED
    with _LOCK:
        _OPEN.add(conn)
        if not _HOOKED:
            _HOOKED = True
            import atexit
            atexit.register(disconnect, every=True)
            if hasattr(os, "register_at_fork"):
                os.register_at_fork(after_in_child=_forget_after_fork)


def _forget_after_fork() -> None:
    global _LOCK
    _LOCK = threading.Lock()
    _INHERITED.extend(_OPEN)
    _OPEN.clear()
    _IDLE.clear()
    _PAUSED.clear()


def _finish(conn: Any) -> None:
    """Close a working connection for good; one a fork inherited is only held."""
    conn._lent = False
    with _LOCK:
        _OPEN.discard(conn)
    if conn._pid and conn._pid != os.getpid():
        _INHERITED.append(conn)
        return
    conn._closed = True
    with contextlib.suppress(Exception):
        conn.pgconn.finish()


def _spares(idle: list) -> list:
    """The idle connections of one address to close: each but the newest that sat
    idle for SPARE_IDLE_SECONDS. Called under the lock; removes them from `idle`."""
    if len(idle) < 2:
        return []
    now = time.monotonic()
    old = [c for c in idle[:-1] if now - c._idle_since >= SPARE_IDLE_SECONDS]
    for conn in old:
        idle.remove(conn)
    return old


def _keep(conn: Any) -> None:
    conn._idle_since = time.monotonic()
    with _LOCK:
        idle = _IDLE.setdefault(conn._key, [])
        idle.append(conn)
        spare = _spares(idle)
    for old in spare:
        _finish(old)


def _fit(conn: Any, seconds: float) -> bool:
    """Whether an idle working connection can be lent again: it is this process's,
    the store has not closed it, and, after PING_AFTER_SECONDS idle, it answers."""
    import select

    psycopg, _ = _psycopg()
    if conn._pid != os.getpid() or conn._gone():
        return False
    if conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE:
        return False
    try:
        ready, _w, _x = select.select([conn.pgconn.socket], [], [], 0)
        if ready:
            # The store said something unasked: it is closing the connection.
            conn.pgconn.consume_input()
            if conn._gone() or conn.pgconn.is_busy():
                return False
    except Exception:
        return False
    if time.monotonic() - conn._idle_since < PING_AFTER_SECONDS:
        return True
    return _round_trip(conn, seconds) is None and not conn._gone()


def _lend(key: str, seconds: float) -> Any:
    """An idle working connection for `key`, lent, or None where there is none."""
    while True:
        with _LOCK:
            idle = _IDLE.get(key) or []
            spare = _spares(idle)
            conn = idle.pop() if idle else None
        for old in spare:
            _finish(old)
        if conn is None:
            return None
        conn._lent = True
        if _fit(conn, min(seconds, CONNECT_TIMEOUT_SECONDS)):
            return conn
        _finish(conn)


def disconnect(*, every: bool = False) -> int:
    """Close this process's idle working connections, so it holds none until its
    next `connect(..., transaction=True)`; with `every`, the lent ones as well, as
    the process does when it exits. Returns how many were closed."""
    with _LOCK:
        closing = [conn for idle in _IDLE.values() for conn in idle]
        _IDLE.clear()
        if every:
            closing += [conn for conn in _OPEN if conn not in closing]
    for conn in closing:
        _finish(conn)
    return len(closing)


def batch(conn: Any, statements: Any) -> list[list]:
    """Send `statements` - each a query, or a `(query, params)` pair - to the store
    as one pipeline on `conn`, a connection from `connect`, and return each one's
    rows, in order: a list of rows for a statement that returns rows, an empty
    list for one that does not. The store answers them all in one round trip.
    Each is one statement; the statements are independent, none reading what an
    earlier one returns.

    On a transaction connection the schema is bound for them. Where each would
    open a transaction of its own - in autocommit, or when every one is a plain
    read - they run as one transaction of their own and leave the connection
    idle, and when every one is a plain read a lost connection runs them again
    on a new one. Otherwise they run inside the transaction that is open, or
    the one the first of them opens, which stays open for the caller's
    commit. A statement that fails fails the pipeline: its error is raised and
    the statements after it are not run."""
    items = []
    for statement in statements:
        if isinstance(statement, tuple):
            query, params = statement
        else:
            query, params = statement, None
        items.append((query, params))
    if not items:
        return []
    psycopg, _ = _psycopg()
    if isinstance(conn, _transaction_class()):
        if psycopg.Pipeline.is_supported():
            return conn._together(items)
        cursors = [conn.cursor() for _ in items]
        for cursor, (query, params) in zip(cursors, items, strict=True):
            cursor.execute(query, params)
    else:
        cursors = [conn.cursor() for _ in items]
        if psycopg.Pipeline.is_supported():
            # A transaction this opens is begun inside the pipeline, not
            # synced on its own.
            opens = (not conn.autocommit
                     and conn.info.transaction_status == psycopg.pq.TransactionStatus.IDLE)
            was, conn._autocommit = conn._autocommit, True
            try:
                with conn.pipeline():
                    if opens:
                        conn.wait(conn._exec_command(conn._get_tx_start_command()))
                    for cursor, (query, params) in zip(cursors, items, strict=True):
                        cursor.execute(query, params)
            finally:
                conn._autocommit = was
        else:
            for cursor, (query, params) in zip(cursors, items, strict=True):
                cursor.execute(query, params)
    return [cursor.fetchall() if cursor.description is not None else []
            for cursor in cursors]


def bound_schema(conn: Any) -> str | None:
    """The schema `connect` bound this connection to, or None."""
    try:
        return _BOUND.get(conn)
    except TypeError:
        return None
