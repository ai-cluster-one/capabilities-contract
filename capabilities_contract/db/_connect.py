"""A connection bound to the configured schema. psycopg is imported here, lazily.

A store has a session address and, when its setting names one, a transaction address.
A session connection binds the schema for its session and may hold session state:
`LISTEN`, session advisory locks, session settings. A transaction connection carries no
session state at all, so it works through a transaction-mode pooler: psycopg prepares
no statement on it, and the schema is bound with `SET LOCAL` at the start of every
transaction rather than once for the session."""

from __future__ import annotations

import contextlib
import re
import weakref
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from capabilities_contract.db._errors import DbError
from capabilities_contract.db._setting import Setting, check_schema_name, resolve_setting

# The schema each connection from `connect` is bound to, so `migrate` needs no
# second argument naming it.
_BOUND: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()

# A connect that gets no answer gives up after CONNECT_TIMEOUT_SECONDS. Both ends
# probe an idle connection: after KEEPALIVE_IDLE_SECONDS without traffic, every
# KEEPALIVE_INTERVAL_SECONDS, giving up after KEEPALIVE_COUNT unanswered probes,
# so the store drops a client that died without closing and the client learns
# of a store that went away.
CONNECT_TIMEOUT_SECONDS = 10
KEEPALIVE_IDLE_SECONDS = 30
KEEPALIVE_INTERVAL_SECONDS = 10
KEEPALIVE_COUNT = 3

# Supabase's transaction pooler: a host under its pooler domain on this port. It keeps
# no session between transactions, so what a session connection sets for its session -
# the schema binding, prepared statements, LISTEN - is lost. Its session pooler is the
# same host on SESSION_POOLER_PORT. The transaction address may name it.
SUPABASE_POOLER_DOMAIN = ".pooler.supabase.com"
TRANSACTION_POOLER_PORT = 6543
SESSION_POOLER_PORT = 5432

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

    idle = pq.TransactionStatus.IDLE
    failed = pq.TransactionStatus.INERROR

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

        def _ready(self, query: Any) -> None:
            conn = self.connection
            if _SESSION_STATE.search(text_of(conn, query)):
                raise DbError("session_state",
                              "a transaction connection keeps no session state: LISTEN, "
                              "PREPARE, a session SET or set_config and a session advisory "
                              "lock belong on a session connection",
                              "open it with connect(..., transaction=False), or take a "
                              "transaction-level lock (pg_advisory_xact_lock)")
            conn._bind_transaction()

        def execute(self, query, params=None, **kwargs):
            conn = self.connection
            if conn.autocommit and conn.info.transaction_status == idle:
                # Autocommit runs each statement as its own transaction, which a
                # SET LOCAL cannot reach; run it in one that binds the schema first.
                with conn.transaction():
                    self._ready(query)
                    return super().execute(query, params, **kwargs)
            self._ready(query)
            return super().execute(query, params, **kwargs)

        def executemany(self, query, params_seq, **kwargs):
            conn = self.connection
            if conn.autocommit and conn.info.transaction_status == idle:
                with conn.transaction():
                    self._ready(query)
                    return super().executemany(query, params_seq, **kwargs)
            self._ready(query)
            return super().executemany(query, params_seq, **kwargs)

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
                return
            if status == failed or self._bound_now:
                return
            self._bind_now()

        @contextmanager
        def transaction(self, savepoint_name=None, force_rollback=False):
            outer = self.info.transaction_status == idle
            if outer:
                self._bound_now = False
            with super().transaction(savepoint_name, force_rollback) as tx:
                if outer:
                    self._bind_now()
                yield tx
            if self.info.transaction_status == idle:
                self._bound_now = False

        def commit(self) -> None:
            try:
                super().commit()
            finally:
                self._bound_now = False

        def rollback(self) -> None:
            try:
                super().rollback()
            finally:
                self._bound_now = False

    TransactionConnection.BindingCursor = BindingCursor
    _TRANSACTION_CLASS = TransactionConnection
    return TransactionConnection


def _keepalives(conn: Any) -> None:
    """Ask the server to probe this client as the client probes the server. Over a
    Unix socket the server ignores the settings."""
    for name, value in (("tcp_keepalives_idle", KEEPALIVE_IDLE_SECONDS),
                        ("tcp_keepalives_interval", KEEPALIVE_INTERVAL_SECONDS),
                        ("tcp_keepalives_count", KEEPALIVE_COUNT)):
        conn.execute("SELECT set_config(%s, %s, false)", (name, str(value)))


def _endpoints(setting: Setting) -> list[tuple[str, int]]:
    """Each host and port libpq would try for the setting's session address, read by
    libpq's own parse. A setting it cannot parse gives none; connecting reports it."""
    import psycopg
    from psycopg.conninfo import conninfo_to_dict

    try:
        params = conninfo_to_dict(**setting.connect_kwargs())
    except (psycopg.Error, ValueError):
        return []
    hosts = str(params.get("host") or "").split(",")
    ports = str(params.get("port") or "").split(",")
    if len(ports) == 1:
        ports = ports * len(hosts)
    out = []
    for host, port in zip(hosts, ports, strict=False):
        port = port.strip() or str(SESSION_POOLER_PORT)
        out.append((host.strip(), int(port) if port.isdigit() else 0))
    return out


def _refuse_transaction_pooler(setting: Setting) -> None:
    """Refuse, before anything is sent, a store whose session address is Supabase's
    transaction pooler. Its transaction address may be."""
    for host, port in _endpoints(setting):
        if host.lower().endswith(SUPABASE_POOLER_DOMAIN) and port == TRANSACTION_POOLER_PORT:
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
    transaction address: psycopg prepares no statement on it, the schema is bound with
    `SET LOCAL` at the start of every transaction, and a statement that would leave
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

    A store that does not answer within `connect_timeout` seconds is refused as
    `store_unreachable`. Both ends send TCP keepalives on a session connection; a
    transaction connection sends them from the client only. A session address that is
    Supabase's transaction pooler is refused as `transaction_pooler` before anything
    is sent to it."""
    if not isinstance(application_name, str) or not application_name:
        raise DbError("bad_application_name", "application_name must be a non-empty string")
    setting = setting if setting is not None else resolve_setting(project_root)
    schema = check_schema_name(setting.schema)
    psycopg, _ = _psycopg()
    if not (transaction and setting.has_transaction_address):
        _refuse_transaction_pooler(setting)
    options = dict(application_name=application_name, connect_timeout=connect_timeout,
                   keepalives=1, keepalives_idle=KEEPALIVE_IDLE_SECONDS,
                   keepalives_interval=KEEPALIVE_INTERVAL_SECONDS,
                   keepalives_count=KEEPALIVE_COUNT)
    try:
        if transaction:
            kind = _transaction_class()
            startup = _startup_settings(setting)
            # No startup option is sent: each one is set for every transaction.
            conn = kind.connect(**{**setting.transaction_kwargs(), "options": ""}, **options,
                                prepare_threshold=None, cursor_factory=kind.BindingCursor)
        else:
            conn = psycopg.connect(**setting.connect_kwargs(), **options)
    except psycopg.OperationalError as exc:
        raise DbError("store_unreachable", f"cannot reach the store: {exc}",
                      "check the database setting with `capabilities store doctor`") from exc
    settings = tuple((str(name), str(value))
                     for name, value in (local_settings or {}).items())
    if transaction:
        conn._bound_schema = schema
        conn._local_settings = startup + settings
        _BOUND[conn] = schema
        if setting.has_transaction_address:
            _answers_within(conn, connect_timeout)
        return conn
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


def _answers_within(conn: Any, seconds: float) -> None:
    """Prove a pooler in front of the store reaches it: one round trip, severed
    when it is not back within `seconds`, so a pooler holding the client while
    the store behind it does not answer is refused as `store_unreachable`
    rather than waited on for as long as the pooler waits."""
    import os
    import socket
    import threading

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
    except psycopg.Error as exc:
        conn.close()
        why = (f"the store did not answer at its transaction address within {seconds:g}s"
               if cut.is_set() else f"cannot reach the store: {exc}")
        raise DbError("store_unreachable", why,
                      "check the database setting with `capabilities store doctor`") from exc
    finally:
        timer.cancel()
        held.close()


def bound_schema(conn: Any) -> str | None:
    """The schema `connect` bound this connection to, or None."""
    try:
        return _BOUND.get(conn)
    except TypeError:
        return None
