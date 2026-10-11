"""A connection bound to the configured schema. psycopg is imported here, lazily."""

from __future__ import annotations

import weakref
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
# no session between transactions, so what a connection sets for its session - the
# schema binding, prepared statements, LISTEN - is lost. Its session pooler is the
# same host on SESSION_POOLER_PORT.
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
    """Set the session's search_path to `schema` alone."""
    _, sql = _psycopg()
    conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))


def _keepalives(conn: Any) -> None:
    """Ask the server to probe this client as the client probes the server. Over a
    Unix socket the server ignores the settings."""
    for name, value in (("tcp_keepalives_idle", KEEPALIVE_IDLE_SECONDS),
                        ("tcp_keepalives_interval", KEEPALIVE_INTERVAL_SECONDS),
                        ("tcp_keepalives_count", KEEPALIVE_COUNT)):
        conn.execute("SELECT set_config(%s, %s, false)", (name, str(value)))


def _endpoints(setting: Setting) -> list[tuple[str, int]]:
    """Each host and port libpq would try for the setting, read by libpq's own parse.
    A setting it cannot parse gives none; connecting reports it."""
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
    """Refuse, before anything is sent, a store reached through Supabase's
    transaction pooler."""
    for host, port in _endpoints(setting):
        if host.lower().endswith(SUPABASE_POOLER_DOMAIN) and port == TRANSACTION_POOLER_PORT:
            raise DbError(
                "transaction_pooler",
                f"the store at {host}:{port} is Supabase's transaction pooler, which keeps "
                "no session between transactions, so the schema binding, prepared statements "
                "and notifications a connection relies on are lost; it is not supported",
                f"use Supabase's session pooler: the same host, {host}, on port "
                f"{SESSION_POOLER_PORT}")


def connect(*, application_name: str, project_root: Path | str | None = None,
            setting: Setting | None = None,
            connect_timeout: int = CONNECT_TIMEOUT_SECONDS) -> Any:
    """A psycopg connection to the database `resolve_setting(project_root)` names, or
    `setting` when given, with search_path set to its schema only (never `public`).
    The schema need not exist yet: `migrate` creates it. The connection is returned
    idle, outside any transaction.

    A store that does not answer within `connect_timeout` seconds is refused as
    `store_unreachable`. Both ends send TCP keepalives on the connection. A store
    reached through Supabase's transaction pooler is refused as `transaction_pooler`
    before anything is sent to it."""
    if not isinstance(application_name, str) or not application_name:
        raise DbError("bad_application_name", "application_name must be a non-empty string")
    setting = setting if setting is not None else resolve_setting(project_root)
    schema = check_schema_name(setting.schema)
    psycopg, _ = _psycopg()
    _refuse_transaction_pooler(setting)
    try:
        conn = psycopg.connect(**setting.connect_kwargs(), application_name=application_name,
                               connect_timeout=connect_timeout, keepalives=1,
                               keepalives_idle=KEEPALIVE_IDLE_SECONDS,
                               keepalives_interval=KEEPALIVE_INTERVAL_SECONDS,
                               keepalives_count=KEEPALIVE_COUNT)
    except psycopg.OperationalError as exc:
        raise DbError("store_unreachable", f"cannot reach the store: {exc}",
                      "check the database setting with `capabilities store doctor`") from exc
    try:
        _keepalives(conn)
        bind_search_path(conn, schema)
        conn.commit()
    except Exception:
        conn.close()
        raise
    _BOUND[conn] = schema
    return conn


def bound_schema(conn: Any) -> str | None:
    """The schema `connect` bound this connection to, or None."""
    try:
        return _BOUND.get(conn)
    except TypeError:
        return None
