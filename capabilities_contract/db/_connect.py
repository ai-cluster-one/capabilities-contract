"""A connection bound to the configured schema. psycopg is imported here, lazily."""

from __future__ import annotations

import weakref
from typing import Any

from capabilities_contract.db._errors import DbError
from capabilities_contract.db._setting import Setting, check_schema_name, read_setting

# The schema each connection from `connect` is bound to, so `migrate` needs no
# second argument naming it.
_BOUND: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


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


def connect(*, application_name: str, setting: Setting | None = None,
            connect_timeout: int = 10) -> Any:
    """A psycopg connection to the store, with search_path set to the configured
    schema only (never `public`). The schema need not exist yet: `migrate` creates
    it. The connection is returned idle, outside any transaction."""
    if not isinstance(application_name, str) or not application_name:
        raise DbError("bad_application_name", "application_name must be a non-empty string")
    setting = setting if setting is not None else read_setting()
    schema = check_schema_name(setting.schema)
    psycopg, _ = _psycopg()
    try:
        conn = psycopg.connect(**setting.connect_kwargs(), application_name=application_name,
                               connect_timeout=connect_timeout)
    except psycopg.OperationalError as exc:
        raise DbError("store_unreachable", f"cannot reach the store: {exc}",
                      "check the store setting with `capabilities store doctor`") from exc
    try:
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
