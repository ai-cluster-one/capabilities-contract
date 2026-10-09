"""Each owner's tables, migrated once under a ledger.

An owner is the tool that owns a set of tables, named for it: every relation, index,
sequence, type and function its steps create is named `<owner>` or `<owner>_*`, in
the configured schema. Two platform tables in the same schema keep the books:
`schema_ledger` (one row per applied step) and `schema_version` (one row per owner).
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from capabilities_contract.db._connect import _psycopg, bind_search_path, bound_schema
from capabilities_contract.db._errors import DbError
from capabilities_contract.db._setting import check_schema_name
from capabilities_contract.version import __version__

LEDGER_TABLE = "schema_ledger"
VERSION_TABLE = "schema_version"
RESERVED_NAMES = (LEDGER_TABLE, VERSION_TABLE)
RESERVED_OWNERS = ("schema", "pg")

# A lock is waited for this long at most, without queueing for it, and a session
# holding one that goes this long without a statement is ended by the server.
LOCK_WAIT_SECONDS = 10.0
LOCK_IDLE_SECONDS = 5
_LOCK_POLL_SECONDS = 0.1

# No underscore: then no owner's `<owner>_` prefix can cover another owner's.
_OWNER = re.compile(r"[a-z][a-z0-9]{0,30}")
_STEP_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


@dataclass(frozen=True)
class Step:
    """One migration step: a stable id and the SQL it runs. The checksum is the
    SHA-256 of the SQL text exactly as given."""

    id: str
    sql: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()


@dataclass
class MigrateResult:
    """What `migrate` did. `warnings` is empty unless the store is ahead of the
    caller in a way the caller may still work with (a newer minor)."""

    owner: str
    schema: str
    applied: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    major: int | None = None
    minor: int | None = None


def check_owner(owner: object) -> str:
    if not isinstance(owner, str) or not _OWNER.fullmatch(owner) or owner in RESERVED_OWNERS:
        raise DbError("bad_owner", f"owner {owner!r} is not a lowercase identifier",
                      "use lowercase letters and digits, starting with a letter, "
                      "no underscore, at most 31 characters")
    return owner


def _check_version_numbers(major: object, minor: object) -> tuple[int, int]:
    for name, value in (("major", major), ("minor", minor)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise DbError("bad_version", f"{name} must be a non-negative integer")
    return major, minor  # type: ignore[return-value]


def _normalise_steps(steps: Iterable[Step | Sequence[str]]) -> list[Step]:
    out: list[Step] = []
    seen: set[str] = set()
    for raw in steps:
        if isinstance(raw, Step):
            step = raw
        elif isinstance(raw, (tuple, list)) and len(raw) == 2:
            step = Step(raw[0], raw[1])
        else:
            raise DbError("bad_step", f"a step is a Step or a (step_id, sql) pair, not {raw!r}")
        if not isinstance(step.id, str) or not _STEP_ID.fullmatch(step.id):
            raise DbError("bad_step", f"step id {step.id!r} is not a valid step id",
                          "letters, digits, '.', '_' and '-', starting with a letter or digit")
        if not isinstance(step.sql, str) or not step.sql.strip():
            raise DbError("bad_step", f"step {step.id!r} has no SQL")
        if step.id in seen:
            raise DbError("bad_step", f"step id {step.id!r} appears twice")
        seen.add(step.id)
        out.append(step)
    return out


_SYSTEM_NS = ("n.nspname NOT IN ('pg_catalog', 'information_schema') "
              "AND n.nspname NOT LIKE 'pg\\_%'")

# Every named object a step can leave behind in a user schema: relations (tables,
# indexes, sequences, views, composite types), free-standing types (an array type
# Postgres makes for another type is skipped), functions and procedures,
# collations, statistics objects, and schemas themselves.
_SNAPSHOT = f"""
SELECT 'relation', c.oid::bigint, n.nspname, c.relname
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE {_SYSTEM_NS}
UNION ALL
SELECT 'type', t.oid::bigint, n.nspname, t.typname
  FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
 WHERE {_SYSTEM_NS} AND t.typrelid = 0
   AND NOT EXISTS (SELECT 1 FROM pg_type e WHERE e.typarray = t.oid)
UNION ALL
SELECT 'function', p.oid::bigint, n.nspname, p.proname
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE {_SYSTEM_NS}
UNION ALL
SELECT 'collation', o.oid::bigint, n.nspname, o.collname
  FROM pg_collation o JOIN pg_namespace n ON n.oid = o.collnamespace WHERE {_SYSTEM_NS}
UNION ALL
SELECT 'statistics', s.oid::bigint, n.nspname, s.stxname
  FROM pg_statistic_ext s JOIN pg_namespace n ON n.oid = s.stxnamespace WHERE {_SYSTEM_NS}
UNION ALL
SELECT 'schema', n.oid::bigint, n.nspname, n.nspname FROM pg_namespace n WHERE {_SYSTEM_NS}
"""


def _snapshot(conn: Any) -> set[tuple]:
    return set(conn.execute(_SNAPSHOT).fetchall())


def _violations(before: set[tuple], after: set[tuple], owner: str, schema: str) -> list[str]:
    bad = []
    for kind, _oid, nspname, name in sorted(after - before, key=lambda r: (r[2], r[3])):
        if kind == "schema":
            bad.append(f"schema {name}")
        elif nspname != schema:
            bad.append(f"{kind} {nspname}.{name} (outside schema {schema})")
        elif name in RESERVED_NAMES:
            bad.append(f"{kind} {name} (reserved)")
        elif not (name == owner or name.startswith(owner + "_")):
            bad.append(f"{kind} {name}")
    return bad


def _lock(conn: Any, key: str) -> None:
    """Take `key`'s lock for the open transaction. The lock is tried, never queued
    for, so a caller that dies while waiting leaves no session behind in the queue;
    the wait is bounded and reported as `store_busy`. While the transaction holds
    it, a session that stops issuing statements is ended by the server."""
    conn.execute("SELECT set_config('idle_in_transaction_session_timeout', %s, true)",
                 (f"{int(LOCK_IDLE_SECONDS * 1000)}ms",))
    deadline = time.monotonic() + LOCK_WAIT_SECONDS
    while not conn.execute("SELECT pg_try_advisory_xact_lock(hashtextextended(%s, 0))",
                           (key,)).fetchone()[0]:
        if time.monotonic() >= deadline:
            raise DbError("store_busy",
                          f"another session has held the store lock {key} for longer "
                          f"than {LOCK_WAIT_SECONDS:g}s",
                          "try again shortly; a session that holds it without working is "
                          f"ended by the store within {LOCK_IDLE_SECONDS:g}s")
        time.sleep(_LOCK_POLL_SECONDS)


def _bootstrap(conn: Any, schema: str) -> None:
    """Create the schema and the platform tables if missing, under the schema lock.
    Existence is checked first, so a role that may not create them can still use them
    once they exist."""
    _, sql = _psycopg()
    with conn.transaction():
        _lock(conn, f"capabilities_contract:{schema}")
        exists = conn.execute("SELECT 1 FROM pg_namespace WHERE nspname = %s",
                              (schema,)).fetchone()
        if not exists:
            conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        ledger = conn.execute("SELECT to_regclass(%s)",
                              (f'"{schema}".{LEDGER_TABLE}',)).fetchone()[0]
        if ledger is None:
            conn.execute(sql.SQL(
                "CREATE TABLE {}.{} (owner text NOT NULL, step text NOT NULL, "
                "checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now(), "
                "library_version text NOT NULL, PRIMARY KEY (owner, step))").format(
                    sql.Identifier(schema), sql.Identifier(LEDGER_TABLE)))
        version = conn.execute("SELECT to_regclass(%s)",
                               (f'"{schema}".{VERSION_TABLE}',)).fetchone()[0]
        if version is None:
            conn.execute(sql.SQL(
                "CREATE TABLE {}.{} (owner text PRIMARY KEY, major integer NOT NULL, "
                "minor integer NOT NULL, updated_at timestamptz NOT NULL DEFAULT now())").format(
                    sql.Identifier(schema), sql.Identifier(VERSION_TABLE)))


def _stored_version(conn: Any, schema: str, owner: str) -> tuple[int, int] | None:
    _, sql = _psycopg()
    row = conn.execute(sql.SQL("SELECT major, minor FROM {}.{} WHERE owner = %s").format(
        sql.Identifier(schema), sql.Identifier(VERSION_TABLE)), (owner,)).fetchone()
    return (row[0], row[1]) if row else None


def _check_version(conn: Any, schema: str, owner: str, major: int, minor: int,
                   result: MigrateResult) -> tuple[int, int] | None:
    stored = _stored_version(conn, schema, owner)
    if stored is None:
        return None
    s_major, s_minor = stored
    if s_major > major:
        raise DbError("schema_too_new",
                      f"the store's {owner} tables are at schema version {s_major}.{s_minor}, "
                      f"newer than the {major}.{minor} this code knows",
                      f"update the release that owns the {owner} tables to one that knows "
                      f"schema major {s_major}")
    if s_major == major and s_minor > minor:
        warning = (f"the store's {owner} tables are at schema version {s_major}.{s_minor}, "
                   f"a newer minor than the {major}.{minor} this code knows; "
                   "it works, but an update is available")
        if warning not in result.warnings:
            result.warnings.append(warning)
    return stored


def _settled(conn: Any, schema: str, owner: str, plan: list[Step], major: int, minor: int,
             result: MigrateResult) -> bool:
    """Whether there is nothing to do: the platform tables exist, every step is
    applied with its SQL, and the store records the caller's version or a newer
    minor. Read without a lock, so a session holding one stops no caller whose
    tables are already in place. Refuses as the locked path would."""
    _, sql = _psycopg()
    with conn.transaction():
        for table in (LEDGER_TABLE, VERSION_TABLE):
            if conn.execute("SELECT to_regclass(%s)",
                            (f'"{schema}".{table}',)).fetchone()[0] is None:
                return False
        stored = _check_version(conn, schema, owner, major, minor, result)
        if stored is None or stored < (major, minor):
            return False
        applied = dict(conn.execute(sql.SQL("SELECT step, checksum FROM {}.{} WHERE owner = %s")
                                    .format(sql.Identifier(schema),
                                            sql.Identifier(LEDGER_TABLE)),
                                    (owner,)).fetchall())
        for step in plan:
            if step.id not in applied:
                return False
            if applied[step.id] != step.checksum:
                raise DbError("checksum_mismatch",
                              f"step {step.id} of {owner} was applied with different SQL",
                              "never edit an applied step; add a new step instead")
    result.skipped = [step.id for step in plan]
    result.major, result.minor = stored
    return True


def migrate(conn: Any, owner: str, steps: Iterable[Step | Sequence[str]], *,
            major: int, minor: int, schema: str | None = None) -> MigrateResult:
    """Apply `owner`'s steps that are not yet applied, in order, each once.

    `conn` comes from `connect` (its bound schema is used) and must be idle. Each
    step runs in its own transaction under a per-owner advisory lock, together with
    its ledger row, so concurrent callers apply it exactly once. Refuses (DbError):
    a stored major newer than `major` (`schema_too_new`), an applied step whose SQL
    changed (`checksum_mismatch`), a step that creates an object not named
    `<owner>`/`<owner>_*` in the schema (`naming_law`, rolled back), and a failing
    step (`step_failed`, rolled back). A newer stored minor proceeds with a warning
    in the result. Afterwards the caller's version is recorded unless the store's is
    newer. When every step is applied and the version recorded, it takes no lock at
    all; otherwise a lock held elsewhere is waited for at most LOCK_WAIT_SECONDS
    and then refused (`store_busy`)."""
    psycopg, sql = _psycopg()
    owner = check_owner(owner)
    major, minor = _check_version_numbers(major, minor)
    schema = check_schema_name(schema if schema is not None else bound_schema(conn))
    plan = _normalise_steps(steps)
    if conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE:
        raise DbError("connection_busy", "migrate needs an idle connection",
                      "commit or roll back before migrating")
    result = MigrateResult(owner=owner, schema=schema)
    lock_key = f"capabilities_contract:{schema}:{owner}"
    ledger = sql.SQL("{}.{}").format(sql.Identifier(schema), sql.Identifier(LEDGER_TABLE))
    versions = sql.SQL("{}.{}").format(sql.Identifier(schema), sql.Identifier(VERSION_TABLE))

    settled = _settled(conn, schema, owner, plan, major, minor, result)
    if not settled:
        _bootstrap(conn, schema)
    bind_search_path(conn, schema)
    conn.commit()
    if settled:
        return result

    for step in plan:
        with conn.transaction():
            _lock(conn, lock_key)
            _check_version(conn, schema, owner, major, minor, result)
            row = conn.execute(sql.SQL("SELECT checksum FROM {} WHERE owner = %s AND step = %s")
                               .format(ledger), (owner, step.id)).fetchone()
            if row is not None:
                if row[0] != step.checksum:
                    raise DbError("checksum_mismatch",
                                  f"step {step.id} of {owner} was applied with different SQL",
                                  "never edit an applied step; add a new step instead")
                result.skipped.append(step.id)
                continue
            before = _snapshot(conn)
            try:
                with conn.transaction():
                    conn.execute(step.sql)
            except psycopg.Error as exc:
                raise DbError("step_failed", f"step {step.id} of {owner} failed: {exc}",
                              "the step was rolled back; fix it and migrate again") from exc
            if conn.info.transaction_status != psycopg.pq.TransactionStatus.INTRANS:
                raise DbError("step_failed",
                              f"step {step.id} of {owner} ended its own transaction",
                              "a step may not COMMIT or ROLLBACK")
            bind_search_path(conn, schema)
            bad = _violations(before, _snapshot(conn), owner, schema)
            if bad:
                raise DbError("naming_law",
                              f"step {step.id} of {owner} creates objects not named "
                              f"{owner}_*: {', '.join(bad)}",
                              f"name everything the step creates {owner} or {owner}_* "
                              f"inside schema {schema}; the step was rolled back")
            conn.execute(sql.SQL("INSERT INTO {} (owner, step, checksum, library_version) "
                                 "VALUES (%s, %s, %s, %s)").format(ledger),
                         (owner, step.id, step.checksum, __version__))
            result.applied.append(step.id)

    with conn.transaction():
        _lock(conn, lock_key)
        stored = _check_version(conn, schema, owner, major, minor, result)
        if stored is None or (major, minor) >= stored:
            conn.execute(sql.SQL(
                "INSERT INTO {} (owner, major, minor) VALUES (%s, %s, %s) "
                "ON CONFLICT (owner) DO UPDATE SET major = EXCLUDED.major, "
                "minor = EXCLUDED.minor, updated_at = now()").format(versions),
                (owner, major, minor))
            result.major, result.minor = major, minor
        else:
            result.major, result.minor = stored
    return result
