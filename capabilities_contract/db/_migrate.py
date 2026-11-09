"""Each owner's tables, migrated once under a ledger.

An owner is the tool that owns a set of tables, named for it: every relation, index,
sequence, type and function its steps create is named `<owner>` or `<owner>_*`, in
the configured schema. One owner, `core`, is named for no tool: its tables are the
plain nouns of `CORE_TABLES`, reserved against every other owner, and its steps run
before any other owner's. Two platform tables in the same schema keep the books:
`schema_ledger` (one row per applied step) and `schema_version` (one row per owner).
A third, `schema_channel`, holds the change versions processes follow by polling.

A step that raises its owner to a new schema major is applied only by the store
upgrade, a procedure a person starts (`capabilities store upgrade`), recognised by
`CAPABILITIES_STORE_UPGRADE=1` in the environment; everywhere else `migrate` refuses
to cross a major, so code that picks up a newer library cannot move a store.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, NamedTuple

from capabilities_contract.db import _connection_created, _connection_ids, _core, _keys
from capabilities_contract.db._changes import CHANNEL_TABLE
from capabilities_contract.db._connect import _psycopg, bind_search_path, bound_schema
from capabilities_contract.db._errors import DbError
from capabilities_contract.db._setting import check_schema_name
from capabilities_contract.version import __version__

LEDGER_TABLE = "schema_ledger"
VERSION_TABLE = "schema_version"
RESERVED_NAMES = (LEDGER_TABLE, VERSION_TABLE, CHANNEL_TABLE)
RESERVED_OWNERS = ("schema", "pg")

# The store's core: the tables any owner's steps may reference, owned by `core` and
# named as plain nouns. `core` names everything its steps create `<table>` or
# `<table>_*` for a table on this list, or `core_premig_*` for a pre-image it keeps;
# those names are reserved against every other owner.
CORE_OWNER = "core"
CORE_TABLES = (
    "agents", "agent_nodes", "nodes", "node_states", "node_updates", "node_logins",
    "node_login_expectations", "node_logs", "node_sessions", "node_session_expectations",
    "connections", "grants", "policies", "settings", "settings_changes",
    "settings_documents", "identifiers", "secrets", "service_instances", "service_leases",
    "store_state", "reference_documents", "reference_versions", "people",
)
CORE_PREIMAGE_PREFIX = "core_premig_"

# The store upgrade: the one procedure that crosses a schema major, started by a
# person. A process runs as part of it when this variable is `1`; nothing in this
# library sets it.
UPGRADE_ENV = "CAPABILITIES_STORE_UPGRADE"
UPGRADE_COMMAND = "capabilities store upgrade"

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
    SHA-256 of the SQL text exactly as given. `core`, for a step that references
    core tables, is the `(major, minor)` of the core it needs; the step is refused
    until the store records the core at that version or later. `major`, for a step
    that raises its owner to a new schema major, is that major: such a step is
    applied outside the store upgrade only to an empty store."""

    id: str
    sql: str
    core: tuple[int, int] | None = None
    major: int | None = None

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.sql.encode("utf-8")).hexdigest()

    # A step also reads as the `(step id, sql)` pair it stands beside in a list of
    # steps, so code that takes a step apart by position reads either alike.
    def __iter__(self):
        return iter((self.id, self.sql))

    def __getitem__(self, index):
        return (self.id, self.sql)[index]

    def __len__(self) -> int:
        return 2


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
    core: MigrateResult | None = None


# The core's own steps and the version they bring it to, which `migrate` runs for
# every other owner first. The first takes a store that holds the same tables as
# owner `capabilities` (schema version 1.23 or older) to the core in place, and
# makes them on a store that holds none (`_core`); the second gives every
# connection its opaque id and moves every core reference to it
# (`_connection_ids`); the third keys every agent and node reference by what
# its parent takes with it, guards the ids and makes a parent's delete
# deliberate (`_keys`); the fourth, a minor step, records when the store made
# each connection's row (`_connection_created`). While empty, nothing runs for
# the core and nothing is written for it.
CORE_STEPS: tuple[Step, ...] = (
    Step(_core.CORE_STEP_ID, _core.CORE_STEP_SQL, major=_core.CORE_MAJOR),
    Step(_connection_ids.STEP_ID, _connection_ids.STEP_SQL, major=_connection_ids.MAJOR),
    Step(_keys.STEP_ID, _keys.STEP_SQL, major=_keys.MAJOR),
    Step(_connection_created.STEP_ID, _connection_created.STEP_SQL),
)
CORE_VERSION = (_connection_created.MAJOR, _connection_created.MINOR)

# The pre-image the connection id step leaves: each connection's id beside the
# capability, the name it was keyed by before core 3.0 and the label it had.
CONNECTION_NAMES_TABLE = _connection_ids.NAMES_TABLE

# The store's major is the major the store records for `core`; a store with
# platform tables that hold rows but no `core` row is at major 1. STORE_MAJOR is
# the store major this library's own steps read.
STORE_MAJOR = CORE_VERSION[0] if CORE_STEPS else 1


class StoreMajor(NamedTuple):
    """A store's major and since when: `major` is None for an empty store, and
    `since` is when the latest major step of the core this library knows was
    applied, None when none was."""

    major: int | None
    since: datetime | None


def upgrading() -> bool:
    """Whether this process runs as part of the store upgrade."""
    return os.environ.get(UPGRADE_ENV) == "1"


@dataclass
class MigrateStatus:
    """Where `owner`'s tables stand against the caller's steps, read without a lock.

    `state` is `current` when every step is applied and the store records the
    caller's version or a newer minor; `pending` when `migrate` has something to
    do; `checksum_mismatch`, `schema_too_new` or `upgrade_needed` when `migrate`
    would refuse."""

    owner: str
    schema: str
    state: str
    major: int
    minor: int
    stored_major: int | None = None
    stored_minor: int | None = None
    applied: list[str] = field(default_factory=list)
    pending: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def moved_stub(old_name: str, columns: Sequence[str | tuple[str, str]], message: str) -> str:
    """The SQL of a refusing stub, for a major step to run after it renamed or
    dropped the table `old_name`: a view under that name with the table's old
    `columns` - each a name, typed `text`, or a `(name, sql_type)` pair - holding
    no data, whose every read fails with an error carrying `message` (say, what
    to run), and which takes no write. Only a step marked `major` may leave it."""
    if not isinstance(old_name, str) or not old_name:
        raise DbError("bad_step", f"a stub needs the moved table's name, not {old_name!r}")
    if not isinstance(message, str) or not message.strip():
        raise DbError("bad_step", f"the stub for {old_name} needs a message")
    if isinstance(columns, str):
        raise DbError("bad_step", f"the stub for {old_name} takes a sequence of columns")
    selected = []
    for column in columns:
        name, kind = (column, "text") if isinstance(column, str) else tuple(column)
        if not isinstance(name, str) or not name or not isinstance(kind, str) or not kind:
            raise DbError("bad_step", f"the stub for {old_name} has a bad column {column!r}",
                          "name each column, or give it as (name, sql_type)")
        selected.append(f"CAST(NULL AS {kind}) AS {_quote_identifier(name)}")
    if not selected:
        raise DbError("bad_step", f"the stub for {old_name} names no column")
    literal = "'" + message.replace("'", "''") + "'"
    # Text cast to integer runs when a query is planned, never when the view is
    # made, so every read of the view fails with the message as the bad input.
    return (f"CREATE VIEW {_quote_identifier(old_name)} AS SELECT {', '.join(selected)} "
            f"WHERE CAST(CAST({literal} AS text) AS integer) IS NULL")


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
        if step.core is not None:
            core = step.core
            if not (isinstance(core, (tuple, list)) and len(core) == 2
                    and all(isinstance(v, int) and not isinstance(v, bool) and v >= 0
                            for v in core)):
                raise DbError("bad_step", f"step {step.id!r} declares core {core!r}",
                              "declare the core version a step needs as (major, minor)")
            step = Step(step.id, step.sql, (core[0], core[1]), step.major)
        if step.major is not None and (isinstance(step.major, bool)
                                       or not isinstance(step.major, int) or step.major < 1):
            raise DbError("bad_step", f"step {step.id!r} declares major {step.major!r}",
                          "declare the major a step raises its owner to as a positive integer")
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


def _core_name(name: str) -> bool:
    """Whether `name` is the core's: a core table, `<table>_*`, or a pre-image."""
    return name.startswith(CORE_PREIMAGE_PREFIX) or any(
        name == table or name.startswith(table + "_") for table in CORE_TABLES)


def _law(owner: str) -> tuple[str, str]:
    """How `owner` names what its steps create: briefly, and in full."""
    if owner == CORE_OWNER:
        core = f"a core table, <table>_* or {CORE_PREIMAGE_PREFIX}*"
        return core, core
    return f"{owner}_*", f"{owner} or {owner}_*"


def _stub_names(conn: Any, schema: str, before: set[tuple]) -> set[str]:
    """The views in `schema` named for a relation the schema held in `before`:
    the refusing stubs a major step may leave under a name it moved."""
    held = {name for kind, _oid, nspname, name in before
            if kind == "relation" and nspname == schema}
    views = {row[0] for row in conn.execute(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = %s AND c.relkind = 'v'", (schema,)).fetchall()}
    return held & views


def _violations(before: set[tuple], after: set[tuple], owner: str, schema: str,
                stubs: set[str] = frozenset()) -> list[str]:
    bad = []
    for kind, _oid, nspname, name in sorted(after - before, key=lambda r: (r[2], r[3])):
        if kind == "schema":
            bad.append(f"schema {name}")
        elif nspname != schema:
            bad.append(f"{kind} {nspname}.{name} (outside schema {schema})")
        elif name in RESERVED_NAMES:
            bad.append(f"{kind} {name} (reserved)")
        elif kind == "relation" and name in stubs:
            continue
        elif owner == CORE_OWNER:
            if not _core_name(name):
                bad.append(f"{kind} {name}")
        elif _core_name(name):
            bad.append(f"{kind} {name} (reserved for {CORE_OWNER})")
        elif not (name == owner or name.startswith(owner + "_")):
            bad.append(f"{kind} {name}")
    return bad


def _check_core(conn: Any, schema: str, owner: str, step: Step) -> None:
    """Refuse `step` while the store's core is older than the version it declares."""
    stored = _stored_version(conn, schema, CORE_OWNER)
    if stored is None or stored < step.core:
        major, minor = step.core
        held = ("has no core tables" if stored is None
                else f"records the core at {stored[0]}.{stored[1]}")
        raise DbError("core_too_old",
                      f"step {step.id} of {owner} needs the store's core at schema version "
                      f"{major}.{minor} or later, and the store {held}",
                      "migrate the core first with the release that owns the core tables "
                      f"at version {major}.{minor} or later, then migrate again")


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


def _may_create(conn: Any, schema: str) -> bool:
    """Whether this session may create a table in `schema`: its role holds CREATE
    on it and the transaction is not read-only."""
    return conn.execute("SELECT has_schema_privilege(%s, 'CREATE') "
                        "AND current_setting('transaction_read_only') = 'off'",
                        (schema,)).fetchone()[0]


def _bootstrap(conn: Any, schema: str) -> None:
    """Create the schema and the platform tables if missing, under the schema lock.
    Existence is checked first, so a role that may not create them can still use them
    once they exist. `schema_channel` came later than the other two, so a store made
    before it is left without it by a session that may not create it, and gets it
    from the first one that may."""
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
        channel = conn.execute("SELECT to_regclass(%s)",
                               (f'"{schema}".{CHANNEL_TABLE}',)).fetchone()[0]
        if channel is None and _may_create(conn, schema):
            table = sql.SQL("{}.{}").format(sql.Identifier(schema),
                                            sql.Identifier(CHANNEL_TABLE))
            conn.execute(sql.SQL(
                "CREATE TABLE {} (channel text NOT NULL CHECK (channel <> ''), "
                "scope text NOT NULL CHECK (scope <> ''), version bigint NOT NULL, "
                "PRIMARY KEY (channel, scope))").format(table))
            conn.execute(sql.SQL(
                "COMMENT ON TABLE {} IS 'One version per channel and scope, raised by a "
                "writer inside the transaction whose change it announces and read by "
                "followers that poll for what moved.'").format(table))
            conn.execute(sql.SQL(
                "COMMENT ON COLUMN {}.scope IS 'What the change is about within the "
                "channel, such as a project id.'").format(table))
            conn.execute(sql.SQL(
                "COMMENT ON COLUMN {}.version IS 'Raised by one on every announced change; "
                "a pair with no row has version 0.'").format(table))


def _stored_version(conn: Any, schema: str, owner: str) -> tuple[int, int] | None:
    _, sql = _psycopg()
    row = conn.execute(sql.SQL("SELECT major, minor FROM {}.{} WHERE owner = %s").format(
        sql.Identifier(schema), sql.Identifier(VERSION_TABLE)), (owner,)).fetchone()
    return (row[0], row[1]) if row else None


def _store_empty(conn: Any, schema: str) -> bool:
    """Whether the store is empty: no `schema_version` table, or no row in it."""
    _, sql = _psycopg()
    if conn.execute("SELECT to_regclass(%s)",
                    (f'"{schema}".{VERSION_TABLE}',)).fetchone()[0] is None:
        return True
    return conn.execute(sql.SQL("SELECT NOT EXISTS (SELECT 1 FROM {}.{})").format(
        sql.Identifier(schema), sql.Identifier(VERSION_TABLE))).fetchone()[0]


def _applied_steps(conn: Any, schema: str, owner: str) -> dict[str, str]:
    _, sql = _psycopg()
    if conn.execute("SELECT to_regclass(%s)",
                    (f'"{schema}".{LEDGER_TABLE}',)).fetchone()[0] is None:
        return {}
    return dict(conn.execute(sql.SQL("SELECT step, checksum FROM {}.{} WHERE owner = %s")
                             .format(sql.Identifier(schema), sql.Identifier(LEDGER_TABLE)),
                             (owner,)).fetchall())


def _upgrade_needed(owner: str, stored: tuple[int, int] | None, plan: list[Step],
                    applied: Iterable[str], major: int, empty: bool) -> str | None:
    """Why taking `owner`'s steps to `major` would cross a schema major, which
    only the store upgrade does, or None. An empty store takes every step. The
    major recorded for `core` on a store with rows but no `core` row is 1."""
    if empty or upgrading():
        return None
    held = stored[0] if stored is not None else (1 if owner == CORE_OWNER else None)
    rising = [step.major for step in plan if step.major is not None and step.id not in applied]
    if not rising and (held is None or held >= major):
        return None
    wanted = max([*rising, major])
    if held is None:
        return (f"this code's steps for the {owner} tables raise them to schema major "
                f"{wanted}, and the store already holds other tables")
    return (f"the store's {owner} tables are at schema major {held}, and this code wants "
            f"major {wanted}")


def _upgrade_refusal(reason: str) -> DbError:
    return DbError("store_upgrade_needed",
                   f"{reason}; moving the store to a newer major is the store upgrade, "
                   "which nothing runs by itself",
                   f"a person runs `{UPGRADE_COMMAND}`, the one way to cross a major; "
                   f"`{UPGRADE_COMMAND} --check` says what it will do")


_TOO_NEW_HINT = ("the store moved to a newer major than this code reads: run "
                 "`capabilities self-update`, then `capabilities update`")


def _major_refusal(found: int | None) -> DbError | None:
    """The refusal for code reading `STORE_MAJOR` against a store at major
    `found`, or None where the store is empty or at that major."""
    if found is None or found == STORE_MAJOR:
        return None
    if found > STORE_MAJOR:
        return DbError("schema_too_new",
                       f"the store is at schema major {found}, newer than the major "
                       f"{STORE_MAJOR} this code reads", _TOO_NEW_HINT)
    return _upgrade_refusal(f"the store is at schema major {found}, and this code reads "
                            f"major {STORE_MAJOR}")


def store_major(conn: Any, schema: str | None = None) -> StoreMajor:
    """The store's major and since when, in one read without a lock, changing
    nothing; inside a caller's transaction it reads in a savepoint of it. The
    major is the one the store records for `core`, 1 for a store with rows but no
    `core` row, and None for an empty store; `since` is when the latest major step
    of `CORE_STEPS` was applied, None when none was."""
    psycopg, sql = _psycopg()
    schema = check_schema_name(schema if schema is not None else bound_schema(conn))
    steps = [step.id for step in CORE_STEPS if step.major is not None]
    query = sql.SQL(
        "SELECT EXISTS (SELECT 1 FROM {versions}), "
        "(SELECT major FROM {versions} WHERE owner = %s), "
        "(SELECT max(applied_at) FROM {ledger} WHERE owner = %s AND step = ANY(%s::text[]))"
    ).format(versions=sql.SQL("{}.{}").format(sql.Identifier(schema),
                                              sql.Identifier(VERSION_TABLE)),
             ledger=sql.SQL("{}.{}").format(sql.Identifier(schema),
                                            sql.Identifier(LEDGER_TABLE)))
    try:
        with conn.transaction():
            held, major, since = conn.execute(query, (CORE_OWNER, CORE_OWNER, steps)).fetchone()
    except psycopg.errors.UndefinedTable:
        return StoreMajor(None, None)
    if not held:
        return StoreMajor(None, None)
    if major is None:
        return StoreMajor(1, None)
    return StoreMajor(major, since)


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
                      _TOO_NEW_HINT)
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
    tables are already in place. Refuses as the locked path would. A missing
    `schema_channel` leaves work only for a session that may create it."""
    _, sql = _psycopg()
    with conn.transaction():
        for table in (LEDGER_TABLE, VERSION_TABLE, CHANNEL_TABLE):
            missing = conn.execute("SELECT to_regclass(%s)",
                                   (f'"{schema}".{table}',)).fetchone()[0] is None
            if missing and (table != CHANNEL_TABLE or _may_create(conn, schema)):
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


def status(conn: Any, owner: str, steps: Iterable[Step | Sequence[str]], *,
           major: int, minor: int, schema: str | None = None) -> MigrateStatus:
    """Report what `migrate` would do for `owner`, changing nothing and taking no
    lock. `conn` comes from `connect` and must be idle."""
    psycopg, sql = _psycopg()
    owner = check_owner(owner)
    major, minor = _check_version_numbers(major, minor)
    schema = check_schema_name(schema if schema is not None else bound_schema(conn))
    plan = _normalise_steps(steps)
    if conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE:
        raise DbError("connection_busy", "status needs an idle connection",
                      "commit or roll back before asking")
    report = MigrateStatus(owner=owner, schema=schema, state="pending",
                           major=major, minor=minor)
    applied: dict[str, str] = {}
    stored = None
    with conn.transaction():
        books = all(conn.execute("SELECT to_regclass(%s)",
                                 (f'"{schema}".{table}',)).fetchone()[0] is not None
                    for table in (LEDGER_TABLE, VERSION_TABLE))
        empty = _store_empty(conn, schema)
        if books:
            stored = _stored_version(conn, schema, owner)
            applied = dict(conn.execute(
                sql.SQL("SELECT step, checksum FROM {}.{} WHERE owner = %s").format(
                    sql.Identifier(schema), sql.Identifier(LEDGER_TABLE)),
                (owner,)).fetchall())
    if stored is not None:
        report.stored_major, report.stored_minor = stored
    for step in plan:
        if step.id not in applied:
            report.pending.append(step.id)
        elif applied[step.id] != step.checksum:
            report.changed.append(step.id)
        else:
            report.applied.append(step.id)
    if stored is not None and stored[0] > major:
        report.state = "schema_too_new"
    elif report.changed:
        report.state = "checksum_mismatch"
    elif _upgrade_needed(owner, stored, plan, applied, major, empty):
        report.state = "upgrade_needed"
    elif report.pending or stored is None or stored < (major, minor):
        report.state = "pending"
    else:
        report.state = "current"
        if stored > (major, minor):
            report.warnings.append(
                f"the store's {owner} tables are at schema version {stored[0]}.{stored[1]}, "
                f"a newer minor than the {major}.{minor} this code knows; "
                "it works, but an update is available")
    return report


def migrate(conn: Any, owner: str, steps: Iterable[Step | Sequence[str]], *,
            major: int, minor: int, schema: str | None = None) -> MigrateResult:
    """Apply `owner`'s steps that are not yet applied, in order, each once.

    `conn` comes from `connect` (its bound schema is used) and must be idle. Each
    step runs in its own transaction under a per-owner advisory lock, together with
    its ledger row, so concurrent callers apply it exactly once. Refuses (DbError):
    a stored major newer than `major` (`schema_too_new`), an applied step whose SQL
    changed (`checksum_mismatch`), a step that creates an object not named
    `<owner>`/`<owner>_*` in the schema or named for the core (`naming_law`, rolled
    back), a step declaring a core version the store's core has not reached
    (`core_too_old`), and a failing step (`step_failed`, rolled back). Outside the
    store upgrade (`upgrading()`), it refuses before applying anything to cross a
    schema major (`store_upgrade_needed`): a pending step marked `major` on a store
    that is not empty, or a stored major for the owner older than `major`. A newer
    stored minor proceeds with a warning in the result. For any owner but `core`,
    the core's own steps (`CORE_STEPS`) are migrated first, under the same rule and
    judging the store empty or not as it was before them, and a refusal of theirs
    refuses the call before any of `owner`'s steps. Afterwards the caller's
    version is recorded unless the store's is newer. When every step is applied and
    the version recorded, it takes no lock at all; otherwise a lock held elsewhere
    is waited for at most LOCK_WAIT_SECONDS and then refused (`store_busy`)."""
    return _migrate(conn, owner, steps, major=major, minor=minor, schema=schema, empty=None)


def _migrate(conn: Any, owner: str, steps: Iterable[Step | Sequence[str]], *,
             major: int, minor: int, schema: str | None, empty: bool | None) -> MigrateResult:
    """`migrate`, with `empty` the store's emptiness when the call began, or None
    to read it when it is needed."""
    psycopg, sql = _psycopg()
    owner = check_owner(owner)
    major, minor = _check_version_numbers(major, minor)
    schema = check_schema_name(schema if schema is not None else bound_schema(conn))
    plan = _normalise_steps(steps)
    if conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE:
        raise DbError("connection_busy", "migrate needs an idle connection",
                      "commit or roll back before migrating")
    result = MigrateResult(owner=owner, schema=schema)
    if owner != CORE_OWNER and CORE_STEPS:
        if empty is None:
            with conn.transaction():
                empty = _store_empty(conn, schema)
        result.core = _migrate(conn, CORE_OWNER, CORE_STEPS, major=CORE_VERSION[0],
                               minor=CORE_VERSION[1], schema=schema, empty=empty)
    lock_key = f"capabilities_contract:{schema}:{owner}"
    ledger = sql.SQL("{}.{}").format(sql.Identifier(schema), sql.Identifier(LEDGER_TABLE))
    versions = sql.SQL("{}.{}").format(sql.Identifier(schema), sql.Identifier(VERSION_TABLE))

    settled = _settled(conn, schema, owner, plan, major, minor, result)
    if not settled:
        with conn.transaction():
            if empty is None:
                empty = _store_empty(conn, schema)
            if not empty:
                stored = _check_version(conn, schema, owner, major, minor, result)
                applied = _applied_steps(conn, schema, owner)
                for step in plan:
                    if step.id in applied and applied[step.id] != step.checksum:
                        raise DbError("checksum_mismatch",
                                      f"step {step.id} of {owner} was applied with different "
                                      "SQL", "never edit an applied step; add a new step instead")
                reason = _upgrade_needed(owner, stored, plan, applied, major, empty)
                if reason:
                    raise _upgrade_refusal(reason)
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
            if step.core is not None:
                _check_core(conn, schema, owner, step)
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
            stubs = _stub_names(conn, schema, before) if step.major is not None else set()
            bad = _violations(before, _snapshot(conn), owner, schema, stubs)
            if bad:
                brief, full = _law(owner)
                raise DbError("naming_law",
                              f"step {step.id} of {owner} creates objects not named "
                              f"{brief}: {', '.join(bad)}",
                              f"name everything the step creates {full} "
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
