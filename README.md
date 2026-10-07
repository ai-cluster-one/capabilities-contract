# capabilities-contract

The capabilities contract as a Python library. Its first part, `capabilities_contract.db`, is the one way the capabilities manager, its capabilities and ContextKit reach the shared Postgres database: read the machine's store setting, connect bound to its schema, and migrate each owner's tables once under a ledger. It does nothing else: no SQLite, no project registry, no records.

## Install

```
pip install capabilities-contract
```

Its one dependency is `psycopg[binary]>=3.2,<4`, imported lazily: `import capabilities_contract.db` does not import psycopg, only `connect` and `migrate` do. In a PEP 723 script, pin the exact version:

```python
# /// script
# dependencies = ["capabilities-contract==0.1.0"]
# ///
```

## The store setting

`read_setting()` returns the store in force as a `Setting`, reading and never writing. `CAPABILITIES_STORE_URL`, when set, wins and must be a `postgresql://` URL. Otherwise it reads the manager's setting, written only by `capabilities store set`: the non-secret values in `$XDG_CONFIG_HOME/capabilities/store.json` and the password as `CAPABILITIES_STORE_PASSWORD` in `$XDG_CONFIG_HOME/capabilities/credentials.env`. The fields and their checks are the manager's: `host`, `database`, `user` with no whitespace, `port` 1-65535 (default 5432), `sslmode` one of `require`, `verify-ca`, `verify-full` (`disable`, `allow` and `prefer` are refused as `sslmode_too_weak`), and an optional `sslrootcert`. A `capabilities.store.v1` setting binds the schema `agentkit`; a `capabilities.store.v2` setting may name another schema in `db_schema` (the document's `schema` key is its id). The URL override binds `agentkit`. With neither a setting nor the override, it raises `DbError("store_not_configured", ..., "run capabilities store set")`.

## Connect

```python
from capabilities_contract.db import DbError, Step, connect, migrate

conn = connect(application_name="automations")
```

`connect(*, application_name, setting=None)` returns a psycopg 3 connection whose `search_path` is the configured schema alone, never `public`, so unqualified names land in that schema. The schema need not exist yet: `migrate` creates it. Pass `setting=` to use a `Setting` other than the machine's.

## Migrate

```python
result = migrate(conn, "automations", [
    Step("0001-runs", "CREATE TABLE automations_runs (id bigint PRIMARY KEY)"),
    ("0002-runs-host", "ALTER TABLE automations_runs ADD COLUMN host text"),
], major=1, minor=1)
for warning in result.warnings:
    print(warning)
```

`migrate(conn, owner, steps, *, major, minor)` applies each step that is not yet applied, in order, once. The owner is the tool that owns the tables, a lowercase identifier without underscores. The first call creates the schema and two platform tables in it: `schema_ledger(owner, step, checksum, applied_at, library_version)` and `schema_version(owner, major, minor, updated_at)`. Each step runs in its own transaction under a per-owner advisory lock together with its ledger row, so concurrent processes apply it exactly once. It returns a `MigrateResult` with `applied`, `skipped`, `warnings`, `major` and `minor`.

It refuses with a `DbError`, rolling the step back: an applied step whose SQL changed (`checksum_mismatch`); a step that creates a relation, index, sequence, type, function, collation, statistics object or schema not named `<owner>` or `<owner>_*` inside the configured schema, or named `schema_ledger` or `schema_version` (`naming_law`); a step that fails or ends its own transaction (`step_failed`). A step cannot use statements that refuse a transaction, such as `CREATE INDEX CONCURRENTLY`.

The version rule lets tools at different releases share one database. When the store records a newer major for the owner than the caller's `major`, `migrate` refuses with `schema_too_new` before applying anything, and the hint says to update. When it records the same major with a newer minor, it proceeds and adds a warning to `result.warnings`, keeping the stored version. Otherwise it records the caller's version.

## Errors

Every failure is a `DbError` with `slug` (stable, for the caller to map to an exit code), `message` and `hint` (possibly `None`). Slugs: `store_not_configured`, `store_not_postgres`, `store_setting_unreadable`, `bad_store_setting`, `sslmode_too_weak`, `bad_schema_name`, `store_unreachable`, `driver_missing`, `bad_application_name`, `bad_owner`, `bad_version`, `bad_step`, `connection_busy`, `checksum_mismatch`, `naming_law`, `step_failed`, `schema_too_new`.

## Development

```
uv venv && uv pip install -e ".[dev]"
uv run pytest
```

The suite starts a throwaway PostgreSQL cluster with TLS under a temporary directory (`initdb` and `pg_ctl` on `PATH`, or in `$PG_BIN`) on a random port. Set `CAPABILITIES_CONTRACT_TEST_URL` to a TLS-enabled server's admin URL to run it against that server instead, as CI does. The tests that compare the setting reader with the manager's own run only when `CAPABILITIES_STORE_TIER` names the manager's `contract/store.py`; otherwise they skip.
