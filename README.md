# capabilities-contract

The capabilities contract as a Python library. Its first part, `capabilities_contract.db`, is the one way the capabilities manager, its capabilities and ContextKit reach the shared PostgreSQL database: resolve which database a project uses, connect bound to its schema, migrate each owner's tables once under a ledger, and report where they stand. It does nothing else: no SQLite, no project registry, no records.

## Install

```
pip install capabilities-contract
```

Its one dependency is `psycopg[binary]>=3.2,<4`, imported lazily: `import capabilities_contract.db` does not import psycopg, only `connect`, `migrate` and `status` do. In a PEP 723 script, pin the exact version:

```python
# /// script
# dependencies = ["capabilities-contract==0.4.0"]
# ///
```

## Which database

`resolve_setting(project_root)` returns the database setting in force for a process standing in that project, as a `Setting`, reading and never writing. It asks three levels in order, and the first that answers is used whole, never completed from a lower level:

1. `project` - the `AGENTKIT_DB_*` keys in the project's `.env.local` and `.env`, `.env.local` winning key by key;
2. `environment` - the same keys in the process environment;
3. `machine` - the machine's store setting file, `$XDG_CONFIG_HOME/agentkit/store.json`, or `~/.config/agentkit/store.json` when `XDG_CONFIG_HOME` is unset, an `agentkit.store.v1` document whose format is the capabilities package's [SHEBANG.md, "The store setting"](https://github.com/ai-cluster-one/capabilities/blob/main/SHEBANG.md#the-store-setting). `setting_path()` gives its absolute path.

A level answers when it sets any `AGENTKIT_DB_*` key to a non-empty value, or, for the machine level, when the file exists. `project_root=None` means the process stands in no project, and the project level is not asked.

The keys (`KEYS`): `AGENTKIT_DB_URL`, `AGENTKIT_DB_HOST`, `AGENTKIT_DB_PORT` (default 5432), `AGENTKIT_DB_NAME`, `AGENTKIT_DB_USER`, `AGENTKIT_DB_PASSWORD`, `AGENTKIT_DB_SCHEMA` (default `agentkit`), `AGENTKIT_DB_SSLMODE` (default `require`), `AGENTKIT_DB_SSLROOTCERT`. Within one level `AGENTKIT_DB_URL` wins and that level's other keys are ignored, except `AGENTKIT_DB_SCHEMA`, which applies beside a URL. A URL is a `postgresql://` or `postgres://` URL; one that names no `sslmode` is connected with `require`. A project file setting a key with the prefix that is not one of these is refused.

The checks are the same at every level: `host`, `database` and `user` with no whitespace, `port` 1-65535, `sslmode` one of `require`, `verify-ca`, `verify-full`, or `disable` for a local host (`localhost`, a loopback address or a Unix socket directory, which is also what a URL naming no host reaches); `disable` elsewhere, `allow` and `prefer` are refused as `sslmode_too_weak`; a schema is a lowercase identifier and never `public`, `information_schema` or `pg_*`. A refusal from the project or environment level names the level and the files or variables it read. A machine file of a newer `agentkit.store.*` version is refused as `store_setting_too_new`. With no level answering it raises `DbError("store_not_configured", ...)` with a hint naming the keys and `capabilities store set`.

`Setting.level` names the level that answered (`LEVELS`), and `Setting.sources` every file, as an absolute path, or variable that supplied a value in force. `Setting.report()` gives the whole setting for a status or doctor surface with every secret replaced by `***`: the password field, or for a URL the parameters libpq reads from it (every parameter libpq's own option table marks as a password, such as `password`, `sslpassword` and `oauth_client_secret`, and the SCRAM keys hidden, `sslmode` defaulting to `require`), never the URL's text; a URL libpq cannot parse reports as `{"unparseable": true}`. The repr never shows the password or the URL.

## Connect

```python
from capabilities_contract.db import DbError, Step, connect, migrate

conn = connect(application_name="automations", project_root=root)
```

`connect(*, application_name, project_root=None, setting=None, connect_timeout=10)` returns a psycopg 3 connection to the database `resolve_setting(project_root)` names, or to `setting` when one is passed, whose `search_path` is that setting's schema alone, never `public`, so unqualified names land in that schema. The schema need not exist yet: `migrate` creates it, in the schema the connection is bound to. A store that does not answer within `connect_timeout` seconds (`CONNECT_TIMEOUT_SECONDS`) is refused as `store_unreachable`. Both ends of the connection send TCP keepalives - after 30 seconds idle, every 10 seconds, giving up after 3 unanswered probes - so the store drops a client that died without closing and the client learns of a store that went away.

## Migrate

```python
result = migrate(conn, "automations", [
    Step("0001-runs", "CREATE TABLE automations_runs (id bigint PRIMARY KEY)"),
    ("0002-runs-host", "ALTER TABLE automations_runs ADD COLUMN host text"),
], major=1, minor=1)
for warning in result.warnings:
    print(warning)
```

`migrate(conn, owner, steps, *, major, minor)` applies each step that is not yet applied, in order, once. The owner is the tool that owns the tables, a lowercase identifier without underscores. The first call creates the schema and two platform tables in it: `schema_ledger(owner, step, checksum, applied_at, library_version)` and `schema_version(owner, major, minor, updated_at)`. Each step runs in its own transaction under a per-owner advisory lock together with its ledger row, so concurrent processes apply it exactly once. When every step is already applied and the store records the caller's version, it reads that without taking any lock, so a session holding one stops no tool whose tables are in place. Otherwise a lock is tried rather than queued for, so a process that dies while waiting leaves nothing in the queue: after 10 seconds held elsewhere (`LOCK_WAIT_SECONDS`) `migrate` refuses with `store_busy`, and a session that holds a lock and then issues no statement for 5 seconds (`LOCK_IDLE_SECONDS`) is ended by the server, which frees the lock. It returns a `MigrateResult` with `applied`, `skipped`, `warnings`, `major` and `minor`.

It refuses with a `DbError`, rolling the step back: an applied step whose SQL changed (`checksum_mismatch`); a step that creates a relation, index, sequence, type, function, collation, statistics object or schema not named `<owner>` or `<owner>_*` inside the configured schema, or named `schema_ledger` or `schema_version` (`naming_law`); a step that fails or ends its own transaction (`step_failed`). A step cannot use statements that refuse a transaction, such as `CREATE INDEX CONCURRENTLY`.

The version rule lets tools at different releases share one database. When the store records a newer major for the owner than the caller's `major`, `migrate` refuses with `schema_too_new` before applying anything, and the hint says to update. When it records the same major with a newer minor, it proceeds and adds a warning to `result.warnings`, keeping the stored version. Otherwise it records the caller's version.

## Status

```python
from capabilities_contract.db import status

report = status(conn, "automations", steps, major=1, minor=1)
print(report.state, report.pending)
```

`status(conn, owner, steps, *, major, minor)` reports what `migrate` would do with the same arguments, changing nothing and taking no lock, so it answers while another session holds one. It returns a `MigrateStatus` with `state`, `major` and `minor` (the caller's), `stored_major` and `stored_minor` (the store's, or `None`), and the step ids under `applied`, `pending` and `changed`, plus `warnings`. `state` is `current` when every step is applied and the store records the caller's version or a newer minor (which adds a warning), `pending` when `migrate` has something to apply or record, and `checksum_mismatch` or `schema_too_new` when `migrate` would refuse.

## Errors

Every failure is a `DbError` with `slug` (stable, for the caller to map to an exit code), `message` and `hint` (possibly `None`). Slugs: `store_not_configured`, `store_not_postgres`, `store_setting_unreadable`, `store_setting_too_new`, `bad_store_setting`, `sslmode_too_weak`, `bad_schema_name`, `store_unreachable`, `driver_missing`, `bad_application_name`, `bad_owner`, `bad_version`, `bad_step`, `connection_busy`, `checksum_mismatch`, `naming_law`, `step_failed`, `schema_too_new`, `store_busy`.

## Development

```
uv venv && uv pip install -e ".[dev]"
uv run pytest
```

The suite starts a throwaway PostgreSQL cluster with TLS under a temporary directory (`initdb` and `pg_ctl` on `PATH`, or in `$PG_BIN`) on a random port. Set `CAPABILITIES_CONTRACT_TEST_URL` to a TLS-enabled server's admin URL to run it against that server instead, as CI does. The tests that compare the machine file reader with the manager's own run only when `CAPABILITIES_STORE_TIER` names the manager's `contract/store.py`; otherwise they skip.
