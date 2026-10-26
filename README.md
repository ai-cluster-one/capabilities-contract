# capabilities-contract

The capabilities contract as a Python library, in two parts. `capabilities_contract.capability` is the code every capability shares - the core, store and connections tiers - which each capability binds rather than carries a copy of; see [Capability](#capability). `capabilities_contract.db` is the one way the capabilities manager, its capabilities and ContextKit reach the shared PostgreSQL database: resolve which database a project uses, connect bound to its schema, migrate each owner's tables once under a ledger, and report where they stand. It does nothing else: no SQLite, no project registry, no records.

## Install

```
pip install capabilities-contract
```

Its dependencies are `psycopg[binary]>=3.2,<4` and `pynacl>=1.5,<2`, each imported lazily: `import capabilities_contract.db` does not import psycopg, only `connect`, `batch`, `migrate`, `status`, `announce` and `Follower` do, and only sealing or opening a secret of [the vault](#vault) imports PyNaCl. A capability declares it in its PEP 723 header by a version range, so a release inside the range reaches it with no edit of its own:

```python
# /// script
# dependencies = ["capabilities-contract>=0.9,<1"]
# ///
```

## Capability

`capabilities_contract.capability` holds the code every capability of the capabilities package shares, as three tiers, each one file under `capabilities_contract/capability/tiers/`: `core` (the declaration surface - summary, manifest, references, guide, ids - and the file, project and I/O plumbing), `store` (the records adapter for identifiers, policy, settings, connections and documents, and a store-mode project's records in its store) and `connections` (the credential cascade and the connection resolver, for a capability that implements connections).

A tier is not a module. `bind(namespace, *tiers)` executes each named tier, in order, in `namespace`, which a capability passes as its own `globals()` where it has defined its declarations:

```python
from capabilities_contract.capability import bind as _contract_bind
_contract_bind(globals(), "core")
_contract_bind(globals(), "store")
_contract_bind(globals(), "connections")
```

So a tier reads the capability's declarations (`NAME`, `SCOPE`, `STATE`, `CRED_KEYS`, `WRITE_VERBS` and the others the package docstring lists) and calls its hooks (`_cmd_connections`, `_inventory`, `_tables` ...) as the capability's own code would, and every name it defines is the capability's: a test that replaces one on the capability's module replaces it for the tier as well. A tier is compiled under the namespace's own `from __future__ import annotations`, as its text would be were it part of the capability's file.

`capabilities_contract.capability.store` is the store tier as a module of its own, for a process that carries no capability - the capabilities manager, a capability's bundled service, a test. `tier_path(tier)` gives a tier's file and `TIERS` names the three.

## Which database

`resolve_setting(project_root)` returns the database setting in force for a process standing in that project, as a `Setting`, reading and never writing. It asks three levels in order, and the first that answers is used whole, never completed from a lower level:

1. `project` - the `AGENTKIT_DB_*` keys in the project's `.env.local` and `.env`, `.env.local` winning key by key;
2. `environment` - the same keys in the process environment;
3. `machine` - the machine's store setting file, `$XDG_CONFIG_HOME/agentkit/store.json`, or `~/.config/agentkit/store.json` when `XDG_CONFIG_HOME` is unset, an `agentkit.store.v1` document whose format is the capabilities package's [SHEBANG.md, "The store setting"](https://github.com/ai-cluster-one/capabilities/blob/main/SHEBANG.md#the-store-setting). `setting_path()` gives its absolute path.

A level answers when it sets any `AGENTKIT_DB_*` key to a non-empty value, or, for the machine level, when the file exists. `project_root=None` means the process stands in no project, and the project level is not asked.

The keys (`KEYS`): `AGENTKIT_DB_URL`, `AGENTKIT_DB_HOST`, `AGENTKIT_DB_PORT` (default 5432), `AGENTKIT_DB_NAME`, `AGENTKIT_DB_USER`, `AGENTKIT_DB_PASSWORD`, `AGENTKIT_DB_SCHEMA` (default `agentkit`), `AGENTKIT_DB_SSLMODE` (default `require`), `AGENTKIT_DB_SSLROOTCERT`, `AGENTKIT_DB_TRANSACTION_HOST`, `AGENTKIT_DB_TRANSACTION_PORT`. Within one level `AGENTKIT_DB_URL` wins and that level's other keys are ignored, except `AGENTKIT_DB_SCHEMA` and the two transaction keys, which apply beside a URL.

The store has one address unless a level names a transaction address as well: `AGENTKIT_DB_TRANSACTION_HOST` and `AGENTKIT_DB_TRANSACTION_PORT`, or `transaction_host` and `transaction_port` in the machine file. It is the same store reached at another endpoint, typically a transaction-mode pooler such as Supabase's on port 6543, and it takes the level's own database, user, password, sslmode and schema; a transaction address naming only a port keeps the session address's host, and one naming only a host keeps its port. The address the level names otherwise is the session address. `Setting.has_transaction_address` says whether a level named one, `Setting.transaction_kwargs()` gives the driver's arguments for it (the session address's when none is named), and the report shows it under `transaction`. A transaction address alone does not make a level answer whole: a level setting only a transaction key is refused as incomplete, never completed from a lower level. A transaction port is 1-65535, a transaction host has no whitespace, and `sslmode` `disable` reaches only a local transaction host. A URL is a `postgresql://` or `postgres://` URL; one that names no `sslmode` is connected with `require`. A project file setting a key with the prefix that is not one of these is refused.

The checks are the same at every level: `host`, `database` and `user` with no whitespace, `port` 1-65535, `sslmode` one of `require`, `verify-ca`, `verify-full`, or `disable` for a local host (`localhost`, a loopback address or a Unix socket directory, which is also what a URL naming no host reaches); `disable` elsewhere, `allow` and `prefer` are refused as `sslmode_too_weak`; a schema is a lowercase identifier and never `public`, `information_schema` or `pg_*`. A refusal from the project or environment level names the level and the files or variables it read. A machine file of a newer `agentkit.store.*` version is refused as `store_setting_too_new`. With no level answering it raises `DbError("store_not_configured", ...)` with a hint naming the keys and `capabilities store set`.

`Setting.level` names the level that answered (`LEVELS`), and `Setting.sources` every file, as an absolute path, or variable that supplied a value in force. `Setting.report()` gives the whole setting for a status or doctor surface with every secret replaced by `***`: the password field, or for a URL the parameters libpq reads from it (every parameter libpq's own option table marks as a password, such as `password`, `sslpassword` and `oauth_client_secret`, and the SCRAM keys hidden, `sslmode` defaulting to `require`), never the URL's text; a URL libpq cannot parse reports as `{"unparseable": true}`. The repr never shows the password or the URL.

## Connect

```python
from capabilities_contract.db import DbError, Step, connect, migrate

conn = connect(application_name="automations", project_root=root)
```

`connect(*, application_name, project_root=None, setting=None, connect_timeout=10, transaction=False, local_settings=None)` returns a psycopg 3 connection to the database `resolve_setting(project_root)` names, or to `setting` when one is passed, whose `search_path` is that setting's schema alone, never `public`, so unqualified names land in that schema. The schema need not exist yet: `migrate` creates it, in the schema the connection is bound to. A store that does not answer within `connect_timeout` seconds (`CONNECT_TIMEOUT_SECONDS`) is refused as `store_unreachable`. Both ends of the connection send TCP keepalives - after 15 seconds idle, every 5 seconds, giving up after 3 unanswered probes - so the store drops a client that died without closing and the client learns of a store that went away. A keepalive is never sent while data the client sent waits for its acknowledgement, so the client also gives the connection up once what it sent has gone unacknowledged for 20 seconds (libpq's `tcp_user_timeout`, `TCP_USER_TIMEOUT_MILLISECONDS`, on a platform whose TCP offers it): a network flow that stopped carrying packets without a FIN or a reset fails in that time as a lost connection, rather than when the store ends the session.

That is a session connection, to the session address: it binds the schema for its session and may hold session state, as a process holding `LISTEN` must. With `transaction=True`, `connect` returns a transaction connection, to the transaction address, or to the one address when the setting names none. It carries no session state, so a transaction-mode pooler, which hands the server session to another client after every transaction, serves it correctly: psycopg prepares no statement on it (`prepare_threshold=None`), the schema is bound with `SET LOCAL search_path` at the start of every transaction rather than once for the session, also around each statement in autocommit mode, and a statement that would leave state in the session - `LISTEN`, `UNLISTEN`, `PREPARE`, a session `SET` or `RESET`, `set_config(..., false)`, a session advisory lock, a cursor `WITH HOLD` - is refused as `session_state` before it is sent. Transaction-level state is fine: `SET LOCAL`, `set_config(..., true)`, `pg_advisory_xact_lock`. `local_settings`, a mapping of run-time parameters such as `{"statement_timeout": "30000"}`, is set beside the schema at the start of every transaction of a transaction connection, and once for the session of a session connection. A transaction connection sends no startup option, which a transaction-mode pooler refuses: each run-time parameter the setting's `options` or `PGOPTIONS` names (`-c name=value`, `--name=value`) is set for each of its transactions instead, and `default_transaction_read_only=on` makes each of them read-only; any other startup option is refused as `session_state`. A transaction connection at a transaction address of its own makes one round trip as it connects, severed when it is not back within `connect_timeout`, so a pooler that holds the client while the store behind it does not answer is refused as `store_unreachable` in that time rather than after the pooler's own wait. On a transaction connection, a statement that would open a transaction and is one of its own - any statement in autocommit, or a plain read (`SELECT`, `WITH`, `VALUES`, `TABLE` or `SHOW`, naming no write, lock, sequence or setting) at READ COMMITTED - reaches the store in one round trip: the schema binding, the statement and its commit go as one simple query, or as one pipeline when the statement takes parameters, so the store never holds a transaction that waits on the client, and the connection is idle after it, never `idle in transaction`; a transaction-mode pooler hands the server session on as soon as it answers. A read inside a transaction that is open - a `transaction()` block, or after a write not yet committed - runs in that transaction, and a write that opens a transaction leaves it open for `commit()`, as before. A connection set to another isolation level, or to `read_only` or `deferrable`, opens a transaction for a read as before. Client-side TCP keepalives apply to both kinds; only a session connection also asks the server to probe it. A server-side (named) cursor is not bound; use client cursors on a transaction connection. `migrate` and `status` work on either kind.

A transaction connection is the process's working connection, since it carries nothing from one transaction to the next: the first `connect(..., transaction=True)` opens it, `close()` or leaving `with` ends the loan - rolling back what was not committed and resetting what the borrower changed, such as `autocommit` or `row_factory` - and every later `connect` for the same address is lent that same connection, its schema, `local_settings` and `application_name` bound for each of its transactions as that call names them. A short command therefore connects once, and a long-running process keeps one connection for all its work. A loan taken while another is still out gets a working connection of its own; each beyond the first is closed once it has sat idle for 30 seconds (`SPARE_IDLE_SECONDS`), and every one is closed when the process exits. `disconnect()` closes the idle ones at once, for a process that is about to wait a long time without the store; `disconnect(every=True)` closes the lent ones too. A child of `fork` never uses or closes its parent's. After `close()` the connection reads as `closed` and refuses statements, as any closed connection does. A session connection is never lent: each `connect` without `transaction` opens one, and its `close()` closes it.

A working connection the store or the network lost is replaced: as it is lent, one the store closed is noticed without a round trip, and one that sat idle for 10 seconds (`PING_AFTER_SECONDS`) makes one round trip, cut at the connect timeout, so a connection that stopped answering is not waited on. One the store or the network closed while it was lent is replaced, without a round trip, before a statement that is a transaction of its own is sent on it. A statement that finds its connection gone before anything of its transaction reached the store - the statement that opens a transaction, a statement in autocommit before it is sent, or the start of a `transaction()` block - runs once more on a new connection in place of the old one. A plain read that is a transaction of its own runs once more on a new connection whenever it loses its connection, while a write in autocommit that was sent is never sent again, since its commit went with it. So does a plain read - `SELECT`, `WITH`, `VALUES`, `TABLE` or `SHOW`, naming no write, lock, sequence or setting - in a transaction at READ COMMITTED that has run only plain reads: each such read sees the store as it is when it starts, so it runs on the new connection in a transaction opened again there, with every `transaction()` block it is inside opened again too, and the commit of a transaction that has only read - `commit()`, the end of a block, or an autocommit statement's own - is not refused when its connection is gone, since it has nothing to commit. A store that ends the session itself (an administrator's or a shutdown's error) counts as a lost connection. A commit whose answer was lost is never sent again, and a transaction that loses its connection after earlier statements fails as before, since what it did is gone; its `rollback()` is then not refused, since the store rolled the transaction back with the connection, and the next statement runs on a new connection. A connect that fails before the store answers - refused, reset, timed out - is tried again after a short pause, jittered and doubling, at most 3 times (`CONNECT_ATTEMPTS`) while `connect_timeout` is not spent, each try waiting at most half of it; a store that answers with a refusal of its own, such as a wrong password, is not tried again. A process whose store did not answer does not dial it again on every statement: after a transaction connection to an address found no store answering, a further one to that address - a `connect`, or the replacement of a lost connection - is refused at once as `store_unreachable`, carrying the last failure as its cause, for a pause drawn between half and all of 1 second (`RECONNECT_FIRST_SECONDS`), doubling with each failure in a row up to 30 seconds (`RECONNECT_LONGEST_SECONDS`); the first one after the pause dials again, and one the store answers ends the pause. The pause is kept per process, so the first connect of a process always dials, and a session connection is never paused.

A session address that is Supabase's transaction pooler - a host under `pooler.supabase.com` on port 6543 - is refused as `transaction_pooler` before anything is sent to it, whichever kind of connection asks, because session connections cannot work through it; the hint names its session pooler, the same host on port 5432, as the address, and port 6543 as the transaction port. As the transaction address it is accepted.

## Batch

```python
from capabilities_contract.db import batch

counts, names = batch(conn, [
    "SELECT count(*) FROM automations_runs",
    ("SELECT name FROM automations_jobs WHERE host = %s", (host,)),
])
```

`batch(conn, statements)` sends independent statements - each a query, or a `(query, params)` pair, and each one statement - to the store as one pipeline on a connection from `connect`, and returns each one's rows in order: a list of rows for a statement that returns rows, an empty list for one that does not. The store answers them all in one round trip, directly or through a transaction-mode pooler. On a transaction connection the schema is bound for them. Where each would be a transaction of its own - in autocommit, or when every one is a plain read - they run as one transaction of their own and leave the connection idle, and a batch of plain reads that loses its connection runs again on a new one; otherwise they run inside the transaction that is open, or the one the first of them opens, which stays open for the caller's `commit()`. A statement that fails fails the batch with its error, and the statements after it are not run.

## Migrate

```python
result = migrate(conn, "automations", [
    Step("0001-runs", "CREATE TABLE automations_runs (id bigint PRIMARY KEY)"),
    ("0002-runs-host", "ALTER TABLE automations_runs ADD COLUMN host text"),
], major=1, minor=1)
for warning in result.warnings:
    print(warning)
```

`migrate(conn, owner, steps, *, major, minor)` applies each step that is not yet applied, in order, once. The owner is the tool that owns the tables, a lowercase identifier without underscores. The first call creates the schema and three platform tables in it: `schema_ledger(owner, step, checksum, applied_at, library_version)`, `schema_version(owner, major, minor, updated_at)` and `schema_channel(channel, scope, version)`, the change versions of [Changes](#changes); a store whose schema was made before `schema_channel` existed gets it on the next `migrate` by a role that may create in the schema, once, under the schema lock, and a role that may not migrates such a store as before, leaving `announce` and `Follower` refused as `not_migrated` until one that may has run. Each step runs in its own transaction under a per-owner advisory lock together with its ledger row, so concurrent processes apply it exactly once. When every step is already applied and the store records the caller's version, it reads that without taking any lock, so a session holding one stops no tool whose tables are in place. Otherwise a lock is tried rather than queued for, so a process that dies while waiting leaves nothing in the queue: after 10 seconds held elsewhere (`LOCK_WAIT_SECONDS`) `migrate` refuses with `store_busy`, and a session that holds a lock and then issues no statement for 5 seconds (`LOCK_IDLE_SECONDS`) is ended by the server, which frees the lock. It returns a `MigrateResult` with `applied`, `skipped`, `warnings`, `major` and `minor`.

It refuses with a `DbError`, rolling the step back: an applied step whose SQL changed (`checksum_mismatch`); a step that creates a relation, index, sequence, type, function, collation, statistics object or schema not named `<owner>` or `<owner>_*` inside the configured schema, or named `schema_ledger`, `schema_version` or `schema_channel` (`naming_law`); a step that fails or ends its own transaction (`step_failed`). A step cannot use statements that refuse a transaction, such as `CREATE INDEX CONCURRENTLY`.

The version rule lets tools at different releases share one database. When the store records a newer major for the owner than the caller's `major`, `migrate` refuses with `schema_too_new` before applying anything, and the hint says to update. When it records the same major with a newer minor, it proceeds and adds a warning to `result.warnings`, keeping the stored version. Otherwise it records the caller's version.

## Changes

```python
from capabilities_contract.db import Follower, announce, connect

with connect(application_name="automations", project_root=root, transaction=True) as conn:
    conn.execute("UPDATE automations_jobs SET paused = true WHERE name = %s", (name,))
    announce(conn, "automations_jobs", project_id)
    conn.commit()

follower = Follower([("automations_jobs", project_id), "automations_runs"],
                    application_name="automations", project_root=root)
follower.run(lambda moved: reload(moved), stop=stopping)
```

A change other processes must see is announced as a version, and a process follows it by polling, so neither side holds a session for it: both work on the process's working connection, directly or through a transaction-mode pooler. The store keeps one version per channel and scope in the platform table `schema_channel`; a pair that was never announced has version 0. A channel is a lowercase identifier of at most 63 characters, conventionally `<owner>_<event>`, and a scope is a non-empty string naming what the change is about, such as a project id.

`announce(conn, channel, scope)` raises that pair's version by one and returns the new version. A writer calls it inside its own transaction, after the change it announces, on a connection from `connect`: the raise is committed with the change and rolled back with it, so a follower never sees a raise whose change did not happen. It is one statement, one round trip. The pair's row stays locked until the writer's transaction ends, so writers announcing the same pair take turns at it: announce last, just before the commit, so that each holds it for the shortest time.

`Follower(follow, *, application_name, project_root=None, setting=None, seen=None)` follows each item of `follow`, a `(channel, scope)` pair or a channel alone, which means every scope of that channel. `read(conn=None)` returns every followed version as the store holds it now, keyed by `(channel, scope)`, in one query and one round trip on the process's working connection, whatever the number of channels. Given `conn`, a connection from `connect` the process already works on and keeps lent, it reads on that one instead and leaves it open, in whatever transaction it was in, so a process that holds its working connection follows without a second. `poll(conn=None)` takes `conn` the same way and returns only the versions that moved since the previous poll, with their new values; the first poll returns every version it reads, unless `seen` - the `seen` property of an earlier follower, the versions it last read - is given, when it returns only those that moved since then. A follower that was not polling for a while, or whose process was down and started again with its `seen`, therefore gets every pair that moved meanwhile on its first poll, once, with its latest version.

`run(on_change, *, interval=1.0, stop=None)` polls every `interval` seconds (`FOLLOW_INTERVAL_SECONDS`) until the `threading.Event` `stop` is set, and calls `on_change` with what moved: once for the first poll even when nothing moved, so the caller reads its state after the versions it starts from and misses nothing that changes later, and afterwards only when something moved. A poll that finds the store unreachable is tried again at the next interval, and the first one that reaches it reports everything that moved meanwhile. A store whose schema has no `schema_channel` yet is refused as `not_migrated`.

## Vault

`capabilities_contract.vault` keeps each agent's secrets in its store, sealed with the agent's own key. The key is `AGENT_ENCRYPTION_KEY` (`KEY_ENV`): 32 random bytes as URL-safe base64 without padding, 43 characters (`generate_key`, `parse_key`, which refuses anything else as `bad_key` without echoing it). `key_source(project_root)` finds it in the project's `.env.local`, then its `.env`, then the machine's `$XDG_CONFIG_HOME/capabilities/shared.env` (`shared_env_path()`), then the process environment, and `agent_key` parses what it found. The store never holds a key: `fingerprint(key)`, a SHA-256 over it, is what `capabilities_agents.vault_key` and each row's `key_fingerprint` keep.

`seal(key, agent_id, name, value)` seals a value with XChaCha20-Poly1305 (libsodium, through PyNaCl) under a fresh 24-byte nonce, the agent id and the name bound as associated data, so a sealed value moved to another agent or name does not open; `unseal` answers None for anything that does not open. Each secret is a row of `capabilities_vault` (`agent_id`, `name`, `ciphertext`, `key_fingerprint`, `updated_at`, `updated_by`), migrated with the contract's other tables; a trigger raises the channel `capabilities_vault` (`VAULT_CHANNEL`) for the agent in `schema_channel` on every change to a row or to the agent's `vault_key`. `put`, `remove`, `rows`, `recorded_key`, `record_key` and `sealed_under_other` read and write it on a connection the caller holds; a row whose fingerprint is not the key's is unreadable, kept until it is set again or removed.

`reader(project_root, agent_id)` is the process's `Reader` of that agent's vault, or None where no key is set. `Reader.seed(rows, version)` takes what `round_trip(agent_id)` reads - the sealed rows and the channel version, two statements to send beside others in one `batch` - and `get(name)` answers a value, opening only the names asked for and keeping what it opened in memory only; without a seed it reads them itself, and asked again after `CHECK_SECONDS` it reads the channel version and rereads the rows only when it moved. A store it cannot read raises `VaultError("vault_unreadable", "the vault could not be read: ...")`, which stands for `RETRY_SECONDS`. The connections tier asks it as the credential cascade's last tier, and the store tier seeds it from the round trip that reads a project's connections. `render_text` and `parse_text` write and read the vault as KEY=value text, a value a plain line would not carry back whole as a JSON string.

## Status

```python
from capabilities_contract.db import status

report = status(conn, "automations", steps, major=1, minor=1)
print(report.state, report.pending)
```

`status(conn, owner, steps, *, major, minor)` reports what `migrate` would do with the same arguments, changing nothing and taking no lock, so it answers while another session holds one. It returns a `MigrateStatus` with `state`, `major` and `minor` (the caller's), `stored_major` and `stored_minor` (the store's, or `None`), and the step ids under `applied`, `pending` and `changed`, plus `warnings`. `state` is `current` when every step is applied and the store records the caller's version or a newer minor (which adds a warning), `pending` when `migrate` has something to apply or record, and `checksum_mismatch` or `schema_too_new` when `migrate` would refuse.

## Bodies

```python
from capabilities_contract.bodies import body_digest, check_body, materialise

path = materialise(script_body, state_dir / "bodies")
subprocess.run([str(path)], check=True)
```

`capabilities_contract.bodies` is the one way a stored executable script body - an automation's `script_body`, a stored tasks hook - is run. It imports nothing outside the standard library. `body_digest(body)` is the sha256 hex digest of the body's UTF-8 bytes. `check_body(body)` raises `ValueError` unless the body is a `str` starting with `#!`. `materialise(body, directory)` checks the body, makes the directory with mode 0700 (and its parents) when it is missing, and returns `<directory>/<body_digest(body)>`, an executable file holding the body: a regular file already there with the same content and mode 0700 is reused, and anything else at that path is replaced atomically by a file written beside it, chmodded 0700 and moved into place with `os.replace`. A process running the file never sees it partial, and processes materialising the same body at once each return the whole file.

## Errors

Every failure is a `DbError` with `slug` (stable, for the caller to map to an exit code), `message` and `hint` (possibly `None`). Slugs: `store_not_configured`, `store_not_postgres`, `store_setting_unreadable`, `store_setting_too_new`, `bad_store_setting`, `sslmode_too_weak`, `bad_schema_name`, `store_unreachable`, `transaction_pooler`, `session_state`, `driver_missing`, `bad_application_name`, `bad_owner`, `bad_version`, `bad_step`, `connection_busy`, `checksum_mismatch`, `naming_law`, `step_failed`, `schema_too_new`, `store_busy`, `bad_channel`, `bad_scope`, `bad_follow`, `bad_interval`, `not_migrated`.

## Development

```
uv venv && uv pip install -e ".[dev]"
uv run pytest
```

The suite starts a throwaway PostgreSQL cluster with TLS under a temporary directory (`initdb` and `pg_ctl` on `PATH`, or in `$PG_BIN`) on a random port. Set `CAPABILITIES_CONTRACT_TEST_URL` to a TLS-enabled server's admin URL to run it against that server instead, as CI does. The transaction-pooler tests run when `CAPABILITIES_CONTRACT_TEST_PGBOUNCER` names a `pgbouncer` executable: they put it in front of the test cluster in `pool_mode=transaction` with one server connection. The tests that compare the machine file reader with the manager's own run only when `CAPABILITIES_STORE_TIER` names a store tier module such as `capabilities_contract/capability/store.py`; otherwise they skip.
