"""connect and migrate against a real PostgreSQL over TLS."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import time

import psycopg
import pytest
from conftest import child_env

from capabilities_contract.db import DbError, Step, connect, migrate, resolve_setting
from capabilities_contract.version import __version__


def _connect():
    return connect(application_name="capabilities-contract-tests")


def _rows(conn, query, params=()):
    rows = conn.execute(query, params).fetchall()
    conn.commit()
    return rows


def _ledger(conn, schema, owner):
    return _rows(conn, f'SELECT step FROM "{schema}".schema_ledger WHERE owner = %s '
                       "ORDER BY step", (owner,))


def _exists(conn, name):
    return _rows(conn, "SELECT to_regclass(%s)", (name,))[0][0] is not None


# --- connect (C4) ---------------------------------------------------------------

def test_connect_binds_the_configured_schema_never_public(store):
    with _connect() as conn:
        assert _rows(conn, "SHOW search_path") == [(store.schema,)]
        assert _rows(conn, "SELECT current_schema()") == [(None,)]  # not created yet
        with pytest.raises(psycopg.errors.InvalidSchemaName):
            conn.execute("CREATE TABLE stray (id int)")
        conn.rollback()
        migrate(conn, "demo", [], major=1, minor=0)
        assert _rows(conn, "SELECT current_schema()") == [(store.schema,)]
        conn.execute("CREATE TABLE demo_plain (id int)")
        conn.commit()
        assert _rows(conn, "SELECT schemaname FROM pg_tables WHERE tablename = 'demo_plain'") \
            == [(store.schema,)]
        assert not _exists(conn, "public.demo_plain")
        assert _rows(conn, "SELECT application_name FROM pg_stat_activity "
                           "WHERE pid = pg_backend_pid()") == [("capabilities-contract-tests",)]


def test_a_machine_file_naming_no_schema_binds_agentkit(store):
    store.write(db_schema=None)
    with _connect() as conn:
        assert _rows(conn, "SHOW search_path") == [("agentkit",)]


def test_connect_runs_over_tls(store):
    with _connect() as conn:
        assert _rows(conn, "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()") \
            == [(True,)]


def test_connect_verifies_the_server_certificate_with_verify_full(store):
    if not store.server.rootcert:
        pytest.skip("no certificate to verify the test server with")
    store.write(sslmode="verify-full", sslrootcert=store.server.rootcert)
    with _connect() as conn:
        assert _rows(conn, "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()") \
            == [(True,)]


def test_verify_full_refuses_a_certificate_it_cannot_verify(store, tmp_path):
    if not store.server.rootcert:
        pytest.skip("no certificate to verify the test server with")
    other = tmp_path / "other.crt"
    subprocess.run(["openssl", "req", "-new", "-x509", "-days", "1", "-nodes",
                    "-subj", "/CN=other", "-keyout", str(tmp_path / "other.key"),
                    "-out", str(other)], check=True, capture_output=True)
    store.write(sslmode="verify-full", sslrootcert=str(other))
    with pytest.raises(DbError) as caught:
        _connect()
    assert caught.value.slug == "store_unreachable"


def test_plain_text_is_refused_by_the_server_and_the_password_is_not_shown(store, monkeypatch):
    password = store.server.password or ""
    monkeypatch.setenv("AGENTKIT_DB_URL", store.url(sslmode="disable"))
    with pytest.raises(DbError) as caught:
        _connect()
    assert caught.value.slug == "store_unreachable"
    if password:
        assert password not in str(caught.value)


# --- each level of the cascade reaches the database ----------------------------

def _bound(conn):
    return _rows(conn, "SHOW search_path")[0][0], _rows(
        conn, "SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()")[0][0]


def _env_file(root, name, keys):
    root.mkdir(parents=True, exist_ok=True)
    (root / name).write_text("".join(f"{k}={v}\n" for k, v in keys.items()))


def test_the_project_files_reach_the_database(store, tmp_path):
    store.write(host="machine.invalid")  # the machine file would fail if it were read
    project = tmp_path / "project"
    _env_file(project, ".env", store.keys(AGENTKIT_DB_PASSWORD="wrong"))
    _env_file(project, ".env.local", {"AGENTKIT_DB_PASSWORD": store.server.password or ""})
    with connect(application_name="t", project_root=project) as conn:
        assert _bound(conn) == (store.schema, True)


def test_a_project_url_reaches_the_database_and_binds_its_schema(store, tmp_path):
    store.write(host="machine.invalid")
    project = tmp_path / "project"
    _env_file(project, ".env.local", {"AGENTKIT_DB_URL": store.url(),
                                      "AGENTKIT_DB_SCHEMA": store.schema,
                                      "AGENTKIT_DB_HOST": "ignored.invalid"})
    with connect(application_name="t", project_root=project) as conn:
        assert _bound(conn) == (store.schema, True)


def test_the_environment_fields_reach_the_database(store, monkeypatch, tmp_path):
    store.write(host="machine.invalid")
    for key, value in store.keys().items():
        monkeypatch.setenv(key, value)
    with connect(application_name="t", project_root=tmp_path / "no-env-files") as conn:
        assert _bound(conn) == (store.schema, True)


def test_an_environment_url_reaches_the_database_with_tls_by_default(store, monkeypatch):
    store.write(host="machine.invalid")
    url = store.url()
    monkeypatch.setenv("AGENTKIT_DB_URL", url.replace("sslmode=require", "application_name=x"))
    monkeypatch.setenv("AGENTKIT_DB_SCHEMA", store.schema)
    with connect(application_name="t", project_root=None) as conn:
        assert _bound(conn) == (store.schema, True)


def test_a_url_without_a_schema_binds_agentkit(store, monkeypatch):
    monkeypatch.setenv("AGENTKIT_DB_URL", store.url())
    with connect(application_name="t") as conn:
        assert _bound(conn) == ("agentkit", True)


def test_the_machine_file_reaches_the_database(store, tmp_path):
    with connect(application_name="t", project_root=tmp_path) as conn:
        assert _bound(conn) == (store.schema, True)


# --- migrate (C6) ----------------------------------------------------------------

STEPS = [
    Step("0001", "CREATE TABLE demo_items (id bigint PRIMARY KEY, name text)"),
    ("0002", "CREATE INDEX demo_items_name ON demo_items (name)"),
    ("0003", "CREATE TYPE demo_state AS ENUM ('a', 'b'); "
             "CREATE SEQUENCE demo_seq; "
             "CREATE FUNCTION demo_one() RETURNS int LANGUAGE sql AS 'SELECT 1'; "
             "CREATE VIEW demo AS SELECT 1 AS x"),
]


def test_migrate_creates_the_ledger_and_applies_each_step_once(store):
    with _connect() as conn:
        first = migrate(conn, "demo", STEPS, major=1, minor=0)
        assert first.applied == ["0001", "0002", "0003"] and first.skipped == []
        assert (first.major, first.minor, first.warnings) == (1, 0, [])
        cols = _rows(conn, "SELECT table_name, column_name FROM information_schema.columns "
                           "WHERE table_schema = %s AND table_name LIKE 'schema_%%' "
                           "ORDER BY table_name, ordinal_position", (store.schema,))
        assert cols == [("schema_ledger", c) for c in
                        ("owner", "step", "checksum", "applied_at", "library_version")] + \
                       [("schema_version", c) for c in ("owner", "major", "minor", "updated_at")]
        again = migrate(conn, "demo", STEPS, major=1, minor=0)
        assert again.applied == [] and again.skipped == ["0001", "0002", "0003"]
        more = migrate(conn, "demo", [*STEPS, ("0004", "ALTER TABLE demo_items ADD c int")],
                       major=1, minor=1)
        assert more.applied == ["0004"]
        assert _ledger(conn, store.schema, "demo") == [("0001",), ("0002",), ("0003",),
                                                       ("0004",)]
        assert _rows(conn, f'SELECT library_version FROM "{store.schema}".schema_ledger '
                           "LIMIT 1") == [(__version__,)]
        assert _rows(conn, f'SELECT major, minor FROM "{store.schema}".schema_version') \
            == [(1, 1)]


def test_owners_keep_separate_ledgers(store):
    with _connect() as conn:
        migrate(conn, "alpha", [("0001", "CREATE TABLE alpha_t (id int)")], major=1, minor=0)
        migrate(conn, "beta", [("0001", "CREATE TABLE beta_t (id int)")], major=3, minor=2)
        assert _rows(conn, f'SELECT owner, major, minor FROM "{store.schema}".schema_version '
                           "ORDER BY owner") == [("alpha", 1, 0), ("beta", 3, 2)]


def test_an_applied_step_with_changed_sql_is_refused(store):
    with _connect() as conn:
        migrate(conn, "demo", STEPS[:1], major=1, minor=0)
        changed = [("0001", "CREATE TABLE demo_items (id int)"), ("0002", "SELECT 1")]
        with pytest.raises(DbError) as caught:
            migrate(conn, "demo", changed, major=1, minor=0)
        assert caught.value.slug == "checksum_mismatch"
        assert _ledger(conn, store.schema, "demo") == [("0001",)]


def test_a_failing_step_is_rolled_back_whole(store):
    with _connect() as conn:
        with pytest.raises(DbError) as caught:
            migrate(conn, "demo", [("0001", "CREATE TABLE demo_a (id int); SELECT 1/0")],
                    major=1, minor=0)
        assert caught.value.slug == "step_failed"
        assert not _exists(conn, f"{store.schema}.demo_a")
        assert _ledger(conn, store.schema, "demo") == []


def test_a_busy_connection_is_refused(store):
    with _connect() as conn:
        conn.execute("SELECT 1")
        with pytest.raises(DbError) as caught:
            migrate(conn, "demo", STEPS, major=1, minor=0)
        assert caught.value.slug == "connection_busy"


@pytest.mark.parametrize("owner", ["Demo", "demo_x", "schema", "1demo", "", None, "a" * 32])
def test_a_bad_owner_is_refused(store, owner):
    with _connect() as conn, pytest.raises(DbError) as caught:
        migrate(conn, owner, STEPS, major=1, minor=0)
    assert caught.value.slug == "bad_owner"


def test_duplicate_step_ids_are_refused(store):
    with _connect() as conn, pytest.raises(DbError) as caught:
        migrate(conn, "demo", [("1", "SELECT 1"), ("1", "SELECT 2")], major=1, minor=0)
    assert caught.value.slug == "bad_step"


CONCURRENT = textwrap.dedent("""
    import json, sys, time, pathlib
    from capabilities_contract.db import connect, migrate
    conn = connect(application_name="worker-" + sys.argv[1])
    go = pathlib.Path(sys.argv[2])
    while not go.exists():
        time.sleep(0.005)
    steps = [
        ("0001", "CREATE TABLE race_hits (n int); INSERT INTO race_hits VALUES (1); "
                 "SELECT pg_sleep(1)"),
        ("0002", "INSERT INTO race_hits VALUES (2); SELECT pg_sleep(0.5)"),
        ("0003", "INSERT INTO race_hits VALUES (3)"),
    ]
    result = migrate(conn, "race", steps, major=1, minor=0)
    print(json.dumps({"applied": result.applied, "skipped": result.skipped}))
""")


def test_two_processes_migrating_one_owner_apply_each_step_exactly_once(store, tmp_path):
    script = tmp_path / "worker.py"
    script.write_text(CONCURRENT)
    go = tmp_path / "go"
    env = child_env(store.config_home)
    procs = [subprocess.Popen([sys.executable, str(script), str(i), str(go)], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
             for i in range(2)]
    with _connect() as conn:
        # Both have connected before either starts.
        for _ in range(3000):
            names = _rows(conn, "SELECT count(*) FROM pg_stat_activity "
                                "WHERE application_name LIKE 'worker-%%'")[0][0]
            if names == 2:
                break
            time.sleep(0.01)
        assert names == 2
        go.touch()
        outs = [p.communicate(timeout=60) for p in procs]
        for p, (_out, err) in zip(procs, outs, strict=True):
            assert p.returncode == 0, err
        results = [json.loads(out) for out, _ in outs]
        applied = sorted(s for r in results for s in r["applied"])
        assert applied == ["0001", "0002", "0003"]
        for r in results:
            assert sorted(r["applied"] + r["skipped"]) == ["0001", "0002", "0003"]
        assert _rows(conn, "SELECT n FROM race_hits ORDER BY n") == [(1,), (2,), (3,)]
        assert _ledger(conn, store.schema, "race") == [("0001",), ("0002",), ("0003",)]


# --- naming law (C7) --------------------------------------------------------------

@pytest.mark.parametrize("sql, named", [
    ("CREATE TABLE stray (id int)", "relation stray"),
    ("CREATE TABLE demo_t (id int); CREATE INDEX stray_idx ON demo_t (id)", "stray_idx"),
    ("CREATE SEQUENCE stray_seq", "stray_seq"),
    ("CREATE TYPE stray_kind AS ENUM ('x')", "type stray_kind"),
    ("CREATE FUNCTION stray_fn() RETURNS int LANGUAGE sql AS 'SELECT 1'", "stray_fn"),
    ("CREATE VIEW demox AS SELECT 1", "demox"),
    ("CREATE TABLE public.demo_public (id int)", "outside schema"),
    ("CREATE SCHEMA demo_extra", "schema demo_extra"),
    ("CREATE TABLE demo_t (id int); ALTER TABLE demo_t RENAME TO renamed", "renamed"),
])
def test_a_step_creating_an_object_outside_the_owners_names_is_refused(store, sql, named):
    with _connect() as conn:
        migrate(conn, "demo", [], major=1, minor=0)  # the platform tables exist first
        snapshot = _rows(conn, "SELECT count(*) FROM pg_class")
        with pytest.raises(DbError) as caught:
            migrate(conn, "demo", [("0001", sql)], major=1, minor=0)
        assert caught.value.slug == "naming_law" and named in caught.value.message
        assert _rows(conn, "SELECT count(*) FROM pg_class") == snapshot
        for name in ("stray", "demo_t", "renamed", "demox", "public.demo_public"):
            assert not _exists(conn, name if "." in name else f"{store.schema}.{name}")
        assert _rows(conn, "SELECT 1 FROM pg_namespace WHERE nspname = 'demo_extra'") == []
        assert _ledger(conn, store.schema, "demo") == []


def test_an_owner_may_not_create_the_reserved_tables(store):
    with _connect() as conn:
        migrate(conn, "demo", [], major=1, minor=0)
        for sql in (
            "DROP TABLE schema_version; CREATE TABLE schema_version (owner text)",
            "CREATE TABLE public.schema_ledger (id int)",
        ):
            with pytest.raises(DbError) as caught:
                migrate(conn, "demo", [("0001", sql)], major=1, minor=0)
            assert caught.value.slug == "naming_law"
        assert _rows(conn, f'SELECT owner, major FROM "{store.schema}".schema_version') \
            == [("demo", 1)]
        assert not _exists(conn, "public.schema_ledger")


def test_the_owners_own_name_and_prefix_are_allowed(store):
    with _connect() as conn:
        result = migrate(conn, "demo", [("0001", "CREATE TABLE demo (id serial PRIMARY KEY); "
                                                 "CREATE TABLE demo_more (id int)")],
                         major=1, minor=0)
        assert result.applied == ["0001"]


# --- version rule and skew (C8) ------------------------------------------------------

HEAD = [("0001", "CREATE TABLE skew_t (id int)"), ("0002", "ALTER TABLE skew_t ADD c int")]


def test_a_newer_stored_major_is_refused_before_anything_is_applied(store):
    with _connect() as conn:
        migrate(conn, "skew", HEAD, major=2, minor=0)
        with pytest.raises(DbError) as caught:
            migrate(conn, "skew", [*HEAD[:1], ("0009", "CREATE TABLE skew_old (id int)")],
                    major=1, minor=4)
        err = caught.value
        assert err.slug == "schema_too_new" and "2.0" in err.message and "update" in err.hint
        assert not _exists(conn, f"{store.schema}.skew_old")
        assert _rows(conn, f'SELECT major, minor FROM "{store.schema}".schema_version') \
            == [(2, 0)]


def test_a_newer_stored_minor_proceeds_with_a_warning_and_keeps_the_stored_version(store):
    with _connect() as conn:
        migrate(conn, "skew", HEAD, major=1, minor=2)
        previous = migrate(conn, "skew", HEAD[:1], major=1, minor=1)
        assert previous.skipped == ["0001"] and previous.applied == []
        assert len(previous.warnings) == 1 and "1.2" in previous.warnings[0]
        assert (previous.major, previous.minor) == (1, 2)
        assert _rows(conn, f'SELECT major, minor FROM "{store.schema}".schema_version') \
            == [(1, 2)]


def test_an_older_or_equal_stored_version_records_the_callers(store):
    with _connect() as conn:
        migrate(conn, "skew", HEAD[:1], major=1, minor=0)
        same = migrate(conn, "skew", HEAD[:1], major=1, minor=0)
        assert same.warnings == [] and (same.major, same.minor) == (1, 0)
        newer = migrate(conn, "skew", HEAD, major=2, minor=0)
        assert newer.applied == ["0002"] and newer.warnings == []
        assert _rows(conn, f'SELECT major, minor FROM "{store.schema}".schema_version') \
            == [(2, 0)]


def test_skew_previous_minor_works_and_previous_major_refuses(store):
    """HEAD migrates the store; the previous minor still works against it (with a
    warning) and the previous major is refused."""
    with _connect() as conn:
        migrate(conn, "skew", HEAD, major=3, minor=1)
        prev_minor = migrate(conn, "skew", HEAD[:1], major=3, minor=0)
        assert prev_minor.warnings and prev_minor.skipped == ["0001"]
        conn.execute("INSERT INTO skew_t (id) VALUES (1)")
        conn.commit()
        with pytest.raises(DbError) as caught:
            migrate(conn, "skew", HEAD[:1], major=2, minor=9)
        assert caught.value.slug == "schema_too_new"


def test_setting_in_force_is_the_fixture(store):
    assert resolve_setting(None).schema == store.schema
