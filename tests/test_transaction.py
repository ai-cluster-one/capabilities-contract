"""The store's two addresses: a session address for connections that hold session state
(LISTEN, session locks), and a transaction address for everything else, whose
connections carry no session state, so a transaction-mode pooler can serve them."""

from __future__ import annotations

import psycopg
import pytest
from conftest import write_family_setting

from capabilities_contract.db import DbError, Setting, connect, migrate, resolve_setting

POOLER = "aws-0-region.pooler.supabase.com"
PASSWORD = "not-a-real-secret"
FAMILY = {"schema": "agentkit.store.v1", "host": "db.example.test", "port": 5432,
          "database": "app", "user": "agent", "sslmode": "require", "password": "pw"}


def _rows(conn, query, params=()):
    return conn.execute(query, params).fetchall()


def _raw(conn, query, params=()):
    """A statement sent past the binding cursor, as a pooler's next client would see it."""
    return psycopg.Cursor(conn).execute(query, params).fetchall()


# --- which address each connection dials -------------------------------------------

@pytest.fixture
def reached(monkeypatch):
    calls = []

    def fake_connect(*args, **kwargs):
        calls.append(kwargs)
        raise psycopg.OperationalError("reached the driver")

    monkeypatch.setattr(psycopg, "connect", fake_connect)
    monkeypatch.setattr(psycopg.Connection, "connect", classmethod(
        lambda cls, *a, **k: fake_connect(*a, **k)))
    return calls


def _dialled(reached, setting, transaction):
    with pytest.raises(DbError) as caught:
        connect(application_name="test", setting=setting, transaction=transaction)
    assert caught.value.slug == "store_unreachable"
    return reached[-1]


def test_without_a_transaction_address_both_paths_dial_the_one_address(reached):
    setting = Setting(level="environment", host="db.example.test", port=5432,
                      database="app", user="agent", sslmode="require", password=PASSWORD)
    session = _dialled(reached, setting, False)
    transaction = _dialled(reached, setting, True)
    assert (session["host"], session["port"]) == ("db.example.test", 5432)
    assert (transaction["host"], transaction["port"]) == ("db.example.test", 5432)
    assert "prepare_threshold" not in session
    assert transaction["prepare_threshold"] is None


def test_the_transaction_path_dials_the_transaction_address(reached):
    setting = Setting(level="environment", host="db.example.test", port=5432,
                      database="app", user="agent", sslmode="require", password=PASSWORD,
                      transaction_host="pool.example.test", transaction_port=6432)
    session = _dialled(reached, setting, False)
    transaction = _dialled(reached, setting, True)
    assert (session["host"], session["port"]) == ("db.example.test", 5432)
    assert (transaction["host"], transaction["port"]) == ("pool.example.test", 6432)
    assert transaction["dbname"] == "app" and transaction["user"] == "agent"
    assert transaction["password"] == PASSWORD


def test_a_url_takes_the_transaction_port_beside_it(reached):
    setting = Setting(level="environment", transaction_port=6543,
                      url=f"postgresql://postgres.ref:{PASSWORD}@{POOLER}:5432/postgres")
    session = _dialled(reached, setting, False)
    transaction = _dialled(reached, setting, True)
    assert "port" not in session and session["conninfo"].endswith(":5432/postgres")
    assert transaction["port"] == 6543 and transaction["conninfo"] == session["conninfo"]


def test_supabases_transaction_pooler_serves_as_the_transaction_address_only(reached):
    split = Setting(level="environment", host=POOLER, port=5432, database="postgres",
                    user="postgres.ref", sslmode="require", password=PASSWORD,
                    transaction_port=6543)
    assert _dialled(reached, split, True)["port"] == 6543
    assert _dialled(reached, split, False)["port"] == 5432
    one = Setting(level="environment", host=POOLER, port=6543, database="postgres",
                  user="postgres.ref", sslmode="require", password=PASSWORD)
    for transaction in (False, True):
        before = len(reached)
        with pytest.raises(DbError) as caught:
            connect(application_name="test", setting=one, transaction=transaction)
        assert caught.value.slug == "transaction_pooler"
        assert "transaction port" in caught.value.hint
        assert len(reached) == before


# --- where the transaction address is configured -------------------------------------

def test_each_level_names_its_transaction_address(clean_env, tmp_path, monkeypatch):
    write_family_setting(clean_env, {**FAMILY, "transaction_host": "pool.example.test",
                                     "transaction_port": 6432})
    machine = resolve_setting(None)
    assert (machine.transaction_host, machine.transaction_port) == ("pool.example.test", 6432)
    assert machine.report()["transaction"] == {"host": "pool.example.test", "port": 6432}

    monkeypatch.setenv("AGENTKIT_DB_URL", "postgresql://agent@db.example.test/app")
    monkeypatch.setenv("AGENTKIT_DB_TRANSACTION_PORT", "6543")
    env = resolve_setting(None)
    assert (env.level, env.transaction_host, env.transaction_port) == \
        ("environment", None, 6543)
    assert "AGENTKIT_DB_TRANSACTION_PORT" in env.sources

    project = tmp_path / "project"
    project.mkdir()
    (project / ".env.local").write_text(
        "AGENTKIT_DB_HOST=db.example.test\nAGENTKIT_DB_NAME=app\nAGENTKIT_DB_USER=agent\n"
        "AGENTKIT_DB_TRANSACTION_HOST=pool.example.test\n")
    found = resolve_setting(project)
    assert (found.level, found.transaction_host, found.transaction_port) == \
        ("project", "pool.example.test", None)


def test_a_setting_naming_none_has_one_address(clean_env):
    write_family_setting(clean_env, FAMILY)
    found = resolve_setting(None)
    assert not found.has_transaction_address
    assert found.transaction_kwargs() == found.connect_kwargs()
    assert "transaction" not in found.report()


def test_a_transaction_address_alone_does_not_complete_a_lower_level(clean_env, monkeypatch):
    write_family_setting(clean_env, FAMILY)
    monkeypatch.setenv("AGENTKIT_DB_TRANSACTION_PORT", "6543")
    with pytest.raises(DbError) as caught:
        resolve_setting(None)
    assert caught.value.slug == "bad_store_setting"


@pytest.mark.parametrize("fields", [
    {"transaction_port": 0}, {"transaction_port": "x"}, {"transaction_host": "a b"},
    {"transaction_host": ""},
])
def test_a_bad_transaction_address_is_refused(clean_env, fields):
    write_family_setting(clean_env, {**FAMILY, **fields})
    with pytest.raises(DbError) as caught:
        resolve_setting(None)
    assert caught.value.slug == "bad_store_setting"


def test_plain_text_reaches_no_remote_transaction_address(clean_env):
    write_family_setting(clean_env, {**FAMILY, "host": "localhost", "sslmode": "disable",
                                     "transaction_host": "pool.example.test"})
    with pytest.raises(DbError) as caught:
        resolve_setting(None)
    assert caught.value.slug == "sslmode_too_weak"
    write_family_setting(clean_env, {**FAMILY, "host": "localhost", "sslmode": "disable",
                                     "transaction_host": "127.0.0.1",
                                     "transaction_port": 6432})
    assert resolve_setting(None).transaction_port == 6432


# --- a transaction connection carries no session state --------------------------------

def test_each_transaction_runs_bound_and_the_session_keeps_nothing(store):
    with connect(application_name="tx-test", transaction=True) as conn:
        assert conn.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
        assert _rows(conn, "SHOW search_path") == [(store.schema,)]
        conn.commit()
        # What the session would show the next client of a pooler: no binding.
        assert _raw(conn, "SHOW search_path") != [(store.schema,)]
        conn.rollback()
        assert _rows(conn, "SHOW search_path") == [(store.schema,)]
        conn.rollback()
        with conn.transaction():
            assert _rows(conn, "SHOW search_path") == [(store.schema,)]
            with pytest.raises(psycopg.errors.DivisionByZero), conn.transaction():
                conn.execute("SELECT 1/0")
            assert _rows(conn, "SHOW search_path") == [(store.schema,)]
        conn.autocommit = True
        assert _rows(conn, "SHOW search_path") == [(store.schema,)]
        assert _raw(conn, "SHOW search_path") != [(store.schema,)]
        with conn.transaction():
            assert _rows(conn, "SHOW search_path") == [(store.schema,)]


def test_migrate_and_unqualified_names_work_on_a_transaction_connection(store):
    with connect(application_name="tx-test", transaction=True) as conn:
        migrate(conn, "demo", [("0001", "CREATE TABLE demo_rows (id int)")], major=1, minor=0)
        conn.execute("INSERT INTO demo_rows VALUES (1)")
        conn.commit()
        conn.autocommit = True
        conn.execute("INSERT INTO demo_rows VALUES (2)")
        assert _rows(conn, "SELECT id FROM demo_rows ORDER BY id") == [(1,), (2,)]
        assert _rows(conn, "SELECT schemaname FROM pg_tables WHERE tablename = 'demo_rows'") \
            == [(store.schema,)]
        again = migrate(conn, "demo", [("0001", "CREATE TABLE demo_rows (id int)")],
                        major=1, minor=0)
        assert again.skipped == ["0001"]


def test_no_statement_is_prepared_on_a_transaction_connection(store):
    with connect(application_name="tx-test", transaction=True) as conn:
        for _ in range(10):
            conn.execute("SELECT %s::int", (1,)).fetchone()
        assert _rows(conn, "SELECT count(*) FROM pg_prepared_statements") == [(0,)]
    with connect(application_name="session-test") as conn:
        for _ in range(10):
            conn.execute("SELECT %s::int", (1,)).fetchone()
        assert _rows(conn, "SELECT count(*) FROM pg_prepared_statements")[0][0] > 0


@pytest.mark.parametrize("statement", [
    "LISTEN demo_changed",
    "SET search_path TO public",
    "SET statement_timeout = 1000",
    "RESET search_path",
    "SELECT pg_advisory_lock(1)",
    "select pg_try_advisory_lock(hashtext('x'))",
    "SELECT pg_advisory_lock_shared(1)",
    "SELECT set_config('statement_timeout', '1000', false)",
    "PREPARE p AS SELECT 1",
])
def test_session_state_is_refused_before_it_is_sent(store, statement):
    with connect(application_name="tx-test", transaction=True) as conn:
        with pytest.raises(DbError) as caught:
            conn.execute(statement)
        assert caught.value.slug == "session_state"
        assert conn.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
        assert _raw(conn, "SELECT count(*) FROM pg_listening_channels()") == [(0,)]
        conn.rollback()
        assert _raw(conn, "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                          "AND pid = pg_backend_pid()") == [(0,)]


@pytest.mark.parametrize("statement", [
    "SELECT pg_advisory_xact_lock(1)",
    "SELECT pg_try_advisory_xact_lock(hashtext('x'))",
    "SET LOCAL statement_timeout = 1000",
    "SELECT set_config('statement_timeout', '1000', true)",
])
def test_transaction_state_is_allowed(store, statement):
    with connect(application_name="tx-test", transaction=True) as conn:
        conn.execute(statement)
        conn.commit()
        assert _raw(conn, "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                          "AND pid = pg_backend_pid()") == [(0,)]


def test_a_session_connection_still_binds_its_session_and_listens(store):
    with connect(application_name="session-test") as conn:
        conn.commit()
        assert _raw(conn, "SHOW search_path") == [(store.schema,)]
        conn.rollback()
        conn.autocommit = True
        conn.execute("LISTEN demo_changed")
        assert _rows(conn, "SELECT pg_listening_channels()") == [("demo_changed",)]


def test_the_transaction_address_is_dialled_for_real(store, server):
    """A transaction address naming the same server on its own port is reached."""
    store.write(transaction_host="127.0.0.1", transaction_port=server.port)
    with connect(application_name="tx-test", transaction=True) as conn:
        assert _rows(conn, "SELECT current_setting('application_name')") == [("tx-test",)]
        assert _rows(conn, "SHOW search_path") == [(store.schema,)]


def test_local_settings_apply_to_every_transaction_and_never_to_the_session(store):
    with connect(application_name="tx-test", transaction=True,
                 local_settings={"statement_timeout": "1234"}) as conn:
        assert _rows(conn, "SHOW statement_timeout") == [("1234ms",)]
        conn.commit()
        assert _raw(conn, "SHOW statement_timeout") != [("1234ms",)]
        conn.rollback()
        conn.autocommit = True
        assert _rows(conn, "SHOW statement_timeout") == [("1234ms",)]
    with connect(application_name="session-test",
                 local_settings={"statement_timeout": "1234"}) as conn:
        conn.commit()
        assert _raw(conn, "SHOW statement_timeout") == [("1234ms",)]
