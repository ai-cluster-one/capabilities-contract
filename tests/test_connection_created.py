"""The core's step 0042-connection-created-at: the store sets when it made a
connection's row on insert, over whatever the writer gave, never changes it,
and leaves the rows it held before the step null; a minor step, applied
outside the store upgrade, that a reader of core 4.0 still reads."""

from __future__ import annotations

import pytest

from capabilities_contract.db import _migrate, connect, migrate

CORE_4_0 = _migrate.CORE_STEPS[:3]
GIVEN = "2001-02-03T04:05:06+00:00"


@pytest.fixture()
def conn(store):
    """A connection to the test's schema, closed before the schema is dropped."""
    found = connect(application_name="capabilities-contract-tests")
    yield found
    found.close()


def _created(conn, label):
    with conn.transaction():
        return conn.execute("SELECT created_at FROM connections WHERE label = %s",
                            (label,)).fetchone()[0]


def test_a_store_at_core_4_0_takes_the_step_without_the_upgrade_and_old_rows_stay_null(
        conn, monkeypatch):
    with monkeypatch.context() as patched:
        patched.setattr(_migrate, "CORE_STEPS", CORE_4_0)
        patched.setattr(_migrate, "CORE_VERSION", (4, 0))
        migrate(conn, "core", CORE_4_0, major=4, minor=0)
    with conn.transaction():
        conn.execute("INSERT INTO connections (capability, label, spec) "
                     "VALUES ('demo', 'old', '{}')")
    monkeypatch.delenv(_migrate.UPGRADE_ENV, raising=False)
    result = migrate(conn, "core", _migrate.CORE_STEPS[:4], major=4, minor=1)
    assert result.applied == ["0042-connection-created-at"]
    assert (result.major, result.minor) == (4, 1)
    assert _created(conn, "old") is None
    with conn.transaction():
        conn.execute("UPDATE connections SET created_at = %s WHERE label = 'old'", (GIVEN,))
    assert _created(conn, "old") is None
    # A reader that knows core 4.0 settles on the store at 4.1, with a warning.
    with monkeypatch.context() as patched:
        patched.setattr(_migrate, "CORE_STEPS", CORE_4_0)
        patched.setattr(_migrate, "CORE_VERSION", (4, 0))
        older = migrate(conn, "core", CORE_4_0, major=4, minor=0)
    assert older.applied == [] and (older.major, older.minor) == (4, 1)
    assert any("newer minor" in warning for warning in older.warnings)


def test_the_store_sets_the_moment_on_insert_and_no_update_moves_it(conn):
    migrate(conn, "core", _migrate.CORE_STEPS, major=4, minor=1)
    with conn.transaction():
        conn.execute("INSERT INTO connections (capability, label, spec, created_at) "
                     "VALUES ('demo', 'new', '{}', %s)", (GIVEN,))
        made, now = conn.execute("SELECT created_at, now() FROM connections "
                                 "WHERE label = 'new'").fetchone()
    assert made == now
    with conn.transaction():
        conn.execute("UPDATE connections SET spec = '{\"a\": 1}' WHERE label = 'new'")
        conn.execute("UPDATE connections SET label = 'renamed' WHERE label = 'new'")
        conn.execute("UPDATE connections SET created_at = %s WHERE label = 'renamed'",
                      (GIVEN,))
        conn.execute("UPDATE connections SET created_at = NULL WHERE label = 'renamed'")
    assert _created(conn, "renamed") == made
    comment = conn.execute("SELECT col_description('connections'::regclass, attnum) "
                           "FROM pg_attribute WHERE attrelid = 'connections'::regclass "
                           "AND attname = 'created_at'").fetchone()[0]
    assert "predates" in comment and "imported from files" in comment
