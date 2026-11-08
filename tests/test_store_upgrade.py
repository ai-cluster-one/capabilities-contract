"""A schema major crosses only through the store upgrade; a minor applies by itself."""

from __future__ import annotations

from datetime import datetime

import psycopg
import pytest

from capabilities_contract.db import (
    STORE_MAJOR,
    UPGRADE_ENV,
    DbError,
    Step,
    _migrate,
    connect,
    migrate,
    moved_stub,
    status,
    store_major,
)

# What the library itself declares, read before any test patches it.
REAL_CORE_STEPS, REAL_CORE_VERSION = _migrate.CORE_STEPS, _migrate.CORE_VERSION


@pytest.fixture(autouse=True)
def outside_the_upgrade(monkeypatch):
    """Outside the upgrade, on a library whose core holds no steps: the rule is
    measured on owners of the tests' own, and a test that needs a core gives it
    its own. The real core's crossing is `test_core`'s."""
    monkeypatch.delenv(UPGRADE_ENV, raising=False)
    monkeypatch.setattr(_migrate, "CORE_STEPS", ())
    monkeypatch.setattr(_migrate, "CORE_VERSION", (0, 0))
    monkeypatch.setattr(_migrate, "STORE_MAJOR", 1)


def _connect():
    return connect(application_name="capabilities-contract-tests")


def _rows(conn, query, params=()):
    rows = conn.execute(query, params).fetchall()
    conn.commit()
    return rows


def _ledger(conn, schema, owner):
    return [r[0] for r in _rows(conn, f'SELECT step FROM "{schema}".schema_ledger '
                                      "WHERE owner = %s ORDER BY step", (owner,))]


def _versions(conn, schema):
    return _rows(conn, f'SELECT owner, major, minor FROM "{schema}".schema_version '
                       "ORDER BY owner")


ONE = [Step("0001", "CREATE TABLE demo_a (id int)")]
MINOR = [*ONE, Step("0002", "ALTER TABLE demo_a ADD COLUMN note text")]
MAJOR = [*MINOR, Step("0003", "CREATE TABLE demo_c (id int)"),
         Step("0004", "ALTER TABLE demo_a RENAME TO demo_b", major=2)]


def _refused(caught, owner, held, wanted):
    err = caught.value
    assert err.slug == "store_upgrade_needed"
    assert f"{owner} tables are at schema major {held}" in err.message
    assert f"wants major {wanted}" in err.message
    assert "`capabilities store upgrade`" in err.hint
    assert "`capabilities store upgrade --check`" in err.hint


def test_minor_steps_still_apply_by_themselves(store):
    with _connect() as conn:
        migrate(conn, "demo", ONE, major=1, minor=0)
        done = migrate(conn, "demo", MINOR, major=1, minor=1)
        assert done.applied == ["0002"] and (done.major, done.minor) == (1, 1)
        assert _versions(conn, store.schema) == [("demo", 1, 1)]


def test_a_major_step_on_a_store_in_use_is_refused_with_nothing_applied(store):
    with _connect() as conn:
        migrate(conn, "demo", ONE, major=1, minor=0)
        with pytest.raises(DbError) as caught:
            migrate(conn, "demo", MAJOR, major=2, minor=0)
        _refused(caught, "demo", 1, 2)
        assert _ledger(conn, store.schema, "demo") == ["0001"]
        assert _versions(conn, store.schema) == [("demo", 1, 0)]
        found = status(conn, "demo", MAJOR, major=2, minor=0)
        assert found.state == "upgrade_needed" and found.pending == ["0002", "0003", "0004"]


def test_a_new_owner_with_a_major_step_on_a_store_in_use_is_refused(store):
    with _connect() as conn:
        migrate(conn, "other", [Step("0001", "CREATE TABLE other_t (id int)")],
                major=1, minor=0)
        with pytest.raises(DbError) as caught:
            migrate(conn, "demo", MAJOR, major=2, minor=0)
        assert caught.value.slug == "store_upgrade_needed"
        assert _ledger(conn, store.schema, "demo") == []
        assert status(conn, "demo", MAJOR, major=2, minor=0).state == "upgrade_needed"


def test_an_empty_store_takes_every_step_major_steps_included(store):
    with _connect() as conn:
        done = migrate(conn, "demo", MAJOR, major=2, minor=0)
        assert done.applied == ["0001", "0002", "0003", "0004"]
        assert _versions(conn, store.schema) == [("demo", 2, 0)]


def test_a_caller_on_a_newer_major_than_the_store_records_is_refused(store):
    with _connect() as conn:
        migrate(conn, "demo", ONE, major=1, minor=0)
        with pytest.raises(DbError) as caught:
            migrate(conn, "demo", MINOR, major=2, minor=0)
        _refused(caught, "demo", 1, 2)
        assert _ledger(conn, store.schema, "demo") == ["0001"]
        assert _versions(conn, store.schema) == [("demo", 1, 0)]
        assert status(conn, "demo", MINOR, major=2, minor=0).state == "upgrade_needed"


def test_the_upgrade_crosses_both_ways_and_records_the_higher_major(store, monkeypatch):
    with _connect() as conn:
        migrate(conn, "demo", ONE, major=1, minor=0)
        migrate(conn, "plain", [Step("0001", "CREATE TABLE plain_t (id int)")],
                major=1, minor=0)
        monkeypatch.setenv(UPGRADE_ENV, "1")
        assert status(conn, "demo", MAJOR, major=2, minor=0).state == "pending"
        done = migrate(conn, "demo", MAJOR, major=2, minor=0)
        assert done.applied == ["0002", "0003", "0004"] and (done.major, done.minor) == (2, 0)
        plain = migrate(conn, "plain", [Step("0001", "CREATE TABLE plain_t (id int)")],
                        major=2, minor=0)
        assert (plain.major, plain.minor) == (2, 0)
        assert _versions(conn, store.schema) == [("demo", 2, 0), ("plain", 2, 0)]
        monkeypatch.delenv(UPGRADE_ENV)
        assert migrate(conn, "demo", MAJOR, major=2, minor=0).skipped == \
            ["0001", "0002", "0003", "0004"]
        assert status(conn, "demo", MAJOR, major=2, minor=0).state == "current"


def test_only_the_value_1_marks_the_upgrade(store, monkeypatch):
    monkeypatch.setenv(UPGRADE_ENV, "yes")
    with _connect() as conn:
        migrate(conn, "demo", ONE, major=1, minor=0)
        with pytest.raises(DbError) as caught:
            migrate(conn, "demo", MAJOR, major=2, minor=0)
        assert caught.value.slug == "store_upgrade_needed"


CORE_ONE = (Step("0001-agents", "CREATE TABLE agents (id text PRIMARY KEY)"),)
CORE_TWO = (*CORE_ONE, Step("0002-nodes", "CREATE TABLE nodes (id text PRIMARY KEY)", major=2))


def test_the_core_pass_is_governed_by_the_same_rule(store, monkeypatch):
    with _connect() as conn:
        migrate(conn, "demo", ONE, major=1, minor=0)
        # A store in use with no core row is at store major 1: the core's minor applies.
        monkeypatch.setattr(_migrate, "CORE_STEPS", CORE_ONE)
        monkeypatch.setattr(_migrate, "CORE_VERSION", (1, 0))
        assert migrate(conn, "demo", ONE, major=1, minor=0).core.applied == ["0001-agents"]
        # Its major step is refused, and so is the owner's call, before anything of either.
        monkeypatch.setattr(_migrate, "CORE_STEPS", CORE_TWO)
        monkeypatch.setattr(_migrate, "CORE_VERSION", (2, 0))
        with pytest.raises(DbError) as caught:
            migrate(conn, "demo", MINOR, major=1, minor=0)
        _refused(caught, "core", 1, 2)
        assert _ledger(conn, store.schema, "core") == ["0001-agents"]
        assert _ledger(conn, store.schema, "demo") == ["0001"]
        assert _versions(conn, store.schema) == [("core", 1, 0), ("demo", 1, 0)]
        assert status(conn, "core", CORE_TWO, major=2, minor=0).state == "upgrade_needed"


def test_a_core_raised_without_a_major_step_on_a_store_at_major_1_is_refused(store, monkeypatch):
    with _connect() as conn:
        migrate(conn, "demo", ONE, major=1, minor=0)
        monkeypatch.setattr(_migrate, "CORE_STEPS", CORE_ONE)
        monkeypatch.setattr(_migrate, "CORE_VERSION", (2, 0))
        with pytest.raises(DbError) as caught:
            migrate(conn, "demo", ONE, major=1, minor=0)
        _refused(caught, "core", 1, 2)
        assert _ledger(conn, store.schema, "core") == []


def test_an_empty_store_takes_the_cores_and_the_owners_major_steps_in_one_call(store, monkeypatch):
    monkeypatch.setattr(_migrate, "CORE_STEPS", CORE_TWO)
    monkeypatch.setattr(_migrate, "CORE_VERSION", (2, 0))
    with _connect() as conn:
        done = migrate(conn, "demo", MAJOR, major=2, minor=0)
        assert done.core.applied == ["0001-agents", "0002-nodes"]
        assert done.applied == ["0001", "0002", "0003", "0004"]
        assert _versions(conn, store.schema) == [("core", 2, 0), ("demo", 2, 0)]


def test_store_major_reads_none_then_1_then_the_cores_major_with_since(store, monkeypatch):
    with _connect() as conn:
        assert store_major(conn) == (None, None)
        migrate(conn, "demo", ONE, major=1, minor=0)
        assert store_major(conn) == (1, None)
        monkeypatch.setattr(_migrate, "CORE_STEPS", CORE_TWO)
        monkeypatch.setattr(_migrate, "CORE_VERSION", (2, 0))
        monkeypatch.setenv(UPGRADE_ENV, "1")
        migrate(conn, "demo", ONE, major=1, minor=0)
        found = store_major(conn)
        assert found.major == 2 and isinstance(found.since, datetime)
        applied = _rows(conn, f'SELECT applied_at FROM "{store.schema}".schema_ledger '
                              "WHERE owner = 'core' AND step = '0002-nodes'")[0][0]
        assert found.since == applied
        monkeypatch.setattr(_migrate, "CORE_STEPS", CORE_ONE)
        assert store_major(conn) == (2, None)


def test_the_library_names_the_store_major_its_own_steps_read():
    expected = REAL_CORE_VERSION[0] if REAL_CORE_STEPS else 1
    assert expected == STORE_MAJOR == 4


MESSAGE = "this store moved to schema 2: run capabilities self-update, then capabilities update"
LEGACY = [Step("0001", "CREATE TABLE legacy_items (id integer, name text)")]


def test_a_stub_left_by_a_major_step_refuses_every_read_and_write(store, monkeypatch):
    with _connect() as conn:
        migrate(conn, "legacy", LEGACY, major=1, minor=0)
        conn.execute("INSERT INTO legacy_items VALUES (1, 'one')")
        conn.commit()
        stub = moved_stub("legacy_items", [("id", "integer"), "name"], MESSAGE)
        moved = (Step("0001-people", "ALTER TABLE legacy_items RENAME TO people; " + stub,
                      major=2),)
        monkeypatch.setenv(UPGRADE_ENV, "1")
        assert migrate(conn, "core", moved, major=2, minor=0).applied == ["0001-people"]
        assert _rows(conn, "SELECT id, name FROM people") == [(1, "one")]
        for read in ("SELECT id FROM legacy_items", "SELECT name FROM legacy_items",
                     "SELECT count(*) FROM legacy_items",
                     "SELECT name FROM legacy_items WHERE id = 1"):
            with pytest.raises(psycopg.Error) as caught:
                conn.execute(read)
            conn.rollback()
            assert MESSAGE in str(caught.value), read
        for write in ("INSERT INTO legacy_items (id, name) VALUES (2, 'two')",
                      "UPDATE legacy_items SET name = 'x'", "DELETE FROM legacy_items"):
            with pytest.raises(psycopg.Error):
                conn.execute(write)
            conn.rollback()
        assert _rows(conn, "SELECT id, name FROM people") == [(1, "one")]


def test_the_naming_law_admits_a_stub_only_in_a_major_step_under_a_held_name(store, monkeypatch):
    stub = moved_stub("legacy_items", ["id", "name"], MESSAGE)
    with _connect() as conn:
        migrate(conn, "legacy", LEGACY, major=1, minor=0)
        # Outside a major step a view under another owner's name is refused.
        with pytest.raises(DbError) as caught:
            migrate(conn, "demo", [Step("0001", "ALTER TABLE legacy_items RENAME TO demo_items; "
                                               + stub)], major=1, minor=0)
        assert caught.value.slug == "naming_law" and "legacy_items" in caught.value.message
        monkeypatch.setenv(UPGRADE_ENV, "1")
        # Inside one, a view under a name that held no relation is refused too.
        fresh = moved_stub("legacy_other", ["id"], MESSAGE)
        with pytest.raises(DbError) as caught:
            migrate(conn, "demo", [Step("0001", fresh, major=2)], major=2, minor=0)
        assert caught.value.slug == "naming_law" and "legacy_other" in caught.value.message
        assert _ledger(conn, store.schema, "demo") == []
        done = migrate(conn, "demo", [Step("0001", "ALTER TABLE legacy_items RENAME TO "
                                                   "demo_items; " + stub, major=2)],
                       major=2, minor=0)
        assert done.applied == ["0001"]


@pytest.mark.parametrize("major", [0, -1, True, "2", 1.0])
def test_a_bad_major_declaration_is_refused(store, major):
    with _connect() as conn, pytest.raises(DbError) as caught:
        migrate(conn, "demo", [Step("0001", "SELECT 1", major=major)], major=1, minor=0)
    assert caught.value.slug == "bad_step"


def test_schema_too_new_names_the_commands_that_catch_the_code_up(store):
    with _connect() as conn:
        migrate(conn, "demo", ONE, major=2, minor=0)
        with pytest.raises(DbError) as caught:
            migrate(conn, "demo", ONE, major=1, minor=0)
        err = caught.value
        assert err.slug == "schema_too_new"
        assert "`capabilities self-update`, then `capabilities update`" in err.hint


# --- the store tier refuses a store at another major before its first read ------

def _tier(monkeypatch):
    from capabilities_contract.capability import store as store_tier
    monkeypatch.setattr(store_tier, "_STORE_MAJOR_SEEN", {})
    return store_tier


def _open(store_tier, tmp_path):
    root = tmp_path / "project"
    (root / "capabilities").mkdir(parents=True, exist_ok=True)
    return store_tier.open_records(root / "capabilities", tmp_path / "global",
                                   project_root=root, project_id="000000000001")


def _tier_refused(store_tier, tmp_path, slug, *hint):
    with pytest.raises(store_tier.StoreError) as caught:
        _open(store_tier, tmp_path)
    assert caught.value.slug == slug, caught.value.message
    for words in hint:
        assert words in caught.value.hint
    with pytest.raises(store_tier.StoreError) as again:
        store_tier._store_connect(tmp_path, "capabilities-contract-tests")
    assert again.value.slug == slug


def test_the_store_tier_reads_an_empty_store_and_one_at_its_major(store, tmp_path, monkeypatch):
    store_tier = _tier(monkeypatch)
    _open(store_tier, tmp_path)
    with _connect() as conn:
        migrate(conn, "demo", ONE, major=1, minor=0)
    store_tier._STORE_MAJOR_SEEN.clear()
    _open(store_tier, tmp_path)
    conn, _schema = store_tier._store_connect(tmp_path, "capabilities-contract-tests")
    conn.close()


def test_the_store_tier_refuses_a_store_at_a_newer_major_as_schema_too_new(
        store, tmp_path, monkeypatch):
    store_tier = _tier(monkeypatch)
    with _connect() as conn:
        migrate(conn, "core", CORE_ONE, major=2, minor=0)
    _tier_refused(store_tier, tmp_path, "schema_too_new",
                  "`capabilities self-update`, then `capabilities update`")


def test_the_store_tier_refuses_a_store_at_an_older_major_as_store_upgrade_needed(
        store, tmp_path, monkeypatch):
    store_tier = _tier(monkeypatch)
    with _connect() as conn:
        migrate(conn, "demo", ONE, major=1, minor=0)
    monkeypatch.setattr(_migrate, "STORE_MAJOR", 2)
    _tier_refused(store_tier, tmp_path, "store_upgrade_needed",
                  "`capabilities store upgrade`", "`capabilities store upgrade --check`")


def test_the_store_upgrade_passes_the_store_tiers_major_guard(store, tmp_path, monkeypatch):
    store_tier = _tier(monkeypatch)
    with _connect() as conn:
        migrate(conn, "demo", ONE, major=1, minor=0)
    monkeypatch.setattr(_migrate, "STORE_MAJOR", 2)
    monkeypatch.setenv(UPGRADE_ENV, "1")
    _open(store_tier, tmp_path)
    assert store_tier._STORE_MAJOR_SEEN == {}


def test_the_store_tier_reads_the_major_once_per_process_per_store(store, tmp_path, monkeypatch):
    store_tier = _tier(monkeypatch)
    _open(store_tier, tmp_path)
    assert len(store_tier._STORE_MAJOR_SEEN) == 1
    with _connect() as conn:
        migrate(conn, "core", CORE_ONE, major=2, minor=0)
    _open(store_tier, tmp_path)  # what it found stands for the rest of the process
    assert len(store_tier._STORE_MAJOR_SEEN) == 1
