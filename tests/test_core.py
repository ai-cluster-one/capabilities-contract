"""The store's core: the manager's tables as owner `core` under plain-noun names,
made on a fresh store and moved in place on a store that holds them as owner
`capabilities`, so both end with the same catalog."""

from __future__ import annotations

import uuid

import psycopg
import pytest
from _core_store import AGENT, NODE, PEER, PREIMAGES, catalog, legacy_store

from capabilities_contract.db import (
    UPGRADE_ENV,
    DbError,
    Step,
    _core,
    _legacy,
    _migrate,
    connect,
    migrate,
)
from capabilities_contract.db import status as migrate_status

CORE_TABLES = sorted(new for _old, new in _core.CORE_RENAMES)
OLDER = list(_legacy.LIBRARY_STEPS[:29])  # up to 0029-vault


def _connect():
    return connect(application_name="capabilities-contract-tests")


def _rows(conn, query, params=()):
    with conn.transaction():
        return conn.execute(query, params).fetchall()


def _tables(conn, schema):
    return {name for (name,) in _rows(
        conn, "SELECT relname FROM pg_class WHERE relnamespace = %s::regnamespace "
              "AND relkind = 'r'", (schema,))}


@pytest.fixture(autouse=True)
def under_the_upgrade(monkeypatch):
    """The core's step raises it to major 2, which a store already in use takes
    only under the store upgrade; a test of a store outside it says so."""
    monkeypatch.setenv(UPGRADE_ENV, "1")


def _stubs(conn, schema):
    return {name for (name,) in _rows(
        conn, "SELECT relname FROM pg_class WHERE relnamespace = %s::regnamespace "
              "AND relkind = 'v'", (schema,))}


def _drop_stubs(conn, schema):
    with conn.transaction():
        for name in _stubs(conn, schema):
            conn.execute(f'DROP VIEW "{schema}"."{name}"')


@pytest.fixture()
def other_schema(store):
    """A second schema in the test database, dropped afterwards."""
    name = f"t_{uuid.uuid4().hex[:12]}"
    yield name
    with store.server.admin() as admin:
        admin.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')


def test_a_fresh_store_gets_the_core_tables_under_their_names(store, monkeypatch):
    monkeypatch.delenv(UPGRADE_ENV)  # an empty store takes the major step unasked
    with _connect() as conn:
        result = migrate(conn, "demo", [Step("0001", "CREATE TABLE demo_t (agent text "
                                                     "REFERENCES agents (id))", core=(2, 0))],
                         major=1, minor=0)
        assert result.core.applied == [_core.CORE_STEP_ID] and result.applied == ["0001"]
        assert (result.core.major, result.core.minor) == (2, 0)
        tables = _tables(conn, store.schema)
        assert set(CORE_TABLES) <= tables
        assert not [t for t in tables if t.startswith("capabilities")]
        assert _stubs(conn, store.schema) == set()
        assert _rows(conn, "SELECT owner, major, minor FROM schema_version ORDER BY owner") == [
            ("capabilities", 2, 0), ("core", 2, 0), ("demo", 1, 0)]
        assert _rows(conn, "SELECT owner, step FROM schema_ledger ORDER BY applied_at, owner") \
            == [("core", _core.CORE_STEP_ID), ("demo", "0001")]
        again = migrate(conn, "demo", [Step("0001", "CREATE TABLE demo_t (agent text "
                                                    "REFERENCES agents (id))", core=(2, 0))],
                        major=1, minor=0)
        assert again.core.skipped == [_core.CORE_STEP_ID] and again.skipped == ["0001"]


@pytest.mark.parametrize("steps, version, preimages", [
    (None, (1, 23), True),                       # library and manager steps, pre-images
    (list(_legacy.LIBRARY_STEPS), (1, 23), False),  # the library's alone
    (OLDER, (1, 13), False),                     # an older minor
], ids=["full", "library", "older"])
def test_a_capabilities_store_moves_to_the_core_in_place_with_every_row(
        store, monkeypatch, steps, version, preimages):
    with _connect() as conn:
        before = legacy_store(conn, monkeypatch, steps, version, preimages=preimages)
        held = _rows(conn, "SELECT step, checksum FROM schema_ledger "
                           "WHERE owner = 'capabilities' ORDER BY step")
        result = migrate(conn, "demo", [], major=1, minor=0)
        assert result.core.applied == [_core.CORE_STEP_ID]
        tables = _tables(conn, store.schema)
        assert not [t for t in tables if t.startswith("capabilities")]
        renames = dict((*_core.CORE_RENAMES,
                        *((name, name.replace("capabilities_", "core_")) for name in PREIMAGES)))
        for old, count in before.items():
            [(now,)] = _rows(conn, f"SELECT count(*) FROM {renames[old]}")
            assert now == count, old
        # Every row kept, its agent under the new column.
        for old, new in _core.CORE_RENAMES:
            if new in _core.AGENT_ID_TABLES and before.get(old):
                assert _rows(conn, f"SELECT DISTINCT agent_id FROM {new}") == [(AGENT,)], new
        assert _rows(conn, "SELECT name, owner_agent_id FROM connections ORDER BY name") == [
            ("home", AGENT), ("work", None)]
        assert _rows(conn, "SELECT agent_id, name FROM secrets") == [(AGENT, "DEMO_TOKEN")]
        assert _rows(conn, "SELECT count(*) FROM store_state") == [(1,)]
        if preimages:
            for name in PREIMAGES:
                assert _rows(conn, f"SELECT id, note FROM {name.replace('capabilities_', 'core_')}"
                             ) == [(1, "kept")]
        # The books are the core's: its history, its version, and a tombstone.
        steps_held = [step for step, _ in held]
        assert _rows(conn, "SELECT owner, step, checksum FROM schema_ledger "
                           "WHERE owner <> 'demo' ORDER BY step") == sorted(
            [("core", step, checksum) for step, checksum in held]
            + [("core", _core.CORE_STEP_ID, _migrate.CORE_STEPS[0].checksum)])
        assert len(steps_held) == len(steps or _legacy.LEGACY_STEPS)
        assert _rows(conn, "SELECT owner, major, minor FROM schema_version ORDER BY owner") == [
            ("capabilities", 2, 0), ("core", 2, 0), ("demo", 1, 0)]


def test_a_store_in_use_moves_to_the_core_only_under_the_upgrade(store, monkeypatch):
    with _connect() as conn:
        before = legacy_store(conn, monkeypatch)
        monkeypatch.delenv(UPGRADE_ENV)
        with pytest.raises(DbError) as caught:
            migrate(conn, "demo", [], major=1, minor=0)
        assert caught.value.slug == "store_upgrade_needed"
        assert "core tables are at schema major 1" in caught.value.message
        assert "`capabilities store upgrade`" in caught.value.hint
        conn.rollback()
        tables = _tables(conn, store.schema)
        assert set(before) <= tables and not set(CORE_TABLES) & tables
        assert _rows(conn, "SELECT owner FROM schema_ledger WHERE owner <> 'capabilities'") == []
        assert _rows(conn, "SELECT owner, major, minor FROM schema_version") == [
            ("capabilities", 1, 23)]


def test_a_moved_store_keeps_a_refusing_stub_under_each_old_name(store, monkeypatch):
    with _connect() as conn:
        legacy_store(conn, monkeypatch)
        migrate(conn, "demo", [], major=1, minor=0)
        assert _stubs(conn, store.schema) == {old for old, _new in _core.CORE_RENAMES}
        # A reader that names the old columns is refused with what to run.
        for sql, old, new in (
                ("SELECT capability, enabled FROM capabilities_policy WHERE agent_id = 'x'",
                 "capabilities_policy", "policies"),
                ("SELECT name, owner FROM capabilities_connections", "capabilities_connections",
                 "connections"),
                ("SELECT project_id FROM capabilities_service_leases",
                 "capabilities_service_leases", "service_leases")):
            with pytest.raises(psycopg.errors.InvalidTextRepresentation) as caught, \
                    conn.transaction():
                conn.execute(sql)
            assert f"{old} is now {new}" in str(caught.value)
            assert "`capabilities self-update`, then `capabilities update`" in str(caught.value)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState), conn.transaction():
            conn.execute("INSERT INTO capabilities_agents (id, slug) VALUES ('x', 'x')")


def test_a_release_that_migrates_owner_capabilities_refuses_the_core_store(
        store, monkeypatch):
    with _connect() as conn:
        legacy_store(conn, monkeypatch)
        migrate(conn, "demo", [], major=1, minor=0)
        # What 0.41.0 does: no core steps, owner `capabilities` at 1.23.
        monkeypatch.setattr(_migrate, "CORE_STEPS", ())
        with pytest.raises(DbError) as caught:
            migrate(conn, "capabilities", list(_legacy.LEGACY_STEPS), major=1, minor=23)
        assert caught.value.slug == "schema_too_new"
        assert "capabilities" in caught.value.message
        assert migrate_status(conn, "capabilities", list(_legacy.LEGACY_STEPS),
                              major=1, minor=23).state == "schema_too_new"
        assert not [t for t in _tables(conn, store.schema) if t.startswith("capabilities")]


def test_a_fresh_store_and_a_moved_one_end_with_the_same_catalog(
        store, monkeypatch, other_schema):
    with _connect() as conn:
        migrate(conn, "demo", [], major=1, minor=0)
        fresh = catalog(conn, store.schema)
        legacy_store(conn, monkeypatch, schema=other_schema)
        migrate(conn, "demo", [], major=1, minor=0, schema=other_schema)
        for name in PREIMAGES:  # made outside the steps: not in a fresh store
            conn.execute(f"DROP TABLE {name.replace('capabilities_', 'core_')}")
        conn.commit()
        # The stubs are left only where the old tables were.
        assert _stubs(conn, other_schema) == {old for old, _new in _core.CORE_RENAMES}
        _drop_stubs(conn, other_schema)
        moved = catalog(conn, other_schema)
    assert fresh - moved == set() and moved - fresh == set()
    assert {row[1] for row in fresh if row[0] == "relation" and row[2] == "r"} >= set(CORE_TABLES)


def test_an_older_store_moved_to_the_core_matches_a_fresh_one(
        store, monkeypatch, other_schema):
    with _connect() as conn:
        migrate(conn, "demo", [], major=1, minor=0)
        fresh = catalog(conn, store.schema)
        legacy_store(conn, monkeypatch, OLDER, (1, 13), schema=other_schema, preimages=False)
        migrate(conn, "demo", [], major=1, minor=0, schema=other_schema)
        _drop_stubs(conn, other_schema)
        moved = catalog(conn, other_schema)
    assert fresh - moved == set() and moved - fresh == set()


def test_nothing_in_the_core_says_project_or_capabilities(store, monkeypatch):
    with _connect() as conn:
        legacy_store(conn, monkeypatch)
        migrate(conn, "demo", [], major=1, minor=0)
        s = store.schema
        named = _rows(conn, """
            SELECT relname FROM pg_class WHERE relnamespace = %(s)s::regnamespace
             AND relkind <> 'v'
            UNION ALL SELECT conname FROM pg_constraint WHERE connamespace = %(s)s::regnamespace
            UNION ALL SELECT tgname FROM pg_trigger WHERE NOT tgisinternal AND tgrelid IN
             (SELECT oid FROM pg_class WHERE relnamespace = %(s)s::regnamespace)
            UNION ALL SELECT proname FROM pg_proc WHERE pronamespace = %(s)s::regnamespace
            UNION ALL SELECT a.attname FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
             WHERE c.relnamespace = %(s)s::regnamespace AND c.relkind = 'r' AND a.attnum > 0""",
                      {"s": s})
        assert [n for (n,) in named if "project" in n or n.startswith("capabilities")] == []
        comments = _rows(conn, """
            SELECT c.relname, d.description FROM pg_description d
             JOIN pg_class c ON c.oid = d.objoid AND d.classoid = 'pg_class'::regclass
             WHERE c.relnamespace = %s::regnamespace AND c.relname = ANY (%s)""",
                         (s, CORE_TABLES))
        assert comments
        # The names a person types stay: the environment variable, the flag and a
        # service's project command.
        allowed = ("CAPABILITIES_PROJECT_ID", "--project", "project command")
        for table, text in comments:
            for word in allowed:
                text = text.replace(word, "")
            assert "project" not in text.lower(), (table, text)
            assert not any(old in text for old, _new in _core.CORE_RENAMES), (table, text)
        for name, body in _rows(conn, "SELECT proname, prosrc FROM pg_proc "
                                      "WHERE pronamespace = %s::regnamespace", (s,)):
            # The channels keep their names.
            body = body.replace("'capabilities_vault'", "").replace(
                "'capabilities_node_update'", "")
            assert "project" not in body and "capabilities_" not in body, name


def test_every_trigger_works_on_a_store_moved_to_the_core(store, monkeypatch):
    with _connect() as conn:
        legacy_store(conn, monkeypatch)
        migrate(conn, "demo", [], major=1, minor=0)
        conn.commit()

        def refused(error, sql, params=()):
            with pytest.raises(error), conn.transaction():
                conn.execute(sql, params)

        def run(sql, params=()):
            with conn.transaction():
                return conn.execute(sql, params)

        # agents_kind, agent_nodes_system
        refused(psycopg.errors.UniqueViolation,
                "INSERT INTO agents (id, slug) VALUES ('prj_000000000009', 'work')")
        run("INSERT INTO agents (id, slug, kind) VALUES ('prj_00000000000a', 'keeper', 'system')")
        run("INSERT INTO nodes (id, label, kind) VALUES ('0f0e0d0c0b0a', 'other', 'mac')")
        run(f"INSERT INTO agent_nodes (agent_id, node) VALUES ('prj_00000000000a', '{NODE}')")
        refused(psycopg.errors.CheckViolation, "INSERT INTO agent_nodes (agent_id, node) "
                "VALUES ('prj_00000000000a', '0f0e0d0c0b0a')")
        refused(psycopg.errors.CheckViolation,
                "UPDATE agents SET kind = 'agent' WHERE id = 'prj_00000000000a'")
        # agent_nodes_node_fields, nodes_to_links
        assert _rows(conn, f"SELECT kind, address FROM agent_nodes WHERE agent_id = '{AGENT}'"
                     ) == [("server", "box.example.test")]
        run(f"UPDATE nodes SET address = 'moved.example.test' WHERE id = '{NODE}'")
        assert _rows(conn, f"SELECT address FROM agent_nodes WHERE agent_id = '{AGENT}'") == [
            ("moved.example.test",)]
        # settings_guard
        refused(psycopg.errors.CheckViolation, "INSERT INTO settings (agent_id, capability, "
                f"path, value, updated_by) VALUES ('{AGENT}', 'demo', '{{a}}', '2', 'u@n')")
        refused(psycopg.errors.CheckViolation, "INSERT INTO settings (agent_id, capability, "
                f"path, value, updated_by) VALUES ('{AGENT}', 'demo', '{{c}}', "
                "'{\"k\": 1}', 'u@n')")
        # settings_changes_append_only
        refused(psycopg.errors.RestrictViolation, "UPDATE settings_changes SET changed_by = 'x'")
        refused(psycopg.errors.RestrictViolation, "TRUNCATE settings_changes")
        # reference_versions_guard
        refused(psycopg.errors.CheckViolation, "UPDATE reference_versions SET body = 'other'")
        refused(psycopg.errors.CheckViolation, "DELETE FROM reference_versions")
        run("UPDATE reference_versions SET active = false")
        # grants_owner, connections_owner, connections_label
        refused(psycopg.errors.CheckViolation, "INSERT INTO grants (agent_id, capability, "
                f"connection) VALUES ('{PEER}', 'demo', 'home')")
        run("INSERT INTO grants (agent_id, capability, connection) VALUES "
            f"('{AGENT}', 'demo', 'work'), ('{PEER}', 'demo', 'work')")
        refused(psycopg.errors.CheckViolation,
                f"UPDATE connections SET owner_agent_id = '{AGENT}' WHERE name = 'work'")
        refused(psycopg.errors.UniqueViolation,
                "UPDATE connections SET label = 'home' WHERE name = 'work'")
        refused(psycopg.errors.CheckViolation,
                "UPDATE connections SET name = 'other' WHERE name = 'work'")
        # policies_service_follows
        run("INSERT INTO policies (agent_id, capability, node, enabled) "
            f"VALUES ('{AGENT}', 'demo', '{NODE}', true)")
        assert _rows(conn, f"SELECT service FROM policies WHERE node = '{NODE}'") == [(True,)]
        # secrets_announce (both triggers) and agents_vault_public_key
        run("INSERT INTO secrets (agent_id, name, ciphertext, key_fingerprint) VALUES "
            f"('{AGENT}', 'OTHER_TOKEN', '\\x01', '{'b' * 64}')")
        run(f"UPDATE agents SET vault_key = '{'c' * 64}', vault_public_key = '{'A' * 43}' "
            f"WHERE id = '{AGENT}'")
        run(f"UPDATE agents SET vault_key = '{'d' * 64}' WHERE id = '{AGENT}'")
        assert _rows(conn, f"SELECT vault_public_key FROM agents WHERE id = '{AGENT}'") == [
            (None,)]
        assert _rows(conn, "SELECT version FROM schema_channel WHERE channel = "
                           "'capabilities_vault' AND scope = %s", (AGENT,)) == [(4,)]
        # node_updates_announce
        run(f"UPDATE node_updates SET state = 'running', started_at = now() WHERE node = '{NODE}'")
        assert _rows(conn, "SELECT version FROM schema_channel WHERE channel = "
                           "'capabilities_node_update' AND scope = %s", (NODE,)) == [(2,)]
