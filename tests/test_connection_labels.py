"""A connection's label beside its id: ledger step 0036-connection-label and
the store tier's rename, which changes what a connection is called and leaves
its id, and so every row naming it, as it was."""

from __future__ import annotations

import pytest

from capabilities_contract.capability import store as store_tier
from capabilities_contract.db import connect, disconnect, migrate

AGENT = "prj_000000000001"
PEER = "prj_000000000002"


def _migrate(steps, major, minor):
    with connect(application_name="setup", transaction=True) as conn:
        result = migrate(conn, store_tier.STORE_OWNER, steps, major=major, minor=minor)
        conn.commit()
    disconnect()
    return result


def _conn():
    return connect(application_name="test", transaction=True)


def _sql(query, params=()):
    with _conn() as conn, conn.transaction():
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _seed():
    _sql("INSERT INTO capabilities_agents (id) VALUES (%s), (%s)", (AGENT, PEER))
    for name in ("work", "home"):
        _sql("INSERT INTO capabilities_connections (capability, name, spec)"
             " VALUES ('clickup', %s, '{}')", (name,))
    _sql("INSERT INTO capabilities_connection_grants"
         " (agent_id, capability, connection, enabled, is_default)"
         " VALUES (%s, 'clickup', 'work', true, true), (%s, 'clickup', 'work', true, false)",
         (AGENT, PEER))


def test_a_store_at_the_node_disabled_step_takes_only_the_label_step_and_keeps_every_grant(store):
    steps = store_tier.record_table_steps()
    at = [step[0] for step in steps].index("0036-connection-label")
    _migrate(steps[:at], 1, 20)
    _seed()
    before = _sql("SELECT agent_id, capability, connection, enabled, is_default"
                  " FROM capabilities_connection_grants ORDER BY agent_id")
    result = _migrate(steps[:at + 1], 1, 21)
    assert result.applied == ["0036-connection-label"]
    assert _sql("SELECT agent_id, capability, connection, enabled, is_default"
                " FROM capabilities_connection_grants ORDER BY agent_id") == before
    assert _sql("SELECT name, label FROM capabilities_connections ORDER BY name") == \
        [("home", None), ("work", None)]
    [(comment,)] = _sql(
        "SELECT col_description(to_regclass('capabilities_connections'), a.attnum)"
        " FROM pg_attribute a WHERE a.attrelid = to_regclass('capabilities_connections')"
        " AND a.attname = 'label'")
    assert comment


def test_a_label_names_one_connection_and_the_id_never_changes(store):
    import psycopg
    _migrate(store_tier.record_table_steps(), *store_tier.STORE_TABLES_VERSION)
    _seed()
    _sql("UPDATE capabilities_connections SET label = 'office' WHERE name = 'work'")
    for query in ("UPDATE capabilities_connections SET label = 'work' WHERE name = 'home'",
                  "UPDATE capabilities_connections SET label = 'office' WHERE name = 'home'",
                  "INSERT INTO capabilities_connections (capability, name, spec)"
                  " VALUES ('clickup', 'office', '{}')"):
        with pytest.raises(psycopg.errors.UniqueViolation):
            _sql(query)
    with pytest.raises(psycopg.errors.CheckViolation):
        _sql("UPDATE capabilities_connections SET name = 'office2' WHERE name = 'work'")
    with pytest.raises(psycopg.errors.CheckViolation):
        _sql("UPDATE capabilities_connections SET label = 'home' WHERE name = 'home'")
    # Another capability's ids and labels are its own.
    _sql("INSERT INTO capabilities_connections (capability, name, spec, label)"
         " VALUES ('slack', 'office', '{}', 'work')")


def test_rename_changes_the_label_alone_and_refuses_what_is_not_the_writers(store, tmp_path):
    _migrate(store_tier.record_table_steps(), *store_tier.STORE_TABLES_VERSION)
    _seed()
    _sql("UPDATE capabilities_connections SET owner = %s WHERE name = 'home'", (PEER,))
    records = store_tier.GlobalRows(tmp_path / "global", None)
    records.rename_connection("clickup", "work", "office")
    assert records.connection_labels("clickup") == {"work": "office"}
    assert _sql("SELECT agent_id, connection, is_default FROM capabilities_connection_grants"
                " ORDER BY agent_id") == [(AGENT, "work", True), (PEER, "work", False)]
    records.rename_connection("clickup", "work", "work")
    assert records.connection_labels("clickup") == {}
    for cid, label, slug in (("work", "home", "connection_exists"),
                             ("home", "mine", "connection_owned"),
                             ("gone", "x", "unknown_connection")):
        with pytest.raises(store_tier.StoreError) as raised:
            records.rename_connection("clickup", cid, label)
        assert raised.value.slug == slug
    records.close()
