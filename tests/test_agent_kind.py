"""An agent's kind: ledger step 0037-agent-kind, which marks a system agent -
one an app keeps on one machine for itself - stays one, lives on one node, is
the only one on its node, and may share its slug with system agents elsewhere
but never with an ordinary agent."""

from __future__ import annotations

import pytest

from capabilities_contract.capability import store as store_tier
from capabilities_contract.db import connect, disconnect, migrate

AGENT = "000000000001"
KEEPER = "000000000002"
KEEPER_ELSEWHERE = "000000000003"


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


def _node(node):
    _sql("INSERT INTO capabilities_nodes (id, label, kind) VALUES (%s, %s, 'mac')",
         (node, node))


def _link(agent, node, master=True):
    _sql("INSERT INTO capabilities_agent_nodes (agent_id, node, is_master)"
         " VALUES (%s, %s, %s)", (agent, node, master))


def test_a_store_at_the_connection_label_step_takes_only_the_kind_step_and_keeps_every_agent(store):
    steps = store_tier.record_table_steps()
    assert steps[-1][0] == "0037-agent-kind"
    assert store_tier.STORE_TABLES_VERSION == (1, 22)
    _migrate(steps[:-1], 1, 21)
    _sql("INSERT INTO capabilities_agents (id, slug) VALUES (%s, 'work')", (AGENT,))
    result = _migrate(steps, *store_tier.STORE_TABLES_VERSION)
    assert result.applied == ["0037-agent-kind"]
    assert _sql("SELECT id, slug, kind FROM capabilities_agents") == [(AGENT, "work", "agent")]
    with _conn() as conn:
        assert store_tier.agent_kind(conn, AGENT) == "agent"
        assert store_tier.agent_kind(conn, KEEPER) is None
    [(comment,)] = _sql(
        "SELECT col_description(to_regclass('capabilities_agents'), a.attnum)"
        " FROM pg_attribute a WHERE a.attrelid = to_regclass('capabilities_agents')"
        " AND a.attname = 'kind'")
    assert comment


def test_a_system_agent_stays_one_on_its_one_node_and_shares_its_slug_only_with_system_agents(store):
    import psycopg
    _migrate(store_tier.record_table_steps(), *store_tier.STORE_TABLES_VERSION)
    _node("mac-a")
    _node("mac-b")
    _sql("INSERT INTO capabilities_agents (id, slug) VALUES (%s, 'work')", (AGENT,))
    _sql("INSERT INTO capabilities_agents (id, slug, kind) VALUES (%s, 'keeper', 'system')",
         (KEEPER,))
    _link(KEEPER, "mac-a")
    _link(AGENT, "mac-a")
    with _conn() as conn:
        assert store_tier.agent_kind(conn, KEEPER) == "system"
    # A system agent on another Mac may carry the same slug; an ordinary one may not.
    _sql("INSERT INTO capabilities_agents (id, slug) VALUES (%s, NULL)", (KEEPER_ELSEWHERE,))
    _link(KEEPER_ELSEWHERE, "mac-b")
    _sql("UPDATE capabilities_agents SET kind = 'system', slug = 'keeper' WHERE id = %s",
         (KEEPER_ELSEWHERE,))
    for query, params in (
            ("UPDATE capabilities_agents SET slug = 'keeper' WHERE id = %s", (AGENT,)),
            ("UPDATE capabilities_agents SET slug = 'work' WHERE id = %s", (KEEPER,)),
            ("INSERT INTO capabilities_agents (id, slug) VALUES ('000000000009', 'work')", ())):
        with pytest.raises(psycopg.errors.UniqueViolation):
            _sql(query, params)
    # It stays a system agent, on its one node, the only one there.
    with pytest.raises(psycopg.errors.CheckViolation):
        _sql("UPDATE capabilities_agents SET kind = 'agent' WHERE id = %s", (KEEPER,))
    with pytest.raises(psycopg.errors.CheckViolation):
        _link(KEEPER, "mac-b", master=False)
    with pytest.raises(psycopg.errors.UniqueViolation):
        _sql("UPDATE capabilities_agent_nodes SET node = 'mac-a' WHERE agent_id = %s",
             (KEEPER_ELSEWHERE,))
    _sql("DELETE FROM capabilities_agent_nodes WHERE agent_id = %s", (KEEPER_ELSEWHERE,))
    _link(AGENT, "mac-b", master=False)
    # An agent on two nodes, or on a node that already holds one, is not made one.
    with pytest.raises(psycopg.errors.CheckViolation):
        _sql("UPDATE capabilities_agents SET kind = 'system' WHERE id = %s", (AGENT,))
    _sql("DELETE FROM capabilities_agent_nodes WHERE agent_id = %s AND node = 'mac-b'",
         (AGENT,))
    with pytest.raises(psycopg.errors.UniqueViolation):
        _sql("UPDATE capabilities_agents SET kind = 'system', slug = NULL WHERE id = %s",
             (AGENT,))
    assert _sql("SELECT id, kind FROM capabilities_agents ORDER BY id") == [
        (AGENT, "agent"), (KEEPER, "system"), (KEEPER_ELSEWHERE, "system")]
