"""`load_identifiers`: the identifiers of many capabilities read in one round
trip, held where each capability's own identifier read holds them, so what
`resolve(name, "identifier")` answers is what it answered before."""

from __future__ import annotations

from capabilities_contract.capability import store as store_tier
from capabilities_contract.db import connect, disconnect, migrate

AGENT = "prj_000000000001"
OTHER = "prj_000000000002"
NODE = "n1"
CAPABILITIES = ["clickup", "slacker", "nothing"]


def _sql(query, params=()):
    with connect(application_name="test", transaction=True) as conn, conn.transaction():
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def _seed():
    with connect(application_name="setup", transaction=True) as conn:
        migrate(conn, store_tier.STORE_OWNER, store_tier.record_table_steps(),
                major=store_tier.STORE_TABLES_VERSION[0],
                minor=store_tier.STORE_TABLES_VERSION[1])
        conn.commit()
    disconnect()
    for agent in (AGENT, OTHER):
        _sql("INSERT INTO agents (id) VALUES (%s)", (agent,))
    for node in (NODE, "n2"):
        _sql("INSERT INTO nodes (id, label, kind) VALUES (%s, %s, 'mac')", (node, node))
    for agent, capability, node, label, value in (
            (AGENT, "clickup", None, "space", "s1"),
            (AGENT, "clickup", None, "list", "l1"),
            (None, "clickup", None, "space", "global-space"),
            (None, "clickup", None, "team", "t1"),
            (AGENT, "clickup", NODE, "list", "l1-here"),
            (AGENT, "clickup", "n2", "list", "l1-there"),
            (None, "slacker", NODE, "channel", "c-here"),
            (None, "slacker", None, "channel", "c-all"),
            (OTHER, "slacker", None, "channel", "not-mine")):
        _sql("INSERT INTO identifiers (agent_id, capability, node, label, value, note) "
             "VALUES (%s, %s, %s, %s, to_jsonb(%s::text), %s)",
             (agent, capability, node, label, value, f"note {label}"))


def _counting(records):
    calls = []
    read = records._read

    def counted(query, params):
        calls.append(query)
        return read(query, params)

    records._read = counted
    return calls


def _store(tmp_path):
    root = tmp_path / "project"
    (root / "capabilities").mkdir(parents=True, exist_ok=True)
    return store_tier.StoreRecords(root / "capabilities", tmp_path / "global",
                                   project_id=AGENT, project_root=root)


def _agent(tmp_path):
    root = tmp_path / "project"
    (root / "capabilities").mkdir(parents=True, exist_ok=True)
    return store_tier.AgentRecords(root / "capabilities", tmp_path / "global", AGENT, None,
                                   agent={"id": AGENT}, node=NODE, project_root=root)


def _resolved(records):
    return {name: records.resolve(name, "identifier") for name in CAPABILITIES}


def _check(make):
    one_by_one = make()
    expected = _resolved(one_by_one)
    one_by_one.close()
    assert expected["clickup"] and expected["slacker"] and expected["nothing"] == {}

    together = make()
    calls = _counting(together)
    together.load_identifiers([*CAPABILITIES, "clickup"])
    assert len(calls) == 1
    assert _resolved(together) == expected
    for name in CAPABILITIES:
        assert list(together.resolve(name, "identifier")) == list(expected[name])
    together.load_identifiers(CAPABILITIES)
    assert len(calls) == 1
    together.close()
    return expected


def test_store_records_read_every_capability_once_and_resolve_as_before(store, tmp_path):
    _seed()
    expected = _check(lambda: _store(tmp_path))
    # The rows for one node are an agent's whose records moved; this one reads
    # the rows for every node, its own over the global ones.
    assert {k: v["value"] for k, v in expected["clickup"].items()} == {
        "list": "l1", "space": "s1", "team": "t1"}
    assert {k: v["value"] for k, v in expected["slacker"].items()} == {"channel": "c-all"}


def test_agent_records_read_every_capability_once_and_resolve_as_before(store, tmp_path):
    _seed()
    expected = _check(lambda: _agent(tmp_path))
    assert {k: v["value"] for k, v in expected["clickup"].items()} == {
        "list": "l1-here", "space": "s1", "team": "t1"}
    assert {k: v["value"] for k, v in expected["slacker"].items()} == {"channel": "c-here"}


def test_load_identifiers_reads_nothing_where_identifiers_are_files(tmp_path):
    records = store_tier.FileRecords(tmp_path / "project", tmp_path / "global")
    records.load_identifiers(CAPABILITIES)
    assert records.resolve("clickup", "identifier") == {}
