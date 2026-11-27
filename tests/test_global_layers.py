"""`GlobalRows.load_layers` and `FileRecords.load_global`: the global layer of
many capabilities read in one round trip, held where `_layer` holds one, so
what each capability's global reads answer is what they answered before."""

from __future__ import annotations

from capabilities_contract.capability import store as store_tier
from capabilities_contract.db import connect, disconnect, migrate

AGENT = "prj_000000000001"
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
    _sql("INSERT INTO agents (id) VALUES (%s)", (AGENT,))
    for capability, label in (("clickup", "work"), ("clickup", "home"),
                              ("slacker", "team")):
        _sql("INSERT INTO connections (capability, label, spec) VALUES (%s, %s, %s)",
             (capability, label, f'{{"workspace": "{label}"}}'))
    _sql("INSERT INTO connections (capability, label, spec, owner_agent_id)"
         " VALUES ('clickup', 'mine', '{}', %s)", (AGENT,))
    _sql("INSERT INTO grants (capability, connection_id, enabled, allow_write, is_default)"
         " SELECT 'clickup', id, label = 'work', label = 'home', label = 'work'"
         " FROM connections WHERE capability = 'clickup' AND owner_agent_id IS NULL")


def _counting(records):
    calls = []
    read_many = records._read_many

    def counted(statements):
        calls.append(len(statements))
        return read_many(statements)

    records._read_many = counted
    return calls


def test_load_layers_reads_every_capability_once_and_each_layer_is_unchanged(store, tmp_path):
    _seed()
    one_by_one = store_tier.GlobalRows(tmp_path / "global", None)
    expected = {name: one_by_one._layer(name) for name in CAPABILITIES}
    one_by_one.close()
    assert set(expected["clickup"]["labels"].values()) == {"work", "home"}
    assert expected["nothing"] == {"connections": {}, "labels": {}, "grants": {},
                                   "default": None}

    together = store_tier.GlobalRows(tmp_path / "global", None)
    calls = _counting(together)
    together.load_layers([*CAPABILITIES, "clickup"])
    assert calls == [2]
    for name in CAPABILITIES:
        assert together._layer(name) == expected[name]
        assert list(together._layer(name)["labels"]) == list(expected[name]["labels"])
    together.load_layers(CAPABILITIES)
    assert calls == [2]
    together.close()


def test_load_global_answers_resolve_scope_as_before(store, tmp_path):
    _seed()
    _sql("UPDATE store_state SET global_migrated_at = now()")

    def resolved(records):
        return {name: (records.resolve_scope(name, "connection", "global"),
                       records.resolve_scope(name, "grant", "global"))
                for name in CAPABILITIES}

    before = resolved(store_tier.global_records(tmp_path / "global", None))
    records = store_tier.global_records(tmp_path / "global", None)
    records.load_global(CAPABILITIES)
    calls = _counting(records._global_rows())
    assert resolved(records) == before
    assert calls == []


def test_load_global_reads_nothing_where_the_global_layer_is_files(tmp_path):
    records = store_tier.FileRecords(tmp_path / "project", tmp_path / "global")
    records.load_global(CAPABILITIES)
    assert records.resolve_scope("clickup", "connection", "global") == {}
