"""Opening a project's records reads the store's major, whether the record tables
need anything from `migrate`, and the agent's registry row and nodes in one round
trip, and answers as reading them one after another answered; `applied` answers
what `status` answers as `applied`, in one round trip."""

from __future__ import annotations

import os
import re

import psycopg

from capabilities_contract.capability import store as store_tier
from capabilities_contract.db import applied, connect, disconnect, migrate, status

AGENT = "prj_000000000001"
NODE = "6e6f64652d31"
STEPS = [("0001", "CREATE TABLE demo_rows (id int)"),
         ("0002", "CREATE TABLE demo_more (id int)")]
IDLE = psycopg.pq.TransactionStatus.IDLE


class _Trace:
    """The round trips libpq makes on `conn` while the block runs: one per Query
    and one per Sync it sends."""

    def __init__(self, conn, path):
        self.conn, self.path = conn, path

    def __enter__(self):
        self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        self.conn.pgconn.trace(self.fd)
        return self

    def __exit__(self, *exc):
        self.conn.pgconn.untrace()
        os.close(self.fd)
        lines = [line.split("\t") for line in self.path.read_text().splitlines()
                 if re.match(r"\d{4}-", line)]
        sent = [line[3] for line in lines if line[1] == "F"]
        self.round_trips = sum(1 for message in sent if message in ("Query", "Sync"))


def _sql(query, params=()):
    with connect(application_name="test", transaction=True) as conn, conn.transaction():
        cur = conn.execute(query, params)
        return cur.fetchall() if cur.description else None


def test_applied_answers_what_status_answers_in_one_round_trip(store, tmp_path):
    with connect(application_name="test", transaction=True) as conn:
        assert applied(conn, "demo", STEPS) == []
        migrate(conn, "demo", STEPS[:1], major=1, minor=0)
        with _Trace(conn, tmp_path / "trace") as trace:
            found = applied(conn, "demo", STEPS)
        assert trace.round_trips == 1
        assert conn.info.transaction_status == IDLE
        assert found == ["0001"] == status(conn, "demo", STEPS, major=1, minor=0).applied
        changed = [("0001", "CREATE TABLE other_rows (id int)"), STEPS[1]]
        report = status(conn, "demo", changed, major=1, minor=0)
        assert applied(conn, "demo", changed) == report.applied == []
        assert report.changed == ["0001"]


def _seed():
    with connect(application_name="setup", transaction=True) as conn:
        migrate(conn, store_tier.STORE_OWNER, store_tier.record_table_steps(),
                major=store_tier.STORE_TABLES_VERSION[0],
                minor=store_tier.STORE_TABLES_VERSION[1])
        conn.commit()
    disconnect()
    _sql("INSERT INTO nodes (id, label, kind) VALUES (%s, 'here', 'mac')", (NODE,))
    _sql("INSERT INTO agents (id, migrated_at) VALUES (%s, now())", (AGENT,))
    _sql("INSERT INTO agent_nodes (agent_id, node, is_master) VALUES (%s, %s, true)",
         (AGENT, NODE))


def _open(tmp_path):
    root = tmp_path / "project"
    (root / "capabilities").mkdir(parents=True, exist_ok=True)
    return store_tier.open_records(root / "capabilities", tmp_path / "global",
                                   project_root=root, project_id=AGENT)


def test_opening_an_agents_records_is_one_round_trip_and_answers_as_before(
        store, tmp_path, monkeypatch):
    monkeypatch.setenv(store_tier.NODE_ID_ENV, NODE)
    monkeypatch.setattr(store_tier, "_STORE_MAJOR_SEEN", {})
    _seed()

    reads = store_tier._opening_reads
    monkeypatch.setattr(store_tier, "_opening_reads", lambda *args: None)
    one_by_one = _open(tmp_path)
    one_by_one.close()
    assert isinstance(one_by_one, store_tier.AgentRecords)
    assert one_by_one._ledger_current is False

    monkeypatch.setattr(store_tier, "_opening_reads", reads)
    store_tier._STORE_MAJOR_SEEN.clear()
    disconnect()
    # The working connection open_records borrows, traced while it is idle.
    conn = connect(application_name=store_tier.STORE_APPLICATION, transaction=True)
    conn.close()
    with _Trace(conn, tmp_path / "trace") as trace:
        together = _open(tmp_path)
    together.close()
    assert trace.round_trips == 1
    assert isinstance(together, store_tier.AgentRecords)
    assert together.agent == one_by_one.agent
    assert together.agent["migrated_at"] and together.agent["master"] == NODE
    # Its tables were read as settled with the agent's state: no migrate read waits.
    assert together._ledger_current is True


def test_a_store_without_the_tables_is_read_one_by_one(store, tmp_path, monkeypatch):
    monkeypatch.setattr(store_tier, "_STORE_MAJOR_SEEN", {})
    conn, setting = store_tier._store_open(tmp_path, "test")
    try:
        assert store_tier._opening_reads(conn, setting, AGENT) is None
        assert conn.info.transaction_status == IDLE
    finally:
        conn.close()
    records = _open(tmp_path)
    records.close()
    assert not isinstance(records, store_tier.AgentRecords)
