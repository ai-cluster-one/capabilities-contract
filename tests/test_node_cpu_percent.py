"""The core's step 0044-node-cpu-percent: a node's state row carries the share
of its whole allotted CPU in use, 0 to 100; a minor step, applied outside the
store upgrade, that a reader of core 4.2 still reads, and that the store tier
reads as null on a store still at core 4.2."""

from __future__ import annotations

import psycopg
import pytest

from capabilities_contract.capability import store as store_tier
from capabilities_contract.db import _migrate, connect, disconnect, migrate

CORE_4_2 = _migrate.CORE_STEPS[:5]
NODE = "0a0b0c0d0e0f"


def _core(major=4, minor=3, steps=None):
    with connect(application_name="setup", transaction=True) as conn:
        result = migrate(conn, "core", steps or _migrate.CORE_STEPS, major=major, minor=minor)
        conn.commit()
    disconnect()
    return result


def _conn():
    return connect(application_name="test", transaction=True)


def _at_core_4_2(monkeypatch):
    with monkeypatch.context() as patched:
        patched.setattr(_migrate, "CORE_STEPS", CORE_4_2)
        patched.setattr(_migrate, "CORE_VERSION", (4, 2))
        return _core(4, 2, CORE_4_2)


def _node():
    with _conn() as conn, conn.transaction():
        conn.execute("INSERT INTO nodes (id, label, kind) VALUES (%s, %s, 'server')",
                     (NODE, NODE))


def test_a_store_at_core_4_2_takes_the_step_without_the_upgrade_and_old_rows_stay_null(
        store, monkeypatch):
    _at_core_4_2(monkeypatch)
    _node()
    with _conn() as conn, conn.transaction():
        conn.execute("INSERT INTO node_states (node, cpu_count, fresh_until)"
                     " VALUES (%s, 2, now() + interval '1 minute')", (NODE,))
        # A reader on this release answers a store still at 4.2, the share null.
        [row] = store_tier.node_states(conn, [NODE])
    assert (row["cpu_count"], row["cpu_percent"]) == (2, None)
    monkeypatch.delenv(_migrate.UPGRADE_ENV, raising=False)
    result = _core()
    assert result.applied == ["0044-node-cpu-percent"]
    assert (result.major, result.minor) == (4, 3) == _migrate.CORE_VERSION
    with _conn() as conn, conn.transaction():
        [row] = store_tier.node_states(conn, [NODE])
        comment = conn.execute(
            "SELECT col_description('node_states'::regclass, a.attnum) FROM pg_attribute a"
            " WHERE a.attrelid = 'node_states'::regclass AND a.attname = 'cpu_percent'"
        ).fetchone()[0]
    assert row["cpu_percent"] is None and comment
    # A reader that knows core 4.2 settles on the store at 4.3, with a warning.
    with monkeypatch.context() as patched:
        patched.setattr(_migrate, "CORE_STEPS", CORE_4_2)
        patched.setattr(_migrate, "CORE_VERSION", (4, 2))
        older = _core(4, 2, CORE_4_2)
    assert older.applied == [] and (older.major, older.minor) == (4, 3)
    assert any("newer minor" in warning for warning in older.warnings)


def test_a_node_writes_its_cpu_share_and_each_write_replaces_it(store):
    _core()
    _node()
    with _conn() as conn:
        with conn.transaction():
            store_tier.node_state_put(conn, NODE, cpu_count=4, cpu_percent=37.5)
        [row] = store_tier.node_states(conn, [NODE])
        assert row["cpu_percent"] == 37.5
        with conn.transaction():
            store_tier.node_state_put(conn, NODE, cpu_count=4)
        [row] = store_tier.node_states(conn, [NODE])
        assert row["cpu_percent"] is None
        with conn.transaction():
            count = conn.execute("SELECT count(*) FROM node_states").fetchone()[0]
    assert count == 1


@pytest.mark.parametrize("share", [-0.5, 100.5])
def test_a_share_outside_0_to_100_is_refused_by_the_tier_and_by_the_store(store, share):
    _core()
    _node()
    with _conn() as conn:
        with pytest.raises(store_tier.StoreError) as refused:
            store_tier.node_state_put(conn, NODE, cpu_percent=share)
        assert refused.value.slug == "bad_state"
        with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
            conn.execute("INSERT INTO node_states (node, cpu_percent, fresh_until)"
                         " VALUES (%s, %s, now() + interval '1 minute')", (NODE, share))
