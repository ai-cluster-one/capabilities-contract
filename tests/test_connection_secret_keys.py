"""The core's step 0046-connection-secret-keys and the store tier that fills it.

Every connection records the names of the secrets it resolves, as its
capability's own `connections` report names them. The capability writes them
after each write of the row; the store clears them when an update changes the
row without setting them; and `connections` records them for every row of the
capability that holds none.

The tier tests bind the tiers into a probe capability outside any project,
against the throwaway store the `store` fixture names in the machine setting.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import NoReturn

import psycopg
import pytest

from capabilities_contract.capability import bind
from capabilities_contract.capability import store as S
from capabilities_contract.db import _migrate, connect, disconnect, migrate

CORE_4_4 = _migrate.CORE_STEPS[:7]
CORE_4_5 = _migrate.CORE_STEPS[:8]


@pytest.fixture
def excepthook():
    saved = sys.excepthook
    yield
    sys.excepthook = saved


def _sql(query: str, params: tuple = ()):
    with connect(application_name="capabilities-contract-tests") as conn:
        cursor = conn.execute(query, params)
        rows = cursor.fetchall() if cursor.description else None
        conn.commit()
        return rows


def _keys(label: str):
    return _sql("SELECT secret_keys FROM connections WHERE label = %s", (label,))[0][0]


def test_a_store_at_core_4_4_takes_the_step_without_the_upgrade_and_old_rows_stay_null(
        store, monkeypatch):
    with connect(application_name="setup", transaction=True) as conn:
        migrate(conn, "core", CORE_4_4, major=4, minor=4)
        conn.execute("INSERT INTO connections (capability, label, spec) "
                     "VALUES ('demo', 'old', '{}')")
        conn.commit()
    disconnect()
    monkeypatch.delenv(_migrate.UPGRADE_ENV, raising=False)
    with connect(application_name="setup", transaction=True) as conn:
        result = migrate(conn, "core", CORE_4_5, major=4, minor=5)
        conn.commit()
    disconnect()
    assert result.applied == ["0046-connection-secret-keys"]
    assert (result.major, result.minor) == (4, 5)
    assert _keys("old") is None
    [(comment,)] = _sql("SELECT col_description('connections'::regclass, attnum) "
                        "FROM pg_attribute WHERE attrelid = 'connections'::regclass "
                        "AND attname = 'secret_keys'")
    assert "connections report" in comment and "Null" in comment
    # A reader that knows core 4.4 settles on the store at 4.5, with a warning.
    with monkeypatch.context() as patched:
        patched.setattr(_migrate, "CORE_STEPS", CORE_4_4)
        patched.setattr(_migrate, "CORE_VERSION", (4, 4))
        with connect(application_name="setup", transaction=True) as conn:
            older = migrate(conn, "core", CORE_4_4, major=4, minor=4)
            conn.commit()
        disconnect()
    assert older.applied == [] and (older.major, older.minor) == (4, 5)
    assert any("newer minor" in warning for warning in older.warnings)


def test_an_update_that_changes_the_row_without_the_names_clears_them(store):
    with connect(application_name="setup", transaction=True) as conn:
        migrate(conn, "core", CORE_4_5, major=4, minor=5)
        conn.commit()
    disconnect()
    _sql("INSERT INTO connections (capability, label, spec, secret_keys) "
         "VALUES ('demo', 'a', '{\"x\": 1}', ARRAY['A_TOKEN'])")
    assert _keys("a") == ["A_TOKEN"]
    # Writing the names alone, or the same row again, keeps them.
    _sql("UPDATE connections SET secret_keys = ARRAY['A_TOKEN', 'A_COOKIE'] "
         "WHERE label = 'a'")
    _sql("UPDATE connections SET spec = spec WHERE label = 'a'")
    assert _keys("a") == ["A_TOKEN", "A_COOKIE"]
    # A spec or a label changed without them clears them; one changed with
    # other names keeps those.
    _sql("UPDATE connections SET spec = '{\"x\": 2}' WHERE label = 'a'")
    assert _keys("a") is None
    _sql("UPDATE connections SET secret_keys = '{}' WHERE label = 'a'")
    assert _keys("a") == []
    _sql("UPDATE connections SET label = 'b' WHERE label = 'a'")
    assert _keys("b") is None
    _sql("UPDATE connections SET spec = '{\"x\": 3}', secret_keys = ARRAY['B'] "
         "WHERE label = 'b'")
    assert _keys("b") == ["B"]
    for bad in ("ARRAY['']", "ARRAY[NULL]::text[]"):
        with pytest.raises(psycopg.errors.CheckViolation):
            _sql(f"UPDATE connections SET secret_keys = {bad} WHERE label = 'b'")


def _report(registry):
    """The probe's own report: the secret named by `token_env`, a fixed one
    every connection resolves, and a value that is not a secret."""
    reg, _ = registry()
    out = {"default": reg.get("default"), "connections": {}}
    for cid, entry in reg["connections"].items():
        keys = [{"key": "base_url", "secret": False}]
        if entry.get("token_env"):
            keys.append({"key": entry["token_env"], "secret": True})
        keys.append({"key": "PROBE_SHARED_KEY", "secret": True})
        keys.append({"key": entry.get("token_env") or "PROBE_SHARED_KEY", "secret": True})
        out["connections"][cid] = {"keys": keys}
    return out


def _probe(store, tmp_path, monkeypatch, rows: dict):
    """The probe outside any project, the store holding a shared row for each
    label of `rows` with its spec: (its namespace, what it emitted)."""
    home = store.config_home
    (home / "probe").mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.chdir(outside)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(outside))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    for key in [k for k in os.environ if k.startswith("CAPABILITIES_")]:
        monkeypatch.delenv(key)
    with connect(application_name="capabilities-contract-tests") as conn:
        migrate(conn, S.STORE_OWNER, S.record_table_steps(),
                major=S.STORE_TABLES_VERSION[0], minor=S.STORE_TABLES_VERSION[1])
        conn.execute("UPDATE store_state SET global_migrated_at = now()")
        for label, spec in rows.items():
            conn.execute("INSERT INTO connections (capability, label, spec) "
                         "VALUES ('probe', %s, %s::jsonb)", (label, json.dumps(spec)))
        conn.commit()
    namespace = {
        "__name__": "probe", "os": os, "sys": sys, "json": json, "Path": Path,
        "NoReturn": NoReturn, "NAME": "probe", "SUMMARY": "a probe", "SCOPE": "user",
        "DOCS_BASE": "", "STATE": False, "INVENTORY": None, "POST_INSTALL": [],
        "_CONFIG_HOME": home, "_STATE_HOME": tmp_path / "state",
        "CREDENTIALS_ENV": home / "probe" / "credentials.env", "CRED_KEYS": [],
        "WRITE_VERBS": set(), "WRITE_DEFAULT": False,
        "CONN_FIELDS": [{"key": "base_url", "help": "where it answers"}],
        "__file__": str(tmp_path / "probe"),
    }
    bind(namespace, "core", "store", "connections")
    # The report reads the store itself, as a capability's may (its labels,
    # its former names): the names are computed on no open transaction.
    namespace["_connections_report"] = lambda: (
        namespace["_records"]().connection_former_name("probe", "none"),
        _report(namespace["_connections_registry"]))[1]
    seen: list = []
    namespace["_emit"] = seen.append
    return namespace, seen


def test_the_capability_records_its_own_report_on_every_write_and_fills_what_is_null(
        store, tmp_path, monkeypatch, excepthook):
    namespace, seen = _probe(store, tmp_path, monkeypatch,
                             {"old": {"base_url": "http://old.invalid",
                                      "token_env": "PROBE_OLD_TOKEN"},
                              "other": {}})
    _sql("INSERT INTO connections (capability, label, spec) "
         "VALUES ('elsewhere', 'theirs', '{}')")
    assert _keys("old") is None
    # `connections` records every row of its own capability that holds none,
    # and leaves another capability's rows alone.
    namespace["_cmd_connections"] = lambda: print(json.dumps({"connections": {}}))
    namespace["_cmd_connections_reported"]()
    assert "policy" in seen[-1]
    assert _keys("old") == ["PROBE_OLD_TOKEN", "PROBE_SHARED_KEY"]
    assert _keys("other") == ["PROBE_SHARED_KEY"]
    assert _keys("theirs") is None
    records = namespace["_records"]()
    # An add, an edit and a rename each record the names of the row as it is.
    records.set("probe", "connection", "new",
                {"base_url": "http://new.invalid", "token_env": "PROBE_NEW_TOKEN"},
                scope="global")
    assert _keys("new") == ["PROBE_NEW_TOKEN", "PROBE_SHARED_KEY"]
    records.set("probe", "connection", "new",
                {"base_url": "http://new.invalid", "token_env": "PROBE_NEWER_TOKEN"},
                scope="global")
    assert _keys("new") == ["PROBE_NEWER_TOKEN", "PROBE_SHARED_KEY"]
    [(cid,)] = _sql("SELECT id FROM connections WHERE label = 'new'")
    records._global_rows().rename_connection("probe", cid, "renamed")
    assert _keys("renamed") == ["PROBE_NEWER_TOKEN", "PROBE_SHARED_KEY"]
    # A writer that does not know them leaves them null, never stale, until
    # the capability records them again.
    _sql("UPDATE connections SET spec = '{\"token_env\": \"PROBE_X\"}' "
         "WHERE label = 'renamed'")
    assert _keys("renamed") is None
    assert records.fill_secret_keys("probe") == 1
    assert _keys("renamed") == ["PROBE_X", "PROBE_SHARED_KEY"]
    assert records.fill_secret_keys("probe") == 0
    # Another capability's rows are not this one's to record.
    assert records.fill_secret_keys("elsewhere") == 0
    # Under the read-only switch nothing is recorded.
    _sql("UPDATE connections SET secret_keys = NULL WHERE label = 'other'")
    monkeypatch.setenv(S.READ_ONLY_ENV, "1")
    assert records.fill_secret_keys("probe") == 0
    assert _keys("other") is None


def test_a_report_that_cannot_answer_records_nothing_and_fails_no_write(
        store, tmp_path, monkeypatch, excepthook):
    namespace, _seen = _probe(store, tmp_path, monkeypatch, {})

    def refuses():
        namespace["_die"](6, "probe_refuses", "the probe cannot report")
    namespace["_connections_report"] = refuses
    records = namespace["_records"]()
    records.set("probe", "connection", "kept", {"base_url": "http://kept.invalid"},
                scope="global")
    assert _sql("SELECT label, secret_keys FROM connections") == [("kept", None)]
    assert namespace["_connection_secret_keys"]("x", None, {}) is None
