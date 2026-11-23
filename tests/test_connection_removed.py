"""A machine connection, once removed, stays removed.

On a machine whose store holds the global rows (`store_state.global_migrated_at`
set), the config home's `<name>/connections.json` answers only for a connection
the store holds no row of. `connection remove --machine` therefore names the
connection by its id or its label, and takes its row and that file's entry - kept
under either name - in one step, handing the capability's own
`_connection_removed(id, entry, scope)` hook what it keeps beside the record; and
nothing that writes a connection back (`_record_identity`, `_connection_rewrite`)
turns an entry only that file holds into a row of the store's.

Each test binds the tiers into a probe capability run outside any project,
against the throwaway store the `store` fixture names in the machine setting."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import NoReturn

import pytest
from _proxy import Proxy

from capabilities_contract.capability import bind
from capabilities_contract.capability import store as S
from capabilities_contract.db import connect, migrate

SPEC = {"base_url": "http://probe.invalid"}


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


def _machine(store, tmp_path, monkeypatch, files: dict, rows: tuple = (),
             in_force: bool = True, **extra) -> tuple[dict, list, dict]:
    """The probe outside any project, its config home's file declaring `files`
    and the store holding a shared row for each label in `rows`: (its
    namespace, what it emitted, each row's id by label)."""
    home = store.config_home
    (home / "probe").mkdir(parents=True, exist_ok=True)
    (home / "probe" / "connections.json").write_text(json.dumps({"connections": files}))
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
        if in_force:
            conn.execute("UPDATE store_state SET global_migrated_at = now()")
        for label in rows:
            conn.execute("INSERT INTO connections (capability, label, spec) "
                         "VALUES ('probe', %s, %s::jsonb)", (label, json.dumps(SPEC)))
        conn.commit()
    ids = dict(_sql("SELECT label, id FROM connections WHERE capability = 'probe'"))
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
    namespace.update(extra)
    bind(namespace, "core", "store", "connections")
    seen: list = []
    namespace["_emit"] = seen.append
    return namespace, seen, ids


def _filed(store) -> dict:
    return json.loads((store.config_home / "probe" / "connections.json").read_text())[
        "connections"]


def _labels() -> list:
    return [row[0] for row in _sql("SELECT label FROM connections "
                                   "WHERE capability = 'probe' ORDER BY label")]


def test_a_machine_connection_goes_by_its_id_or_its_label_with_its_config_home_entry(
        store, tmp_path, monkeypatch, excepthook):
    namespace, seen, ids = _machine(
        store, tmp_path, monkeypatch, {"one": SPEC, "two": SPEC, "three": SPEC},
        rows=("one", "two", "three"))
    # The config home may keep a connection under its id as well as its label.
    body = {"connections": {"one": SPEC, ids["two"]: SPEC, "three": SPEC}}
    (store.config_home / "probe" / "connections.json").write_text(json.dumps(body))
    namespace["_cmd_connection"](["remove", ids["one"], "--machine"])
    assert seen[-1]["connection"] == ids["one"] and seen[-1]["label"] == "one"
    namespace["_cmd_connection"](["remove", "two", "--machine"])
    assert seen[-1]["connection"] == ids["two"] and seen[-1]["scope"] == "global"
    namespace["_cmd_connection"](["remove", "three", "--global"])
    assert _labels() == []
    assert _filed(store) == {}
    assert "state_removed" not in seen[-1]
    # Nothing answers for them any more.
    namespace["_RECORDS"] = None
    assert namespace["_records"]().resolve_scope("probe", "connection", "global") == {}


def test_the_hook_takes_what_the_capability_keeps_of_a_removed_connection(
        store, tmp_path, monkeypatch, excepthook):
    called = []

    def removed(cid, entry, scope):
        called.append((cid, entry, scope))
        return [tmp_path / "state" / cid / "session.session"]

    namespace, seen, ids = _machine(store, tmp_path, monkeypatch, {"one": SPEC},
                                    rows=("one",), _connection_removed=removed)
    namespace["_cmd_connection"](["remove", "one", "--machine"])
    assert called == [(ids["one"], {**SPEC, "id": ids["one"], "label": "one"}, "global")]
    assert seen[-1]["state_removed"] == [str(tmp_path / "state" / ids["one"]
                                             / "session.session")]


def test_a_write_back_never_adds_an_entry_only_the_config_home_holds(
        store, tmp_path, monkeypatch, excepthook):
    namespace, _seen, ids = _machine(store, tmp_path, monkeypatch,
                                     {"gone": SPEC, "kept": SPEC}, rows=("kept",))
    assert namespace["_record_identity"]("gone", "42", "Gone") is False
    assert namespace["_connection_rewrite"]("gone", {"base_url": "http://x.invalid"}) is False
    assert _labels() == ["kept"]
    assert _filed(store)["gone"] == SPEC
    # A connection the store holds still records who it is, under its id or its label.
    assert namespace["_record_identity"]("kept", "7", "Kept") is True
    [(spec,)] = _sql("SELECT spec FROM connections WHERE id = %s", (ids["kept"],))
    assert spec["identity"] == {"id": "7", "display_name": "Kept"}
    assert _labels() == ["kept"]


def test_a_write_back_lands_in_the_config_home_where_the_store_holds_no_global_rows(
        store, tmp_path, monkeypatch, excepthook):
    namespace, _seen, _ids = _machine(store, tmp_path, monkeypatch, {"filed": SPEC},
                                      in_force=False)
    assert namespace["_record_identity"]("filed", "42") is True
    assert _filed(store)["filed"]["identity"] == {"id": "42", "display_name": None}
    assert _labels() == []


def test_a_store_that_does_not_answer_refuses_a_machine_remove_rather_than_reading_files(
        store, server, tmp_path, monkeypatch, excepthook, capsys):
    namespace, _seen, ids = _machine(store, tmp_path, monkeypatch, {"one": SPEC},
                                     rows=("one",))
    proxy = Proxy(server.host, server.port)
    try:
        proxy.stalled.set()
        store.write(host="127.0.0.1", port=proxy.port)
        with pytest.raises(SystemExit) as stop:
            namespace["_cmd_connection"](["remove", ids["one"], "--machine"])
        assert stop.value.code == 5
        assert json.loads(capsys.readouterr().err.strip().splitlines()[-1])[
            "error"]["code"] == "store_unreachable"
    finally:
        proxy.close()
        store.write()
    assert _labels() == ["one"] and _filed(store) == {"one": SPEC}
