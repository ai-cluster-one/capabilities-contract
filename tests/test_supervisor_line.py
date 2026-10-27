"""doctor raises one line for the supervisor, and only on a real conflict."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import NoReturn

import pytest

from capabilities_contract.capability import bind


@pytest.fixture
def probe(tmp_path, monkeypatch):
    """A connections-bound capability standing in a project, its vault a dict
    and its registry a folder of the test's own."""
    saved = sys.excepthook
    root = tmp_path / "project"
    (root / "capabilities").mkdir(parents=True)
    for key in ("CAPABILITIES_PROJECT_ID", "CAPABILITIES_PROJECT_ID_ROOT", "PROBE_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(root))
    monkeypatch.setenv("CAPABILITIES_PROJECT_ENVELOPE", str(root / "capabilities"))
    monkeypatch.setenv("CAPABILITIES_PROJECT_ENVELOPE_ROOT", str(root))
    monkeypatch.setenv("CAPABILITIES_HOME", str(tmp_path / "registry"))
    home = tmp_path / "config"
    namespace = {
        "__name__": "probe", "os": os, "sys": sys, "json": json,
        "Path": Path, "NoReturn": NoReturn,
        "NAME": "probe", "SUMMARY": "a probe", "SCOPE": "project", "DOCS_BASE": "",
        "STATE": False, "INVENTORY": None, "POST_INSTALL": [],
        "_CONFIG_HOME": home, "_STATE_HOME": home,
        "CREDENTIALS_ENV": home / "probe" / "credentials.env", "CRED_KEYS": [],
        "WRITE_VERBS": set(), "WRITE_DEFAULT": False,
    }
    bind(namespace, "core", "store", "connections")
    vault: dict = {}
    namespace["_vault_value"] = lambda key: ((vault[key], "vault:prj") if key in vault
                                             else (None, None))
    namespace["vault"] = vault
    namespace["root"] = root
    yield namespace
    sys.excepthook = saved


def test_a_key_a_file_and_the_vault_hold_differently_is_asked_about(probe):
    (probe["root"] / ".env.local").write_text("PROBE_TOKEN=from-file\n")
    probe["vault"]["PROBE_TOKEN"] = "from-vault"
    assert probe["_resolve_env_key"]("PROBE_TOKEN")[0] == "from-file"
    question = probe["_supervisor_question"]()
    assert question["conflicts"] == [{"key": "PROBE_TOKEN",
                                      "files": [str(probe["root"] / ".env.local")]}]
    assert question["update_failed"] is None
    assert "from-file" not in json.dumps(question)
    assert "from-vault" not in json.dumps(question)


def test_equal_values_and_a_key_in_one_place_raise_nothing(probe):
    (probe["root"] / ".env").write_text("PROBE_TOKEN=same\nPROBE_FILE_ONLY=x\n")
    probe["vault"].update({"PROBE_TOKEN": "same", "PROBE_VAULT_ONLY": "y"})
    for key in ("PROBE_TOKEN", "PROBE_FILE_ONLY", "PROBE_VAULT_ONLY"):
        assert probe["_resolve_env_key"](key)[0]
    assert probe["_supervisor_question"]() is None


def test_a_failed_update_is_asked_about_and_a_healthy_state_is_not(probe, tmp_path):
    assert probe["_supervisor_question"]() is None
    record = tmp_path / "registry" / ".update-failed" / "probe.json"
    record.parent.mkdir(parents=True)
    record.write_text(json.dumps({"error": {"code": "network_error",
                                            "message": "fetch failed"}}))
    question = probe["_supervisor_question"]()
    assert question["conflicts"] == []
    assert question["update_failed"]["error"]["code"] == "network_error"
    assert "fetch failed" in question["question"]


def test_doctor_arms_one_line_on_stderr_and_answers_nothing_else(probe, capsys,
                                                                   monkeypatch):
    armed = []
    monkeypatch.setattr("atexit.register", armed.append)
    probe["_contract"](["doctor"])
    assert armed == [probe["_supervisor_line"]]
    (probe["root"] / ".env.local").write_text("PROBE_TOKEN=a\n")
    probe["vault"]["PROBE_TOKEN"] = "b"
    probe["_resolve_env_key"]("PROBE_TOKEN")
    probe["_supervisor_line"]()
    out, err = capsys.readouterr()
    assert out == ""
    lines = err.splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["supervisor"]["conflicts"][0]["key"] == "PROBE_TOKEN"
    probe["vault"]["PROBE_TOKEN"] = "a"
    probe["_supervisor_line"]()
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("argv", [["--connection", "main", "doctor"],
                                  ["--connection=main", "doctor"],
                                  ["doctor", "--connection", "main"]])
def test_doctor_arms_the_line_wherever_the_connection_is_named(probe, monkeypatch, argv):
    armed = []
    monkeypatch.setattr("atexit.register", armed.append)
    probe["_contract"](argv)
    assert armed == [probe["_supervisor_line"]]


@pytest.mark.parametrize("argv", [["service", "doctor"],
                                  ["--connection", "main", "service", "doctor"],
                                  ["--connection", "doctor"]])
def test_only_the_doctor_verb_arms_the_line(probe, monkeypatch, argv):
    armed = []
    monkeypatch.setattr("atexit.register", armed.append)
    probe["_contract"](argv)
    assert armed == []
