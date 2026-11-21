"""The layered help: `help` is the menu and `help <verb>` one verb's whole
contract, for a capability that declares `HELP_VERBS`; any other answers as
before."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import NoReturn

import pytest

from capabilities_contract.capability import bind

MENU = """probe - a probe.

  probe send <to>               send one message
  probe cards list              the cards
  probe cards create <title>    make one card
"""

PAGES = {
    "send": "probe send <to> [--urgent]\n\n  Sends one message.\n",
    "cards list": "probe cards list [--all]\n\n  Lists the cards.\n",
    "cards create": "probe cards create <title>\n\n  Makes one card.\n",
    "doctor": "  It also proves the probe answers.\n",
}


@pytest.fixture
def probe(tmp_path, monkeypatch):
    saved = sys.excepthook
    root = tmp_path / "project"
    (root / "capabilities").mkdir(parents=True)
    for key in ("CAPABILITIES_PROJECT_ID", "CAPABILITIES_PROJECT_ID_ROOT",
                "CAPABILITIES_AUTH_CONTEXT"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(root))
    monkeypatch.setenv("CAPABILITIES_PROJECT_ENVELOPE", str(root / "capabilities"))
    monkeypatch.setenv("CAPABILITIES_PROJECT_ENVELOPE_ROOT", str(root))
    monkeypatch.setenv("CAPABILITIES_HOME", str(tmp_path / "registry"))
    bundle = tmp_path / "probe"
    (bundle / "bin").mkdir(parents=True)
    (bundle / "guides").mkdir()
    (bundle / "guides" / "usage.md").write_text("# Usage\n\nHow to use it.\n")
    home = tmp_path / "config"

    def make(layered: bool) -> dict:
        namespace = {
            "__name__": "probe", "__file__": str(bundle / "bin" / "probe"),
            "os": os, "sys": sys, "json": json, "Path": Path, "NoReturn": NoReturn,
            "NAME": "probe", "SUMMARY": "a probe", "SCOPE": "project", "DOCS_BASE": "",
            "STATE": False, "INVENTORY": None, "POST_INSTALL": [],
            "_CONFIG_HOME": home, "_STATE_HOME": home,
            "CREDENTIALS_ENV": home / "probe" / "credentials.env",
            "CRED_KEYS": [{"key": "PROBE_TOKEN", "secret": True, "required": True}],
            "WRITE_VERBS": {"send"}, "WRITE_DEFAULT": False, "HELP": MENU,
            "CONN_FIELDS": [{"key": "secret_env", "label": "Token", "type": "string",
                             "secret": True, "required": True, "env": "PROBE_{ID}_TOKEN",
                             "help": "the probe's token"}],
        }
        if layered:
            namespace["HELP_VERBS"] = dict(PAGES)
        bind(namespace, "core", "store", "connections")
        namespace["_identifiers_load"] = lambda: {}
        return namespace

    yield make
    sys.excepthook = saved


def _run(namespace, monkeypatch, capsys, *argv):
    monkeypatch.setattr(sys, "argv", ["probe", *argv])
    try:
        namespace["_contract"](list(argv))
    except SystemExit as stop:
        code = stop.code
    else:
        code = None
    out = capsys.readouterr()
    return code, out.out, out.err


def test_the_menu_is_the_body_the_contract_verbs_and_the_pointer(probe, monkeypatch, capsys):
    code, out, _err = _run(probe(True), monkeypatch, capsys, "help")
    assert code == 0
    assert out.startswith(MENU)
    for line in ("probe help [<verb>]", "probe doctor", "probe connections",
                 "probe connection add|remove|seal|rename", "probe stub",
                 "probe manifest", "probe ids list|get|set|rm", "probe refs [show <name>]",
                 "probe inventory", "probe guide [<topic>]"):
        assert f"\n  {line} " in out, line
    assert "guides: usage" in out
    assert "Run `probe help <verb>`" in out
    # The declared sections are verb pages, not menu text: no flag opens a line
    # and no verb line carries one.
    assert "connection add <id>" not in out and "Where a secret resolves" not in out
    for line in out.splitlines():
        assert not line.lstrip().startswith("-"), line
        if line.lstrip().startswith("probe "):
            assert " --" not in line, line


def test_a_verb_page_is_that_verbs_whole_contract(probe, monkeypatch, capsys):
    namespace = probe(True)
    code, out, _err = _run(namespace, monkeypatch, capsys, "help", "send")
    assert (code, out) == (0, PAGES["send"])
    code, out, _err = _run(namespace, monkeypatch, capsys, "help", "cards", "create")
    assert (code, out) == (0, PAGES["cards create"])
    # The longest declared path the words begin with answers.
    code, out, _err = _run(namespace, monkeypatch, capsys, "help", "send", "extra")
    assert (code, out) == (0, PAGES["send"])


def test_a_group_lists_its_verbs(probe, monkeypatch, capsys):
    code, out, _err = _run(probe(True), monkeypatch, capsys, "help", "cards")
    assert code == 0
    assert "probe cards create <title>" in out and "probe cards list [--all]" in out


def test_a_contract_verb_page_comes_from_the_contract_and_takes_the_capabilitys_own(
        probe, monkeypatch, capsys):
    namespace = probe(True)
    code, out, _err = _run(namespace, monkeypatch, capsys, "help", "doctor")
    assert code == 0
    assert out.startswith("probe doctor [--connection <id>]")
    assert out.endswith(PAGES["doctor"])
    code, out, _err = _run(namespace, monkeypatch, capsys, "help", "connection")
    assert code == 0
    assert "connection add <id>" in out and "Where a secret resolves" in out
    code, out, _err = _run(namespace, monkeypatch, capsys, "help", "connections")
    assert code == 0 and "Where connections live" in out
    for verb in ("help", "stub", "manifest", "guide", "ids", "refs", "inventory"):
        code, out, _err = _run(namespace, monkeypatch, capsys, "help", verb)
        assert code == 0 and out.startswith(f"probe {verb}"), verb


def test_an_unknown_verb_answers_the_menus_pointer_and_never_a_dump(
        probe, monkeypatch, capsys):
    code, out, err = _run(probe(True), monkeypatch, capsys, "help", "nosuch")
    assert code == 6 and out == ""
    error = json.loads(err.strip().splitlines()[-1])["error"]
    assert error["code"] == "unknown_verb"
    assert "probe help" in error["hint"]


def test_a_capability_without_help_verbs_answers_as_before(probe, monkeypatch, capsys):
    namespace = probe(False)
    code, out, _err = _run(namespace, monkeypatch, capsys, "help")
    assert code == 0
    assert out.startswith(MENU)
    assert "Where connections live" in out and "connection add <id>" in out
    assert "## Contract verbs" not in out
    # `help <x>` is the capability's own parser's.
    code, out, _err = _run(namespace, monkeypatch, capsys, "help", "send")
    assert (code, out) == (None, "")
