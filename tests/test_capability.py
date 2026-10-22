"""The shared capability code binds into a capability's own namespace."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import NoReturn

import pytest

from capabilities_contract.capability import TIERS, bind, tier_path


def _declarations(**extra) -> dict:
    """What a capability defines before it binds a tier."""
    home = Path("/nonexistent-capability-home")
    namespace = {
        "__name__": "probe", "os": os, "sys": sys, "json": __import__("json"),
        "Path": Path, "NoReturn": NoReturn,
        "NAME": "probe", "SUMMARY": "a probe", "SCOPE": "project", "DOCS_BASE": "",
        "STATE": False, "INVENTORY": None, "POST_INSTALL": [],
        "_CONFIG_HOME": home, "_STATE_HOME": home,
        "CREDENTIALS_ENV": home / "probe" / "credentials.env", "CRED_KEYS": [],
        "WRITE_VERBS": set(), "WRITE_DEFAULT": False,
    }
    namespace.update(extra)
    return namespace


@pytest.fixture
def excepthook():
    """The core tier installs its own excepthook; the test leaves none behind."""
    saved = sys.excepthook
    yield
    sys.excepthook = saved


def test_every_tier_binds_into_the_namespace_it_is_given(excepthook):
    namespace = _declarations()
    bind(namespace, *TIERS)
    for name in ("_contract", "_die", "_emit", "open_records", "StoreError",
                 "_resolve_env_key", "_doctor_gate"):
        assert callable(namespace[name]), name
    assert namespace["_contract"].__globals__ is namespace
    assert "__doc__" not in namespace


def test_a_name_replaced_in_the_namespace_is_replaced_for_the_tier(excepthook):
    namespace = _declarations()
    bind(namespace, "core", "store")
    seen = []

    def emit(value):
        seen.append(value)

    namespace["_emit"] = emit
    assert namespace["_die"].__globals__["_emit"] is emit


def test_a_tier_takes_the_namespace_future_annotations(excepthook):
    import __future__

    lazy = _declarations(annotations=__future__.annotations)
    bind(lazy, "core")
    eager = _declarations()
    bind(eager, "core")
    assert lazy["_die"].__annotations__["exit_code"] == "int"
    assert eager["_die"].__annotations__["exit_code"] is int


def test_the_store_tier_imports_as_a_module_of_its_own():
    from capabilities_contract.capability import store

    assert issubclass(store.StoreError, Exception)
    assert isinstance(store.STORE_TABLES_VERSION, tuple)
    assert store.open_records.__globals__ is vars(store)


def test_an_unknown_tier_is_refused():
    with pytest.raises(ValueError, match="unknown capability tier"):
        tier_path("other")
    for tier in TIERS:
        assert tier_path(tier).is_file()


def _project(tmp_path, monkeypatch, **files) -> tuple[dict, Path]:
    """A project folder and a core-bound namespace standing in it, its
    envelope handed down so no manager is asked for it."""
    root = tmp_path / "project"
    (root / "capabilities").mkdir(parents=True)
    for name, text in files.items():
        path = root / name.replace("__", "/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    for key in ("CAPABILITIES_PROJECT_ID", "CAPABILITIES_PROJECT_ID_ROOT"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(root))
    monkeypatch.setenv("CAPABILITIES_PROJECT_ENVELOPE", str(root / "capabilities"))
    monkeypatch.setenv("CAPABILITIES_PROJECT_ENVELOPE_ROOT", str(root))
    namespace = _declarations()
    bind(namespace, "core")
    return namespace, root


def test_the_project_id_is_read_from_env_local_before_env(tmp_path, monkeypatch, excepthook):
    namespace, root = _project(
        tmp_path, monkeypatch,
        **{".env": "CAPABILITIES_PROJECT_ID=prj_00000000e0e0\n",
           ".env.local": "OTHER=1\nCAPABILITIES_PROJECT_ID=\"prj_00000000a1a1\"\n"})
    assert namespace["_project_id_state"]() == {"state": "declared", "id": "prj_00000000a1a1"}
    (root / ".env.local").write_text("OTHER=1\n")
    assert namespace["_project_id_state_at"](root)["id"] == "prj_00000000e0e0"


def test_the_environment_wins_over_the_env_files(tmp_path, monkeypatch, excepthook):
    namespace, root = _project(
        tmp_path, monkeypatch, **{".env.local": "CAPABILITIES_PROJECT_ID=prj_00000000a1a1\n"})
    monkeypatch.setenv("CAPABILITIES_PROJECT_ID", "prj_00000000b2b2")
    state = namespace["_project_id_state"]()
    assert state == {"state": "handed", "id": "prj_00000000b2b2"}
    assert namespace["_identity_refusal"](state) is None
    assert namespace["_project_id"](write=True) == "prj_00000000b2b2"
    # A value handed down for another root is passed over.
    monkeypatch.setenv("CAPABILITIES_PROJECT_ID_ROOT", str(tmp_path / "elsewhere"))
    assert namespace["_project_id_state_at"](root)["id"] == "prj_00000000a1a1"


def test_an_id_in_project_json_is_not_the_projects_id(tmp_path, monkeypatch, excepthook):
    """project.json's id is read by the manager alone, which moves it into
    .env.local; a capability asks the manager and takes its answer."""
    manager = tmp_path / "manager"
    manager.write_text(
        "#!/bin/sh\n"
        f"printf '%s' '{{\"project_root\": \"{tmp_path / 'project'}\", "
        "\"project_identity\": {\"state\": \"declared\", \"id\": \"prj_00000000c3c3\"}}'\n")
    manager.chmod(0o755)
    monkeypatch.setenv("CAPABILITIES_MANAGER_BIN", str(manager))
    namespace, root = _project(
        tmp_path, monkeypatch,
        **{"capabilities__project.json": '{"id": "prj_00000000d4d4", "slug": "p"}'})
    assert namespace["_project_id_state"]() == {"state": "declared", "id": "prj_00000000c3c3"}
    # Without an id left anywhere, nobody is asked and there is no id.
    (root / "capabilities" / "project.json").write_text('{"slug": "p"}')
    manager.write_text("#!/bin/sh\nexit 9\n")
    namespace["_PROJECT_ID_HANDED"].clear()
    for key in ("CAPABILITIES_PROJECT_ID", "CAPABILITIES_PROJECT_ID_ROOT"):
        monkeypatch.delenv(key, raising=False)
    assert namespace["_project_id_state_at"](root) == {"state": "undeclared", "id": None}
