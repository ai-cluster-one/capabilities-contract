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


def test_the_last_line_naming_the_id_in_a_file_wins(tmp_path, monkeypatch, excepthook):
    """As in any env file, and as the manager reads it."""
    namespace, root = _project(
        tmp_path, monkeypatch,
        **{".env.local": "CAPABILITIES_PROJECT_ID=prj_00000000a1a1\nOTHER=1\n"
                         "CAPABILITIES_PROJECT_ID=prj_00000000b2b2\n"})
    assert namespace["_project_id_state_at"](root)["id"] == "prj_00000000b2b2"
    from capabilities_contract.capability.tiers import store
    assert store._bound_project_id(root) == "prj_00000000b2b2"


def test_the_environment_wins_over_the_env_files(tmp_path, monkeypatch, excepthook):
    namespace, root = _project(
        tmp_path, monkeypatch, **{".env.local": "CAPABILITIES_PROJECT_ID=prj_00000000a1a1\n"})
    monkeypatch.setenv("CAPABILITIES_PROJECT_ID", "prj_00000000b2b2")
    monkeypatch.setenv("CAPABILITIES_PROJECT_ID_ROOT", str(root))
    state = namespace["_project_id_state"]()
    assert state == {"state": "handed", "id": "prj_00000000b2b2"}
    assert namespace["_identity_refusal"](state) is None
    assert namespace["_project_id"](write=True) == "prj_00000000b2b2"
    # A value handed down for another root is passed over.
    monkeypatch.setenv("CAPABILITIES_PROJECT_ID_ROOT", str(tmp_path / "elsewhere"))
    assert namespace["_project_id_state_at"](root)["id"] == "prj_00000000a1a1"


def test_an_id_in_the_environment_without_a_root_binds_nothing(tmp_path, monkeypatch,
                                                                excepthook):
    namespace, root = _project(tmp_path, monkeypatch)
    monkeypatch.setenv("CAPABILITIES_PROJECT_ID", "prj_00000000b2b2")
    assert namespace["_project_id_state_at"](root) == {"state": "undeclared", "id": None}
    from capabilities_contract.capability.tiers import store
    assert store._bound_project_id(root) is None
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    assert namespace["_project_root"]() is None


def _walker(tmp_path, monkeypatch) -> dict:
    """A core-bound namespace whose walk starts where CLAUDE_PROJECT_DIR says."""
    for key in ("CAPABILITIES_PROJECT_ID", "CAPABILITIES_PROJECT_ID_ROOT",
                "CAPABILITIES_PROJECT_ENVELOPE", "CAPABILITIES_PROJECT_ENVELOPE_ROOT"):
        monkeypatch.delenv(key, raising=False)
    namespace = _declarations()
    bind(namespace, "core")
    return namespace


def test_the_root_is_the_nearest_folder_whose_env_files_set_the_id(tmp_path, monkeypatch,
                                                                   excepthook):
    namespace = _walker(tmp_path, monkeypatch)
    agent = tmp_path / "agent"
    work = agent / "workspace" / "repo"
    (work / ".git").mkdir(parents=True)
    (agent / ".env.local").write_text("CAPABILITIES_PROJECT_ID=prj_00000000a1a1\n")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(work))
    # A repository inside the agent's folder is not a project of its own.
    assert namespace["_project_root"]() == agent.resolve()
    # Without a bound folder above it, the repository names an unbound one.
    (agent / ".env.local").write_text("OTHER=1\n")
    assert namespace["_project_root"]() == work.resolve()
    # A folder that still has its project.json is bound by it.
    (agent / "capabilities").mkdir()
    (agent / "capabilities" / "project.json").write_text('{"slug": "agent"}')
    assert namespace["_project_root"]() == agent.resolve()


def test_the_environment_binds_its_root_from_anywhere_outside_a_bound_folder(
        tmp_path, monkeypatch, excepthook):
    namespace = _walker(tmp_path, monkeypatch)
    app = tmp_path / "app"
    app.mkdir()
    elsewhere = tmp_path / "elsewhere" / "repo"
    (elsewhere / ".git").mkdir(parents=True)
    monkeypatch.setenv("CAPABILITIES_PROJECT_ID", "prj_00000000a1a1")
    monkeypatch.setenv("CAPABILITIES_PROJECT_ID_ROOT", str(app))
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(elsewhere))
    assert namespace["_project_root"]() == app.resolve()
    assert namespace["_project_id_state_at"](app.resolve()) == {
        "state": "handed", "id": "prj_00000000a1a1"}
    # A folder bound to an id of its own is passed over by nobody's hand-down.
    other = tmp_path / "other"
    other.mkdir()
    (other / ".env.local").write_text("CAPABILITIES_PROJECT_ID=prj_00000000b2b2\n")
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(other))
    assert namespace["_project_root"]() == other.resolve()
    assert namespace["_project_id_state_at"](other.resolve())["id"] == "prj_00000000b2b2"


def _no_database(tmp_path, monkeypatch) -> None:
    for key in list(os.environ):
        if key.startswith("AGENTKIT_DB_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))


def test_the_slug_is_an_older_project_json_s_else_the_id_without_a_store(
        tmp_path, monkeypatch, excepthook):
    _no_database(tmp_path, monkeypatch)
    namespace, root = _project(
        tmp_path, monkeypatch, **{".env.local": "CAPABILITIES_PROJECT_ID=prj_00000000a1a1\n"})
    bind(namespace, "store")
    assert namespace["_project_slug"](root) == "prj_00000000a1a1"
    namespace["_PROJECT_SLUG"].clear()
    (root / "capabilities" / "project.json").write_text('{"slug": "kept"}')
    assert namespace["_project_slug"](root) == "kept"
    assert namespace["_project_identity"]() == {"id": "prj_00000000a1a1", "slug": "kept"}


def test_a_project_bound_by_its_id_alone_keeps_its_records_in_the_store(
        tmp_path, monkeypatch, excepthook):
    from capabilities_contract.capability.tiers import store
    _no_database(tmp_path, monkeypatch)
    root = tmp_path / "project"
    envelope = root / "capabilities"
    envelope.mkdir(parents=True)
    (root / ".env.local").write_text("CAPABILITIES_PROJECT_ID=prj_00000000a1a1\n")
    # No database resolves: nothing but the files can hold them.
    assert store.records_mode(envelope) == "files"
    monkeypatch.setenv("AGENTKIT_DB_URL", "postgresql://agent@127.0.0.1:1/app")
    assert store.records_mode(envelope) == "store"
    assert store.connections_mode(envelope, root) == "store"
    # A settings.json gate is a project in files mode.
    (envelope / "settings.json").write_text('{"capabilities": {}}')
    assert store.records_mode(envelope) == "files"
    # An older project.json still says it.
    (envelope / "project.json").write_text('{"slug": "p", "records": "store"}')
    assert store.records_mode(envelope) == "store"
    (envelope / "settings.json").unlink()
    (envelope / "project.json").write_text('{"slug": "p"}')
    assert store.records_mode(envelope) == "files"
    # Without an id nothing binds it to an agent.
    (envelope / "project.json").unlink()
    (root / ".env.local").write_text("OTHER=1\n")
    assert store.records_mode(envelope) == "files"


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
