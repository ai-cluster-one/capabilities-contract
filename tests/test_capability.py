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
