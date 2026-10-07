"""The setting is read exactly as the manager's store tier reads it."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import write_setting

from capabilities_contract.db import DbError, read_setting, setting_files

BASE = {"schema": "capabilities.store.v1", "host": "db.example.test", "port": 5432,
        "database": "app", "user": "agent", "sslmode": "require"}


def _read(home: Path, document: dict, password: str | None = "pw"):
    write_setting(home, document, password)
    return read_setting()


def _refused(home: Path, document) -> DbError:
    folder = home / "capabilities"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "store.json").write_text(
        document if isinstance(document, str) else __import__("json").dumps(document))
    with pytest.raises(DbError) as caught:
        read_setting()
    return caught.value


# --- accepted -------------------------------------------------------------------

def test_the_files_are_the_managers(clean_env):
    assert setting_files() == (clean_env / "capabilities" / "store.json",
                               clean_env / "capabilities" / "credentials.env")


def test_a_v1_setting_binds_agentkit_and_reads_the_password(clean_env):
    s = _read(clean_env, BASE, password="p@ss word")
    assert (s.host, s.port, s.database, s.user, s.sslmode) == (
        "db.example.test", 5432, "app", "agent", "require")
    assert s.schema == "agentkit" and s.password == "p@ss word"
    assert s.source == str(clean_env / "capabilities" / "store.json")
    assert "p@ss" not in repr(s)


def test_the_port_defaults_and_a_digit_string_is_a_port(clean_env):
    doc = {k: v for k, v in BASE.items() if k != "port"}
    assert _read(clean_env, doc).port == 5432
    assert _read(clean_env, {**BASE, "port": "6543"}).port == 6543


def test_no_password_file_means_no_password(clean_env):
    assert _read(clean_env, BASE, password=None).password is None


@pytest.mark.parametrize("mode", ["require", "verify-ca", "verify-full"])
def test_require_and_stronger_are_accepted(clean_env, mode):
    s = _read(clean_env, {**BASE, "sslmode": mode, "sslrootcert": "/etc/ssl/root.crt"})
    assert s.sslmode == mode and s.sslrootcert == "/etc/ssl/root.crt"


def test_a_v2_setting_names_its_schema(clean_env):
    doc = {**BASE, "schema": "capabilities.store.v2", "db_schema": "shared_state"}
    assert _read(clean_env, doc).schema == "shared_state"


def test_a_v2_setting_without_a_schema_binds_agentkit(clean_env):
    assert _read(clean_env, {**BASE, "schema": "capabilities.store.v2"}).schema == "agentkit"


def test_a_v1_setting_ignores_unknown_fields_as_the_store_tier_does(clean_env):
    doc = {**BASE, "db_schema": "elsewhere", "comment": "x"}
    assert _read(clean_env, doc).schema == "agentkit"


def test_the_override_wins_over_the_setting(clean_env, monkeypatch):
    write_setting(clean_env, BASE, "pw")
    monkeypatch.setenv("CAPABILITIES_STORE_URL", "postgresql://u:secret@h:5/d?sslmode=require")
    s = read_setting()
    assert s.source == "CAPABILITIES_STORE_URL" and s.schema == "agentkit"
    assert s.connect_kwargs() == {"conninfo": "postgresql://u:secret@h:5/d?sslmode=require"}
    assert "secret" not in repr(s)


def test_the_override_wins_with_no_setting(clean_env, monkeypatch):
    monkeypatch.setenv("CAPABILITIES_STORE_URL", "postgres://h/d")
    assert read_setting().source == "CAPABILITIES_STORE_URL"
    assert os.listdir(clean_env) == []


def test_an_override_that_is_not_postgres_is_refused(clean_env, monkeypatch):
    monkeypatch.setenv("CAPABILITIES_STORE_URL", "/var/lib/store.db")
    with pytest.raises(DbError) as caught:
        read_setting()
    assert caught.value.slug == "store_not_postgres"


# --- refused --------------------------------------------------------------------

@pytest.mark.parametrize("mode", ["disable", "allow", "prefer"])
def test_an_sslmode_below_require_is_refused(clean_env, mode):
    err = _refused(clean_env, {**BASE, "sslmode": mode})
    assert err.slug == "sslmode_too_weak" and "require" in err.hint


@pytest.mark.parametrize("document", [
    {k: v for k, v in BASE.items() if k != "sslmode"},
    {**BASE, "sslmode": "verify"},
    {**BASE, "host": "db example"},
    {**BASE, "host": ""},
    {k: v for k, v in BASE.items() if k != "user"},
    {**BASE, "database": 5},
    {**BASE, "port": 0},
    {**BASE, "port": 70000},
    {**BASE, "port": True},
    {**BASE, "port": "54x"},
    {**BASE, "sslrootcert": ""},
    {**BASE, "sslrootcert": "a\nb"},
    {**BASE, "schema": "capabilities.store.v3"},
    {k: v for k, v in BASE.items() if k != "schema"},
    [1, 2],
    "not json",
    {**BASE, "schema": "capabilities.store.v2", "db_schema": "public"},
    {**BASE, "schema": "capabilities.store.v2", "db_schema": "pg_catalog"},
    {**BASE, "schema": "capabilities.store.v2", "db_schema": "Agent-Kit"},
    {**BASE, "schema": "capabilities.store.v2", "db_schema": 7},
])
def test_a_malformed_setting_is_refused(clean_env, document):
    err = _refused(clean_env, document)
    assert err.slug in ("bad_store_setting", "bad_schema_name"), err


# --- not configured (C3) ---------------------------------------------------------

def test_no_setting_and_no_override_is_store_not_configured_and_creates_nothing(clean_env):
    with pytest.raises(DbError) as caught:
        read_setting()
    err = caught.value
    assert err.slug == "store_not_configured"
    assert err.message == "this machine has no store setting"
    assert err.hint == "run capabilities store set"
    assert list(clean_env.rglob("*")) == []


def test_connect_without_a_setting_is_store_not_configured_and_creates_nothing(clean_env):
    from capabilities_contract.db import connect
    with pytest.raises(DbError) as caught:
        connect(application_name="test")
    assert caught.value.slug == "store_not_configured"
    assert list(clean_env.rglob("*")) == []


# --- parity with the manager's own store tier, when it is on this machine ---------

STORE_TIER = Path(os.environ.get("CAPABILITIES_STORE_TIER",
                                 "/Users/kz/dev/capabilities/contract/store.py"))

PARITY_CASES = [
    BASE,
    {**BASE, "port": "6543", "sslmode": "verify-full", "sslrootcert": "system"},
    {k: v for k, v in BASE.items() if k != "port"},
    {**BASE, "extra": 1},
    {**BASE, "sslmode": "prefer"},
    {**BASE, "sslmode": "disable"},
    {**BASE, "sslmode": "nope"},
    {**BASE, "host": "a b"},
    {**BASE, "port": 0},
    {**BASE, "port": True},
    {**BASE, "sslrootcert": "x\ny"},
    {k: v for k, v in BASE.items() if k != "database"},
    {**BASE, "schema": "other"},
]


@pytest.fixture(scope="module")
def tier(tmp_path_factory):
    if not STORE_TIER.exists():
        pytest.skip("the manager's store tier is not on this machine")
    # Imported from a copy, so nothing is written beside the original.
    copy = tmp_path_factory.mktemp("tier") / "store_tier.py"
    shutil.copyfile(STORE_TIER, copy)
    spec = importlib.util.spec_from_file_location("store_tier", copy)
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode, before = True, sys.dont_write_bytecode
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = before
    return module


@pytest.mark.parametrize("document", PARITY_CASES)
def test_the_setting_reads_as_the_store_tier_reads_it(tier, clean_env, document):
    write_setting(clean_env, document, "pw")
    try:
        theirs = tier.read_store_setting()
        their_error = None
    except tier.StoreError as exc:
        theirs, their_error = None, exc.slug
    try:
        ours = read_setting()
        our_error = None
    except DbError as exc:
        ours, our_error = None, exc.slug
    assert our_error == their_error
    if theirs is not None:
        assert {k: getattr(ours, k) for k in theirs} == theirs


def test_the_store_tier_refuses_a_v2_setting(tier, clean_env):
    """Why a schema field needs a new setting id: today's readers refuse it."""
    write_setting(clean_env, {**BASE, "schema": "capabilities.store.v2", "db_schema": "x"})
    with pytest.raises(tier.StoreError):
        tier.read_store_setting()
    assert read_setting().schema == "x"


def test_import_does_not_load_the_driver():
    """C5: a fresh interpreter importing the module leaves psycopg unloaded."""
    code = ("import sys, capabilities_contract.db as db; "
            "assert db.connect and db.migrate; "
            "print('psycopg' in sys.modules, any(m.startswith('psycopg') for m in sys.modules))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         check=True).stdout.split()
    assert out == ["False", "False"]
