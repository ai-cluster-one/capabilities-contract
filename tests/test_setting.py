"""The setting is read exactly as the manager's store tier reads it."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import write_family_setting, write_setting

from capabilities_contract.db import DbError, read_setting, setting_files, setting_path

BASE = {"schema": "capabilities.store.v1", "host": "db.example.test", "port": 5432,
        "database": "app", "user": "agent", "sslmode": "require"}
FAMILY = {**BASE, "schema": "agentkit.store.v1", "password": "pw"}


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


# --- the family file ---------------------------------------------------------------

def test_the_family_file_is_under_agentkit(clean_env, monkeypatch):
    assert setting_path() == clean_env / "agentkit" / "store.json"
    monkeypatch.delenv("XDG_CONFIG_HOME")
    monkeypatch.setenv("HOME", str(clean_env / "home"))
    assert setting_path() == clean_env / "home" / ".config" / "agentkit" / "store.json"
    assert setting_path().is_absolute()


def test_the_family_file_is_read_with_its_password(clean_env):
    path = write_family_setting(clean_env, {**FAMILY, "password": "p@ss word"})
    s = read_setting()
    assert (s.host, s.port, s.database, s.user, s.sslmode) == (
        "db.example.test", 5432, "app", "agent", "require")
    assert s.schema == "agentkit" and s.password == "p@ss word"
    assert s.source == str(path)
    assert "p@ss" not in repr(s)


def test_the_family_file_names_its_schema_and_may_carry_no_password(clean_env):
    doc = {k: v for k, v in FAMILY.items() if k != "password"}
    write_family_setting(clean_env, {**doc, "db_schema": "shared_state"})
    s = read_setting()
    assert s.schema == "shared_state" and s.password is None


def test_the_family_file_wins_over_the_legacy_pair(clean_env):
    write_setting(clean_env, {**BASE, "host": "legacy.example.test"}, "old")
    path = write_family_setting(clean_env, FAMILY)
    s = read_setting()
    assert s.host == "db.example.test" and s.password == "pw" and s.source == str(path)


def test_the_legacy_pair_is_read_while_the_family_file_is_absent(clean_env):
    write_setting(clean_env, BASE, "old")
    s = read_setting()
    assert s.password == "old"
    assert s.source == str(clean_env / "capabilities" / "store.json")


def test_agentkit_store_url_wins_over_capabilities_store_url(clean_env, monkeypatch):
    write_family_setting(clean_env, FAMILY)
    monkeypatch.setenv("CAPABILITIES_STORE_URL", "postgresql://c@h/d")
    assert read_setting().source == "CAPABILITIES_STORE_URL"
    monkeypatch.setenv("AGENTKIT_STORE_URL", "postgresql://a@h/d")
    s = read_setting()
    assert s.source == "AGENTKIT_STORE_URL" and s.schema == "agentkit"
    assert s.connect_kwargs() == {"conninfo": "postgresql://a@h/d"}


def test_an_agentkit_store_url_that_is_not_postgres_is_refused(clean_env, monkeypatch):
    monkeypatch.setenv("AGENTKIT_STORE_URL", "sqlite:///x.db")
    with pytest.raises(DbError) as caught:
        read_setting()
    assert caught.value.slug == "store_not_postgres"
    assert "AGENTKIT_STORE_URL" in caught.value.message


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "::1", "/var/run/postgresql"])
def test_sslmode_disable_is_admitted_for_a_local_host(clean_env, host):
    write_family_setting(clean_env, {**FAMILY, "host": host, "sslmode": "disable"})
    s = read_setting()
    assert s.host == host and s.sslmode == "disable"


@pytest.mark.parametrize("host,mode", [("db.example.test", "disable"),
                                       ("192.0.2.10", "disable"),
                                       ("localhost", "prefer"),
                                       ("localhost", "allow")])
def test_plain_text_is_refused_elsewhere_and_allow_prefer_everywhere(clean_env, host, mode):
    write_family_setting(clean_env, {**FAMILY, "host": host, "sslmode": mode})
    with pytest.raises(DbError) as caught:
        read_setting()
    assert caught.value.slug == "sslmode_too_weak"


def test_a_newer_family_version_is_refused_and_not_read_past(clean_env):
    write_setting(clean_env, BASE, "old")
    write_family_setting(clean_env, {**FAMILY, "schema": "agentkit.store.v2", "extra": 1})
    with pytest.raises(DbError) as caught:
        read_setting()
    assert caught.value.slug == "store_setting_too_new"
    assert "update" in caught.value.hint


@pytest.mark.parametrize("document", [
    {**FAMILY, "at": "2026-10-08T00:00:00Z"},
    {**FAMILY, "schema": "capabilities.store.v1"},
    {k: v for k, v in FAMILY.items() if k != "schema"},
    {**FAMILY, "password": 5},
    {**FAMILY, "password": "a\nb"},
    {**FAMILY, "db_schema": "public"},
    {k: v for k, v in FAMILY.items() if k != "host"},
    "not json",
    [1],
])
def test_a_malformed_family_file_is_refused(clean_env, document):
    write_family_setting(clean_env, document)
    with pytest.raises(DbError) as caught:
        read_setting()
    assert caught.value.slug in ("bad_store_setting", "bad_schema_name"), caught.value


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

# The manager's own store tier (its contract/store.py), named explicitly; without it
# the parity tests skip.
STORE_TIER_ENV = "CAPABILITIES_STORE_TIER"

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
    named = os.environ.get(STORE_TIER_ENV)
    if not named:
        pytest.skip(f"{STORE_TIER_ENV} does not name the manager's store.py")
    tier_file = Path(named)
    if not tier_file.is_file():
        pytest.skip(f"{STORE_TIER_ENV} names {tier_file}, which is not a file")
    # Imported from a copy, so nothing is written beside the original.
    copy = tmp_path_factory.mktemp("tier") / "store_tier.py"
    shutil.copyfile(tier_file, copy)
    spec = importlib.util.spec_from_file_location("store_tier", copy)
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode, before = True, sys.dont_write_bytecode
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = before
    return module


FAMILY_PARITY_CASES = [
    FAMILY,
    {**FAMILY, "db_schema": "other_schema"},
    {**FAMILY, "host": "localhost", "sslmode": "disable"},
    {**FAMILY, "host": "db.example.test", "sslmode": "disable"},
    {**FAMILY, "schema": "agentkit.store.v9"},
    {**FAMILY, "extra": 1},
]


@pytest.mark.parametrize("document", FAMILY_PARITY_CASES)
def test_the_family_file_reads_as_the_store_tier_reads_it(tier, clean_env, document):
    write_family_setting(clean_env, document)
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
        ours_values = {k: getattr(ours, k) for k in theirs if k != "db_schema"}
        assert ours_values == {k: v for k, v in theirs.items() if k != "db_schema"}
        assert ours.schema == theirs["db_schema"]


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
