"""Which database a project uses: the project's env files, then the process
environment, then the machine file, the first level that answers winning whole."""

from __future__ import annotations

import importlib.util
import json
import os
import random
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote

import pytest
from conftest import write_family_setting

from capabilities_contract.db import DbError, Setting, resolve_setting, setting_path

FAMILY = {"schema": "agentkit.store.v1", "host": "db.example.test", "port": 5432,
          "database": "app", "user": "agent", "sslmode": "require", "password": "pw"}
FIELDS = {"AGENTKIT_DB_HOST": "env.example.test", "AGENTKIT_DB_NAME": "envdb",
          "AGENTKIT_DB_USER": "envuser", "AGENTKIT_DB_PASSWORD": "env-secret"}


def _env_file(root: Path, name: str, keys: dict) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    path.write_text("".join(f"{k}={v}\n" for k, v in keys.items()))
    return path


def _setenv(monkeypatch, keys: dict) -> None:
    for key, value in keys.items():
        monkeypatch.setenv(key, value)


def _refused(*args, **kwargs) -> DbError:
    with pytest.raises(DbError) as caught:
        resolve_setting(*args, **kwargs)
    return caught.value


@pytest.fixture()
def project(tmp_path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    return root


# --- the order -------------------------------------------------------------------

def test_the_project_answers_before_the_environment_and_the_machine(clean_env, project,
                                                                    monkeypatch):
    write_family_setting(clean_env, FAMILY)
    _setenv(monkeypatch, FIELDS)
    path = _env_file(project, ".env", {**FIELDS, "AGENTKIT_DB_HOST": "project.example.test"})
    s = resolve_setting(project)
    assert (s.level, s.sources, s.host) == ("project", (str(path),), "project.example.test")


def test_the_environment_answers_before_the_machine(clean_env, project, monkeypatch):
    write_family_setting(clean_env, FAMILY)
    _setenv(monkeypatch, FIELDS)
    s = resolve_setting(project)
    assert (s.level, s.host, s.database, s.user, s.password) == (
        "environment", "env.example.test", "envdb", "envuser", "env-secret")
    assert set(s.sources) == set(FIELDS)


def test_the_machine_file_answers_last(clean_env, project):
    path = write_family_setting(clean_env, FAMILY)
    s = resolve_setting(project)
    assert (s.level, s.sources) == ("machine", (str(path),))
    assert (s.host, s.port, s.database, s.user, s.sslmode, s.password, s.schema) == (
        "db.example.test", 5432, "app", "agent", "require", "pw", "agentkit")


def test_no_project_root_skips_the_project_level(clean_env, project, monkeypatch):
    _env_file(project, ".env", {**FIELDS, "AGENTKIT_DB_HOST": "project.example.test"})
    _setenv(monkeypatch, FIELDS)
    assert resolve_setting(None).level == "environment"
    monkeypatch.chdir(project)
    assert resolve_setting(None).level == "environment"


def test_env_local_wins_over_env_key_by_key(clean_env, project):
    env = _env_file(project, ".env", FIELDS)
    local = _env_file(project, ".env.local", {"AGENTKIT_DB_PASSWORD": "local-secret",
                                              "OTHER": "x"})
    s = resolve_setting(project)
    assert (s.host, s.password) == ("env.example.test", "local-secret")
    assert set(s.sources) == {str(env), str(local)}


def test_a_level_is_never_completed_from_a_lower_one(clean_env, project, monkeypatch):
    write_family_setting(clean_env, FAMILY)
    _setenv(monkeypatch, FIELDS)
    _env_file(project, ".env", {"AGENTKIT_DB_SCHEMA": "mine"})
    err = _refused(project)
    assert err.slug == "bad_store_setting"
    assert "project level" in err.message and "host" in err.message
    monkeypatch.delenv("AGENTKIT_DB_HOST")
    err = _refused(None)
    assert "environment level" in err.message and "host" in err.message


def test_empty_values_and_other_keys_do_not_answer(clean_env, project, monkeypatch):
    path = write_family_setting(clean_env, FAMILY)
    _env_file(project, ".env", {"AGENTKIT_DB_URL": "", "DATABASE_URL": "postgresql://x/y"})
    monkeypatch.setenv("AGENTKIT_DB_HOST", "")
    assert resolve_setting(project).sources == (str(path),)


def test_the_retired_variables_and_files_are_not_read(clean_env, project, monkeypatch):
    monkeypatch.setenv("AGENTKIT_STORE_URL", "postgresql://a@h/d")
    monkeypatch.setenv("CAPABILITIES_STORE_URL", "postgresql://c@h/d")
    monkeypatch.setenv("CAPABILITIES_STORE_PASSWORD", "x")
    legacy = clean_env / "capabilities"
    legacy.mkdir()
    (legacy / "store.json").write_text(json.dumps({**FAMILY, "schema": "capabilities.store.v1"}))
    (legacy / "credentials.env").write_text("CAPABILITIES_STORE_PASSWORD=pw\n")
    _env_file(project, ".env", {"CAPABILITIES_STORE_URL": "postgresql://p@h/d"})
    assert _refused(project).slug == "store_not_configured"


def test_an_unknown_agentkit_db_key_in_a_project_file_is_refused(clean_env, project):
    _env_file(project, ".env", {**FIELDS, "AGENTKIT_DB_HOSTNAME": "x"})
    err = _refused(project)
    assert err.slug == "bad_store_setting" and "AGENTKIT_DB_HOSTNAME" in err.message


def test_the_env_files_parse_as_the_credential_cascade_parses_them(clean_env, project):
    (project / ".env").write_text(
        "# comment\n\nexport AGENTKIT_DB_HOST=env.example.test\n"
        "AGENTKIT_DB_NAME = \"envdb\"\nAGENTKIT_DB_USER='envuser'\nnot a line\n")
    s = resolve_setting(project)
    assert (s.host, s.database, s.user) == ("env.example.test", "envdb", "envuser")


# --- the separate fields ---------------------------------------------------------

def test_fields_take_their_defaults(clean_env, monkeypatch):
    _setenv(monkeypatch, {k: v for k, v in FIELDS.items() if k != "AGENTKIT_DB_PASSWORD"})
    s = resolve_setting(None)
    assert (s.port, s.sslmode, s.schema, s.password, s.sslrootcert) == (
        5432, "require", "agentkit", None, None)
    assert s.connect_kwargs() == {"host": "env.example.test", "port": 5432, "dbname": "envdb",
                                  "user": "envuser", "sslmode": "require"}


def test_every_field_is_read(clean_env, monkeypatch):
    _setenv(monkeypatch, {**FIELDS, "AGENTKIT_DB_PORT": "6543", "AGENTKIT_DB_SCHEMA": "shared",
                          "AGENTKIT_DB_SSLMODE": "verify-full",
                          "AGENTKIT_DB_SSLROOTCERT": "/etc/ssl/root.crt"})
    s = resolve_setting(None)
    assert (s.port, s.schema, s.sslmode, s.sslrootcert) == (
        6543, "shared", "verify-full", "/etc/ssl/root.crt")
    assert s.connect_kwargs()["password"] == "env-secret"


@pytest.mark.parametrize("keys,slug", [
    ({"AGENTKIT_DB_PORT": "54x"}, "bad_store_setting"),
    ({"AGENTKIT_DB_PORT": "0"}, "bad_store_setting"),
    ({"AGENTKIT_DB_HOST": "a b"}, "bad_store_setting"),
    ({"AGENTKIT_DB_SSLMODE": "prefer"}, "sslmode_too_weak"),
    ({"AGENTKIT_DB_SSLMODE": "disable"}, "sslmode_too_weak"),
    ({"AGENTKIT_DB_SSLMODE": "verify"}, "bad_store_setting"),
    ({"AGENTKIT_DB_SCHEMA": "public"}, "bad_schema_name"),
    ({"AGENTKIT_DB_SCHEMA": "Agent-Kit"}, "bad_schema_name"),
])
def test_bad_fields_are_refused_naming_where_they_came_from(clean_env, monkeypatch, keys, slug):
    _setenv(monkeypatch, {**FIELDS, **keys})
    err = _refused(None)
    assert err.slug == slug and err.message.startswith("the environment level (")


def test_sslmode_disable_is_admitted_for_a_local_host(clean_env, monkeypatch):
    _setenv(monkeypatch, {**FIELDS, "AGENTKIT_DB_HOST": "localhost",
                          "AGENTKIT_DB_SSLMODE": "disable"})
    assert resolve_setting(None).sslmode == "disable"


# --- the URL ---------------------------------------------------------------------

def test_the_url_wins_within_its_level_and_the_schema_applies_beside_it(clean_env, project):
    url = "postgresql://u:secret@db.example.test:6543/d?sslmode=verify-full"
    path = _env_file(project, ".env.local", {**FIELDS, "AGENTKIT_DB_URL": url,
                                             "AGENTKIT_DB_SCHEMA": "shared"})
    s = resolve_setting(project)
    assert (s.url, s.schema, s.host, s.password) == (url, "shared", None, None)
    assert s.sources == (str(path),)
    assert s.connect_kwargs() == {"conninfo": url}


def test_a_url_in_one_file_ignores_the_fields_of_the_other(clean_env, project):
    _env_file(project, ".env", {**FIELDS, "AGENTKIT_DB_SCHEMA": "shared"})
    local = _env_file(project, ".env.local", {"AGENTKIT_DB_URL": "postgresql://u@h/d"})
    s = resolve_setting(project)
    assert s.url == "postgresql://u@h/d" and s.schema == "shared"
    assert s.sources[0] == str(local) and len(s.sources) == 2


def test_a_url_without_a_schema_binds_agentkit(clean_env, monkeypatch):
    monkeypatch.setenv("AGENTKIT_DB_URL", "postgres://u@h/d")
    s = resolve_setting(None)
    assert (s.schema, s.level, s.sources) == ("agentkit", "environment", ("AGENTKIT_DB_URL",))


def test_a_url_naming_no_sslmode_is_given_require(clean_env, monkeypatch):
    monkeypatch.setenv("AGENTKIT_DB_URL", "postgresql://u@h/d")
    assert resolve_setting(None).connect_kwargs() == {"conninfo": "postgresql://u@h/d",
                                                      "sslmode": "require"}


@pytest.mark.parametrize("url,slug", [
    ("sqlite:///x.db", "store_not_postgres"),
    ("/var/lib/store.db", "store_not_postgres"),
    ("postgresql://u@db.example.test/d?sslmode=disable", "sslmode_too_weak"),
    ("postgresql://u@localhost/d?sslmode=prefer", "sslmode_too_weak"),
])
def test_a_bad_url_is_refused(clean_env, monkeypatch, url, slug):
    monkeypatch.setenv("AGENTKIT_DB_URL", url)
    err = _refused(None)
    assert err.slug == slug and "AGENTKIT_DB_URL" in err.message


@pytest.mark.parametrize("url", ["postgresql://u@localhost/d?sslmode=disable",
                                 "postgresql://u@127.0.0.1:5/d?sslmode=disable",
                                 "postgresql:///d?host=/var/run/postgresql&sslmode=disable",
                                 "postgresql:///d?sslmode=disable"])
def test_a_url_to_a_local_host_may_disable_tls(clean_env, monkeypatch, url):
    monkeypatch.setenv("AGENTKIT_DB_URL", url)
    assert resolve_setting(None).url == url


# --- the report ------------------------------------------------------------------

def test_the_report_names_the_level_and_sources_and_redacts_secrets(clean_env, project,
                                                                    monkeypatch):
    url = "postgresql://u:hunter22@h/d?sslmode=require&sslpassword=hunter23"
    monkeypatch.setenv("AGENTKIT_DB_URL", url)
    s = resolve_setting(project)
    report = s.report()
    assert report == {"level": "environment", "sources": ["AGENTKIT_DB_URL"],
                      "schema": "agentkit",
                      "url": {"user": "u", "password": "***", "host": "h", "dbname": "d",
                              "sslmode": "require", "sslpassword": "***"}}
    assert "hunter2" not in repr(s) and "hunter2" not in json.dumps(report)
    monkeypatch.delenv("AGENTKIT_DB_URL")
    path = write_family_setting(clean_env, FAMILY)
    report = resolve_setting(project).report()
    assert report == {"level": "machine", "sources": [str(path)], "schema": "agentkit",
                      "host": "db.example.test", "port": 5432, "database": "app",
                      "user": "agent", "sslmode": "require", "sslrootcert": None,
                      "password": "***"}


def test_the_report_of_a_url_is_what_libpq_reads_with_the_default_sslmode(clean_env, monkeypatch):
    monkeypatch.setenv("AGENTKIT_DB_URL", "postgresql://u@db.example.com:6432/d")
    assert resolve_setting(None).report()["url"] == {
        "user": "u", "host": "db.example.com", "port": "6432", "dbname": "d",
        "sslmode": "require"}


def test_a_url_libpq_cannot_parse_is_reported_without_its_text():
    report = Setting(url="postgresql://u:SEKRET@h/d?bogus=1").report()
    assert report["url"] == {"unparseable": True}
    assert "SEKRET" not in json.dumps(report)


def _libpq_reads(url: str) -> dict | None:
    from psycopg import Error
    from psycopg.conninfo import conninfo_to_dict

    try:
        return conninfo_to_dict(url)
    except (Error, ValueError):
        return None


def _assert_no_secret_shown(url: str, read: dict) -> bool:
    """Whether the URL carried a secret; every secret libpq reads from it is absent
    from the report, unless the report shows the same text as something else libpq
    reads, such as the host of an unencoded `pa@ss@host`, or as a key."""
    report = Setting(url=url, level="environment", sources=("AGENTKIT_DB_URL",)).report()
    shown = json.dumps(report, ensure_ascii=False)
    public = json.dumps({**report, "url": {k: v for k, v in report["url"].items()
                                           if k not in ("password", "sslpassword")}},
                        ensure_ascii=False) + ' "password" "sslpassword"'
    carried = False
    for key in ("password", "sslpassword"):
        if key in read:
            carried = True
            assert report["url"][key] == "***", url
            if read[key] and read[key] not in public:
                assert read[key] not in shown, url
    return carried


SHAPES = [
    "postgresql://u:pw@db.example.com/db?sslpassword=KEYPASS&password=QPASS",
    "postgresql://u@db.example.com/d?pass%77ord=ENCPASS",
    "postgresql://u@db.example.com/d?ssl%70assword=ENCKEY&sslmode=require",
    "postgresql://agent:pa#ss@db.example.com:5432/app",
    "postgresql://agent:pa?ss@db.example.com/app?sslmode=require",
    "postgresql://agent:pa@ss@db.example.com/app",
    "postgresql://agent@db.example.com/app?password=pa#ss&sslmode=require",
    "postgresql://agent@db.example.com/app#x?password=pa#ss",
    "postgresql://agent:pw@db.example.com:5432?sslpassword=k@y&password=QX",
    "postgresql://agent:pw@db.example.com:5432?application_name=a@b&password=QX",
    "postgresql://ag?ent@db.example.com/app?password=QX",
    "postgresql://ag?ent:pw@db.example.com/app?password=QX",
]


@pytest.mark.parametrize("url", SHAPES)
def test_the_report_hides_every_secret_libpq_reads_from_a_named_shape(url):
    read = _libpq_reads(url)
    assert read is not None
    assert _assert_no_secret_shown(url, read)


def _generated_urls(count: int, seed: int = 20261009):
    rng = random.Random(seed)
    specials = "#?@/&=:%,[]+ ;"

    def token(tag: str, n: int) -> str:
        chars = [rng.choice(specials + "abcXYZ019") for _ in range(rng.randint(0, 6))]
        chars.insert(rng.randint(0, len(chars)), f"{tag}{n:05d}")
        return "".join(chars)

    def maybe_encoded(text: str) -> str:
        return quote(text, safe="") if rng.random() < 0.25 else text

    for n in range(count):
        user = rng.choice(["agent", token("Us", n)])
        password = rng.choice(["", f":{maybe_encoded(token('Pw', n))}"])
        auth = rng.choice([f"{user}{password}@", f"{user}@", ""])
        host = rng.choice(["db.example.com", "127.0.0.1", "db.example.com:5432", ""])
        path = rng.choice(["/app", "", "/", f"/{token('Db', n)}"])
        params = []
        for _ in range(rng.randint(0, 3)):
            key = rng.choice(["password", "sslpassword", "pass%77ord", "ssl%70assword",
                              "PASSWORD", "application_name", "sslmode"])
            value = ("require" if key == "sslmode"
                     else maybe_encoded(token("Qv", n)))
            params.append(f"{key}={value}")
        query = f"?{'&'.join(params)}" if params else ""
        yield f"{rng.choice(['postgresql', 'postgres'])}://{auth}{host}{path}{query}"


def test_the_report_hides_every_secret_libpq_reads_across_a_generated_corpus():
    """Each generated URL libpq accepts, checked against libpq's own parse."""
    accepted = carried = 0
    for url in _generated_urls(6000):
        read = _libpq_reads(url)
        if read is None:
            continue
        accepted += 1
        carried += _assert_no_secret_shown(url, read)
    assert accepted > 1500 and carried > 1000, (accepted, carried)


# --- the machine file ------------------------------------------------------------

def test_the_machine_file_is_under_agentkit(clean_env, monkeypatch):
    assert setting_path() == clean_env / "agentkit" / "store.json"
    monkeypatch.delenv("XDG_CONFIG_HOME")
    monkeypatch.setenv("HOME", str(clean_env / "home"))
    assert setting_path() == clean_env / "home" / ".config" / "agentkit" / "store.json"
    assert setting_path().is_absolute()


def test_the_machine_file_names_its_schema_and_may_carry_no_password(clean_env):
    doc = {k: v for k, v in FAMILY.items() if k != "password"}
    write_family_setting(clean_env, {**doc, "db_schema": "shared_state", "port": "6543"})
    s = resolve_setting(None)
    assert (s.schema, s.password, s.port) == ("shared_state", None, 6543)
    assert "pw" not in repr(resolve_setting(None))


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "::1", "/var/run/postgresql"])
def test_sslmode_disable_is_admitted_in_the_file_for_a_local_host(clean_env, host):
    write_family_setting(clean_env, {**FAMILY, "host": host, "sslmode": "disable"})
    s = resolve_setting(None)
    assert s.host == host and s.sslmode == "disable"


@pytest.mark.parametrize("host,mode", [("db.example.test", "disable"),
                                       ("192.0.2.10", "disable"),
                                       ("localhost", "prefer"),
                                       ("localhost", "allow")])
def test_plain_text_is_refused_elsewhere_and_allow_prefer_everywhere(clean_env, host, mode):
    write_family_setting(clean_env, {**FAMILY, "host": host, "sslmode": mode})
    assert _refused(None).slug == "sslmode_too_weak"


def test_a_newer_machine_file_version_is_refused(clean_env):
    write_family_setting(clean_env, {**FAMILY, "schema": "agentkit.store.v2", "extra": 1})
    err = _refused(None)
    assert err.slug == "store_setting_too_new" and "update" in err.hint


@pytest.mark.parametrize("document", [
    {**FAMILY, "at": "2026-10-08T00:00:00Z"},
    {**FAMILY, "schema": "capabilities.store.v1"},
    {k: v for k, v in FAMILY.items() if k != "schema"},
    {k: v for k, v in FAMILY.items() if k != "sslmode"},
    {**FAMILY, "password": 5},
    {**FAMILY, "password": "a\nb"},
    {**FAMILY, "db_schema": "public"},
    {**FAMILY, "db_schema": "pg_catalog"},
    {k: v for k, v in FAMILY.items() if k != "host"},
    {**FAMILY, "port": True},
    {**FAMILY, "port": 70000},
    {**FAMILY, "sslrootcert": ""},
    "not json",
    [1],
])
def test_a_malformed_machine_file_is_refused(clean_env, document):
    write_family_setting(clean_env, document)
    assert _refused(None).slug in ("bad_store_setting", "bad_schema_name")


# --- not configured --------------------------------------------------------------

def test_nothing_configured_is_store_not_configured_and_creates_nothing(clean_env, project):
    err = _refused(project)
    assert err.slug == "store_not_configured"
    assert "AGENTKIT_DB_URL" in err.hint and "capabilities store set" in err.hint
    assert list(clean_env.rglob("*")) == [] and list(project.rglob("*")) == []


def test_connect_without_a_setting_is_store_not_configured_and_creates_nothing(clean_env,
                                                                              project):
    from capabilities_contract.db import connect
    with pytest.raises(DbError) as caught:
        connect(application_name="test", project_root=project)
    assert caught.value.slug == "store_not_configured"
    assert list(clean_env.rglob("*")) == []


# --- parity with the manager's own store tier, when it is on this machine ---------

# The manager's own store tier (its contract/store.py), named explicitly; without it
# the parity tests skip.
STORE_TIER_ENV = "CAPABILITIES_STORE_TIER"


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
def test_the_machine_file_reads_as_the_store_tier_reads_it(tier, clean_env, monkeypatch,
                                                           document):
    for name in ("AGENTKIT_STORE_URL", "CAPABILITIES_STORE_URL"):
        monkeypatch.delenv(name, raising=False)
    write_family_setting(clean_env, document)
    try:
        theirs = tier.read_store_setting()
        their_error = None
    except tier.StoreError as exc:
        theirs, their_error = None, exc.slug
    try:
        ours = resolve_setting(None)
        our_error = None
    except DbError as exc:
        ours, our_error = None, exc.slug
    assert our_error == their_error
    if theirs is not None:
        ours_values = {k: getattr(ours, k) for k in theirs if k != "db_schema"}
        assert ours_values == {k: v for k, v in theirs.items() if k != "db_schema"}
        assert ours.schema == theirs["db_schema"]


def test_import_does_not_load_the_driver():
    """A fresh interpreter importing the module leaves psycopg unloaded."""
    code = ("import sys, capabilities_contract.db as db; "
            "assert db.connect and db.migrate and db.resolve_setting; "
            "print('psycopg' in sys.modules, any(m.startswith('psycopg') for m in sys.modules))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         check=True).stdout.split()
    assert out == ["False", "False"]
