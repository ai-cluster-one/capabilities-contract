"""Which database a project uses, resolved through one cascade.

Three levels are asked in order, and the first that answers is the setting in force;
a level is never completed from a lower one:

1. `project` - the `AGENTKIT_DB_*` keys in the project's `.env.local` and `.env`,
   `.env.local` winning key by key;
2. `environment` - the same keys in the process environment;
3. `machine` - the machine's store setting file, `$XDG_CONFIG_HOME/agentkit/store.json`
   (`~/.config/agentkit/store.json` when `XDG_CONFIG_HOME` is unset), an
   `agentkit.store.v1` document whose format is the capabilities package's SHEBANG.md,
   "The store setting".

Within one level `AGENTKIT_DB_URL` wins and that level's separate fields are ignored,
except `AGENTKIT_DB_SCHEMA`, which applies beside a URL. This module reads and writes
nothing else.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlunparse

from capabilities_contract.db._errors import DbError

SETTING_FORMAT = "agentkit.store.v1"
SETTING_FORMAT_PREFIX = "agentkit.store."
SSLMODES = ("require", "verify-ca", "verify-full")
SSLMODES_REFUSED = ("disable", "allow", "prefer")
SSLMODE_LOCAL = "disable"
SETTING_FIELDS = ("host", "port", "database", "user", "sslmode", "sslrootcert")
SCHEMA_FIELD = "db_schema"
FORMAT_FIELDS = ("schema", *SETTING_FIELDS, "password", SCHEMA_FIELD)
DEFAULT_SCHEMA = "agentkit"
DEFAULT_PORT = 5432
DEFAULT_SSLMODE = "require"

KEY_PREFIX = "AGENTKIT_DB_"
URL_KEY = "AGENTKIT_DB_URL"
SCHEMA_KEY = "AGENTKIT_DB_SCHEMA"
PASSWORD_KEY = "AGENTKIT_DB_PASSWORD"
# The separate fields, each key with the setting field it fills.
FIELD_KEYS = {
    "AGENTKIT_DB_HOST": "host",
    "AGENTKIT_DB_PORT": "port",
    "AGENTKIT_DB_NAME": "database",
    "AGENTKIT_DB_USER": "user",
    "AGENTKIT_DB_SSLMODE": "sslmode",
    "AGENTKIT_DB_SSLROOTCERT": "sslrootcert",
}
KEYS = (URL_KEY, *FIELD_KEYS, PASSWORD_KEY, SCHEMA_KEY)

LEVELS = ("project", "environment", "machine")
PROJECT_FILES = (".env.local", ".env")

NOT_CONFIGURED_HINT = ("set AGENTKIT_DB_URL or the AGENTKIT_DB_* fields in the project's "
                       ".env.local or the process environment, or run capabilities store set")

_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]{0,62}")
_SYSTEM_SCHEMAS = ("public", "information_schema")
_REDACTED = "***"


def check_schema_name(name: object) -> str:
    """A schema name the library may bind: a lowercase identifier, never `public`
    and never a system schema."""
    if not isinstance(name, str) or not _IDENTIFIER.fullmatch(name):
        raise DbError("bad_schema_name",
                      f"schema name {name!r} is not a lowercase identifier",
                      "use letters, digits and underscores, starting with a letter or _")
    if name in _SYSTEM_SCHEMAS or name.startswith("pg_"):
        raise DbError("bad_schema_name", f"schema {name!r} is reserved",
                      "name a schema of the store's own, such as agentkit")
    return name


def redact_url(url: str) -> str:
    """The URL with any password, in the authority or the query, replaced."""
    parsed = urlparse(url)
    netloc = parsed.netloc
    if parsed.password is not None:
        userinfo, _, hostport = netloc.rpartition("@")
        user = userinfo.split(":", 1)[0]
        netloc = f"{user}:{_REDACTED}@{hostport}"
    query = re.sub(r"(^|&)(password=)[^&]*", rf"\g<1>\g<2>{_REDACTED}", parsed.query)
    return urlunparse(parsed._replace(netloc=netloc, query=query))


@dataclass(frozen=True)
class Setting:
    """Where the database is, which schema it binds, and where that was found.

    Either `url` or the host fields are set. `level` is `project`, `environment` or
    `machine`; `sources` names every file (an absolute path) or variable that supplied
    a value in force. The password and URL are never shown in the repr; `report()`
    gives the whole setting with its secrets redacted."""

    schema: str = DEFAULT_SCHEMA
    level: str = ""
    sources: tuple[str, ...] = ()
    url: str | None = field(default=None, repr=False)
    host: str | None = None
    port: int | None = None
    database: str | None = None
    user: str | None = None
    sslmode: str | None = None
    sslrootcert: str | None = None
    password: str | None = field(default=None, repr=False)

    def connect_kwargs(self) -> dict:
        """Arguments for `psycopg.connect`: a conninfo string, or keyword values. A URL
        that names no sslmode is given `require`."""
        if self.url is not None:
            out = {"conninfo": self.url}
            if "sslmode" not in parse_qs(urlparse(self.url).query):
                out["sslmode"] = DEFAULT_SSLMODE
            return out
        out = {"host": self.host, "port": self.port, "dbname": self.database,
               "user": self.user, "sslmode": self.sslmode}
        if self.sslrootcert:
            out["sslrootcert"] = self.sslrootcert
        if self.password:
            out["password"] = self.password
        return out

    def report(self) -> dict:
        """The setting in force for a status or doctor surface, secrets redacted."""
        out = {"level": self.level, "sources": list(self.sources), "schema": self.schema}
        if self.url is not None:
            out["url"] = redact_url(self.url)
            return out
        out.update(host=self.host, port=self.port, database=self.database, user=self.user,
                   sslmode=self.sslmode, sslrootcert=self.sslrootcert,
                   password=_REDACTED if self.password else None)
        return out


def _config_home(config_home: Path | str | None) -> Path:
    return Path(os.path.abspath(config_home or os.environ.get("XDG_CONFIG_HOME")
                                or os.path.join(os.path.expanduser("~"), ".config")))


def setting_path(config_home: Path | str | None = None) -> Path:
    """The machine's store setting file, as an absolute path."""
    return _config_home(config_home) / "agentkit" / "store.json"


def host_is_local(host: object) -> bool:
    """Whether the host is this machine: a Unix socket directory, `localhost`, or a
    loopback address."""
    if not isinstance(host, str) or not host:
        return False
    if host.startswith("/") or host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _check_sslmode(sslmode: object, local: bool) -> None:
    if sslmode in SSLMODES or (sslmode == SSLMODE_LOCAL and local):
        return
    if sslmode in SSLMODES_REFUSED:
        raise DbError("sslmode_too_weak",
                      f"sslmode {sslmode!r} lets the store be reached without TLS",
                      f"use one of {', '.join(SSLMODES)}; disable is admitted only "
                      "for a local host or Unix socket")
    raise DbError("bad_store_setting", f"unknown sslmode {sslmode!r}",
                  f"use one of {', '.join(SSLMODES)}")


def check_setting(values: dict) -> dict:
    """The setting's non-secret values, checked and normalised, or DbError: no unknown
    field, host/database/user without whitespace, port 1-65535, sslmode at least
    `require`, or `disable` for a local host."""
    if not isinstance(values, dict):
        raise DbError("bad_store_setting", "the store setting is not an object")
    unknown = sorted(set(values) - set(SETTING_FIELDS))
    if unknown:
        raise DbError("bad_store_setting",
                      f"the store setting carries unknown fields: {', '.join(unknown)}")
    out: dict = {}
    for name in ("host", "database", "user"):
        value = values.get(name)
        if not isinstance(value, str) or not value or any(
                ch.isspace() or ch == "\0" for ch in value):
            raise DbError("bad_store_setting",
                          f"the store setting needs a {name} with no whitespace")
        out[name] = value
    port = values.get("port", DEFAULT_PORT)
    if isinstance(port, str) and port.isdigit():
        port = int(port)
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        raise DbError("bad_store_setting", "the store port must be 1-65535")
    out["port"] = port
    sslmode = values.get("sslmode")
    _check_sslmode(sslmode, host_is_local(out["host"]))
    out["sslmode"] = sslmode
    root = values.get("sslrootcert")
    if root is not None:
        if not isinstance(root, str) or not root or "\n" in root:
            raise DbError("bad_store_setting",
                          "sslrootcert must be a certificate file path or `system`")
        out["sslrootcert"] = root
    return out


def check_url(url: str) -> str:
    """A PostgreSQL URL whose sslmode, when it names one, holds to the TLS rule."""
    parsed = urlparse(url)
    if parsed.scheme not in ("postgres", "postgresql"):
        raise DbError("store_not_postgres",
                      f"{URL_KEY} names a {parsed.scheme or 'file'} store, not PostgreSQL",
                      f"point {URL_KEY} at a postgresql:// URL")
    query = parse_qs(parsed.query)
    host = (query.get("host") or [parsed.hostname])[-1]
    sslmode = (query.get("sslmode") or [DEFAULT_SSLMODE])[-1]
    _check_sslmode(sslmode, host is None or host_is_local(host))
    return url


def _read_env_file(path: Path) -> dict:
    """The `AGENTKIT_DB_*` keys of a KEY=VALUE env file, parsed as the contract's
    credential cascade parses one. A missing file holds none."""
    try:
        text = path.read_text()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise DbError("store_setting_unreadable", f"cannot read {path}: {exc}") from exc
    out: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        if key.startswith(KEY_PREFIX):
            out[key] = value.strip().strip('"').strip("'")
    return out


def _project_values(project_root: Path | str) -> dict[str, tuple[str, str]]:
    """Each key the project's env files set, with the file it came from."""
    root = Path(os.path.abspath(project_root))
    found: dict[str, tuple[str, str]] = {}
    for name in reversed(PROJECT_FILES):  # .env first, so .env.local wins
        path = root / name
        for key, value in _read_env_file(path).items():
            if value:
                found[key] = (value, str(path))
    return found


def _environment_values() -> dict[str, tuple[str, str]]:
    return {key: (os.environ[key], key) for key in KEYS if os.environ.get(key)}


def _from_keys(level: str, found: dict[str, tuple[str, str]]) -> Setting:
    """The setting one level's keys describe, never completed from another level."""
    unknown = sorted(key for key in found if key not in KEYS)
    if unknown:
        raise DbError("bad_store_setting",
                      f"the {level} level sets keys the database setting does not have: "
                      f"{', '.join(unknown)} ({_where(found, unknown)})",
                      f"use only {', '.join(KEYS)}")
    used = [URL_KEY, SCHEMA_KEY] if URL_KEY in found else list(found)
    used = [key for key in used if key in found]
    try:
        schema = check_schema_name(found[SCHEMA_KEY][0]) if SCHEMA_KEY in found \
            else DEFAULT_SCHEMA
        if URL_KEY in found:
            return Setting(schema=schema, level=level, sources=_sources(found, used),
                           url=check_url(found[URL_KEY][0]))
        values = {name: found[key][0] for key, name in FIELD_KEYS.items() if key in found}
        values.setdefault("sslmode", DEFAULT_SSLMODE)
        password = found[PASSWORD_KEY][0] if PASSWORD_KEY in found else None
        return Setting(schema=schema, level=level, sources=_sources(found, used),
                       password=password, **check_setting(values))
    except DbError as exc:
        raise DbError(exc.slug, f"the {level} level ({_where(found, used)}): {exc.message}",
                      exc.hint) from None


def _sources(found: dict[str, tuple[str, str]], keys: list[str]) -> tuple[str, ...]:
    out: list[str] = []
    for key in keys:
        if found[key][1] not in out:
            out.append(found[key][1])
    return tuple(out)


def _where(found: dict[str, tuple[str, str]], keys: list[str]) -> str:
    return ", ".join(_sources(found, keys))


def resolve_setting(project_root: Path | str | None, *,
                    config_home: Path | str | None = None) -> Setting:
    """The database setting in force for a process standing in `project_root`.

    The project's `.env.local` / `.env`, then the process environment, then the
    machine's store setting file; the first level that sets any `AGENTKIT_DB_*` key,
    or the machine level when its file exists, answers whole. `project_root` None
    means the process stands in no project, so the project level is not asked. With
    no level answering, raises DbError `store_not_configured`. Reads only; never
    creates a file."""
    if project_root is not None:
        found = _project_values(project_root)
        if found:
            return _from_keys("project", found)
    found = _environment_values()
    if found:
        return _from_keys("environment", found)
    path = setting_path(config_home)
    try:
        raw = path.read_text()
    except FileNotFoundError:
        raise DbError("store_not_configured",
                      "no database is configured for this project or this machine",
                      NOT_CONFIGURED_HINT) from None
    except OSError as exc:
        raise DbError("store_setting_unreadable",
                      f"cannot read the store setting {path}: {exc}") from exc
    return _read_machine_file(path, raw)


def _read_machine_file(path: Path, raw: str) -> Setting:
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise DbError("bad_store_setting", f"{path} is not a store setting",
                      "rewrite it with `capabilities store set`") from exc
    version = data.get("schema") if isinstance(data, dict) else None
    if isinstance(version, str) and version.startswith(SETTING_FORMAT_PREFIX) \
            and version != SETTING_FORMAT:
        raise DbError("store_setting_too_new",
                      f"{path} is a {version} setting, which this library does not know",
                      "update the tool that uses it; the setting was written by a newer one")
    if version != SETTING_FORMAT:
        raise DbError("bad_store_setting", f"{path} is not a {SETTING_FORMAT} setting",
                      "rewrite it with `capabilities store set`")
    unknown = sorted(set(data) - set(FORMAT_FIELDS))
    if unknown:
        raise DbError("bad_store_setting",
                      f"{path} carries fields {SETTING_FORMAT} does not have: "
                      f"{', '.join(unknown)}",
                      "rewrite it with `capabilities store set`")
    values = check_setting({k: v for k, v in data.items() if k in SETTING_FIELDS})
    schema = DEFAULT_SCHEMA
    if data.get(SCHEMA_FIELD) is not None:
        schema = check_schema_name(data[SCHEMA_FIELD])
    password = data.get("password")
    if password is not None and (not isinstance(password, str) or "\n" in password):
        raise DbError("bad_store_setting", f"{path} carries a password that is not one line")
    return Setting(schema=schema, level="machine", sources=(str(path),),
                   password=password or None, **values)
