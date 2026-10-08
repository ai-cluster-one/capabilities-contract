"""The machine's store setting, read exactly as the manager's store tier reads it.

The setting is one file shared by every tool of the family on the machine:
`$XDG_CONFIG_HOME/agentkit/store.json`, or `~/.config/agentkit/store.json` when
`XDG_CONFIG_HOME` is unset, an `agentkit.store.v1` document holding the connection
values and the password. Its format is the capabilities package's SHEBANG.md, "The
store setting". This module reads it and writes nothing. `AGENTKIT_STORE_URL`, then
`CAPABILITIES_STORE_URL`, when set, is the store in force and wins over the setting.

While the file is absent the setting is read from the legacy pair the manager wrote
before: the non-secret values in `$XDG_CONFIG_HOME/capabilities/store.json`
(`capabilities.store.v1`, binding `agentkit`, or `capabilities.store.v2`, which may
name `db_schema`) and the password as `CAPABILITIES_STORE_PASSWORD` in
`$XDG_CONFIG_HOME/capabilities/credentials.env`.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from capabilities_contract.db._errors import DbError

SETTING_FORMAT = "agentkit.store.v1"
SETTING_FORMAT_PREFIX = "agentkit.store."
SETTING_SCHEMA_V1 = "capabilities.store.v1"
SETTING_SCHEMA_V2 = "capabilities.store.v2"
SETTING_SCHEMAS = (SETTING_SCHEMA_V1, SETTING_SCHEMA_V2)
PASSWORD_KEY = "CAPABILITIES_STORE_PASSWORD"
URL_ENVS = ("AGENTKIT_STORE_URL", "CAPABILITIES_STORE_URL")
URL_ENV = "CAPABILITIES_STORE_URL"
SSLMODES = ("require", "verify-ca", "verify-full")
SSLMODES_REFUSED = ("disable", "allow", "prefer")
SSLMODE_LOCAL = "disable"
SETTING_FIELDS = ("host", "port", "database", "user", "sslmode", "sslrootcert")
SCHEMA_FIELD = "db_schema"
FORMAT_FIELDS = ("schema", *SETTING_FIELDS, "password", SCHEMA_FIELD)
DEFAULT_SCHEMA = "agentkit"

_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]{0,62}")
_SYSTEM_SCHEMAS = ("public", "information_schema")

NOT_CONFIGURED_HINT = "run capabilities store set"


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


@dataclass(frozen=True)
class Setting:
    """Where the store is and which schema it binds.

    Either `url` (from `AGENTKIT_STORE_URL` or `CAPABILITIES_STORE_URL`) or the host
    fields are set. `source` is the override's name or the absolute path of the file
    the setting was read from. The password and URL are never shown in the repr."""

    schema: str = DEFAULT_SCHEMA
    source: str = ""
    url: str | None = field(default=None, repr=False)
    host: str | None = None
    port: int | None = None
    database: str | None = None
    user: str | None = None
    sslmode: str | None = None
    sslrootcert: str | None = None
    password: str | None = field(default=None, repr=False)

    def connect_kwargs(self) -> dict:
        """Arguments for `psycopg.connect`: a conninfo string, or keyword values."""
        if self.url is not None:
            return {"conninfo": self.url}
        out = {"host": self.host, "port": self.port, "dbname": self.database,
               "user": self.user, "sslmode": self.sslmode}
        if self.sslrootcert:
            out["sslrootcert"] = self.sslrootcert
        if self.password:
            out["password"] = self.password
        return out


def _config_home(config_home: Path | str | None) -> Path:
    return Path(os.path.abspath(config_home or os.environ.get("XDG_CONFIG_HOME")
                                or os.path.join(os.path.expanduser("~"), ".config")))


def setting_path(config_home: Path | str | None = None) -> Path:
    """The family's store setting file, as an absolute path."""
    return _config_home(config_home) / "agentkit" / "store.json"


def setting_files(config_home: Path | str | None = None) -> tuple[Path, Path]:
    """The legacy setting file and password file, in that order."""
    home = _config_home(config_home)
    return (home / "capabilities" / "store.json",
            home / "capabilities" / "credentials.env")


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


def check_setting(values: dict) -> dict:
    """The setting's non-secret values, checked and normalised, or DbError. The same
    rules as the manager's store tier: no unknown field, host/database/user without
    whitespace, port 1-65535, sslmode at least `require`, or `disable` for a local
    host."""
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
    port = values.get("port", 5432)
    if isinstance(port, str) and port.isdigit():
        port = int(port)
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        raise DbError("bad_store_setting", "the store port must be 1-65535")
    out["port"] = port
    sslmode = values.get("sslmode")
    local = sslmode == SSLMODE_LOCAL and host_is_local(out["host"])
    if sslmode in SSLMODES_REFUSED and not local:
        raise DbError("sslmode_too_weak",
                      f"sslmode {sslmode!r} lets the store be reached without TLS",
                      f"use one of {', '.join(SSLMODES)}; disable is admitted only "
                      "for a local host or Unix socket")
    if sslmode not in SSLMODES and not local:
        raise DbError("bad_store_setting", f"unknown sslmode {sslmode!r}",
                      f"use one of {', '.join(SSLMODES)}")
    out["sslmode"] = sslmode
    root = values.get("sslrootcert")
    if root is not None:
        if not isinstance(root, str) or not root or "\n" in root:
            raise DbError("bad_store_setting",
                          "sslrootcert must be a certificate file path or `system`")
        out["sslrootcert"] = root
    return out


def read_setting(config_home: Path | str | None = None) -> Setting:
    """The store in force on this machine.

    `AGENTKIT_STORE_URL`, then `CAPABILITIES_STORE_URL`, then the family's setting
    file, then, while that file is absent, the legacy pair. With none of them, raises
    DbError `store_not_configured`. Reads only; never creates a file."""
    for name in URL_ENVS:
        url = os.environ.get(name)
        if url:
            scheme = urlparse(url).scheme
            if scheme not in ("postgres", "postgresql"):
                raise DbError("store_not_postgres",
                              f"{name} names a {scheme or 'file'} store, not Postgres",
                              f"point {name} at a postgresql:// URL or unset it")
            return Setting(url=url, schema=DEFAULT_SCHEMA, source=name)
    path = setting_path(config_home)
    try:
        raw = path.read_text()
    except FileNotFoundError:
        return _read_legacy(config_home)
    except OSError as exc:
        raise DbError("store_setting_unreadable",
                      f"cannot read the store setting {path}: {exc}") from exc
    return _read_family(path, raw)


def _read_family(path: Path, raw: str) -> Setting:
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
    return Setting(schema=schema, source=str(path), password=password or None, **values)


def _read_legacy(config_home: Path | str | None) -> Setting:
    setting_file, password_file = setting_files(config_home)
    try:
        raw = setting_file.read_text()
    except FileNotFoundError:
        raise DbError("store_not_configured", "this machine has no store setting",
                      NOT_CONFIGURED_HINT) from None
    except OSError as exc:
        raise DbError("store_setting_unreadable",
                      f"cannot read the store setting {setting_file}: {exc}") from exc
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise DbError("bad_store_setting", f"{setting_file} is not a store setting",
                      "rewrite it with `capabilities store set`") from exc
    if not isinstance(data, dict) or data.get("schema") not in SETTING_SCHEMAS:
        raise DbError("bad_store_setting",
                      f"{setting_file} is not a {' or '.join(SETTING_SCHEMAS)} setting",
                      "rewrite it with `capabilities store set`")
    values = check_setting({k: v for k, v in data.items() if k in SETTING_FIELDS})
    schema = DEFAULT_SCHEMA
    if data["schema"] == SETTING_SCHEMA_V2 and data.get(SCHEMA_FIELD) is not None:
        schema = check_schema_name(data[SCHEMA_FIELD])
    password = None
    try:
        lines = password_file.read_text().splitlines()
    except FileNotFoundError:
        lines = []
    except OSError as exc:
        raise DbError("store_setting_unreadable",
                      f"cannot read the store password file {password_file}: {exc}") from exc
    prefix = PASSWORD_KEY + "="
    for line in lines:
        if line.startswith(prefix):
            password = line[len(prefix):] or None
    return Setting(schema=schema, source=str(setting_file), password=password, **values)
