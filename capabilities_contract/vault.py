"""An agent's vault: named secrets kept in the store, sealed with the agent's own key.

Every agent has one encryption key, `AGENT_ENCRYPTION_KEY`, held in its environment
and never in the store: on a Mac its folder's `.env.local`, on a node its environment
or the node's machine file `$XDG_CONFIG_HOME/capabilities/shared.env`. Each secret is
a row of `capabilities_vault` - the agent, the name, the sealed value and the
fingerprint of the key that sealed it - and the agent's row in `capabilities_agents`
keeps the fingerprint of its key in `vault_key`, never the key.

A value is sealed with XChaCha20-Poly1305 (libsodium, through PyNaCl), a fresh random
nonce each time, the agent id and the name bound as associated data, so a sealed value
moved to another agent or another name does not open. A row sealed under a key other
than the agent's present one is unreadable: it is kept and reported, and is set again
to be read.

`Reader` is how a process resolves vault values: it reads the agent's sealed rows and
the vault's channel version in one round trip (or is handed them by the round trip that
reads the agent's connections), opens only the names asked for, keeps what it opened in
process memory only, and, asked again after `CHECK_SECONDS`, reads the channel version
and rereads the rows only when it moved, so a long-running process sees a changed
secret within about a second and without a restart.

Importing this module imports neither psycopg nor PyNaCl; each is imported on use.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets as _secrets
import time
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from capabilities_contract.db._errors import DbError

KEY_ENV = "AGENT_ENCRYPTION_KEY"
VAULT_TABLE = "capabilities_vault"
VAULT_CHANNEL = "capabilities_vault"
KEY_BYTES = 32
NONCE_BYTES = 24
# The first byte of every sealed value: the format it is sealed in.
SEALED_FORMAT = 1
NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,254}")
FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}")
# How long a reader trusts what it read before it asks the channel again.
CHECK_SECONDS = 1.0
# How long a store that could not be read stands refused, so one command that
# asks for several names waits on it once.
RETRY_SECONDS = 2.0

_AAD_PREFIX = b"capabilities-vault/v1\0"
_FINGERPRINT_PREFIX = b"capabilities-vault-key/v1\0"


class VaultError(DbError):
    """A vault refusal: `slug` names it, as the database library's errors do."""


def _nacl() -> Any:
    try:
        from nacl import bindings
    except ImportError as exc:
        raise VaultError("vault_driver_missing",
                         f"PyNaCl, which seals the vault, cannot be loaded: {exc}",
                         "reinstall capabilities-contract, which depends on it") from None
    return bindings


# --- The key ---------------------------------------------------------------------


def generate_key() -> str:
    """A new key as its text: 32 random bytes, URL-safe base64 without padding."""
    return encode_key(_secrets.token_bytes(KEY_BYTES))


def encode_key(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).decode("ascii").rstrip("=")


def parse_key(text: str) -> bytes:
    """The key `text` holds, or VaultError `bad_key`. Never echoes the text."""
    if not isinstance(text, str):
        raise VaultError("bad_key", f"{KEY_ENV} is not text")
    raw = text.strip()
    try:
        key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except (ValueError, TypeError):
        key = b""
    if len(key) != KEY_BYTES or encode_key(key) != raw.rstrip("="):
        raise VaultError("bad_key",
                         f"{KEY_ENV} is not a key: it is {KEY_BYTES} bytes in URL-safe "
                         "base64 (43 characters)",
                         "`capabilities key generate` makes one")
    return key


def fingerprint(key: bytes) -> str:
    """What the store keeps of a key: a SHA-256 over it, as lowercase hex."""
    return hashlib.sha256(_FINGERPRINT_PREFIX + key).hexdigest()


def shared_env_path() -> Path:
    """The machine's file of shared values, where a node keeps its agent's key."""
    home = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(home) / "capabilities" / "shared.env"


def _env_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        text = path.read_text()
    except (OSError, UnicodeDecodeError):
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        if name.startswith("export "):
            name = name[len("export "):].strip()
        out[name] = value.strip().strip('"').strip("'")
    return out


def key_source(project_root: Path | str | None) -> tuple[str | None, str | None]:
    """(the key's text, where it was found) for a process standing in
    `project_root`, or (None, None): the project's `.env.local`, then its `.env`,
    then the machine's `shared.env`, then the process environment - the
    credential cascade's order. The text is not checked here."""
    places: list[Path] = []
    if project_root is not None:
        places += [Path(project_root) / ".env.local", Path(project_root) / ".env"]
    places.append(shared_env_path())
    for path in places:
        value = _env_file(path).get(KEY_ENV)
        if value:
            return value, str(path)
    value = os.environ.get(KEY_ENV)
    if value:
        return value, "env"
    return None, None


def agent_key(project_root: Path | str | None) -> bytes | None:
    """The agent's key where one is set, None where none is, VaultError
    `bad_key` where what is set is not a key."""
    text, _where = key_source(project_root)
    return parse_key(text) if text else None


# --- Sealing ---------------------------------------------------------------------


def check_name(name: object) -> str:
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise VaultError("bad_secret_name",
                         f"a secret's name is an environment variable name, not {name!r}",
                         "letters, digits and '_', not starting with a digit")
    return name


def _aad(agent_id: str, name: str) -> bytes:
    return _AAD_PREFIX + agent_id.encode() + b"\0" + name.encode()


def seal(key: bytes, agent_id: str, name: str, value: str) -> bytes:
    """`value` sealed for `name` of `agent_id`: the format byte, the nonce, then
    the ciphertext with its tag."""
    nacl = _nacl()
    nonce = _secrets.token_bytes(NONCE_BYTES)
    sealed = nacl.crypto_aead_xchacha20poly1305_ietf_encrypt(
        value.encode("utf-8"), _aad(agent_id, check_name(name)), nonce, key)
    return bytes([SEALED_FORMAT]) + nonce + sealed


def unseal(key: bytes, agent_id: str, name: str, blob: bytes) -> str | None:
    """The value `blob` holds, or None where it does not open under `key` for
    this agent and name."""
    blob = bytes(blob)
    if len(blob) < 1 + NONCE_BYTES or blob[0] != SEALED_FORMAT:
        return None
    nacl = _nacl()
    nonce, sealed = blob[1:1 + NONCE_BYTES], blob[1 + NONCE_BYTES:]
    try:
        plain = nacl.crypto_aead_xchacha20poly1305_ietf_decrypt(
            sealed, _aad(agent_id, name), nonce, key)
    except Exception:  # nacl.exceptions.CryptoError: the tag does not verify
        return None
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError:
        return None


# --- The store -------------------------------------------------------------------


ROWS_QUERY = ("SELECT name, ciphertext, key_fingerprint, updated_at, updated_by "
              "FROM capabilities_vault WHERE agent_id = %s ORDER BY name")
VERSION_QUERY = "SELECT version FROM schema_channel WHERE channel = %s AND scope = %s"
KEY_QUERY = "SELECT vault_key FROM capabilities_agents WHERE id = %s"


def round_trip(agent_id: str) -> list[tuple[str, tuple]]:
    """The statements a reader is seeded from, to send beside others: the
    agent's sealed rows, then the vault's channel version for it."""
    return [(ROWS_QUERY, (agent_id,)), (VERSION_QUERY, (VAULT_CHANNEL, agent_id))]


def rows(conn: Any, agent_id: str) -> list[dict[str, Any]]:
    """Every row of the agent's vault, sealed, in name order."""
    return [{"name": name, "ciphertext": bytes(blob), "key_fingerprint": fp,
             "updated_at": at, "updated_by": by}
            for name, blob, fp, at, by in conn.execute(ROWS_QUERY, (agent_id,)).fetchall()]


def recorded_key(conn: Any, agent_id: str) -> tuple[bool, str | None]:
    """(whether the agent has a registry row, the fingerprint of the key it
    keeps its vault under, None where none is recorded)."""
    found = conn.execute(KEY_QUERY, (agent_id,)).fetchall()
    return (bool(found), found[0][0] if found else None)


def record_key(conn: Any, agent_id: str, key_fingerprint: str) -> None:
    conn.execute("UPDATE capabilities_agents SET vault_key = %s, updated_at = now() "
                 "WHERE id = %s", (key_fingerprint, agent_id))


def put(conn: Any, key: bytes, agent_id: str, name: str, value: str,
        updated_by: str | None = None) -> None:
    """Seal `value` under `key` and keep it as `name`, replacing what was there."""
    conn.execute(
        "INSERT INTO capabilities_vault (agent_id, name, ciphertext, key_fingerprint, "
        "updated_by) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (agent_id, name) DO UPDATE "
        "SET ciphertext = excluded.ciphertext, key_fingerprint = excluded.key_fingerprint, "
        "updated_at = now(), updated_by = excluded.updated_by",
        (agent_id, check_name(name), seal(key, agent_id, name, value),
         fingerprint(key), updated_by))


def remove(conn: Any, agent_id: str, names: Iterable[str]) -> list[str]:
    """Remove the named rows, which needs no key; the names that were there."""
    wanted = [check_name(n) for n in names]
    found = conn.execute(
        "DELETE FROM capabilities_vault WHERE agent_id = %s AND name = ANY(%s) "
        "RETURNING name", (agent_id, wanted)).fetchall()
    return sorted(name for (name,) in found)


def sealed_under_other(conn: Any, agent_id: str, key_fingerprint: str) -> int:
    """How many of the agent's rows were sealed under another key."""
    return conn.execute(
        "SELECT count(*) FROM capabilities_vault WHERE agent_id = %s "
        "AND key_fingerprint <> %s", (agent_id, key_fingerprint)).fetchone()[0]


# --- Reading in a process --------------------------------------------------------


class Reader:
    """The agent's vault as one process reads it: sealed rows and the channel
    version they were read at, the values opened so far kept in memory only."""

    def __init__(self, agent_id: str, key: bytes, *, project_root: Path | str | None,
                 application_name: str):
        self.agent_id = agent_id
        self._key = key
        self.key_fingerprint = fingerprint(key)
        self._project_root = project_root
        self._application_name = application_name
        self._sealed: dict[str, tuple[bytes, str]] | None = None
        self._version: int | None = None
        self._checked = 0.0
        self._opened: dict[str, tuple[bytes, str | None]] = {}
        self.problem: str | None = None
        self._failure: VaultError | None = None
        self._failed_at = 0.0

    @property
    def loaded(self) -> bool:
        return self._sealed is not None

    def seed(self, found_rows: Iterable[Any], found_version: Iterable[Any]) -> None:
        """Take the rows and the version `round_trip` read, in that order."""
        sealed = {}
        for row in found_rows:
            name, blob, fp = row[0], row[1], row[2]
            sealed[name] = (bytes(blob), fp)
        self._sealed = sealed
        versions = [row[0] for row in found_version]
        self._version = versions[0] if versions else 0
        self._checked = time.monotonic()
        self.problem = None
        self._failure = None

    def _connect(self) -> Any:
        from capabilities_contract import db
        return db.connect(application_name=self._application_name,
                          project_root=self._project_root, transaction=True)

    def _unreadable(self, exc: BaseException) -> VaultError:
        message = getattr(exc, "message", None) or str(exc)
        self.problem = f"the vault could not be read: {message}"
        self._failure = VaultError("vault_unreadable", self.problem,
                                   "check the database setting with "
                                   "`capabilities store doctor`")
        self._failed_at = time.monotonic()
        return self._failure

    def _refresh(self) -> None:
        """Load the rows where none are held; else, once CHECK_SECONDS have
        passed, ask the channel and reload only when it moved. A store that
        cannot be read on a re-check leaves what was read in place, asked again
        after RETRY_SECONDS, so a running process keeps the values it has
        through a passing outage; only a reader that never read refuses."""
        if self._sealed is not None and time.monotonic() - self._checked < CHECK_SECONDS:
            return
        if self._sealed is not None:
            try:
                self._load()
            except VaultError:
                self._checked = time.monotonic() - CHECK_SECONDS + RETRY_SECONDS
            return
        self._load()

    def _load(self) -> None:
        if self._failure is not None:
            if time.monotonic() - self._failed_at < RETRY_SECONDS:
                raise self._failure
            self._failure = None
        from capabilities_contract import db
        try:
            import psycopg
        except ImportError as exc:
            raise self._unreadable(exc) from None
        try:
            with self._connect() as conn:
                if self._sealed is not None:
                    found = conn.execute(VERSION_QUERY,
                                         (VAULT_CHANNEL, self.agent_id)).fetchall()
                    version = found[0][0] if found else 0
                    if version == self._version:
                        self._checked = time.monotonic()
                        return
                statements = round_trip(self.agent_id)
                try:
                    found_rows, found_version = db.batch(conn, statements)
                except psycopg.errors.UndefinedTable:
                    # A store the vault was never migrated into holds no secret.
                    conn.rollback()
                    found_rows, found_version = [], []
                self.seed(found_rows, found_version)
        except DbError as exc:
            raise self._unreadable(exc) from None
        except psycopg.Error as exc:
            raise self._unreadable(exc) from None

    def get(self, name: str) -> str | None:
        """The value of `name`, None where the vault holds none this key opens;
        VaultError `vault_unreadable` where the store could not be read."""
        self._refresh()
        held = (self._sealed or {}).get(name)
        if held is None:
            return None
        blob, fp = held
        if fp != self.key_fingerprint:
            return None
        opened = self._opened.get(name)
        if opened is None or opened[0] != blob:
            opened = (blob, unseal(self._key, self.agent_id, name, blob))
            self._opened[name] = opened
        return opened[1]


_READERS: dict[tuple[str, str, str], Reader] = {}


def reader(project_root: Path | str | None, agent_id: str | None, *,
           application_name: str = "capabilities") -> Reader | None:
    """The process's reader of `agent_id`'s vault for `project_root`, or None
    where no agent or no key is there; VaultError `bad_key` for a key that is
    not one. One reader per agent, root and key, so every connection of the
    process opens a name once."""
    if not agent_id:
        return None
    key = agent_key(project_root)
    if key is None:
        return None
    slot = (str(project_root), agent_id, fingerprint(key))
    found = _READERS.get(slot)
    if found is None:
        found = _READERS[slot] = Reader(agent_id, key, project_root=project_root,
                                        application_name=application_name)
    return found


# --- KEY=value text ---------------------------------------------------------------


def _plain(value: str) -> bool:
    return (value == value.strip() and not any(c in value for c in "\n\r\"'#")
            and value != "")


def render_text(values: Mapping[str, str]) -> str:
    """`values` as KEY=value lines, in name order: a value that a plain line
    would not carry back whole is written as a JSON string."""
    import json
    lines = [f"{name}={value if _plain(value) else json.dumps(value)}"
             for name, value in sorted(values.items())]
    return "".join(line + "\n" for line in lines)


def parse_text(text: str) -> dict[str, str]:
    """The KEY=value lines `render_text` writes, or a .env file: blank lines and
    `#` comments skipped, `export ` allowed, a double-quoted value read as a JSON
    string, a single-quoted one taken as it stands. VaultError `bad_text` names
    the first line that is not one, by number only."""
    import json
    out: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            raise VaultError("bad_text", f"line {number} is not KEY=value")
        name, value = stripped.split("=", 1)
        name = name.strip()
        if name.startswith("export "):
            name = name[len("export "):].strip()
        if not NAME_RE.fullmatch(name):
            raise VaultError("bad_text", f"line {number} does not start with a name")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            try:
                value = json.loads(value)
            except ValueError:
                raise VaultError("bad_text",
                                 f"line {number} holds a double-quoted value that is not "
                                 "a JSON string") from None
        elif len(value) >= 2 and value[0] == value[-1] == "'":
            value = value[1:-1]
        if name in out:
            raise VaultError("bad_text", f"line {number} names {name} a second time")
        out[name] = value
    return out
