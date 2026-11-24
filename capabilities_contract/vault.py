"""An agent's vault: named secrets kept in the store, sealed with the agent's own key.

Every agent has one encryption key, `AGENT_ENCRYPTION_KEY`, held in its environment
and never in the store: on a Mac its folder's `.env.local`, on a node its environment
or the node's machine file `$XDG_CONFIG_HOME/capabilities/shared.env`. Each secret is
a row of `secrets` - the agent, the name, the sealed value and the
fingerprint of the key that sealed it - and the agent's row in `agents`
keeps the fingerprint of its key in `vault_key`, never the key.

A value is sealed with XChaCha20-Poly1305 (libsodium, through PyNaCl), a fresh random
nonce each time, the agent id and the name bound as associated data, so a sealed value
moved to another agent or another name does not open. A row sealed under a key other
than the agent's present one is unreadable: it is kept and reported, and is set again
to be read.

Every key also gives the agent a public sealing key, an X25519 public key derived from
it, which the agent's row publishes in `vault_public_key` beside the fingerprint; the
key itself still never enters the store. A writer that does not hold an agent's key -
another agent writing a shared connection's secret for each of its grantees - seals a
value for that public key (`seal_for`): an ephemeral X25519 key agreed with it gives
the XChaCha20-Poly1305 key, the agent id and the name bound as before. The row is the
agent's like any other, recorded under the agent's key fingerprint, and only the
agent's key opens it (`unseal` reads either format).

Every entry a release of this library writes is sealed in format 3: to the agent's
public key with sender authentication (libsodium's Box agreement, `crypto_box_beforenm`,
keying XChaCha20-Poly1305), the sender's public key carried in the entry. The agent's
own entries are sent by itself; an entry anyone else writes is sent by the platform,
whose keypair the capabilities manager keeps in a file of its own machine
(`capabilities_contract.platform`) and whose public key the store publishes. An agent
opens a format 3 entry only where it was sent by itself or by the platform key it
pinned: the pin is an entry of its own vault (`PIN_NAME`), sealed by its own key so only
a holder of the key writes it, taken the first time a process holding the key sees a
published platform key - a key read from the store alone is never trusted. Format 1
keeps opening; format 2 opens only while the agent holds no pin, so once it does, a row
anyone with the store's login wrote opens nothing. Where the agent holds a pin, each of
its own writes also leaves the platform a copy, sent by the agent.

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
VAULT_TABLE = "secrets"
VAULT_CHANNEL = "capabilities_vault"
KEY_BYTES = 32
NONCE_BYTES = 24
# The first byte of every sealed value: the format it is sealed in - under the
# agent's own key, or for its public sealing key by a writer without the key.
SEALED_FORMAT = 1
SEALED_FORMAT_PUBLIC = 2
# Sealed to the agent's public key by a sender that authenticates itself: the
# format every write of this release makes.
SEALED_FORMAT_BOX = 3
# The entry of an agent's own vault that pins the platform's public key.
PIN_NAME = "CAPABILITIES_PLATFORM_PIN"
PUBLIC_BYTES = 32
PUBLIC_RE = re.compile(r"[A-Za-z0-9_-]{43}")
NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,254}")
FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}")
# How long a reader trusts what it read before it asks the channel again.
CHECK_SECONDS = 1.0
# How long a store that could not be read stands refused, so one command that
# asks for several names waits on it once.
RETRY_SECONDS = 2.0

_AAD_PREFIX = b"capabilities-vault/v1\0"
_FINGERPRINT_PREFIX = b"capabilities-vault-key/v1\0"
_PUBLIC_SECRET_PREFIX = b"capabilities-vault-public/v1\0"
_PUBLIC_SEAL_PREFIX = b"capabilities-vault-public-seal/v1\0"
_BOX_AAD_PREFIX = b"capabilities-vault-box/v1\0"


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


def _public_secret(key: bytes) -> bytes:
    """The X25519 secret scalar an agent's key gives: a SHA-256 over it, apart
    from the fingerprint, so neither is learnt from the other."""
    return hashlib.sha256(_PUBLIC_SECRET_PREFIX + key).digest()


def public_key(key: bytes) -> bytes:
    """The agent's public sealing key: the X25519 public key of the scalar its
    key gives. What the store publishes of the agent beside its fingerprint."""
    return _nacl().crypto_scalarmult_base(_public_secret(key))


def public_text(key: bytes) -> str:
    """The public sealing key as the store keeps it: URL-safe base64 of its 32
    bytes, without padding."""
    return encode_key(public_key(key))


def parse_public(text: object) -> bytes | None:
    """The public sealing key `text` holds, or None where it holds none."""
    if not isinstance(text, str) or not PUBLIC_RE.fullmatch(text):
        return None
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        return None
    return raw if len(raw) == PUBLIC_BYTES else None


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
    """`value` sealed for `name` of `agent_id` by the agent itself: format 3,
    sent by and to the public key `key` gives (`seal_box`)."""
    return seal_box(_public_secret(key), public_key(key), agent_id, name, value)


def seal_symmetric(key: bytes, agent_id: str, name: str, value: str) -> bytes:
    """`value` sealed under `key` itself, format 1: the format byte, the nonce,
    then the ciphertext with its tag. No release writes it any more; it is
    what an older one wrote, and still opens."""
    nacl = _nacl()
    nonce = _secrets.token_bytes(NONCE_BYTES)
    sealed = nacl.crypto_aead_xchacha20poly1305_ietf_encrypt(
        value.encode("utf-8"), _aad(agent_id, check_name(name)), nonce, key)
    return bytes([SEALED_FORMAT]) + nonce + sealed


def _box_key(secret: bytes, public: bytes) -> bytes:
    """The key the holder of X25519 `secret` and the holder of the secret of
    `public` agree on (libsodium's `crypto_box_beforenm`); VaultError
    `bad_public_key` for a point that agrees on nothing."""
    nacl = _nacl()
    if len(public) != PUBLIC_BYTES:
        raise VaultError("bad_public_key", "a public key is 32 bytes")
    try:
        return nacl.crypto_box_beforenm(public, secret)
    except Exception:  # nacl.exceptions.CryptoError: a low-order point
        raise VaultError("bad_public_key", "a public key agrees on nothing") from None


def _box_aad(scope: str, name: str, sender: bytes, recipient: bytes) -> bytes:
    return (_BOX_AAD_PREFIX + scope.encode() + b"\0" + name.encode() + b"\0"
            + sender + recipient)


def seal_box(sender_secret: bytes, recipient: bytes, scope: str, name: str,
             value: str) -> bytes:
    """`value` sealed for `name` of `scope` (an agent id, or the scope of a
    platform copy) from the holder of X25519 `sender_secret` to the holder of
    the secret of `recipient`: the format byte, the sender's public key, the
    nonce, then the ciphertext with its tag. Only the two of them open it, and
    whoever opens it learns who sent it."""
    nacl = _nacl()
    sender = nacl.crypto_scalarmult_base(sender_secret)
    nonce = _secrets.token_bytes(NONCE_BYTES)
    sealed = nacl.crypto_aead_xchacha20poly1305_ietf_encrypt(
        value.encode("utf-8"), _box_aad(scope, check_name(name), sender, recipient),
        nonce, _box_key(sender_secret, recipient))
    return bytes([SEALED_FORMAT_BOX]) + sender + nonce + sealed


def box_sender(blob: bytes) -> bytes | None:
    """The public key of whoever sent a format 3 entry, None for any other."""
    blob = bytes(blob)
    if blob[:1] != bytes([SEALED_FORMAT_BOX]) or len(blob) < 1 + PUBLIC_BYTES + NONCE_BYTES:
        return None
    return blob[1:1 + PUBLIC_BYTES]


def open_box(secret: bytes, scope: str, name: str, blob: bytes,
             senders: Iterable[bytes], recipient: bytes | None = None) -> str | None:
    """The value of a format 3 entry for `name` of `scope`, opened with X25519
    `secret`, or None: where it does not open, or where its sender is not one
    of `senders`. `recipient` is the public key it was sealed to, the one
    `secret` gives unless the sender opens what it sent."""
    nacl = _nacl()
    blob = bytes(blob)
    sender = box_sender(blob)
    if sender is None or sender not in {bytes(s) for s in senders if s}:
        return None
    own = nacl.crypto_scalarmult_base(secret)
    recipient = own if recipient is None else recipient
    peer = sender if recipient == own else recipient
    nonce = blob[1 + PUBLIC_BYTES:1 + PUBLIC_BYTES + NONCE_BYTES]
    try:
        plain = nacl.crypto_aead_xchacha20poly1305_ietf_decrypt(
            blob[1 + PUBLIC_BYTES + NONCE_BYTES:], _box_aad(scope, name, sender, recipient),
            nonce, _box_key(secret, peer))
    except Exception:  # nacl.exceptions.CryptoError, or a point that agrees on nothing
        return None
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _public_seal_key(shared: bytes, ephemeral: bytes, public: bytes) -> bytes:
    return hashlib.sha256(_PUBLIC_SEAL_PREFIX + shared + ephemeral + public).digest()


def seal_for(public: bytes, agent_id: str, name: str, value: str) -> bytes:
    """`value` sealed for `name` of `agent_id` by a writer that holds only the
    agent's public sealing key: the format byte, the ephemeral public key, the
    nonce, then the ciphertext with its tag. Only the agent's key opens it."""
    nacl = _nacl()
    if len(public) != PUBLIC_BYTES:
        raise VaultError("bad_public_key", f"agent {agent_id}'s public sealing key is not one")
    ephemeral_secret = _secrets.token_bytes(PUBLIC_BYTES)
    ephemeral = nacl.crypto_scalarmult_base(ephemeral_secret)
    try:
        shared = nacl.crypto_scalarmult(ephemeral_secret, public)
    except Exception:  # a low-order point agrees on nothing
        raise VaultError("bad_public_key",
                         f"agent {agent_id}'s public sealing key is not one") from None
    nonce = _secrets.token_bytes(NONCE_BYTES)
    sealed = nacl.crypto_aead_xchacha20poly1305_ietf_encrypt(
        value.encode("utf-8"), _aad(agent_id, check_name(name)), nonce,
        _public_seal_key(shared, ephemeral, public))
    return bytes([SEALED_FORMAT_PUBLIC]) + ephemeral + nonce + sealed


def _unseal_public(key: bytes, agent_id: str, name: str, blob: bytes) -> str | None:
    nacl = _nacl()
    if len(blob) < 1 + PUBLIC_BYTES + NONCE_BYTES:
        return None
    ephemeral = blob[1:1 + PUBLIC_BYTES]
    nonce = blob[1 + PUBLIC_BYTES:1 + PUBLIC_BYTES + NONCE_BYTES]
    sealed = blob[1 + PUBLIC_BYTES + NONCE_BYTES:]
    secret = _public_secret(key)
    try:
        shared = nacl.crypto_scalarmult(secret, ephemeral)
        plain = nacl.crypto_aead_xchacha20poly1305_ietf_decrypt(
            sealed, _aad(agent_id, name), nonce,
            _public_seal_key(shared, ephemeral, nacl.crypto_scalarmult_base(secret)))
    except Exception:  # nacl.exceptions.CryptoError, or a low-order point
        return None
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError:
        return None


class _Strict:
    def __repr__(self) -> str:
        return "STRICT"


# What a caller that does not know whether the agent holds a pin passes: only
# what the agent's key alone can have written opens.
STRICT: Any = _Strict()


def unseal(key: bytes, agent_id: str, name: str, blob: bytes,
           pin: bytes | _Strict | None = STRICT) -> str | None:
    """The value `blob` holds, or None where it does not open under `key` for
    this agent and name. `pin` is the platform public key the agent pinned
    (`pin_of`), None where it holds no pin, STRICT where the caller does not
    know: format 1 always opens; format 3 opens where the agent sent it, or
    the pinned platform key did; format 2 opens only where `pin` is None."""
    blob = bytes(blob)
    if blob[:1] == bytes([SEALED_FORMAT_BOX]):
        senders = [public_key(key)]
        if isinstance(pin, bytes):
            senders.append(pin)
        return open_box(_public_secret(key), agent_id, name, blob, senders)
    if blob[:1] == bytes([SEALED_FORMAT_PUBLIC]):
        if pin is not None:
            return None
        return _unseal_public(key, agent_id, name, blob)
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
              "FROM secrets WHERE agent_id = %s ORDER BY name")
VERSION_QUERY = "SELECT version FROM schema_channel WHERE channel = %s AND scope = %s"
KEY_QUERY = "SELECT vault_key FROM agents WHERE id = %s"


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
    conn.execute("UPDATE agents SET vault_key = %s, updated_at = now() "
                 "WHERE id = %s", (key_fingerprint, agent_id))


def publish(conn: Any, agent_id: str, key: bytes) -> bool | None:
    """Publish the agent's public sealing key on its row, where the row records
    this key's fingerprint and does not already publish it: True where it was
    written, False where nothing changed (already published, or the row
    records another key or none), None where the store predates the column.
    Run inside the caller's transaction, under a savepoint of its own."""
    import psycopg
    text, current = public_text(key), fingerprint(key)
    try:
        with conn.transaction():
            done = conn.execute(
                "UPDATE agents SET vault_public_key = %s WHERE id = %s "
                "AND vault_key = %s AND vault_public_key IS DISTINCT FROM %s",
                (text, agent_id, current, text)).rowcount
    except psycopg.errors.UndefinedColumn:
        return None
    return bool(done)


def recipients(conn: Any, agent_ids: Iterable[str]) -> dict[str, tuple[str | None, bytes | None]]:
    """{agent: (the fingerprint of its key, its public sealing key)} for each
    of `agent_ids` the store registers, either None where its row records none;
    an agent the store does not register is left out. A store that predates the
    public column answers None for every public key."""
    import psycopg
    wanted = sorted(set(agent_ids))
    if not wanted:
        return {}
    try:
        with conn.transaction():
            found = conn.execute(
                "SELECT id, vault_key, vault_public_key FROM agents "
                "WHERE id = ANY(%s)", (wanted,)).fetchall()
    except psycopg.errors.UndefinedColumn:
        found = [(agent, fp, None) for agent, fp in conn.execute(
            "SELECT id, vault_key FROM agents WHERE id = ANY(%s)",
            (wanted,)).fetchall()]
    return {agent: (fp, parse_public(public) if fp else None) for agent, fp, public in found}


def put_for(conn: Any, agent_id: str, key_fingerprint: str, public: bytes, name: str,
            value: str, updated_by: str | None = None) -> None:
    """Seal `value` for the agent's public sealing key and keep it as `name` of
    its vault, under the fingerprint of its key, replacing what was there."""
    conn.execute(
        "INSERT INTO secrets (agent_id, name, ciphertext, key_fingerprint, "
        "updated_by) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (agent_id, name) DO UPDATE "
        "SET ciphertext = excluded.ciphertext, key_fingerprint = excluded.key_fingerprint, "
        "updated_at = now(), updated_by = excluded.updated_by",
        (agent_id, check_name(name), seal_for(public, agent_id, name, value),
         key_fingerprint, updated_by))


def put_row(conn: Any, agent_id: str, name: str, blob: bytes, key_fingerprint: str,
            updated_by: str | None = None) -> None:
    """Keep the sealed `blob` as `name` of the agent's vault, recorded under the
    fingerprint of the agent key it opens under, replacing what was there."""
    conn.execute(
        "INSERT INTO secrets (agent_id, name, ciphertext, key_fingerprint, "
        "updated_by) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (agent_id, name) DO UPDATE "
        "SET ciphertext = excluded.ciphertext, key_fingerprint = excluded.key_fingerprint, "
        "updated_at = now(), updated_by = excluded.updated_by",
        (agent_id, check_name(name), blob, key_fingerprint, updated_by))


def put(conn: Any, key: bytes, agent_id: str, name: str, value: str,
        updated_by: str | None = None) -> None:
    """Seal `value` as the agent itself and keep it as `name`, replacing what
    was there; where the agent pins a platform key (`take_pin`), leave the
    platform its copy, sent by the agent."""
    if check_name(name) == PIN_NAME:
        raise VaultError("bad_secret_name", f"{PIN_NAME} is the vault's own pin of the "
                         "platform key, not a secret", "choose another name")
    put_row(conn, agent_id, name, seal(key, agent_id, name, value), fingerprint(key),
            updated_by)
    pin = take_pin(conn, key, agent_id, updated_by=updated_by)
    if pin is not None:
        put_copy_row(conn, seal_box(_public_secret(key), pin, copy_scope(agent_id=agent_id),
                                    name, value), name, agent_id=agent_id,
                     updated_by=updated_by)


def remove(conn: Any, agent_id: str, names: Iterable[str]) -> list[str]:
    """Remove the named rows, which needs no key, and the platform's copies of
    them; the names that were there."""
    import psycopg
    wanted = [check_name(n) for n in names]
    found = conn.execute(
        "DELETE FROM secrets WHERE agent_id = %s AND name = ANY(%s) "
        "RETURNING name", (agent_id, wanted)).fetchall()
    try:
        with conn.transaction():
            conn.execute("DELETE FROM platform_secrets WHERE agent_id = %s "
                         "AND name = ANY(%s)", (agent_id, wanted))
    except psycopg.errors.UndefinedTable:
        pass
    return sorted(name for (name,) in found)


# --- The pin of the platform's key, and the platform's copies -----------------


def copy_scope(agent_id: str | None = None, connection_id: str | None = None) -> str:
    """What a platform copy is bound to as associated data: the agent whose
    own entry it copies, or the shared connection whose secret it is."""
    if (agent_id is None) == (connection_id is None):
        raise VaultError("bad_copy", "a platform copy is of one agent or one connection")
    return f"platform/agent/{agent_id}" if agent_id else f"platform/connection/{connection_id}"


def put_copy_row(conn: Any, blob: bytes, name: str, *, agent_id: str | None = None,
                 connection_id: str | None = None, updated_by: str | None = None) -> bool:
    """Keep `blob` as the platform's copy of `name` of one agent's own vault or
    of one shared connection, replacing what was there: False where the store
    keeps no copies (its core is older than 4.4)."""
    import psycopg
    copy_scope(agent_id, connection_id)
    column = "agent_id" if agent_id else "connection_id"
    try:
        with conn.transaction():
            conn.execute(
                f"INSERT INTO platform_secrets ({column}, name, ciphertext, updated_by) "
                f"VALUES (%s, %s, %s, %s) ON CONFLICT ({column}, name) "
                f"WHERE {column} IS NOT NULL DO UPDATE SET ciphertext = excluded.ciphertext, "
                "updated_at = now(), updated_by = excluded.updated_by",
                (agent_id or connection_id, check_name(name), blob, updated_by))
    except (psycopg.errors.UndefinedTable, psycopg.errors.UndefinedColumn):
        return False
    return True


def platform_published(conn: Any) -> bytes | None:
    """The platform's public key as the store publishes it, None where it
    publishes none or predates the column. Read inside the caller's
    transaction, under a savepoint of its own."""
    import psycopg
    try:
        with conn.transaction():
            found = conn.execute("SELECT platform_public_key FROM store_state").fetchall()
    except (psycopg.errors.UndefinedColumn, psycopg.errors.UndefinedTable):
        return None
    return parse_public(found[0][0]) if found else None


def _open_pin(key: bytes, agent_id: str, blob: bytes) -> bytes | None:
    """The platform key a pin entry holds, where the agent's key alone could
    have written it."""
    text = unseal(key, agent_id, PIN_NAME, blob)
    return parse_public(text) if text else None


def pin_of(key: bytes, agent_id: str, found_rows: Iterable[Any]) -> bytes | None:
    """The platform public key the agent pinned, from its vault's rows (dicts
    as `rows` answers them, or (name, ciphertext, key_fingerprint, ...)
    tuples), None where it pinned none its key opens."""
    current = fingerprint(key)
    for row in found_rows:
        name, blob, fp = ((row["name"], row["ciphertext"], row["key_fingerprint"])
                          if isinstance(row, Mapping) else (row[0], row[1], row[2]))
        if name == PIN_NAME and fp == current:
            return _open_pin(key, agent_id, bytes(blob))
    return None


def write_pin(conn: Any, key: bytes, agent_id: str, platform: bytes,
              updated_by: str | None = None) -> None:
    """Pin `platform` as the platform key the agent trusts, sealed by the
    agent's own key, which only a holder of the key writes."""
    put_row(conn, agent_id, PIN_NAME, seal(key, agent_id, PIN_NAME, encode_key(platform)),
            fingerprint(key), updated_by)


def take_pin(conn: Any, key: bytes, agent_id: str,
             updated_by: str | None = None) -> bytes | None:
    """The platform key the agent pinned; where it pinned none and the store
    publishes one, that one, pinned now - the first sight of it by a process
    holding the key. None where there is none to pin."""
    found = conn.execute(
        "SELECT name, ciphertext, key_fingerprint FROM secrets WHERE agent_id = %s "
        "AND name = %s", (agent_id, PIN_NAME)).fetchall()
    pinned = pin_of(key, agent_id, found)
    if pinned is not None:
        return pinned
    published = platform_published(conn)
    if published is None:
        return None
    write_pin(conn, key, agent_id, published, updated_by=updated_by)
    return published


def reseal(conn: Any, key: bytes, agent_id: str,
           updated_by: str | None = None) -> dict[str, list[str]]:
    """Seal again in format 3, as the agent itself, every entry of its vault
    an older release wrote (format 1, and format 2 while the agent holds no
    pin), with the same key and value: {resealed, unreadable} by name. An
    entry under another key, or one that does not open, is left as it is."""
    current = fingerprint(key)
    held = rows(conn, agent_id)
    pin = pin_of(key, agent_id, held)
    out: dict[str, list[str]] = {"resealed": [], "unreadable": []}
    for row in held:
        name, blob = row["name"], row["ciphertext"]
        if name == PIN_NAME or blob[:1] == bytes([SEALED_FORMAT_BOX]):
            continue
        value = unseal(key, agent_id, name, blob, pin) if row["key_fingerprint"] == current \
            else None
        if value is None:
            out["unreadable"].append(name)
            continue
        put(conn, key, agent_id, name, value, updated_by=updated_by)
        out["resealed"].append(name)
    return out


def sealed_under_other(conn: Any, agent_id: str, key_fingerprint: str) -> int:
    """How many of the agent's rows were sealed under another key."""
    return conn.execute(
        "SELECT count(*) FROM secrets WHERE agent_id = %s "
        "AND key_fingerprint <> %s", (agent_id, key_fingerprint)).fetchone()[0]


# --- Writing from a process ------------------------------------------------------


def _in_store(project_root: Path | str | None, application_name: str, work: Any) -> Any:
    """`work(conn)` in one transaction against the store `project_root` resolves,
    the store's own failures raised as VaultError `vault_unwritable`."""
    from capabilities_contract import db
    try:
        import psycopg
    except ImportError as exc:
        raise VaultError("vault_unwritable", f"the vault could not be written: {exc}") from None
    try:
        with db.connect(application_name=application_name, project_root=project_root,
                        transaction=True) as conn, conn.transaction():
            return work(conn)
    except VaultError:
        raise
    except (DbError, psycopg.Error) as exc:
        message = getattr(exc, "message", None) or str(exc).strip()
        raise VaultError("vault_unwritable", f"the vault could not be written: {message}",
                         "check the database setting with `capabilities store doctor`") \
            from None


def _forget(agent_id: str) -> None:
    """Make this process's readers of `agent_id` read the vault again on their
    next question, so what it just wrote is what it reads back."""
    for slot, found in _READERS.items():
        if slot[1] == agent_id:
            found._sealed = None
            found._opened.clear()


def write(project_root: Path | str | None, agent_id: str, values: Mapping[str, str], *,
          application_name: str = "capabilities",
          updated_by: str | None = None) -> dict[str, str]:
    """Seal each of `values` into `agent_id`'s vault under the key `project_root`
    resolves, in one transaction, recording the key's fingerprint where the
    agent has none yet: {name: "created" | "replaced"}. Nothing is written where
    it refuses: VaultError `key_missing` with no key here, `bad_key`,
    `agent_unregistered` where the store has no row for the agent, `key_mismatch`
    where the agent's vault is kept under another key, `vault_unwritable` where
    the store cannot be written."""
    names = [check_name(name) for name in values]
    key = agent_key(project_root)
    if key is None:
        raise VaultError("key_missing", f"this agent has no {KEY_ENV} here",
                         "`capabilities key generate` makes the agent's first one")
    current = fingerprint(key)

    def seal_all(conn: Any) -> dict[str, str]:
        found, recorded = recorded_key(conn, agent_id)
        if not found:
            raise VaultError("agent_unregistered",
                             f"the store registers no agent {agent_id}",
                             "run `capabilities init` in the agent's folder")
        if recorded is None:
            record_key(conn, agent_id, current)
        elif recorded != current:
            raise VaultError("key_mismatch",
                             f"the {KEY_ENV} here is not the key agent {agent_id}'s vault "
                             "is kept under",
                             "bring the agent's key with `capabilities key set`")
        publish(conn, agent_id, key)
        held = {row[0] for row in conn.execute(
            "SELECT name FROM secrets WHERE agent_id = %s AND name = ANY(%s)",
            (agent_id, names)).fetchall()}
        for name in names:
            put(conn, key, agent_id, name, values[name], updated_by=updated_by)
        return {name: "replaced" if name in held else "created" for name in names}

    done = _in_store(project_root, application_name, seal_all)
    _forget(agent_id)
    return done


UNPUBLISHED_HINT = ("an agent's public sealing key is published by the first command "
                    "that uses its key against the store in its folder: "
                    "`capabilities connections seal` there")
PLATFORM_HINT = ("a shared connection's value is written on the machine that holds the "
                 "platform key, where the capabilities manager delivers it to every agent "
                 "granted it: give it there, or run `capabilities secrets migrate` there "
                 "to take it from the vaults that hold it")


def share(project_root: Path | str | None, writer: str | None, values: Mapping[str, str],
          agents: Iterable[str], *, replace: bool = True,
          application_name: str = "capabilities",
          updated_by: str | None = None) -> dict[str, Any]:
    """Seal each of `values` into the writer's own vault (`writer`, where it is
    one of `agents`) under the key `project_root` resolves, in one
    transaction. Another agent's vault is written only by the platform
    (`capabilities_contract.platform`), from its own copy: `agents` naming any
    other is refused, VaultError `shared_by_platform`, with nothing written.
    With `replace` false a name the vault already holds under its present key
    is left as it is, so running it again changes nothing. Answers {sealed:
    {agent: {name: "created" | "replaced"}}, unchanged: {agent: [name]},
    unpublished: [], unregistered: [agent]}. VaultError as `write` raises it,
    for the writer's own key, and `vault_unwritable`."""
    names = [check_name(name) for name in values]
    targets = sorted(set(agents))
    others = [agent for agent in targets if agent != writer]
    if others:
        raise VaultError("shared_by_platform",
                         f"a value for agent(s) {', '.join(others)} is not this agent's to "
                         "seal: another agent's vault is written only by the platform",
                         PLATFORM_HINT)
    key = agent_key(project_root) if writer in targets else None
    if writer in targets and key is None:
        raise VaultError("key_missing", f"this agent has no {KEY_ENV} here",
                         "`capabilities key generate` makes the agent's first one")

    def seal_all(conn: Any) -> dict[str, Any]:
        out: dict[str, Any] = {"sealed": {}, "unchanged": {}, "unpublished": [],
                               "unregistered": []}
        if key is not None:
            found, recorded = recorded_key(conn, writer)
            current = fingerprint(key)
            if found and recorded is None:
                record_key(conn, writer, current)
            elif found and recorded != current:
                raise VaultError("key_mismatch",
                                 f"the {KEY_ENV} here is not the key agent {writer}'s vault "
                                 "is kept under",
                                 "bring the agent's key with `capabilities key set`")
            if found:
                publish(conn, writer, key)
        known = recipients(conn, targets)
        for agent in targets:
            if agent not in known:
                out["unregistered"].append(agent)
                continue
            fp, public = known[agent]
            own = agent == writer and key is not None
            if not own and (fp is None or public is None):
                out["unpublished"].append(agent)
                continue
            fp = fingerprint(key) if own else fp
            held = {name for name, at in conn.execute(
                "SELECT name, key_fingerprint FROM secrets WHERE agent_id = %s "
                "AND name = ANY(%s)", (agent, names)).fetchall() if at == fp}
            present = {row[0] for row in conn.execute(
                "SELECT name FROM secrets WHERE agent_id = %s AND name = ANY(%s)",
                (agent, names)).fetchall()}
            for name in names:
                if not replace and name in held:
                    out["unchanged"].setdefault(agent, []).append(name)
                    continue
                if own:
                    put(conn, key, agent, name, values[name], updated_by=updated_by)
                else:
                    put_for(conn, agent, fp, public, name, values[name], updated_by=updated_by)
                out["sealed"].setdefault(agent, {})[name] = (
                    "replaced" if name in present else "created")
        if out["unpublished"]:
            out["hint"] = UNPUBLISHED_HINT
        return out

    done = _in_store(project_root, application_name, seal_all)
    for agent in done["sealed"]:
        _forget(agent)
    return done


def delete(project_root: Path | str | None, agent_id: str, names: Iterable[str], *,
           application_name: str = "capabilities") -> list[str]:
    """Remove the named rows of `agent_id`'s vault, which needs no key; the
    names that were there. VaultError `vault_unwritable` where the store cannot
    be written."""
    wanted = [check_name(name) for name in names]
    if not wanted:
        return []
    done = _in_store(project_root, application_name, lambda conn: remove(conn, agent_id, wanted))
    _forget(agent_id)
    return done


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
        self._public = public_key(key)
        self._pinned: Any = STRICT

    @property
    def loaded(self) -> bool:
        return self._sealed is not None

    def seed(self, found_rows: Iterable[Any], found_version: Iterable[Any]) -> None:
        """Take the rows and the version `round_trip` read, in that order."""
        sealed = {}
        for row in found_rows:
            name, blob, fp = row[0], row[1], row[2]
            sealed[name] = (bytes(blob), fp)
        if (self._sealed or {}).get(PIN_NAME) != sealed.get(PIN_NAME):
            self._opened.clear()  # what opens depends on the pin
        self._sealed = sealed
        self._pinned = STRICT
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

    def _pin(self) -> bytes | None:
        """The platform key the agent pinned, from the rows read, None where it
        pinned none its key opens."""
        if self._pinned is STRICT:
            held = (self._sealed or {}).get(PIN_NAME)
            self._pinned = (_open_pin(self._key, self.agent_id, held[0])
                            if held is not None and held[1] == self.key_fingerprint else None)
        return self._pinned

    def _take_pin(self) -> bytes | None:
        """Pin the platform key the store publishes, on first sight of an entry
        another than the agent sent; None where none is published or the
        store cannot be written."""
        try:
            with self._connect() as conn, conn.transaction():
                pin = take_pin(conn, self._key, self.agent_id)
        except Exception:  # an outage, a read-only login: the entry stays unopened
            return None
        if pin is not None:
            self._pinned = pin
            self._opened.clear()
        return pin

    def get(self, name: str) -> str | None:
        """The value of `name`, None where the vault holds none this key opens
        from a sender it trusts; VaultError `vault_unreadable` where the store
        could not be read."""
        self._refresh()
        if name == PIN_NAME:
            return None
        held = (self._sealed or {}).get(name)
        if held is None:
            return None
        blob, fp = held
        if fp != self.key_fingerprint:
            return None
        opened = self._opened.get(name)
        if opened is None or opened[0] != blob:
            value = unseal(self._key, self.agent_id, name, blob, self._pin())
            sender = box_sender(blob)
            if (value is None and self._pin() is None and sender is not None
                    and sender != self._public and self._take_pin() is not None):
                value = unseal(self._key, self.agent_id, name, blob, self._pin())
            opened = (blob, value)
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
