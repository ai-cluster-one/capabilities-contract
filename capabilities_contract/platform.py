"""The platform's side of the vault: the one writer of every entry an agent did not
write itself.

The platform is a keypair the capabilities manager makes on first need, on the machine
it runs on, in a file only its user reads: `$XDG_CONFIG_HOME/capabilities/platform/key`,
32 random bytes as URL-safe base64, like an agent's key, its X25519 secret derived the
same way. It never enters the store and never reaches a node; the store publishes its
public key (`store_state.platform_public_key`) for display and hints, and no agent
trusts it from there: an agent trusts the platform key it pinned in its own vault, or
the key file on its own machine (`vault.take_pin`). A machine that finds the store
publishing another platform key than the one its file holds, or one while it holds
none, is refused (`platform_key_elsewhere`), so there is one platform per store.

The platform keeps its own copy of every secret in `platform_secrets`, sealed to its own
public key with sender authentication (`vault.seal_box`): a shared connection's secret
by the platform itself, an agent's own entry by that agent (`vault.put`). It opens an
agent's copy only where that agent sent it, under the public key the platform pinned
for it, or where the platform did.

Every entry the platform writes into an agent's vault is sealed from its copy to the
agent's public key twice in one row: in format 2 (`vault.seal_for`), which every
release opens, and beside it in `platform_ciphertext` in format 3, sent by the platform,
which a release that reads it opens only from the platform key the agent trusts. The
platform pins each agent's public key at first sight, in
`$XDG_CONFIG_HOME/capabilities/platform/pins.json` beside its key, and refuses to seal
for an agent whose published key is no longer the one it pinned (`agent_key_changed`)
until a recovery pins the new one, so a writer of the store cannot swap an agent's key
for its own and receive its grants.

Importing this module imports neither psycopg nor PyNaCl; each is imported on use.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from capabilities_contract import vault
from capabilities_contract.vault import VaultError

KEY_FILE = "key"
PINS_FILE = "pins.json"
UPDATED_BY = "platform"
MISSING_HINT = vault.PLATFORM_HINT
ELSEWHERE_HINT = ("the platform key lives on one machine, beside the capabilities "
                  "manager that made it; run this there")


def home() -> Path:
    """Where the platform keeps its key and its pins: the manager's config home."""
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "capabilities" / "platform"


class Platform:
    """The platform keypair, its secret held in this process only."""

    def __init__(self, key: bytes):
        self._key = key
        self.secret = vault._public_secret(key)
        self.public = vault.public_key(key)

    @property
    def public_text(self) -> str:
        return vault.encode_key(self.public)


def _private_file(path: Path, text: str, *, exclusive: bool = False) -> None:
    """Write `text` to `path` readable only by this user, in a directory only it
    enters; with `exclusive` an existing file is refused."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    if exclusive:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        return
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def load() -> Platform | None:
    """The platform keypair this machine holds, None where it holds none;
    VaultError `bad_platform_key` for a file that is not a key or that another
    user can read."""
    path = home() / KEY_FILE
    try:
        mode = path.stat().st_mode
        text = path.read_text()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise VaultError("bad_platform_key", f"the platform key at {path} cannot be read: "
                         f"{exc.strerror}") from None
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise VaultError("bad_platform_key",
                         f"the platform key at {path} is readable by more than its user",
                         f"`chmod 600 {path}`")
    try:
        return Platform(vault.parse_key(text))
    except VaultError:
        raise VaultError("bad_platform_key", f"{path} does not hold a platform key") from None


def create() -> Platform:
    """Make the platform keypair and keep it in its file, mode 0600; VaultError
    `platform_key_exists` where the file is already there."""
    path = home() / KEY_FILE
    text = vault.generate_key()
    try:
        _private_file(path, text + "\n", exclusive=True)
    except FileExistsError:
        raise VaultError("platform_key_exists", f"{path} already holds a platform key") \
            from None
    return Platform(vault.parse_key(text))


def publish(conn: Any, platform: Platform) -> bool:
    """Publish the platform's public key where the store publishes none: True
    where written; VaultError `platform_key_elsewhere` where it publishes
    another, `store_too_old` where its core predates the column."""
    import psycopg
    try:
        with conn.transaction():
            row = conn.execute("SELECT platform_public_key FROM store_state "
                               "FOR UPDATE").fetchone()
            if row is None:
                raise VaultError("store_too_old", "the store holds no store_state row")
            if row[0] == platform.public_text:
                return False
            if row[0] is not None:
                raise VaultError("platform_key_elsewhere",
                                 "the store publishes another platform key than the one "
                                 "this machine holds", ELSEWHERE_HINT)
            conn.execute("UPDATE store_state SET platform_public_key = %s",
                         (platform.public_text,))
    except psycopg.errors.UndefinedColumn:
        raise VaultError("store_too_old", "the store keeps no platform key: its core is "
                         "older than 4.4", "`capabilities store migrate` brings it there") \
            from None
    return True


def ensure(conn: Any, *, create_missing: bool = False) -> Platform:
    """The platform keypair of this machine, its public key published: made
    here where `create_missing` and neither this machine nor the store holds
    one. VaultError `platform_key_missing` where none is here, and
    `platform_key_elsewhere` where the store publishes another or one this
    machine does not hold."""
    local = load()
    published = vault.platform_published(conn)
    if local is not None:
        if published is not None and published != local.public:
            raise VaultError("platform_key_elsewhere",
                             "the store publishes another platform key than the one this "
                             "machine holds", ELSEWHERE_HINT)
        if published is None:
            publish(conn, local)
        return local
    if published is not None:
        raise VaultError("platform_key_elsewhere",
                         "the platform key the store publishes is held on another machine",
                         ELSEWHERE_HINT)
    if not create_missing:
        raise VaultError("platform_key_missing", "this machine holds no platform key",
                         MISSING_HINT)
    made = create()
    publish(conn, made)
    return made


# --- The agents' public keys, pinned at first sight ------------------------------


@contextlib.contextmanager
def _pins_locked():
    import fcntl
    path = home() / PINS_FILE
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = path.parent / ".pins.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            held = json.loads(path.read_text())
        except FileNotFoundError:
            held = {}
        except (OSError, ValueError):
            raise VaultError("bad_platform_pins", f"{path} is not the platform's pins") \
                from None
        if not isinstance(held, dict):
            raise VaultError("bad_platform_pins", f"{path} is not the platform's pins")
        before = dict(held)
        yield held
        if held != before:
            _private_file(path, json.dumps(held, indent=2, sort_keys=True) + "\n")
    finally:
        os.close(fd)


def pins() -> dict[str, str]:
    """{agent: the public key the platform pinned for it, as text}."""
    with _pins_locked() as held:
        return dict(held)


def pin_agent(agent_id: str, public: bytes, *, replace: bool = False) -> str:
    """Pin `public` for the agent: "pinned" where it had none, "same" where it
    is the one pinned, "repinned" where `replace` moved it; VaultError
    `agent_key_changed` where another is pinned and `replace` is false."""
    text = vault.encode_key(public)
    with _pins_locked() as held:
        pinned = held.get(agent_id)
        if pinned == text:
            return "same"
        if pinned is not None and not replace:
            raise VaultError("agent_key_changed",
                             f"agent {agent_id}'s published public key is not the one the "
                             "platform pinned for it, so nothing is sealed for it",
                             "where the agent's key was replaced or lost, "
                             "`capabilities key recover` in its folder issues it a new one "
                             "and re-delivers its entries")
        held[agent_id] = text
        return "repinned" if pinned is not None else "pinned"


def pinned_public(agent_id: str) -> bytes | None:
    found = pins().get(agent_id)
    return vault.parse_public(found) if found else None


def recipient(conn: Any, agent_id: str) -> tuple[str, bytes]:
    """(the fingerprint of the agent's key, its public key) as the store
    publishes them, the public key pinned at first sight; VaultError
    `agent_unregistered`, `agent_unpublished` where its row publishes no
    public key, `agent_key_changed` where it is not the pinned one."""
    found = vault.recipients(conn, [agent_id]).get(agent_id)
    if found is None:
        raise VaultError("agent_unregistered", f"the store registers no agent {agent_id}")
    fp, public = found
    if fp is None or public is None:
        raise VaultError("agent_unpublished",
                         f"agent {agent_id} publishes no public key", vault.UNPUBLISHED_HINT)
    pin_agent(agent_id, public)
    return fp, public


# --- The platform's copies -------------------------------------------------------


def copies(conn: Any, *, agent_id: str | None = None,
           connection_id: str | None = None) -> dict[str, bytes]:
    """{name: sealed copy} the platform keeps of one agent's own vault or one
    shared connection; {} where the store keeps none."""
    import psycopg
    vault.copy_scope(agent_id, connection_id)
    column = "agent_id" if agent_id else "connection_id"
    try:
        with conn.transaction():
            found = conn.execute(
                f"SELECT name, ciphertext FROM platform_secrets WHERE {column} = %s "
                "ORDER BY name", (agent_id or connection_id,)).fetchall()
    except psycopg.errors.UndefinedTable:
        return {}
    return {name: bytes(blob) for name, blob in found}


def put_copy(conn: Any, platform: Platform, name: str, value: str, *,
             agent_id: str | None = None, connection_id: str | None = None,
             updated_by: str | None = UPDATED_BY) -> None:
    """Keep the platform's copy of `name`, sent by the platform itself."""
    scope = vault.copy_scope(agent_id, connection_id)
    if not vault.put_copy_row(conn, vault.seal_box(platform.secret, platform.public, scope,
                                                   name, value),
                              name, agent_id=agent_id, connection_id=connection_id,
                              updated_by=updated_by):
        raise VaultError("store_too_old", "the store keeps no platform copies: its core is "
                         "older than 4.4", "`capabilities store migrate` brings it there")


def open_copy(platform: Platform, name: str, blob: bytes, *, agent_id: str | None = None,
              connection_id: str | None = None,
              agent_public: bytes | None = None) -> str | None:
    """The value of a platform copy, None where it does not open: a shared
    connection's copy only where the platform sent it; an agent's own copy
    where the platform did, or the agent under `agent_public` (its pinned key
    where None is given)."""
    senders = [platform.public]
    if agent_id is not None:
        senders.append(agent_public if agent_public is not None else pinned_public(agent_id))
    return vault.open_box(platform.secret, vault.copy_scope(agent_id, connection_id), name,
                          blob, senders)


def connection_values(conn: Any, platform: Platform, connection_id: str) -> dict[str, str]:
    """{name: value} of a shared connection's copies that open."""
    out = {}
    for name, blob in copies(conn, connection_id=connection_id).items():
        value = open_copy(platform, name, blob, connection_id=connection_id)
        if value is not None:
            out[name] = value
    return out


# --- Delivering into an agent's vault ----------------------------------------------


def deliver(conn: Any, platform: Platform, agent_id: str, values: Mapping[str, str], *,
            updated_by: str | None = UPDATED_BY) -> dict[str, str]:
    """Seal each of `values` into the agent's vault, to the agent's pinned
    public key: in format 2, and beside it the platform's format 3 copy, sent
    by the platform. {name: "created" | "replaced" | "unchanged"}, an entry
    the platform already delivered with the same value left as it is - a
    format 2 entry beside a copy the platform sent of that value - so
    delivering again changes nothing. VaultError as `recipient` raises it,
    with nothing written."""
    fp, public = recipient(conn, agent_id)
    names = [vault.check_name(name) for name in values]
    held = {row["name"]: row for row in vault.rows(conn, agent_id) if row["name"] in names}
    out = {}
    for name in names:
        found = held.get(name)
        if (found is not None and found["key_fingerprint"] == fp
                and found["ciphertext"][:1] == bytes([vault.SEALED_FORMAT_PUBLIC])
                and found["box"] is not None
                and vault.open_box(platform.secret, agent_id, name, found["box"],
                                   [platform.public], recipient=public) == values[name]):
            out[name] = "unchanged"
            continue
        vault.put_row(conn, agent_id, name, vault.seal_for(public, agent_id, name, values[name]),
                      fp, updated_by,
                      box=vault.seal_box(platform.secret, public, agent_id, name, values[name]))
        out[name] = "replaced" if found is not None else "created"
    return out


def write_agent_pin(conn: Any, platform: Platform, agent_id: str, key: bytes,
                    updated_by: str | None = UPDATED_BY) -> bool:
    """Where the platform holds the agent's key, pin the platform key in the
    agent's vault and the agent's public key on the platform: True where the
    agent's pin was written."""
    if vault.fingerprint(key) != vault.recorded_key(conn, agent_id)[1]:
        raise VaultError("key_mismatch",
                         f"the key here is not the one agent {agent_id}'s vault is kept under")
    pin_agent(agent_id, vault.public_key(key))
    held = conn.execute("SELECT name, ciphertext, key_fingerprint FROM secrets "
                        "WHERE agent_id = %s AND name = %s",
                        (agent_id, vault.PIN_NAME)).fetchall()
    if vault.pin_of(key, agent_id, held) == platform.public:
        return False
    vault.write_pin(conn, key, agent_id, platform.public, updated_by=updated_by)
    return True


def grantees(conn: Any, connection_id: str) -> list[str] | None:
    """The agents an enabled grant gives the connection to, where the store
    shares it (its owner null); None for an agent's own connection or none."""
    row = conn.execute("SELECT owner_agent_id IS NULL FROM connections WHERE id = %s",
                       (connection_id,)).fetchone()
    if row is None or not row[0]:
        return None
    return [agent for (agent,) in conn.execute(
        "SELECT DISTINCT agent_id FROM grants WHERE connection_id = %s AND enabled "
        "AND agent_id IS NOT NULL ORDER BY agent_id", (connection_id,)).fetchall()]


def deliver_connection(conn: Any, platform: Platform, connection_id: str, *,
                       agents: Iterable[str] | None = None,
                       updated_by: str | None = UPDATED_BY) -> dict[str, Any]:
    """Deliver a shared connection's copies to every agent granted it, or to
    those of `agents` granted it: {sealed: {agent: {name: outcome}}, refused:
    [{agent, code, message, hint}]}, an agent the platform cannot seal for
    named, never skipped in silence, the others delivered."""
    granted = grantees(conn, connection_id) or []
    wanted = granted if agents is None else [a for a in granted if a in set(agents)]
    values = connection_values(conn, platform, connection_id)
    out: dict[str, Any] = {"sealed": {}, "refused": []}
    if not values:
        return out
    for agent in wanted:
        try:
            with conn.transaction():
                out["sealed"][agent] = deliver(conn, platform, agent, values,
                                               updated_by=updated_by)
        except VaultError as exc:
            out["refused"].append({"agent": agent, "code": exc.slug, "message": exc.message,
                                   "hint": exc.hint})
    return out


def revoke(conn: Any, connection_id: str, agent_id: str) -> list[str]:
    """Take a shared connection's secret out of the agent's vault: the names
    removed."""
    names = sorted(copies(conn, connection_id=connection_id))
    return vault.remove(conn, agent_id, names) if names else []


def share_connection(project_root: Path | str | None, connection_id: str,
                     values: Mapping[str, str], *, replace: bool = True,
                     application_name: str = "capabilities",
                     updated_by: str | None = None) -> dict[str, Any]:
    """Write a shared connection's secret where the platform key is: one copy
    per name, then delivered to every agent granted the connection, in one
    transaction. With `replace` false a name the platform already keeps is
    left as it is. Answers {copies: {name: "created" | "replaced" |
    "unchanged"}, sealed, refused} (`deliver_connection`). VaultError
    `platform_key_missing` with its hint where this machine holds no platform
    key, nothing written."""
    names = [vault.check_name(name) for name in values]
    if load() is None:
        raise VaultError("platform_key_missing",
                         "this machine holds no platform key, and a shared connection's "
                         "value is written only where it is", MISSING_HINT)

    def work(conn: Any) -> dict[str, Any]:
        platform = ensure(conn)
        held = copies(conn, connection_id=connection_id)
        out: dict[str, Any] = {"copies": {}}
        for name in names:
            if name in held and (not replace or open_copy(
                    platform, name, held[name], connection_id=connection_id) == values[name]):
                out["copies"][name] = "unchanged"
                continue
            put_copy(conn, platform, name, values[name], connection_id=connection_id,
                     updated_by=updated_by or UPDATED_BY)
            out["copies"][name] = "replaced" if name in held else "created"
        out.update(deliver_connection(conn, platform, connection_id,
                                      updated_by=updated_by or UPDATED_BY))
        return out

    done = vault._in_store(project_root, application_name, work)
    for agent in done["sealed"]:
        vault._forget(agent)
    return done
