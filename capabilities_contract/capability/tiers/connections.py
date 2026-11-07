# The shared capability code - the connections tier: the credential cascade and the connection resolver,
# carried by a capability that implements connections.
#
# This is not a module. `capabilities_contract.capability.bind` executes it in
# the namespace of the capability that binds it, so it reads that capability's
# declarations and calls its hooks as its own code does. See the package
# docstring of `capabilities_contract.capability`.
#

def _shared_credentials_env() -> Path:
    """The machine's one home for the values several capabilities share:
    `$XDG_CONFIG_HOME/capabilities/shared.env`, keyed by each value's shared
    name."""
    return _CONFIG_HOME / "capabilities" / "shared.env"


def _shared_name(key: str) -> str | None:
    """The shared name a declared setup field gives its env key, or None when
    the key is the capability's own."""
    import re as _re
    for field in globals().get("SETUP_FIELDS") or []:
        if not isinstance(field, dict):
            continue
        name = field.get("shared")
        if (field.get("key") == key and isinstance(name, str)
                and _re.fullmatch(r"[A-Z][A-Z0-9_]*", name)):
            return name
    return None


# Why the vault could not answer a key this process asked it for, by key: the
# store could not be read, or the agent's key is not one. Reported beside the
# key, never in place of a value another tier gives.
_VAULT_UNREAD: dict = {}


def _vault_value(key: str) -> tuple[str | None, str | None]:
    """The cascade's first tier: (the value the agent's vault holds for `key`,
    where), or (None, None). The vault is the store's, sealed with the agent's
    own key or for the public key it gives; only the names asked for are
    opened, and kept in memory only."""
    import re as _re
    if not _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,254}", key):
        return None, None
    root = _project_root()
    agent = _project_id() if root is not None else None
    if not agent:
        return None, None
    try:
        from capabilities_contract import vault as _vault
    except ImportError:
        return None, None
    try:
        reader = _vault.reader(root, agent, application_name=NAME)
        if reader is None:
            return None, None
        value = reader.get(key)
    except _vault.VaultError as e:
        _VAULT_UNREAD[key] = e.message
        return None, None
    _VAULT_UNREAD.pop(key, None)
    if value is None:
        return None, None
    return value, f"vault:{agent}"


# The keys this process resolved from the agent's vault, in the order it asked:
# the ones a file may hold another value of, which the vault's shadows
# (`_vault_conflicts`).
_VAULT_KEYS: dict = {}


def _file_values(key: str) -> list:
    """[(file, value, tier)] for every file of the cascade that holds `key`, in the
    cascade's order: the project's .env.local and .env, the machine's
    shared.env under the key's shared name, the capability's credentials.env."""
    found = []
    root = _project_root()
    if root is not None:
        for fname in (".env.local", ".env"):
            val = _parse_env_file(root / fname).get(key)
            if val:
                found.append((root / fname, val, "project"))
    shared = _shared_name(key)
    if shared is not None:
        val = _parse_env_file(_shared_credentials_env()).get(shared)
        if val:
            found.append((_shared_credentials_env(), val, "user"))
    val = _parse_env_file(CREDENTIALS_ENV).get(key)
    if val:
        found.append((CREDENTIALS_ENV, val, "user"))
    return found


def _vault_conflicts() -> list:
    """[{key, files}] for each key this process resolved from the agent's
    vault where a file of the cascade holds another value: the files whose
    value is not the vault's, which the vault shadows. A key the vault does
    not hold, or cannot open, is no conflict."""
    out = []
    for key in _VAULT_KEYS:
        held, _where = _vault_value(key)
        if held is None:
            continue
        files = [str(path) for path, val, _tier in _file_values(key) if val != held]
        if files:
            out.append({"key": key, "files": files})
    return out


def _resolve_env_key(key: str) -> tuple[str | None, str | None, Path | None]:
    """Resolve one env key through cascade tiers 2-5: the agent's vault →
    project .env(.local) → user config → process env. Returns (value, tier,
    source). The vault is preferred, never exclusive: a key it does not hold,
    or cannot be read for, resolves from the files and the environment as it
    always did. User config is the capability's credentials.env, after the
    machine's shared.env for a key a setup field declares shared."""
    val, where = _vault_value(key)
    if val:
        _VAULT_KEYS.setdefault(key, None)
        return val, "vault", where
    for path, val, tier in _file_values(key):
        return val, tier, path
    val = os.environ.get(key)
    if val:
        return val, "env", None
    return None, None, None


def _mask(value: str) -> str:
    return ("…" + value[-4:]) if len(value) >= 8 else "****"


def _grant_hint(cid: str) -> str:
    """One wording for the one way a project grants an inherited connection.

    Same shape as `_write_gate`'s: the gate is the human's to lift, never the
    agent's, and the hint carries the exact command rather than a description
    of one. Where no project resolves there is no scope to grant in, so the
    hint names the command that makes one and then the grant, in the order they
    have to happen."""
    grant = f"`capabilities set {NAME} grant {cid} '{{\"enabled\": true}}'`"
    if _project_root() is None:
        return ("Do not lift the gate yourself — ask the user; run "
                f"`capabilities init` in the project that should use {NAME}, "
                f"then {grant} there.")
    return ("Do not lift the gate yourself — ask the user; granting is "
            f"{grant} run inside this project.")


# The connections the machine lent this process for a machine read, by id, each
# with the file it was declared in; empty in every other process.
_MACHINE_LENT: dict = {}


def _grant_gate(reg: dict, cid: str) -> None:
    """Refuse a connection this project may not use, for read as for write.

    A connection declared outside the project is not the project's to use until
    the project itself says so, and one the project switched off is off;
    nothing in the cascade lifts either. Outside a project there is no scope in
    which anything could have said so, which is a different situation and says
    so rather than asserting a project that is not there."""
    entry = (reg.get("withheld") or {}).get(cid)
    if entry is None:
        return
    label = (reg.get("labels") or {}).get(cid)
    named = f"{cid!r}" + (f" ({label})" if label and label != cid else "")
    if entry.get("scope") == "project":
        message = f"connection {named} is disabled in this project"
    elif _machine_read():
        message = (f"connection {named} is switched off on this machine by "
                   f"its grant")
    elif _project_root() is None:
        message = (f"connection {named} is declared globally and there is no "
                   f"project here to grant it in")
    else:
        message = (f"connection {named} is declared outside this project and "
                   f"this project has not granted it")
    _die(4, "connection_not_granted", message, _grant_hint(cid))


def _connections_composed() -> dict:
    """The connections envelope shape, composed out of resolved records.

    Deliberately reconstituted rather than returned in some store-shaped form:
    selection, the write gate and the `connections` report all read the envelope
    shape, and they should not learn where the rows came from. What changes here
    is the source, never the shape.

    The permission a project was granted is folded back onto the entry as
    `allow_write`, which is where the rest of the contract looks for it.

    A connection this project may not use is kept apart under `withheld`, not
    dropped: `connections` holds exactly what may be acted on — which is what
    every capability's own report iterates — while selection still has the name
    it needs to explain a refusal instead of pretending the connection was
    never declared.

    `sources` names, per connection, the file its identity was read out of. An
    identity is taken whole from one scope, so each connection has exactly one
    origin, and a project that merely granted an inherited connection is not
    where that connection's values are written. It is kept beside the entries
    rather than folded into them because it describes a record rather than
    configuring one: nothing resolves through it, and its one reader is each
    capability's own report, naming the origin of its `connection`-tier keys."""
    adapter = _records()
    machine = _machine_read()
    _MACHINE_LENT.clear()
    try:
        effective = adapter.connections(NAME, write_default=WRITE_DEFAULT,
                                        include_disabled=True,
                                        machine_read=machine)
        default = adapter.get(NAME, "setting", "connection.default")
        source = adapter.collection_source(NAME, "connection")
    except StoreError as e:
        _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)
    if not effective:
        _die(6, "connections_required",
             f"{NAME} requires an explicit connections registry and "
             f"{source} holds none",
             'expected {"default": "<id>", "connections": {"<id>": { ... }}}')
    usable = {cid: e for cid, e in effective.items() if e["enabled"]}
    withheld = {cid: e for cid, e in effective.items() if not e["enabled"]}
    if not usable:
        # Named by label, the word a person reads; files call one by its key.
        named = ", ".join(sorted(entry.get("label") or cid for cid, entry in withheld.items()))
        if machine:
            refusal = (f"every {NAME} connection this machine declares is "
                       f"switched off by its grant: {named}")
        elif _project_root() is None:
            refusal = (f"there is no project here to use a {NAME} connection in, "
                       f"so every connection declared globally stays "
                       f"withheld: {named}")
        else:
            refusal = (f"no {NAME} connection is usable in this project; every "
                       f"one it can see is withheld: {named}")
        _die(4, "connection_not_granted", refusal, _grant_hint("<id>"))
    sources = {cid: adapter.record_source(NAME, "connection", entry["scope"][0], cid)
               for cid, entry in usable.items()}
    _MACHINE_LENT.update({cid: sources[cid] for cid, entry in usable.items()
                          if entry.get("machine_read")})
    return {
        "default": default,
        "connections": {cid: {**entry["value"], "allow_write": entry["allow_write"],
                              "id": cid, "label": entry.get("label") or cid}
                        for cid, entry in usable.items()},
        "sources": sources,
        "withheld": {cid: {"scope": entry["scope"][0]}
                     for cid, entry in withheld.items()},
        "labels": {cid: entry.get("label") or cid for cid, entry in effective.items()},
    }


def _inventory_connections(machine_read: bool | None = None) -> dict:
    """Every connection this project declares, granted or not.

    An inventory reports where selection refuses, so this is deliberately the
    one connection read that never dies: no registry is zero connections, and
    a connection the project may not act on is still a connection worth
    showing. `granted` carries which is which. `machine_read` asks as one of
    the capability's machine reads would, else as the invoked verb does."""
    machine = _machine_read() if machine_read is None else bool(machine_read)
    try:
        adapter = _records()
        effective = adapter.connections(NAME, write_default=WRITE_DEFAULT,
                                        include_disabled=True,
                                        machine_read=machine) or {}
        default = adapter.get(NAME, "setting", "connection.default")
    except StoreError:
        return {"default": None, "connections": {}}
    return {"default": default,
            "connections": {
                cid: {**entry["value"], "allow_write": entry["allow_write"],
                      "granted": bool(entry["enabled"]), "id": cid,
                      "label": entry.get("label") or cid}
                for cid, entry in effective.items()}}


def _connections_registry() -> tuple[dict | None, Path | str | None]:
    """The connections envelope and where it came from.

    Composed from the two records a connection is kept as -- who it is, and
    what this project may do with it -- and handed on in the shape the rest of
    the contract already reads, so selection, the write gate and the report
    never learn which source answered.

    The path returned beside it answers for the collection -- where this project
    reads connections from. Where one connection's own values came from is a
    question about that connection, and `reg["sources"][cid]` is what answers
    it."""
    return _connections_composed(), _records().collection_source(NAME, "connection")


def _connection_labels() -> dict:
    """What each connection the store holds is called, by its id: the word it
    was added under, or the label `connection rename` gave it. A connection
    kept in files is called by its id and is not listed."""
    try:
        return _records().connection_labels(NAME)
    except StoreError as e:
        _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)


def _connection_label(cid: str) -> str:
    """What connection `cid` is called: its label in the store, else its id,
    which is what a connection kept in files is called."""
    return _connection_labels().get(cid) or cid


def _connection_former_name(cid: str) -> str | None:
    """The name connection `cid` of this capability was keyed by before the
    store gave every connection an id, as the store's pre-image of that
    cutover keeps it; None for a connection kept in files, on a store made
    after the cutover, and where the pre-image holds no row for it."""
    try:
        held = getattr(_records(), "connection_former_name", None)
        return held(NAME, cid) if held is not None and cid else None
    except StoreError:
        return None


def _connection_state_dir(base, cid: str) -> "Path":
    """Where this capability keeps state for connection `cid` under `base`:
    `base / cid`. Where that does not exist and state was made under the name
    the connection had before its id (`_connection_former_name`), that path is
    renamed to `base / cid` first - once, on the same filesystem, never over a
    path that exists - and one line on stderr says what moved; where both
    exist, `base / cid` is the one used and stderr says so."""
    import os
    import sys
    from pathlib import Path
    base = Path(base)
    target = base / cid
    former = _connection_former_name(cid)
    if not former or former == cid or former in (".", "..") or "/" in former:
        return target
    old = base / former
    if not (old.exists() or old.is_symlink()):
        return target
    if target.exists() or target.is_symlink():
        sys.stderr.write(f"{NAME}: connection {cid} keeps its state at {target}; {old}, "
                         f"made under its former name {former!r}, is left as it is\n")
        sys.stderr.flush()
        return target
    os.rename(old, target)
    sys.stderr.write(f"{NAME}: moved {old} to {target}: connection {former!r} is keyed by "
                     f"its id {cid} now\n")
    sys.stderr.flush()
    return target


def _labelled(wanted: str | None) -> str | None:
    """The id of the connection called `wanted`, where that is a label and
    not an id; a label is read only once `wanted` named no id."""
    if not wanted:
        return None
    return next((cid for cid, label in _connection_labels().items() if label == wanted),
                None)


def _select_connection(reg: dict | None, wanted: str | None) -> tuple[str, dict | None]:
    """flag → default pointer → sole entry → die 6: (the connection's id, its
    entry, which carries `id` and `label` beside its fields). The flag names a
    connection by its id, else by its label; the default pointer may hold
    either. A connection's own `address` field selects it too (used where a
    connection carries a human-recognizable address; absent fields never match).

    A connection the project was never granted is refused here rather than
    reported missing, so the one enforcement point every capability already
    routes through is also the one that answers "why not"."""
    if reg is None:
        _die(6, "connections_required",
             f"{NAME} requires an explicit connections registry")
    conns = reg["connections"]
    withheld = reg.get("withheld") or {}
    # A registry the capability composed itself carries no labels; they are
    # read only once a word names no id.
    labels = reg.get("labels") or {}

    def named(word: str) -> str | None:
        if word in conns or word in withheld:
            return word
        held = labels if "labels" in reg else _connection_labels()
        return next((cid for cid, label in held.items()
                     if label == word and (cid in conns or cid in withheld)), None)

    def chosen(cid: str) -> tuple[str, dict | None]:
        entry = conns[cid]
        if isinstance(entry, dict):
            entry.setdefault("id", cid)
            entry.setdefault("label", labels.get(cid) or cid)
        return cid, entry

    def known() -> str:
        return ", ".join(cid if (labels.get(cid) or cid) == cid
                         else f"{labels[cid]} ({cid})" for cid in conns)

    if wanted:
        cid = named(wanted)
        if cid is not None:
            if cid in conns:
                return chosen(cid)
            _grant_gate(reg, cid)
        for cid, entry in conns.items():
            if (entry or {}).get("address", "").lower() == wanted.lower():
                return chosen(cid)
        _grant_gate(reg, wanted)
        _die(6, "unknown_connection", f"no connection matches {wanted!r}",
             f"known: {known()}")
    default = reg.get("default")
    if default:
        cid = named(default)
        if cid is None or cid not in conns:
            _grant_gate(reg, cid or default)
            _die(6, "bad_default", f"default points to unknown connection {default!r}",
                 f"known: {known()}")
        return chosen(cid)
    if len(conns) == 1:
        return chosen(next(iter(conns)))
    _die(6, "ambiguous_connection",
         f"registry defines {len(conns)} connections and no default; "
         f"pass --connection <id>",
         f"known: {known()}")


def _write_gate(conn_id: str, allow_write: bool, verb: str) -> None:
    """Policy from the committed registry; nothing in the cascade lifts it.
    The read-only switch closes it for every connection and names itself."""
    if verb in WRITE_VERBS:
        _read_only_gate(f"write verb {verb!r} on connection {conn_id!r}")
    if verb in WRITE_VERBS and not allow_write and conn_id in _MACHINE_LENT:
        _die(4, "read_only",
             f"connection {conn_id!r} is the machine's, lent read-only to a "
             f"machine read outside any project",
             "Do not lift the gate yourself — ask the user; a write runs "
             "inside a project that grants this connection.")
    if verb in WRITE_VERBS and not allow_write:
        _die(4, "read_only",
             f"connection {conn_id!r} does not allow writes",
             "Do not lift the gate yourself — ask the user; granting is "
             f"`capabilities set {NAME} grant {conn_id} '{{\"allow_write\": true}}'` "
             "run inside this project.")


def _key_report(key: str, secret: bool, required: bool,
                value: str | None, tier: str | None, source) -> dict:
    report = {"key": key, "secret": secret, "required": required,
              "set": bool(value), "tier": tier if value else None,
              "source": str(source) if (value and source) else None,
              "value": (_mask(value) if secret else value) if value else None}
    if not value and key in _VAULT_UNREAD:
        report["vault"] = _VAULT_UNREAD[key]
    return report


def _missing_required(keys: list) -> list:
    """Required report rows (from _key_report) that did not resolve through the
    cascade — empty ⇒ credentials present. The primitive behind doctor's
    network-free readiness gate, read from the same per-key resolution
    `connections` reports, so the gate and the report can never disagree."""
    return [k["key"] for k in keys if k["required"] and not k["set"]]


def _doctor_gate(report: dict, wanted: str | None) -> None:
    """doctor's network-free readiness gate. Refuse with exit 2 — naming the
    unresolved required keys, before any round-trip — when a connection under
    test cannot resolve its required config through the cascade, so readiness is
    judged by the same resolution `connections` reports, never a parallel check.
    Checks the selected connection, else every connection in the report."""
    conns = report.get("connections") or {}
    if wanted and wanted not in conns:
        wanted = _labelled(wanted) or wanted
    targets = [wanted] if (wanted and wanted in conns) else list(conns)
    problems: dict = {}
    for cid in targets:
        miss = _missing_required((conns.get(cid) or {}).get("keys") or [])
        if miss:
            problems[cid] = miss
    if problems:
        # Named by label, the word a person reads; a connection kept in files is
        # called by its key.
        labels = _connection_labels()
        detail = "; ".join(f"{labels.get(c) or c}: {', '.join(ks)}"
                           for c, ks in sorted(problems.items()))
        unread = sorted({_VAULT_UNREAD[k] for ks in problems.values() for k in ks
                         if k in _VAULT_UNREAD})
        if unread:
            detail += " (" + "; ".join(unread) + ")"
        _die(2, "credentials_missing",
             f"unresolved required config — {detail}",
             f"set each in the agent's vault (`capabilities secrets set <KEY>`), the "
             f"project .env/.env.local, the user credentials.env or process env; "
             f"`{NAME} connections` shows where every value resolves")


# --- Who a connection is ------------------------------------------------------
#
# A connection's spec may carry `identity`, {"id": text, "display_name": text or
# null}: the account it is signed in as, kept in the connection's own record so
# `connections` names it without a round-trip. A capability declares which of
# its CONN_FIELDS is its main identifier with `"identity": true` on that field;
# where nothing is recorded yet, that field's value is the identity's id.
# login and doctor record it on success (`_record_identity`), and a person sets
# it with `connection add <id> --identity ID [--display-name TEXT]`.

IDENTITY_KEY = "identity"


def _identity_value(ident, display_name=None) -> dict:
    """The stored shape of one identity. Raises ValueError naming what is
    wrong."""
    if isinstance(ident, bool) or not isinstance(ident, (str, int)):
        raise ValueError("an identity's id is text")
    ident = str(ident).strip()
    if not ident or len(ident) > 256:
        raise ValueError("an identity's id is text of 1 to 256 characters")
    if display_name is not None:
        if not isinstance(display_name, str):
            raise ValueError("an identity's display name is text")
        display_name = display_name.strip() or None
    return {"id": ident, "display_name": display_name}


def _identity_field() -> str | None:
    """The key of the connection field the capability declares as its main
    identifier, if it declares one."""
    for field in globals().get("CONN_FIELDS") or []:
        if field.get("identity") is True:
            return field.get("key")
    return None


def _connection_identity(entry: dict | None) -> dict | None:
    """Who one connection is, from its record alone: the identity recorded on
    it, else the declared identifier field's value as the id, else None."""
    entry = entry if isinstance(entry, dict) else {}
    held = entry.get(IDENTITY_KEY)
    if isinstance(held, dict):
        try:
            return _identity_value(held.get("id"), held.get("display_name"))
        except ValueError:
            pass
    key = _identity_field()
    value = entry.get(key) if key else None
    if value not in (None, "") and not isinstance(value, (bool, list, dict)):
        return {"id": str(value), "display_name": None}
    return None


def _record_identity(cid: str, ident, display_name: str | None = None) -> bool:
    """Record who connection `cid` is, as login or doctor just proved it.

    Written to the connection's own record, at the scope that holds it, and
    only where it changes. Never fails the verb that proved it: under the
    read-only switch, for a connection no record here holds, or where the
    records refuse the write, nothing is written and False is answered."""
    try:
        value = _identity_value(ident, display_name)
    except ValueError:
        return False
    if read_only_switch() or not cid:
        return False
    try:
        adapter = _records()
        # The connection is named by its id; a label names it too.
        cid = adapter._word_id(NAME, cid) if hasattr(adapter, "_word_id") else cid
        scopes = ["project", "global"] if _project_root() is not None else ["global"]
        for scope in scopes:
            held = adapter.resolve_scope(NAME, "connection", scope).get(cid)
            if held is None:
                continue
            entry = dict(held.get("value") or {})
            if entry.get(IDENTITY_KEY) == value:
                return True
            entry[IDENTITY_KEY] = value
            if scope == "project" and adapter.mode_of("connection") == "store":
                adapter.set(NAME, "connection", cid, entry, scope=scope, own=True)
            else:
                adapter.set(NAME, "connection", cid, entry, scope=scope)
            return True
    except (StoreError, OSError):
        return False
    return False


# --- Writing connections and the machine's setup -----------------------------
#
# `connection add|remove` and `setup` are the one way every capability takes a
# connection or a machine prerequisite from a person: the fields are the ones
# the script declares (CONN_FIELDS, SETUP_FIELDS), a secret arrives on standard
# input and never on argv, and it is sealed into the agent's vault, never into
# a record. A connection the store shares (its owner null) carries its secret
# in the vault of every agent granted it: the writer seals it under its own key
# and for each other grantee's public sealing key. A file takes it only when
# asked (--file), at the machine's scope where no grantee's vault takes it, or
# where no vault here takes it: the project's .env.local, or the capability's
# credentials.env in the user's config home.

def _vault_agent() -> tuple[str | None, str | None]:
    """(the agent whose vault a secret written here goes into, None), or (None,
    why there is none)."""
    root = _project_root()
    if root is None:
        return None, "there is no project here, and a vault is an agent's"
    agent = _project_id(write=True, refuse=False)
    if not agent:
        return None, "this project has no settled agent id"
    return agent, None


def _vault_key_here() -> bool:
    """Whether the agent's key is set for this folder, so it keeps a vault."""
    try:
        from capabilities_contract import vault as _vault
    except ImportError:
        return False
    return _project_root() is not None and bool(_vault.key_source(_project_root())[0])


def _vault_writer() -> str:
    try:
        return f"{_user_name()}@{node_name()}"
    except Exception:
        return NAME


def _shared_grantees(cid: str | None) -> list | None:
    """The agents a grant enables connection `cid` for, where it is a row of
    the store the capability shares (its owner null); None for any other
    connection - an agent's own, one kept in files, or none yet."""
    if not cid:
        return None
    try:
        held = getattr(_records(), "shared_grantees", None)
        return held(NAME, cid) if held is not None else None
    except StoreError:
        return None


def _vault_share(agent: str | None, secrets: dict, agents: list,
                 replace: bool = True) -> dict:
    """Seal `secrets` into the vault of each of `agents`: the writer `agent`'s
    under its key here, every other one's for its public sealing key. The
    library's answer (`capabilities_contract.vault.share`); VaultError where
    it refuses."""
    from capabilities_contract import vault as _vault
    done = _vault.share(_project_root(), agent, secrets, agents, replace=replace,
                        application_name=NAME, updated_by=_vault_writer())
    if agent in done.get("sealed", {}):
        for key in secrets:
            _VAULT_UNREAD.pop(key, None)
    return done


def _shared_report(done: dict) -> dict:
    """What sealing a shared connection's secret answers: the agents it was
    sealed for, and each grantee whose public sealing key is not published,
    with how it is."""
    out = {"sealed_for": sorted(done.get("sealed") or {}),
           "unpublished": list(done.get("unpublished") or [])}
    if done.get("unregistered"):
        out["unregistered"] = list(done["unregistered"])
    if out["unpublished"]:
        out["hint"] = done.get("hint")
    return out


def _vault_seal(secrets: dict, cid: str | None = None,
                report: dict | None = None) -> tuple[str | None, str | None]:
    """Seal `secrets` into the agent's vault: ("vault:<agent>", None) once they
    are, or (None, why not) with nothing sealed. The vault is read before every
    file of the cascade, so a key a file also sets resolves from the vault from
    then on. For a connection the store shares, every agent granted it gets
    the secret in its vault too, sealed for its public key; `report`, where
    given, takes `shared`, the agents it reached and those it could not."""
    agent, why = _vault_agent()
    if agent is None:
        return None, why
    try:
        from capabilities_contract import vault as _vault
    except ImportError:
        return None, "this capability's library carries no vault"
    if not hasattr(_vault, "write"):
        return None, "this capability's library cannot write the vault"
    grantees = _shared_grantees(cid)
    try:
        if grantees and hasattr(_vault, "share"):
            done = _vault_share(agent, secrets, sorted({agent, *grantees}))
            if agent not in done.get("sealed", {}):
                return None, f"agent {agent} could not be sealed for"
            if report is not None:
                report["shared"] = _shared_report(done)
        else:
            _vault.write(_project_root(), agent, secrets, application_name=NAME,
                         updated_by=_vault_writer())
    except _vault.VaultError as e:
        return None, e.message
    for key in secrets:
        _VAULT_UNREAD.pop(key, None)
    return f"vault:{agent}", None


def _machine_seal(secrets: dict, cid: str, report: dict) -> str | None:
    """At the machine's scope, seal a shared connection's secret for every
    agent granted it, where the store shares it and grants it to any:
    "vault:<agent>,..." once sealed, else None, and the file takes it as
    before. `report` takes `shared`."""
    grantees = _shared_grantees(cid)
    if not grantees:
        return None
    try:
        from capabilities_contract import vault as _vault
    except ImportError:
        return None
    if not hasattr(_vault, "share"):
        return None
    agent = _vault_agent()[0] if _project_root() is not None else None
    if agent is not None and not _vault.key_source(_project_root())[0]:
        agent = None
    try:
        done = _vault_share(agent, secrets, sorted(grantees))
    except _vault.VaultError as e:
        report["vault_skipped"] = e.message
        return None
    report["shared"] = _shared_report(done)
    if not done.get("sealed"):
        return None
    return ",".join(f"vault:{a}" for a in sorted(done["sealed"]))


def _vault_unseal(keys: list) -> tuple[list, str | None]:
    """Take `keys` out of the agent's vault where this folder has the agent's
    key: (the keys that were there, None), or ([], why it was not asked)."""
    if not keys:
        return [], None
    agent, why = _vault_agent()
    if agent is None:
        return [], why
    try:
        from capabilities_contract import vault as _vault
    except ImportError:
        return [], "this capability's library carries no vault"
    if not hasattr(_vault, "delete"):
        return [], "this capability's library cannot write the vault"
    if not _vault.key_source(_project_root())[0]:
        return [], f"this agent has no {_vault.KEY_ENV} here"
    try:
        return _vault.delete(_project_root(), agent, keys, application_name=NAME), None
    except _vault.VaultError as e:
        return [], e.message


def _env_file_key(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        return None
    key = stripped.split("=", 1)[0].strip()
    if key.startswith("export "):
        key = key[len("export "):].strip()
    return key


def _env_file_write(path: Path, values: dict) -> None:
    """Set or drop keys in an env file, keeping every other line as it was.

    A value of None drops its key. Values are written single-quoted, which the
    contract's parser reads back whole, the file is replaced atomically at mode
    0600, and every write is proven by reading it back through that parser."""
    for key, value in values.items():
        if value is not None and ("'" in value or "\n" in value or "\r" in value):
            _die(6, "input", f"the value for {key} holds a quote or a line break, "
                 "which an env file cannot carry")
    lines = path.read_text().splitlines() if path.exists() else []
    out, done = [], set()
    for line in lines:
        key = _env_file_key(line)
        if key in values:
            if key not in done and values[key] is not None:
                out.append(f"{key}='{values[key]}'")
            done.add(key)
            continue
        out.append(line)
    for key, value in values.items():
        if key not in done and value is not None:
            out.append(f"{key}='{value}'")
    path.parent.mkdir(parents=True, exist_ok=True)
    spare = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(spare, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write("\n".join(out) + ("\n" if out else ""))
        os.chmod(spare, 0o600)
        os.replace(spare, path)
    finally:
        if spare.exists():
            spare.unlink()
    os.chmod(path, 0o600)
    held = _parse_env_file(path)
    for key, value in values.items():
        if held.get(key) != value and not (value is None and key not in held):
            _die(5, "credentials_write_failed",
                 f"{path} does not read back what was written for {key}")


def _field_args(argv: list[str], usage: str) -> tuple[dict, list[str], bool]:
    """`--field KEY=VALUE` pairs, the remaining words, and whether `--stdin`
    was asked for."""
    fields, words, stdin = {}, [], False
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--field":
            if i + 1 >= len(argv) or "=" not in argv[i + 1]:
                _die(6, "input", "--field takes KEY=VALUE", usage)
            key, value = argv[i + 1].split("=", 1)
            fields[key.strip()] = value
            i += 2
        elif arg.startswith("--field="):
            pair = arg[len("--field="):]
            if "=" not in pair:
                _die(6, "input", "--field takes KEY=VALUE", usage)
            key, value = pair.split("=", 1)
            fields[key.strip()] = value
            i += 1
        elif arg == "--stdin":
            stdin = True
            i += 1
        else:
            words.append(arg)
            i += 1
    return fields, words, stdin


def _declared_values(declared: list, argv_values: dict, stdin: bool,
                     what: str) -> dict:
    """The values a person gave, each checked against its declared field: argv
    carries no secret, stdin carries a JSON object, and null clears a field."""
    by_key = {f["key"]: f for f in declared}
    given: dict = {}
    for key, raw in argv_values.items():
        field = by_key.get(key)
        if field is None:
            _die(6, "unknown_field", f"{NAME} declares no {what} field {key!r}",
                 f"fields: {', '.join(by_key) or 'none'}")
        if field.get("secret"):
            _die(6, "secret_on_argv", f"{key} is a secret and is never taken on argv",
                 "pass it in the JSON object on stdin with --stdin")
        try:
            given[key] = _field_value(field, raw, from_argv=True)
        except ValueError as e:
            _die(6, "bad_field", str(e))
    if stdin:
        for key, raw in _stdin_document(f"the {what} fields").items():
            field = by_key.get(key)
            if field is None:
                _die(6, "unknown_field", f"{NAME} declares no {what} field {key!r}",
                     f"fields: {', '.join(by_key) or 'none'}")
            if raw is None:
                given[key] = None
                continue
            try:
                given[key] = _field_value(field, raw)
            except ValueError as e:
                _die(6, "bad_field", str(e))
    return given


def _connection_env_name(field: dict, cid: str) -> str:
    """The env key a secret field's value is written under for one connection,
    its template's `{ID}` filled from `cid`: the label a connection is added
    under, which is its id in files. The key is kept in the connection's spec
    when it is added, so nothing recomputes it later."""
    import re as _re
    ident = _re.sub(r"[^A-Z0-9]", "_", cid.upper())
    template = field.get("env") or (
        f"{_re.sub(r'[^A-Z0-9]', '_', NAME.upper())}_{{ID}}_"
        f"{_re.sub(r'[^A-Z0-9]', '_', field['key'].upper().removesuffix('_ENV'))}")
    return template.replace("{ID}", ident)


def _connection_scope(words: list[str], usage: str) -> tuple[str, list[str]]:
    """The scope a connection is written at. `--machine` is the machine's
    scope, `--global`'s, named as administration of the machine
    (`_machine_administration`), so it cannot be asked of a project."""
    scope = "project"
    rest = []
    for word in words:
        if word in ("--project", "--global", "--machine"):
            scope = word[2:]
        else:
            rest.append(word)
    if "--machine" in words and "--project" in words:
        _die(6, "input", "--machine writes the machine's connection, --project this "
             "project's; pass one", usage)
    return ("global" if scope == "machine" else scope), rest


def _connection_grantees(adapter, cid: str, scope: str, root) -> list:
    """The projects a connection removed at `scope` is granted to and would be
    taken from: every project the store holds an enabling grant for, for a
    connection kept in the store, the machine's included once the store holds
    the global rows; the project the call runs in, for a
    connection of the machine it grants and does not declare itself. A
    project's own connection in its files is granted to no other project, and
    neither is an agent's own connection in the store."""
    if scope == "global":
        # A machine connection that is a row of the store's is one row every
        # agent may be granted, and removing it takes it from each of them.
        held = getattr(adapter, "global_grantees", None)
        stored = held(NAME, cid) if held is not None else []
        if stored:
            return stored
        if root is None or adapter.mode_of("grant") != "files":
            return []
        grant = (adapter.resolve_scope(NAME, "grant", "project").get(cid) or {}).get("value")
        own = (adapter.resolve_scope(NAME, "connection", "project").get(cid) or {}).get("value")
        if isinstance(grant, dict) and grant.get("enabled") is True and not own:
            return [str(root)]
        return []
    if adapter.mode_of("connection") == "store":
        grantees = adapter.grantees(NAME, cid)
        if adapter.project_id and adapter.connection_owner(NAME, cid) == adapter.project_id:
            return [agent for agent in grantees if agent != adapter.project_id]
        return grantees
    return []


# Where a machine-held value comes from, by tier: the machine's files and the
# process environment, which another node does not have.
_MACHINE_TIERS = ("user", "env")


def _connection_prefilled(cid: str, entry: dict, declared: list, given: set,
                          sealing: dict) -> list:
    """Write into a new connection the values the machine holds for it, so it
    carries them from then on: what the capability's `_connection_prefill(cid,
    entry)` hook answers ({"fields": {...}, "secrets": {env key: value}}, such
    as an app of its own copied from the machine's), and the value of each
    secret the entry names that resolves from the machine's files or the
    process environment. Sealed into the agent's vault, and only there: where
    no vault takes them nothing is prefilled and the entry stays as it was
    (`sealing["prefill_skipped"]` says why). [{key, from}] for each value."""
    fields: dict = {}
    values: dict = {}
    origin: dict = {}
    hook = globals().get("_connection_prefill")
    if callable(hook):
        offered = hook(cid, dict(entry)) or {}
        fields = {k: v for k, v in (offered.get("fields") or {}).items()
                  if k not in entry}
        values = dict(offered.get("secrets") or {})
        origin.update({key: "machine" for key in values})
    named = dict(entry, **fields)
    for field in declared:
        env_key = named.get(field["key"]) if field.get("secret") else None
        if not isinstance(env_key, str) or not env_key or env_key in given or env_key in values:
            continue
        value, tier, source = _resolve_env_key(env_key)
        if value and tier in _MACHINE_TIERS:
            values[env_key] = value
            origin[env_key] = str(source) if source else tier
    if not values and not fields:
        return []
    if values:
        sealed, why = _vault_seal(values)
        if sealed is None:
            # A project with no agent key here keeps no vault, and sees no
            # change: nothing is copied and nothing more is said.
            if _vault_key_here():
                sealing["prefill_skipped"] = why
            return []
    entry.update(fields)
    return ([{"key": key, "from": "machine"} for key in sorted(fields)]
            + [{"key": key, "from": origin.get(key)} for key in sorted(values)])


def _scope_credentials(scope: str) -> Path:
    if scope == "global":
        return CREDENTIALS_ENV
    return _project_root() / ".env.local"


def _cmd_connection(argv: list[str]) -> None:
    """`connection add <id>` writes one connection from its declared fields,
    its secrets into the agent's vault, or the scope's credentials file at the
    machine's scope, with --file, or where no vault here takes them;
    `connection remove <id>` takes it out again with the secrets it wrote."""
    usage = (f"{NAME} connection add <id> [--project|--global|--machine] [--default] "
             "[--replace] [--file] [--field KEY=VALUE ...] [--env KEY=ENV_KEY ...] [--stdin] "
             "[--identity ID [--display-name TEXT]] | "
             f"{NAME} connection remove <id> [--project|--global|--machine] | "
             f"{NAME} connection rename <id> <label> | "
             f"{NAME} connection seal [<id>] [--share]")
    import re as _re
    sub = argv[0] if argv else ""
    if sub == "rename":
        return _cmd_connection_rename(argv[1:], usage)
    if sub == "seal":
        return _cmd_connection_seal(argv[1:], usage)
    if sub not in ("add", "remove"):
        _die(6, "input", f"unknown connection subcommand {sub!r}", usage)
    # `--env KEY=ENV_KEY` names, for a secret field, an env key already set,
    # so the entry points at it and no value is copied.
    named: dict = {}
    rest_argv: list = []
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--env" or arg.startswith("--env="):
            pair = arg[len("--env="):] if arg.startswith("--env=") else (
                argv[i + 1] if i + 1 < len(argv) else "")
            if "=" not in pair:
                _die(6, "input", "--env takes KEY=ENV_KEY", usage)
            key, env_key = pair.split("=", 1)
            named[key.strip()] = env_key.strip()
            i += 1 if arg.startswith("--env=") else 2
        else:
            rest_argv.append(arg)
            i += 1
    if named and sub != "add":
        _die(6, "input", "--env is an option of connection add", usage)
    identity_given: dict = {}
    words_left: list = []
    i = 0
    while i < len(rest_argv):
        arg = rest_argv[i]
        option = next((o for o in ("--identity", "--display-name")
                       if arg == o or arg.startswith(o + "=")), None)
        if option is None:
            words_left.append(arg)
            i += 1
            continue
        if arg.startswith(option + "="):
            identity_given[option] = arg[len(option) + 1:]
            i += 1
        elif i + 1 < len(rest_argv):
            identity_given[option] = rest_argv[i + 1]
            i += 2
        else:
            _die(6, "input", f"{option} takes a value", usage)
    rest_argv = words_left
    if identity_given and sub != "add":
        _die(6, "input", "--identity and --display-name are options of connection add",
             usage)
    argv_values, words, stdin = _field_args(rest_argv, usage)
    default = "--default" in words
    replace = "--replace" in words
    to_file = "--file" in words
    if replace and sub != "add":
        _die(6, "input", "--replace is an option of connection add", usage)
    if to_file and sub != "add":
        _die(6, "input", "--file is an option of connection add", usage)
    words = [w for w in words if w not in ("--default", "--replace", "--file")]
    scope, rest = _connection_scope(words, usage)
    flags = [w for w in rest if w.startswith("--")]
    if flags:
        _die(6, "input", f"unknown connection option {flags[0]!r}", usage)
    if len(rest) != 1:
        _die(6, "input", f"connection {sub} names one connection id", usage)
    cid = rest[0]
    if not _re.fullmatch(r"[a-z0-9][a-z0-9._@+-]{0,127}", cid, _re.IGNORECASE):
        # A connection is named by its label as well as its id.
        cid = _labelled(cid) or cid
    if not _re.fullmatch(r"[a-z0-9][a-z0-9._@+-]{0,127}", cid, _re.IGNORECASE):
        _die(6, "input", f"connection id {cid!r} is letters, digits and . _ @ + -")
    _read_only_gate(f"`{NAME} connection {sub}`")
    declared = globals().get("CONN_FIELDS")
    if declared is None:
        _die(6, "connection_fields_undeclared",
             f"{NAME} does not declare its connection fields",
             f"`{NAME} help` says how its connections are written")
    root = _project_root()
    if scope == "project":
        if root is None:
            _die(6, "no_project", f"--project writes this project's {NAME} connection "
                 "and there is no project here", "run it inside the project, or pass --global")
        if not _project_capabilities_dir(root).is_dir():
            _die(6, "no_envelope", "no capabilities/ envelope in this project",
                 "run `capabilities init` first")
    adapter = _records()
    try:
        held = adapter.resolve_scope(NAME, "connection", scope).get(cid)
        if held is None and _labelled(cid) is not None:
            cid = _labelled(cid)
            held = adapter.resolve_scope(NAME, "connection", scope).get(cid)
    except StoreError as e:
        _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)
    existing = dict((held or {}).get("value") or {})
    credentials = _scope_credentials(scope)

    if sub == "remove":
        if held is None:
            _die(3, "unknown_connection", f"no {scope} connection {cid!r}",
                 f"`{NAME} connections` lists them")
        try:
            grantees = _connection_grantees(adapter, cid, scope, root)
        except StoreError as e:
            _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)
        if grantees:
            _die(6, "connection_granted",
                 f"connection {cid!r} is granted to {len(grantees)} project(s), so "
                 f"removing it would take it from them: {', '.join(grantees)}",
                 "ask the user; each project switches its grant off first, with "
                 f"`capabilities set {NAME} grant {cid} '{{\"enabled\": false}}'` "
                 "run in that project")
        others = {}
        label = _connection_label(cid)
        mine = {field["key"]: _connection_field_keys(field, cid)
                for field in declared if field.get("secret")}
        try:
            for other, row in adapter.resolve_scope(NAME, "connection", scope).items():
                if other != cid:
                    others[other] = row.get("value") or {}
            pointer = adapter.resolve_scope(NAME, "setting", scope).get("connection.default")
            adapter.delete(NAME, "connection", cid, scope=scope)
            was_default = bool(pointer and pointer.get("value") in (cid, label))
            if was_default:
                adapter.delete(NAME, "setting", "connection.default", scope=scope)
            source = adapter.scope_source(NAME, "connection", scope)
        except StoreError as e:
            _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)
        own, kept = [], []
        for field in declared:
            env_key = existing.get(field["key"]) if field.get("secret") else None
            if not isinstance(env_key, str) or not env_key:
                continue
            shared = any(entry.get(field["key"]) == env_key for entry in others.values())
            if env_key in mine.get(field["key"], ()) and not shared:
                own.append(env_key)
            else:
                kept.append(env_key)
        held_in_file = _parse_env_file(credentials)
        removed = [key for key in own if key in held_in_file]
        if removed:
            _env_file_write(credentials, {key: None for key in removed})
        # The machine's scope writes no vault; a project's own secret may be in either.
        unsealed, unread = _vault_unseal(own) if scope == "project" else ([], None)
        kept += [key for key in own if key not in removed and key not in unsealed]
        out = {"ok": True, "action": "remove", "connection": cid, "label": label,
               "scope": scope, "registry": source, "default_cleared": was_default,
               "credentials": str(credentials) if removed else None,
               "secrets_removed": removed, "vault_removed": unsealed,
               "secrets_kept": kept}
        if unread and kept:
            out["vault_not_read"] = unread
        _emit(out)
        return

    if held is not None and not replace:
        _die(6, "connection_exists",
             f"a {scope} connection {cid!r} already exists, and connection add "
             "writes over it only when asked to",
             f"pass --replace to change it, keeping every field not given; "
             f"`{NAME} connections` shows it as it resolves")
    given = _declared_values(declared, argv_values, stdin, "connection")
    by_key = {f["key"]: f for f in declared}
    for key, env_key in named.items():
        if key not in by_key:
            _die(6, "unknown_field", f"{NAME} declares no connection field {key!r}",
                 f"fields: {', '.join(by_key) or 'none'}")
        if not by_key[key].get("secret"):
            _die(6, "input", f"--env names the env key of a secret field, and {key} is "
                 "not one", f"give {key} with --field {key}=VALUE")
        if key in given:
            _die(6, "input", f"{key} is given both as a value and as an env key name",
                 "pass one")
        # The name is not echoed: a secret given here by mistake stays off the output.
        if not _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", env_key):
            _die(6, "bad_field", f"--env {key} takes the name of an env key")
        if not _resolve_env_key(env_key)[0]:
            _die(6, "env_key_unset",
                 f"the env key --env names for {key} is set in none of the project's "
                 f".env.local or .env, {CREDENTIALS_ENV}, the environment, or the "
                 "agent's vault",
                 "set it there first, or give the secret itself in the JSON object "
                 "on stdin")
    entry = dict(existing)
    secrets: dict = {}
    # A new connection is called by the word it is added under, and its env
    # keys are filled from that label; one that exists keeps its own keys.
    label = _connection_label(cid) if held is not None else cid

    def own_key(field: dict) -> str:
        held_key = existing.get(field["key"])
        if held is not None and isinstance(held_key, str) \
                and held_key in _connection_field_keys(field, cid):
            return held_key
        return _connection_env_name(field, label)

    for field in declared:
        key = field["key"]
        if key in named:
            entry[key] = named[key]
        elif key in given:
            value = given[key]
            if value is None:
                entry.pop(key, None)
            elif field.get("secret"):
                # Always this connection's own key: a key the entry named
                # before may be shared with another connection.
                env_key = own_key(field)
                secrets[env_key] = value
                entry[key] = env_key
            else:
                entry[key] = value
        elif key not in entry and field.get("secret") and field.get("required"):
            env_key = own_key(field)
            if _resolve_env_key(env_key)[0]:
                entry[key] = env_key
        elif key not in entry and field.get("default") is not None and field.get("required"):
            entry[key] = field["default"]
    if identity_given:
        ident = identity_given.get("--identity")
        held_identity = entry.get(IDENTITY_KEY)
        if ident == "":
            if "--display-name" in identity_given:
                _die(6, "input", "--identity '' clears the identity, and takes no "
                     "--display-name", usage)
            entry.pop(IDENTITY_KEY, None)
        else:
            if ident is None:
                if not isinstance(held_identity, dict) or not held_identity.get("id"):
                    _die(6, "input", f"connection {cid!r} records no identity to name",
                         "give --identity ID with --display-name")
                ident = held_identity["id"]
            name = identity_given.get("--display-name",
                                      (held_identity or {}).get("display_name")
                                      if "--identity" not in identity_given else None)
            try:
                entry[IDENTITY_KEY] = _identity_value(ident, name)
            except ValueError as e:
                _die(6, "bad_field", str(e))
    sealing: dict = {}
    prefilled = None
    if held is None and scope == "project" and not to_file:
        # Values the machine holds for a new connection are written into it,
        # and are its own from then on: kept only where its vault takes them.
        prefilled = _connection_prefilled(cid, entry, declared, set(secrets), sealing)
    missing = [f["key"] for f in declared if f.get("required") and entry.get(f["key"]) in (None, "")]
    if missing:
        _die(6, "fields_required", f"connection {cid!r} needs: {', '.join(missing)}",
             f"`{NAME} manifest` lists the fields; secrets go in the JSON object on stdin")
    secrets_in, vault_skipped = None, None
    if secrets and scope == "project" and not to_file:
        secrets_in, vault_skipped = _vault_seal(secrets, cid, sealing)
    elif secrets and scope == "global" and not to_file:
        secrets_in = _machine_seal(secrets, cid, sealing)
        vault_skipped = sealing.pop("vault_skipped", None)
    if secrets and secrets_in is None:
        _env_file_write(credentials, secrets)
        secrets_in = str(credentials)
    try:
        if scope == "project" and adapter.mode_of("connection") == "store":
            # A connection added in a project in store mode is the project's
            # own, written with its grant.
            written = adapter.set(NAME, "connection", cid, entry, scope=scope, own=True)
        else:
            written = adapter.set(NAME, "connection", cid, entry, scope=scope)
        # The store mints a new connection's id; in files the id is the key.
        cid = written if isinstance(written, str) and written else cid
        if default:
            adapter.set(NAME, "setting", "connection.default", cid, scope=scope)
        source = adapter.scope_source(NAME, "connection", scope)
    except StoreError as e:
        _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)
    report = []
    for field in declared:
        value = entry.get(field["key"])
        row = {"key": field["key"], "secret": bool(field.get("secret")),
               "set": value not in (None, "")}
        if field.get("secret") and isinstance(value, str) and value:
            resolved, tier, where = _resolve_env_key(value)
            row.update({"env": value, "set": bool(resolved), "tier": tier,
                        "source": str(where) if where else None,
                        "value": _mask(resolved) if resolved else None})
        else:
            row["value"] = value
        report.append(row)
    out = {"ok": True, "action": "add" if held is None else "update",
           "connection": cid, "label": label, "scope": scope, "registry": source,
           "credentials": secrets_in if secrets and secrets_in == str(credentials) else None,
           "secrets_in": secrets_in, "default": default, "fields": report,
           "identity": _connection_identity(entry),
           "next": f"`{NAME} doctor --connection {label}` proves it"}
    if vault_skipped:
        out["vault_skipped"] = vault_skipped
    if sealing.get("shared"):
        out["shared"] = sealing["shared"]
    if prefilled:
        out["prefilled"] = prefilled
    if sealing.get("prefill_skipped"):
        out["prefill_skipped"] = sealing["prefill_skipped"]
    methods = globals().get("LINK_METHODS") or []
    if methods:
        out["link"] = [m.get("id") for m in methods]
        out["next"] = (f"link it with one of `{NAME} manifest`'s connections.link "
                       f"methods, adding --connection {label}")
    if root is not None:
        # Whether this project may use what was just written: a project in
        # store mode keeps even its own connection usable only through a grant.
        # The write has happened, so a registry that cannot be read here
        # leaves the answer unsaid rather than refusing it.
        try:
            usable = adapter.connections(NAME, write_default=WRITE_DEFAULT,
                                         include_disabled=True).get(cid)
        except StoreError:
            usable = None
        if usable is not None:
            out["granted"] = bool(usable.get("enabled"))
        if scope == "global" or out.get("granted") is False:
            out["hint"] = _grant_hint(cid)
    _emit(out)


# The names a connection never carries in the vault: the agent's key, its id
# and the store setting are read before the vault can be.
_SEAL_NEVER = ("AGENT_ENCRYPTION_KEY", "CAPABILITIES_PROJECT_ID", "CAPABILITIES_PROJECT_ID_ROOT")


def _sealable(row: object) -> bool:
    """Whether a row of a connection's report names an env key the vault may
    carry: not a value the connection's record states itself (tier
    `connection`, or a field's own lower-case name), and none read before the
    vault can be."""
    import re as _re
    key = row.get("key") if isinstance(row, dict) else None
    return (isinstance(key, str) and bool(_re.fullmatch(r"[A-Z_][A-Z0-9_]{0,254}", key))
            and row.get("tier") != "connection"
            and key not in _SEAL_NEVER and not key.startswith("AGENTKIT_"))


def _own_report() -> dict:
    """{connection: entry} of the capability's own `connections` report, each
    entry's `keys` the per-key resolution doctor gates on; {} where it
    refuses."""
    import contextlib
    import io
    captured = io.StringIO()
    try:
        with contextlib.redirect_stdout(captured):
            _cmd_connections()
    except SystemExit:
        return {}
    try:
        report = json.loads(captured.getvalue())
    except ValueError:
        return {}
    conns = report.get("connections") if isinstance(report, dict) else None
    return conns if isinstance(conns, dict) else {}


def _connection_rewrite(cid: str, fields: dict) -> bool:
    """Write `fields` into connection `cid`'s own record, at the scope that
    holds it, where they change it; whether the record holds them now."""
    adapter = _records()
    scopes = ["project", "global"] if _project_root() is not None else ["global"]
    for scope in scopes:
        held = adapter.resolve_scope(NAME, "connection", scope).get(cid)
        if held is None:
            continue
        entry = dict(held.get("value") or {})
        if all(entry.get(k) == v for k, v in fields.items()):
            return True
        entry.update(fields)
        if scope == "project" and adapter.mode_of("connection") == "store":
            adapter.set(NAME, "connection", cid, entry, scope=scope, own=True)
        else:
            adapter.set(NAME, "connection", cid, entry, scope=scope)
        return True
    return False


def _connection_field_keys(field: dict, cid: str) -> set:
    """The env keys that are connection `cid`'s own for one secret field: the
    one its template gives for the connection's label, and for the name it
    was keyed by before its id, where it had one (`_connection_former_name`)."""
    words = {_connection_label(cid) if cid else cid}
    former = _connection_former_name(cid)
    if former:
        words.add(former)
    return {_connection_env_name(field, word) for word in words if word}


def _connection_own_keys(cid: str) -> set:
    """The env keys that are connection `cid`'s alone: the ones each declared
    secret field is written under for it (`_connection_field_keys`)."""
    return {key for field in globals().get("CONN_FIELDS") or [] if field.get("secret")
            for key in _connection_field_keys(field, cid)}


def _cmd_connection_seal(argv: list[str], usage: str) -> None:
    """`connection seal [<id>] [--share]` writes into each connection this
    project may use (or the one named) the values it resolves today from the
    project's .env files and the machine's files, sealed into the agent's
    vault, so it resolves them the same on a node that has none of those; a
    value only the process environment holds is the invoking shell's, not the
    connection's, and is left there (`not_sealed`). What the capability's
    `_connection_prefill` hook asks of a connection naming none of its own (an
    app of its own) is written into its record first. With --share a
    connection the store shares is sealed for every other agent granted it
    too, for its public sealing key, from what it resolves here, vault
    included - but only under a key that is the connection's own
    (`_connection_env_name`): a vault answers for every connection of its
    agent, so a name another connection or a setup field may read is never
    written into another agent's vault (`not_shared`). Nothing a vault
    already holds is written over, so running it again changes nothing; a
    grantee whose public key is not published is named, never skipped in
    silence. A file is never changed: once the vault holds a value the
    cascade reads it first."""
    share = "--share" in argv
    words = [w for w in argv if w != "--share"]
    flags = [w for w in words if w.startswith("--")]
    if flags:
        _die(6, "input", f"unknown connection seal option {flags[0]!r}", usage)
    if len(words) > 1:
        _die(6, "input", "connection seal names at most one connection", usage)
    _read_only_gate(f"`{NAME} connection seal`")
    agent, why = _vault_agent()
    if agent is None:
        _die(6, "no_vault", f"there is no vault to seal into: {why}",
             "run it in the agent's folder")
    try:
        from capabilities_contract import vault as _vault
    except ImportError:
        _vault = None
    if _vault is None or not hasattr(_vault, "share"):
        _die(6, "vault_unavailable", "this capability's library cannot seal a connection",
             f"`capabilities update {NAME}` brings the library that does")
    if not _vault.key_source(_project_root())[0]:
        _die(6, "key_missing", f"this agent has no {_vault.KEY_ENV} here",
             "bring the agent's key with `capabilities key set`, or make its first one with "
             "`capabilities key generate`")
    inventory = _inventory_connections().get("connections") or {}
    usable = {cid: entry for cid, entry in inventory.items() if entry.get("granted")}
    if words:
        cid = words[0] if words[0] in inventory else (_labelled(words[0]) or words[0])
        if cid not in inventory:
            _die(3, "unknown_connection", f"no {NAME} connection {words[0]!r}",
                 f"`{NAME} connections` lists them")
        if cid not in usable:
            _grant_gate({"withheld": {cid: {"scope": "project"}}}, cid)
        usable = {cid: usable[cid]}
    unpublished: dict = {}
    results: dict = {}

    def sealed_into(res: dict, done: dict) -> None:
        for whom, names in (done.get("sealed") or {}).items():
            res["sealed"].setdefault(whom, [])
            res["sealed"][whom] = sorted(set(res["sealed"][whom]) | set(names))
        for whom, names in (done.get("unchanged") or {}).items():
            res["unchanged"] = sorted(set(res["unchanged"]) | set(names))
        for whom in done.get("unpublished") or []:
            unpublished.setdefault(whom, set()).add(cid)
            res["unpublished"] = sorted(set(res["unpublished"]) | {whom})

    hook = globals().get("_connection_prefill")
    try:
        for cid, entry in sorted(usable.items()):
            res = {"label": entry.get("label") or cid, "shared": False, "sealed": {},
                   "unchanged": [], "unresolved": [], "from": {}, "unpublished": []}
            results[cid] = res
            grantees = _shared_grantees(cid)
            res["shared"] = grantees is not None
            others = sorted(set(grantees or []) - {agent}) if share else []
            spec = {k: v for k, v in entry.items()
                    if k not in ("allow_write", "granted", "id", "label")}
            offered = (hook(cid, spec) or {}) if callable(hook) else {}
            fields = {k: v for k, v in (offered.get("fields") or {}).items() if k not in spec}
            values = dict(offered.get("secrets") or {})
            if (fields or values) and (grantees is None or share):
                # A connection's record changes only once every agent it is
                # granted to holds what the change names.
                done = _vault_share(agent, values, [agent, *others], replace=False) \
                    if values else {}
                sealed_into(res, done)
                res["from"].update({key: "machine" for key in values})
                if not done.get("unpublished") and not done.get("unregistered"):
                    if _connection_rewrite(cid, fields):
                        res["spec"] = fields
                else:
                    res["spec_pending"] = fields
        report = _own_report()
        for cid, res in results.items():
            own, everyone = {}, {}
            res["not_sealed"], res["not_shared"] = [], []
            for row in (report.get(cid) or {}).get("keys") or []:
                if not _sealable(row):
                    continue
                key = row["key"]
                value, tier, source = _resolve_env_key(key)
                if not value:
                    if row.get("required"):
                        res["unresolved"].append(key)
                    continue
                if tier == "vault":
                    everyone[key] = value
                    res["from"].setdefault(key, str(source))
                elif tier in ("project", "user"):
                    own[key] = everyone[key] = value
                    res["from"][key] = str(source) if source else tier
                elif tier == "env":
                    res["not_sealed"].append(key)
            if own:
                sealed_into(res, _vault_share(agent, own, [agent], replace=False))
            grantees = _shared_grantees(cid)
            others = sorted(set(grantees or []) - {agent}) if share else []
            if everyone and others:
                mine = _connection_own_keys(cid)
                res["not_shared"] = sorted(key for key in everyone if key not in mine)
                everyone = {k: v for k, v in everyone.items() if k in mine}
            if everyone and others:
                sealed_into(res, _vault_share(agent, everyone, others, replace=False))
            res["unresolved"] = sorted(set(res["unresolved"]))
            res["not_sealed"] = sorted(set(res["not_sealed"]))
    except _vault.VaultError as e:
        _die(5 if e.slug == "vault_unwritable" else 6, e.slug, e.message, e.hint)
    except StoreError as e:
        _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)
    out = {"ok": True, "action": "seal", "capability": NAME, "agent": agent,
           "share": share, "connections": results,
           "unpublished": [{"agent": whom, "connections": sorted(cids)}
                           for whom, cids in sorted(unpublished.items())]}
    if unpublished:
        out["hint"] = _vault.UNPUBLISHED_HINT
    _emit(out)


def _cmd_connection_rename(argv: list[str], usage: str) -> None:
    """`connection rename <id> <label>` changes what a connection is called
    and nothing else: its id, which every grant, default pointer, secret's
    env key and this capability's own state hold, stays, so whoever used it
    by its id keeps it and its label now names it too. The connection is
    named by its id or its current label; renaming it to its id clears the
    label. Only a connection the store holds has a label."""
    flags = [w for w in argv if w.startswith("--")]
    if flags:
        _die(6, "input", f"unknown connection rename option {flags[0]!r}", usage)
    if len(argv) != 2:
        _die(6, "input", "connection rename names one connection and its new label", usage)
    wanted, label = argv
    if (label != label.strip() or not label or len(label) > 128
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in label)):
        _die(6, "input", f"label {label!r} is up to 128 characters with no control "
             "character and no space at either end", usage)
    _read_only_gate(f"`{NAME} connection rename`")
    adapter = _records()
    try:
        held = adapter.connections(NAME, write_default=WRITE_DEFAULT, include_disabled=True)
        cid = wanted if wanted in held else _labelled(wanted)
        if cid is None or cid not in held:
            _die(3, "unknown_connection", f"no {NAME} connection {wanted!r}",
                 f"`{NAME} connections` lists them")
        source = adapter.record_source(NAME, "connection", held[cid]["scope"][0], cid)
        if not str(source).startswith("store:"):
            _die(6, "connection_not_in_store",
                 f"connection {cid!r} is kept in {source}, where a connection is called "
                 "by its id and has no label",
                 "move this project into the store with `capabilities migrate`")
        before = _connection_labels().get(cid)
        adapter.rename_connection(NAME, cid, label)
        after = _records().connection_labels(NAME).get(cid)
    except StoreError as e:
        _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)
    _emit({"ok": True, "action": "rename", "connection": cid, "label": after or cid,
           "previous_label": before or cid, "changed": (before or cid) != (after or cid),
           "registry": source})


def _reveal_args(argv: list[str], usage: str) -> tuple[str | None, list[str]]:
    """The key `--reveal <KEY>` names, if any, and the words around it."""
    reveal, rest = None, []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--reveal" or arg.startswith("--reveal="):
            key = arg[len("--reveal="):] if arg.startswith("--reveal=") else (
                argv[i + 1] if i + 1 < len(argv) else "")
            if not key or key.startswith("--") or reveal is not None:
                _die(6, "input", "--reveal names one key", usage)
            reveal = key
            i += 1 if arg.startswith("--reveal=") else 2
        else:
            rest.append(arg)
            i += 1
    return reveal, rest


def _cmd_connections_show(argv: list[str]) -> None:
    """`connections show <id> --reveal <KEY>` prints one value of one usable
    connection in the clear: the value its declared field KEY resolves to,
    which `connections` reports masked when the field is a secret. The
    connection is selected as every verb selects one, so a connection this
    project may not use is refused, never revealed."""
    usage = f"{NAME} connections show <id> --reveal <KEY>"
    reveal, words = _reveal_args(argv, usage)
    flags = [w for w in words if w.startswith("--")]
    if flags:
        _die(6, "input", f"unknown connections show option {flags[0]!r}", usage)
    if len(words) != 1:
        _die(6, "input", "connections show names one connection id", usage)
    if reveal is None:
        _die(6, "input", "connections show reveals one field and takes --reveal <KEY>",
             f"`{NAME} connections` reports every connection, secrets masked")
    declared = globals().get("CONN_FIELDS")
    if declared is None:
        _die(6, "connection_fields_undeclared",
             f"{NAME} does not declare its connection fields",
             f"`{NAME} connections` reports its connections, secrets masked")
    field = {f["key"]: f for f in declared}.get(reveal)
    if field is None:
        _die(6, "unknown_field", f"{NAME} declares no connection field {reveal!r}",
             f"fields: {', '.join(f['key'] for f in declared) or 'none'}")
    reg, _ = _connections_registry()
    cid, entry = _select_connection(reg, words[0])
    value = (entry or {}).get(reveal)
    if field.get("secret"):
        value = _resolve_env_key(value)[0] if isinstance(value, str) and value else None
    elif isinstance(value, bool):
        value = "true" if value else "false"
    elif isinstance(value, (list, dict)):
        value = json.dumps(value)
    elif value is not None:
        value = str(value)
    if not value:
        _die(3, "not_set", f"connection {cid!r} holds no value for {reveal}",
             f"`{NAME} connections` says where each value resolves from")
    _emit(value)


def _setup_presentation() -> dict:
    """What `SETUP` declares about the machine's setup as a whole - its
    `title`, the `guide` {url, steps} a person follows to obtain the fields,
    and the `verify` verb that asks the remote system whether it accepts them -
    each key only where it is declared."""
    declared = globals().get("SETUP") or {}
    return {key: declared[key] for key in ("title", "guide", "verify") if key in declared}


def _cmd_setup(argv: list[str]) -> None:
    """`setup` reports the machine prerequisites the capability declares and
    where each resolves from; `setup show --reveal <KEY>` prints the one value
    that report masks for KEY, in the clear; `setup set` writes them, secrets
    from stdin: a secret into the agent's vault, every other field - and a
    secret with --machine, with --file, or where no vault here takes it - into
    the capability's credentials.env; `setup unset` takes them out of both.
    A field that declares `shared` is listed under `shared`, apart from
    `fields`, and is written to and removed from the machine's shared.env
    under its shared name, so one value serves every capability that declares
    it; unset also takes the key out of the capability's own credentials.env.
    `--machine` names a write as administration of the machine
    (`_machine_administration`)."""
    usage = (f"{NAME} setup [show] [--reveal <KEY>] | setup set [--machine] [--file] "
             "[--field KEY=VALUE ...] [--stdin] | setup unset [--machine] <KEY> ...")
    declared = list(globals().get("SETUP_FIELDS") or [])
    reveal, argv = _reveal_args(argv, usage)
    sub = argv[0] if argv and not argv[0].startswith("--") else "show"
    rest = argv[1:] if argv and argv[0] == sub else argv
    if sub not in ("show", "set", "unset"):
        _die(6, "input", f"unknown setup subcommand {sub!r}", usage)
    if reveal is not None:
        if sub != "show":
            _die(6, "input", "--reveal is an option of setup show", usage)
        field = {f["key"]: f for f in declared}.get(reveal)
        if field is None:
            _die(6, "unknown_field", f"{NAME} declares no setup field {reveal!r}",
                 f"fields: {', '.join(f['key'] for f in declared) or 'none'}")
        value = _resolve_env_key(reveal)[0]
        if not value:
            _die(3, "not_set", f"setup field {reveal} resolves nowhere",
                 f"`{NAME} setup` says where each field resolves from")
        _emit(value)
        return
    machine = sub != "show" and "--machine" in rest
    to_file = sub == "set" and "--file" in rest
    if sub != "show":
        rest = [w for w in rest if w not in ("--machine", "--file")]
    changed: list = []
    secrets_in, vault_skipped, unsealed = None, None, None
    if sub == "set":
        argv_values, words, stdin = _field_args(rest, usage)
        if words:
            _die(6, "input", f"unexpected {words[0]!r}", usage)
        _read_only_gate(f"`{NAME} setup set`")
        given = _declared_values(declared, argv_values, stdin, "setup")
        if not given:
            _die(6, "input", "setup set was given nothing to set", usage)
        written = {
            key: (None if value is None else
                  ("true" if value is True else "false" if value is False else
                   json.dumps(value) if isinstance(value, (list, dict)) else str(value)))
            for key, value in given.items()}
        own = {key: value for key, value in written.items() if _shared_name(key) is None}
        shared = {_shared_name(key): value for key, value in written.items()
                  if _shared_name(key) is not None}
        secret = {f["key"] for f in declared if f.get("secret")}
        sealed = {key: value for key, value in own.items()
                  if key in secret and value is not None}
        if sealed and not (machine or to_file):
            secrets_in, vault_skipped = _vault_seal(sealed)
            if secrets_in is not None:
                own = {key: value for key, value in own.items() if key not in sealed}
        if sealed and secrets_in is None:
            secrets_in = str(CREDENTIALS_ENV)
        cleared = [key for key, value in own.items() if key in secret and value is None]
        if cleared and not machine:
            unsealed, _why = _vault_unseal(cleared)
        if own:
            _env_file_write(CREDENTIALS_ENV, own)
        if shared:
            _env_file_write(_shared_credentials_env(), shared)
        changed = sorted(given)
    elif sub == "unset":
        keys = [w for w in rest if not w.startswith("--")]
        known = {f["key"] for f in declared}
        unknown = [k for k in keys if k not in known]
        if not keys or unknown:
            _die(6, "unknown_field" if unknown else "input",
                 f"{NAME} declares no setup field {unknown[0]!r}" if unknown
                 else "setup unset names the keys to remove", usage)
        _read_only_gate(f"`{NAME} setup unset`")
        _env_file_write(CREDENTIALS_ENV, {key: None for key in keys})
        if not machine:
            secret = {f["key"] for f in declared if f.get("secret")}
            unsealed, _why = _vault_unseal(
                [key for key in keys if key in secret and _shared_name(key) is None])
        shared = {_shared_name(key): None for key in keys if _shared_name(key) is not None}
        if shared:
            _env_file_write(_shared_credentials_env(), shared)
        changed = sorted(keys)
    fields, shared_fields = [], []
    for field in declared:
        value, tier, source = _resolve_env_key(field["key"])
        secret = bool(field.get("secret"))
        (shared_fields if _shared_name(field["key"]) else fields).append(
            {**field, "set": bool(value), "tier": tier if value else None,
             "source": str(source) if (value and source) else None,
             "value": (_mask(value) if secret else value) if value else None})
    out = {"capability": NAME, "credentials": str(CREDENTIALS_ENV),
           "ready": all(f["set"] for f in fields + shared_fields if f.get("required")),
           "fields": fields, **_setup_presentation()}
    if shared_fields:
        out.update({"shared": shared_fields,
                    "shared_credentials": str(_shared_credentials_env())})
    if sub != "show":
        out.update({"ok": True, "action": sub, "changed": changed})
    if sub == "set":
        out["secrets_in"] = secrets_in
        if vault_skipped:
            out["vault_skipped"] = vault_skipped
    if sub == "unset" or unsealed:
        out["vault_removed"] = unsealed or []
    _emit(out)

