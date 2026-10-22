# The shared capability code - the connections tier: the credential cascade and the connection resolver,
# carried by a capability that implements connections.
#
# This is not a module. `capabilities_contract.capability.bind` executes it in
# the namespace of the capability that binds it, so it reads that capability's
# declarations and calls its hooks as its own code does. See the package
# docstring of `capabilities_contract.capability`.
#

def _resolve_env_key(key: str) -> tuple[str | None, str | None, Path | None]:
    """Resolve one env key through cascade tiers 2-4: project .env(.local) →
    user credentials.env → process env. Returns (value, tier, source)."""
    root = _project_root()
    if root is not None:
        for fname in (".env.local", ".env"):
            val = _parse_env_file(root / fname).get(key)
            if val:
                return val, "project", root / fname
    val = _parse_env_file(CREDENTIALS_ENV).get(key)
    if val:
        return val, "user", CREDENTIALS_ENV
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
    if entry.get("scope") == "project":
        message = f"connection {cid!r} is disabled in this project"
    elif _machine_read():
        message = (f"connection {cid!r} is switched off on this machine by "
                   f"its grant")
    elif _project_root() is None:
        message = (f"connection {cid!r} is declared globally and there is no "
                   f"project here to grant it in")
    else:
        message = (f"connection {cid!r} is declared outside this project and "
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
        named = ", ".join(sorted(withheld))
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
    sources = {cid: adapter.scope_source(NAME, "connection", entry["scope"][0])
               for cid, entry in usable.items()}
    _MACHINE_LENT.update({cid: sources[cid] for cid, entry in usable.items()
                          if entry.get("machine_read")})
    return {
        "default": default,
        "connections": {cid: {**entry["value"], "allow_write": entry["allow_write"]}
                        for cid, entry in usable.items()},
        "sources": sources,
        "withheld": {cid: {"scope": entry["scope"][0]}
                     for cid, entry in withheld.items()},
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
                      "granted": bool(entry["enabled"])}
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


def _select_connection(reg: dict | None, wanted: str | None) -> tuple[str, dict | None]:
    """flag → default pointer → sole entry → die 6. A connection's own
    `address` field selects it too (used where a
    connection carries a human-recognizable address; absent fields never match).

    A connection the project was never granted is refused here rather than
    reported missing, so the one enforcement point every capability already
    routes through is also the one that answers "why not"."""
    if reg is None:
        _die(6, "connections_required",
             f"{NAME} requires an explicit connections registry")
    conns = reg["connections"]
    if wanted:
        if wanted in conns:
            return wanted, conns[wanted]
        for cid, entry in conns.items():
            if (entry or {}).get("address", "").lower() == wanted.lower():
                return cid, entry
        _grant_gate(reg, wanted)
        _die(6, "unknown_connection", f"no connection matches {wanted!r}",
             f"known: {', '.join(conns)}")
    default = reg.get("default")
    if default:
        if default not in conns:
            _grant_gate(reg, default)
            _die(6, "bad_default", f"default points to unknown connection {default!r}",
                 f"known: {', '.join(conns)}")
        return default, conns[default]
    if len(conns) == 1:
        cid = next(iter(conns))
        return cid, conns[cid]
    _die(6, "ambiguous_connection",
         f"registry defines {len(conns)} connections and no default; "
         f"pass --connection <id>",
         f"known: {', '.join(conns)}")


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
    return {"key": key, "secret": secret, "required": required,
            "set": bool(value), "tier": tier if value else None,
            "source": str(source) if (value and source) else None,
            "value": (_mask(value) if secret else value) if value else None}


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
    targets = [wanted] if (wanted and wanted in conns) else list(conns)
    problems: dict = {}
    for cid in targets:
        miss = _missing_required((conns.get(cid) or {}).get("keys") or [])
        if miss:
            problems[cid] = miss
    if problems:
        detail = "; ".join(f"{c}: {', '.join(ks)}" for c, ks in sorted(problems.items()))
        _die(2, "credentials_missing",
             f"unresolved required config — {detail}",
             f"set each in the project .env/.env.local, the user credentials.env, "
             f"or process env; `{NAME} connections` shows where every value resolves")


# --- Writing connections and the machine's setup -----------------------------
#
# `connection add|remove` and `setup` are the one way every capability takes a
# connection or a machine prerequisite from a person: the fields are the ones
# the script declares (CONN_FIELDS, SETUP_FIELDS), a secret arrives on standard
# input and never on argv, and it is written to the credentials file of the
# scope the record lands in - the project's .env.local, or the capability's
# credentials.env in the user's config home - never into a record.

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
    """The env key a secret field's value is written under for one connection."""
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
    connection kept in the store; the project the call runs in, for a
    connection of the machine it grants and does not declare itself. A
    project's own connection in its files is granted to no other project, and
    neither is an agent's own connection in the store."""
    if scope == "global":
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


def _scope_credentials(scope: str) -> Path:
    if scope == "global":
        return CREDENTIALS_ENV
    return _project_root() / ".env.local"


def _cmd_connection(argv: list[str]) -> None:
    """`connection add <id>` writes one connection from its declared fields,
    its secrets into the scope's credentials file; `connection remove <id>`
    takes it out again with the secrets it wrote."""
    usage = (f"{NAME} connection add <id> [--project|--global|--machine] [--default] "
             "[--replace] [--field KEY=VALUE ...] [--env KEY=ENV_KEY ...] [--stdin] | "
             f"{NAME} connection remove <id> [--project|--global|--machine]")
    import re as _re
    sub = argv[0] if argv else ""
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
    argv_values, words, stdin = _field_args(rest_argv, usage)
    default = "--default" in words
    replace = "--replace" in words
    if replace and sub != "add":
        _die(6, "input", "--replace is an option of connection add", usage)
    words = [w for w in words if w not in ("--default", "--replace")]
    scope, rest = _connection_scope(words, usage)
    flags = [w for w in rest if w.startswith("--")]
    if flags:
        _die(6, "input", f"unknown connection option {flags[0]!r}", usage)
    if len(rest) != 1:
        _die(6, "input", f"connection {sub} names one connection id", usage)
    cid = rest[0]
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
        try:
            for other, row in adapter.resolve_scope(NAME, "connection", scope).items():
                if other != cid:
                    others[other] = row.get("value") or {}
            pointer = adapter.resolve_scope(NAME, "setting", scope).get("connection.default")
            adapter.delete(NAME, "connection", cid, scope=scope)
            was_default = bool(pointer and pointer.get("value") == cid)
            if was_default:
                adapter.delete(NAME, "setting", "connection.default", scope=scope)
            source = adapter.scope_source(NAME, "connection", scope)
        except StoreError as e:
            _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)
        removed, kept = [], []
        for field in declared:
            env_key = existing.get(field["key"]) if field.get("secret") else None
            if not isinstance(env_key, str) or not env_key:
                continue
            shared = any(entry.get(field["key"]) == env_key for entry in others.values())
            if env_key == _connection_env_name(field, cid) and not shared \
                    and env_key in _parse_env_file(credentials):
                removed.append(env_key)
            else:
                kept.append(env_key)
        if removed:
            _env_file_write(credentials, {key: None for key in removed})
        _emit({"ok": True, "action": "remove", "connection": cid, "scope": scope,
               "registry": source, "default_cleared": was_default,
               "credentials": str(credentials) if removed else None,
               "secrets_removed": removed, "secrets_kept": kept})
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
                 f".env.local or .env, {CREDENTIALS_ENV}, or the environment",
                 "set it there first, or give the secret itself in the JSON object "
                 "on stdin")
    entry = dict(existing)
    secrets: dict = {}
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
                env_key = _connection_env_name(field, cid)
                secrets[env_key] = value
                entry[key] = env_key
            else:
                entry[key] = value
        elif key not in entry and field.get("secret") and field.get("required"):
            env_key = _connection_env_name(field, cid)
            if _resolve_env_key(env_key)[0]:
                entry[key] = env_key
        elif key not in entry and field.get("default") is not None and field.get("required"):
            entry[key] = field["default"]
    missing = [f["key"] for f in declared if f.get("required") and entry.get(f["key"]) in (None, "")]
    if missing:
        _die(6, "fields_required", f"connection {cid!r} needs: {', '.join(missing)}",
             f"`{NAME} manifest` lists the fields; secrets go in the JSON object on stdin")
    if secrets:
        _env_file_write(credentials, secrets)
    try:
        if scope == "project" and adapter.mode_of("connection") == "store":
            # A connection added in a project in store mode is the project's
            # own, written with its grant.
            adapter.set(NAME, "connection", cid, entry, scope=scope, own=True)
        else:
            adapter.set(NAME, "connection", cid, entry, scope=scope)
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
           "connection": cid, "scope": scope, "registry": source,
           "credentials": str(credentials) if secrets else None,
           "default": default, "fields": report,
           "next": f"`{NAME} doctor --connection {cid}` proves it"}
    methods = globals().get("LINK_METHODS") or []
    if methods:
        out["link"] = [m.get("id") for m in methods]
        out["next"] = (f"link it with one of `{NAME} manifest`'s connections.link "
                       f"methods, adding --connection {cid}")
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


def _cmd_setup(argv: list[str]) -> None:
    """`setup` reports the machine prerequisites the capability declares and
    where each resolves from; `setup set` writes them to the capability's
    credentials.env, secrets from stdin; `setup unset` takes them out.
    `--machine` names a write as administration of the machine
    (`_machine_administration`)."""
    usage = (f"{NAME} setup [show] | setup set [--machine] [--field KEY=VALUE ...] "
             "[--stdin] | setup unset [--machine] <KEY> ...")
    declared = list(globals().get("SETUP_FIELDS") or [])
    sub = argv[0] if argv and not argv[0].startswith("--") else "show"
    rest = argv[1:] if argv and argv[0] == sub else argv
    if sub not in ("show", "set", "unset"):
        _die(6, "input", f"unknown setup subcommand {sub!r}", usage)
    if sub != "show":
        rest = [w for w in rest if w != "--machine"]
    changed: list = []
    if sub == "set":
        argv_values, words, stdin = _field_args(rest, usage)
        if words:
            _die(6, "input", f"unexpected {words[0]!r}", usage)
        _read_only_gate(f"`{NAME} setup set`")
        given = _declared_values(declared, argv_values, stdin, "setup")
        if not given:
            _die(6, "input", "setup set was given nothing to set", usage)
        _env_file_write(CREDENTIALS_ENV, {
            key: (None if value is None else
                  ("true" if value is True else "false" if value is False else
                   json.dumps(value) if isinstance(value, (list, dict)) else str(value)))
            for key, value in given.items()})
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
        changed = sorted(keys)
    fields = []
    for field in declared:
        value, tier, source = _resolve_env_key(field["key"])
        secret = bool(field.get("secret"))
        fields.append({**field, "set": bool(value), "tier": tier if value else None,
                       "source": str(source) if (value and source) else None,
                       "value": (_mask(value) if secret else value) if value else None})
    out = {"capability": NAME, "credentials": str(CREDENTIALS_ENV),
           "ready": all(f["set"] for f in fields if f.get("required")),
           "fields": fields}
    if sub != "show":
        out.update({"ok": True, "action": sub, "changed": changed})
    _emit(out)

