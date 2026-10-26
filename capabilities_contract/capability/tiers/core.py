# The shared capability code - the capability core: the declaration surface (summary, manifest, references,
# guide, ids) and the file, project and I/O plumbing every capability carries.
#
# This is not a module. `capabilities_contract.capability.bind` executes it in
# the namespace of the capability that binds it, so it reads that capability's
# declarations and calls its hooks as its own code does. See the package
# docstring of `capabilities_contract.capability`.
#

# --- Error reporting ---------------------------------------------------------

def _die(exit_code: int, code: str, message: str,
         hint: str | None = None, status: int | None = None) -> NoReturn:
    err: dict = {"code": code, "message": message}
    if hint:
        err["hint"] = hint
    if status is not None:
        err["status"] = status
    if _EVENTS_ON[0]:
        sys.stdout.write(json.dumps({"event": "error", "exit": exit_code, "error": err},
                                    ensure_ascii=False) + "\n")
        sys.stdout.flush()
    sys.stderr.write(json.dumps({"error": err}, ensure_ascii=False) + "\n")
    sys.exit(exit_code)


def _store_lost(kind, exc, trace) -> None:
    """A store connection lost where nothing caught it ends the command as the
    store being unreachable, exit 5, rather than with a traceback: the database
    library has already tried again everything it safely could."""
    driver = sys.modules.get("psycopg")
    if driver is None or not isinstance(exc, driver.OperationalError):
        _UNCAUGHT[0](kind, exc, trace)
        return
    try:
        _die(5, "store_unreachable",
             "the store stopped answering: " + " ".join(str(exc).split())[:300],
             "check the database setting with `capabilities store doctor`")
    except SystemExit:
        pass
    import atexit
    import os
    atexit._run_exitfuncs()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(5)


_UNCAUGHT = [sys.excepthook]
sys.excepthook = _store_lost


def _emit(value) -> None:
    if _EVENTS_ON[0]:
        sys.stdout.write(json.dumps({"event": "done", "result": value},
                                    ensure_ascii=False, default=str) + "\n")
        sys.stdout.flush()
        return
    if isinstance(value, str):
        sys.stdout.write(value)
        if value and not value.endswith("\n"):
            sys.stdout.write("\n")
    else:
        sys.stdout.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


# --- Project / file plumbing -------------------------------------------------

def _parse_env_file(path: Path) -> dict:
    """Parse a KEY=VALUE env/dotenv file. Missing/unreadable file -> {}."""
    out: dict = {}
    try:
        text = path.read_text()
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        if k.startswith("export "):
            k = k[len("export "):].strip()
        out[k] = v.strip().strip('"').strip("'")
    return out


def _home_dirs() -> set[Path]:
    """Every directory that is a home directory of the account running this.

    $HOME answers for the process and moves wherever a caller points it; the
    password database answers for the account and cannot be pointed anywhere.
    A caller that redirects $HOME - a dev lane, a service under a supervisor, a
    sandbox - would otherwise carry the guard onto the home it invented and stop
    excluding the account's own, which is the one the machine registry sits in.
    """
    import pwd

    homes: set[Path] = set()
    candidates = [Path.home()]
    try:
        account = pwd.getpwuid(os.getuid()).pw_dir
    except (KeyError, OSError):
        account = ""
    # The account's field counts only when it is absolute. An empty or relative
    # one names no directory of its own: it resolves against the cwd, an empty
    # one to the cwd itself, so taken as a home it would stop the walk wherever
    # the process stands. Some service accounts carry an empty field.
    if os.path.isabs(account):
        candidates.append(Path(account))
    for candidate in candidates:
        try:
            homes.add(candidate.resolve())
        except OSError:
            continue
    return homes


def _is_machine_registry(path: Path) -> bool:
    """Whether this `.capabilities/` is a machine registry, not a legacy envelope.

    The two share the name, and only the registry carries `.manager/`. The
    registry $CAPABILITIES_HOME points at names itself even without it.
    """
    registry = Path(os.environ.get("CAPABILITIES_HOME") or (Path.home() / ".capabilities"))
    try:
        if path.resolve() == registry.resolve():
            return True
    except OSError:
        return False
    return (path / ".manager").is_dir()


def _env_bound_root() -> Path | None:
    """The folder the process environment binds: CAPABILITIES_PROJECT_ID_ROOT,
    where CAPABILITIES_PROJECT_ID is set beside it and it names an existing
    absolute folder. An id without a root binds no folder."""
    ident = os.environ.get("CAPABILITIES_PROJECT_ID", "").strip()
    scope = os.environ.get("CAPABILITIES_PROJECT_ID_ROOT", "").strip()
    if not ident or not scope:
        return None
    path = Path(scope).expanduser()
    if not path.is_absolute():
        return None
    try:
        path = path.resolve()
    except OSError:
        return None
    return path if path.is_dir() else None


def _bound_folder(d: Path, bound: Path | None) -> bool:
    """Whether `d` is a project bound to its id: the folder the environment
    binds, one whose `.env.local` or `.env` sets CAPABILITIES_PROJECT_ID, or
    one that still carries a binding of an older kind - an envelope's
    `project.json` or `settings.json`, a legacy `.capabilities/` envelope, or
    a ContextKit binding."""
    if d == bound or _env_file_project_id(d):
        return True
    legacy = d / ".capabilities"
    return ((d / "capabilities" / "settings.json").is_file()
            or (d / "capabilities" / "project.json").is_file()
            or (d / ".contextkit" / "config.toml").is_file()
            or (legacy.is_dir() and not _is_machine_registry(legacy)))


def _project_root() -> Path | None:
    """The project root, walking up from $CLAUDE_PROJECT_DIR (else cwd).

    The nearest bound folder (`_bound_folder`) is the root. Where no folder on
    the walk is bound, the folder the environment binds is, so a deployed agent
    whose environment sets CAPABILITIES_PROJECT_ID with
    CAPABILITIES_PROJECT_ID_ROOT is found from anywhere; otherwise the nearest
    folder holding .env(.local) or .git names an unbound project.
    Markers are read from the filesystem alone: the root is what the envelope
    location is resolved against, so resolving one cannot depend on the other.
    A home directory is never a project root (the machine registry lives in
    one), and a `.capabilities/` that is a machine registry names that registry
    rather than a legacy envelope."""
    start = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    here = Path(start).resolve()
    homes = _home_dirs()
    bound = _env_bound_root()
    unbound = None
    for d in (here, *here.parents):
        if d in homes:
            break
        if _bound_folder(d, bound):
            return d
        if unbound is None and ((d / ".env").exists() or (d / ".env.local").exists()
                                or (d / ".git").is_dir()):
            unbound = d
    if bound is not None and bound not in homes:
        return bound
    return unbound


_ENVELOPE_HOME: dict = {}


def _validated_project_envelope(root: Path, raw, provider: str) -> Path:
    """Validate the manager/context-owner answer without selecting a fallback."""
    value = str(raw or "").strip()
    if not value:
        _die(6, "project_envelope_empty",
             f"{provider} returned an empty capabilities envelope path")
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        _die(6, "project_envelope_relative",
             f"{provider} returned a relative capabilities envelope path: {value!r}")
    try:
        resolved = candidate.resolve()
        resolved.relative_to(root.resolve())
    except (OSError, ValueError):
        _die(6, "project_envelope_outside_project",
             f"{provider} returned a capabilities envelope outside the project: {candidate}")
    return resolved


def _handed_off_envelope(root: Path) -> str:
    """The handoff meant for THIS project root, or "" when there is none.

    `CAPABILITIES_PROJECT_ENVELOPE` is inherited by every descendant process, and
    a descendant does not always stand in the project its parent stood in: a peer
    spawned in another project, or a worker whose cwd sits under a different root,
    must resolve its own envelope. `CAPABILITIES_PROJECT_ENVELOPE_ROOT` names the
    root the handed value answers for, so a handoff that crossed a project
    boundary is passed over instead of being applied to the wrong project. A
    handoff supplied without that companion belongs to whoever launched the
    process and is honored as given, which is how a context owner hands its answer
    over in advance.
    """
    override = os.environ.get("CAPABILITIES_PROJECT_ENVELOPE", "").strip()
    if not override:
        return ""
    scope = os.environ.get("CAPABILITIES_PROJECT_ENVELOPE_ROOT", "").strip()
    if not scope:
        return override
    try:
        if Path(scope).expanduser().resolve() != root.resolve():
            return ""
    except OSError:
        return ""
    return override


ENVELOPE_CACHE_VERSION = 1


def _record_file(kind: str, key: str) -> Path:
    """Where the manager records one kind of answer for one absolute project root.

    The file name only buckets roots apart; the entry's own `root` field is what
    proves identity, so two roots landing in one bucket cost a miss rather than
    a wrong answer.
    """
    import zlib

    base = Path(os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache"))
    return (base / "capabilities" / kind
            / f"{format(zlib.crc32(key.encode()), '08x')}.json")


def _envelope_witness(path) -> dict:
    """One input a recorded answer rests on, as that input stands right now."""
    try:
        seen = os.stat(path)
    except OSError:
        return {"path": str(path), "present": False}
    return {"path": str(path), "present": True,
            "size": seen.st_size, "mtime_ns": seen.st_mtime_ns}


def _cached_record(kind: str, version: int, root: Path):
    """The recorded entry for this root while every input it rests on holds.

    The manager writes the record and names the inputs its answer consulted; a
    reader re-observes each of them and compares it whole. Anything at all in
    doubt — an unreadable file, an unexpected shape, an input that moved, an
    expiry already behind the clock or a write ahead of it — returns None and
    costs a full resolution, so the failure mode is slow and never wrong.
    """
    import time

    key = str(root.resolve())
    try:
        entry = json.loads(_record_file(kind, key).read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(entry, dict):
        return None
    if entry.get("version") != version or entry.get("root") != key:
        return None
    written, expires = entry.get("written_at"), entry.get("expires_at")
    if not isinstance(written, (int, float)) or not isinstance(expires, (int, float)):
        return None
    now = time.time()
    if now < written or now >= expires:
        return None
    witness = entry.get("witness")
    if not isinstance(witness, list):
        return None
    for observed in witness:
        if (not isinstance(observed, dict)
                or _envelope_witness(observed.get("path")) != observed):
            return None
    return entry


def _cached_envelope(root: Path):
    """The recorded envelope for this root, while its record stands."""
    entry = _cached_record("envelope", ENVELOPE_CACHE_VERSION, root)
    if entry is None:
        return None
    envelope = Path(str(entry.get("envelope") or ""))
    if not envelope.is_absolute():
        return None
    try:
        envelope.resolve().relative_to(entry["root"])
    except (OSError, ValueError):
        return None
    return envelope


def _ask_manager(root: Path, *flags: str) -> tuple:
    """`capabilities path --json` for this root: (answer, None) or (None, error).

    The error carries the exit code the caller should use and the manager's own
    code, message and hint where it gave them."""
    import subprocess

    env = dict(os.environ)
    env["CLAUDE_PROJECT_DIR"] = str(root)
    # Asked at all, the manager answers from the project itself: a live id
    # hand-down for this root is used before asking, so any in the environment
    # is this process's own and must not come back as the answer. A root the
    # environment binds is found by that binding, so it goes with the question.
    if _env_bound_root() != root.resolve():
        env.pop("CAPABILITIES_PROJECT_ID", None)
        env.pop("CAPABILITIES_PROJECT_ID_ROOT", None)
    manager = os.environ.get("CAPABILITIES_MANAGER_BIN", "").strip()
    if not manager:
        source_manager = Path(__file__).resolve().parents[3] / "bin" / "capabilities"
        manager = str(source_manager) if source_manager.is_file() else "capabilities"
    try:
        proc = subprocess.run(
            [manager, "path", "--json", *flags], cwd=root, env=env,
            capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        return None, {"exit": 6, "code": "capabilities_manager_unavailable",
                      "message": "the capabilities manager is required to resolve the project",
                      "hint": "install or repair the `capabilities` command"}
    except subprocess.TimeoutExpired:
        return None, {"exit": 6, "code": "capabilities_path_timeout",
                      "message": "the capabilities manager did not resolve the project within 10 seconds"}
    except OSError as exc:
        return None, {"exit": 6, "code": "capabilities_manager_unavailable",
                      "message": f"could not run the capabilities manager: {exc}"}
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip()
        try:
            error = json.loads(detail).get("error", {})
        except (AttributeError, ValueError):
            error = {}
        return None, {"exit": proc.returncode if proc.returncode in (3, 4, 5, 6) else 6,
                      "code": str(error.get("code") or "capabilities_path_failed"),
                      "message": str(error.get("message") or "the capabilities manager could not resolve the project"),
                      "hint": str(error.get("hint") or detail or "run `capabilities path --json` for details")}
    try:
        answer = json.loads(proc.stdout)
    except ValueError as exc:
        return None, {"exit": 6, "code": "capabilities_path_malformed",
                      "message": f"the capabilities manager returned invalid JSON: {exc}"}
    if not isinstance(answer, dict):
        return None, {"exit": 6, "code": "capabilities_path_malformed",
                      "message": "the capabilities manager path answer must be a JSON object"}
    manager_root = Path(str(answer.get("project_root") or ""))
    if not manager_root.is_absolute() or manager_root.resolve() != root.resolve():
        return None, {"exit": 6, "code": "capabilities_project_mismatch",
                      "message": "the capabilities manager resolved a different project root"}
    return answer, None


def _manager_project_envelope(root: Path) -> Path:
    """Consume the capabilities manager's one authoritative project answer."""
    override = _handed_off_envelope(root)
    if override:
        return _validated_project_envelope(root, override, "environment handoff")
    answer, error = _ask_manager(root)
    if error:
        _die(error["exit"], error["code"], error["message"], error.get("hint"))
    provider = str(answer.get("provider") or "capabilities manager")
    return _validated_project_envelope(
        root, answer.get("project_envelope"), provider)


def _envelope_home(root: Path) -> Path:
    """The project's envelope root, resolved once per invocation.

    The capabilities manager owns project-envelope discovery, including any
    delegation to ContextKit. Capability CLIs consume that answer and never
    duplicate context-owner detection.

    The answer is then handed to this process's descendants, scoped to the root
    it answers for. Asking for it costs two interpreter starts — the manager and
    the context owner it delegates to — so a worker, a peer, or a nested
    capability call that would otherwise repeat the whole chain under whatever
    load the machine is under by then reads it instead.

    A fresh top-level call has no such handoff, and reads the manager's recorded
    answer for this root instead, which stands only while every input that answer
    rests on is unchanged. A live handoff outranks the record, and any doubt about
    the record asks the manager again.
    """
    cached = _ENVELOPE_HOME.get(root)
    if cached is not None:
        return cached
    home = None if _handed_off_envelope(root) else _cached_envelope(root)
    if home is None:
        home = _manager_project_envelope(root)
    _ENVELOPE_HOME[root] = home
    os.environ["CAPABILITIES_PROJECT_ENVELOPE"] = str(home)
    os.environ["CAPABILITIES_PROJECT_ENVELOPE_ROOT"] = str(root)
    # The id travels with the envelope: resolved at read level, handed down
    # only where a write may stamp it, and never a reason to refuse here.
    try:
        _project_id_state_at(root)
    except Exception:
        pass
    return home


def _project_capabilities_dir(root: Path) -> Path:
    """The active project envelope root.

    The resolved envelope is canonical. A legacy `.capabilities/` remains
    readable until `capabilities init` migrates it. If both exist, the canonical
    tree wins once it carries either the legacy file gate or the project identity;
    otherwise the legacy configured tree remains active so merely creating an
    empty visible directory loses no gate.
    """
    current = _envelope_home(root)
    legacy = root / ".capabilities"
    if ((current / "settings.json").is_file()
            or (current / "project.json").is_file()
            or not legacy.is_dir()):
        return current
    return legacy


def _manager_declared_id(root: Path) -> dict:
    """The id the capabilities manager answers for a project whose environment
    and env files declare none while it still holds an id in an older home -
    `project.json`, or its ContextKit binding: the manager moves that id into
    the project's `.env.local` once and answers it. `{"id"}`, or `{"error"}`
    when the manager cannot answer."""
    reply, error = _ask_manager(root, "--identity")
    state = (reply or {}).get("project_identity")
    if error or not isinstance(state, dict):
        return {"error": error or {
            "code": "capabilities_path_malformed",
            "message": "the capabilities manager returned no project identity"}}
    ident = state.get("id")
    return {"id": ident.strip() if isinstance(ident, str) and ident.strip() else None}


def _identity_refusal(state: dict):
    """Why a write may not stamp this project's id, or None when it may.

    A project without an id is left to the caller, whose refusal already names
    `capabilities init`."""
    if state["state"] == "unresolved":
        return state["error"]
    return None


def _handed_off_project_id(root: Path) -> str:
    """The project id the environment gives THIS root, or "" when it gives none.

    `CAPABILITIES_PROJECT_ID` is the project's binding: set by a deployment for
    the agent it runs, or handed down by a process that resolved the id, scoped
    by `CAPABILITIES_PROJECT_ID_ROOT`. One that crossed a project boundary is
    passed over, and one supplied without the companion binds no folder.
    """
    handed = os.environ.get("CAPABILITIES_PROJECT_ID", "").strip()
    if not handed:
        return ""
    scope = os.environ.get("CAPABILITIES_PROJECT_ID_ROOT", "").strip()
    if not scope:
        return ""
    try:
        if Path(scope).expanduser().resolve() != root.resolve():
            return ""
    except OSError:
        return ""
    return handed


_PROJECT_ID_HANDED: dict = {}

# The env files at the project root that may bind it to its id, the first
# that names one winning; the process environment wins over both.
PROJECT_ID_FILES = (".env.local", ".env")


def _env_file_project_id(root: Path) -> str | None:
    """The id the project's `.env.local`, else its `.env`, declares, or None.

    Only the CAPABILITIES_PROJECT_ID line is read: the files hold the
    project's secrets too, and resolving which project this is never needs
    a value of theirs."""
    for name in PROJECT_ID_FILES:
        try:
            lines = (root / name).read_text().splitlines()
        except OSError:
            continue
        ident = ""  # the last line naming the key wins, as in any env file
        for line in lines:
            key, eq, value = line.strip().partition("=")
            key = key.strip()
            if key.startswith("export "):
                key = key[len("export "):].strip()
            if eq and key == "CAPABILITIES_PROJECT_ID":
                ident = value.strip().strip('"').strip("'")
        if ident:
            return ident
    return None


def _id_left_to_move(root: Path) -> bool:
    """Whether the project still holds its id where it was kept before the
    env files - an `id` in the envelope's `project.json`, or a ContextKit
    binding - which only the manager reads and moves."""
    if (root / ".contextkit" / "config.toml").is_file():
        return True
    try:
        identity = json.loads((_project_capabilities_dir(root) / "project.json").read_text())
    except (OSError, ValueError):
        return False
    return isinstance(identity, dict) and bool(str(identity.get("id") or "").strip())


def _project_id_state():
    """The id of the project this command stands in, where it came from, and
    whether a write may stamp it; None outside a project.

    `CAPABILITIES_PROJECT_ID` binds a project to its id: the process
    environment's value for this root first (`handed`), then the one the
    project root's `.env.local`, else `.env`, declares (`declared`). Where none
    does and the project still holds its id in an older home, the manager is
    asked: it moves that id into `.env.local` once. An id a write may stamp is
    handed on to this process's descendants. Reading it asks no records
    backend: the id is what selects a project's records, so it is read before
    any of them."""
    root = _project_root()
    if root is None:
        return None
    return _project_id_state_at(root)


def _project_id_state_at(root: Path) -> dict:
    """`_project_id_state` for a known project root."""
    handed = _handed_off_project_id(root)
    if handed and _PROJECT_ID_HANDED.get(str(root)) == handed:
        handed = ""  # this process's own hand-down, not its launcher's
    if handed:
        state = {"state": "handed", "id": handed}
    else:
        declared = _env_file_project_id(root)
        if declared is None and _id_left_to_move(root):
            answer = _manager_declared_id(root)
            if "error" in answer:
                state = {"state": "unresolved", "id": None, "error": answer["error"]}
            else:
                declared = answer["id"]
                state = {"state": "declared" if declared else "undeclared", "id": declared}
        else:
            state = {"state": "declared" if declared else "undeclared", "id": declared}
    if not handed and state["id"] and _identity_refusal(state) is None:
        os.environ["CAPABILITIES_PROJECT_ID"] = state["id"]
        os.environ["CAPABILITIES_PROJECT_ID_ROOT"] = str(root)
        _PROJECT_ID_HANDED[str(root)] = state["id"]
    return state


def _project_id(write: bool = False, refuse: bool = True):
    """The project id this command stands in, or None where there is none.

    A read takes the id in every state. A write that stamps it takes it only
    once it is verified for this invocation, and otherwise exits 6 naming what
    to settle, or, with `refuse=False`, answers None so a read path that would
    stamp the id can leave that step out instead of refusing. A project that
    declares no id is still None, left to the caller's own refusal."""
    state = _project_id_state()
    if state is None:
        return None
    if write:
        refusal = _identity_refusal(state)
        if refusal:
            if not refuse:
                return None
            _die(6, refusal["code"], refusal["message"], refusal.get("hint"))
    return state["id"]


def _project_env() -> dict:
    """Project .env(.local) at the project root. .env.local overrides .env."""
    root = _project_root()
    if root is None:
        return {}
    merged = _parse_env_file(root / ".env")
    merged.update(_parse_env_file(root / ".env.local"))  # .local wins
    return merged


def _auth_context() -> dict | None:
    """Optional runtime authority envelope passed by an ingress/service.

    Absence means the ordinary project gate is the whole policy. Presence means
    a request-scoped authority layer exists and must fail closed before any
    credential or network work happens.
    """
    raw = os.environ.get("CAPABILITIES_AUTH_CONTEXT")
    if not raw:
        return None
    try:
        if raw.lstrip().startswith("{"):
            data = json.loads(raw)
        else:
            data = json.loads(Path(raw).read_text())
    except (OSError, ValueError) as e:
        _die(4, "auth_context_unreadable",
             "runtime authority context could not be read",
             f"{raw}: {e}")
    if not isinstance(data, dict):
        _die(4, "auth_context_invalid",
             "runtime authority context is not an object")
    return data


def _auth_capability_allowed(rule) -> bool:
    if rule is True or rule == "*":
        return True
    if rule in (False, None):
        return False
    if isinstance(rule, list):
        return True
    if isinstance(rule, dict):
        if rule.get("deny") is True:
            return False
        if rule.get("enabled") is False or rule.get("allow") is False:
            return False
        return True
    return False


# Verbs a rule's verb list never withholds: they say what the capability is and
# how it is configured, which is what an agent should reach for before acting.
_AUTH_CONTRACT_VERBS = frozenset(
    {"help", "guide", "ids", "connections", "refs", "stub", "manifest"})


def _reveals() -> bool:
    """Whether this call prints a connection's value in the clear. It is the
    `connections` verb, so it is told apart here: it reads a secret, and passes
    no gate as a discovery verb. It is judged on the words a capability
    dispatches, with `--connection <id>` lifted out wherever it stands."""
    argv, words, i = sys.argv[1:], [], 0
    while i < len(argv):
        if argv[i] == "--connection" and i + 1 < len(argv):
            i += 2
        elif argv[i].startswith("--connection="):
            i += 1
        else:
            words.append(argv[i])
            i += 1
    return words[:2] == ["connections", "show"]


def _auth_rule_verbs(rule) -> list | None:
    """The verbs a capability rule limits its grant to, or None when it grants
    the whole capability. A bare list is shorthand for {"verbs": [...]}."""
    if isinstance(rule, list):
        verbs = rule
    elif isinstance(rule, dict) and "verbs" in rule:
        verbs = rule["verbs"]
    else:
        return None
    if not isinstance(verbs, list) or not all(isinstance(v, str) for v in verbs):
        _die(4, "auth_context_invalid",
             f"runtime authority context has invalid verbs for {NAME}",
             "verbs must be a list of verb names")
    return verbs


def _auth_gate() -> None:
    ctx = _auth_context()
    if ctx is None:
        return
    allowed = ctx.get("allowed_capabilities")
    if allowed is None:
        return
    if allowed is True or allowed == "*":
        return
    source = ctx.get("source") or "runtime"
    role = ctx.get("sender_role") or ctx.get("role") or "unknown"
    chat = ctx.get("chat_id") or "unknown"
    if isinstance(allowed, list):
        if NAME in allowed or "*" in allowed:
            return
    elif isinstance(allowed, dict):
        rule = allowed.get(NAME, allowed.get("*"))
        if _auth_capability_allowed(rule):
            verbs = _auth_rule_verbs(rule)
            verb = sys.argv[1] if len(sys.argv) > 1 else "help"
            if verbs is None or verb in verbs or (
                    verb in _AUTH_CONTRACT_VERBS and not _reveals()):
                return
            _die(4, "verb_not_authorized",
                 f"verb refused: `{NAME} {verb}` is not among the verbs this "
                 f"{source} request may run ({', '.join(verbs) or 'none'})",
                 f"role={role}; chat_id={chat}; adjust runtime authority policy instead of bypassing the gate")
    else:
        _die(4, "auth_context_invalid",
             "runtime authority context has invalid allowed_capabilities")
    _die(4, "capability_not_authorized",
         f"{NAME} is not authorized for this {source} request",
         f"role={role}; chat_id={chat}; adjust runtime authority policy instead of bypassing the gate")


def _policy_row():
    """The effective policy row from the same records adapter as everything else."""
    try:
        row = _records().resolve("capabilities", "policy").get(NAME)
    except StoreError as e:
        _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)
    if row is None:
        return None
    entry = row.get("value")
    if (not isinstance(entry, dict) or set(entry) != {"enabled"}
            or not isinstance(entry.get("enabled"), bool)):
        _die(6, "bad_policy",
             f"invalid {NAME} policy entry in {_policy_source()}",
             'expected {"enabled": true|false}')
    return row


def _policy_source() -> str:
    """Where the gate is kept: the project's envelope, or the store's policy
    table in a project whose records are in the store."""
    records = _records()
    if records.mode_of("policy") != "store":
        return records.source
    try:
        return records.collection_source("capabilities", "policy")
    except StoreError:
        return "the store"


def _project_enabled_explicitly() -> bool:
    """True only for an explicit project enabled entry; global inheritance is
    deliberately insufficient for project-owned service activation."""
    row = _policy_row()
    return bool(row and row.get("scope") == "project"
                and row["value"].get("enabled") is True)


def _require_project_enabled_for_service() -> Path:
    root = _project_root()
    if root is None or not _project_enabled_explicitly():
        _die(4, "project_enable_required",
             f"{NAME} service activation requires an explicit project enable",
             f"ask the user, then run `capabilities enable {NAME} --project` "
             "before service init/start/run")
    return root


def _read_only_gate(action: str) -> None:
    """Refuse `action` when this process runs under the read-only switch.

    The switch is decided by the store tier's `read_only_switch`; this is the
    one refusal every writer that consults it gives, so a caller branches on one
    code, and that code is distinct from a connection's own read-only grant."""
    if read_only_switch():
        _die(4, "read_only_switch",
             f"{action} is refused: {READ_ONLY_ENV} is set, so {NAME} may read "
             "but change nothing in this process",
             "Do not lift the switch yourself — ask the user; the change has to "
             f"run in a process without {READ_ONLY_ENV}.")


_MACHINE_SCHEMA = "capabilities.machine.v1"


def _machine_state() -> str:
    """This machine's ceiling for this capability: `allowed` or `quarantined`.

    The manager alone writes `$XDG_CONFIG_HOME/capabilities/machine.json`. A
    capability with no entry, and every capability while the file is absent,
    is allowed, so the ceiling only ever closes what the two scopes open."""
    path = _CONFIG_HOME / "capabilities" / "machine.json"
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        return "allowed"
    except (OSError, ValueError) as e:
        _die(6, "bad_machine_state", f"cannot read the machine ceiling {path}: {e}",
             "the manager alone writes it; `capabilities list` reports each "
             "capability's machine state")
    entries = data.get("capabilities") if isinstance(data, dict) else None
    if (not isinstance(data, dict) or data.get("schema") != _MACHINE_SCHEMA
            or not isinstance(entries, dict)):
        _die(6, "bad_machine_state", f"{path} is not a machine ceiling",
             f'expected {{"schema": "{_MACHINE_SCHEMA}", "capabilities": {{...}}}}')
    entry = entries.get(NAME)
    if entry is None:
        return "allowed"
    state = entry.get("state") if isinstance(entry, dict) else None
    if state not in ("allowed", "quarantined"):
        _die(6, "bad_machine_state", f"invalid {NAME} entry in {path}",
             'expected {"state": "allowed"|"quarantined", "at": ..., "by": ...}')
    return state


def _machine_gate() -> None:
    """The ceiling above both scopes: quarantined is disabled everywhere."""
    if _machine_state() == "quarantined":
        _die(4, "quarantined",
             f"{NAME} is quarantined on this machine, so no project and no "
             "machine service may use it, whatever project or global policy says",
             f"ask the user whether to allow {NAME} on this machine; if yes, they "
             f"run `capabilities allow {NAME}` - an agent never lifts a "
             "quarantine itself")


def _gate() -> None:
    """Project policy overrides global policy; absence inherits, and absence at
    both scopes is default deny. Safe local discovery verbs remain available so
    a disabled capability can be understood and configured before use.

    If an ingress supplied CAPABILITIES_AUTH_CONTEXT, that request-scoped gate
    is stricter and runs first, before credentials or network calls. The
    machine ceiling runs next: a capability quarantined on this machine is
    refused before any project or policy row is resolved.

    Under the read-only switch a bundled service is neither set up nor started
    nor handed a new declaration.

    A service that declares `machine` takes `--machine` on its service verbs;
    such a call resolves no project and reads no policy row, because the
    machine service checks each opted-in project's own policy before every
    action it takes for that project. `join` is a project act and always takes
    the ordinary path.

    `migrate` of a capability that declares `TABLES` acts on the machine's
    store rather than for a project, so it too reads no policy row: it answers
    to the machine ceiling, and `migrate` (not `migrate status`) to the
    read-only switch. `migrate files` is the manager's `capabilities migrate`
    moving this capability's files of a project into the store, whether or not
    the project enabled it: it answers to the machine ceiling, and `migrate
    files write` to the read-only switch.

    Machine administration reads no policy row either: it answers to the
    machine ceiling, and its writes to the read-only switch
    (`_machine_administration`).
    """
    _auth_gate()
    verb = sys.argv[1] if len(sys.argv) > 1 else "help"
    safe = verb in {"help", "stub", "manifest", "connections"} and not _reveals()
    if not safe:
        _machine_gate()
    service_action = sys.argv[2] if len(sys.argv) > 2 else None
    if verb == "migrate" and service_action == "files":
        if sys.argv[3:4] == ["write"]:
            _read_only_gate(f"`{NAME} migrate files write`")
        return
    if verb == "migrate" and _tables_declared():
        if service_action != "status":
            _read_only_gate(f"`{NAME} migrate`")
        return
    service_contract = globals().get("SERVICE")
    service_call = isinstance(service_contract, dict) and verb == "service"
    machine_service = service_call and isinstance(service_contract.get("machine"), dict)
    if service_call and (service_action in {"init", "start", "run", "reload"}
                         or (machine_service and service_action in {"join", "leave"})):
        _read_only_gate(f"`{NAME} service {service_action}`")
    if machine_service and service_action != "join" and "--machine" in sys.argv[3:]:
        return
    if not safe and _machine_administration():
        return
    if service_call and (service_action in {"init", "start", "run"}
                         or (machine_service and service_action == "join")):
        _require_project_enabled_for_service()
    if safe:
        return
    row = _policy_row()
    entry = row.get("value") if row else None
    scope = row.get("scope") if row else None
    if isinstance(entry, dict) and entry.get("enabled") is True:
        return
    if isinstance(entry, dict) and entry.get("enabled") is False and scope == "project":
        _die(4, "disabled",
             f"{NAME} is disabled in this project ({_policy_source()})",
             f"ask the user whether to enable {NAME} for this project; if yes, "
             f"run `capabilities enable {NAME} --project`")
    if isinstance(entry, dict) and entry.get("enabled") is False:
        message = f"{NAME} is disabled globally ({_policy_source()})"
    else:
        message = f"{NAME} is not enabled by project or global policy"
    _die(4, "not_enabled", message,
         f"ask the user whether to enable {NAME} only for this project or "
         f"globally for every project; then run `capabilities enable {NAME} "
         "--project` or `--global` exactly as requested")


def _invoked_verb() -> str | None:
    """The verb this process was invoked with: its first argument once the
    contract's own `--connection <id>` selection is lifted out of the way."""
    argv = sys.argv[1:]
    i = 0
    while i < len(argv):
        if argv[i] == "--connection":
            i += 2
        elif argv[i].startswith("--connection="):
            i += 1
        else:
            return argv[i]
    return None


def _link_verbs() -> tuple:
    """The verbs that link a connection: the one each `LINK_METHODS` ceremony
    runs, read from its argv."""
    verbs = []
    for method in globals().get("LINK_METHODS") or []:
        argv = method.get("argv") if isinstance(method, dict) else None
        if isinstance(argv, list) and len(argv) > 1 and argv[1] not in verbs:
            verbs.append(argv[1])
    return tuple(verbs)


def _machine_read(verb: str | None = None) -> bool:
    """Whether `verb`, else the invoked one, uses the machine's connections here.

    Outside any project there is no scope a grant could have been written in,
    so a verb the capability declares in `MACHINE_READS`, and a verb that links
    a connection, uses the machine's own connections instead, read-only: a
    connection is linked on the machine before any project is granted it.
    Inside a project the grant model alone decides, and a capability that
    declares neither has none."""
    declared = globals().get("MACHINE_READS")
    declared = declared if isinstance(declared, tuple) else ()
    declared = declared + _link_verbs()
    if not declared:
        return False
    if _project_root() is not None:
        return False
    return (verb if verb is not None else _invoked_verb()) in declared


def _machine_administration() -> bool:
    """Whether this call administers the machine rather than acting for a
    project, so it reads no policy row and answers to the machine ceiling
    alone, its writes to the read-only switch as well.

    Outside any project, a machine read - a verb declared in `MACHINE_READS`,
    a verb that links a connection, and `setup` reporting the machine's
    prerequisites - has no project whose policy it could answer to, and uses
    the machine's connections only read-only. A write to the machine's own
    configuration - `setup set|unset`, and `connection add|remove` at machine
    scope - is administration only when it says so with `--machine`, wherever
    it runs; it is never inferred from where the call runs."""
    verb = _invoked_verb()
    first = sys.argv[1] if len(sys.argv) > 1 else None
    rest = sys.argv[2:]
    if (verb == "setup" == first and "_cmd_setup" in globals()
            and globals().get("SETUP_FIELDS")):
        sub = rest[0] if rest and not rest[0].startswith("--") else "show"
        if sub in ("set", "unset"):
            return "--machine" in rest
        return _project_root() is None
    if (verb == "connection" == first and "_cmd_connection" in globals()
            and globals().get("CONN_FIELDS") is not None):
        return "--machine" in rest
    return _machine_read(verb)


def _policy_state() -> dict:
    """This capability's effective policy, in the words `capabilities list`
    uses: `effective` enabled or disabled, the `source` that decided it -
    `machine` (the ceiling), `project`, `global` or `default` - and the
    `machine` ceiling itself. A record that cannot be read is reported as the
    refusal the gate would give, so the report around it still answers."""
    import contextlib
    import io
    errors = io.StringIO()
    try:
        with contextlib.redirect_stderr(errors):
            machine = _machine_state()
            row = None if machine == "quarantined" else _policy_row()
    except SystemExit:
        lines = errors.getvalue().strip().splitlines()
        try:
            return {"error": json.loads(lines[-1])["error"]}
        except (IndexError, ValueError, KeyError, TypeError):
            return {"error": {"code": "policy_unreadable",
                              "message": errors.getvalue().strip()}}
    if machine == "quarantined":
        return {"effective": "disabled", "source": "machine", "machine": machine}
    if row is None:
        return {"effective": "disabled", "source": "default", "machine": machine}
    return {"effective": "enabled" if row["value"]["enabled"] else "disabled",
            "source": row.get("scope"), "machine": machine}


def _env_dir() -> Path | None:
    """The capability's envelope dir in the project's active capabilities/."""
    root = _project_root()
    return (_project_capabilities_dir(root) / NAME) if root is not None else None


_RECORDS = None
# Who this process writes records as, where it is not the person running it:
# `migrate` while `migrate files` moves the project's files into the store.
_RECORDS_ACTOR = None


def _records():
    """The adapter this project's records are read and written through: the
    project's envelope, then the user's config home; in a project whose
    connections are in store mode, its store for connections and grants, read
    for the project's id. Everything below asks it for a collection, never for
    a path."""
    global _RECORDS
    if _RECORDS is None:
        root = _project_root()
        envelope = (_project_capabilities_dir(root) if root is not None
                    else _CONFIG_HOME / "no-project")
        try:
            project_only = os.environ.get("CAPABILITIES_RECORDS_PROJECT_ONLY", "") \
                .strip().lower() in ("1", "true", "yes", "on")
            in_store = root is not None and connections_mode(envelope, root) == "store"
            _RECORDS = open_records(
                envelope, _CONFIG_HOME, project_only=project_only,
                project_root=root, project_id=_project_id() if in_store else None,
                application_name=NAME, actor=_RECORDS_ACTOR)
        except StoreError as e:
            _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)
    return _RECORDS


_PROJECT_SLUG: dict = {}


def _project_slug(root: Path | None = None) -> str | None:
    """The project's slug, its short technical name: the one its agent's row in
    the store holds (`capabilities_agents.slug`, which `capabilities relabel`
    writes), else the one an older `project.json` still names, else the
    project's id; None outside a project, or for one with none of them.

    A project whose store is configured but does not answer, and which has no
    older `project.json` slug, is refused (StoreError) rather than named by its
    id, which would move everything its slug names. An answer is reused for
    STORE_READ_SECONDS, so one command asks once and a long-running service
    sees a new slug."""
    import time

    root = root or _project_root()
    if root is None:
        return None
    kept = _PROJECT_SLUG.get(str(root))
    if kept is not None and time.monotonic() - kept[0] < STORE_READ_SECONDS:
        return kept[1]
    try:
        identity = json.loads((_project_capabilities_dir(root) / "project.json").read_text())
    except (OSError, ValueError):
        identity = {}
    legacy = identity.get("slug") if isinstance(identity, dict) else None
    legacy = legacy.strip() if isinstance(legacy, str) and legacy.strip() else None
    ident = _project_id_state_at(root)["id"]
    slug = None
    if ident:
        try:
            conn, _schema = _store_connect(root, NAME, _PROBE_TIMEOUT)
        except StoreError as exc:
            if exc.slug != "store_not_configured" and legacy is None:
                raise
            conn = None
        if conn is not None:
            import psycopg
            try:
                slug = agent_slug(conn, ident)
            except psycopg.Error as exc:
                if legacy is None:
                    raise StoreError("store_unreachable",
                                     f"cannot read the agent registry: {exc}",
                                     "check the database setting with "
                                     "`capabilities store doctor`") from None
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
    slug = slug or legacy or ident
    _PROJECT_SLUG[str(root)] = (time.monotonic(), slug)
    return slug


def _project_identity() -> dict:
    """This project's id and slug (`_project_slug`), refusing outside a project
    or for a project with neither."""
    root = _project_root()
    if root is None:
        _die(6, "no_project", "no project here to resolve records for")
    try:
        slug = _project_slug(root)
    except StoreError as e:
        _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)
    if not slug:
        _die(6, "no_project_identity", f"{root} is bound to no project id",
             "run `capabilities init` in the project")
    return {"id": _project_id_state_at(root)["id"], "slug": slug}


def _state_dir() -> Path:
    """State follows the scope of the credentials that minted it; project state
    lands inside the envelope only where capabilities/ already exists."""
    if SCOPE == "project":
        root = _project_root()
        if root is not None:
            envelope = _project_capabilities_dir(root)
            if ((envelope / "project.json").is_file()
                    or (envelope / "settings.json").is_file()
                    or (envelope.is_dir() and (_handed_off_project_id(root)
                                               or _env_file_project_id(root)))):
                return envelope / NAME / "state"
    return _STATE_HOME / NAME


# --- Capability contract — the declaration surface --------------------------

def _docs_base() -> str:
    key = f"{NAME.upper()}_DOCS_BASE"
    return (_project_env().get(key)
            or _parse_env_file(CREDENTIALS_ENV).get(key)
            or os.environ.get(key)
            or DOCS_BASE)


def _guide_dir() -> Path:
    executable = Path(__file__).resolve()
    bundle = (executable.parent.parent
              if executable.parent.name == "bin" else executable.parent)
    return bundle / "guides"


def _guide_menu() -> list[dict[str, str]]:
    menu = []
    guide_dir = _guide_dir()
    files = sorted(guide_dir.glob("*.md")) if guide_dir.is_dir() else []
    for path in files:
        lines = path.read_text().splitlines()
        title = ""
        title_index = -1
        for index, line in enumerate(lines):
            if line.startswith("# "):
                title = line[2:].strip()
                title_index = index
                break
        paragraph = []
        for line in lines[title_index + 1:]:
            stripped = line.strip()
            if not stripped:
                if paragraph:
                    break
                continue
            if stripped.startswith("#"):
                break
            paragraph.append(stripped)
        topic = path.stem
        menu.append({
            "topic": topic,
            "title": title,
            "preview": " ".join(paragraph),
            "command": f"{NAME} guide {topic}",
        })
    return menu


def _cmd_guide(argv: list[str]) -> None:
    menu = _guide_menu()
    if not argv:
        _emit(menu); return
    topic = argv[0]
    topics = {entry["topic"] for entry in menu}
    if topic not in topics:
        _die(3, "not_found", f"no guide topic {topic!r}",
             f"run `{NAME} guide` to list available guides")
    import urllib.error as _ue
    import urllib.request as _ur
    url = _docs_base().rstrip("/") + "/" + topic + ".md"
    cache_dir = _STATE_HOME / NAME / "guides"
    cache, etag_f = cache_dir / f"{topic}.md", cache_dir / f"{topic}.etag"
    headers = {}
    if cache.exists() and etag_f.exists():
        headers["If-None-Match"] = etag_f.read_text().strip()
    try:
        req = _ur.Request(url, headers=headers)
        with _ur.urlopen(req, timeout=10.0) as resp:
            text = resp.read().decode(resp.headers.get_content_charset() or "utf-8")
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache.write_text(text)
            if resp.headers.get("etag"):
                etag_f.write_text(resp.headers["etag"])
            _emit(text); return
    except _ue.HTTPError as e:
        if e.code == 304 and cache.exists():
            _emit(cache.read_text()); return
        if e.code == 404:
            _die(3, "not_found", f"guide {topic!r} missing upstream", url)
        err = f"upstream returned {e.code}"
    except _ue.URLError as e:
        err = str(e.reason)
    except OSError as e:
        err = str(e)
    if cache.exists():
        sys.stderr.write(json.dumps(
            {"warning": f"upstream unreachable; serving cached copy ({err})"},
            ensure_ascii=False) + "\n")
        _emit(cache.read_text()); return
    _die(5, "network_error", f"could not fetch guide {topic!r}; no cache exists", url)


def _render_ids_markdown(data: dict) -> str:
    """Render the {label: {value, note}} envelope as the labelled markdown
    list the manager's `capabilities ids <NAME>` also produces — one shared
    format across the ids surface and the identifiers section of `help`."""
    lines: list[str] = []
    for label, entry in sorted(data.items()):
        entry = entry if isinstance(entry, dict) else {"value": entry}
        v = entry.get("value")
        vs = f"`{v}`" if isinstance(v, str) else "`" + json.dumps(v, ensure_ascii=False) + "`"
        line = f"- **{label}**: {vs}"
        note = entry.get("note")
        if note:
            line += f" — {note}"
        lines.append(line)
    return "\n".join(lines)


def _identifiers_load() -> dict:
    """The identifiers envelope, resolved through the records adapter, in one
    shape — `{label: {value, note, scope}}` — for the help section, the report
    and `ids get`; `scope` names where the value came from, `project` or
    `global`."""
    try:
        resolved = _records().resolve(NAME, "identifier")
    except StoreError as e:
        _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)
    return {label: {"note": row["note"] or "", "value": row["value"],
                    "scope": row["scope"]}
            for label, row in sorted(resolved.items())}


def _identifiers_scope(scope: str) -> dict:
    """The identifiers one scope holds itself, without inheritance."""
    try:
        return _records().resolve_scope(NAME, "identifier", scope)
    except StoreError as e:
        _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)


def _identifiers_stamp(scope: str) -> None:
    """A project row in the store carries the project id as its agent, so it
    is written only once the id is verified for this invocation."""
    if scope == "project" and _records().mode_of("identifier") == "store":
        _project_id(write=True)


def _identifiers_write(label: str, value, note: str, scope: str = "project") -> None:
    """Rule 15: a capability is the sole writer of its own identifiers,
    addressed by (capability, collection) rather than by path."""
    _identifiers_stamp(scope)
    kept = note or ((_identifiers_scope(scope).get(label) or {}).get("note") or "")
    try:
        _records().set(NAME, "identifier", label, value,
                       actor=f"{NAME} ids set", note=kept or None, scope=scope)
    except StoreError as e:
        _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)


def _identifiers_remove(label: str, scope: str = "project") -> None:
    _identifiers_stamp(scope)
    try:
        _records().delete(NAME, "identifier", label, scope=scope)
    except StoreError as e:
        _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)


def _identifiers_section() -> str:
    """The Identifiers block appended to the bare top-level help — deterministic
    first-touch surfacing of `capabilities/<NAME>/identifiers.json` so an
    agent following the `<NAME> help` startup protocol loads the discovered
    labels/values/notes into context at once. Empty when no project envelope
    or nothing recorded (do not bloat help with an empty section)."""
    data = _identifiers_load()
    if not data:
        return ""
    header = (
        "\n═══ Identifiers ═════════════════════════════════════════════════════════════\n\n"
        f"Structural lookups discovered for `{NAME}` in this project. Fetch a single\n"
        f"raw value with `{NAME} ids get <label>`; the full envelope is also at\n"
        f"`capabilities ids {NAME}`.\n\n"
    )
    return header + _render_ids_markdown(data) + "\n"


def _connections_home_section() -> str:
    """Where the connections this help describes are kept, for the project it
    is run in - rendered from the project's connections mode, so help names
    the home the resolver reads rather than one it may not. Empty for a
    capability without the connections tier. Reads the project's files and
    never reaches the store, so help stays local."""
    if "_resolve_env_key" not in globals():
        return ""
    machine = _CONFIG_HOME / NAME / "connections.json"
    header = (
        "\n═══ Where connections live ══════════════════════════════════════════════════\n\n")
    reported = f"`{NAME} connections` names where each value resolves from.\n"
    root = _project_root()
    if root is None:
        return (header + "There is no project here, so connections are read from the "
                "machine's\n"
                f"  {machine}\n" + reported)
    envelope = _project_capabilities_dir(root)
    try:
        mode = connections_mode(envelope, root)
    except StoreError as e:
        _die(6, e.slug, e.message, e.hint)
    if mode == "store":
        return (header + "This project keeps its connections in its store, not in "
                "files: each\n"
                "connection is a row of the store's `capabilities_connections` table, "
                "and\n"
                "this project's grant on it a row of `capabilities_connection_grants`.\n"
                "No connections.json, the project's or the machine's, is read for this "
                "project.\n" + reported)
    return (header + "This project keeps its connections in files: its own\n"
            f"  {envelope / NAME / 'connections.json'}\n"
            "then, for a connection id the project does not declare itself, the "
            "machine's\n"
            f"  {machine}\n"
            "used here once this project grants it.\n" + reported)


def _cmd_help() -> None:
    """Bare top-level help: the CLI's HELP body (module-level `HELP` if
    defined, else the module docstring), then where this project keeps the
    capability's connections, then the project's Identifiers section. Only
    fires when no extra args follow — per-verb help stays untouched so
    `<NAME> help <subcommand>` is not intercepted."""
    g = globals()
    text = g.get("HELP") or g.get("__doc__") or ""
    if text.startswith("\n"):
        text = text.lstrip("\n")
    sys.stdout.write(text)
    if text and not text.endswith("\n"):
        sys.stdout.write("\n")
    home = _connections_home_section()
    if home:
        sys.stdout.write(home)
    declared = _declared_section()
    if declared:
        sys.stdout.write(declared)
    section = _identifiers_section()
    if section:
        sys.stdout.write(section)


def _field_line(field: dict, scoped: bool = False) -> str:
    """One declared field or setting as help prints it."""
    kind = field.get("type") or "string"
    if kind == "enum":
        kind = "|".join(field.get("choices") or [])
    traits = [kind, "required" if field.get("required") else "optional"]
    if field.get("secret"):
        traits.append("secret, stdin only" + (f", kept as {field['env']}" if field.get("env") else ""))
    if field.get("default") is not None:
        traits.append(f"default {json.dumps(field['default'])}")
    if field.get("identity") is True:
        traits.append("main identifier")
    if scoped:
        traits = [kind]
        if field.get("default") is not None:
            traits.append(f"default {json.dumps(field['default'])}")
        traits.append({"reload": "a running service takes it on `service reload`",
                       "restart": "a running service takes it on a restart",
                       "next_call": "read on the next call"}.get(field.get("apply"), ""))
        return (f"    {field['key']} @{field.get('scope')} ({', '.join(t for t in traits if t)})"
                f" - {field.get('help', '')}\n")
    return f"    {field['key']} ({', '.join(traits)}) - {field.get('help', '')}\n"


def _declared_section() -> str:
    """The verbs the contract answers from this capability's declarations -
    `connection`, `setup`, `settings` and the linking methods - rendered from
    the declarations themselves, so help and behaviour cannot part."""
    conns = _connections_declaration()
    settings = _settings_declaration()
    out = ""
    if conns and conns.get("fields") is not None:
        out += (f"\n## Connections, written through the contract\n\n"
                f"  {NAME} connection add <id> [--project|--global|--machine] [--default] "
                "[--replace] [--field KEY=VALUE ...] [--env KEY=ENV_KEY ...] [--stdin]\n"
                "      [--identity ID [--display-name TEXT]]\n"
                "      Write one connection from the fields below. --project (the default)\n"
                "      writes this project's record, --global the machine's, and --machine\n"
                "      the machine's as administration of the machine: from anywhere, with\n"
                "      no project or global policy read. Where the store holds the rows\n"
                "      every agent inherits, a connection, its grant and a default pointer\n"
                "      are rows of the store at either scope and no file is written: a\n"
                "      project that keeps its records in files is refused (exit 6\n"
                "      connections_in_store), and so is a global write while the store does\n"
                "      not answer (exit 5). A secret field is\n"
                "      taken only from the JSON object on stdin (--stdin), never from argv, and\n"
                "      written to that scope's credentials file - the project's .env.local, or\n"
                f"      {CREDENTIALS_ENV} - under its own env key, which the\n"
                "      entry names. --env KEY=ENV_KEY instead names, for a secret field, a\n"
                "      key already set in the cascade, and writes no value for it (exit 6\n"
                "      env_key_unset where it resolves nowhere). A connection that exists\n"
                "      is refused (exit 6 connection_exists) unless --replace is given; it\n"
                "      then keeps every field not given, and null in the JSON object clears\n"
                "      one. --default\n"
                "      points the scope's default at it. --identity ID records who the\n"
                "      connection is, as login and doctor record it on success, with\n"
                "      --display-name TEXT beside it; --display-name alone renames the one\n"
                "      recorded, and --identity '' clears it. `connections` lists each\n"
                "      connection's identity from its record, with no round-trip: the one\n"
                "      recorded, else the value of the field marked main identifier below.\n"
                "      Answers the fields as they now resolve, secrets masked.\n"
                f"  {NAME} connection remove <id> [--project|--global|--machine]\n"
                "      Remove it, its default pointer, and the secret lines `connection add`\n"
                "      wrote for it; a key another connection names is kept. Refused (exit 6\n"
                "      connection_granted) while a project is granted it, naming each one.\n"
                f"  {NAME} connections show <id> --reveal <KEY>\n"
                "      Print the value of one field below of one connection this project may\n"
                "      use, raw and in the clear, and nothing else: the value `connections`\n"
                "      reports masked for a secret. It passes the policy gate as an operational\n"
                "      verb. An undeclared key exits 6 unknown_field and a key that holds no\n"
                "      value exits 3 not_set, with nothing on stdout.\n")
        out += "  Fields:\n" + ("".join(_field_line(f) for f in conns["fields"])
                                or "    none - an entry carries no fields of its own\n")
    if conns and conns.get("setup"):
        out += (f"\n## Machine setup, written through the contract\n\n"
                f"  {NAME} setup [show] [--reveal <KEY>] | setup set [--machine] "
                "[--field KEY=VALUE ...] [--stdin] | setup unset [--machine] <KEY> ...\n"
                "      What this machine is given once, before any connection, kept in\n"
                f"      {CREDENTIALS_ENV}; `show` says where each resolves\n"
                "      from, secrets masked, and outside any project reads no policy.\n"
                "      --reveal <KEY> prints that one value instead, raw and in the clear, and\n"
                "      nothing else; an undeclared key exits 6 unknown_field and one that\n"
                "      resolves nowhere exits 3 not_set, with nothing on stdout. A secret\n"
                "      is taken only from the JSON object on stdin. --machine writes as\n"
                "      administration of the machine: from anywhere, with no policy read.\n")
        out += "".join(_field_line(f) for f in conns["setup"])
    if conns and conns.get("link"):
        out += ("\n## Linking a connection\n\n"
                "  Each method runs with --connection <id> added, speaks JSON lines on stdout -\n"
                "  one object per line naming its `event`: qr {payload, expires?, refreshed},\n"
                "  pairing_code {code, phone}, phone_needed, code_needed {phone, retry},\n"
                "  password_needed {hint, retry}, linked, progress, then done {result} or\n"
                "  error {exit, error} - and reads the answer to each *_needed event as one\n"
                "  line on stdin. The exit code is the one the method has without --events.\n")
        for method in conns["link"]:
            out += (f"  {' '.join(method.get('argv') or [])}\n"
                    f"      {method.get('label', '')}: {method.get('help', '')}\n")
    if settings:
        out += (f"\n## Settings, read and written through the contract\n\n"
                f"  {NAME} settings [show] [--scope S]\n"
                "      Every settings document, whole, with the declared keys below resolved.\n"
                f"  {NAME} settings get <key> | set <key> <value> | unset <key> [--scope S]\n"
                "      One key, dotted for a nested one; <value> is read as JSON, else as text.\n"
                f"  {NAME} settings put [--scope S] < document.json\n"
                "      Replace one scope's document whole.\n"
                "      A write is checked as the capability reads it before it replaces the file\n"
                "      (exit 6 settings_invalid otherwise); a TOML file is rewritten from its\n"
                "      content, so its comments are not kept. S is the scope a key is declared\n"
                "      at, else the only one; homes:\n")
        for home in settings["homes"]:
            base = ("<envelope>/" + NAME if home["scope"] == "project"
                    else str(_CONFIG_HOME / NAME))
            out += (f"    {home['scope']}: {base}/{home['path']} ({home['format']})"
                    + (f", inheriting {home['inherits']} key by key" if home.get("inherits") else "")
                    + "\n")
        if settings["keys"]:
            out += "  Declared keys:\n" + "".join(_field_line(k, scoped=True) for k in settings["keys"])
    return out


def _cmd_ids(argv: list[str]) -> None:
    sub = argv[0] if argv else "list"
    scope = "project"
    if sub in ("set", "rm") and "--global" in argv[1:]:
        argv = [a for a in argv if a != "--global"]
        scope = "global"
    data = _identifiers_load()
    if sub == "list":
        _emit(data); return
    if sub == "get":
        if len(argv) < 2 or argv[1] not in data:
            _die(3, "not_found", "unknown identifier label",
                 f"`{NAME} ids list` shows the labels")
        _emit((data[argv[1]] or {}).get("value")); return
    if sub in ("set", "rm"):
        _read_only_gate(f"`{NAME} ids {sub}`")
    if sub == "set":
        if len(argv) < 3:
            _die(6, "input", f"usage: {NAME} ids set <label> <value> [--note <text>] [--global]")
        label, raw = argv[1], argv[2]
        try:
            value = json.loads(raw)
        except ValueError:
            value = raw
        note = ""
        if "--note" in argv:
            ni = argv.index("--note")
            if ni + 1 >= len(argv):
                _die(6, "input", "--note needs a value")
            note = argv[ni + 1]
        _identifiers_write(label, value, note, scope)
        _emit({"set": label} if scope == "project" else {"set": label, "scope": scope})
        return
    if sub == "rm":
        held = data if scope == "project" else _identifiers_scope(scope)
        if len(argv) < 2 or argv[1] not in held:
            _die(3, "not_found", "unknown identifier label",
                 f"`{NAME} ids list` shows the labels")
        _identifiers_remove(argv[1], scope)
        _emit({"removed": argv[1]} if scope == "project"
              else {"removed": argv[1], "scope": scope})
        return
    _die(6, "input", f"unknown ids subcommand {sub!r}", f"{NAME} ids list|get|set|rm")


REFERENCE_PREFIX = "reference."


def _front_matter(body: str) -> tuple[str | None, str | None]:
    """`name` and `description` out of a reference's leading front matter."""
    lines = body.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, None
    name = desc = None
    for line in lines[1:30]:
        if line.strip() == "---":
            break
        if line.startswith("name:"):
            name = line.split(":", 1)[1].strip()
        elif line.startswith("description:"):
            desc = line.split(":", 1)[1].strip()
    return name, desc


def _reference_bodies() -> dict[str, str]:
    """Every reference this project can see, keyed by its document key."""
    out: dict[str, str] = {}
    try:
        adapter = _records()
        for key in adapter.document_keys(NAME):
            if not key.startswith(REFERENCE_PREFIX):
                continue
            doc = adapter.document_read(NAME, key)
            if doc:
                out[key] = doc["body"]
    except StoreError as e:
        _die(6, e.slug, e.message, e.hint)
    return out


def _cmd_refs(argv: list[str] | None = None) -> None:
    """`refs` lists what this project can load; `refs show <name>` prints one.

    The listing carries each reference's path; `refs show` prints a body."""
    argv = argv or []
    bodies = _reference_bodies()
    adapter = _records()
    entries = []
    for key, body in sorted(bodies.items()):
        name, desc = _front_matter(body)
        if not name:
            continue
        entry = {"name": name, "description": desc or "", "key": key}
        # A path when there is one to open, a source when there is not. The
        # adapter answers that; the listing does not ask where it lives.
        path = adapter.document_path(NAME, key)
        if path is None:
            entry["source"] = adapter.source
        else:
            entry["path"] = str(path)
        entries.append((name, entry, body))

    if argv and argv[0] == "show":
        if len(argv) < 2:
            _die(6, "input", f"usage: {NAME} refs show <name>")
        wanted = argv[1]
        for name, entry, body in entries:
            if wanted in (name, entry["key"], entry["key"][len(REFERENCE_PREFIX):]):
                sys.stdout.write(body if body.endswith("\n") else body + "\n")
                return
        _die(3, "not_found", f"no reference named {wanted!r}",
             f"`{NAME} refs` lists them")
    if argv:
        _die(6, "input", f"unknown refs subcommand {argv[0]!r}", f"{NAME} refs [show <name>]")
    _emit([entry for _name, entry, _body in entries])


def _context_edit_files(key: str) -> tuple[Path, Path]:
    token = hashlib.sha256(f"{NAME}\0{key}".encode()).hexdigest()[:16]
    root = _state_dir() / "record-edits"
    return root / f"{token}.md", root / f"{token}.json"


def _cmd_context(argv: list[str]) -> None:
    """Read or edit project long text without exposing its backend."""
    sub = argv[0] if argv else "list"
    adapter = _records()
    if sub == "list":
        _emit({"documents": adapter.document_keys(NAME),
               "records": {"mode": adapter.mode, "source": adapter.source}})
        return
    if len(argv) < 2:
        _die(6, "input", f"usage: {NAME} context show|edit|put <key>")
    key = argv[1]
    if sub in ("edit", "put"):
        _read_only_gate(f"`{NAME} context {sub}`")
    if sub == "show":
        doc = adapter.document_read(NAME, key)
        if doc is None:
            _die(3, "not_found", f"no context document {key!r}",
                 f"`{NAME} context list` shows the keys")
        sys.stdout.write(doc["body"] if doc["body"].endswith("\n")
                         else doc["body"] + "\n")
        return
    work, meta = _context_edit_files(key)
    if sub == "edit":
        doc = adapter.document_read(NAME, key)
        direct = adapter.document_path(NAME, key)
        base = doc["hash"] if doc else None
        path = direct or work
        if direct is None:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(doc["body"] if doc else "")
        meta.parent.mkdir(parents=True, exist_ok=True)
        meta.write_text(json.dumps({"key": key, "path": str(path),
                                    "base": base, "direct": direct is not None},
                                   ensure_ascii=False, indent=2) + "\n")
        _emit({"key": key, "path": str(path), "base": base,
               "records": {"mode": adapter.mode, "source": adapter.source},
               "next": f"edit the path, then run `{NAME} context put {key}`"})
        return
    if sub == "put":
        try:
            checkout = json.loads(meta.read_text())
        except (OSError, ValueError) as exc:
            _die(6, "edit_not_started",
                 f"no valid edit checkout for {key!r}: {exc}",
                 f"run `{NAME} context edit {key}` first")
        if checkout.get("key") != key:
            _die(6, "edit_mismatch", f"edit checkout does not belong to {key!r}")
        path = Path(str(checkout.get("path") or ""))
        try:
            body = path.read_text()
            version = adapter.document_put(
                NAME, key, body, author=f"{NAME} context put",
                media_type="text/markdown", base=checkout.get("base"))
        except OSError as exc:
            _die(6, "edit_unreadable", f"cannot read edit path {path}: {exc}")
        except StoreError as exc:
            _die(6, exc.slug, exc.message, exc.hint)
        meta.unlink(missing_ok=True)
        if not checkout.get("direct"):
            path.unlink(missing_ok=True)
        _emit({"put": key, "version": version,
               "records": {"mode": adapter.mode, "source": adapter.source}})
        return
    _die(6, "input", f"unknown context subcommand {sub!r}",
         f"{NAME} context list|show|edit|put")


INVENTORY_NETWORK_MODES = ("none", "optional", "required")


def _inventory_declaration() -> dict | None:
    """The manifest's `inventory` block, derived from the INVENTORY constant.

    `None` says the capability has nothing of its own to report here, so a
    reader assembling a whole project knows before it asks; the verb still
    answers, with the empty envelope, so nothing branches on absence."""
    if not INVENTORY:
        return None
    network = INVENTORY.get("network", "none")
    return {"network": network if network in INVENTORY_NETWORK_MODES else "none"}


def _cmd_inventory(argv: list[str]) -> None:
    """What this capability holds in this project, in one shape for all of them.

    The read is local, secret-free, and leaves nothing changed behind it.
    `--network` is the caller's explicit consent to reach the remote system for
    detail a local read cannot supply; without it that detail is named in
    `deferred` rather than fetched, so assembling a whole project never waits
    on a network the caller did not choose. `--json` is accepted for
    explicitness; the output is always this JSON."""
    network = False
    for arg in argv:
        if arg == "--network":
            network = True
        elif arg != "--json":
            _die(6, "input", f"unknown inventory option {arg!r}",
                 f"{NAME} inventory [--network]")
    root = _project_root()
    report: dict = {"capability": NAME,
                    "project": str(root) if root is not None else None,
                    "network": network,
                    "metrics": [], "items": [], "service": None, "deferred": []}
    if INVENTORY:
        built = _inventory(network) or {}
        for field in ("metrics", "items", "deferred"):
            report[field] = list(built.get(field) or [])
        report["service"] = built.get("service")
    _emit(report)


# A store setting that cannot be used is a configuration fault; a store that
# cannot be reached, is busy, or refuses the migration is the environment's.
_STORE_SETTING_SLUGS = frozenset({
    "store_not_configured", "store_not_postgres", "store_setting_unreadable",
    "store_setting_too_new", "bad_store_setting", "sslmode_too_weak",
    "bad_schema_name", "driver_missing"})


def _tables_declared() -> bool:
    """Whether the capability keeps tables in the machine's store (`TABLES`)."""
    return bool(globals().get("TABLES"))


def _cmd_migrate(argv: list[str]) -> None:
    """`migrate` applies the capability's pending steps to its tables in the
    machine's store, through the shared database library and under its lock;
    `migrate status` reports where they stand, without a lock, changing nothing.
    The manager runs `migrate` when it installs or updates the payload, and a
    service runs it when it starts."""
    if argv not in ([], ["status"]):
        _die(6, "input", f"unknown migrate arguments {' '.join(argv)!r}",
             f"{NAME} migrate [status]")
    steps, major, minor = _tables()
    try:
        from capabilities_contract import db
    except ImportError:
        _die(6, "driver_missing",
             "the shared database library capabilities-contract is not installed",
             f"run {NAME} through its own script header, which pins it")
    conn = None
    try:
        conn = db.connect(application_name=NAME, transaction=True)
        if argv:
            found = db.status(conn, NAME, steps, major=major, minor=minor)
            stored = (None if found.stored_major is None
                      else {"major": found.stored_major, "minor": found.stored_minor})
            report = {"owner": found.owner, "schema": found.schema, "state": found.state,
                      "code": {"major": found.major, "minor": found.minor},
                      "store": stored, "applied": found.applied,
                      "pending": found.pending, "changed": found.changed,
                      "warnings": found.warnings}
        else:
            done = db.migrate(conn, NAME, steps, major=major, minor=minor)
            report = {"owner": done.owner, "schema": done.schema,
                      "applied": done.applied, "skipped": done.skipped,
                      "version": {"major": done.major, "minor": done.minor},
                      "warnings": done.warnings}
    except db.DbError as exc:
        _die(6 if exc.slug in _STORE_SETTING_SLUGS else 5, exc.slug, exc.message, exc.hint)
    finally:
        if conn is not None:
            conn.close()
    _emit(report)


# What `migrate files plan` reads its tables through: one connection per
# database, held in one transaction that is never committed, in which the
# steps of any table a migration would make or bring forward are run, so the
# capability reads the store as an upgrade would leave it, and the transaction
# is rolled back when the plan ends. The steps it ran, by owner.
_PLAN_LINKS: dict = {}
_PLAN_RAN: set = set()
_PLAN_PENDING: dict = {}


class _PlanConnection:
    """A connection of a plan: the database's one plan link, where a commit
    keeps what the caller did for the rest of the plan and a rollback or a
    close undoes what it did since, and nothing ever reaches the store."""

    _OWN = ("_real", "_setting", "_closed", "row_factory")

    def __init__(self, real, setting):
        object.__setattr__(self, "_real", real)
        object.__setattr__(self, "_setting", setting)
        object.__setattr__(self, "_closed", False)
        object.__setattr__(self, "row_factory", None)

    def __getattr__(self, name: str):
        return getattr(self._real, name)

    def __setattr__(self, name: str, value) -> None:
        if name in self._OWN:
            object.__setattr__(self, name, value)
        elif name != "autocommit":
            setattr(self._real, name, value)

    @property
    def autocommit(self) -> bool:
        return False

    @property
    def closed(self) -> bool:
        return self._closed or self._real.closed

    def cursor(self, *args, **kwargs):
        if self.row_factory is not None:
            kwargs.setdefault("row_factory", self.row_factory)
        return self._real.cursor(*args, **kwargs)

    def execute(self, query, params = None, **kwargs):
        return self.cursor().execute(query, params, **kwargs)

    def transaction(self, *args, **kwargs):
        return self._real.transaction(*args, **kwargs)

    def commit(self) -> None:
        self._real.execute("RELEASE SAVEPOINT capabilities_plan")
        self._real.execute("SAVEPOINT capabilities_plan")

    def rollback(self) -> None:
        if not self._real.closed:
            self._real.execute("ROLLBACK TO SAVEPOINT capabilities_plan")

    def close(self) -> None:
        if not self._closed:
            self.rollback()
        object.__setattr__(self, "_closed", True)

    def __enter__(self) -> "_PlanConnection":
        return self

    def __exit__(self, kind, *exc) -> None:
        if not self._closed:
            if kind is None:
                self.commit()
            self.close()


def _plan_store() -> None:
    """Make every connection this process opens through the shared database
    layer a plan connection, and every migration on one a step run inside the
    plan's transaction and recorded under its owner, never committed: a plan
    creates and upgrades nothing, whatever tables the capability reaches."""
    try:
        from capabilities_contract import db
    except ImportError:
        return
    real_connect, real_migrate, real_status = db.connect, db.migrate, db.status

    def plan_connect(*, application_name: str, project_root = None,
                     setting = None, **kwargs):
        # A plan holds one transaction open on its link for the whole run, so
        # the link is a session connection whichever kind the caller asked for.
        kwargs.pop("transaction", None)
        setting = setting if setting is not None else db.resolve_setting(project_root)
        key = (repr(sorted(setting.connect_kwargs().items())), setting.schema)
        link = _PLAN_LINKS.get(key)
        if link is None or link.closed or link.broken:
            link = real_connect(application_name=application_name, setting=setting, **kwargs)
            link.execute("SET TRANSACTION READ WRITE")
            link.execute("SET LOCAL lock_timeout = '5s'")
            link.execute("SAVEPOINT capabilities_plan")
            _PLAN_LINKS[key] = link
        return _PlanConnection(link, setting)

    def held(conn, owner: str, steps, major: int, minor: int, schema):
        fresh = real_connect(application_name=NAME, setting=conn._setting)
        try:
            return real_status(fresh, owner, steps, major=major, minor=minor,
                               schema=schema or conn._setting.schema)
        finally:
            fresh.close()

    def plan_status(conn, owner: str, steps, *, major: int, minor: int,
                    schema = None):
        if not isinstance(conn, _PlanConnection):
            return real_status(conn, owner, steps, major=major, minor=minor, schema=schema)
        found = held(conn, owner, list(steps), major, minor, schema)
        found.pending = [s for s in found.pending if (id(conn._real), owner, s) not in _PLAN_RAN]
        if found.state == "pending" and not found.pending:
            found.state = "current"
        return found

    def plan_migrate(conn, owner: str, steps, *, major: int, minor: int,
                     schema = None):
        if not isinstance(conn, _PlanConnection):
            return real_migrate(conn, owner, steps, major=major, minor=minor, schema=schema)
        steps = list(steps)
        found = held(conn, owner, steps, major, minor, schema)
        if found.state in ("checksum_mismatch", "schema_too_new"):
            raise db.DbError(found.state, f"the store's {owner} tables cannot be brought to "
                             f"{major}.{minor}: {found.state}")
        if found.pending:
            _PLAN_PENDING[owner] = {
                "from": None if found.stored_major is None
                else f"{found.stored_major}.{found.stored_minor}",
                "to": f"{major}.{minor}", "steps": list(found.pending)}
        by_id = {}
        for step in steps:
            ident, text = (step.id, step.sql) if hasattr(step, "sql") else (step[0], step[1])
            by_id[ident] = text
        for ident in found.pending:
            if (id(conn._real), owner, ident) in _PLAN_RAN:
                continue
            try:
                with conn._real.transaction():
                    conn._real.execute(by_id[ident])
            except Exception as exc:
                raise db.DbError("step_failed", f"step {ident} of {owner} could not be "
                                 f"planned: {exc}") from None
            _PLAN_RAN.add((id(conn._real), owner, ident))
        # What the steps made stays for the rest of the plan, whichever
        # connection of it rolls back later.
        conn._real.execute("RELEASE SAVEPOINT capabilities_plan")
        conn._real.execute("SAVEPOINT capabilities_plan")
        return db.MigrateResult(owner=owner, schema=schema or conn._setting.schema,
                                skipped=list(found.applied), major=major, minor=minor)

    db.connect, db.migrate, db.status = plan_connect, plan_migrate, plan_status
    here = globals()
    here["_HOLD_RECORDS_CONNECTION"] = True
    for name, value in list(here.items()):
        for real, planned in ((real_connect, plan_connect), (real_migrate, plan_migrate),
                              (real_status, plan_status)):
            if value is real:
                here[name] = planned


MIGRATE_FILES_ACTIONS = ("plan", "write", "verify")


def _cmd_migrate_files(argv: list[str]) -> None:
    """`migrate files plan|write|verify [--answers FILE]` moves this
    capability's own configuration files of the project into the store, for
    the manager's `capabilities migrate`, which runs it on the agent's master
    and owns the order: `plan` says what would be written and every question
    code cannot answer, writing nothing; `write` writes it, leaving the files
    for the manager to archive and remove; `verify` reads it back and says
    whether the store now holds what the files said. The capability's own
    `_migrate_files_mover(action, answers, all_answers)`, outside the fences,
    does the moving and returns its report: `items`, `questions`, `files` (the
    ones it consumed), `verified` and whatever else it names; a capability
    without one moves nothing here. `--answers` is the person's recorded
    answers as JSON, keyed by capability. Every record or setting written here
    is the migration's own (`migrate@<node>`). `plan` changes nothing in the
    store, tables included: a table it would make or bring forward is made or
    brought forward only inside a transaction that is rolled back, and its
    steps are named under `tables_to_upgrade` by owner."""
    global _RECORDS_ACTOR
    action = argv[0] if argv else ""
    rest = argv[1:]
    answers: dict = {}
    if rest[:1] == ["--answers"] and len(rest) == 2:
        try:
            answers = json.loads(Path(rest[1]).read_text())
        except (OSError, ValueError) as e:
            _die(6, "input", f"cannot read the answers file {rest[1]}: {e}")
        if not isinstance(answers, dict):
            _die(6, "input", f"the answers file {rest[1]} must hold a JSON object")
    elif rest:
        _die(6, "input", f"unknown migrate files arguments {' '.join(rest)!r}",
             f"{NAME} migrate files plan|write|verify [--answers FILE]")
    if action not in MIGRATE_FILES_ACTIONS:
        _die(6, "input", f"migrate files needs one of {', '.join(MIGRATE_FILES_ACTIONS)}",
             f"{NAME} migrate files plan|write|verify [--answers FILE]")
    if _project_root() is None:
        _die(6, "no_project", "migrate files moves a project's files, and this is not one",
             "run it in the project; `capabilities migrate` does")
    _RECORDS_ACTOR = "migrate"
    if action == "plan":
        # A plan writes nothing, the capability's tables included: it reads
        # them as an upgrade would leave them and names the steps instead.
        _plan_store()
    mover = globals().get("_migrate_files_mover")
    report = {"capability": NAME, "action": action, "mover": callable(mover),
              "items": [], "questions": [], "files": [], "warnings": []}
    if callable(mover):
        mine = answers.get(NAME) if isinstance(answers.get(NAME), dict) else {}
        report.update(mover(action, mine, answers) or {})
    if _PLAN_PENDING:
        report["tables_to_upgrade"] = dict(_PLAN_PENDING)
    if action == "verify":
        report.setdefault("verified", True)
    _emit(report)


MACHINE_READ_EFFECT = ("outside any project these verbs use the machine's own "
                       "connections, read-only; inside a project its grants "
                       "alone decide")


def _cmd_connections_reported() -> None:
    """The capability's own connections report, with what the contract knows
    beside it. The report stays the capability's: it is taken whole, and the
    capability's effective policy state is added to it. Under the read-only
    switch every connection in it is marked read-only and the switch is named
    beside it, so a reader sees why no connection may write; in a machine read
    each connection the machine lent is named as the machine's, read-only.
    Each connection carries `identity`, who it is as its record says, read
    without a round-trip."""
    import contextlib
    import io
    captured = io.StringIO()
    try:
        with contextlib.redirect_stdout(captured):
            _cmd_connections()
    except SystemExit:
        sys.stdout.write(captured.getvalue())
        raise
    try:
        report = json.loads(captured.getvalue())
    except ValueError:
        report = None
    if not isinstance(report, dict):
        sys.stdout.write(captured.getvalue())
        return
    conns = report.get("connections")
    conns = conns if isinstance(conns, dict) else {}
    if "_connection_identity" in globals() and conns:
        # Who each connection is, from its record alone: no round-trip.
        held = _inventory_connections().get("connections") or {}
        for cid, entry in conns.items():
            if isinstance(entry, dict):
                entry["identity"] = _connection_identity(held.get(cid))
    if read_only_switch():
        for entry in conns.values():
            if isinstance(entry, dict):
                entry["allow_write"] = False
        report["read_only_switch"] = {
            "variable": READ_ONLY_ENV, "on": True,
            "effect": READ_ONLY_EFFECT}
    lent = globals().get("_MACHINE_LENT") or {}
    if lent:
        for cid in lent:
            if isinstance(conns.get(cid), dict):
                conns[cid]["allow_write"] = False
        report["machine_reads"] = {
            "verbs": list(MACHINE_READS),
            "connections": {cid: {"scope": "machine", "source": source}
                            for cid, source in sorted(lent.items())},
            "effect": MACHINE_READ_EFFECT}
    report["policy"] = _policy_state()
    _emit(report)


# --- Declared connection fields, setup, linking and settings -----------------
#
# What a person is asked for is declared once, at the top of the script, so any
# reader - `manifest`, an agent, a control panel - renders it without knowing
# the capability. Each declaration is optional and read with `globals().get`,
# so a script that declares none still runs:
#   CONN_FIELDS   a connection entry's own fields, one dict per field
#   SETUP_FIELDS  what the machine is given once, before any connection
#   SETUP         that setup's title, the guide to obtaining it, its verify verb
#   LINK_METHODS  the interactive ceremonies that link a connection
#   SETTINGS      where the capability's settings live, and the keys it declares

FIELD_TYPES = ("string", "integer", "number", "boolean", "url", "email",
               "phone", "path", "enum", "list", "object")
SETTING_SCOPES = ("project", "global", "machine")
SETTING_APPLY = ("next_call", "reload", "restart")
SETTING_FORMATS = ("json", "toml")
LINK_EVENTS = ("qr", "pairing_code", "phone_needed", "code_needed",
               "password_needed", "progress", "linked", "done", "error")


def _connections_declaration() -> dict | None:
    """The `connections` manifest entry: null for a capability without the
    connections tier; `fields` null where the capability declares none yet."""
    if "_resolve_env_key" not in globals():
        return None
    fields = globals().get("CONN_FIELDS")
    return {"fields": [dict(f) for f in fields] if fields is not None else None,
            "setup": [dict(f) for f in (globals().get("SETUP_FIELDS") or [])],
            "link": [dict(m) for m in (globals().get("LINK_METHODS") or [])]}


def _settings_declaration() -> dict | None:
    """The `settings` manifest entry: null when the capability keeps none."""
    declared = globals().get("SETTINGS")
    if not declared:
        return None
    return {"homes": [dict(h) for h in (declared.get("homes") or [])],
            "keys": [dict(k) for k in (declared.get("keys") or [])]}


def _manifest_core() -> dict:
    """The declaration every capability's manifest carries. A capability that
    adds to its manifest - a service, a contribution - starts from this, so the
    shared part has one home."""
    return {"name": NAME, "summary": SUMMARY,
            "credentials": {"scope": SCOPE, "keys": CRED_KEYS},
            "docs": {"base": DOCS_BASE,
                     "topics": [entry["topic"] for entry in _guide_menu()]},
            "state": STATE, "inventory": _inventory_declaration(),
            "post_install": POST_INSTALL, "tables": _tables_declared(),
            "connections": _connections_declaration(),
            "settings": _settings_declaration(),
            "migrate_files": callable(globals().get("_migrate_files_mover")),
            **({"setup": _setup_presentation()}
               if "_setup_presentation" in globals() and globals().get("SETUP") else {})}


def _field_value(field: dict, raw, from_argv: bool = False):
    """One declared field's value, checked against its type. A value given on
    argv arrives as text and is read as the type would write it; a value from
    a JSON document arrives typed. Raises ValueError naming what is wrong."""
    import re as _re
    kind = field.get("type") or "string"
    key = field.get("key")
    if kind in ("string", "url", "email", "phone", "path", "enum"):
        if not isinstance(raw, str) or (field.get("required") and not raw.strip()):
            raise ValueError(f"{key} is text")
        value = raw.strip()
        if kind == "url" and not _re.match(r"https?://[^/\s]+", value):
            raise ValueError(f"{key} is an http(s) URL")
        if kind == "email" and not _re.fullmatch(r"[^@\s]+@[^@\s]+", value):
            raise ValueError(f"{key} is an email address")
        if kind == "phone" and not _re.fullmatch(r"\+?[0-9][0-9 ()-]{4,}", value):
            raise ValueError(f"{key} is a phone number, digits with an optional +")
        if kind == "enum" and value not in (field.get("choices") or []):
            raise ValueError(f"{key} is one of: {', '.join(field.get('choices') or [])}")
        return value
    if kind in ("integer", "number"):
        value = raw
        if from_argv and isinstance(raw, str):
            try:
                value = int(raw) if kind == "integer" else float(raw)
            except ValueError:
                raise ValueError(f"{key} is a {'whole ' if kind == 'integer' else ''}number") from None
        if isinstance(value, bool) or not isinstance(
                value, int if kind == "integer" else (int, float)):
            raise ValueError(f"{key} is a {'whole ' if kind == 'integer' else ''}number")
        if field.get("minimum") is not None and value < field["minimum"]:
            raise ValueError(f"{key} is at least {field['minimum']}")
        if field.get("maximum") is not None and value > field["maximum"]:
            raise ValueError(f"{key} is at most {field['maximum']}")
        return value
    if kind == "boolean":
        if from_argv and isinstance(raw, str):
            lowered = raw.strip().lower()
            if lowered in ("true", "yes", "on", "1"):
                return True
            if lowered in ("false", "no", "off", "0"):
                return False
        if not isinstance(raw, bool):
            raise ValueError(f"{key} is true or false")
        return raw
    if kind in ("list", "object"):
        value = raw
        if from_argv and isinstance(raw, str):
            try:
                value = json.loads(raw)
            except ValueError:
                if kind == "object":
                    raise ValueError(f"{key} is a JSON object") from None
                value = [part.strip() for part in raw.split(",") if part.strip()]
        if kind == "list" and not isinstance(value, list):
            raise ValueError(f"{key} is a list")
        if kind == "object" and not isinstance(value, dict):
            raise ValueError(f"{key} is a JSON object")
        return value
    raise ValueError(f"{key} declares an unknown type {kind!r}")


def _stdin_document(what: str) -> dict:
    """One JSON object read whole from standard input."""
    text = sys.stdin.read()
    try:
        document = json.loads(text) if text.strip() else {}
    except ValueError as e:
        _die(6, "input", f"{what} on stdin is not JSON: {e}")
    if not isinstance(document, dict):
        _die(6, "input", f"{what} on stdin is a JSON object")
    return document


# --- Linking events ----------------------------------------------------------
#
# A verb that links a connection interactively takes `--events`, and then
# speaks JSON lines on stdout, one object per line naming its `event`, and
# reads each answer it asks for as one line on stdin - so a program with no
# terminal can drive it. `_emit` then writes the result as the `done` event and
# `_die` writes an `error` event before its usual envelope on stderr.

_EVENTS_ON = [False]


def _events_begin() -> None:
    """Turn this process's output into the linking event stream."""
    _EVENTS_ON[0] = True


def _event(name: str, **fields) -> None:
    if not _EVENTS_ON[0]:
        return
    sys.stdout.write(json.dumps({"event": name, **fields}, ensure_ascii=False,
                                default=str) + "\n")
    sys.stdout.flush()


def _event_answer(name: str, **fields) -> str:
    """Ask for one value with a `*_needed` event and read its line from stdin."""
    _event(name, **fields)
    line = sys.stdin.readline()
    if not line:
        _die(6, "input_closed", f"standard input closed while {name} waited for an answer",
             "write one line on stdin for every *_needed event")
    return line.rstrip("\r\n")


# --- Settings ----------------------------------------------------------------

def _settings_homes(scope: str | None = None) -> list[dict]:
    homes = list(((globals().get("SETTINGS") or {}).get("homes")) or [])
    return [h for h in homes if scope is None or h.get("scope") == scope]


def _settings_home_path(home: dict) -> Path | None:
    """Where one home's document sits: under the capability's folder in the
    project envelope for `project`, under its config home otherwise."""
    if home.get("scope") == "project":
        root = _project_root()
        if root is None:
            return None
        return _project_capabilities_dir(root) / NAME / home["path"]
    return _CONFIG_HOME / NAME / home["path"]


def _settings_in_rows(home: dict) -> bool:
    """Whether one home's document is rows of the store: a project or global
    home of an agent whose records moved there. A machine home stays a file."""
    if home.get("scope") not in ("project", "global") or _project_root() is None:
        return False
    try:
        return _records().settings_kept() == "store"
    except StoreError as e:
        _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)


def _settings_read(home: dict) -> tuple:
    """One home's document: where it is kept, the document (None where there
    is none yet) and what keeps it from being read. Where the home is rows,
    `where` names the store's table rather than a file."""
    if _settings_in_rows(home):
        try:
            records = _records()
            return (records.collection_source(NAME, "setting"),
                    records.setting_document(NAME, home["scope"]), None)
        except StoreError as e:
            _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)
    path = _settings_home_path(home)
    if path is None or not path.is_file():
        return path, None, None
    try:
        text = path.read_text()
        if home.get("format") == "toml":
            import tomllib
            document = tomllib.loads(text)
        else:
            document = json.loads(text) if text.strip() else {}
    except Exception as e:
        return path, None, f"cannot read {path}: {e}"
    if not isinstance(document, dict):
        return path, None, f"{path} does not hold an object"
    return path, document, None


def _settings_parts(key) -> list:
    """A settings key as the keys from the document root: a dotted path, or a
    JSON array of keys for a path whose keys contain dots."""
    if isinstance(key, (list, tuple)):
        return [str(part) for part in key]
    if key.startswith("["):
        try:
            parts = json.loads(key)
        except ValueError:
            parts = None
        if isinstance(parts, list) and parts and all(
                isinstance(part, str) and part for part in parts):
            return parts
    return key.split(".")


def _settings_dig(document, key):
    """The value at a key, and whether it is there."""
    here = document
    for part in _settings_parts(key):
        if not isinstance(here, dict) or part not in here:
            return None, False
        here = here[part]
    return here, True


def _settings_put(document: dict, key, value) -> None:
    parts = _settings_parts(key)
    here = document
    for part in parts[:-1]:
        if not isinstance(here.get(part), dict):
            here[part] = {}
        here = here[part]
    here[parts[-1]] = value


def _settings_drop(document: dict, key) -> bool:
    parts = _settings_parts(key)
    here = document
    for part in parts[:-1]:
        here = here.get(part) if isinstance(here, dict) else None
        if not isinstance(here, dict):
            return False
    return here.pop(parts[-1], None) is not None if isinstance(here, dict) else False


def _toml_scalar(value) -> str:
    import datetime as _dt
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (_dt.datetime, _dt.date, _dt.time)):
        return value.isoformat()
    if isinstance(value, list):
        return "[" + ", ".join(_toml_scalar(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{_toml_name(k)} = {_toml_scalar(v)}"
                               for k, v in value.items()) + " }"
    raise ValueError(f"TOML holds no {type(value).__name__}")


def _toml_name(key: str) -> str:
    import re as _re
    return key if _re.fullmatch(r"[A-Za-z0-9_-]+", key) else json.dumps(key)


def _toml_dumps(document: dict, prefix: tuple = ()) -> str:
    """A document as TOML: scalars first, then each table, then each array of
    tables, which reads back as the same document. Comments are not kept."""
    lines, tables, arrays = [], [], []
    for key, value in document.items():
        if isinstance(value, dict):
            tables.append((key, value))
        elif isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            arrays.append((key, value))
        else:
            lines.append(f"{_toml_name(key)} = {_toml_scalar(value)}")
    out = "\n".join(lines) + ("\n" if lines else "")
    for key, value in tables:
        name = ".".join(_toml_name(k) for k in (*prefix, key))
        body = _toml_dumps(value, (*prefix, key))
        # A table holding only tables needs no header of its own.
        holds_tables_only = value and all(
            isinstance(v, dict) or (isinstance(v, list) and v and all(isinstance(i, dict) for i in v))
            for v in value.values())
        out += (body if holds_tables_only else f"\n[{name}]\n" + body)
    for key, items in arrays:
        name = ".".join(_toml_name(k) for k in (*prefix, key))
        for item in items:
            out += f"\n[[{name}]]\n" + _toml_dumps(item, (*prefix, key))
    return out


def _settings_write(home: dict, path: Path, document: dict) -> None:
    """Replace one home's document whole: checked by the capability where it
    checks its settings, written beside it, then renamed over it."""
    try:
        _records().guard_write(NAME, "setting", home.get("scope"))
    except StoreError as e:
        _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)
    text = (_toml_dumps(document) if home.get("format") == "toml"
            else json.dumps(document, ensure_ascii=False, indent=2) + "\n")
    check = globals().get("_settings_check")
    problems = [str(p) for p in (check(home["scope"], document) or [])] if check else []
    if problems:
        _die(6, "settings_invalid",
             problems[0] if str(path) in problems[0] else f"{path}: {problems[0]}",
             f"`{NAME} settings` shows the document; `{NAME} help` states the keys")
    path.parent.mkdir(parents=True, exist_ok=True)
    spare = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
        fd = os.open(spare, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
        os.replace(spare, path)
    finally:
        if spare.exists():
            spare.unlink()


def _settings_rows_write(home: dict, scope: str, change, base=None) -> dict:
    """Change one home's document where it is rows, in the store's one
    transaction: `change` takes the document and returns the new one, and the
    capability's check reads the whole result before anything is written.
    `base`, where given, is `{"generation": ...}` as the document was read,
    and the write is refused where another write moved it since."""
    check = globals().get("_settings_check")

    def checked(document: dict) -> list:
        return [str(p) for p in (check(scope, document) or [])] if check else []
    try:
        return _records().settings_write(NAME, scope, change, check=checked,
                                         seed=home.get("seed"),
                                         **({"base": base["generation"]} if base else {}))
    except StoreError as e:
        if e.slug == "not_found":
            _die(3, e.slug, e.message, e.hint)
        if e.slug == "settings_invalid":
            _die(6, e.slug, e.message,
                 f"`{NAME} settings` shows the document; `{NAME} help` states the keys")
        _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)


def _records_in_store() -> bool:
    """Whether this project is an agent whose records and settings moved into
    the store (its registry row has `migrated_at`): every record and settings
    document it keeps is then rows, and no file of them is read or written."""
    if _project_root() is None:
        return False
    try:
        return _records().settings_kept() == "store"
    except StoreError as e:
        _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)


def _env_override(*keys: str, value=None):
    """The first of `keys` the environment sets (or `value`, where the caller
    read it elsewhere), naming a file to read records or settings from; for an
    agent whose records moved into the store such a file is not read, so the
    override is ignored with a one-line notice on stderr, and None returned."""
    found = value if value is not None else next(
        (os.environ.get(k) for k in keys if os.environ.get(k)), None)
    if not found:
        return None
    if _records_in_store():
        named = next((k for k in keys if os.environ.get(k)), keys[0] if keys else "override")
        sys.stderr.write(f"{NAME}: {named} is ignored: this agent's records and settings "
                         "are in the store, and no file is read for them\n")
        return None
    return found


def _settings_diff(before: dict, after: dict) -> list:
    """What changes between two documents, path by path: `-` removed, `+`
    added, `~` changed."""
    def leaves(document, prefix=()):
        out = {}
        for key, value in (document or {}).items():
            if isinstance(value, dict) and value:
                out.update(leaves(value, (*prefix, key)))
            else:
                out[(*prefix, key)] = value
        return out

    def name(path):
        return (".".join(path) if all("." not in part for part in path)
                else json.dumps(list(path), ensure_ascii=False))

    def show(value):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    old, new = leaves(before), leaves(after)
    lines = [f"- {name(p)}: {show(old[p])}" for p in sorted(set(old) - set(new))]
    for p in sorted(new):
        if p not in old:
            lines.append(f"+ {name(p)}: {show(new[p])}")
        elif show(old[p]) != show(new[p]):
            lines.append(f"~ {name(p)}: {show(old[p])} -> {show(new[p])}")
    return lines


def _settings_key_decl(key: str, scope: str | None = None) -> dict | None:
    """A key's declaration: at `scope` when one is named, else the first."""
    for decl in ((globals().get("SETTINGS") or {}).get("keys")) or []:
        if decl.get("key") == key and (scope is None or decl.get("scope") == scope):
            return decl
    return None


def _settings_value(decl: dict, documents: dict) -> tuple:
    """A declared key's value and the scope it came from: its own scope, then
    the scope that scope inherits from, by top-level key, else its default."""
    scope = decl.get("scope")
    top = decl["key"].split(".", 1)[0]
    seen: set = set()
    while scope and scope not in seen:
        seen.add(scope)
        document = documents.get(scope)
        if isinstance(document, dict) and top in document:
            value, found = _settings_dig(document, decl["key"])
            return (value, scope) if found else (decl.get("default"), "default")
        home = next(iter(_settings_homes(scope)), {})
        scope = home.get("inherits")
    return decl.get("default"), "default"


def _settings_report(scope: str | None) -> dict:
    homes, documents, in_rows = [], {}, False
    for home in _settings_homes(scope):
        path, document, error = _settings_read(home)
        documents[home["scope"]] = document
        rows = _settings_in_rows(home)
        in_rows = in_rows or rows
        row = {"scope": home["scope"], "format": home.get("format", "json"),
               "path": str(path) if path else None,
               "exists": (document is not None) if rows else bool(path and path.is_file()),
               "document": document}
        if home.get("inherits"):
            row["inherits"] = home["inherits"]
        if error:
            row["error"] = error
        homes.append(row)
    for home in _settings_homes():
        if home["scope"] not in documents:
            documents[home["scope"]] = _settings_read(home)[1]
    keys = []
    for decl in ((globals().get("SETTINGS") or {}).get("keys")) or []:
        if scope and decl.get("scope") != scope:
            continue
        value, source = _settings_value(decl, documents)
        keys.append({**decl, "value": value, "from": source})
    report = {"capability": NAME, "declared": bool(globals().get("SETTINGS")),
              "homes": homes, "keys": keys}
    if in_rows:
        # Which state of the store this was assembled from: a reader holding
        # these generations has read exactly what they name.
        try:
            report["generations"] = _records().setting_generations(NAME)
        except StoreError as e:
            _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)
    return report


def _settings_checked_put(scope: str, document) -> dict:
    """A whole document given for `scope`, its declared keys checked."""
    if not isinstance(document, dict):
        _die(6, "input", "the settings document must be a JSON object")
    for each in ((globals().get("SETTINGS") or {}).get("keys")) or []:
        if each.get("scope") != scope:
            continue
        value, found = _settings_dig(document, each["key"])
        if found:
            try:
                _field_value(each, value)
            except ValueError as e:
                _die(6, "settings_invalid", str(e))
    return document


def _settings_edit(home: dict, scope: str, current: dict, yes: bool) -> dict:
    """The document after the person edited it in $VISUAL or $EDITOR, once
    they confirmed what changes; None where they changed nothing."""
    import shlex
    import subprocess
    import tempfile
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
    fd, name = tempfile.mkstemp(prefix=f"{NAME}-settings-{scope}-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(json.dumps(current, ensure_ascii=False, indent=2) + "\n")
        try:
            ran = subprocess.run([*shlex.split(editor), name])
        except OSError as e:
            _die(6, "editor_failed", f"cannot run the editor {editor!r}: {e}",
                 "set VISUAL or EDITOR to an editor that waits until the file is closed")
        if ran.returncode != 0:
            _die(6, "editor_failed", f"the editor {editor!r} exited {ran.returncode}; "
                 "nothing was written")
        try:
            edited = json.loads(Path(name).read_text())
        except ValueError as e:
            _die(6, "input", f"the edited document is not JSON: {e}; nothing was written")
    finally:
        try:
            os.unlink(name)
        except OSError:
            pass
    edited = _settings_checked_put(scope, edited)
    diff = _settings_diff(current, edited)
    if not diff:
        return None
    sys.stderr.write("\n".join(diff) + "\n")
    if not yes:
        if not sys.stdin.isatty():
            _die(6, "confirm_required",
                 f"the edit changes {len(diff)} path(s) and was not written",
                 f"run `{NAME} settings edit` on a terminal to confirm, or pass --yes")
        sys.stderr.write("write these changes? [y/N] ")
        sys.stderr.flush()
        if sys.stdin.readline().strip().lower() not in ("y", "yes"):
            _die(6, "not_confirmed", "nothing was written")
    return edited


def _cmd_settings(argv: list[str]) -> None:
    """`settings` reads every settings document the capability keeps, wherever
    it lives, with its declared keys resolved; `get`, `set`, `unset`, `put`,
    `export` and `edit` read and write them through one surface. A key is a
    dotted path, or a JSON array of keys where a key contains dots."""
    usage = (f"{NAME} settings [show] [--scope S] | get <key> [--scope S] | "
             "set <key> <value> [--scope S] | unset <key> [--scope S] | "
             "put [--scope S] < document.json | export [--scope S] | "
             "edit [--scope S] [--yes]")
    scope = None
    yes = False
    rest = []
    i = 0
    while i < len(argv):
        if argv[i] == "--scope":
            if i + 1 >= len(argv) or argv[i + 1] not in SETTING_SCOPES:
                _die(6, "input", f"--scope is one of {', '.join(SETTING_SCOPES)}", usage)
            scope = argv[i + 1]
            i += 2
        elif argv[i] == "--json":
            i += 1
        elif argv[i] == "--yes":
            yes = True
            i += 1
        else:
            rest.append(argv[i])
            i += 1
    sub = rest[0] if rest else "show"
    if sub == "show" and len(rest) <= 1:
        _emit(_settings_report(scope)); return
    if sub not in ("get", "set", "unset", "put", "export", "edit"):
        _die(6, "input", f"unknown settings subcommand {sub!r}", usage)
    if not globals().get("SETTINGS"):
        _die(6, "settings_undeclared", f"{NAME} declares no settings",
             f"`{NAME} manifest` carries `settings: null`")
    key = rest[1] if len(rest) > 1 and sub not in ("export", "edit") else None
    if sub in ("get", "set", "unset") and not key:
        _die(6, "input", f"settings {sub} needs a key", usage)
    decl_key = ".".join(_settings_parts(key)) if key else None
    decl = _settings_key_decl(decl_key, scope) if key else None
    if scope is None:
        if decl and decl.get("scope"):
            scope = decl["scope"]
        elif len(_settings_homes()) == 1:
            scope = _settings_homes()[0]["scope"]
        else:
            _die(6, "scope_required", f"{NAME} keeps settings at more than one scope",
                 f"pass --scope {'|'.join(h['scope'] for h in _settings_homes())}")
    homes = _settings_homes(scope)
    if not homes:
        _die(6, "unknown_scope", f"{NAME} keeps no settings at scope {scope!r}",
             f"scopes: {', '.join(h['scope'] for h in _settings_homes())}")
    home = homes[0]
    rows = _settings_in_rows(home)
    path, document, error = _settings_read(home)
    if error:
        _die(6, "settings_unreadable", error)
    if document is None and sub != "put":
        # A document not written yet starts as the document its home declares.
        document = json.loads(json.dumps(home.get("seed") or {}))
    if path is None:
        _die(6, "no_project", f"the {scope} settings live in a project and there is no "
             "project here", "run it inside the project")
    if sub == "get":
        value, found = _settings_dig(document or {}, key)
        if not found:
            if decl is None:
                _die(3, "not_found", f"{key} is not set at scope {scope}")
            value = decl.get("default")
        _emit(value if not isinstance(value, str) else json.dumps(value)); return
    if sub == "export":
        _emit(document or {}); return
    _read_only_gate(f"`{NAME} settings {sub}`")
    document = dict(document or {})
    previous = None
    base = None
    if sub == "edit" and rows:
        # The generation first, then the document: an edit is refused where
        # another write lands between this read and its own.
        try:
            base = {"generation": _records().setting_generations(NAME).get(scope)}
        except StoreError as e:
            _die(5 if e.slug in STORE_ENVIRONMENT_SLUGS else 6, e.slug, e.message, e.hint)
        path, document, error = _settings_read(home)
        if error:
            _die(6, "settings_unreadable", error)
        document = dict(document if document is not None
                        else json.loads(json.dumps(home.get("seed") or {})))
    if sub == "edit":
        edited = _settings_edit(home, scope, document, yes)
        if edited is None:
            _emit({"ok": True, "scope": scope, "path": str(path), "action": sub,
                   "changed": False}); return
        new_document = edited
    elif sub == "put":
        new_document = _settings_checked_put(scope, _stdin_document("the settings document"))
    elif sub == "set":
        if len(rest) < 3:
            _die(6, "input", "settings set needs a key and a value", usage)
        try:
            value = json.loads(rest[2])
        except ValueError:
            value = rest[2]
        if decl is not None:
            # A textual key takes the word as written, so "123" stays text.
            textual = (decl.get("type") or "string") in (
                "string", "enum", "url", "email", "phone", "path")
            try:
                value = _field_value(decl, rest[2] if textual else value,
                                     from_argv=True)
            except ValueError as e:
                _die(6, "settings_invalid", str(e))
    out = {"ok": True, "scope": scope, "path": str(path), "action": sub}
    if rows:
        def change(target: dict) -> dict:
            if sub in ("put", "edit"):
                return new_document
            if sub == "set":
                _settings_put(target, key, value)
                return target
            if not _settings_dig(target, key)[1]:
                raise StoreError("not_found", f"{key} is not set at scope {scope}")
            _settings_drop(target, key)
            return target
        written = _settings_rows_write(home, scope, change, base)
        out["path"] = written["source"]
        if key:
            out.update({"key": key, "previous": _settings_dig(written["before"], key)[0]})
            if sub == "set":
                out["value"] = _settings_dig(written["after"], key)[0]
        if sub == "edit":
            out["changed"] = True
        out["generation"] = written["generation"]
        if written.get("node"):
            out["node"] = written["node"]
    else:
        if sub in ("put", "edit"):
            document = new_document
        elif sub == "set":
            previous, _ = _settings_dig(document, key)
            _settings_put(document, key, value)
        else:
            previous, found = _settings_dig(document, key)
            if not found:
                _die(3, "not_found", f"{key} is not set at scope {scope}")
            _settings_drop(document, key)
        _settings_write(home, path, document)
        if key:
            out.update({"key": key, "previous": previous})
            if sub == "set":
                out["value"] = _settings_dig(document, key)[0]
        if sub == "edit":
            out["changed"] = True
    applies = (decl or {}).get("apply") or home.get("apply")
    if applies:
        out["apply"] = applies
        if applies == "reload":
            out["hint"] = f"`{NAME} service reload` adopts it in a running service"
        elif applies == "restart":
            out["hint"] = f"a running service adopts it only after `{NAME} service stop` and `start`"
    _emit(out)


def _contract(argv: list[str]) -> None:
    """Dispatch the contract verbs; domain verbs fall through to the CLI's own
    parser. Runs after _gate(), before any credential is resolved.

    `help` is a contract verb only when bare (no extra args) — the top-level
    dump plus the Identifiers section. `<NAME> help <subcommand>` falls
    through to the CLI so per-verb help stays clean."""
    cmd = argv[0] if argv else ""
    if cmd == "stub":
        _emit(f"{SUMMARY} Run `{NAME} help`.")
    elif cmd == "manifest":
        _emit(_manifest_core())
    elif cmd == "migrate" and argv[1:2] == ["files"]:
        _cmd_migrate_files(argv[2:])
    elif cmd == "migrate" and _tables_declared():
        _cmd_migrate(argv[1:])
    elif cmd == "guide":
        _cmd_guide(argv[1:])
    elif cmd == "ids":
        _cmd_ids(argv[1:])
    elif cmd == "refs":
        _cmd_refs(argv[1:])
    elif cmd == "context":
        _cmd_context(argv[1:])
    elif cmd == "connections" and argv[1:2] == ["show"]:
        if not _reveals():
            _die(4, "reveal_not_gated",
                 f"`{NAME} connections show` reached dispatch without the gate a reveal passes",
                 f"run `{NAME} connections show <id> --reveal <KEY>` as written")
        if "_cmd_connections_show" not in globals():
            _die(6, "unknown_connection", f"{NAME} has no connections",
                 f"`{NAME} connections` reports an empty map")
        _cmd_connections_show(argv[2:])
    elif cmd == "connections":
        _cmd_connections_reported()
    elif cmd == "inventory":
        _cmd_inventory(argv[1:])
    elif cmd == "settings" and globals().get("SETTINGS") is not None:
        _cmd_settings(argv[1:])
    elif cmd == "connection" and "_cmd_connection" in globals() \
            and globals().get("CONN_FIELDS") is not None:
        _cmd_connection(argv[1:])
    elif cmd == "setup" and "_cmd_setup" in globals() and globals().get("SETUP_FIELDS"):
        _cmd_setup(argv[1:])
    elif cmd == "help" and len(argv) == 1:
        _cmd_help()
    else:
        return
    sys.exit(0)

