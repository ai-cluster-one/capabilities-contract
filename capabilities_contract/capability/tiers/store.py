# The shared capability code - the store tier: the records adapter for identifiers, policy, settings,
# connections and documents, and a store-mode project's records in its store.
#
# This is not a module. `capabilities_contract.capability.bind` executes it in
# the namespace of the capability that binds it, so it reads that capability's
# declarations and calls its hooks as its own code does. See the package
# docstring of `capabilities_contract.capability`.
#
# A region carries what it needs. Relying on the host file to have imported
# the right names is a coupling nothing checks and nothing reports: it works in
# whichever capability happened to import them and fails at import time in the
# rest. Re-importing a name the host already has costs nothing.
import json
import os
import hashlib
import re
import socket
# The capability core region reads the clock through `time` and imports nothing
# of its own, so this region keeps carrying it.
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any


# Two scopes and no more: a record either belongs to one project (the
# project's envelope) or to every project (the user's config home).
SCOPE_KINDS = ("global", "project")

FIRST = "first"
MERGE = "merge"
EXACT = "exact"

# The collection registry: how each resolves, and who is allowed to write it.
# Adding a collection here is the only place a new record class is declared.
#
# `connection` and `grant` are the same fact split along the seam that matters:
# an entry's identity — where the thing is and how to reach it — is a fact about
# the world, the same in every project forever. What a project may DO with that
# identity is a decision, different per project by definition. Glued together,
# the second cannot be overridden without restating the first; apart, a project
# that needs write access writes one grant and repeats no address, no host,
# no secret.
#
# An identity is atomic: it merges by entry, never by field, so no connection is
# ever assembled from two scopes. That is what rule 18's "never merged" was
# protecting, and it survives; what it gives up is refusing to let a project add
# to the global set at all.
COLLECTIONS: dict[str, dict[str, str]] = {
    "connection": {"resolve": MERGE, "writer": "human"},
    "grant": {"resolve": MERGE, "writer": "human"},
    "identifier": {"resolve": MERGE, "writer": "capability"},
    "setting": {"resolve": MERGE, "writer": "human"},
    "policy": {"resolve": MERGE, "writer": "manager"},
    "document": {"resolve": MERGE, "writer": "human"},
}

# Grant fields and what they mean when nothing declares them. `allow_write`
# falls back to the capability's own WRITE_DEFAULT rather than to a value here,
# because "does a write leave the system" is the capability's fact.
GRANT_FIELDS = ("enabled", "allow_write")

# A document version is named by the first twelve hex characters of its sha256.
# Forty-eight bits is far more than a project's worth of prose needs, and a name
# a person can read at a glance is worth more than headroom nobody will reach.
HASH_LENGTH = 12

# A key is a label a human chose, and for a mailbox that label is naturally an
# email address — so `@` and `+` belong here. What stays out is whitespace,
# separators and anything that would make a key ambiguous to address.
KEY_RE = re.compile(r"[a-z0-9][a-z0-9._@+-]{0,127}", re.IGNORECASE)
CAPABILITY_RE = re.compile(r"[a-z][a-z0-9-]{0,63}")


class StoreError(Exception):
    """Every failure this tier reports. Carries a slug the caller maps to an
    exit code, so the CLI's error envelope stays the capability's own."""

    def __init__(self, slug: str, message: str, hint: str | None = None):
        super().__init__(message)
        self.slug = slug
        self.message = message
        self.hint = hint


# The process-wide read-only switch. A caller hands a whole process tree to
# something that may read through the capabilities but change nothing through
# them by setting this one variable, which every descendant inherits. It is
# decided here and nowhere else, because this tier is the one every capability
# carries and the one the manager and the bundled services import. It only ever
# closes: nothing it says makes a connection writable, and unset, `0` or
# `false` leave every record and every gate exactly as declared.
READ_ONLY_ENV = "CAPABILITIES_READ_ONLY"
READ_ONLY_EFFECT = ("every connection resolves read-only whatever its grant or "
                    "WRITE_DEFAULT; write verbs, project-record writes and "
                    "service activation exit 4")


def read_only_switch() -> bool:
    """True when this process runs under the read-only switch: the variable
    holds `1` or `true`, in any case."""
    return os.environ.get(READ_ONLY_ENV, "").strip().lower() in ("1", "true")


# A node is the machine a process runs on, keyed in the store by its id and
# shown by its label. The id is twelve lowercase hex characters, as an agent's
# is, and the machine resolves it itself with nothing configured: a Mac from its
# hardware UUID through a hash, so the same Mac always answers the same id and
# the UUID never leaves it; any other machine - a server, a container - from
# the id kept in its config home, minted there once, where a container keeps it
# on its persistent volume. AGENT_NODE_ID, where set, overrides both (a
# container that is handed its id, a test); it also takes the name a node
# registered before ids is still keyed by, which a box compiled for such a node
# is handed. The label is the node's row's in
# the store; AGENT_NODE_NAME, else the host name, is only the label a machine
# gives itself when it is first registered.
NODE_ID_ENV = "AGENT_NODE_ID"
NODE_NAME_ENV = "AGENT_NODE_NAME"
NODE_ID_RE = re.compile(r"[0-9a-f]{12}")
# The id a node registered before ids keeps until it is moved to its own: the
# name it was registered by, as a deployment target declared it.
NODE_LEGACY_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}")
NODE_ID_FILE = "node-id"
_NODE_HASH_PREFIX = "capabilities-node:"
# A Mac's id, derived once per process: asking the hardware is a subprocess.
_mac_node_id: str | None = None


def _node_id_path() -> Path:
    """Where a machine that is not a Mac keeps its node id: beside the
    manager's machine record in the config home."""
    home = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(os.path.abspath(home)) / "capabilities" / NODE_ID_FILE


def _mac_hardware_uuid() -> str | None:
    import subprocess
    try:
        out = subprocess.run(["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    found = re.search(r'"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"', out or "")
    return found.group(1).upper() if found else None


def _read_node_id_file(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as exc:
        raise StoreError("node_unidentified", f"cannot read this machine's node id at "
                         f"{path}: {exc.__class__.__name__}") from None
    if not NODE_ID_RE.fullmatch(value):
        raise StoreError("node_unidentified", f"{path} holds no node id: it holds twelve "
                         "lowercase hex characters",
                         "set it with `capabilities node id --set <id>`")
    return value


def write_node_id(node_id: str, path: Path | None = None, replace: bool = True) -> str:
    """Keep `node_id` as this machine's id in its config home, the file a
    machine that is not a Mac resolves its id from. Without `replace` an id
    already there wins, so two processes minting at once agree. Answers the id
    the file holds."""
    if not NODE_ID_RE.fullmatch(node_id or ""):
        raise StoreError("bad_node_id", f"node id {node_id!r} is not twelve lowercase hex "
                         "characters")
    path = path or _node_id_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        import tempfile
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".node-id.")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(node_id + "\n")
            os.chmod(tmp, 0o644)
            if replace:
                os.replace(tmp, path)
            else:
                try:
                    os.link(tmp, path)
                except FileExistsError:
                    pass
        finally:
            if os.path.lexists(tmp):
                os.unlink(tmp)
    except OSError as exc:
        raise StoreError("node_unidentified", f"cannot keep this machine's node id at "
                         f"{path}: {exc.__class__.__name__}",
                         f"make {path.parent} writable, or set {NODE_ID_ENV}") from None
    return _read_node_id_file(path) or node_id


def node_identity() -> dict[str, str]:
    """This machine's node: {id, source}, source being `env`, `hardware`,
    `file` or `minted`."""
    global _mac_node_id
    given = os.environ.get(NODE_ID_ENV, "").strip()
    if given:
        if not (NODE_ID_RE.fullmatch(given) or NODE_LEGACY_ID_RE.fullmatch(given)):
            raise StoreError("bad_node_id", f"{NODE_ID_ENV}={given!r} is not a node id: "
                             "twelve lowercase hex characters, or the name a node "
                             "registered before ids is keyed by")
        return {"id": given, "source": "env"}
    import sys
    if sys.platform == "darwin":
        if _mac_node_id is None:
            uuid = _mac_hardware_uuid()
            if not uuid:
                raise StoreError("node_unidentified", "this Mac did not answer its hardware "
                                 "UUID (ioreg IOPlatformUUID), which its node id is derived "
                                 "from", f"set {NODE_ID_ENV} to run as a node anyway")
            _mac_node_id = hashlib.sha256((_NODE_HASH_PREFIX + uuid).encode()).hexdigest()[:12]
        return {"id": _mac_node_id, "source": "hardware"}
    path = _node_id_path()
    held = _read_node_id_file(path)
    if held is not None:
        return {"id": held, "source": "file"}
    import secrets
    return {"id": write_node_id(secrets.token_hex(6), path, replace=False), "source": "minted"}


def node_id() -> str:
    """The id of the node this process runs on: the key every store row that
    names a node holds - a grant, a policy row or a setting for one node, a
    service's lease, the node a run or a session belongs to."""
    return node_identity()["id"]


def node_name() -> str:
    """The node this process runs on, as the store names it: its id
    (`node_id`). Kept under this name, which every capability already calls."""
    return node_id()


def node_label() -> str:
    """The label this machine gives itself when it is first registered as a
    node: AGENT_NODE_NAME where set, else its host name. Once registered, the
    node's row in the store holds its label, changed there at will."""
    return os.environ.get(NODE_NAME_ENV, "").strip() or socket.gethostname()


def this_node() -> dict[str, str]:
    """This machine as a node: {id, label, source}."""
    return {**node_identity(), "label": node_label()}


def _node_check(node: Any) -> str | None:
    """A node a policy row is written for: a name, stripped, or None for every
    node."""
    if node is None:
        return None
    if not isinstance(node, str) or not node.strip():
        raise StoreError("bad_node", f"node {node!r} must name a node, or be null "
                         "for every node")
    return node.strip()


# Where a project keeps its records: files (the default) or the store, which
# then holds its connections, grants, identifiers and policy together. The
# manager alone writes this key into `project.json`, when it imports a
# project's files into the store; nothing infers it from a configured store.
RECORDS_MODE_KEY = "records"
RECORDS_MODES = ("files", "store")

# The key a project that moved only its connections and grants to the store
# carries. It keeps meaning exactly that: such a project reads its identifiers
# and its gate from files until it is imported again.
CONNECTIONS_MODE_KEY = "connections"
CONNECTIONS_MODES = ("files", "store")

# The contract's own tables in the store, migrated under the contract's own
# ledger owner, and the schema version this code writes them at.
STORE_OWNER = "capabilities"
STORE_CONNECTIONS_TABLE = "capabilities_connections"
STORE_GRANTS_TABLE = "capabilities_connection_grants"
STORE_IDENTIFIERS_TABLE = "capabilities_identifiers"
STORE_POLICY_TABLE = "capabilities_policy"
# The kernel's own tables, migrated in the same ledger: the agent registry, the
# nodes, which agent lives on which node, and the one row of facts about the
# store as a whole. The manager alone writes them.
STORE_AGENTS_TABLE = "capabilities_agents"
STORE_NODES_TABLE = "capabilities_nodes"
STORE_AGENT_NODES_TABLE = "capabilities_agent_nodes"
STORE_GLOBAL_TABLE = "capabilities_global"
# Settings of an agent whose records moved into the store: one row per leaf,
# the documents that exist, and the append-only trail of every change.
STORE_SETTINGS_TABLE = "capabilities_settings"
STORE_SETTINGS_DOCUMENTS_TABLE = "capabilities_settings_documents"
STORE_SETTINGS_CHANGES_TABLE = "capabilities_settings_changes"
# Every capability's references for each project, versioned: one row per
# version, the active one read before the project's files.
STORE_REFERENCES_TABLE = "capabilities_references"
# What each node actually runs: a row per service it supervises, keyed by
# project, capability and node, in one of a closed set of states.
STORE_SERVICE_INSTANCES_TABLE = "capabilities_service_instances"
# Each agent's secrets, sealed with the agent's own key (capabilities_contract.vault).
STORE_VAULT_TABLE = "capabilities_vault"
SERVICE_INSTANCE_STATES = ("starting", "ready", "unusable", "degraded", "failing",
                           "held", "waiting", "stopping")
SERVICE_INSTANCE_TEXT_CHARS = 2000
# What each node says of itself on a short beat: one row per node, shared by
# every agent on it, and per agent the sign-ins its tools hold there and the
# device-bound sessions it holds there.
STORE_NODE_STATES_TABLE = "capabilities_node_states"
STORE_NODE_LOGINS_TABLE = "capabilities_node_logins"
STORE_NODE_SESSIONS_TABLE = "capabilities_node_sessions"
# The owner's word, per agent and node, on whether a sign-in or a device
# session is expected there, over what the node's placed services need.
STORE_NODE_LOGIN_EXPECTATIONS_TABLE = "capabilities_node_login_expectations"
STORE_NODE_SESSION_EXPECTATIONS_TABLE = "capabilities_node_session_expectations"
# The tools whose sign-in a node reports for each agent, each a pair of
# columns, and the closed set of what a tool's own answer can say of it.
NODE_STATE_TOOLS = ("claude", "codex", "gh")
NODE_LOGIN_STATES = ("signed_in", "signed_out", "absent", "unknown")
# How long a node's row stands for it: a node that has not written its row
# again within this many seconds reads as unreachable.
NODE_STATE_FRESH_SECONDS = 90
NODE_STATE_TEXT_CHARS = 500
STORE_TABLES_VERSION = (1, 16)

# Which collections each store mode keeps in the store. The default pointer is
# a setting kept with the grants in both.
STORE_COLLECTIONS = {
    CONNECTIONS_MODE_KEY: frozenset({"connection", "grant"}),
    RECORDS_MODE_KEY: frozenset({"connection", "grant", "identifier", "policy"}),
}
STORE_TABLES = {
    "connection": STORE_CONNECTIONS_TABLE,
    "grant": STORE_GRANTS_TABLE,
    "identifier": STORE_IDENTIFIERS_TABLE,
    "policy": STORE_POLICY_TABLE,
    "setting": STORE_SETTINGS_TABLE,
}

# What the global layer takes from the store's rows for every agent once they
# are in force: connections, their grants, the default pointer (a setting
# kept on a grant) and policy. Identifiers and settings documents stay files.
GLOBAL_STORE_COLLECTIONS = frozenset({"connection", "grant", "setting", "policy"})

# A store that cannot be reached or is busy is the environment's fault, not
# the configuration's: a capability maps these to its network exit code.
STORE_ENVIRONMENT_SLUGS = frozenset({"store_unreachable", "store_busy"})

# How long one process reuses what it read from the store, and a refusal to
# connect: long enough that one command asks once, short enough that a
# long-running service sees a changed grant, or a store that came back, at once.
STORE_READ_SECONDS = 2.0

# Whether an adapter keeps its connection between operations. Only a migration
# plan sets it: the plan's one link holds a transaction open for the whole run,
# and closing it after an operation would undo what the plan did so far.
_HOLD_RECORDS_CONNECTION = False


# A reference's name is its file's name without `.md`.
_REFERENCE_NAME = r"^[A-Za-z0-9][A-Za-z0-9._-]*$"


def record_table_steps() -> list[tuple[str, str]]:
    """The migration steps of the contract's tables. `enabled` and
    `allow_write` left null decide nothing, as a field absent from a file's
    grant does; `node` null is the grant, or the policy row, for every node;
    `agent_id` null is an identifier or a policy row for every project."""
    return [
        ("0001-connections",
         "CREATE TABLE capabilities_connections ("
         " capability text NOT NULL,"
         " name text NOT NULL,"
         " spec jsonb NOT NULL,"
         " PRIMARY KEY (capability, name),"
         " CHECK (jsonb_typeof(spec) = 'object'))"),
        ("0002-connection-grants",
         "CREATE TABLE capabilities_connection_grants ("
         " agent_id text NOT NULL,"
         " capability text NOT NULL,"
         " connection text NOT NULL,"
         " node text CHECK (node <> ''),"
         " enabled boolean,"
         " allow_write boolean,"
         " is_default boolean NOT NULL DEFAULT false,"
         " FOREIGN KEY (capability, connection)"
         "  REFERENCES capabilities_connections (capability, name)"
         "  ON DELETE CASCADE ON UPDATE CASCADE)"),
        ("0003-connection-grants-key",
         "CREATE UNIQUE INDEX capabilities_connection_grants_key"
         " ON capabilities_connection_grants"
         " (agent_id, capability, connection, (coalesce(node, '')))"),
        ("0004-connection-grants-default",
         "CREATE UNIQUE INDEX capabilities_connection_grants_default"
         " ON capabilities_connection_grants"
         " (agent_id, capability, (coalesce(node, ''))) WHERE is_default"),
        ("0005-identifiers",
         "CREATE TABLE capabilities_identifiers ("
         " agent_id text CHECK (agent_id <> ''),"
         " capability text NOT NULL,"
         " label text NOT NULL,"
         " value jsonb NOT NULL,"
         " note text NOT NULL DEFAULT '',"
         " updated_at timestamptz NOT NULL DEFAULT now())"),
        ("0006-identifiers-key",
         "CREATE UNIQUE INDEX capabilities_identifiers_key"
         " ON capabilities_identifiers"
         " ((coalesce(agent_id, '')), capability, label)"),
        ("0007-policy",
         "CREATE TABLE capabilities_policy ("
         " agent_id text CHECK (agent_id <> ''),"
         " capability text NOT NULL,"
         " node text CHECK (node <> ''),"
         " enabled boolean NOT NULL,"
         " updated_at timestamptz NOT NULL DEFAULT now())"),
        ("0008-policy-key",
         "CREATE UNIQUE INDEX capabilities_policy_key"
         " ON capabilities_policy"
         " ((coalesce(agent_id, '')), capability, (coalesce(node, '')))"),
        # The agent registry. `id` is the project id `project.json` declares;
        # the registry never mints or changes one. An icon and its SHA-256 are
        # present together or absent together.
        ("0009-agents",
         "CREATE TABLE capabilities_agents ("
         " id text PRIMARY KEY CHECK (id <> ''),"
         " name text CHECK (name <> ''),"
         " description text CHECK (description <> ''),"
         " icon bytea,"
         " icon_sha text CHECK (icon_sha ~ '^[0-9a-f]{64}$'),"
         " onboarding_status text CHECK (onboarding_status IN ('pending', 'complete')),"
         " onboarding_routine text CHECK (onboarding_routine <> ''),"
         " migrating_since timestamptz,"
         " migrated_at timestamptz,"
         " created_at timestamptz NOT NULL DEFAULT now(),"
         " updated_at timestamptz NOT NULL DEFAULT now(),"
         " CHECK ((icon IS NULL) = (icon_sha IS NULL)));"
         " COMMENT ON TABLE capabilities_agents IS"
         " 'The agent registry: one row per agent, keyed by the project id its"
         " capabilities/project.json declares. Written by the capabilities manager alone.';"
         " COMMENT ON COLUMN capabilities_agents.id IS"
         " 'The project id from capabilities/project.json (prj_<12 hex>, or an older UUID).';"
         " COMMENT ON COLUMN capabilities_agents.name IS"
         " 'Display name; null while the agent has none of its own.';"
         " COMMENT ON COLUMN capabilities_agents.icon IS"
         " 'The agent''s icon as PNG bytes; null with icon_sha when it has none.';"
         " COMMENT ON COLUMN capabilities_agents.icon_sha IS"
         " 'Lowercase hex SHA-256 of icon.';"
         " COMMENT ON COLUMN capabilities_agents.onboarding_status IS"
         " 'pending while the agent still runs its onboarding routine, complete once"
         " it finished; null when no onboarding is tracked.';"
         " COMMENT ON COLUMN capabilities_agents.onboarding_routine IS"
         " 'The routine the agent runs while onboarding is pending.';"
         " COMMENT ON COLUMN capabilities_agents.migrating_since IS"
         " 'Set while a move of this agent''s records from files into the store is open.';"
         " COMMENT ON COLUMN capabilities_agents.migrated_at IS"
         " 'When this agent''s records and settings moved into the store; null while"
         " they are still read from files.'"),
        # ContextKit's registry rows, taken over once where that table exists in
        # the same schema. An empty name or description meant none there.
        ("0010-agents-from-contextkit",
         "DO $copy$ BEGIN"
         " IF to_regclass('contextkit_agents') IS NOT NULL THEN"
         "  INSERT INTO capabilities_agents"
         "   (id, name, description, icon, icon_sha, created_at, updated_at)"
         "  SELECT id, nullif(name, ''), nullif(description, ''),"
         "   CASE WHEN icon IS NOT NULL AND icon_sha ~ '^[0-9a-f]{64}$' THEN icon END,"
         "   CASE WHEN icon IS NOT NULL AND icon_sha ~ '^[0-9a-f]{64}$' THEN icon_sha END,"
         "   created_at, updated_at"
         "  FROM contextkit_agents WHERE id <> ''"
         "  ON CONFLICT (id) DO NOTHING;"
         " END IF;"
         " END $copy$"),
        # The machines an agent runs on. Exactly one may be its master, which
        # the partial index below enforces; a node is removed with its agent.
        ("0011-agent-nodes",
         "CREATE TABLE capabilities_agent_nodes ("
         " agent_id text NOT NULL REFERENCES capabilities_agents (id)"
         "  ON DELETE CASCADE ON UPDATE CASCADE,"
         " node text NOT NULL CHECK (node <> ''),"
         " kind text NOT NULL CHECK (kind IN ('mac', 'server')),"
         " address text CHECK (address <> ''),"
         " is_master boolean NOT NULL DEFAULT false,"
         " may_write boolean NOT NULL DEFAULT false,"
         " target text CHECK (target <> ''),"
         " last_seen_at timestamptz,"
         " PRIMARY KEY (agent_id, node));"
         " COMMENT ON TABLE capabilities_agent_nodes IS"
         " 'The nodes an agent runs on, one row per (agent, node). Written by the"
         " capabilities manager alone. agent_id references capabilities_agents"
         " because a node exists only as a node of a registered agent.';"
         " COMMENT ON COLUMN capabilities_agent_nodes.node IS"
         " 'The name the node gives itself in AGENT_NODE_NAME.';"
         " COMMENT ON COLUMN capabilities_agent_nodes.address IS"
         " 'Host name or IP address the node is reached at, where it is fixed.';"
         " COMMENT ON COLUMN capabilities_agent_nodes.is_master IS"
         " 'The node that writes the rows every node of the agent inherits; at"
         " most one per agent.';"
         " COMMENT ON COLUMN capabilities_agent_nodes.may_write IS"
         " 'Whether a node that is not the master may write rows of its own, marked"
         " with its node.';"
         " COMMENT ON COLUMN capabilities_agent_nodes.target IS"
         " 'The deployment target this node is deployed by; null for a node that"
         " is not deployed, such as a Mac.';"
         " COMMENT ON COLUMN capabilities_agent_nodes.last_seen_at IS"
         " 'When the node last reported itself.'"),
        ("0012-agent-nodes-master",
         "CREATE UNIQUE INDEX capabilities_agent_nodes_master"
         " ON capabilities_agent_nodes (agent_id) WHERE is_master"),
        # Facts about the store as a whole, in its one row.
        ("0013-global",
         "CREATE TABLE capabilities_global ("
         " singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),"
         " global_migrated_at timestamptz);"
         " INSERT INTO capabilities_global DEFAULT VALUES;"
         " COMMENT ON TABLE capabilities_global IS"
         " 'One row of facts about this store as a whole.';"
         " COMMENT ON COLUMN capabilities_global.singleton IS"
         " 'Always true; keeps the table at one row.';"
         " COMMENT ON COLUMN capabilities_global.global_migrated_at IS"
         " 'When the global records were written into the store; null until then.'"),
        # A grant for every agent: `agent_id` null, beneath each agent's own
        # grant, and a default pointer for every agent the same way. The keys
        # of 0003 and 0004 stay as they are, so code that names them in its
        # ON CONFLICT keeps writing an agent's grants; the keys below coalesce
        # the agent as well, so two global rows can never stand for one grant.
        ("0014-connection-grants-global",
         "ALTER TABLE capabilities_connection_grants ALTER COLUMN agent_id DROP NOT NULL;"
         " ALTER TABLE capabilities_connection_grants"
         "  ADD CONSTRAINT capabilities_connection_grants_agent_id_check"
         "  CHECK (agent_id <> '');"
         " CREATE UNIQUE INDEX capabilities_connection_grants_scope_key"
         "  ON capabilities_connection_grants"
         "  ((coalesce(agent_id, '')), capability, connection, (coalesce(node, '')));"
         " CREATE UNIQUE INDEX capabilities_connection_grants_scope_default"
         "  ON capabilities_connection_grants"
         "  ((coalesce(agent_id, '')), capability, (coalesce(node, ''))) WHERE is_default;"
         " COMMENT ON TABLE capabilities_connection_grants IS"
         " 'What an agent may do with a connection: one row per (agent, capability,"
         " connection, node). A row whose agent_id is null is the grant for every"
         " agent, beneath each agent''s own; it never enables a connection by itself.';"
         " COMMENT ON COLUMN capabilities_connection_grants.agent_id IS"
         " 'The agent the grant is for; null for the grant every agent inherits.';"
         " COMMENT ON COLUMN capabilities_connection_grants.node IS"
         " 'The node the grant is for; null for every node. A node row is read before"
         " the row for every node.';"
         " COMMENT ON COLUMN capabilities_connection_grants.is_default IS"
         " 'Whether this connection is the default pointer at this grant''s scope and"
         " node; at most one per scope and node.'"),
        # An identifier for one node, read before the row for every node.
        ("0015-identifiers-node",
         "ALTER TABLE capabilities_identifiers ADD COLUMN node text CHECK (node <> '');"
         " DROP INDEX capabilities_identifiers_key;"
         " CREATE UNIQUE INDEX capabilities_identifiers_key ON capabilities_identifiers"
         "  ((coalesce(agent_id, '')), capability, label, (coalesce(node, '')));"
         " COMMENT ON TABLE capabilities_identifiers IS"
         " 'Durable non-secret lookups a capability discovered, one row per (agent,"
         " capability, label, node); agent_id null for every agent.';"
         " COMMENT ON COLUMN capabilities_identifiers.node IS"
         " 'The node the identifier is for; null for every node. A node row is read"
         " before the row for every node.'"),
        # Settings: one row per leaf of a capability's settings document, for
        # one agent (or every agent, agent_id null) and one node (or every
        # node). A writer takes, for the whole transaction, the advisory lock
        #   pg_advisory_xact_lock(hashtext(concat_ws(chr(31), schema,
        #     coalesce(agent_id, ''), capability, coalesce(node, ''))))
        # of the document it writes, so two writers of one document queue.
        # agent_id keeps the name the contract's other tables give it.
        ("0016-settings",
         "CREATE TABLE capabilities_settings ("
         " agent_id text CHECK (agent_id <> ''),"
         " capability text NOT NULL CHECK (capability <> ''),"
         " node text CHECK (node <> ''),"
         " path text[] NOT NULL"
         "  CHECK (cardinality(path) > 0 AND array_position(path, NULL) IS NULL),"
         " value jsonb NOT NULL,"
         " updated_at timestamptz NOT NULL DEFAULT now(),"
         " updated_by text NOT NULL CHECK (updated_by <> ''));"
         " CREATE UNIQUE INDEX capabilities_settings_key ON capabilities_settings"
         "  ((coalesce(agent_id, '')), capability, (coalesce(node, '')), path);"
         " CREATE FUNCTION capabilities_settings_guard() RETURNS trigger"
         "  LANGUAGE plpgsql SET search_path FROM CURRENT AS $guard$"
         " BEGIN"
         "  IF jsonb_typeof(NEW.value) = 'object' AND NEW.value <> '{}'::jsonb THEN"
         "   RAISE EXCEPTION 'setting % holds an object with keys; a row holds a scalar,"
         " an array or {}', array_to_string(NEW.path, '.')"
         "    USING ERRCODE = 'check_violation';"
         "  END IF;"
         "  IF EXISTS (SELECT 1 FROM capabilities_settings s"
         "   WHERE coalesce(s.agent_id, '') = coalesce(NEW.agent_id, '')"
         "   AND s.capability = NEW.capability"
         "   AND coalesce(s.node, '') = coalesce(NEW.node, '')"
         "   AND s.path <> NEW.path"
         "   AND (s.path[1:cardinality(NEW.path)] = NEW.path"
         "    OR NEW.path[1:cardinality(s.path)] = s.path)) THEN"
         "   RAISE EXCEPTION 'setting % overlaps another row of its document: a path"
         " never prefixes another', array_to_string(NEW.path, '.')"
         "    USING ERRCODE = 'check_violation';"
         "  END IF;"
         "  RETURN NEW;"
         " END $guard$;"
         " CREATE TRIGGER capabilities_settings_guard"
         "  BEFORE INSERT OR UPDATE ON capabilities_settings"
         "  FOR EACH ROW EXECUTE FUNCTION capabilities_settings_guard();"
         " COMMENT ON TABLE capabilities_settings IS"
         " 'Capability settings, one row per leaf path of a document. A document is"
         " (agent_id, capability, node); agent_id null is every agent''s, node null"
         " every node''s. Writers lock the document with pg_advisory_xact_lock(hashtext("
         "concat_ws(chr(31), schema, coalesce(agent_id, ''''), capability,"
         " coalesce(node, ''''))));"
         " a trigger refuses an object with keys as a value and a path that prefixes"
         " or is prefixed by another row of the same document.';"
         " COMMENT ON COLUMN capabilities_settings.agent_id IS"
         " 'The agent the setting is for; null for the setting every agent inherits.';"
         " COMMENT ON COLUMN capabilities_settings.node IS"
         " 'The node the setting is for; null for every node. A node row is read over"
         " the row for every node.';"
         " COMMENT ON COLUMN capabilities_settings.path IS"
         " 'The keys from the document root to this leaf; a key may contain dots.';"
         " COMMENT ON COLUMN capabilities_settings.value IS"
         " 'The leaf: a JSON scalar (null included), a whole array, or {} for an"
         " object left empty.';"
         " COMMENT ON COLUMN capabilities_settings.updated_by IS"
         " 'Who wrote the row: user@node, migrate@node or <capability>-service@node.'"),
        ("0017-settings-documents",
         "CREATE TABLE capabilities_settings_documents ("
         " agent_id text CHECK (agent_id <> ''),"
         " capability text NOT NULL CHECK (capability <> ''),"
         " node text CHECK (node <> ''),"
         " generation bigint NOT NULL,"
         " created_at timestamptz NOT NULL DEFAULT now());"
         " CREATE UNIQUE INDEX capabilities_settings_documents_key"
         "  ON capabilities_settings_documents"
         "  ((coalesce(agent_id, '')), capability, (coalesce(node, '')));"
         " COMMENT ON TABLE capabilities_settings_documents IS"
         " 'The settings documents that exist: a document without a row here reads as"
         " the capability''s seed; one with a row reads from its rows, even none.';"
         " COMMENT ON COLUMN capabilities_settings_documents.generation IS"
         " 'The id of the last capabilities_settings_changes row applied to the"
         " document; 0 before any.'"),
        ("0018-settings-changes",
         "CREATE TABLE capabilities_settings_changes ("
         " id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
         " agent_id text CHECK (agent_id <> ''),"
         " capability text NOT NULL CHECK (capability <> ''),"
         " node text CHECK (node <> ''),"
         " action text NOT NULL CHECK (action IN ('set', 'unset')),"
         " path text[] NOT NULL CHECK (cardinality(path) > 0),"
         " old_value jsonb,"
         " new_value jsonb,"
         " changed_at timestamptz NOT NULL DEFAULT now(),"
         " changed_by text NOT NULL CHECK (changed_by <> ''));"
         " CREATE FUNCTION capabilities_settings_changes_append_only() RETURNS trigger"
         "  LANGUAGE plpgsql AS $trail$"
         " BEGIN"
         "  RAISE EXCEPTION 'capabilities_settings_changes is append-only'"
         "   USING ERRCODE = 'restrict_violation';"
         " END $trail$;"
         " CREATE TRIGGER capabilities_settings_changes_append_only"
         "  BEFORE UPDATE OR DELETE ON capabilities_settings_changes"
         "  FOR EACH ROW EXECUTE FUNCTION capabilities_settings_changes_append_only();"
         " CREATE TRIGGER capabilities_settings_changes_no_truncate"
         "  BEFORE TRUNCATE ON capabilities_settings_changes"
         "  FOR EACH STATEMENT EXECUTE FUNCTION capabilities_settings_changes_append_only();"
         " COMMENT ON TABLE capabilities_settings_changes IS"
         " 'The append-only trail of settings: one row per path a write set or unset."
         " A document''s generation is the id of its last row here.';"
         " COMMENT ON COLUMN capabilities_settings_changes.action IS"
         " 'set: the path took new_value (old_value null where it was absent);"
         " unset: the path was removed (new_value null).';"
         " COMMENT ON COLUMN capabilities_settings_changes.changed_by IS"
         " 'Who wrote it: user@node, migrate@node or <capability>-service@node.'"),
        ("0019-references",
         "CREATE TABLE capabilities_references ("
         " id uuid PRIMARY KEY DEFAULT gen_random_uuid(),"
         " project_id text NOT NULL CHECK (project_id <> ''),"
         " capability text NOT NULL CHECK (capability ~ '^[a-z][a-z0-9-]*$'),"
         f" name text NOT NULL CHECK (name ~ '{_REFERENCE_NAME}' AND name !~* '[.]md$'),"
         " body text NOT NULL,"
         " active boolean NOT NULL DEFAULT true,"
         " created_at timestamptz NOT NULL DEFAULT now(),"
         " created_by text NOT NULL CHECK (created_by <> ''),"
         " note text);"
         " CREATE UNIQUE INDEX capabilities_references_active ON capabilities_references"
         "  (project_id, capability, (lower(replace(name, '_', '-')))) WHERE active;"
         " CREATE INDEX capabilities_references_history ON capabilities_references"
         "  (project_id, capability, (lower(replace(name, '_', '-'))), created_at DESC);"
         " CREATE FUNCTION capabilities_references_guard() RETURNS trigger"
         "  LANGUAGE plpgsql AS $guard$"
         " BEGIN"
         "  IF tg_op IN ('DELETE', 'TRUNCATE') THEN"
         "   RAISE EXCEPTION 'reference versions are never deleted: retire the reference'"
         "    USING ERRCODE = 'check_violation';"
         "  END IF;"
         "  IF (to_jsonb(NEW) - 'active') IS DISTINCT FROM (to_jsonb(OLD) - 'active') THEN"
         "   RAISE EXCEPTION 'a reference version is immutable: save a new version'"
         "    USING ERRCODE = 'check_violation';"
         "  END IF;"
         "  IF NEW.active AND NOT OLD.active THEN"
         "   RAISE EXCEPTION 'a reference version is not made active again: save its"
         " body as a new version' USING ERRCODE = 'check_violation';"
         "  END IF;"
         "  RETURN NEW;"
         " END $guard$;"
         " CREATE TRIGGER capabilities_references_guard"
         "  BEFORE UPDATE OR DELETE ON capabilities_references"
         "  FOR EACH ROW EXECUTE FUNCTION capabilities_references_guard();"
         " CREATE TRIGGER capabilities_references_truncate"
         "  BEFORE TRUNCATE ON capabilities_references"
         "  FOR EACH STATEMENT EXECUTE FUNCTION capabilities_references_guard();"
         " COMMENT ON TABLE capabilities_references IS"
         " 'Every version of each capability''s references for a project: the file"
         " capabilities/<capability>/reference/<name>.md as a row. A reference with an"
         " active version is read from here before the project''s files; one with none"
         " is retired. Immutable but for active, which a save clears as it adds the next.';"
         " COMMENT ON COLUMN capabilities_references.project_id IS"
         " 'The project''s declared id.';"
         " COMMENT ON COLUMN capabilities_references.name IS"
         " 'The file''s name without .md, as it was imported; the reference''s key is"
         " reference.<name> with underscores as hyphens and in lower case, unique among"
         " active versions.';"
         " COMMENT ON COLUMN capabilities_references.body IS"
         " 'Every byte of the file, front matter included, kept exactly.';"
         " COMMENT ON COLUMN capabilities_references.active IS"
         " 'The version in force; at most one per reference, none once it is retired.';"
         " COMMENT ON COLUMN capabilities_references.created_by IS"
         " 'Who saved the version: user@node.';"
         " COMMENT ON COLUMN capabilities_references.note IS"
         " 'Why the version was saved.'"),
        # A connection's owner: null for one shared by the capability and
        # grantable to any agent, an agent's id for that agent's own account,
        # which no other agent is granted. A store made before owners gives a
        # row its owner once, by the rule the owner set: a connection whose
        # grants name exactly one agent, and none is for every agent, is that
        # agent's own where it is named for it - the first word of the
        # agent's registered name (lowercase letters and digits) is a word of
        # the connection's name or of its spec's display `name`. Every other
        # row is shared.
        ("0020-connection-owner",
         "ALTER TABLE capabilities_connections ADD COLUMN owner text CHECK (owner <> '');"
         " UPDATE capabilities_connections c SET owner = s.agent_id"
         "  FROM (SELECT capability, connection, min(agent_id) AS agent_id"
         "   FROM capabilities_connection_grants GROUP BY capability, connection"
         "   HAVING count(*) FILTER (WHERE agent_id IS NULL) = 0"
         "    AND count(DISTINCT agent_id) = 1) s,"
         "   capabilities_agents a"
         "  WHERE c.capability = s.capability AND c.name = s.connection AND a.id = s.agent_id"
         "   AND substring(lower(a.name) FROM '[a-z0-9]+') = ANY (regexp_split_to_array("
         "    lower(c.name || ' ' || coalesce(c.spec->>'name', '')), '[^a-z0-9]+'));"
         " CREATE FUNCTION capabilities_connection_grants_owner() RETURNS trigger"
         "  LANGUAGE plpgsql SET search_path FROM CURRENT AS $owner$"
         " DECLARE held text;"
         " BEGIN"
         "  SELECT owner INTO held FROM capabilities_connections"
         "   WHERE capability = NEW.capability AND name = NEW.connection;"
         "  IF held IS NOT NULL AND NEW.agent_id IS DISTINCT FROM held THEN"
         "   RAISE EXCEPTION '% connection % is agent %''s own and is granted to no other"
         " agent', NEW.capability, NEW.connection, held USING ERRCODE = 'check_violation';"
         "  END IF;"
         "  RETURN NEW;"
         " END $owner$;"
         " CREATE TRIGGER capabilities_connection_grants_owner"
         "  BEFORE INSERT OR UPDATE ON capabilities_connection_grants"
         "  FOR EACH ROW EXECUTE FUNCTION capabilities_connection_grants_owner();"
         " CREATE FUNCTION capabilities_connections_owner() RETURNS trigger"
         "  LANGUAGE plpgsql SET search_path FROM CURRENT AS $owner$"
         " BEGIN"
         "  IF NEW.owner IS NOT NULL AND EXISTS (SELECT 1 FROM capabilities_connection_grants"
         "   WHERE capability = OLD.capability AND connection = OLD.name"
         "   AND agent_id IS DISTINCT FROM NEW.owner) THEN"
         "   RAISE EXCEPTION '% connection % is granted to agents other than %, so it"
         " cannot be that agent''s own', OLD.capability, OLD.name, NEW.owner"
         "    USING ERRCODE = 'check_violation';"
         "  END IF;"
         "  RETURN NEW;"
         " END $owner$;"
         " CREATE TRIGGER capabilities_connections_owner"
         "  BEFORE UPDATE OF owner ON capabilities_connections"
         "  FOR EACH ROW EXECUTE FUNCTION capabilities_connections_owner();"
         " COMMENT ON TABLE capabilities_connections IS"
         " 'What a connection is: one row per (capability, name), its spec the entry"
         " interior with secret references only. A row is shared by the capability"
         " (owner null) or one agent''s own.';"
         " COMMENT ON COLUMN capabilities_connections.owner IS"
         " 'The agent whose own connection this is - its own account, granted to no"
         " other agent; null for a connection shared by the capability, which any agent"
         " may be granted.'"),
        # An agent's slug: its short technical name, which names its state
        # directories, its service log lines and its `--project` shorthand.
        # Unique within the store and path-safe; null while the agent has none,
        # where its id stands in. The id is CAPABILITIES_PROJECT_ID, no longer
        # a file's.
        ("0021-agent-slug",
         "ALTER TABLE capabilities_agents ADD COLUMN slug text"
         " CHECK (slug ~ '^[a-z0-9-]+$');"
         " CREATE UNIQUE INDEX capabilities_agents_slug ON capabilities_agents (slug);"
         " COMMENT ON TABLE capabilities_agents IS"
         " 'The agent registry: one row per agent, keyed by its project id"
         " (CAPABILITIES_PROJECT_ID). Written by the capabilities manager alone.';"
         " COMMENT ON COLUMN capabilities_agents.id IS"
         " 'The project id, CAPABILITIES_PROJECT_ID (prj_<12 hex>, or an older UUID).';"
         " COMMENT ON COLUMN capabilities_agents.slug IS"
         " 'The agent''s short technical name: lowercase letters, digits and hyphens,"
         " unique within the store. It names the agent''s state directories, service log"
         " lines and --project shorthand; null while it has none, where the id stands in.'"),
        # A node created as a Coolify resource names the coolify connection it
        # was created through, the server and the resource, so it is reached
        # and removed through that connection, whose token stays there. The
        # three are set together or not at all. A node's public key is the
        # X25519 key whose private half the node made and keeps.
        ("0022-agent-node-coolify",
         "ALTER TABLE capabilities_agent_nodes"
         " ADD COLUMN coolify_connection text CHECK (coolify_connection <> ''),"
         " ADD COLUMN coolify_server text CHECK (coolify_server <> ''),"
         " ADD COLUMN coolify_resource text CHECK (coolify_resource <> ''),"
         " ADD COLUMN public_key text CHECK (public_key ~ '^[A-Za-z0-9+/]{43}=$'),"
         " ADD CONSTRAINT capabilities_agent_nodes_coolify CHECK"
         "  (num_nonnulls(coolify_connection, coolify_server, coolify_resource) IN (0, 3));"
         " COMMENT ON COLUMN capabilities_agent_nodes.coolify_connection IS"
         " 'The coolify capability connection the node was created through; its token"
         " stays in that connection. Null for a node that is not a Coolify resource.';"
         " COMMENT ON COLUMN capabilities_agent_nodes.coolify_server IS"
         " 'The uuid of the Coolify server the node''s resource runs on.';"
         " COMMENT ON COLUMN capabilities_agent_nodes.coolify_resource IS"
         " 'The uuid of the Coolify resource that is the node.';"
         " COMMENT ON COLUMN capabilities_agent_nodes.public_key IS"
         " 'The node''s X25519 public key, its 32 bytes in base64; the private key"
         " never leaves the node.'"),
        # What binds an agent beyond its id, kept in its row rather than in a
        # file of its folder: where its body sits inside the project and how
        # it collaborates. A body root is a relative, visible folder, as the
        # manager reads one: not empty, not absolute, no `..` part, and a
        # first part that does not start with `.`; null is the project root.
        ("0023-agent-binding",
         "ALTER TABLE capabilities_agents"
         " ADD COLUMN body_root text CHECK (body_root <> '' AND body_root = btrim(body_root)"
         "  AND left(body_root, 1) NOT IN ('/', '.')"
         "  AND body_root !~ '(^|/)[.][.](/|$)'),"
         " ADD COLUMN collaboration_mode text"
         "  CHECK (collaboration_mode IN ('ask', 'direct'));"
         " COMMENT ON COLUMN capabilities_agents.body_root IS"
         " 'The folder inside the project that holds the agent''s body - its context,"
         " assets, routines and capabilities layers - as a relative path such as agent;"
         " null where the body sits at the project root.';"
         " COMMENT ON COLUMN capabilities_agents.collaboration_mode IS"
         " 'ask: the agent offers Direct or Agent Team mode before non-trivial work;"
         " direct: it does not offer. Null is ask.'"),
        # The folder an agent lives in on a node: its project root on that
        # machine, an absolute path. One folder on a node is one agent's, which
        # the unique index enforces; null where the node's folder is not
        # recorded, as for a node created elsewhere.
        ("0024-agent-node-folder",
         "ALTER TABLE capabilities_agent_nodes"
         " ADD COLUMN folder text CHECK (folder <> '' AND left(folder, 1) = '/');"
         " CREATE UNIQUE INDEX capabilities_agent_nodes_folder"
         "  ON capabilities_agent_nodes (node, folder);"
         " COMMENT ON COLUMN capabilities_agent_nodes.folder IS"
         " 'The folder the agent lives in on this node, its project root there, as an"
         " absolute path such as /app; null where it is not recorded. One folder on a"
         " node is one agent''s.'"),
        # Whether the agent's bundled service of the capability is placed on
        # the node its row names, apart from whether the capability is usable
        # there (`enabled`). Only an agent's row naming a node places a service.
        # A row written before this column placed a service exactly where it
        # enabled the capability on a node of its own, so that is its value.
        # A writer that predates the column still means that: a trigger gives
        # `service` the value of `enabled` on an agent's row naming a node
        # where an insert leaves it out, or an update changes `enabled` and
        # leaves `service` as it was.
        ("0025-policy-service",
         "ALTER TABLE capabilities_policy"
         " ADD COLUMN service boolean NOT NULL DEFAULT false;"
         " UPDATE capabilities_policy SET service = enabled"
         "  WHERE agent_id IS NOT NULL AND node IS NOT NULL;"
         " ALTER TABLE capabilities_policy ALTER COLUMN service DROP DEFAULT;"
         " ALTER TABLE capabilities_policy ADD CONSTRAINT capabilities_policy_service"
         "  CHECK (NOT service OR (agent_id IS NOT NULL AND node IS NOT NULL));"
         " CREATE FUNCTION capabilities_policy_service_follows() RETURNS trigger"
         "  LANGUAGE plpgsql AS $follows$"
         " BEGIN"
         "  IF NEW.agent_id IS NULL OR NEW.node IS NULL THEN"
         "   NEW.service := coalesce(NEW.service, false);"
         "  ELSIF tg_op = 'INSERT' THEN"
         "   NEW.service := coalesce(NEW.service, NEW.enabled);"
         "  ELSIF NEW.enabled IS DISTINCT FROM OLD.enabled"
         "   AND NEW.service IS NOT DISTINCT FROM OLD.service THEN"
         "   NEW.service := NEW.enabled;"
         "  END IF;"
         "  RETURN NEW;"
         " END $follows$;"
         " CREATE TRIGGER capabilities_policy_service_follows"
         "  BEFORE INSERT OR UPDATE ON capabilities_policy"
         "  FOR EACH ROW EXECUTE FUNCTION capabilities_policy_service_follows();"
         " COMMENT ON COLUMN capabilities_policy.service IS"
         " 'Whether the agent''s bundled service of this capability is placed on the node"
         " the row names: the service runs there. Apart from enabled, which says whether"
         " the capability is usable there. Only an agent''s row naming a node places."
         " A trigger sets it to enabled on such a row where an insert leaves it out or"
         " an update changes enabled alone, as a writer that predates the column means.'"),
        # The node registry: a node is a row of its own, keyed by its id and
        # shown by its label, apart from which agent lives on it. A node's own
        # fields - its kind, address, target, Coolify resource, public key and
        # when it was last seen - move from each agent's link to it, and a link
        # keeps what belongs to the pair: the folder, the master and the write
        # flag. Every node a link named becomes a row whose id and label are
        # that name, the id it was known by until it moves to a twelve-hex id
        # of its own (`capabilities node rekey`); its fields are taken from the
        # link that is a master first, then the one seen last.
        ("0026-nodes",
         "CREATE TABLE capabilities_nodes ("
         " id text PRIMARY KEY CHECK (id <> ''),"
         " label text NOT NULL CHECK (label <> '' AND label = btrim(label)),"
         " kind text NOT NULL CHECK (kind IN ('mac', 'server')),"
         " address text CHECK (address <> ''),"
         " target text CHECK (target <> ''),"
         " coolify_connection text CHECK (coolify_connection <> ''),"
         " coolify_server text CHECK (coolify_server <> ''),"
         " coolify_resource text CHECK (coolify_resource <> ''),"
         " public_key text CHECK (public_key ~ '^[A-Za-z0-9+/]{43}=$'),"
         " last_seen_at timestamptz,"
         " created_at timestamptz NOT NULL DEFAULT now(),"
         " updated_at timestamptz NOT NULL DEFAULT now(),"
         " CONSTRAINT capabilities_nodes_coolify CHECK"
         "  (num_nonnulls(coolify_connection, coolify_server, coolify_resource) IN (0, 3)));"
         " INSERT INTO capabilities_nodes (id, label, kind, address, target,"
         "  coolify_connection, coolify_server, coolify_resource, public_key, last_seen_at)"
         " SELECT DISTINCT ON (n.node) n.node, n.node, n.kind, n.address, n.target,"
         "  n.coolify_connection, n.coolify_server, n.coolify_resource, n.public_key,"
         "  (SELECT max(m.last_seen_at) FROM capabilities_agent_nodes m WHERE m.node = n.node)"
         " FROM capabilities_agent_nodes n"
         " ORDER BY n.node, n.is_master DESC, n.last_seen_at DESC NULLS LAST, n.agent_id;"
         " ALTER TABLE capabilities_agent_nodes"
         "  DROP CONSTRAINT capabilities_agent_nodes_coolify,"
         "  DROP COLUMN kind, DROP COLUMN address, DROP COLUMN target,"
         "  DROP COLUMN last_seen_at, DROP COLUMN coolify_connection,"
         "  DROP COLUMN coolify_server, DROP COLUMN coolify_resource, DROP COLUMN public_key,"
         "  ADD CONSTRAINT capabilities_agent_nodes_node FOREIGN KEY (node)"
         "   REFERENCES capabilities_nodes (id) ON DELETE CASCADE ON UPDATE CASCADE;"
         " COMMENT ON TABLE capabilities_nodes IS"
         " 'The node registry: one row per machine an agent runs on, keyed by its id and"
         " shown by its label. Written by the capabilities manager alone.';"
         " COMMENT ON COLUMN capabilities_nodes.id IS"
         " 'The id the machine resolves for itself: twelve lowercase hex characters, from a"
         " Mac''s hardware or a server''s config home, or AGENT_NODE_ID; a row registered"
         " before ids holds the name it had until `capabilities node rekey` moves it. Every"
         " store row that names a node holds this id.';"
         " COMMENT ON COLUMN capabilities_nodes.label IS"
         " 'The name shown for the node, free text set and changed at will; renaming a node"
         " changes this column alone.';"
         " COMMENT ON COLUMN capabilities_nodes.kind IS"
         " 'mac: the node resolves its id from its hardware; server: from the id minted onto"
         " its config volume.';"
         " COMMENT ON COLUMN capabilities_nodes.address IS"
         " 'Host name or IP address the node is reached at, where it is fixed.';"
         " COMMENT ON COLUMN capabilities_nodes.target IS"
         " 'The deployment target this node is deployed by; null for a node that is not"
         " deployed, such as a Mac.';"
         " COMMENT ON COLUMN capabilities_nodes.coolify_connection IS"
         " 'The coolify capability connection the node was created through; its token"
         " stays in that connection. Null for a node that is not a Coolify resource.';"
         " COMMENT ON COLUMN capabilities_nodes.coolify_server IS"
         " 'The uuid of the Coolify server the node''s resource runs on.';"
         " COMMENT ON COLUMN capabilities_nodes.coolify_resource IS"
         " 'The uuid of the Coolify resource that is the node.';"
         " COMMENT ON COLUMN capabilities_nodes.public_key IS"
         " 'The node''s X25519 public key, its 32 bytes in base64; the private key"
         " never leaves the node.';"
         " COMMENT ON COLUMN capabilities_nodes.last_seen_at IS"
         " 'When the node last reported itself.';"
         " COMMENT ON TABLE capabilities_agent_nodes IS"
         " 'Which agent lives on which node, one row per (agent, node), with what belongs to"
         " the pair. Written by the capabilities manager alone.';"
         " COMMENT ON COLUMN capabilities_agent_nodes.node IS"
         " 'The node''s id in capabilities_nodes.'"),
        # A reader from before the node registry - an older manager, AgentKit -
        # still reads a node's fields off its links, so they stay there as a
        # copy the store keeps of the node's row until those readers read the
        # registry: nothing writes them, a trigger fills them on every link
        # written, and a node's row copies them to its links where they
        # differ. A label is not copied, so renaming a node is still its row
        # alone. The triggers name the tables in the schema they fire in, so a
        # writer's search_path does not matter. A step of its own after `0026-nodes`, which a store may hold
        # already, so every store reaches the same tables.
        ("0027-agent-node-fields-kept",
         "ALTER TABLE capabilities_agent_nodes"
         " ADD COLUMN kind text, ADD COLUMN address text, ADD COLUMN target text,"
         " ADD COLUMN last_seen_at timestamptz, ADD COLUMN coolify_connection text,"
         " ADD COLUMN coolify_server text, ADD COLUMN coolify_resource text,"
         " ADD COLUMN public_key text;"
         " CREATE FUNCTION capabilities_agent_nodes_node_fields() RETURNS trigger"
         "  LANGUAGE plpgsql AS $fields$"
         " BEGIN"
         "  EXECUTE format('SELECT kind, address, target, last_seen_at, coolify_connection,"
         "   coolify_server, coolify_resource, public_key FROM %I.capabilities_nodes"
         "   WHERE id = $1', tg_table_schema)"
         "  INTO NEW.kind, NEW.address, NEW.target, NEW.last_seen_at, NEW.coolify_connection,"
         "   NEW.coolify_server, NEW.coolify_resource, NEW.public_key"
         "  USING NEW.node;"
         "  RETURN NEW;"
         " END $fields$;"
         " CREATE TRIGGER capabilities_agent_nodes_node_fields"
         "  BEFORE INSERT OR UPDATE ON capabilities_agent_nodes"
         "  FOR EACH ROW EXECUTE FUNCTION capabilities_agent_nodes_node_fields();"
         " CREATE FUNCTION capabilities_nodes_to_links() RETURNS trigger"
         "  LANGUAGE plpgsql AS $links$"
         " BEGIN"
         "  EXECUTE format('UPDATE %I.capabilities_agent_nodes SET node = node WHERE node = $1"
         "   AND (kind, address, target, last_seen_at, coolify_connection, coolify_server,"
         "    coolify_resource, public_key) IS DISTINCT FROM ($2, $3, $4, $5, $6, $7, $8, $9)',"
         "   tg_table_schema)"
         "  USING NEW.id, NEW.kind, NEW.address, NEW.target, NEW.last_seen_at,"
         "   NEW.coolify_connection, NEW.coolify_server, NEW.coolify_resource, NEW.public_key;"
         "  RETURN NULL;"
         " END $links$;"
         " CREATE TRIGGER capabilities_nodes_to_links"
         "  AFTER INSERT OR UPDATE ON capabilities_nodes"
         "  FOR EACH ROW EXECUTE FUNCTION capabilities_nodes_to_links();"
         " UPDATE capabilities_agent_nodes SET node = node;"
         " COMMENT ON COLUMN capabilities_agent_nodes.kind IS"
         " 'A copy of capabilities_nodes.kind kept by the store for readers from before the"
         " node registry; nothing writes it, and it goes once they read the registry.';"
         " COMMENT ON COLUMN capabilities_agent_nodes.address IS"
         " 'A copy of capabilities_nodes.address kept by the store, as kind.';"
         " COMMENT ON COLUMN capabilities_agent_nodes.target IS"
         " 'A copy of capabilities_nodes.target kept by the store, as kind.';"
         " COMMENT ON COLUMN capabilities_agent_nodes.last_seen_at IS"
         " 'A copy of capabilities_nodes.last_seen_at kept by the store, as kind.';"
         " COMMENT ON COLUMN capabilities_agent_nodes.coolify_connection IS"
         " 'A copy of capabilities_nodes.coolify_connection kept by the store, as kind.';"
         " COMMENT ON COLUMN capabilities_agent_nodes.coolify_server IS"
         " 'A copy of capabilities_nodes.coolify_server kept by the store, as kind.';"
         " COMMENT ON COLUMN capabilities_agent_nodes.coolify_resource IS"
         " 'A copy of capabilities_nodes.coolify_resource kept by the store, as kind.';"
         " COMMENT ON COLUMN capabilities_agent_nodes.public_key IS"
         " 'A copy of capabilities_nodes.public_key kept by the store, as kind.'"),
        # What runs where: one row per service a node supervises, written by
        # whatever supervises it there - today deployment's runner - and
        # deleted when it stops supervising it, so the nodes that run a
        # service are a plain read. `node` carries no foreign key, as the
        # lease's does not: a service running on a node nobody registered is
        # still shown, and `capabilities node rekey` moves the column with
        # every other that names a node. `ready` is computed from `state`,
        # which alone says whether the service can do its work.
        ("0028-service-instances",
         "CREATE TABLE capabilities_service_instances ("
         " project_id text NOT NULL CHECK (project_id <> ''),"
         " capability text NOT NULL CHECK (capability ~ '^[a-z][a-z0-9_-]*$'),"
         " node text NOT NULL CHECK (node <> ''),"
         " state text NOT NULL CHECK (state IN ('starting', 'ready', 'unusable', 'degraded', 'failing', 'held', 'waiting', 'stopping')),"
         " ready boolean GENERATED ALWAYS AS (state IN ('ready', 'degraded')) STORED,"
         " problem text CHECK (problem <> ''),"
         " problem_code text CHECK (problem_code <> ''),"
         " payload_sha256 text CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),"
         " pid integer CHECK (pid > 0),"
         " host text CHECK (host <> ''),"
         " started_at timestamptz,"
         " checked_at timestamptz NOT NULL DEFAULT now(),"
         " last_exit_code integer,"
         " last_error text CHECK (last_error <> ''),"
         " last_error_at timestamptz,"
         " skipped_settings jsonb NOT NULL DEFAULT '[]'"
         "  CHECK (jsonb_typeof(skipped_settings) = 'array'),"
         " PRIMARY KEY (project_id, capability, node),"
         " CONSTRAINT capabilities_service_instances_unusable_says_why"
         "  CHECK (state <> 'unusable' OR problem IS NOT NULL),"
         " CONSTRAINT capabilities_service_instances_failing_says_why"
         "  CHECK (state <> 'failing' OR last_error IS NOT NULL));"
         " COMMENT ON TABLE capabilities_service_instances IS"
         " 'What each node actually runs: one row per (project, capability, node) while"
         " something on that node supervises the service, deleted when it stops"
         " supervising it. Placement says where a service should run and the lease which"
         " node may run an exclusive one; this row says what runs and whether it works.';"
         " COMMENT ON COLUMN capabilities_service_instances.project_id IS"
         " 'The project''s declared id.';"
         " COMMENT ON COLUMN capabilities_service_instances.node IS"
         " 'The id of the node the service runs on, as capabilities_nodes keys it.';"
         " COMMENT ON COLUMN capabilities_service_instances.state IS"
         " 'starting: running, not yet passed its probe; ready: running and its probe"
         " passes; unusable: running, and its probe says it cannot do its work (problem says"
         " why); degraded: ready, with settings skipped on this node; failing: exits and is"
         " restarted, or cannot be started (last_error says why); held: stopped and not"
         " restarted until the gate answer changes; waiting: placed here, while another"
         " node holds the lease; stopping: no longer placed here, being stopped.';"
         " COMMENT ON COLUMN capabilities_service_instances.ready IS"
         " 'Whether the service can do its work here: state ready or degraded.';"
         " COMMENT ON COLUMN capabilities_service_instances.problem IS"
         " 'Why the service is not ready, in its declared doctor''s words.';"
         " COMMENT ON COLUMN capabilities_service_instances.problem_code IS"
         " 'The error code the doctor named, else the category its exit code stands for.';"
         " COMMENT ON COLUMN capabilities_service_instances.payload_sha256 IS"
         " 'The installed payload of the capability the service was started from.';"
         " COMMENT ON COLUMN capabilities_service_instances.pid IS"
         " 'The service''s process on host; null while it does not run.';"
         " COMMENT ON COLUMN capabilities_service_instances.host IS"
         " 'The host name of the machine the pid is on.';"
         " COMMENT ON COLUMN capabilities_service_instances.started_at IS"
         " 'When the running process started; null while it does not run.';"
         " COMMENT ON COLUMN capabilities_service_instances.checked_at IS"
         " 'When the supervisor last wrote the row; a node that stops writing it is gone"
         " or cut off, and its rows say nothing after that.';"
         " COMMENT ON COLUMN capabilities_service_instances.last_exit_code IS"
         " 'The exit code the service last failed with on this node; null when it could not"
         " be started at all.';"
         " COMMENT ON COLUMN capabilities_service_instances.last_error IS"
         " 'The last lines the service printed to stderr when it last failed, or why it"
         " could not be started.';"
         " COMMENT ON COLUMN capabilities_service_instances.last_error_at IS"
         " 'When the service last failed on this node.';"
         " COMMENT ON COLUMN capabilities_service_instances.skipped_settings IS"
         " 'The settings the service reported it cannot honour on this node and skipped,"
         " as its doctor named them.'"),
        # Each agent's vault: its secrets, sealed with the agent's own key,
        # which the store never holds; the agent's row keeps only the key's
        # fingerprint. A row sealed under another key than the agent's present
        # one is unreadable, kept until it is set again or removed. Every
        # change raises the vault's channel version for the agent, so a
        # process that resolved a secret rereads it.
        ("0029-vault",
         "CREATE TABLE capabilities_vault ("
         " agent_id text NOT NULL CHECK (agent_id <> ''),"
         " name text NOT NULL CHECK (name ~ '^[A-Za-z_][A-Za-z0-9_]{0,254}$'),"
         " ciphertext bytea NOT NULL,"
         " key_fingerprint text NOT NULL CHECK (key_fingerprint ~ '^[0-9a-f]{64}$'),"
         " updated_at timestamptz NOT NULL DEFAULT now(),"
         " updated_by text CHECK (updated_by <> ''),"
         " PRIMARY KEY (agent_id, name));"
         " ALTER TABLE capabilities_agents ADD COLUMN vault_key text"
         "  CHECK (vault_key ~ '^[0-9a-f]{64}$');"
         " CREATE FUNCTION capabilities_vault_announce() RETURNS trigger AS $$"
         " DECLARE agent text;"
         " BEGIN"
         "  IF tg_table_name = 'capabilities_agents' THEN agent := new.id;"
         "  ELSIF tg_op = 'DELETE' THEN agent := old.agent_id;"
         "  ELSE agent := new.agent_id; END IF;"
         "  IF to_regclass(format('%I.schema_channel', tg_table_schema)) IS NOT NULL THEN"
         "   EXECUTE format('INSERT INTO %I.schema_channel AS c (channel, scope, version)"
         " VALUES (%L, $1, 1) ON CONFLICT (channel, scope)"
         " DO UPDATE SET version = c.version + 1',"
         "                  tg_table_schema, 'capabilities_vault') USING agent;"
         "  END IF;"
         "  RETURN NULL;"
         " END $$ LANGUAGE plpgsql;"
         " CREATE TRIGGER capabilities_vault_changed"
         "  AFTER INSERT OR UPDATE OR DELETE ON capabilities_vault"
         "  FOR EACH ROW EXECUTE FUNCTION capabilities_vault_announce();"
         " CREATE TRIGGER capabilities_vault_key_changed"
         "  AFTER UPDATE OF vault_key ON capabilities_agents"
         "  FOR EACH ROW WHEN (old.vault_key IS DISTINCT FROM new.vault_key)"
         "  EXECUTE FUNCTION capabilities_vault_announce();"
         " COMMENT ON TABLE capabilities_vault IS"
         " 'Each agent''s vault: one row per named secret, sealed with XChaCha20-Poly1305"
         " under the agent''s own key (AGENT_ENCRYPTION_KEY, kept in the agent''s"
         " environment and never here), the agent id and the name bound as associated"
         " data. Written by the capabilities manager''s secrets verbs.';"
         " COMMENT ON COLUMN capabilities_vault.agent_id IS"
         " 'The agent the secret is sealed for, as capabilities_agents keys it.';"
         " COMMENT ON COLUMN capabilities_vault.name IS"
         " 'The environment variable name the secret answers in the credential cascade.';"
         " COMMENT ON COLUMN capabilities_vault.ciphertext IS"
         " 'A format byte, the 24-byte nonce, then the ciphertext with its tag.';"
         " COMMENT ON COLUMN capabilities_vault.key_fingerprint IS"
         " 'The fingerprint of the key that sealed the value; a row whose fingerprint is"
         " not the agent''s vault_key is unreadable.';"
         " COMMENT ON COLUMN capabilities_agents.vault_key IS"
         " 'The fingerprint of the agent''s encryption key, never the key; null while"
         " the agent has none.'"),
        # What each node says of itself, written by its own manager on a short
        # beat: one row per machine, shared by every agent on it as its
        # registry row is, so it carries no project. A node stands for itself
        # until fresh_until, the store's time, and reads as unreachable once
        # that has passed. Beside it, per agent, whether its tools are signed
        # in on that node and whether each device-bound connection holds a
        # live session there. A sign-in is per agent rather than per machine
        # because a tool keeps it in the home of the OS user it runs as, and
        # one machine can hold agents of several OS users, each under its own
        # manager. All three name the node through a foreign key to the
        # registry: a row means nothing without its node, a rekey moves it
        # with the registry's id, and removing the node removes it.
        ("0030-node-states",
         "CREATE TABLE capabilities_node_states ("
         " node text PRIMARY KEY"
         "  REFERENCES capabilities_nodes (id) ON DELETE CASCADE ON UPDATE CASCADE,"
         " load_1 double precision CHECK (load_1 >= 0),"
         " load_5 double precision CHECK (load_5 >= 0),"
         " load_15 double precision CHECK (load_15 >= 0),"
         " cpu_count integer CHECK (cpu_count > 0),"
         " memory_used_bytes bigint CHECK (memory_used_bytes >= 0),"
         " memory_limit_bytes bigint CHECK (memory_limit_bytes > 0),"
         " disk_used_bytes bigint CHECK (disk_used_bytes >= 0),"
         " disk_total_bytes bigint CHECK (disk_total_bytes > 0),"
         " booted_at timestamptz,"
         " boot_line text CHECK (boot_line <> ''),"
         " image_version text CHECK (image_version <> ''),"
         " reported_at timestamptz NOT NULL DEFAULT now(),"
         " fresh_until timestamptz NOT NULL,"
         " CONSTRAINT capabilities_node_states_fresh_after_report"
         "  CHECK (fresh_until > reported_at));"
         " CREATE TABLE capabilities_node_logins ("
         " project_id text NOT NULL CHECK (project_id <> ''),"
         " node text NOT NULL"
         "  REFERENCES capabilities_nodes (id) ON DELETE CASCADE ON UPDATE CASCADE,"
         " claude_login text NOT NULL DEFAULT 'unknown'"
         "  CHECK (claude_login IN ('signed_in', 'signed_out', 'absent', 'unknown')),"
         " claude_account text CHECK (claude_account <> ''),"
         " codex_login text NOT NULL DEFAULT 'unknown'"
         "  CHECK (codex_login IN ('signed_in', 'signed_out', 'absent', 'unknown')),"
         " codex_account text CHECK (codex_account <> ''),"
         " gh_login text NOT NULL DEFAULT 'unknown'"
         "  CHECK (gh_login IN ('signed_in', 'signed_out', 'absent', 'unknown')),"
         " gh_account text CHECK (gh_account <> ''),"
         " checked_at timestamptz NOT NULL DEFAULT now(),"
         " PRIMARY KEY (project_id, node),"
         " CONSTRAINT capabilities_node_logins_account_signed_in CHECK"
         "  ((claude_account IS NULL OR claude_login = 'signed_in')"
         "   AND (codex_account IS NULL OR codex_login = 'signed_in')"
         "   AND (gh_account IS NULL OR gh_login = 'signed_in')));"
         " CREATE INDEX capabilities_node_logins_node"
         "  ON capabilities_node_logins (node);"
         " CREATE TABLE capabilities_node_sessions ("
         " project_id text NOT NULL CHECK (project_id <> ''),"
         " node text NOT NULL"
         "  REFERENCES capabilities_nodes (id) ON DELETE CASCADE ON UPDATE CASCADE,"
         " capability text NOT NULL CHECK (capability ~ '^[a-z][a-z0-9_-]*$'),"
         " connection text NOT NULL CHECK (connection <> ''),"
         " live boolean NOT NULL,"
         " account text CHECK (account <> ''),"
         " checked_at timestamptz NOT NULL DEFAULT now(),"
         " PRIMARY KEY (project_id, node, capability, connection));"
         " CREATE INDEX capabilities_node_sessions_node"
         "  ON capabilities_node_sessions (node);"
         " COMMENT ON TABLE capabilities_node_states IS"
         " 'What each node says of itself: one row per machine, written by that"
         " machine''s capabilities manager alone on a short beat and when it changes."
         " The row belongs to the machine and is shared by every agent on it, as its"
         " row in capabilities_nodes is, so it carries no project. Read it directly:"
         " the node is reachable while fresh_until has not passed.';"
         " COMMENT ON COLUMN capabilities_node_states.node IS"
         " 'The node''s id in capabilities_nodes.';"
         " COMMENT ON COLUMN capabilities_node_states.load_1 IS"
         " 'The machine''s load average over 1 minute, as the operating system"
         " reports it.';"
         " COMMENT ON COLUMN capabilities_node_states.load_5 IS"
         " 'The machine''s load average over 5 minutes.';"
         " COMMENT ON COLUMN capabilities_node_states.load_15 IS"
         " 'The machine''s load average over 15 minutes.';"
         " COMMENT ON COLUMN capabilities_node_states.cpu_count IS"
         " 'How many CPUs this node''s processes may run on.';"
         " COMMENT ON COLUMN capabilities_node_states.memory_used_bytes IS"
         " 'Memory in use: the container''s, less the file cache it may give back,"
         " where the node runs under a memory limit; else the machine''s.';"
         " COMMENT ON COLUMN capabilities_node_states.memory_limit_bytes IS"
         " 'The memory limit the node runs under, where it has one; else the"
         " machine''s physical memory.';"
         " COMMENT ON COLUMN capabilities_node_states.disk_used_bytes IS"
         " 'Bytes used on the filesystem holding the home of the user the node''s"
         " manager runs as.';"
         " COMMENT ON COLUMN capabilities_node_states.disk_total_bytes IS"
         " 'The size of the filesystem disk_used_bytes measures.';"
         " COMMENT ON COLUMN capabilities_node_states.booted_at IS"
         " 'When the node started: the container''s start on a container node, the"
         " machine''s boot otherwise. Its uptime is the store''s now less this.';"
         " COMMENT ON COLUMN capabilities_node_states.boot_line IS"
         " 'The line an agent-node image''s boot path last wrote of what it is doing;"
         " null off the image.';"
         " COMMENT ON COLUMN capabilities_node_states.image_version IS"
         " 'The version of the agent-node image the node runs; null off the image.';"
         " COMMENT ON COLUMN capabilities_node_states.reported_at IS"
         " 'The store''s time of the node''s last write of this row.';"
         " COMMENT ON COLUMN capabilities_node_states.fresh_until IS"
         " 'The store''s time until which the row stands for the node: its write time"
         " and the stated interval. Once it has passed, the node reads as"
         " unreachable.';"
         " COMMENT ON TABLE capabilities_node_logins IS"
         " 'Per agent, whether Claude Code, Codex and the GitHub CLI are signed in on a"
         " node and as whom, as each tool answers for the OS user the agent''s folder"
         " there belongs to. Written by that OS user''s capabilities manager, which"
         " replaces the agent''s row on each write; a machine with several OS users"
         " has one manager each, and none writes another''s agents.';"
         " COMMENT ON COLUMN capabilities_node_logins.project_id IS"
         " 'The agent whose tools they are.';"
         " COMMENT ON COLUMN capabilities_node_logins.node IS"
         " 'The node''s id in capabilities_nodes.';"
         " COMMENT ON COLUMN capabilities_node_logins.claude_login IS"
         " 'Whether Claude Code is signed in for this agent on this node, as its own"
         " status answer there says: signed_in, signed_out, absent (not installed) or"
         " unknown (its answer could not be read).';"
         " COMMENT ON COLUMN capabilities_node_logins.claude_account IS"
         " 'The account Claude Code states it is signed in as; null unless signed in.';"
         " COMMENT ON COLUMN capabilities_node_logins.codex_login IS"
         " 'Whether Codex is signed in on this node, as its own status answer says,"
         " in claude_login''s terms.';"
         " COMMENT ON COLUMN capabilities_node_logins.codex_account IS"
         " 'The account Codex states it is signed in as; null unless signed in and"
         " where it states none.';"
         " COMMENT ON COLUMN capabilities_node_logins.gh_login IS"
         " 'Whether the GitHub CLI is signed in to github.com on this node, as its own"
         " status answer says, in claude_login''s terms.';"
         " COMMENT ON COLUMN capabilities_node_logins.gh_account IS"
         " 'The github.com login the GitHub CLI is signed in as; null unless signed in.';"
         " COMMENT ON COLUMN capabilities_node_logins.checked_at IS"
         " 'The store''s time of the write that last asked the tools.';"
         " COMMENT ON TABLE capabilities_node_sessions IS"
         " 'Per agent, whether each connection of a device-bound capability holds a"
         " live session on a node, as that capability answers in the agent''s folder"
         " there. Written by the node''s capabilities manager, which replaces an"
         " agent''s rows for one capability on a node on each write.';"
         " COMMENT ON COLUMN capabilities_node_sessions.project_id IS"
         " 'The agent whose connection it is.';"
         " COMMENT ON COLUMN capabilities_node_sessions.node IS"
         " 'The node''s id in capabilities_nodes.';"
         " COMMENT ON COLUMN capabilities_node_sessions.live IS"
         " 'Whether a live session of the connection exists on the node.';"
         " COMMENT ON COLUMN capabilities_node_sessions.account IS"
         " 'The account the session is, as the capability states it; null where it"
         " states none.';"
         " COMMENT ON COLUMN capabilities_node_sessions.checked_at IS"
         " 'The store''s time of the write that last asked the capability.'"),
        # What a node is expected to have. Each agent's sign-in row says which
        # tools the services it places on that node need, as the node's own
        # manager derives it from their manifests; beside it, the owner's word
        # per tool and per device-bound connection, expected on or off, which
        # stands over what the services need. An override is the owner's, not
        # the node's: no manager write replaces it, and it goes only with its
        # node or when the owner takes it back.
        ("0031-node-expectations",
         "ALTER TABLE capabilities_node_logins"
         " ADD COLUMN claude_needed boolean NOT NULL DEFAULT false,"
         " ADD COLUMN codex_needed boolean NOT NULL DEFAULT false,"
         " ADD COLUMN gh_needed boolean NOT NULL DEFAULT false;"
         " CREATE TABLE capabilities_node_login_expectations ("
         " project_id text NOT NULL CHECK (project_id <> ''),"
         " node text NOT NULL"
         "  REFERENCES capabilities_nodes (id) ON DELETE CASCADE ON UPDATE CASCADE,"
         " tool text NOT NULL CHECK (tool IN ('claude', 'codex', 'gh')),"
         " expected boolean NOT NULL,"
         " updated_at timestamptz NOT NULL DEFAULT now(),"
         " updated_by text CHECK (updated_by <> ''),"
         " PRIMARY KEY (project_id, node, tool));"
         " CREATE INDEX capabilities_node_login_expectations_node"
         "  ON capabilities_node_login_expectations (node);"
         " CREATE TABLE capabilities_node_session_expectations ("
         " project_id text NOT NULL CHECK (project_id <> ''),"
         " node text NOT NULL"
         "  REFERENCES capabilities_nodes (id) ON DELETE CASCADE ON UPDATE CASCADE,"
         " capability text NOT NULL CHECK (capability ~ '^[a-z][a-z0-9_-]*$'),"
         " connection text NOT NULL CHECK (connection <> ''),"
         " expected boolean NOT NULL,"
         " updated_at timestamptz NOT NULL DEFAULT now(),"
         " updated_by text CHECK (updated_by <> ''),"
         " PRIMARY KEY (project_id, node, capability, connection));"
         " CREATE INDEX capabilities_node_session_expectations_node"
         "  ON capabilities_node_session_expectations (node);"
         " COMMENT ON COLUMN capabilities_node_logins.claude_needed IS"
         " 'Whether a service the agent places on this node needs Claude Code signed"
         " in here, as the node''s manager derives it from the services'' manifests.';"
         " COMMENT ON COLUMN capabilities_node_logins.codex_needed IS"
         " 'Whether a service the agent places on this node needs Codex signed in"
         " here, in claude_needed''s terms.';"
         " COMMENT ON COLUMN capabilities_node_logins.gh_needed IS"
         " 'Whether a service the agent places on this node needs the GitHub CLI"
         " signed in here, in claude_needed''s terms.';"
         " COMMENT ON TABLE capabilities_node_login_expectations IS"
         " 'The owner''s word on whether a tool''s sign-in is expected for an agent on"
         " a node, standing over whether its placed services need it. A tool with no"
         " row is expected where they need it.';"
         " COMMENT ON COLUMN capabilities_node_login_expectations.project_id IS"
         " 'The agent whose sign-in it is.';"
         " COMMENT ON COLUMN capabilities_node_login_expectations.node IS"
         " 'The node''s id in capabilities_nodes.';"
         " COMMENT ON COLUMN capabilities_node_login_expectations.tool IS"
         " 'The tool: claude, codex or gh.';"
         " COMMENT ON COLUMN capabilities_node_login_expectations.expected IS"
         " 'Whether the sign-in is expected there: true on, false off.';"
         " COMMENT ON COLUMN capabilities_node_login_expectations.updated_at IS"
         " 'When the owner last set it.';"
         " COMMENT ON COLUMN capabilities_node_login_expectations.updated_by IS"
         " 'Who set it, where the writer names itself.';"
         " COMMENT ON TABLE capabilities_node_session_expectations IS"
         " 'The owner''s word on whether a device-bound connection of an agent is"
         " expected to hold a live session on a node, standing over whether the agent"
         " places that capability''s service there. A connection with no row is"
         " expected where it is placed.';"
         " COMMENT ON COLUMN capabilities_node_session_expectations.project_id IS"
         " 'The agent whose connection it is.';"
         " COMMENT ON COLUMN capabilities_node_session_expectations.node IS"
         " 'The node''s id in capabilities_nodes.';"
         " COMMENT ON COLUMN capabilities_node_session_expectations.capability IS"
         " 'The device-bound capability the connection is of.';"
         " COMMENT ON COLUMN capabilities_node_session_expectations.connection IS"
         " 'The connection''s id within that capability.';"
         " COMMENT ON COLUMN capabilities_node_session_expectations.expected IS"
         " 'Whether a live session is expected there: true on, false off.';"
         " COMMENT ON COLUMN capabilities_node_session_expectations.updated_at IS"
         " 'When the owner last set it.';"
         " COMMENT ON COLUMN capabilities_node_session_expectations.updated_by IS"
         " 'Who set it, where the writer names itself.'"),
    ]


def service_instance_put(conn: Any, project_id: str, capability: str, node: str, *,
                         state: str, problem: str | None = None,
                         problem_code: str | None = None,
                         payload_sha256: str | None = None, pid: int | None = None,
                         host: str | None = None, started_at: Any = None,
                         last_exit_code: int | None = None, last_error: str | None = None,
                         last_error_at: Any = None,
                         skipped_settings: Sequence[Any] = ()) -> None:
    """Write the whole row of what `node` runs of `capability` for the project,
    as its supervisor sees it now; `checked_at` is the store's now. Text is
    kept to its last SERVICE_INSTANCE_TEXT_CHARS characters, and an empty
    string is written as nothing."""
    if state not in SERVICE_INSTANCE_STATES:
        raise StoreError("bad_state", f"service state {state!r} is not one of "
                         f"{', '.join(SERVICE_INSTANCE_STATES)}")

    def text(value: str | None) -> str | None:
        value = (value or "").strip()
        return value[-SERVICE_INSTANCE_TEXT_CHARS:] or None

    conn.execute(
        "INSERT INTO capabilities_service_instances AS i (project_id, capability, node,"
        " state, problem, problem_code, payload_sha256, pid, host, started_at,"
        " last_exit_code, last_error, last_error_at, skipped_settings)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)"
        " ON CONFLICT (project_id, capability, node) DO UPDATE SET"
        " state = EXCLUDED.state, problem = EXCLUDED.problem,"
        " problem_code = EXCLUDED.problem_code, payload_sha256 = EXCLUDED.payload_sha256,"
        " pid = EXCLUDED.pid, host = EXCLUDED.host, started_at = EXCLUDED.started_at,"
        " checked_at = now(), last_exit_code = EXCLUDED.last_exit_code,"
        " last_error = EXCLUDED.last_error, last_error_at = EXCLUDED.last_error_at,"
        " skipped_settings = EXCLUDED.skipped_settings",
        (project_id, capability, node, state, text(problem), text(problem_code),
         payload_sha256 or None, pid, text(host), started_at, last_exit_code,
         text(last_error), last_error_at, json.dumps(list(skipped_settings))))


def service_instance_drop(conn: Any, project_id: str, capability: str, node: str) -> bool:
    """Delete the row once `node` no longer supervises `capability` for the
    project; whether there was one."""
    return bool(conn.execute(
        "DELETE FROM capabilities_service_instances"
        " WHERE project_id = %s AND capability = %s AND node = %s",
        (project_id, capability, node)).rowcount)


NODE_STATE_COLUMNS = ("load_1", "load_5", "load_15", "cpu_count", "memory_used_bytes",
                      "memory_limit_bytes", "disk_used_bytes", "disk_total_bytes",
                      "booted_at", "boot_line", "image_version", "reported_at", "fresh_until")
NODE_LOGIN_COLUMNS = tuple(f"{tool}_{part}" for tool in NODE_STATE_TOOLS
                           for part in ("login", "account"))
NODE_LOGIN_NEED_COLUMNS = tuple(f"{tool}_needed" for tool in NODE_STATE_TOOLS)
NODE_SESSION_COLUMNS = ("node", "capability", "connection", "live", "account", "checked_at")
NODE_EXPECTATION_COLUMNS = ("expected", "updated_at", "updated_by")


def _node_text(value: Any) -> str | None:
    value = " ".join(str(value).split()) if value is not None else ""
    return value[:NODE_STATE_TEXT_CHARS] or None


def node_state_put(conn: Any, node: str, *, load: Sequence[float] | None = None,
                   cpu_count: int | None = None, memory_used_bytes: int | None = None,
                   memory_limit_bytes: int | None = None,
                   disk_used_bytes: int | None = None, disk_total_bytes: int | None = None,
                   booted_at: Any = None, boot_line: str | None = None,
                   image_version: str | None = None,
                   fresh_seconds: float = NODE_STATE_FRESH_SECONDS) -> dict[str, Any]:
    """Write the whole row of what `node` says of itself now; `reported_at` is
    the store's now and `fresh_until` that and `fresh_seconds`. Text is one
    line of at most NODE_STATE_TEXT_CHARS characters, and an empty string is
    written as nothing. Answers {reported_at, fresh_until}."""
    if not fresh_seconds > 0:
        raise StoreError("bad_state", "a node's state stands for a positive interval")
    loads = list(load) if load is not None else [None, None, None]
    if len(loads) != 3:
        raise StoreError("bad_state", "a node's load is three averages: 1, 5 and 15 minutes")
    values = [*loads, cpu_count, memory_used_bytes, memory_limit_bytes, disk_used_bytes,
              disk_total_bytes, booted_at, _node_text(boot_line), _node_text(image_version)]
    written = NODE_STATE_COLUMNS[:-2]
    row = conn.execute(
        f"INSERT INTO capabilities_node_states (node, {', '.join(written)}, reported_at,"
        " fresh_until) VALUES (%s, " + ", ".join(["%s"] * len(written))
        + ", now(), now() + make_interval(secs => %s))"
        " ON CONFLICT (node) DO UPDATE SET "
        + ", ".join(f"{column} = EXCLUDED.{column}"
                    for column in (*written, "reported_at", "fresh_until"))
        + " RETURNING reported_at, fresh_until",
        (node, *values, float(fresh_seconds))).fetchone()
    return {"reported_at": row[0], "fresh_until": row[1]}


def node_logins_put(conn: Any, project_id: str, node: str,
                    logins: dict[str, tuple[str, str | None]],
                    needed: Sequence[str] | None = None) -> None:
    """Write the project's whole row of whether its tools are signed in on
    `node`; `checked_at` is the store's now. `logins` maps each of
    NODE_STATE_TOOLS to (state, account), a tool it leaves out written as
    unknown; an account is kept only where its tool is signed in. `needed`
    names the tools the services the project places on `node` need signed
    in there; None leaves what the row says of that as it is, none on a new
    row."""
    logins = dict(logins or {})
    unknown = sorted((set(logins) | set(needed or ())) - set(NODE_STATE_TOOLS))
    if unknown:
        raise StoreError("bad_state", f"no sign-in is kept for {', '.join(unknown)}; "
                         f"the tools are {', '.join(NODE_STATE_TOOLS)}")
    values: list[Any] = []
    for tool in NODE_STATE_TOOLS:
        state, account = logins.get(tool) or ("unknown", None)
        if state not in NODE_LOGIN_STATES:
            raise StoreError("bad_state", f"{tool} login state {state!r} is not one of "
                             f"{', '.join(NODE_LOGIN_STATES)}")
        values += [state, _node_text(account) if state == "signed_in" else None]
    columns: tuple[str, ...] = NODE_LOGIN_COLUMNS
    if needed is not None:
        values += [tool in needed for tool in NODE_STATE_TOOLS]
        columns += NODE_LOGIN_NEED_COLUMNS
    conn.execute(
        "INSERT INTO capabilities_node_logins (project_id, node, "
        f"{', '.join(columns)}, checked_at) VALUES (%s, %s, " + ", ".join(["%s"] * len(columns))
        + ", now()) ON CONFLICT (project_id, node) DO UPDATE SET "
        + ", ".join(f"{column} = EXCLUDED.{column}" for column in (*columns, "checked_at")),
        (project_id, node, *values))


def node_sessions_put(conn: Any, project_id: str, node: str, capability: str,
                      sessions: Sequence[tuple[str, bool, str | None]]) -> None:
    """Replace the project's sessions of `capability` on `node` with
    `sessions`, each (connection, live, account); `checked_at` is the store's
    now. An empty set leaves the project no row for it there."""
    conn.execute("DELETE FROM capabilities_node_sessions"
                 " WHERE project_id = %s AND node = %s AND capability = %s",
                 (project_id, node, capability))
    for connection, live, account in sessions:
        conn.execute("INSERT INTO capabilities_node_sessions (project_id, node, capability,"
                     " connection, live, account) VALUES (%s, %s, %s, %s, %s, %s)",
                     (project_id, node, capability, connection, bool(live),
                      _node_text(account)))


def node_agents_prune(conn: Any, node: str, asked: Sequence[str],
                      kept: Sequence[tuple[str, str]]) -> int:
    """Delete on `node` the sessions of each project in `asked` whose
    (project, capability) is not in `kept` - a capability no longer installed
    or no longer device-bound - and the sessions and sign-ins of every project
    no longer linked to the node. A project linked to the node but not asked
    is another manager's on the same machine and keeps its rows. Answers how
    many rows went."""
    projects = [project for project, _capability in kept]
    capabilities = [capability for _project, capability in kept]
    unlinked = (" NOT EXISTS (SELECT 1 FROM capabilities_agent_nodes l"
                "  WHERE l.agent_id = t.project_id AND l.node = t.node)")
    gone = conn.execute(
        "DELETE FROM capabilities_node_sessions t WHERE t.node = %s AND ((t.project_id = ANY (%s)"
        " AND NOT EXISTS (SELECT 1 FROM unnest(%s::text[], %s::text[]) AS k (project_id,"
        " capability) WHERE k.project_id = t.project_id AND k.capability = t.capability))"
        " OR" + unlinked + ")",
        (node, list(asked), projects, capabilities)).rowcount
    return gone + conn.execute(
        "DELETE FROM capabilities_node_logins t WHERE t.node = %s AND" + unlinked,
        (node,)).rowcount


def node_states(conn: Any, nodes: Sequence[str]) -> list[dict[str, Any]]:
    """The state rows of `nodes`, by node, each with `reachable` - whether its
    fresh_until is still ahead of the store's now - and `uptime_seconds`, the
    store's now less booted_at. A node with no row is not answered."""
    found = conn.execute(
        f"SELECT node, {', '.join(NODE_STATE_COLUMNS)}, fresh_until > now(),"
        " extract(epoch FROM now() - booted_at) FROM capabilities_node_states"
        " WHERE node = ANY (%s) ORDER BY node", (list(nodes),)).fetchall()
    out = []
    for row in found:
        entry = dict(zip(("node", *NODE_STATE_COLUMNS), row[:-2], strict=True))
        uptime = row[-1]
        entry.update({"reachable": bool(row[-2]),
                      "uptime_seconds": int(uptime) if uptime is not None else None})
        out.append(entry)
    return out


def node_logins(conn: Any, project_id: str, nodes: Sequence[str]) -> list[dict[str, Any]]:
    """The project's sign-ins on `nodes`, by node: whether each of its tools is
    signed in there and as whom, whether its placed services need it, and
    when that was asked. A node with no row for the project is not answered."""
    columns = ("node", *NODE_LOGIN_COLUMNS, *NODE_LOGIN_NEED_COLUMNS, "checked_at")
    found = conn.execute(
        f"SELECT {', '.join(columns)} FROM capabilities_node_logins"
        " WHERE project_id = %s AND node = ANY (%s) ORDER BY node",
        (project_id, list(nodes))).fetchall()
    return [dict(zip(columns, row, strict=True)) for row in found]


def node_sessions(conn: Any, project_id: str, nodes: Sequence[str]) -> list[dict[str, Any]]:
    """The project's sessions on `nodes`, by node, capability and connection."""
    found = conn.execute(
        f"SELECT {', '.join(NODE_SESSION_COLUMNS)} FROM capabilities_node_sessions"
        " WHERE project_id = %s AND node = ANY (%s) ORDER BY node, capability, connection",
        (project_id, list(nodes))).fetchall()
    return [dict(zip(NODE_SESSION_COLUMNS, row, strict=True)) for row in found]


def node_expectation_set(conn: Any, project_id: str, node: str, *,
                         tool: str | None = None, capability: str | None = None,
                         connection: str | None = None, expected: bool | None,
                         by: str | None = None) -> dict[str, Any]:
    """Set the owner's word on whether the project's sign-in of `tool`, or the
    live session of `capability`'s `connection`, is expected on `node`: True
    on, False off, None to take it back so that what the placed services need
    decides again. Answers {before, after, changed}, each word True, False or
    None."""
    if (tool is None) == (capability is None) or (capability is None) != (connection is None):
        raise StoreError("bad_state", "an expectation names a tool, or a capability and"
                         " its connection")
    if tool is not None and tool not in NODE_STATE_TOOLS:
        raise StoreError("bad_state", f"no sign-in is kept for {tool}; the tools are"
                         f" {', '.join(NODE_STATE_TOOLS)}")
    if expected is not None and not isinstance(expected, bool):
        raise StoreError("bad_state", "an expectation is true, false or none")
    if tool is not None:
        table, keys, key_values = ("capabilities_node_login_expectations", ("tool",), (tool,))
    else:
        table, keys, key_values = ("capabilities_node_session_expectations",
                                   ("capability", "connection"), (capability, connection))
    where = " AND ".join(f"{column} = %s" for column in ("project_id", "node", *keys))
    params = (project_id, node, *key_values)
    row = conn.execute(f"SELECT expected FROM {table} WHERE {where} FOR UPDATE",
                       params).fetchone()
    before = row[0] if row else None
    if expected is None:
        if row:
            conn.execute(f"DELETE FROM {table} WHERE {where}", params)
    elif before != expected:
        conn.execute(
            f"INSERT INTO {table} (project_id, node, {', '.join(keys)}, expected, updated_by)"
            f" VALUES (%s, %s, {', '.join(['%s'] * len(keys))}, %s, %s)"
            f" ON CONFLICT (project_id, node, {', '.join(keys)}) DO UPDATE SET"
            " expected = EXCLUDED.expected, updated_at = now(),"
            " updated_by = EXCLUDED.updated_by",
            (*params, expected, _node_text(by)))
    return {"before": before, "after": expected, "changed": before != expected}


def node_expectations(conn: Any, project_id: str,
                      nodes: Sequence[str]) -> dict[str, list[dict[str, Any]]]:
    """The owner's words for the project on `nodes`: {sign_ins [{node, tool,
    expected, updated_at, updated_by}], sessions [{node, capability,
    connection, expected, updated_at, updated_by}]}."""
    out: dict[str, list[dict[str, Any]]] = {}
    for kind, table, keys in (("sign_ins", "capabilities_node_login_expectations", ("tool",)),
                              ("sessions", "capabilities_node_session_expectations",
                               ("capability", "connection"))):
        columns = ("node", *keys, *NODE_EXPECTATION_COLUMNS)
        found = conn.execute(
            f"SELECT {', '.join(columns)} FROM {table}"
            " WHERE project_id = %s AND node = ANY (%s)"
            f" ORDER BY node, {', '.join(keys)}", (project_id, list(nodes))).fetchall()
        out[kind] = [dict(zip(columns, row, strict=True)) for row in found]
    return out


def _refuse_record_write(capability: str, collection: str) -> None:
    """A project record is the human's or the manager's, so under the switch
    nothing writes one. Operational state (a capability's state directory and
    its tables in the database) is not a record and keeps working."""
    if read_only_switch():
        raise StoreError(
            "read_only_switch",
            f"writing {capability} {collection} records is refused: "
            f"{READ_ONLY_ENV} is set, so this process changes no project record",
            "Do not lift the switch yourself — ask the user; the change has to "
            f"run in a process without {READ_ONLY_ENV}.")


def _store_check(name: str, value: str, pattern: re.Pattern) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise StoreError("bad_name", f"{name} {value!r} must match {pattern.pattern}")
    return value


def _semantics(collection: str) -> str:
    spec = COLLECTIONS.get(collection)
    if not spec:
        raise StoreError("bad_collection", f"unknown collection {collection!r}",
                         f"known: {', '.join(sorted(COLLECTIONS))}")
    return spec["resolve"]


def _grant_decisions(cid: str, rows: Sequence[dict[str, Any]]) -> tuple[dict, dict]:
    """One grant assembled field by field, highest scope first.

    This is the line COLLECTIONS already draws between the two records. An
    identity is a fact about the world, so it is atomic: taken whole from
    one scope, never assembled out of two. A grant is a decision, and a
    decision a lower scope made about one field stands until some higher
    scope decides that same field — so a machine-wide `allow_write: false`
    survives a project that only says `enabled: true`, and write permission
    is never acquired by saying something else.

    Returns the decided fields and, per field, the scope that decided it."""
    decided: dict[str, Any] = {}
    decided_at: dict[str, str] = {}
    for row in rows:
        value = row["value"]
        if not isinstance(value, dict):
            raise StoreError("bad_grant",
                             f"grant {cid!r} must be a table, got {type(value).__name__}")
        unknown = set(value) - set(GRANT_FIELDS)
        if unknown:
            raise StoreError("bad_grant",
                             f"grant {cid!r} has unknown field(s): {', '.join(sorted(unknown))}",
                             f"known: {', '.join(GRANT_FIELDS)}")
        for field, decision in value.items():
            if field not in decided:
                decided[field] = decision
                decided_at[field] = row["scope"]
    return decided, decided_at


# --- records: the files a project keeps its configuration in ------------------
#
# Runtime state is not on this axis: runs, queues and cursors a capability's
# processes share live in its tables in the database. What this answers is
# where CONFIGURATION is read and written. A capability calls the verbs below
# and never a path, so the layout is described in one place.

DOCUMENT_LOCATIONS: tuple[tuple[str | None, str, str], ...] = (
    ("reference", "{cap}/reference", ".md"),
    ("context", "{cap}/service/context", ".md"),
    ("script", "automations/scripts", ".py"),
    (None, "{cap}/service", ".md"),
)


def _document_key(prefix: str | None, stem: str) -> str:
    """The key a file answers to. Underscores fold to hyphens and case is lost,
    so the map from file to key is one-way — which is why finding a document
    searches rather than computes."""
    slug = stem.replace("_", "-").lower()
    return f"{prefix}.{slug}" if prefix else slug


# --- references in the store -----------------------------------------------------
#
# A project's references may be rows of `capabilities_references` rather than
# files: one row per version, keyed by project, capability and name, the body
# every byte of the file. A reference with an active version is read from
# there before any file; where the store holds none, or no store answers, the
# files are read as they always were. The manager imports and exports them.

REFERENCE_DOCUMENT_PREFIX = "reference"
_REFERENCE_NAME_RE = re.compile(_REFERENCE_NAME)
_REFERENCE_COLUMNS = ("id, capability, name, body, active, created_at, created_by, note")


def reference_name_ok(name: str) -> bool:
    """Whether `name` (a file's name without `.md`) can be a stored reference."""
    return bool(_REFERENCE_NAME_RE.match(name)) and not name.lower().endswith(".md")


def reference_key(name: str) -> str:
    """The document key a reference of this name answers to."""
    return _document_key(REFERENCE_DOCUMENT_PREFIX, name)


def _reference_row(row: Sequence[Any]) -> dict[str, Any]:
    vid, capability, name, body, active, created_at, created_by, note = row
    return {"version": str(vid), "capability": capability, "name": name,
            "key": reference_key(name), "body": body, "active": bool(active),
            "hash": hashlib.sha256(body.encode()).hexdigest()[:HASH_LENGTH],
            "created_at": _stamp(created_at), "created_by": created_by, "note": note}


def stored_references(conn: Any, project_id: str,
                      capability: str | None = None) -> list[dict[str, Any]]:
    """The active version of each reference the store holds for the project,
    of one capability or of all, ordered by capability and name."""
    query = (f"SELECT {_REFERENCE_COLUMNS} FROM {STORE_REFERENCES_TABLE} "
             "WHERE project_id = %s AND active")
    params: list[Any] = [project_id]
    if capability is not None:
        query += " AND capability = %s"
        params.append(capability)
    rows = conn.execute(query + " ORDER BY capability, name", params).fetchall()
    return [_reference_row(row) for row in rows]


def reference_history(conn: Any, project_id: str, capability: str,
                      name: str) -> list[dict[str, Any]]:
    """Every version of one reference, newest first."""
    rows = conn.execute(
        f"SELECT {_REFERENCE_COLUMNS} FROM {STORE_REFERENCES_TABLE} "
        "WHERE project_id = %s AND capability = %s "
        "AND lower(replace(name, '_', '-')) = %s ORDER BY created_at DESC, id",
        (project_id, capability, reference_key(name)[len(REFERENCE_DOCUMENT_PREFIX) + 1:])
    ).fetchall()
    return [_reference_row(row) for row in rows]


def _reference_lock(conn: Any, project_id: str, capability: str, name: str) -> None:
    """One writer at a time per reference, so two saves from one base cannot
    both find it active."""
    conn.execute("SELECT pg_advisory_xact_lock(hashtext(concat_ws(chr(31), %s::text, "
                 "%s::text, %s::text, %s::text)))",
                 (STORE_REFERENCES_TABLE, project_id, capability, reference_key(name)))


def reference_save(conn: Any, project_id: str, capability: str, name: str, body: str,
                   author: str, *, base_version: str | None = None,
                   base_hash: str | None = None, note: str | None = None,
                   check_base: bool = True) -> dict[str, Any]:
    """Save `body` as the reference's new active version, inside the caller's
    transaction, clearing `active` on the version it replaces. A body equal to
    the active one adds nothing. `base_version` (a version id or a prefix of
    six or more characters) or `base_hash` names the version the edit was made
    from: the save is refused with `stale_base` when another is active now.
    Answers {version, changed, previous}."""
    if not reference_name_ok(name):
        raise StoreError("bad_reference_name",
                         f"{name!r} cannot name a reference",
                         "a name is letters, digits, '.', '_' and '-', starting with a "
                         "letter or digit, without .md")
    _reference_lock(conn, project_id, capability, name)
    history = reference_history(conn, project_id, capability, name)
    active = next((row for row in history if row["active"]), None)
    if check_base and (base_version is not None or base_hash is not None):
        if base_version is not None:
            wanted = base_version.strip().lower()
            matches = [row for row in history if row["version"].startswith(wanted)] \
                if len(wanted) >= 6 else []
            if len(matches) != 1:
                raise StoreError("unknown_base",
                                 f"{base_version!r} names no single version of "
                                 f"{capability}/{name}",
                                 f"`capabilities references history {capability} {name}` "
                                 "lists them")
            current = active is not None and matches[0]["version"] == active["version"]
        else:
            current = active is not None and active["hash"] == base_hash
        if not current:
            now = active["version"] if active else "none"
            raise StoreError("stale_base",
                             f"{capability}/{name} is at version {now} now, not the "
                             "base the edit was made from",
                             "read it again and apply the change to what is active")
    if active is not None and active["body"] == body and active["name"] == name:
        return {"version": active["version"], "changed": False,
                "previous": active["version"]}
    if active is not None:
        conn.execute(f"UPDATE {STORE_REFERENCES_TABLE} SET active = false WHERE id = %s",
                     (active["version"],))
    [(vid,)] = conn.execute(
        f"INSERT INTO {STORE_REFERENCES_TABLE} (project_id, capability, name, body, "
        "created_by, note) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
        (project_id, capability, name, body, author, note)).fetchall()
    return {"version": str(vid), "changed": True,
            "previous": active["version"] if active else None}


def reference_retire(conn: Any, project_id: str, capability: str, name: str) -> str | None:
    """Clear the reference's active version inside the caller's transaction,
    keeping every version. Answers the version retired, None where none was
    active."""
    _reference_lock(conn, project_id, capability, name)
    active = next((row for row in reference_history(conn, project_id, capability, name)
                   if row["active"]), None)
    if active is None:
        return None
    conn.execute(f"UPDATE {STORE_REFERENCES_TABLE} SET active = false WHERE id = %s",
                 (active["version"],))
    return active["version"]


class Records:
    """The surface a capability reads and writes its configuration through."""

    mode = "?"
    source = "?"

    def mode_of(self, collection: str, key: str | None = None) -> str:
        """Where one collection is kept: `files`, or `store` for what a
        project in store mode keeps there."""
        return self.mode

    def __enter__(self) -> "Records":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        pass

    def resolve_scope(self, capability: str, collection: str,
                      scope: str) -> dict[str, dict[str, Any]]:
        """Resolve exactly one scope, without inheritance."""
        raise NotImplementedError

    def grantees(self, capability: str, connection: str) -> list[str]:
        """Every project a grant enables this connection for, on any node.
        Only the store holds a connection more than one project is granted;
        files keep each project's grants in that project alone."""
        return []

    # Whether settings documents are rows of the store rather than files: true
    # only for an agent whose records moved into the store.
    settings_in_rows = False

    def settings_kept(self) -> str:
        """Where this adapter reads settings documents: `files` or `store`.
        Raises when it cannot tell."""
        return "store" if self.settings_in_rows else "files"

    def guard_write(self, capability: str, collection: str,
                    scope: str | None = None) -> None:
        """Refuse a write this process may not make now. A writer that does
        not go through `set`, such as the settings verb writing a file, asks
        here first."""
        _refuse_record_write(capability, collection)


# A policy record says which node its row names. Files carry no node, so every
# policy record read from them names none: it is the record for every node.
_FILE_NODE = {"policy": {"node": None}}


def _files_carry_no_node(node: Any) -> None:
    if node is not None:
        raise StoreError(
            "node_requires_store",
            "a policy row naming a node is kept only in the store: files carry no "
            "node, so a record written there is for every node",
            "import this project's records into its store with `capabilities "
            "connections import`, then write the row for the node")


class FileRecords(Records):
    """Configuration kept as the files the envelope has always held.

    The layout is not invented here — it is the one the capabilities already
    read, described in one place instead of re-derived at each call site. Two
    directories with that layout make the scope chain: the project's envelope,
    then the user's config home."""

    mode = "files"

    def __init__(self, envelope: Path, global_dir: Path,
                 project_id: str | None = None, project: str | None = None,
                 include_global: bool = True):
        self.envelope, self.global_dir = Path(envelope), Path(global_dir)
        self.project_id, self.project = project_id, project
        self.include_global = bool(include_global)
        self.source = str(self.envelope)
        # The agent whose registry row a project write is checked against, and
        # where its database resolves; set by `open_records` alone.
        self._guard_agent: str | None = None
        self._guard_root: Path | None = None
        self._guard_application = STORE_OWNER
        self.actor: str | None = None

    # Where the global layer's connections, grants, default pointer and policy
    # may be the store's rows for every agent: `(project_root,)`, the folder
    # its database resolves for (None outside any project), set by
    # `open_records` and `global_records` alone. An adapter made directly
    # reads the config home's files, as the manager's migration does.
    _global_from: tuple | None = None
    # What asking answered: None not yet, a GlobalRows where the store holds
    # the global rows, False where it does not or no database is configured,
    # or (when, StoreError) where a configured store did not answer.
    _global_state: Any = None

    def _global_rows(self, write: bool = False) -> "GlobalRows | None":
        """The store's rows for every agent where they are in force - a
        database resolves and `capabilities_global.global_migrated_at` is
        set - else None, and the config home's files are the global layer as
        before. A configured store that does not answer leaves a read on the
        files and refuses a write (`write`), which would otherwise land in a
        file the store's rows shadow once it answers again."""
        if self._global_from is None or not self.include_global:
            return None
        state = self._global_state
        if isinstance(state, tuple) and time.monotonic() - state[0] >= STORE_READ_SECONDS:
            state = None
        if state is None:
            rows = GlobalRows(self.global_dir, self._global_from[0], self._guard_application)
            try:
                state = rows if rows.in_force() else False
            except StoreError as exc:
                state = (time.monotonic(), exc)
            self._global_state = state
        if isinstance(state, tuple):
            if write:
                raise state[1]
            return None
        return state or None

    def global_kept(self) -> str:
        """Where this adapter keeps the global layer's connections, grants,
        default pointer and policy: `store` once the store's global rows are
        in force, else `files`. A configured store that does not answer
        raises StoreError, since a write could land in neither."""
        return "store" if self._global_rows(write=True) is not None else "files"

    def global_grantees(self, capability: str, connection: str) -> list[str]:
        """Every agent a grant enables a connection of the global layer for,
        where that layer is the store's rows; none where it is files."""
        rows = self._global_rows()
        return rows.grantees(capability, connection) if rows is not None else []

    def _agent_now(self) -> dict | None:
        """This project's registry row as the store holds it now, or None
        where no database answers or it holds none: a project whose records
        are files then writes them as it always has."""
        if not self._guard_agent:
            return None
        try:
            conn, _schema = _store_connect(self._guard_root or self.envelope.parent,
                                           self._guard_application, _PROBE_TIMEOUT)
        except StoreError:
            return None
        try:
            return _agent_state(conn, self._guard_agent)
        except Exception:
            return None
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def guard_write(self, capability: str, collection: str,
                    scope: str | None = None) -> None:
        """A project record is not written to files while its agent's records
        are moving into the store, nor once they moved."""
        _refuse_record_write(capability, collection)
        if (scope or "project") != "project":
            return
        _refuse_frozen(self._agent_now(), self._guard_agent, self.actor,
                       files=True)

    def setting_document(self, capability: str, scope: str) -> dict | None:
        """One scope's settings document as the adapter's setting collection
        keeps it, or None where there is none."""
        _store_check("capability", capability, CAPABILITY_RE)
        root, _pid = self._scope_root(scope)
        body = self._load(self._file(root, capability, "setting"))
        return body if isinstance(body, dict) else None

    # -- where a record lives --------------------------------------------------

    def _chain(self) -> list[tuple[str, str | None, Path]]:
        chain = [("project", self.project_id, self.envelope)]
        if self.include_global:
            chain.append(("global", None, self.global_dir))
        return chain

    @staticmethod
    def _load(path: Path) -> Any:
        try:
            return json.loads(path.read_text())
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            raise StoreError("bad_config", f"cannot read {path}: {exc}") from None

    @staticmethod
    def _save(path: Path, body: Any, sort: bool = False) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(body, indent=2, ensure_ascii=False,
                                   sort_keys=sort) + "\n")

    def _policy_file(self, root: Path) -> Path:
        """The gate. A project keeps it at the envelope root; the config home
        keeps it under the manager's own name, which is the same rule seen from
        outside -- there, `capabilities` is a capability like any other."""
        return (root / "settings.json" if root == self.envelope
                else root / "capabilities" / "settings.json")

    def _file(self, root: Path, capability: str, collection: str,
              key: str | None = None) -> Path:
        if collection == "policy":
            return self._policy_file(root)
        if collection == "identifier":
            return root / capability / "identifiers.json"
        if collection in ("connection", "grant"):
            return root / capability / "connections.json"
        if collection == "setting":
            if key == "connection.default":
                return root / capability / "connections.json"
            return root / capability / "service" / "settings.json"
        raise StoreError("bad_collection",
                         f"collection {collection!r} is not kept in files")

    # -- reading ---------------------------------------------------------------

    def _entries(self, root: Path, capability: str, collection: str) -> dict[str, Any]:
        """Every entry of one collection held at one scope, keyed by the name a
        record answers to. Where the store's global rows are in force, the
        global scope's connections, grants, default pointer and policy are
        theirs, and its files answer only for what the store holds no row of."""
        files = self._file_entries(root, capability, collection)
        if root != self.global_dir or collection not in GLOBAL_STORE_COLLECTIONS:
            return files
        rows = self._global_rows()
        return files if rows is None else rows.entries(capability, collection, files)

    def _file_entries(self, root: Path, capability: str, collection: str) -> dict[str, Any]:
        """Every entry of one collection one scope's files hold."""
        if collection == "policy":
            body = self._load(self._policy_file(root)) or {}
            return dict((body.get("capabilities") or {}))
        if collection == "identifier":
            body = self._load(root / capability / "identifiers.json") or {}
            raw = body.get("identifiers") if isinstance(body.get("identifiers"), dict) else body
            out = {}
            for label, entry in raw.items():
                out[label] = entry["value"] if isinstance(entry, dict) and "value" in entry else entry
            return out
        registry = self._load(root / capability / "connections.json") or {}
        if collection in ("connection", "grant"):
            declared = registry.get("connections")
            if not isinstance(declared, dict):
                return {}
            out = {}
            for cid, entry in declared.items():
                if not isinstance(entry, dict):
                    continue
                if collection == "connection":
                    out[cid] = {k: v for k, v in entry.items() if k not in GRANT_FIELDS}
                else:
                    grant = {k: entry[k] for k in GRANT_FIELDS if k in entry}
                    if grant:
                        out[cid] = grant
            return out
        if collection == "setting":
            out = {}
            if registry.get("default"):
                out["connection.default"] = registry["default"]
            service = self._load(root / capability / "service" / "settings.json")
            if isinstance(service, dict):
                out.update(service)
            return out
        raise StoreError("bad_collection", f"unknown collection {collection!r}",
                         f"known: {', '.join(sorted(COLLECTIONS))}")

    def _note(self, root: Path, capability: str, collection: str, key: str) -> str | None:
        if collection != "identifier":
            return None
        body = self._load(root / capability / "identifiers.json") or {}
        raw = body.get("identifiers") if isinstance(body.get("identifiers"), dict) else body
        entry = raw.get(key)
        return entry.get("note") if isinstance(entry, dict) else None

    def config_layers(self, capability: str, collection: str,
                      _scopes: Any = None) -> list[dict[str, dict[str, Any]]]:
        """Each scope's own entries, highest scope first, uncollapsed."""
        _store_check("capability", capability, CAPABILITY_RE)
        _semantics(collection)
        layers: list[dict[str, dict[str, Any]]] = []
        for scope, pid, root in self._chain():
            entries = self._entries(root, capability, collection)
            if not entries:
                continue
            layers.append({
                key: {"id": f"{scope}:{capability}/{collection}/{key}", "scope": scope,
                      "project_id": pid, "capability": capability,
                      "collection": collection, "key": key, "value": value,
                      "note": self._note(root, capability, collection, key),
                      "updated_at": None, "updated_by": None,
                      **_FILE_NODE.get(collection, {})}
                for key, value in entries.items()
            })
        return layers

    def resolve(self, capability: str, collection: str) -> dict[str, dict[str, Any]]:
        semantics = _semantics(collection)
        out: dict[str, dict[str, Any]] = {}
        for rows in self.config_layers(capability, collection):
            if semantics == FIRST:
                return rows
            for key, row in rows.items():
                prior = out.get(key)
                if prior is None:
                    out[key] = row
                elif (collection == "connection" and not prior["value"]
                        and row["value"]):
                    # One file holds both records here, so an entry carrying
                    # only grant fields yields an identity with no fields. That
                    # is a decision about an inherited connection, never a
                    # replacement for it: it must not blank the identity the
                    # lower scope declared. Where nothing is inherited the
                    # fieldless identity stands, which is the only reading a
                    # glued file leaves for it.
                    out[key] = row
        return out

    def _scope_root(self, scope: str) -> tuple[Path, str | None]:
        """The directory one named scope keeps its records in, and the project
        it answers for. Named once so asking a scope for its rows and asking it
        for its file can never land in different trees."""
        if scope == "project":
            return self.envelope, self.project_id
        if scope == "global":
            return self.global_dir, None
        raise StoreError("bad_scope",
                         f"scope {scope!r} must be one of {', '.join(SCOPE_KINDS)}")

    def resolve_scope(self, capability: str, collection: str,
                      scope: str) -> dict[str, dict[str, Any]]:
        _store_check("capability", capability, CAPABILITY_RE)
        root, pid = self._scope_root(scope)
        return {
            key: {"id": f"{scope}:{capability}/{collection}/{key}",
                  "scope": scope, "project_id": pid,
                  "capability": capability, "collection": collection,
                  "key": key, "value": value,
                  "note": self._note(root, capability, collection, key),
                  "updated_at": None, "updated_by": None,
                  **_FILE_NODE.get(collection, {})}
            for key, value in self._entries(root, capability, collection).items()
        }

    def get(self, capability: str, collection: str, key: str) -> Any:
        entry = self.resolve(capability, collection).get(key)
        return entry["value"] if entry else None

    def collection_source(self, capability: str, collection: str) -> str:
        """The file that answered, named exactly. A report that says only
        "files" makes the reader go and find out which one, and the scope a
        record resolved at is half of what they came to learn."""
        for scope, _pid, root in self._chain():
            if self._entries(root, capability, collection):
                return self.scope_source(capability, collection, scope)
        return str(self._file(self.envelope, capability, collection))

    def scope_source(self, capability: str, collection: str, scope: str) -> str:
        """The file one named scope keeps this collection in. What a record
        resolved *to* is a question about that record, so the caller that knows
        which scope answered asks here rather than for the collection's own
        file: one file per scope, and the chain is not walked again."""
        _store_check("capability", capability, CAPABILITY_RE)
        root, _pid = self._scope_root(scope)
        if scope == "global" and collection in GLOBAL_STORE_COLLECTIONS \
                and collection != "setting":
            rows = self._global_rows()
            if rows is not None:
                return rows.table_source(collection)
        return str(self._file(root, capability, collection))

    def record_source(self, capability: str, collection: str, scope: str,
                      key: str) -> str:
        """Where one record of one scope was read: as `scope_source`, except
        that a global connection a config-home file still answers for, the
        store holding no row of it, names that file."""
        source = self.scope_source(capability, collection, scope)
        if scope == "global" and collection == "connection" and source.startswith("store:"):
            rows = self._global_rows()
            if rows is not None and key not in rows._layer(capability)["connections"]:
                return str(self._file(self.global_dir, capability, collection))
        return source

    def connections(self, capability: str, write_default: bool = False,
                    include_disabled: bool = False,
                    machine_read: bool = False) -> dict[str, dict[str, Any]]:
        """Every connection this project may use, already carrying the decision
        made about it — the one read a capability needs before it acts.

        `machine_read` is the caller's word that this is one of the
        capability's declared machine reads outside any project: an identity
        the machine itself declares is then usable, read-only, unless its grant
        resolves to `enabled: false`."""
        identities = self.resolve(capability, "connection")
        layers = self.config_layers(capability, "grant")
        # Under the read-only switch every connection is a source, whatever its
        # grant or the capability's WRITE_DEFAULT says.
        writable = not read_only_switch()
        out: dict[str, dict[str, Any]] = {}
        for cid, entry in identities.items():
            rows = [layer[cid] for layer in layers if cid in layer]
            decided, decided_at = _grant_decisions(cid, rows)
            # Where the identity resolves decides whether it is this project's
            # to use at all. A project that declares an identity locally has
            # already said yes by declaring it; an identity inherited from the
            # global scope is withheld until a grant *resolving at project
            # scope* says `enabled: true`. A global `enabled: true` can never be
            # the blessing — one global line would otherwise hand every project
            # on the machine the same connection back.
            declared = decided.get("enabled")
            identity_is_project = entry["scope"] == "project"
            blessed_here = decided_at.get("enabled") == "project"
            if declared is None:
                enabled = identity_is_project
            else:
                enabled = bool(declared) and (identity_is_project or blessed_here)
            # A machine read lends the machine's own connection and nothing
            # more: never a write, and never one a grant switched off.
            lent = (machine_read and not enabled and entry["scope"] == "global"
                    and (declared is None or bool(declared)))
            if lent:
                enabled = True
            if not enabled and not include_disabled:
                continue
            grant = rows[0] if rows else None
            out[cid] = {
                "id": cid,
                "value": entry["value"],
                "scope": (entry["scope"], entry["project_id"]),
                "enabled": enabled,
                "allow_write": (writable and not lent
                                and bool(decided.get("allow_write", write_default))),
                "grant_scope": (grant["scope"], grant["project_id"]) if grant else None,
            }
            if lent:
                out[cid]["machine_read"] = True
        return out

    # -- writing ---------------------------------------------------------------

    def set(self, capability: str, collection: str, key: str, value: Any,
            actor: str | None = None, note: str | None = None,
            scope: str | None = None, node: str | None = None) -> None:
        _store_check("capability", capability, CAPABILITY_RE)
        _store_check("key", key, KEY_RE)
        _semantics(collection)
        _files_carry_no_node(node)
        target_scope = scope or "project"
        if target_scope not in SCOPE_KINDS:
            _refuse_record_write(capability, collection)
            raise StoreError("bad_scope",
                             f"scope {target_scope!r} must be one of {', '.join(SCOPE_KINDS)}")
        self.guard_write(capability, collection, target_scope)
        rows = self._store_kept(collection, key, target_scope)
        if rows is not None:
            return rows.set(capability, collection, key, value)
        root = self.envelope if target_scope == "project" else self.global_dir
        if target_scope == "project" and not self.envelope.is_dir():
            raise StoreError("no_envelope", "no capabilities/ envelope in this project",
                             "run `capabilities init` first")
        path = self._file(root, capability, collection, key)
        body = self._load(path)
        body = body if isinstance(body, dict) else {}
        if collection == "policy":
            body.setdefault("capabilities", {})[key] = value
        elif collection == "identifier":
            # Flat at the top level, which is the shape the envelope has always
            # had and the shape `audit` holds this to. A file already carrying
            # the wrapper keeps it: reshaping someone's file on an unrelated
            # write is not this writer's business.
            holder = (body["identifiers"] if isinstance(body.get("identifiers"), dict)
                      else body)
            holder[key] = {"value": value, "note": note or ""}
        elif collection in ("connection", "grant"):
            entry = body.setdefault("connections", {}).setdefault(key, {})
            if collection == "connection":
                for field in list(entry):
                    if field not in GRANT_FIELDS:
                        entry.pop(field)
                entry.update(value if isinstance(value, dict) else {})
            else:
                entry.update({k: v for k, v in (value or {}).items() if k in GRANT_FIELDS})
        elif key == "connection.default":
            body["default"] = value
        else:
            body[key] = value
        self._save(path, body, sort=collection == "identifier")

    def delete(self, capability: str, collection: str, key: str,
               scope: str | None = None, node: str | None = None) -> bool:
        _files_carry_no_node(node)
        target_scope = scope or "project"
        if target_scope not in SCOPE_KINDS:
            _refuse_record_write(capability, collection)
            raise StoreError("bad_scope",
                             f"scope {target_scope!r} must be one of {', '.join(SCOPE_KINDS)}")
        self.guard_write(capability, collection, target_scope)
        rows = self._store_kept(collection, key, target_scope)
        if rows is not None:
            # The row goes, and so does a legacy file's entry of the same name,
            # which would otherwise answer again where the store holds none.
            gone = rows.delete(capability, collection, key)
            return self._file_delete(self.global_dir, capability, collection, key) or gone
        root = self.envelope if target_scope == "project" else self.global_dir
        return self._file_delete(root, capability, collection, key)

    def _store_kept(self, collection: str, key: str | None,
                    scope: str) -> "GlobalRows | None":
        """Where a write lands once the store's global rows are in force: the
        store's rows for a global connection, grant, default pointer or
        policy; a refusal for a connection, grant or default pointer of a
        project that keeps its records in files, since no connection is
        written to a file any more; None where the files take it as before."""
        if collection not in GLOBAL_STORE_COLLECTIONS or (
                collection == "setting" and key != "connection.default"):
            return None
        if scope == "project" and collection == "policy":
            return None
        rows = self._global_rows(write=True)
        if rows is None or scope == "global":
            return rows
        raise StoreError(
            "connections_in_store",
            "this project keeps its records in files, and the store this machine "
            "reads holds the connections every agent uses: a connection, its grant "
            "and the default pointer are no longer written to a file",
            "move this project's records into the store with `capabilities migrate`, "
            "then write it again")

    def _file_delete(self, root: Path, capability: str, collection: str,
                     key: str) -> bool:
        path = self._file(root, capability, collection, key)
        body = self._load(path)
        if not isinstance(body, dict):
            return False
        if collection == "policy":
            gone = (body.get("capabilities") or {}).pop(key, None) is not None
        elif collection == "identifier":
            holder = body.get("identifiers") if isinstance(body.get("identifiers"), dict) else body
            gone = holder.pop(key, None) is not None
        elif collection in ("connection", "grant"):
            entry = (body.get("connections") or {}).get(key)
            if not isinstance(entry, dict):
                return False
            if collection == "connection":
                gone = body["connections"].pop(key, None) is not None
            else:
                gone = any(entry.pop(field, None) is not None for field in GRANT_FIELDS)
        elif key == "connection.default":
            gone = body.pop("default", None) is not None
        else:
            gone = body.pop(key, None) is not None
        if gone:
            self._save(path, body, sort=collection == "identifier")
        return gone

    # -- documents -------------------------------------------------------------

    def _documents(self, root: Path, capability: str) -> dict[str, Path]:
        """Every long-text file this scope holds, by the key it answers to. The
        map is built by walking rather than by computing a path from a key,
        because the key loses case and underscores on the way in."""
        found: dict[str, Path] = {}
        for prefix, shape, suffix in DOCUMENT_LOCATIONS:
            if prefix == "script" and capability != "automations":
                continue
            folder = root / shape.format(cap=capability)
            if not folder.is_dir():
                continue
            for path in sorted(folder.glob(f"*{suffix}")):
                if path.is_file():
                    found.setdefault(_document_key(prefix, path.stem), path)
        return found

    # -- references the store holds ------------------------------------------

    # What the last read of the store's references answered, when, and why no
    # store answered it: set by `open_records` where its own probe failed, so
    # a store that is away costs one wait per process, not one per question.
    _references: dict[tuple[str, str], dict[str, Any]] | None = None
    _references_at = 0.0
    _references_failure: StoreError | None = None

    def _stored_references(self) -> dict[tuple[str, str], dict[str, Any]]:
        """(capability, key) -> the active version of each reference the store
        holds for this project. Empty where the project has no id, no store is
        configured, the store does not answer, or it holds none: its files are
        then read as they always were."""
        if self._references is not None and (
                self._references_failure is not None
                or time.monotonic() - self._references_at < STORE_READ_SECONDS):
            return self._references
        found: dict[tuple[str, str], dict[str, Any]] = {}
        failure: StoreError | None = None
        if self._guard_agent:
            try:
                conn, _schema = _store_connect(self._guard_root or self.envelope.parent,
                                               self._guard_application, _PROBE_TIMEOUT)
            except StoreError as exc:
                if exc.slug != "store_not_configured":
                    failure = exc
            else:
                import psycopg
                try:
                    for row in stored_references(conn, self._guard_agent):
                        found.setdefault((row["capability"], row["key"]), row)
                except psycopg.errors.UndefinedTable:
                    pass
                except psycopg.Error as exc:
                    failure = StoreError("store_unreachable",
                                         f"cannot read the stored references: {exc}",
                                         "check the database setting with "
                                         "`capabilities store doctor`")
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass
        self._references, self._references_failure = found, failure
        self._references_at = time.monotonic()
        return found

    def _stored_reference(self, capability: str, key: str) -> dict[str, Any] | None:
        if not key.startswith(REFERENCE_DOCUMENT_PREFIX + "."):
            return None
        return self._stored_references().get((capability, key))

    def document_path(self, capability: str, key: str) -> Path | None:
        """The file this key names. It is the truth here, not a copy of it, so
        an edit to what this returns is the edit — which is why `put` validates
        rather than transports. A reference the store holds has no file."""
        if self._stored_reference(capability, key) is not None:
            return None
        for _scope, _pid, root in self._chain():
            path = self._documents(root, capability).get(key)
            if path:
                return path
        return None

    def document_read(self, capability: str, key: str) -> dict[str, Any] | None:
        stored = self._stored_reference(capability, key)
        if stored is not None:
            return {"id": stored["version"], "key": key, "hash": stored["hash"],
                    "body": stored["body"], "media_type": "text/markdown",
                    "author": stored["created_by"], "created_at": stored["created_at"],
                    "scope": ("project", self._guard_agent), "path": None,
                    "version": stored["version"]}
        for scope, pid, root in self._chain():
            path = self._documents(root, capability).get(key)
            if not path:
                continue
            body = path.read_text()
            return {"id": str(path), "key": key,
                    "hash": hashlib.sha256(body.encode()).hexdigest()[:HASH_LENGTH],
                    "body": body, "media_type": None, "author": None,
                    "created_at": None, "scope": (scope, pid), "path": str(path)}
        return None

    def document_keys(self, capability: str) -> list[str]:
        keys: set[str] = set()
        for _scope, _pid, root in self._chain():
            keys.update(self._documents(root, capability))
        keys.update(key for cap, key in self._stored_references() if cap == capability)
        return sorted(keys)

    def document_put(self, capability: str, key: str, body: str,
                     author: str | None = None, media_type: str | None = None,
                     base: str | None = None) -> str:
        self.guard_write(capability, "document")
        if key.startswith(REFERENCE_DOCUMENT_PREFIX + "."):
            stored = self._stored_reference(capability, key)
            if stored is not None:
                return self._put_stored_reference(capability, stored, body, base)
        path = self._documents(self.envelope, capability).get(key)
        if path is None:
            path = self._new_document_path(capability, key)
        if base is not None and path.is_file():
            current = path.read_text()
            live = hashlib.sha256(current.encode()).hexdigest()[:HASH_LENGTH]
            # In files mode `context edit` deliberately hands out the truth,
            # not a copy. By put-time the live hash is therefore expected to
            # differ from the checkout hash; equality of the submitted body and
            # the file proves the edit landed at the path the adapter named.
            if live != base and current != body:
                raise StoreError(
                    "stale_edit",
                    f"{path} is {live} now, not {base} as it was when the edit began",
                    "re-read it and apply the change again")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
        return hashlib.sha256(body.encode()).hexdigest()[:HASH_LENGTH]

    def _put_stored_reference(self, capability: str, stored: dict[str, Any],
                              body: str, base: str | None) -> str:
        """A new version of a reference the store holds, refused where another
        became active after the edit began."""
        conn, _schema = _store_connect(self._guard_root or self.envelope.parent,
                                       self._guard_application)
        import psycopg
        try:
            with conn.transaction():
                reference_save(conn, self._guard_agent, capability, stored["name"], body,
                               f"{_user_name()}@{node_name()}", base_hash=base)
        except psycopg.Error as exc:
            raise StoreError("store_unreachable", f"cannot save the reference: {exc}",
                             "check the database setting with `capabilities store doctor`"
                             ) from None
        finally:
            try:
                conn.close()
            except Exception:
                pass
        self._references = None
        return hashlib.sha256(body.encode()).hexdigest()[:HASH_LENGTH]

    def _new_document_path(self, capability: str, key: str) -> Path:
        """Where a document this project does not have yet would go. The prefix
        chooses the folder; what follows it is the file."""
        for prefix, shape, suffix in DOCUMENT_LOCATIONS:
            if prefix and key.startswith(prefix + "."):
                return self.envelope / shape.format(cap=capability) / (key[len(prefix) + 1:] + suffix)
        prefix, shape, suffix = DOCUMENT_LOCATIONS[-1]
        return self.envelope / shape.format(cap=capability) / (key + suffix)

    # -- what a directory cannot answer ---------------------------------------

    def _refuse(self, what: str) -> None:
        raise StoreError("files_mode", f"{what} is not kept: records are files",
                         "their history is the repository's; read it with git")

    def revisions(self, *_a: Any, **_k: Any) -> list:
        self._refuse("a record's history")
        return []

    def document_versions(self, capability: str | None = None, key: str | None = None,
                          *_a: Any, **_k: Any) -> list:
        stored = (self._stored_reference(capability, key)
                  if capability is not None and key is not None else None)
        if stored is not None:
            conn, _schema = _store_connect(self._guard_root or self.envelope.parent,
                                           self._guard_application)
            try:
                return reference_history(conn, self._guard_agent, capability,
                                         stored["name"])
            finally:
                conn.close()
        self._refuse("a document's earlier versions")
        return []


class StoreRecords(FileRecords):
    """A project in store mode: its connections, its grants, its default
    pointer, its identifiers and its policy are read from and written to the
    contract's tables in the project's store, and every other record stays in
    the files `FileRecords` reads. A project that moved only its connections
    and grants (`held="connections"`) keeps its identifiers and policy in
    files. The two homes never compose: what the store holds is not read from
    the files at all.

    A connection row belongs to no project, so it resolves as an identity the
    project did not declare itself would: withheld until this project's grant
    enables it. This project's grants are the rows whose `agent_id` is its id,
    the row naming this node read before the row for every node, field by
    field. A row never holds a secret value: `spec` names each secret by its
    `*_env` key, which resolves on each node through that node's own cascade.

    An identifier or a policy row whose `agent_id` is null is global: it
    applies to every project reading this store, beneath the project's own
    row. Identifiers resolve label by label, the project's row over the global
    one. Policy resolves per capability, from the first of: the project's row
    for this node, its row for every node, the global row for this node, the
    global row for every node; none is default deny. A policy record carries
    `node`, the node the row that answered names (None for every node), and
    `set`/`delete` of a policy row take `node` to write or remove the row for
    one node.

    The store is reached through the shared database library, on first use
    only, so a call that reads nothing the store holds never connects, and
    each read or write borrows the process's working connection while it
    runs and gives it back after. A connection handed in belongs to the
    caller and stays open."""

    def __init__(self, envelope: Path, global_dir: Path,
                 project_id: str | None = None, project: str | None = None,
                 include_global: bool = True, project_root: Path | None = None,
                 application_name: str = STORE_OWNER, connection: Any = None,
                 schema: str | None = None, held: str = RECORDS_MODE_KEY):
        super().__init__(envelope, global_dir, project_id, project, include_global)
        if held not in STORE_COLLECTIONS:
            raise StoreError("bad_records_mode",
                             f"a store holds {', '.join(sorted(STORE_COLLECTIONS))}, "
                             f"not {held!r}")
        self.held = held
        self.collections = STORE_COLLECTIONS[held]
        self.project_root = (Path(project_root) if project_root is not None
                             else self.envelope.parent)
        self.application_name = application_name
        # The node is resolved where a read or write first needs it, so an
        # adapter that never names a node - the global rows a files-mode
        # project reads - resolves, and mints, no node id.
        self._node: str | None = None
        self._conn = connection
        self._owns_conn = connection is None
        # How many operations are running on the owned connection: it is closed
        # when the last of them ends.
        self._depth = 0
        self._schema = schema
        self._failure: StoreError | None = None
        self._failed_at = 0.0
        self._cache: dict[tuple[str, str], tuple[float, Any]] = {}
        # Why this adapter could not ask the store whether the agent's records
        # moved into it. Its settings are then not read from files, which
        # would be stale for an agent that did.
        self._settings_blocked: StoreError | None = None

    @property
    def node(self) -> str:
        """The node this adapter's rows are read and written for."""
        if self._node is None:
            self._node = node_name()
        return self._node

    @node.setter
    def node(self, value: str) -> None:
        self._node = value

    def settings_kept(self) -> str:
        if self._settings_blocked is not None:
            raise self._settings_blocked
        return super().settings_kept()

    def setting_document(self, capability: str, scope: str) -> dict | None:
        if self._settings_blocked is not None:
            raise self._settings_blocked
        return super().setting_document(capability, scope)

    def _agent_now(self) -> dict | None:
        # A connection handed in carries its caller's own transaction, which
        # the manager holds for a write of its own.
        if not self._guard_agent or not self._owns_conn:
            return None
        try:
            conn = self._begin()
        except StoreError:
            return None
        import psycopg
        try:
            return _agent_state(conn, self._guard_agent)
        except psycopg.OperationalError as exc:
            raise self._unreachable(exc) from None
        finally:
            if self._conn is not None and self._depth == 1:
                try:
                    self._conn.rollback()
                except Exception:
                    pass
            self._end()

    def _held(self, collection: str, key: str | None = None) -> bool:
        return (collection in self.collections
                or (collection == "setting" and key == "connection.default"))

    def mode_of(self, collection: str, key: str | None = None) -> str:
        return "store" if self._held(collection, key) else "files"

    def close(self) -> None:
        if self._owns_conn and self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    # -- reaching the store ----------------------------------------------------

    def _fail(self, error: StoreError) -> StoreError:
        self._failure, self._failed_at = error, time.monotonic()
        return error

    def _unreachable(self, exc: Exception) -> StoreError:
        """A connection that broke is dropped, so the next use opens a new one."""
        if self._owns_conn and self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
        return self._fail(StoreError(
            "store_unreachable", f"cannot reach the store: {exc}",
            "check the database setting with `capabilities store doctor`"))

    def _fresh(self, key: tuple[str, str]) -> Any:
        held = self._cache.get(key)
        if held is not None and time.monotonic() - held[0] < STORE_READ_SECONDS:
            return held[1]
        return None

    def _begin(self) -> Any:
        """The connection for one operation, borrowed for it unless one is
        running; `_end` gives it back once the last operation on it ends."""
        self._depth += 1
        try:
            return self._db()
        except BaseException:
            self._end()
            raise

    def _end(self) -> None:
        self._depth = max(0, self._depth - 1)
        if self._depth == 0 and not _HOLD_RECORDS_CONNECTION:
            self.close()

    def _db(self) -> Any:
        """The connection, opened on first use. A refusal to connect stands for
        STORE_READ_SECONDS, so one command does not wait on it twice."""
        if self._failure is not None:
            if time.monotonic() - self._failed_at < STORE_READ_SECONDS:
                raise self._failure
            self._failure = None
        if self._conn is not None:
            return self._conn
        try:
            from capabilities_contract import db
        except ImportError:
            raise self._fail(StoreError(
                "driver_missing",
                "the shared database library capabilities-contract is not installed",
                "run the capability through its own script header, which pins it")) from None
        try:
            setting = db.resolve_setting(self.project_root)
            self._conn = db.connect(application_name=self.application_name,
                                    setting=setting, transaction=True)
        except db.DbError as exc:
            raise self._fail(StoreError(exc.slug, exc.message, exc.hint)) from None
        self._schema = setting.schema
        return self._conn

    def _read(self, query: str, params: Sequence[Any]) -> list[tuple]:
        conn = self._begin()
        try:
            return self._read_on(conn, query, params)
        finally:
            self._end()

    def _read_on(self, conn: Any, query: str, params: Sequence[Any]) -> list[tuple]:
        import psycopg
        try:
            rows = conn.execute(query, params).fetchall()
        except psycopg.errors.UndefinedTable:
            # A store nothing was ever imported into holds no connection.
            if self._owns_conn:
                conn.rollback()
            return []
        except psycopg.OperationalError as exc:
            raise self._unreachable(exc) from None
        except psycopg.Error as exc:
            if self._owns_conn:
                conn.rollback()
            raise StoreError("store_read_failed",
                             f"reading records from the store failed: {exc}") from None
        if self._owns_conn:
            conn.rollback()
        return rows

    def _read_many(self, statements: Sequence[tuple[str, Sequence[Any]]]) -> list[list]:
        """The rows of each of `statements`, independent reads, as `_read` gives
        them, sent to the store together on one connection. A table that is
        not there is read as `_read` reads it, one statement at a time."""
        import psycopg
        conn = self._begin()
        try:
            if not self._owns_conn:
                # A caller's transaction: read as `_read` reads in it.
                return [self._read_on(conn, query, params) for query, params in statements]
            try:
                found = _read_together(conn, statements)
            except psycopg.errors.UndefinedTable:
                conn.rollback()
                return [self._read_on(conn, query, params) for query, params in statements]
            except psycopg.OperationalError as exc:
                raise self._unreachable(exc) from None
            except psycopg.Error as exc:
                conn.rollback()
                raise StoreError("store_read_failed",
                                 f"reading records from the store failed: {exc}") from None
            conn.rollback()
            return found
        finally:
            self._end()

    def _write(self, work: Any) -> Any:
        """Run `work(conn)` in one transaction, the tables migrated first. A
        connection handed in belongs to a caller holding its own transaction,
        which this neither migrates nor commits. A write whose connection was
        lost before its commit was sent runs once more on a new one; one lost
        while committing is never written again."""
        conn = self._begin()
        import psycopg
        from capabilities_contract import db
        try:
            try:
                if not self._owns_conn:
                    return work(conn)
                major, minor = STORE_TABLES_VERSION
                for attempt in (0, 1):
                    committing = False
                    try:
                        db.migrate(conn, STORE_OWNER, record_table_steps(),
                                   major=major, minor=minor)
                        with conn.transaction():
                            done = work(conn)
                            committing = True
                        return done
                    except psycopg.OperationalError:
                        if attempt or committing or self._depth != 1 \
                                or not getattr(conn, "broken", False):
                            raise
                    self.close()
                    conn = self._db()
            except db.DbError as exc:
                raise StoreError(exc.slug, exc.message, exc.hint) from None
            except psycopg.OperationalError as exc:
                raise self._unreachable(exc) from None
            except psycopg.Error as exc:
                raise StoreError("store_write_failed",
                                 f"writing records to the store failed: {exc}") from None
        finally:
            self._cache.clear()
            self._end()

    def _table_source(self, collection: str) -> str:
        if self._schema is None:
            self._begin()
            self._end()
        return f"store:{self._schema}.{STORE_TABLES.get(collection, STORE_CONNECTIONS_TABLE)}"

    # -- reading ---------------------------------------------------------------

    def vault_reader(self) -> Any:
        """This agent's vault as this process reads it, or None where the
        agent has no key here. A key that is not one is left to the cascade,
        which names it where a value is resolved."""
        if not self.project_id:
            return None
        try:
            from capabilities_contract import vault
            return vault.reader(self.project_root, self.project_id,
                                application_name=self.application_name)
        except Exception:
            return None

    def _connection_rows(self, capability: str) -> dict[str, dict[str, Any]]:
        key = ("connection", capability)
        held = self._fresh(key)
        if held is None:
            statements: list[tuple[str, Sequence[Any]]] = [(
                "SELECT name, spec FROM capabilities_connections "
                "WHERE capability = %s ORDER BY name", (capability,))]
            # The agent's sealed secrets ride in the same round trip, so the
            # cascade's last tier asks the store nothing more.
            reader = self.vault_reader()
            if reader is not None and not reader.loaded:
                from capabilities_contract import vault
                statements += vault.round_trip(self.project_id)
            found = self._read_many(statements)
            rows = found[0]
            if len(found) == 3:
                reader.seed(found[1], found[2])
            held = {name: spec if isinstance(spec, dict) else {} for name, spec in rows}
            self._cache[key] = (time.monotonic(), held)
        return held

    def _grant_rows(self, capability: str) -> dict[str, list[dict[str, Any]]]:
        """This project's grants on this node, per connection: the row naming
        this node first, then the row for every node."""
        key = ("grant", capability)
        held = self._fresh(key)
        if held is None:
            out: dict[str, list[dict[str, Any]]] = {}
            if self.project_id:
                rows = self._read(
                    "SELECT connection, node, enabled, allow_write, is_default "
                    "FROM capabilities_connection_grants "
                    "WHERE agent_id = %s AND capability = %s "
                    "AND (node IS NULL OR node = %s) "
                    "ORDER BY connection, node NULLS LAST",
                    (self.project_id, capability, self.node))
                for cid, node, enabled, allow_write, is_default in rows:
                    out.setdefault(cid, []).append({
                        "node": node, "enabled": enabled,
                        "allow_write": allow_write, "is_default": bool(is_default)})
            self._cache[key] = (time.monotonic(), out)
            held = out
        return held

    def connection_owner(self, capability: str, connection: str) -> str | None:
        """The agent whose own connection this is; None for a shared one."""
        _store_check("capability", capability, CAPABILITY_RE)
        rows = self._read(
            "SELECT owner FROM capabilities_connections WHERE capability = %s "
            "AND name = %s", (capability, connection))
        return rows[0][0] if rows else None

    def grantees(self, capability: str, connection: str) -> list[str]:
        _store_check("capability", capability, CAPABILITY_RE)
        if "grant" not in self.collections:
            return []
        rows = self._read(
            "SELECT DISTINCT agent_id FROM capabilities_connection_grants "
            "WHERE capability = %s AND connection = %s AND enabled "
            "AND agent_id IS NOT NULL ORDER BY agent_id", (capability, connection))
        return [agent for (agent,) in rows]

    def _store_default(self, capability: str) -> str | None:
        """The default pointer: this node's, else the one for every node."""
        grants = self._grant_rows(capability)
        for node in (self.node, None):
            for cid in sorted(grants):
                if any(r["is_default"] and r["node"] == node for r in grants[cid]):
                    return cid
        return None

    def _identifier_rows(self, capability: str) -> dict[str, dict[str, tuple]]:
        """This capability's identifiers in the store, per scope: this
        project's rows and the global ones, each label to its value, note and
        time of writing."""
        key = ("identifier", capability)
        held = self._fresh(key)
        if held is None:
            held = {"project": {}, "global": {}}
            # A row for one node is an agent's whose records moved into the
            # store; this project reads the rows for every node. The node is
            # read through the row's JSON, so a store whose identifiers carry
            # no node yet is read the same way.
            rows = self._read(
                "SELECT agent_id, label, value, note, updated_at, "
                "to_jsonb(i) ->> 'node' "
                "FROM capabilities_identifiers i "
                "WHERE capability = %s AND (agent_id IS NULL OR agent_id = %s) "
                "ORDER BY label", (capability, self.project_id))
            for agent_id, label, value, note, updated_at, node in rows:
                if node is not None:
                    continue
                scope = "global" if agent_id is None else "project"
                held[scope][label] = (value, note or "", _stamp(updated_at))
            self._cache[key] = (time.monotonic(), held)
        return held

    def _policy_rows(self) -> list[tuple[str, str | None, dict[str, tuple]]]:
        """The policy rows that apply to this project on this node, as the
        layers they resolve in, highest first: (scope, node, rows by name)."""
        key = ("policy", "")
        held = self._fresh(key)
        if held is None:
            found: dict[tuple[str, str | None], dict[str, tuple]] = {}
            rows = self._read(
                "SELECT agent_id, capability, node, enabled, updated_at, service "
                "FROM capabilities_policy "
                "WHERE (agent_id IS NULL OR agent_id = %s) "
                "AND (node IS NULL OR node = %s) ORDER BY capability",
                (self.project_id, self.node))
            for agent_id, name, node, enabled, updated_at, service in rows:
                scope = "global" if agent_id is None else "project"
                found.setdefault((scope, node), {})[name] = (
                    {"enabled": bool(enabled)}, _stamp(updated_at), bool(service))
            held = [(scope, node, found.get((scope, node), {}))
                    for scope in ("project", "global") for node in (self.node, None)]
            self._cache[key] = (time.monotonic(), held)
        return held

    def _record(self, scope: str, capability: str, collection: str, key: str,
                value: Any, ref: str, note: str | None = None,
                updated_at: str | None = None, node: str | None = None,
                service: bool | None = None) -> dict[str, Any]:
        record = {"id": f"store:{capability}/{collection}/{ref}", "scope": scope,
                  "project_id": self.project_id if scope == "project" else None,
                  "capability": capability, "collection": collection, "key": key,
                  "value": value, "note": note, "updated_at": updated_at,
                  "updated_by": None}
        if collection == "policy":
            # Which node the row that answered names: this node's name, or None
            # for the row for every node; and whether it places the service.
            record["node"] = node
            if service is not None:
                record["service"] = service
        return record

    def _scope_layers(self, capability: str, collection: str,
                      scope: str) -> list[dict[str, dict[str, Any]]]:
        """One scope's identifier or policy layers in the store, highest first:
        for policy, the row for this node before the row for every node."""
        if collection == "identifier":
            rows = self._identifier_rows(capability)[scope]
            return [{label: self._record(scope, capability, collection, label, value,
                                         f"{scope}/{label}", note=note,
                                         updated_at=updated_at)
                     for label, (value, note, updated_at) in rows.items()}]
        return [{name: self._record(scope, capability, collection, name, value,
                                    f"{scope}/{name}@{node or '*'}",
                                    updated_at=updated_at, node=node, service=service)
                 for name, (value, updated_at, service) in rows.items()}
                for at, node, rows in self._policy_rows() if at == scope]

    def _entries(self, root: Path, capability: str, collection: str) -> dict[str, Any]:
        if collection in self.collections:
            # What the global scope holds of a connection is a row of the
            # store's once the global rows are in force, never a file.
            rows = (self._global_rows() if root == self.global_dir
                    and collection in ("connection", "grant") else None)
            return {} if rows is None else rows.entries(capability, collection, {})
        if collection == "setting" and self._settings_blocked is not None:
            raise self._settings_blocked
        entries = super()._entries(root, capability, collection)
        if collection == "setting":
            entries.pop("connection.default", None)
        return entries

    def config_layers(self, capability: str, collection: str,
                      _scopes: Any = None) -> list[dict[str, dict[str, Any]]]:
        _store_check("capability", capability, CAPABILITY_RE)
        if collection == "connection":
            rows = self._connection_rows(capability)
            return [{name: self._record("store", capability, collection, name, spec, name)
                     for name, spec in rows.items()}] if rows else []
        if collection == "grant":
            layers: list[dict[str, dict[str, Any]]] = []
            for node in (self.node, None):
                layer = {}
                for cid, rows in self._grant_rows(capability).items():
                    for row in rows:
                        if row["node"] == node:
                            value = {f: row[f] for f in GRANT_FIELDS if row[f] is not None}
                            layer[cid] = self._record("project", capability, collection,
                                                      cid, value, f"{cid}@{node or '*'}")
                if layer:
                    layers.append(layer)
            return layers
        if collection in self.collections:
            scopes = ("project", "global") if self.include_global else ("project",)
            return [layer for scope in scopes
                    for layer in self._scope_layers(capability, collection, scope)
                    if layer]
        layers = super().config_layers(capability, collection)
        if collection == "setting":
            default = self._store_default(capability)
            if default is not None:
                layers.insert(0, {"connection.default": self._record(
                    "project", capability, collection, "connection.default", default,
                    "connection.default")})
        return layers

    def resolve_scope(self, capability: str, collection: str,
                      scope: str) -> dict[str, dict[str, Any]]:
        if collection in ("connection", "grant") and scope in ("project", "store"):
            return self.resolve(capability, collection)
        if collection in self.collections and collection in ("identifier", "policy"):
            _store_check("capability", capability, CAPABILITY_RE)
            self._scope_root(scope)
            out: dict[str, dict[str, Any]] = {}
            for layer in self._scope_layers(capability, collection, scope):
                for key, row in layer.items():
                    out.setdefault(key, row)
            return out
        return super().resolve_scope(capability, collection, scope)

    def get(self, capability: str, collection: str, key: str) -> Any:
        """A grant answers with the row that applies on this node, and says
        which node it names (null for every node) and whether it is the
        default pointer."""
        if collection == "grant":
            _store_check("capability", capability, CAPABILITY_RE)
            rows = self._grant_rows(capability).get(key)
            if not rows:
                return None
            row = rows[0]
            out = {f: row[f] for f in GRANT_FIELDS if row[f] is not None}
            out.update(node=row["node"], is_default=row["is_default"])
            return out
        return super().get(capability, collection, key)

    def collection_source(self, capability: str, collection: str) -> str:
        if collection in self.collections:
            return self._table_source(collection)
        return super().collection_source(capability, collection)

    def scope_source(self, capability: str, collection: str, scope: str) -> str:
        if collection in self.collections:
            return self._table_source(collection)
        return super().scope_source(capability, collection, scope)

    # -- writing ---------------------------------------------------------------

    def _grant_value(self, cid: str, value: Any) -> tuple[dict[str, Any], str | None]:
        if not isinstance(value, dict):
            raise StoreError("bad_grant",
                             f"grant {cid!r} must be a table, got {type(value).__name__}")
        known = (*GRANT_FIELDS, "node", "is_default")
        unknown = set(value) - set(known)
        if unknown:
            raise StoreError("bad_grant",
                             f"grant {cid!r} has unknown field(s): {', '.join(sorted(unknown))}",
                             f"known: {', '.join(known)}")
        for field in (*GRANT_FIELDS, "is_default"):
            if field in value and not isinstance(value[field], bool) \
                    and not (field in GRANT_FIELDS and value[field] is None):
                raise StoreError("bad_grant", f"grant {cid!r} {field} must be true or false")
        node = value.get("node")
        if node is not None and (not isinstance(node, str) or not node.strip()):
            raise StoreError("bad_grant",
                             f"grant {cid!r} node must name a node, or be null for every node")
        return {f: value[f] for f in (*GRANT_FIELDS, "is_default") if f in value}, node

    def _put_connection(self, conn: Any, capability: str, cid: str, spec: dict,
                        agent: str | None, own: bool, change: bool = True) -> bool:
        """Write a connection's spec for the writer `agent` (None at the
        machine's scope); whether the row is new. A new row is the writer's own
        where `own` is asked and the writer is an agent, and shared otherwise; a
        row that exists keeps its owner, and one another agent owns is refused.
        With `change` false an existing row is left as it is."""
        added = conn.execute(
            "INSERT INTO capabilities_connections (capability, name, spec, owner) "
            "VALUES (%s, %s, %s::jsonb, %s) ON CONFLICT (capability, name) DO NOTHING",
            (capability, cid, json.dumps(spec, ensure_ascii=False),
             agent if own else None)).rowcount
        if added:
            return True
        if not change:
            return False
        (held,) = conn.execute(
            "SELECT owner FROM capabilities_connections WHERE capability = %s "
            "AND name = %s FOR UPDATE", (capability, cid)).fetchone()
        if held is not None and held != agent:
            raise StoreError("connection_owned",
                             f"{capability} connection {cid!r} is agent {held}'s own, "
                             "so only that agent changes it",
                             "change it in that agent's project, or add a connection "
                             "of this agent's own under another id")
        conn.execute(
            "UPDATE capabilities_connections SET spec = %s::jsonb "
            "WHERE capability = %s AND name = %s",
            (json.dumps(spec, ensure_ascii=False), capability, cid))
        return False

    def _drop_connection(self, conn: Any, capability: str, cid: str,
                         agent: str | None) -> bool:
        """Remove a connection with its grants; whether it was there. One
        another agent owns is refused."""
        row = conn.execute(
            "SELECT owner FROM capabilities_connections WHERE capability = %s "
            "AND name = %s FOR UPDATE", (capability, cid)).fetchone()
        if row is None:
            return False
        if row[0] is not None and row[0] != agent:
            raise StoreError("connection_owned",
                             f"{capability} connection {cid!r} is agent {row[0]}'s own, "
                             "so only that agent removes it",
                             "remove it in that agent's project")
        return conn.execute(
            "DELETE FROM capabilities_connections WHERE capability = %s AND name = %s",
            (capability, cid)).rowcount > 0

    def _put_grant(self, conn: Any, capability: str, cid: str,
                   fields: dict[str, Any], node: str | None) -> None:
        if not self.project_id:
            raise StoreError("no_project_id",
                             "this project has no id a grant could name",
                             "run `capabilities init` in the project")
        known = conn.execute(
            "SELECT 1 FROM capabilities_connections WHERE capability = %s AND name = %s",
            (capability, cid)).fetchone()
        if known is None:
            raise StoreError("unknown_connection",
                             f"the store holds no {capability} connection {cid!r}",
                             f"declare it first: `capabilities set {capability} "
                             f"connection {cid} '{{...}}'`")
        if fields.get("is_default"):
            conn.execute(
                "UPDATE capabilities_connection_grants SET is_default = false "
                "WHERE agent_id = %s AND capability = %s AND connection <> %s "
                "AND coalesce(node, '') = coalesce(%s, '') AND is_default",
                (self.project_id, capability, cid, node))
        columns = ["agent_id", "capability", "connection", "node", *fields]
        values = [self.project_id, capability, cid, node, *fields.values()]
        updates = ", ".join(f"{field} = EXCLUDED.{field}" for field in fields)
        conn.execute(
            f"INSERT INTO capabilities_connection_grants ({', '.join(columns)}) "
            f"VALUES ({', '.join(['%s'] * len(values))}) "
            "ON CONFLICT (agent_id, capability, connection, (coalesce(node, ''))) "
            + (f"DO UPDATE SET {updates}" if updates else "DO NOTHING"),
            values)

    def _put_default(self, conn: Any, capability: str, cid: str | None,
                     node: str | None) -> None:
        if not self.project_id:
            raise StoreError("no_project_id",
                             "this project has no id a grant could name",
                             "run `capabilities init` in the project")
        conn.execute(
            "UPDATE capabilities_connection_grants SET is_default = false "
            "WHERE agent_id = %s AND capability = %s "
            "AND coalesce(node, '') = coalesce(%s, '') AND is_default",
            (self.project_id, capability, node))
        if cid is not None:
            self._put_grant(conn, capability, cid, {"is_default": True}, node)

    def _scoped(self, collection: str, key: str | None, scope: str | None) -> bool:
        """Whether a write at `scope` lands in the store. Identifiers and
        policy keep both scopes there; a global connection, grant or default
        pointer stays the config home's."""
        if not self._held(collection, key):
            return False
        return scope != "global" or collection in ("identifier", "policy")

    def _agent(self, scope: str | None) -> str | None:
        """The `agent_id` a row at `scope` carries: this project's id, or null
        for a global row."""
        if scope not in (None, "project", "global"):
            raise StoreError("bad_scope",
                             f"scope {scope!r} must be one of {', '.join(SCOPE_KINDS)}")
        if scope == "global":
            return None
        if not self.project_id:
            raise StoreError("no_project_id",
                             "this project has no id a store row could name",
                             "run `capabilities init` in the project")
        return self.project_id

    def _put_identifier(self, capability: str, label: str, value: Any,
                        note: str | None, scope: str | None) -> None:
        agent = self._agent(scope)
        self._write(lambda conn: conn.execute(
            "INSERT INTO capabilities_identifiers "
            "(agent_id, capability, label, value, note) "
            "VALUES (%s, %s, %s, %s::jsonb, %s) "
            "ON CONFLICT ((coalesce(agent_id, '')), capability, label, "
            "(coalesce(node, ''))) "
            "DO UPDATE SET value = EXCLUDED.value, note = EXCLUDED.note, "
            "updated_at = now()",
            (agent, capability, label, json.dumps(value, ensure_ascii=False),
             note or "")))

    def _put_policy(self, name: str, value: Any, scope: str | None,
                    node: str | None = None) -> None:
        if (not isinstance(value, dict) or set(value) != {"enabled"}
                or not isinstance(value["enabled"], bool)):
            raise StoreError("bad_policy", f"policy for {name!r} must be "
                             '{"enabled": true|false}')
        agent = self._agent(scope)
        node = _node_check(node)
        self._write(lambda conn: _upsert_policy(conn, agent, name, node, value["enabled"]))

    def set(self, capability: str, collection: str, key: str, value: Any,
            actor: str | None = None, note: str | None = None,
            scope: str | None = None, node: str | None = None, own: bool = False) -> None:
        """`own` writes a new connection at project scope as this project's
        own, with its grant enabling it, in one transaction."""
        if not self._scoped(collection, key, scope):
            return super().set(capability, collection, key, value,
                               actor=actor, note=note, scope=scope, node=node)
        _store_check("capability", capability, CAPABILITY_RE)
        _store_check("key", key, KEY_RE)
        _only_policy_names_a_node(collection, node)
        self.guard_write(capability, collection, scope)
        if collection == "identifier":
            return self._put_identifier(capability, key, value, note, scope)
        if collection == "policy":
            return self._put_policy(key, value, scope, node)
        if scope not in (None, "project"):
            raise StoreError("bad_scope",
                             f"scope {scope!r} must be one of {', '.join(SCOPE_KINDS)}")
        if collection == "connection":
            if not isinstance(value, dict):
                raise StoreError("bad_connection",
                                 f"connection {key!r} must be a table, got "
                                 f"{type(value).__name__}")
            spec = {k: v for k, v in value.items() if k not in GRANT_FIELDS}
            grant = {k: value[k] for k in GRANT_FIELDS if k in value}

            def work(conn: Any) -> None:
                added = self._put_connection(conn, capability, key, spec,
                                             self.project_id, own)
                wanted = ({"enabled": True, **grant} if added and own and self.project_id
                          else grant)
                if wanted:
                    fields, node = self._grant_value(key, wanted)
                    self._put_grant(conn, capability, key, fields, node)
            self._write(work)
        elif collection == "grant":
            fields, node = self._grant_value(key, value)
            self._write(lambda conn: self._put_grant(conn, capability, key, fields, node))
        else:
            cid = value if isinstance(value, str) and value else None
            if value not in (None, "") and cid is None:
                raise StoreError("bad_default", "the default pointer names a connection id")
            self._write(lambda conn: self._put_default(conn, capability, cid, None))

    def place(self, capability: str, node: str, placed: bool, exclusive: bool = False,
              actor: str | None = None) -> dict[str, Any]:
        """Place this project's bundled service of `capability` on `node`, or take
        it off, leaving whether the capability is usable on any node as it is:
        only the `service` of the project's rows changes. Placing where the
        project has no row naming the node writes one that enables the
        capability there, since a service runs only where its project enables
        it; placing where that row disables it is refused (`disabled_on_node`).
        `exclusive` - a service that runs on one node at a time - takes the
        service off every other node in the same transaction, which is how it
        moves. Answers {node, changed, unplaced, enabled_on_node?}."""
        _store_check("capability", capability, CAPABILITY_RE)
        node = _node_check(node)
        if node is None:
            raise StoreError("bad_node", "a service is placed on one named node")
        self.guard_write(capability, "policy", "project")
        agent = self._agent("project")
        where = "agent_id = %s AND capability = %s AND node = %s"

        def work(conn: Any) -> dict[str, Any]:
            target = self._place_node(conn, node, actor)
            row = conn.execute(
                f"SELECT enabled, service FROM capabilities_policy WHERE {where} "
                "FOR UPDATE", (agent, capability, target)).fetchone()
            out: dict[str, Any] = {"node": target, "changed": False, "unplaced": []}
            if placed:
                if row is not None and not row[0]:
                    raise StoreError(
                        "disabled_on_node",
                        f"{capability} is disabled for this project on node {target}, "
                        "so its service cannot run there",
                        f"enable it there first: `capabilities enable {capability} "
                        f"--project --node {target}`")
                if row is None:
                    conn.execute(
                        "INSERT INTO capabilities_policy "
                        "(agent_id, capability, node, enabled, service) "
                        "VALUES (%s, %s, %s, true, true)", (agent, capability, target))
                    out.update(changed=True, enabled_on_node=True)
                elif not row[1]:
                    conn.execute(
                        "UPDATE capabilities_policy SET service = true, updated_at = now() "
                        f"WHERE {where}", (agent, capability, target))
                    out["changed"] = True
                if exclusive:
                    others = [n for (n,) in conn.execute(
                        "SELECT node FROM capabilities_policy WHERE agent_id = %s "
                        "AND capability = %s AND node <> %s AND service "
                        "ORDER BY node FOR UPDATE", (agent, capability, target)).fetchall()]
                    for other in others:
                        self._place_node(conn, other, actor)
                    if others:
                        conn.execute(
                            "UPDATE capabilities_policy SET service = false, "
                            "updated_at = now() WHERE agent_id = %s AND capability = %s "
                            "AND node = ANY(%s)", (agent, capability, others))
                        out.update(changed=True, unplaced=others)
            elif row is not None and row[1]:
                conn.execute(
                    "UPDATE capabilities_policy SET service = false, updated_at = now() "
                    f"WHERE {where}", (agent, capability, target))
                out["changed"] = True
            return out
        return self._write(work)

    def placed_nodes(self, capability: str) -> list[str]:
        """The nodes this project's bundled service of `capability` is placed
        on, by name."""
        _store_check("capability", capability, CAPABILITY_RE)
        agent = self._agent("project")
        return [node for (node,) in self._read(
            "SELECT node FROM capabilities_policy WHERE agent_id = %s "
            "AND capability = %s AND service ORDER BY node", (agent, capability))]

    def _place_node(self, conn: Any, node: str, actor: str | None) -> str:
        """The node a placement row is written for, refused where this process
        may not write it."""
        del conn, actor
        return node

    def delete(self, capability: str, collection: str, key: str,
               scope: str | None = None, node: str | None = None) -> bool:
        if not self._scoped(collection, key, scope):
            return super().delete(capability, collection, key, scope=scope, node=node)
        _only_policy_names_a_node(collection, node)
        self.guard_write(capability, collection, scope)
        if collection == "identifier":
            agent = self._agent(scope)

            def work(conn: Any) -> bool:
                return conn.execute(
                    "DELETE FROM capabilities_identifiers "
                    "WHERE coalesce(agent_id, '') = coalesce(%s, '') "
                    "AND capability = %s AND label = %s AND node IS NULL",
                    (agent, capability, key)).rowcount > 0
        elif collection == "policy":
            agent = self._agent(scope)
            node = _node_check(node)

            def work(conn: Any) -> bool:
                return conn.execute(
                    "DELETE FROM capabilities_policy "
                    "WHERE coalesce(agent_id, '') = coalesce(%s, '') "
                    "AND capability = %s AND coalesce(node, '') = coalesce(%s, '')",
                    (agent, key, node)).rowcount > 0
        elif collection == "connection":
            def work(conn: Any) -> bool:
                return self._drop_connection(conn, capability, key, self.project_id)
        elif collection == "grant":
            def work(conn: Any) -> bool:
                return conn.execute(
                    "DELETE FROM capabilities_connection_grants WHERE agent_id = %s "
                    "AND capability = %s AND connection = %s AND node IS NULL",
                    (self.project_id, capability, key)).rowcount > 0
        else:
            def work(conn: Any) -> bool:
                return conn.execute(
                    "UPDATE capabilities_connection_grants SET is_default = false "
                    "WHERE agent_id = %s AND capability = %s AND node IS NULL "
                    "AND is_default", (self.project_id, capability)).rowcount > 0
        return bool(self._write(work))


# --- an agent whose records moved into the store --------------------------------

# How long asking the store whether an agent's records moved may take where the
# answer only decides whether its files are still the truth: a store that does
# not answer by then leaves a project whose records are files on its files.
_PROBE_TIMEOUT = 2

# The writers that name themselves: the migration, and a capability's service.
# Every other writer is the person running the command, `<user>@<node>`.
_ACTOR_RE = re.compile(r"migrate|[a-z][a-z0-9-]{0,62}-service")


def _store_connect(project_root: Path, application_name: str,
                   timeout: int | None = None) -> tuple[Any, str]:
    """A transaction connection to the database resolved for `project_root`,
    and its schema, for one operation the caller closes. Raises StoreError."""
    try:
        from capabilities_contract import db
    except ImportError:
        raise StoreError(
            "driver_missing",
            "the shared database library capabilities-contract is not installed",
            "run the capability through its own script header, which pins it") from None
    try:
        setting = db.resolve_setting(project_root)
        extra = {"connect_timeout": timeout} if timeout else {}
        conn = db.connect(application_name=application_name, setting=setting,
                          transaction=True, **extra)
    except db.DbError as exc:
        raise StoreError(exc.slug, exc.message, exc.hint) from None
    return conn, setting.schema


def _read_together(conn: Any, statements: Sequence[tuple[str, Sequence[Any]]]) -> list[list]:
    """The rows of each of `statements`, independent reads on `conn`, sent to the
    store together and answered in one round trip where the shared database
    library offers it (`db.batch`), else one after another."""
    from capabilities_contract import db
    together = getattr(db, "batch", None)
    if together is None:
        return [conn.execute(query, params).fetchall() for query, params in statements]
    return together(conn, list(statements))


def _agent_state(conn: Any, agent_id: str) -> dict | None:
    """The agent's registry row and its nodes, or None where the store holds
    no such row or no registry at all."""
    import psycopg
    from capabilities_contract import db
    agent = ("SELECT migrating_since, migrated_at FROM capabilities_agents WHERE id = %s",
             (agent_id,))
    nodes_of = ("SELECT node, is_master, may_write FROM capabilities_agent_nodes "
                "WHERE agent_id = %s ORDER BY node", (agent_id,))
    try:
        if getattr(db, "batch", None) is not None:
            # Both in one round trip; the nodes are read whether or not the
            # row is there, and count only where it is.
            rows, nodes = db.batch(conn, [agent, nodes_of])
            row = rows[0] if rows else None
        else:
            row = conn.execute(*agent).fetchone()
            nodes = conn.execute(*nodes_of).fetchall() if row else []
    except psycopg.errors.UndefinedTable:
        conn.rollback()
        return None
    if row is None:
        return None
    # Stamped here rather than through `_stamp`, a name a capability may also
    # define for itself: a moment that is not there stays None.
    since, moved = (None if moment is None else moment.isoformat() for moment in row)
    return {"id": agent_id, "migrating_since": since, "migrated_at": moved,
            "nodes": {node: {"is_master": bool(master), "may_write": bool(may_write)}
                      for node, master, may_write in nodes},
            "master": next((node for node, master, _w in nodes if master), None)}


def _master_hint(state: dict) -> str:
    master = state.get("master")
    if master:
        return (f"the agent's master node is {master}: register this node there with "
                "`capabilities node add <id> --label <label> --kind mac|server`, the id "
                "being the one `capabilities node id` answers here")
    return ("the agent has no master node registered: register one with "
            "`capabilities node add <id> --label <label> --kind mac|server --master` on "
            "the machine that is its master, the id being the one `capabilities node id` "
            "answers there")


def _refuse_frozen(state: dict | None, agent_id: str | None, role: str | None,
                   node: str | None = None, files: bool = False) -> None:
    """A write to an agent whose records are moving into the store comes from
    the migration on its master alone; a file write for an agent whose records
    already moved is never made."""
    if not state:
        return
    if files and state.get("migrated_at"):
        raise StoreError(
            "agent_migrated",
            f"agent {agent_id} keeps its records in the store since "
            f"{state['migrated_at']}, and this process opened them as files",
            "run the command again: a new process reads and writes them in the store")
    since = state.get("migrating_since")
    if not since:
        return
    here = node if node is not None else node_id()
    if role == "migrate" and here and here == state.get("master"):
        return
    raise StoreError(
        "agent_migrating",
        f"agent {agent_id}'s records are being moved into the store (since {since}); "
        f"until that finishes only the migration on its master "
        f"{state.get('master') or '(none registered)'} writes them",
        "wait for `capabilities migrate` to finish on the master, then run it again")


def _json_copy(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False))
    except (TypeError, ValueError) as exc:
        raise StoreError("bad_setting", f"a setting holds JSON only: {exc}") from None


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _tree_put(document: dict, path: Sequence[str], value: Any) -> None:
    """Put `value` at `path`, making each missing or non-object parent an
    object; an object given replaces the subtree there."""
    here = document
    for part in path[:-1]:
        if not isinstance(here.get(part), dict):
            here[part] = {}
        here = here[part]
    here[path[-1]] = _json_copy(value)


def settings_tree(rows: Sequence[tuple[Sequence[str], Any]]) -> dict:
    """A settings document assembled from its leaf rows."""
    document: dict = {}
    for path, value in sorted(rows, key=lambda row: list(row[0])):
        _tree_put(document, list(path), value)
    return document


def settings_leaves(document: dict, prefix: tuple = ()) -> dict[tuple, Any]:
    """A settings document as its leaf rows: every path to a scalar, an array
    or an empty object. A document's root is never a leaf."""
    out: dict[tuple, Any] = {}
    for key, value in document.items():
        if not isinstance(key, str):
            raise StoreError("bad_setting", f"a settings key is text, not {key!r}")
        path = (*prefix, key)
        if isinstance(value, dict) and value:
            out.update(settings_leaves(value, path))
        else:
            out[path] = value
    return out


class GlobalRows(StoreRecords):
    """The store's rows for every agent, which are the global layer once the
    store holds them (`capabilities_global.global_migrated_at` is set): every
    shared connection row (its owner null; a row an agent owns is that agent's
    own and never part of the global layer), the grant for every agent and
    every node with the default pointer it carries, and the policy row for
    every agent and every node.
    `project_root` is the folder the database resolves for; None outside any
    project, where the machine's store setting answers.

    A connection written here is shared (its owner null), and one an agent
    owns is refused (`connection_owned`). Its grant names no agent and no
    node, and the store refuses one for a connection an agent owns."""

    def __init__(self, global_dir: Path | str, project_root: Path | str | None,
                 application_name: str = STORE_OWNER):
        super().__init__(Path(global_dir), Path(global_dir), None, None,
                         application_name=application_name)
        self.project_root = Path(project_root) if project_root is not None else None
        self._in_force: bool | None = None

    def in_force(self) -> bool:
        """Whether the store holds the global rows; False where no database
        is configured. A configured store that does not answer within
        `_PROBE_TIMEOUT` raises StoreError."""
        if self._in_force is not None:
            return self._in_force
        try:
            conn, schema = _store_connect(self.project_root, self.application_name,
                                          _PROBE_TIMEOUT)
        except StoreError as exc:
            if exc.slug in ("store_not_configured", "driver_missing"):
                self._in_force = False
                return False
            raise
        import psycopg
        try:
            try:
                row = conn.execute("SELECT global_migrated_at FROM capabilities_global"
                                   ).fetchone()
            except psycopg.errors.UndefinedTable:
                row = None
            conn.rollback()
        except psycopg.Error as exc:
            raise StoreError("store_unreachable", f"cannot read the store's global rows: {exc}",
                             "check the database setting with `capabilities store doctor`"
                             ) from None
        finally:
            try:
                conn.close()
            except Exception:
                pass
        self._schema = schema
        self._in_force = bool(row and row[0])
        return self._in_force

    def table_source(self, collection: str) -> str:
        return self._table_source(collection)

    # -- reading ---------------------------------------------------------------

    def _layer(self, capability: str) -> dict[str, Any]:
        """One capability's global layer: its shared connection rows, the grant
        fields every agent's grant decides, and the default pointer."""
        key = ("global", capability)
        held = self._fresh(key)
        if held is None:
            connections, grants = self._read_many([
                ("SELECT name, spec FROM capabilities_connections "
                 "WHERE capability = %s AND owner IS NULL ORDER BY name", (capability,)),
                ("SELECT connection, enabled, allow_write, is_default "
                 "FROM capabilities_connection_grants WHERE agent_id IS NULL "
                 "AND node IS NULL AND capability = %s ORDER BY connection",
                 (capability,))])
            held = {"connections": {name: dict(spec) if isinstance(spec, dict) else {}
                                    for name, spec in connections},
                    "grants": {}, "default": None}
            for cid, enabled, allow_write, is_default in grants:
                fields = {f: v for f, v in (("enabled", enabled),
                                            ("allow_write", allow_write)) if v is not None}
                if fields:
                    held["grants"][cid] = fields
                if is_default and held["default"] is None:
                    held["default"] = cid
            self._cache[key] = (time.monotonic(), held)
        return held

    def _policy(self) -> dict[str, dict[str, bool]]:
        key = ("global", "")
        held = self._fresh(key)
        if held is None:
            held = {name: {"enabled": bool(enabled)} for name, enabled in self._read(
                "SELECT capability, enabled FROM capabilities_policy "
                "WHERE agent_id IS NULL AND node IS NULL ORDER BY capability", ())}
            self._cache[key] = (time.monotonic(), held)
        return held

    def entries(self, capability: str, collection: str,
                files: dict[str, Any]) -> dict[str, Any]:
        """The global scope's entries of one collection: the store's, with
        `files` (the config home's) answering only for a name the store holds
        no row of - a connection id, or a capability's policy. A file's
        default pointer stands only for a capability the store holds no
        connection of."""
        if collection == "policy":
            stored = self._policy()
            return {**{k: v for k, v in files.items() if k not in stored}, **stored}
        layer = self._layer(capability)
        names = layer["connections"]
        if collection == "connection":
            out = {cid: v for cid, v in files.items() if cid not in names}
            out.update(names)
            return out
        if collection == "grant":
            out = {cid: v for cid, v in files.items() if cid not in names}
            out.update(layer["grants"])
            return out
        out = dict(files)
        if names:
            out.pop("connection.default", None)
        if layer["default"] is not None:
            out["connection.default"] = layer["default"]
        return out

    # -- writing ---------------------------------------------------------------

    def _put_global_grant(self, conn: Any, capability: str, cid: str,
                          fields: dict[str, Any]) -> None:
        known = conn.execute(
            "SELECT 1 FROM capabilities_connections WHERE capability = %s AND name = %s",
            (capability, cid)).fetchone()
        if known is None:
            raise StoreError("unknown_connection",
                             f"the store holds no {capability} connection {cid!r}",
                             f"add it first: `{capability} connection add {cid} --machine`")
        if fields.get("is_default"):
            conn.execute(
                "UPDATE capabilities_connection_grants SET is_default = false "
                "WHERE agent_id IS NULL AND node IS NULL AND capability = %s "
                "AND connection <> %s AND is_default", (capability, cid))
        columns = ["capability", "connection", *fields]
        values = [capability, cid, *fields.values()]
        updates = ", ".join(f"{field} = EXCLUDED.{field}" for field in fields)
        conn.execute(
            f"INSERT INTO capabilities_connection_grants (agent_id, node, {', '.join(columns)}) "
            f"VALUES (NULL, NULL, {', '.join(['%s'] * len(values))}) "
            "ON CONFLICT ((coalesce(agent_id, '')), capability, connection, "
            "(coalesce(node, ''))) "
            + (f"DO UPDATE SET {updates}" if updates else "DO NOTHING"),
            values)

    def _clear_default(self, conn: Any, capability: str) -> bool:
        return conn.execute(
            "UPDATE capabilities_connection_grants SET is_default = false "
            "WHERE agent_id IS NULL AND node IS NULL AND capability = %s AND is_default",
            (capability,)).rowcount > 0

    def set(self, capability: str, collection: str, key: str, value: Any,
            actor: str | None = None, note: str | None = None,
            scope: str | None = None, node: str | None = None, own: bool = False) -> None:
        if collection == "policy":
            return self._put_policy(key, value, "global")
        if collection == "connection":
            if not isinstance(value, dict):
                raise StoreError("bad_connection",
                                 f"connection {key!r} must be a table, got "
                                 f"{type(value).__name__}")
            spec = {k: v for k, v in value.items() if k not in GRANT_FIELDS}
            grant = {k: value[k] for k in GRANT_FIELDS if k in value}

            def work(conn: Any) -> None:
                self._put_connection(conn, capability, key, spec, None, False)
                if grant:
                    self._put_global_grant(conn, capability, key, grant)
            return self._write(work)
        if collection == "grant":
            fields = {k: v for k, v in (value or {}).items() if k in GRANT_FIELDS}
            return self._write(lambda conn: self._put_global_grant(conn, capability, key,
                                                                   fields))
        cid = value if isinstance(value, str) and value else None
        if value not in (None, "") and cid is None:
            raise StoreError("bad_default", "the default pointer names a connection id")

        def put_default(conn: Any) -> None:
            self._clear_default(conn, capability)
            if cid is not None:
                self._put_global_grant(conn, capability, cid, {"is_default": True})
        return self._write(put_default)

    def delete(self, capability: str, collection: str, key: str,
               scope: str | None = None, node: str | None = None) -> bool:
        if collection == "policy":
            def work(conn: Any) -> bool:
                return conn.execute(
                    "DELETE FROM capabilities_policy WHERE agent_id IS NULL "
                    "AND node IS NULL AND capability = %s", (key,)).rowcount > 0
        elif collection == "connection":
            def work(conn: Any) -> bool:
                return self._drop_connection(conn, capability, key, None)
        elif collection == "grant":
            def work(conn: Any) -> bool:
                cleared = conn.execute(
                    "UPDATE capabilities_connection_grants SET enabled = NULL, "
                    "allow_write = NULL WHERE agent_id IS NULL AND node IS NULL "
                    "AND capability = %s AND connection = %s "
                    "AND (enabled IS NOT NULL OR allow_write IS NOT NULL)",
                    (capability, key)).rowcount > 0
                conn.execute(
                    "DELETE FROM capabilities_connection_grants WHERE agent_id IS NULL "
                    "AND node IS NULL AND capability = %s AND connection = %s "
                    "AND NOT is_default", (capability, key))
                return cleared
        else:
            def work(conn: Any) -> bool:
                return self._clear_default(conn, capability)
        return bool(self._write(work))


def global_records(global_dir: Path | str, project_root: Path | str | None = None,
                   application_name: str = STORE_OWNER) -> "FileRecords":
    """The machine's global layer alone, as a process outside any project
    reads and writes it: the config home's files, or the store's rows for
    every agent once they are in force there (see `GlobalRows`), the database
    resolved for `project_root` (None: the machine's store setting)."""
    global_dir = Path(global_dir)
    adapter = FileRecords(global_dir / "no-project", global_dir)
    adapter._global_from = (Path(project_root) if project_root is not None else None,)
    adapter._guard_application = application_name
    return adapter


class _Unchanged(Exception):
    """Raised by a settings change that finds nothing to do, so the write
    it runs in leaves the document as it was."""


# A settings write that names no generation it was read at.
_UNREAD = object()


def _user_name() -> str:
    name = os.environ.get("USER") or os.environ.get("LOGNAME")
    if not name:
        try:
            import getpass
            name = getpass.getuser()
        except Exception:
            name = "unknown"
    return name


class AgentRecords(StoreRecords):
    """An agent whose records moved into the store: its `capabilities_agents`
    row has `migrated_at`. Every record it keeps - connections, grants, the
    default pointer, identifiers, policy - and its settings documents are rows
    of the contract's tables; its files are not read. Documents stay files.

    Each record resolves the agent's own rows over the rows for every agent
    (`agent_id` null), and at each of those scopes the row for this node over
    the row for every node. This node is AGENT_NODE_NAME, registered among the
    agent's nodes; `open_records` refuses an agent that has moved without it.

    Who writes what: the agent's master, and every node its link lets write
    (`may_write`), writes the rows every node shares (node null) and the rows
    for its own node; a row for another node is the master's alone. A node
    that is not the master and already holds its own row for what it writes
    reads it from that row, so its write lands there. While the
    agent's `migrating_since` is set, only the migration on its master writes.
    A settings document is written in one transaction under its advisory lock:
    assembled, changed, checked whole, then stored as the paths that changed,
    removals first, each with a trail row, and its generation moved to the
    last of them. A write made from a document read earlier names the
    generation it read, and is refused while another write has moved it."""

    settings_in_rows = True

    def __init__(self, envelope: Path, global_dir: Path, project_id: str,
                 project: str | None, *, agent: dict, node: str,
                 include_global: bool = True, project_root: Path | None = None,
                 application_name: str = STORE_OWNER, actor: str | None = None):
        super().__init__(envelope, global_dir, project_id, project,
                         include_global=include_global, project_root=project_root,
                         application_name=application_name, held=RECORDS_MODE_KEY)
        self.collections = frozenset({"connection", "grant", "identifier", "policy",
                                      "setting"})
        self.agent = agent
        self.node = node
        self.actor = actor
        self._guard_agent = project_id
        self._ledger_current = False
        self._txn = False

    def _held(self, collection: str, key: str | None = None) -> bool:
        return collection in self.collections

    def settings_kept(self) -> str:
        return "store"

    # -- reaching the store ----------------------------------------------------

    def _db(self) -> Any:
        """The connection, its tables brought to this code's version once."""
        conn = super()._db()
        if not self._ledger_current and self._owns_conn and not self._txn:
            import psycopg
            from capabilities_contract import db
            major, minor = STORE_TABLES_VERSION
            try:
                db.migrate(conn, STORE_OWNER, record_table_steps(), major=major, minor=minor)
            except db.DbError as exc:
                raise StoreError(exc.slug, exc.message, exc.hint) from None
            except psycopg.OperationalError as exc:
                raise self._unreachable(exc) from None
            self._ledger_current = True
        return conn

    def _role(self, actor: str | None) -> str | None:
        for named in (actor, self.actor):
            if isinstance(named, str) and _ACTOR_RE.fullmatch(named):
                return named
        return None

    def actor_name(self, actor: str | None = None) -> str:
        """Who a write is recorded as: `migrate@<node>`,
        `<capability>-service@<node>`, or the person, `<user>@<node>`."""
        return f"{self._role(actor) or _user_name()}@{self.node}"

    def _authority(self, conn: Any, scope: str | None, wanted: str | None,
                   actor: str | None) -> str | None:
        """The node a write lands on, decided from the registry as it stands
        in this transaction: the master writes the shared rows (or a row for
        the node it names); another node its link lets write writes the shared
        rows and its own, and a node it does not let write writes nothing."""
        state = _agent_state(conn, self.project_id) or {}
        if scope != "global":
            _refuse_frozen(state, self.project_id, self._role(actor), node=self.node)
        mine = (state.get("nodes") or {}).get(self.node)
        if mine is None:
            raise StoreError("node_unregistered",
                             f"node {self.node} is not a node of agent {self.project_id}",
                             _master_hint(state))
        if mine["is_master"]:
            return wanted
        if not mine["may_write"]:
            raise StoreError(
                "node_read_only",
                f"node {self.node} is not the master of agent {self.project_id} and "
                "may not write: the rows every node shares are written on the master "
                f"{state.get('master') or '(none registered)'} or on a node it lets write",
                "write it on the master, or let this node write with "
                f"`capabilities node set {self.node} --may-write`")
        if wanted not in (None, self.node):
            raise StoreError(
                "node_read_only",
                f"node {self.node} is not the master of agent {self.project_id} and "
                f"writes the shared rows and its own, not rows for node {wanted}",
                f"write it on the master {state.get('master') or '(none registered)'}")
        return wanted

    def _landing(self, conn: Any, scope: str | None, wanted: str | None,
                 actor: str | None, table: str, agent: str | None, where: str,
                 params: Sequence[Any] = ()) -> str | None:
        """The node a write lands on, as `_authority` decides it, except that
        a node other than the master that already holds its own row of
        `table` for what is written - the agent's, matching `where` - reads
        it from that row, so a write naming no node lands there."""
        at = self._authority(conn, scope, wanted, actor)
        if at is not None or wanted is not None:
            return at
        mine = ((_agent_state(conn, self.project_id) or {}).get("nodes") or {}).get(self.node)
        if mine is None or mine["is_master"]:
            return at
        found = conn.execute(
            f"SELECT 1 FROM {table} WHERE coalesce(agent_id, '') = coalesce(%s::text, '') "
            f"AND {where} AND node = %s", (agent, *params, self.node)).fetchone()
        return self.node if found is not None else at

    def _place_node(self, conn: Any, node: str, actor: str | None) -> str:
        """A placement row is written where the registry lets this node write
        it: the master any node's, another node only its own where it may."""
        return self._authority(conn, "project", node, actor)

    def _write(self, work: Any) -> Any:
        """One transaction, as the store tier's own, during which reads made
        on the same connection (a settings check reading the other scope)
        stay inside it."""
        def inside(conn: Any) -> Any:
            self._txn = True
            try:
                return work(conn)
            finally:
                self._txn = False
        return super()._write(inside)

    def _read(self, query: str, params: Sequence[Any]) -> list[tuple]:
        if not self._txn:
            return super()._read(query, params)
        import psycopg
        try:
            return self._db().execute(query, params).fetchall()
        except psycopg.OperationalError as exc:
            raise self._unreachable(exc) from None
        except psycopg.Error as exc:
            raise StoreError("store_read_failed",
                             f"reading records from the store failed: {exc}") from None

    def _read_many(self, statements: Sequence[tuple[str, Sequence[Any]]]) -> list[list]:
        if not self._txn:
            return super()._read_many(statements)
        import psycopg
        try:
            return _read_together(self._db(), statements)
        except psycopg.OperationalError as exc:
            raise self._unreachable(exc) from None
        except psycopg.Error as exc:
            raise StoreError("store_read_failed",
                             f"reading records from the store failed: {exc}") from None

    def guard_write(self, capability: str, collection: str,
                    scope: str | None = None) -> None:
        _refuse_record_write(capability, collection)
        if (scope or "project") == "project" and collection == "document":
            state = self._agent_now()
            _refuse_frozen(state, self.project_id, self._role(None), node=self.node)

    # -- reading ---------------------------------------------------------------

    def _record(self, scope: str, capability: str, collection: str, key: str,
                value: Any, ref: str, note: str | None = None,
                updated_at: str | None = None, node: str | None = None,
                service: bool | None = None) -> dict[str, Any]:
        record = super()._record(scope, capability, collection, key, value, ref,
                                 note=note, updated_at=updated_at, node=node,
                                 service=service)
        if collection in ("identifier", "grant"):
            record["node"] = node
        return record

    def _grant_rows(self, capability: str) -> dict[str, list[dict[str, Any]]]:
        """This agent's grants and the grants for every agent, per connection,
        in the order they decide: the agent's before every agent's, and at
        each the row naming this node before the row for every node."""
        key = ("grant", capability)
        held = self._fresh(key)
        if held is None:
            out: dict[str, list[dict[str, Any]]] = {}
            rows = self._read(
                "SELECT agent_id, connection, node, enabled, allow_write, is_default "
                "FROM capabilities_connection_grants "
                "WHERE capability = %s AND (agent_id = %s OR (agent_id IS NULL AND %s)) "
                "AND (node IS NULL OR node = %s) "
                "ORDER BY connection, agent_id NULLS LAST, node NULLS LAST",
                (capability, self.project_id, self.include_global, self.node))
            for agent_id, cid, node, enabled, allow_write, is_default in rows:
                out.setdefault(cid, []).append({
                    "scope": "global" if agent_id is None else "project",
                    "node": node, "enabled": enabled, "allow_write": allow_write,
                    "is_default": bool(is_default)})
            self._cache[key] = (time.monotonic(), out)
            held = out
        return held

    def _defaults(self, capability: str) -> dict[str, str]:
        """The default pointer at each scope: this node's, else every node's."""
        grants = self._grant_rows(capability)
        found: dict[str, str] = {}
        for scope in ("project", "global"):
            for node in (self.node, None):
                for cid in sorted(grants):
                    if scope not in found and any(
                            r["is_default"] and r["node"] == node and r["scope"] == scope
                            for r in grants[cid]):
                        found[scope] = cid
        return found

    def _store_default(self, capability: str) -> str | None:
        found = self._defaults(capability)
        return found.get("project") or found.get("global")

    def _identifier_rows(self, capability: str) -> dict:
        key = ("identifier", capability)
        held = self._fresh(key)
        if held is None:
            held = {(scope, node): {} for scope in ("project", "global")
                    for node in (self.node, None)}
            rows = self._read(
                "SELECT agent_id, node, label, value, note, updated_at "
                "FROM capabilities_identifiers "
                "WHERE capability = %s AND (agent_id IS NULL OR agent_id = %s) "
                "AND (node IS NULL OR node = %s) ORDER BY label",
                (capability, self.project_id, self.node))
            for agent_id, node, label, value, note, updated_at in rows:
                scope = "global" if agent_id is None else "project"
                held[(scope, node)][label] = (value, note or "", _stamp(updated_at))
            self._cache[key] = (time.monotonic(), held)
        return held

    def _scope_layers(self, capability: str, collection: str,
                      scope: str) -> list[dict[str, dict[str, Any]]]:
        if collection != "identifier":
            return super()._scope_layers(capability, collection, scope)
        rows = self._identifier_rows(capability)
        return [{label: self._record(scope, capability, collection, label, value,
                                     f"{scope}/{label}@{node or '*'}", note=note,
                                     updated_at=updated_at, node=node)
                 for label, (value, note, updated_at) in rows[(scope, node)].items()}
                for node in (self.node, None)]

    def _settings_rows(self, capability: str) -> tuple[dict, dict]:
        """The settings documents that exist for this agent and every agent,
        on this node and every node, with their generations, and their rows."""
        key = ("setting", capability)
        held = self._fresh(key)
        if held is None:
            docs: dict[tuple, int] = {}
            rows: dict[tuple, list] = {}
            where = (capability, self.project_id, self.node)
            documents, leaves = self._read_many([
                ("SELECT agent_id, node, generation FROM capabilities_settings_documents "
                 "WHERE capability = %s AND (agent_id IS NULL OR agent_id = %s) "
                 "AND (node IS NULL OR node = %s)", where),
                ("SELECT agent_id, node, path, value FROM capabilities_settings "
                 "WHERE capability = %s AND (agent_id IS NULL OR agent_id = %s) "
                 "AND (node IS NULL OR node = %s) ORDER BY path", where)])
            for agent_id, node, generation in documents:
                docs[("global" if agent_id is None else "project", node)] = int(generation)
            for agent_id, node, path, value in leaves:
                rows.setdefault(("global" if agent_id is None else "project", node),
                                []).append((list(path), value))
            held = (docs, rows)
            self._cache[key] = (time.monotonic(), held)
        return held

    def setting_document(self, capability: str, scope: str) -> dict | None:
        """One scope's settings document as this node reads it: the rows for
        every node with this node's rows over them. None where neither
        document exists, which a reader takes as the capability's seed."""
        _store_check("capability", capability, CAPABILITY_RE)
        self._scope_root(scope)
        docs, rows = self._settings_rows(capability)
        shared, mine = (scope, None), (scope, self.node)
        if not any(k in docs or k in rows for k in (shared, mine)):
            return None
        document = settings_tree(rows.get(shared, []))
        for path, value in rows.get(mine, []):
            _tree_put(document, path, value)
        return document

    def setting_generations(self, capability: str) -> dict[str, int | None]:
        """The generation each scope's document was assembled from: the
        latest of its shared and this node's documents, None where none
        exists."""
        docs, _rows = self._settings_rows(capability)
        out: dict[str, int | None] = {}
        for scope in ("project", "global"):
            found = [docs[(scope, node)] for node in (None, self.node) if (scope, node) in docs]
            out[scope] = max(found) if found else None
        return out

    def config_layers(self, capability: str, collection: str,
                      _scopes: Any = None) -> list[dict[str, dict[str, Any]]]:
        _store_check("capability", capability, CAPABILITY_RE)
        if collection == "grant":
            layers: list[dict[str, dict[str, Any]]] = []
            for scope in ("project", "global"):
                for node in (self.node, None):
                    layer = {}
                    for cid, rows in self._grant_rows(capability).items():
                        for row in rows:
                            if row["scope"] == scope and row["node"] == node:
                                value = {f: row[f] for f in GRANT_FIELDS if row[f] is not None}
                                layer[cid] = self._record(
                                    scope, capability, collection, cid, value,
                                    f"{scope}/{cid}@{node or '*'}", node=node)
                    if layer:
                        layers.append(layer)
            return layers
        if collection == "setting":
            scopes = ("project", "global") if self.include_global else ("project",)
            return [layer for layer in (self.resolve_scope(capability, "setting", scope)
                                        for scope in scopes) if layer]
        return super().config_layers(capability, collection)

    def resolve_scope(self, capability: str, collection: str,
                      scope: str) -> dict[str, dict[str, Any]]:
        if collection == "setting":
            _store_check("capability", capability, CAPABILITY_RE)
            self._scope_root(scope)
            out = {key: self._record(scope, capability, collection, key, value,
                                     f"{scope}/{key}")
                   for key, value in (self.setting_document(capability, scope) or {}).items()}
            default = self._defaults(capability).get(scope)
            if default is not None:
                out["connection.default"] = self._record(
                    scope, capability, collection, "connection.default", default,
                    f"{scope}/connection.default")
            return out
        if collection == "grant":
            if scope == "store":
                scope = "project"
            self._scope_root(scope)
            out = {}
            for layer in self.config_layers(capability, "grant"):
                for key, row in layer.items():
                    if row["scope"] == scope:
                        out.setdefault(key, row)
            return out
        if collection == "connection" and scope == "global":
            # The machine's connections are the shared rows, which no agent
            # owns; a row an agent owns is that agent's own and never one.
            _store_check("capability", capability, CAPABILITY_RE)
            rows = self._read(
                "SELECT name, spec FROM capabilities_connections "
                "WHERE capability = %s AND owner IS NULL ORDER BY name", (capability,))
            return {name: self._record("global", capability, collection, name,
                                       spec if isinstance(spec, dict) else {},
                                       f"global/{name}")
                    for name, spec in rows}
        return super().resolve_scope(capability, collection, scope)

    def global_grantees(self, capability: str, connection: str) -> list[str]:
        """Every agent a grant enables a shared connection for, which removing
        it would take it from: the shared rows are this agent's global layer."""
        return self.grantees(capability, connection)

    def get(self, capability: str, collection: str, key: str) -> Any:
        if collection == "grant":
            _store_check("capability", capability, CAPABILITY_RE)
            rows = self._grant_rows(capability).get(key)
            if not rows:
                return None
            row = rows[0]
            out = {f: row[f] for f in GRANT_FIELDS if row[f] is not None}
            out.update(node=row["node"], is_default=row["is_default"], scope=row["scope"])
            return out
        return super().get(capability, collection, key)

    # -- writing ---------------------------------------------------------------

    def _lock_document(self, conn: Any, agent: str | None, capability: str,
                       node: str | None) -> None:
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtext(concat_ws(chr(31), %s::text, "
            "coalesce(%s::text, ''), %s::text, coalesce(%s::text, ''))))",
            (self._schema, agent, capability, node))

    def _document_rows(self, conn: Any, agent: str | None, capability: str,
                       node: str | None) -> tuple[dict[tuple, Any], int | None]:
        rows, documents = _read_together(conn, [
            ("SELECT path, value FROM capabilities_settings "
             "WHERE coalesce(agent_id, '') = coalesce(%s::text, '') AND capability = %s "
             "AND coalesce(node, '') = coalesce(%s::text, '')", (agent, capability, node)),
            ("SELECT generation FROM capabilities_settings_documents "
             "WHERE coalesce(agent_id, '') = coalesce(%s::text, '') AND capability = %s "
             "AND coalesce(node, '') = coalesce(%s::text, '')", (agent, capability, node))])
        found = documents[0] if documents else None
        return ({tuple(path): value for path, value in rows},
                int(found[0]) if found else None)

    def settings_write(self, capability: str, scope: str, change: Any,
                       check: Any = None, seed: dict | None = None,
                       actor: str | None = None, base: Any = _UNREAD) -> dict[str, Any]:
        """Change one scope's settings document in one transaction: lock it,
        assemble it (the seed where no document exists yet), apply `change`
        (a function from the document to the new one), check the result as
        this node will read it with `check` (a function returning problems),
        then write the paths that differ, removals first, one trail row each,
        and move the document's generation to the last of them. `base` is the
        generation the change was made from, as `setting_generations` gave it
        (None where no document existed); given, the write is refused
        (`stale_edit`) where the scope's generation is another now. A refused
        write changes nothing."""
        _store_check("capability", capability, CAPABILITY_RE)
        _refuse_record_write(capability, "setting")
        agent = self._agent(scope)
        who = self.actor_name(actor)

        def put(conn: Any, node: str | None, old: dict[tuple, Any],
                new: dict[tuple, Any], generation: int | None) -> tuple[int, int]:
            """Store one document's paths that differ, removals first, each
            with a trail row; its generation and how many paths changed."""
            changed = 0

            def trail(action: str, path: tuple, was: Any, now: Any) -> int:
                return conn.execute(
                    "INSERT INTO capabilities_settings_changes "
                    "(agent_id, capability, node, action, path, old_value, new_value, "
                    "changed_by) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s) "
                    "RETURNING id",
                    (agent, capability, node, action, list(path),
                     None if action == "set" and path not in old else _canonical(was),
                     None if action == "unset" else _canonical(now), who)).fetchone()[0]

            for path in sorted(set(old) - set(new)):
                conn.execute(
                    "DELETE FROM capabilities_settings "
                    "WHERE coalesce(agent_id, '') = coalesce(%s::text, '') "
                    "AND capability = %s AND coalesce(node, '') = coalesce(%s::text, '') "
                    "AND path = %s", (agent, capability, node, list(path)))
                generation = trail("unset", path, old[path], None)
                changed += 1
            for path in sorted(new):
                if path in old and _canonical(old[path]) == _canonical(new[path]):
                    continue
                if path in old:
                    conn.execute(
                        "UPDATE capabilities_settings SET value = %s::jsonb, "
                        "updated_at = now(), updated_by = %s "
                        "WHERE coalesce(agent_id, '') = coalesce(%s::text, '') "
                        "AND capability = %s AND coalesce(node, '') = coalesce(%s::text, '') "
                        "AND path = %s",
                        (_canonical(new[path]), who, agent, capability, node, list(path)))
                else:
                    conn.execute(
                        "INSERT INTO capabilities_settings "
                        "(agent_id, capability, node, path, value, updated_by) "
                        "VALUES (%s, %s, %s, %s, %s::jsonb, %s)",
                        (agent, capability, node, list(path), _canonical(new[path]), who))
                generation = trail("set", path, old.get(path), new[path])
                changed += 1
            conn.execute(
                "INSERT INTO capabilities_settings_documents "
                "(agent_id, capability, node, generation) VALUES (%s, %s, %s, %s) "
                "ON CONFLICT ((coalesce(agent_id, '')), capability, (coalesce(node, ''))) "
                "DO UPDATE SET generation = EXCLUDED.generation",
                (agent, capability, node, generation or 0))
            return generation or 0, changed

        def work(conn: Any) -> dict[str, Any]:
            # A node holding paths of its own in this document writes those
            # paths there, and the rest in the shared document.
            node = self._landing(conn, scope, None, actor, "capabilities_settings",
                                 agent, "capability = %s", (capability,))
            self._lock_document(conn, agent, capability, None)
            if node is not None:
                self._lock_document(conn, agent, capability, node)
            if base is not _UNREAD:
                [(now,)] = conn.execute(
                    "SELECT max(generation) FROM capabilities_settings_documents "
                    "WHERE coalesce(agent_id, '') = coalesce(%s::text, '') "
                    "AND capability = %s AND (node IS NULL OR node = %s)",
                    (agent, capability, self.node)).fetchall()
                if (None if now is None else int(now)) != base:
                    raise StoreError(
                        "stale_edit",
                        f"the {scope} settings of {capability} are at generation "
                        f"{now} now, not {base} as they were when the edit began",
                        "read them again and apply the change again")
            shared, generation = self._document_rows(conn, agent, capability, None)
            exists = generation is not None or bool(shared)
            current = (settings_tree(list(shared.items())) if exists
                       else _json_copy(seed or {}))
            start = settings_leaves(current)
            mine: dict[tuple, Any] = {}
            mine_generation = None
            if node is not None:
                mine, mine_generation = self._document_rows(conn, agent, capability, node)
                for path, value in sorted(mine.items()):
                    _tree_put(current, list(path), value)
            before = _json_copy(current)
            after = change(_json_copy(current))
            if not isinstance(after, dict):
                raise StoreError("bad_setting", "a settings document is an object")
            after = _json_copy(after)
            if check is not None:
                read = (after if node is not None
                        else self._as_read(conn, agent, capability, None, after, seed))
                problems = check(read) or []
                if problems:
                    raise StoreError("settings_invalid", str(problems[0]))
            new = settings_leaves(after)

            def held(path: tuple) -> bool:
                return any(m[:len(path)] == path or path[:len(m)] == m for m in mine)

            new_mine = {p: v for p, v in new.items() if held(p)}
            new_shared = {p: v for p, v in new.items() if not held(p)}
            new_shared.update({p: v for p, v in start.items() if held(p)})

            def same(a: dict, b: dict) -> bool:
                return a.keys() == b.keys() and all(
                    _canonical(a[p]) == _canonical(b[p]) for p in a)

            changed = 0
            mine_moved = node is not None and not same(mine, new_mine)
            if mine_moved:
                mine_generation, count = put(conn, node, mine, new_mine, mine_generation)
                changed += count
            if node is None or not same(start, new_shared):
                generation, count = put(conn, None, shared, new_shared, generation)
                changed += count
            return {"before": before, "after": after,
                    "generation": max(generation or 0, mine_generation or 0),
                    "changed": changed, "node": node if mine_moved else None,
                    "actor": who, "source": self._table_source("setting")}
        return self._write(work)

    def _as_read(self, conn: Any, agent: str | None, capability: str,
                 node: str | None, document: dict, seed: dict | None) -> dict:
        """`document`, written for `node`, as this node will read its scope:
        the shared document with this node's rows over it."""
        if node is None:
            mine, _gen = self._document_rows(conn, agent, capability, self.node)
            composed = _json_copy(document)
        else:
            shared, generation = self._document_rows(conn, agent, capability, None)
            composed = (settings_tree(list(shared.items()))
                        if shared or generation is not None else _json_copy(seed or {}))
            mine = settings_leaves(document)
        for path, value in sorted(mine.items()):
            _tree_put(composed, list(path), value)
        return composed

    def _put_grant_at(self, conn: Any, capability: str, cid: str,
                      fields: dict[str, Any], agent: str | None, node: str | None) -> None:
        known = conn.execute(
            "SELECT 1 FROM capabilities_connections WHERE capability = %s AND name = %s",
            (capability, cid)).fetchone()
        if known is None:
            raise StoreError("unknown_connection",
                             f"the store holds no {capability} connection {cid!r}",
                             f"declare it first: `capabilities set {capability} "
                             f"connection {cid} '{{...}}'`")
        if fields.get("is_default"):
            conn.execute(
                "UPDATE capabilities_connection_grants SET is_default = false "
                "WHERE coalesce(agent_id, '') = coalesce(%s::text, '') AND capability = %s "
                "AND connection <> %s AND coalesce(node, '') = coalesce(%s::text, '') "
                "AND is_default", (agent, capability, cid, node))
        columns = ["agent_id", "capability", "connection", "node", *fields]
        values = [agent, capability, cid, node, *fields.values()]
        updates = ", ".join(f"{field} = EXCLUDED.{field}" for field in fields)
        conn.execute(
            f"INSERT INTO capabilities_connection_grants ({', '.join(columns)}) "
            f"VALUES ({', '.join(['%s'] * len(values))}) "
            "ON CONFLICT ((coalesce(agent_id, '')), capability, connection, "
            "(coalesce(node, ''))) "
            + (f"DO UPDATE SET {updates}" if updates else "DO NOTHING"),
            values)

    def _put_default_at(self, conn: Any, capability: str, cid: str | None,
                        agent: str | None, node: str | None) -> bool:
        cleared = conn.execute(
            "UPDATE capabilities_connection_grants SET is_default = false "
            "WHERE coalesce(agent_id, '') = coalesce(%s::text, '') AND capability = %s "
            "AND coalesce(node, '') = coalesce(%s::text, '') AND is_default",
            (agent, capability, node)).rowcount
        if cid is not None:
            self._put_grant_at(conn, capability, cid, {"is_default": True}, agent, node)
        return cleared > 0

    def set(self, capability: str, collection: str, key: str, value: Any,
            actor: str | None = None, note: str | None = None,
            scope: str | None = None, node: str | None = None, own: bool = False) -> None:
        if collection not in self.collections:
            return FileRecords.set(self, capability, collection, key, value,
                                   actor=actor, note=note, scope=scope, node=node)
        _store_check("capability", capability, CAPABILITY_RE)
        _store_check("key", key, KEY_RE)
        _only_policy_names_a_node(collection, node)
        _refuse_record_write(capability, collection)
        agent = self._agent(scope)
        if collection == "setting" and key != "connection.default":
            def put(document: dict) -> dict:
                document[key] = value
                return document
            self.settings_write(capability, scope or "project", put, actor=actor)
            return None
        if collection == "setting":
            cid = value if isinstance(value, str) and value else None
            if value not in (None, "") and cid is None:
                raise StoreError("bad_default", "the default pointer names a connection id")
            self._write(lambda conn: self._put_default_at(
                conn, capability, cid, agent, self._landing(
                    conn, scope, None, actor, "capabilities_connection_grants", agent,
                    "capability = %s AND is_default", (capability,))))
            return None
        if collection == "identifier":
            def work(conn: Any) -> None:
                at = self._landing(
                    conn, scope, None, actor, "capabilities_identifiers", agent,
                    "capability = %s AND label = %s", (capability, key))
                conn.execute(
                    "INSERT INTO capabilities_identifiers "
                    "(agent_id, capability, node, label, value, note) "
                    "VALUES (%s, %s, %s, %s, %s::jsonb, %s) "
                    "ON CONFLICT ((coalesce(agent_id, '')), capability, label, "
                    "(coalesce(node, ''))) "
                    "DO UPDATE SET value = EXCLUDED.value, note = EXCLUDED.note, "
                    "updated_at = now()",
                    (agent, capability, at, key, json.dumps(value, ensure_ascii=False),
                     note or ""))
            self._write(work)
            return None
        if collection == "policy":
            if (not isinstance(value, dict) or set(value) != {"enabled"}
                    or not isinstance(value["enabled"], bool)):
                raise StoreError("bad_policy", f"policy for {key!r} must be "
                                 '{"enabled": true|false}')
            wanted = _node_check(node)
            self._write(lambda conn: _upsert_policy(
                conn, agent, key, self._landing(
                    conn, scope, wanted, actor, "capabilities_policy", agent,
                    "capability = %s", (key,)),
                value["enabled"]))
            return None
        if collection == "connection":
            if not isinstance(value, dict):
                raise StoreError("bad_connection",
                                 f"connection {key!r} must be a table, got "
                                 f"{type(value).__name__}")
            spec = {k: v for k, v in value.items() if k not in GRANT_FIELDS}
            grant = {k: value[k] for k in GRANT_FIELDS if k in value}

            def work(conn: Any) -> None:
                at = self._authority(conn, scope, None, actor)
                # A connection is one row for every agent and node, so a node
                # that writes only its own rows may add one, never change one
                # another node may use. One added as the agent's own is
                # granted to it in the same transaction.
                added = self._put_connection(conn, capability, key, spec, agent, own,
                                             change=at is None)
                if not added and at is not None:
                    raise StoreError(
                        "node_read_only",
                        f"node {self.node} may add a connection but not change "
                        f"{capability} connection {key!r}, which every node shares",
                        f"change it on the master {self.agent.get('master')}")
                wanted_grant = ({"enabled": True, **grant}
                                if added and own and agent is not None else grant)
                if wanted_grant:
                    fields, wanted = self._grant_value(key, wanted_grant)
                    if at is None:
                        at = self._landing(
                            conn, scope, wanted, actor, "capabilities_connection_grants",
                            agent, "capability = %s AND connection = %s", (capability, key))
                    self._put_grant_at(conn, capability, key, fields, agent, at)
            self._write(work)
            return None
        fields, wanted = self._grant_value(key, value)
        self._write(lambda conn: self._put_grant_at(
            conn, capability, key, fields, agent,
            self._landing(conn, scope, wanted, actor, "capabilities_connection_grants",
                          agent, "capability = %s AND connection = %s", (capability, key))))
        return None

    def delete(self, capability: str, collection: str, key: str,
               scope: str | None = None, node: str | None = None) -> bool:
        if collection not in self.collections:
            return FileRecords.delete(self, capability, collection, key,
                                      scope=scope, node=node)
        _only_policy_names_a_node(collection, node)
        _refuse_record_write(capability, collection)
        agent = self._agent(scope)
        if collection == "setting" and key != "connection.default":
            def drop(document: dict) -> dict:
                if key not in document:
                    # Nothing to remove leaves the document as it was, even
                    # one that does not exist yet.
                    raise _Unchanged()
                document.pop(key)
                return document
            try:
                self.settings_write(capability, scope or "project", drop)
            except _Unchanged:
                return False
            return True
        if collection == "setting":
            return bool(self._write(lambda conn: self._put_default_at(
                conn, capability, None, agent, self._landing(
                    conn, scope, None, None, "capabilities_connection_grants", agent,
                    "capability = %s AND is_default", (capability,)))))
        wanted = _node_check(node) if collection == "policy" else None
        if collection == "identifier":
            sql = ("DELETE FROM capabilities_identifiers "
                   "WHERE coalesce(agent_id, '') = coalesce(%s::text, '') AND capability = %s "
                   "AND label = %s AND coalesce(node, '') = coalesce(%s::text, '')")
            target = (agent, capability, key)
            own = ("capabilities_identifiers", "capability = %s AND label = %s",
                   (capability, key))
        elif collection == "policy":
            sql = ("DELETE FROM capabilities_policy "
                   "WHERE coalesce(agent_id, '') = coalesce(%s::text, '') AND capability = %s "
                   "AND coalesce(node, '') = coalesce(%s::text, '')")
            target = (agent, key)
            own = ("capabilities_policy", "capability = %s", (key,))
        elif collection == "grant":
            sql = ("DELETE FROM capabilities_connection_grants "
                   "WHERE coalesce(agent_id, '') = coalesce(%s::text, '') AND capability = %s "
                   "AND connection = %s AND coalesce(node, '') = coalesce(%s::text, '')")
            target = (agent, capability, key)
            own = ("capabilities_connection_grants", "capability = %s AND connection = %s",
                   (capability, key))
        else:
            def work(conn: Any) -> bool:
                if self._authority(conn, scope, None, None) is not None:
                    raise StoreError(
                        "node_read_only",
                        f"node {self.node} may not remove {capability} connection "
                        f"{key!r}, which every node shares",
                        f"remove it on the master {self.agent.get('master')}")
                return self._drop_connection(conn, capability, key, agent)
            return bool(self._write(work))
        return bool(self._write(lambda conn: conn.execute(
            sql, (*target, self._landing(conn, scope, wanted, None, own[0], agent, own[1],
                                          own[2]))).rowcount > 0))


def _upsert_policy(conn: Any, agent: str | None, capability: str, node: str | None,
                   enabled: bool) -> None:
    """Write one policy row. A row the agent writes for a node of its own places
    the capability's service there exactly when it enables the capability
    there, as `enable --node` and `disable --node` always have; `place` is what
    changes the one without the other."""
    conn.execute(
        "INSERT INTO capabilities_policy (agent_id, capability, node, enabled, service) "
        "VALUES (%s, %s, %s, %s, %s) "
        "ON CONFLICT ((coalesce(agent_id, '')), capability, (coalesce(node, ''))) "
        "DO UPDATE SET enabled = EXCLUDED.enabled, service = EXCLUDED.service, "
        "updated_at = now()",
        (agent, capability, node, enabled,
         bool(enabled and agent is not None and node is not None)))


def _only_policy_names_a_node(collection: str, node: Any) -> None:
    """A grant names its node inside its value; a policy row is the one record
    written for a node through `node`."""
    if node is not None and collection != "policy":
        raise StoreError("bad_node", f"a {collection} record is not written for a "
                         "node this way; only a policy row is")


def _stamp(moment: Any) -> str | None:
    """A row's time of writing as the text a report carries."""
    return moment.isoformat() if hasattr(moment, "isoformat") else moment


def _bound_project_id(root: Path) -> str | None:
    """The project's id where no caller resolved it: CAPABILITIES_PROJECT_ID
    from the process environment where CAPABILITIES_PROJECT_ID_ROOT names this
    root (one for another root, or one without a root, binds nothing here),
    else the one the root's .env.local, else its .env, sets. project.json
    holds no id."""
    handed = os.environ.get("CAPABILITIES_PROJECT_ID", "").strip()
    scope = os.environ.get("CAPABILITIES_PROJECT_ID_ROOT", "").strip()
    if handed and scope:
        try:
            if Path(scope).expanduser().resolve() == Path(root).resolve():
                return handed
        except OSError:
            pass
    for name in (".env.local", ".env"):
        try:
            lines = (Path(root) / name).read_text().splitlines()
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


def _identity_record(envelope: Path) -> dict[str, Any]:
    try:
        identity = json.loads((Path(envelope) / "project.json").read_text())
    except (OSError, ValueError):
        return {}
    return identity if isinstance(identity, dict) else {}


def _database_resolves(root: Path) -> bool:
    """Whether a database setting resolves for this project root - read from
    its env files, the environment and the machine's store setting, without
    reaching the database."""
    try:
        from capabilities_contract import db
    except ImportError:
        return False
    try:
        db.resolve_setting(root)
    except db.DbError as exc:
        return exc.slug != "store_not_configured"
    return True


def records_mode(envelope: Path | str, project_root: Path | str | None = None) -> str:
    """Where this project keeps its records, read without reaching the store.

    A `project.json`, while a project still has one, says it: `files` unless
    `"records": "store"`. Without one, a project that keeps its gate in a
    `settings.json` keeps its records in files, and a project bound to its id
    (CAPABILITIES_PROJECT_ID) for which a database resolves keeps them in the
    store; anything else keeps them in files. `project_root` is the folder
    the id and the database resolve for, the envelope's parent unless named."""
    envelope = Path(envelope)
    identity_file = envelope / "project.json"
    if identity_file.is_file():
        declared = _identity_record(envelope).get(RECORDS_MODE_KEY, "files")
        if declared not in RECORDS_MODES:
            raise StoreError("bad_records_mode",
                             f"{identity_file} declares records {declared!r}",
                             f"one of: {', '.join(RECORDS_MODES)}; the manager writes it")
        return declared
    if (envelope / "settings.json").is_file():
        return "files"
    root = Path(project_root) if project_root else envelope.parent
    if _bound_project_id(root) and _database_resolves(root):
        return "store"
    return "files"


def connections_mode(envelope: Path | str, project_root: Path | str | None = None) -> str:
    """Where this project keeps its connections and grants: `store` when its
    records are in the store or its `project.json` says `"connections":
    "store"`, `files` otherwise."""
    if records_mode(envelope, project_root) == "store":
        return "store"
    identity_file = Path(envelope) / "project.json"
    declared = _identity_record(Path(envelope)).get(CONNECTIONS_MODE_KEY, "files")
    if declared not in CONNECTIONS_MODES:
        raise StoreError("bad_connections_mode",
                         f"{identity_file} declares connections {declared!r}",
                         f"one of: {', '.join(CONNECTIONS_MODES)}; the manager writes it")
    return declared


def agent_slug(conn: Any, agent_id: str) -> str | None:
    """The agent's slug as its registry row holds it: None where the row has
    none, the store holds no such row, or its registry predates slugs."""
    import psycopg
    try:
        row = conn.execute(f"SELECT slug FROM {STORE_AGENTS_TABLE} WHERE id = %s",
                           (agent_id,)).fetchone()
    except (psycopg.errors.UndefinedTable, psycopg.errors.UndefinedColumn):
        conn.rollback()
        return None
    return row[0] if row and row[0] else None


def open_records(envelope: Path | str, global_dir: Path | str,
                 project_only: bool = False, project_root: Path | str | None = None,
                 project_id: str | None = None,
                 application_name: str = STORE_OWNER,
                 actor: str | None = None) -> Records:
    """The adapter this project's configuration is read and written through:
    the project's envelope, then `global_dir` unless `project_only`; in store
    mode a project's connections, grants, identifiers and policy come from its
    store instead (only its connections and grants where it moved only those),
    for the project id given (else CAPABILITIES_PROJECT_ID, as
    `_bound_project_id` reads it), its database resolved for `project_root`
    (else the envelope's parent).

    Where a database resolves, the agent's registry row decides first: an
    agent whose `migrated_at` is set reads and writes all its records and its
    settings in the store (`AgentRecords`), whatever `project.json` says, and
    only on a node it has registered, named by AGENT_NODE_NAME. Every other
    project is read as above. Asking cannot fail a project whose records are
    files: a store that does not answer within `_PROBE_TIMEOUT` leaves it on
    its files. A project in store mode whose store does not answer keeps the
    refusal for its settings, rather than reading files that may be stale.
    `actor` names a writer that is not the person running the command:
    `migrate` or `<capability>-service`.

    A `project.json` that declares a `store` other than `files` is refused
    rather than read as files, since the records it points at are not where it
    says."""
    envelope, global_dir = Path(envelope), Path(global_dir)
    identity_file = envelope / "project.json"
    identity = _identity_record(envelope)
    declared = identity.get("store", "files")
    if declared != "files":
        raise StoreError("bad_store_mode",
                         f"{identity_file} declares store {declared!r}; records are "
                         "kept only in files",
                         'remove "store" from project.json, or set it to "files"')
    root = Path(project_root) if project_root else None
    in_store = connections_mode(envelope, root) == "store"
    agent_id = project_id or _bound_project_id(root or envelope.parent)
    if in_store:
        held = (RECORDS_MODE_KEY if records_mode(envelope, root) == "store"
                else CONNECTIONS_MODE_KEY)
        legacy: Records = StoreRecords(
            envelope, global_dir, agent_id, identity.get("slug"),
            include_global=not project_only, project_root=root,
            application_name=application_name, held=held)
    else:
        legacy = FileRecords(envelope, global_dir, agent_id, identity.get("slug"),
                             include_global=not project_only)
    legacy._guard_agent = agent_id if isinstance(agent_id, str) and agent_id else None
    legacy._guard_root = root
    legacy._guard_application = application_name
    legacy._global_from = (root,)
    legacy.actor = actor
    if legacy._guard_agent is None:
        return legacy
    try:
        conn, schema = _store_connect(root or envelope.parent, application_name,
                                      None if in_store else _PROBE_TIMEOUT)
    except StoreError as exc:
        if in_store and exc.slug != "store_not_configured":
            legacy._settings_blocked = exc
        # No store answers: the references are the files, without asking again.
        legacy._references = {}
        legacy._references_failure = (None if exc.slug == "store_not_configured"
                                      else exc)
        return legacy
    import psycopg
    try:
        state = _agent_state(conn, agent_id)
        conn.rollback()
    except psycopg.Error as exc:
        try:
            conn.close()
        except Exception:
            pass
        if in_store:
            legacy._settings_blocked = StoreError(
                "store_unreachable", f"cannot read the agent registry: {exc}",
                "check the database setting with `capabilities store doctor`")
        return legacy
    conn.close()
    if not state or not state.get("migrated_at"):
        if in_store:
            legacy._schema = schema
        return legacy
    node = node_id()
    if node not in state["nodes"]:
        raise StoreError(
            "node_unregistered",
            f"agent {agent_id} keeps its records in the store, and node {node} is "
            "not one of its nodes", _master_hint(state))
    adapter = AgentRecords(envelope, global_dir, agent_id, identity.get("slug"),
                           agent=state, node=node, include_global=not project_only,
                           project_root=root, application_name=application_name,
                           actor=actor)
    adapter._guard_root = root
    adapter._guard_application = application_name
    adapter._schema = schema
    return adapter

