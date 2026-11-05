"""The core's step: the manager's tables as owner `core`, named as plain nouns.

Until schema version 1.23 the same tables were owner `capabilities`, named
`capabilities_*`, and their agent columns `project_id`. The core's first step
takes a store from wherever it stands to the core's shape in one transaction:

1. it replays each of the steps owner `capabilities` ever had (`_legacy`) that
   the store has not applied - every one, on a store that holds none - so every
   store stands at the last of them, whatever it held;
2. it renames each table to its core name, and every index, constraint,
   sequence, trigger and function named for one to the same name under the new
   table's, keeping every row; an agent column becomes `agent_id` and a
   connection's owner `owner_agent_id`;
3. it recreates every function whose body names a table or a column it renamed,
   and words every comment for the new names;
4. on a store that held them, it leaves a refusing stub under each old table
   name (`moved_stub`'s shape, made from the moved table's columns under their
   old names), so a release that still reads `capabilities_*` fails with what
   to run rather than reading no rows; a fresh store gets none;
5. it hands the books to the core: the ledger rows of owner `capabilities` become
   the core's, and owner `capabilities` keeps a row in `schema_version` at major
   2, so a release that still migrates owner `capabilities` refuses the store
   (`schema_too_new`) rather than making its tables again.

A store made before the core and a fresh store therefore end with the same
catalog, the stubs apart. The step raises the core to major 2, so outside the
store upgrade it is applied only to an empty store. Never edit the step once
released: a store holds its checksum.
"""

from __future__ import annotations

from capabilities_contract.db._legacy import LEGACY_OWNER, LEGACY_STEPS

CORE_STEP_ID = "0039-core"
CORE_MAJOR, CORE_MINOR = 2, 0

# Each table of owner `capabilities` and the core's name for it. A pre-image the
# manager kept (`capabilities_premig_*`, made outside these steps) moves with the
# prefix, where the store holds one.
CORE_RENAMES: tuple[tuple[str, str], ...] = (
    ("capabilities_agents", "agents"),
    ("capabilities_nodes", "nodes"),
    ("capabilities_agent_nodes", "agent_nodes"),
    ("capabilities_node_states", "node_states"),
    ("capabilities_node_updates", "node_updates"),
    ("capabilities_node_logins", "node_logins"),
    ("capabilities_node_login_expectations", "node_login_expectations"),
    ("capabilities_node_logs", "node_logs"),
    ("capabilities_node_sessions", "node_sessions"),
    ("capabilities_node_session_expectations", "node_session_expectations"),
    ("capabilities_connections", "connections"),
    ("capabilities_connection_grants", "grants"),
    ("capabilities_policy", "policies"),
    ("capabilities_settings", "settings"),
    ("capabilities_settings_changes", "settings_changes"),
    ("capabilities_settings_documents", "settings_documents"),
    ("capabilities_identifiers", "identifiers"),
    ("capabilities_vault", "secrets"),
    ("capabilities_service_instances", "service_instances"),
    ("capabilities_service_leases", "service_leases"),
    ("capabilities_global", "store_state"),
    ("capabilities_references", "reference_versions"),
)
PREIMAGE_RENAME = ("capabilities_premig", "core_premig")

# The tables whose agent column was `project_id`.
AGENT_ID_TABLES = (
    "node_login_expectations", "node_logins", "node_logs", "node_session_expectations",
    "node_sessions", "reference_versions", "service_instances", "service_leases",
)


def _replay() -> str:
    """Each legacy step the store's ledger does not record, run in order."""
    lines = ["DO $replay$ BEGIN"]
    for step_id, sql in LEGACY_STEPS:
        tag = "$legacy" + "".join(ch for ch in step_id if ch.isalnum()) + "$"
        assert tag not in sql and "$replay$" not in sql
        lines.append(f" IF NOT EXISTS (SELECT 1 FROM schema_ledger WHERE owner = '{LEGACY_OWNER}'"
                     f" AND step = '{step_id}') THEN")
        lines.append(f"  EXECUTE {tag}{sql}{tag};")
        lines.append(" END IF;")
    lines.append("END $replay$;")
    return "\n".join(lines)


def _array(values: list[str]) -> str:
    return "ARRAY[" + ", ".join(f"'{v}'" for v in values) + "]"


def _rename() -> str:
    """Every table, column, constraint, index, sequence, trigger and function of
    owner `capabilities` moved to the core's name."""
    pairs = sorted((*CORE_RENAMES, PREIMAGE_RENAME), key=lambda p: -len(p[0]))
    olds, news = _array([p[0] for p in pairs]), _array([p[1] for p in pairs])
    tables = _array([new for _old, new in CORE_RENAMES])
    columns = "\n".join(f" ALTER TABLE {table} RENAME COLUMN project_id TO agent_id;"
                        for table in AGENT_ID_TABLES)
    return f"""DO $rename$
DECLARE
 olds text[] := {olds};
 news text[] := {news};
 core text[] := {tables};
 r record;
 renamed text;
BEGIN
 FOR i IN 1 .. array_length(olds, 1) LOOP
  IF olds[i] <> '{PREIMAGE_RENAME[0]}' THEN
   EXECUTE format('ALTER TABLE %I RENAME TO %I', olds[i], news[i]);
  END IF;
 END LOOP;
 FOR r IN SELECT c.relname FROM pg_class c
   WHERE c.relnamespace = current_schema()::regnamespace AND c.relkind IN ('r', 'p')
   AND starts_with(c.relname, '{PREIMAGE_RENAME[0]}_') ORDER BY c.relname LOOP
  EXECUTE format('ALTER TABLE %I RENAME TO %I', r.relname,
   '{PREIMAGE_RENAME[1]}' || substr(r.relname, length('{PREIMAGE_RENAME[0]}') + 1));
  core := core || ('{PREIMAGE_RENAME[1]}' || substr(r.relname, length('{PREIMAGE_RENAME[0]}') + 1));
 END LOOP;
{columns}
 ALTER TABLE connections RENAME COLUMN owner TO owner_agent_id;
 FOR r IN
  SELECT 'constraint' AS kind, o.conname AS name, t.relname AS tab, NULL::regprocedure AS fn
   FROM pg_constraint o JOIN pg_class t ON t.oid = o.conrelid
   WHERE t.relnamespace = current_schema()::regnamespace AND t.relname = ANY (core)
   AND starts_with(o.conname, 'capabilities_')
  UNION ALL
  SELECT 'trigger', g.tgname, t.relname, NULL
   FROM pg_trigger g JOIN pg_class t ON t.oid = g.tgrelid
   WHERE NOT g.tgisinternal AND t.relnamespace = current_schema()::regnamespace
   AND t.relname = ANY (core) AND starts_with(g.tgname, 'capabilities_')
  UNION ALL
  SELECT 'function', p.proname, NULL, p.oid::regprocedure
   FROM pg_proc p WHERE p.pronamespace = current_schema()::regnamespace
   AND starts_with(p.proname, 'capabilities_')
  ORDER BY 1, 2
 LOOP
  SELECT m.new || substr(r.name, length(m.old) + 1) INTO renamed
   FROM unnest(olds, news) AS m (old, new)
   WHERE r.name = m.old OR starts_with(r.name, m.old || '_')
   ORDER BY length(m.old) DESC LIMIT 1;
  CONTINUE WHEN renamed IS NULL;
  renamed := replace(renamed, '_project_id', '_agent_id');
  IF renamed = 'connections_owner_check' THEN
   renamed := 'connections_owner_agent_id_check';
  END IF;
  IF r.kind = 'constraint' THEN
   EXECUTE format('ALTER TABLE %I RENAME CONSTRAINT %I TO %I', r.tab, r.name, renamed);
  ELSIF r.kind = 'trigger' THEN
   EXECUTE format('ALTER TRIGGER %I ON %I RENAME TO %I', r.name, r.tab, renamed);
  ELSE
   EXECUTE format('ALTER FUNCTION %s RENAME TO %I', r.fn, renamed);
  END IF;
 END LOOP;
 FOR r IN
  SELECT c.relname AS name, c.relkind AS kind FROM pg_class c
   WHERE c.relnamespace = current_schema()::regnamespace AND c.relkind IN ('i', 'S')
   AND starts_with(c.relname, 'capabilities_') ORDER BY 1
 LOOP
  SELECT m.new || substr(r.name, length(m.old) + 1) INTO renamed
   FROM unnest(olds, news) AS m (old, new)
   WHERE starts_with(r.name, m.old || '_')
   ORDER BY length(m.old) DESC LIMIT 1;
  CONTINUE WHEN renamed IS NULL;
  renamed := replace(renamed, '_project_id', '_agent_id');
  IF r.kind = 'i' THEN
   EXECUTE format('ALTER INDEX %I RENAME TO %I', r.name, renamed);
  ELSE
   EXECUTE format('ALTER SEQUENCE %I RENAME TO %I', r.name, renamed);
  END IF;
 END LOOP;
 FOR r IN
  SELECT d.objoid, d.objsubid, d.description, t.relname, a.attname
   FROM pg_description d JOIN pg_class t ON t.oid = d.objoid
   LEFT JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = d.objsubid
   WHERE d.classoid = 'pg_class'::regclass AND t.relnamespace = current_schema()::regnamespace
   AND t.relname = ANY (core) AND d.description ~ 'capabilities_'
 LOOP
  renamed := r.description;
  FOR i IN 1 .. array_length(olds, 1) LOOP
   renamed := regexp_replace(renamed, '\\m' || olds[i] || '\\M', news[i], 'g');
  END LOOP;
  CONTINUE WHEN renamed = r.description;
  IF r.objsubid = 0 THEN
   EXECUTE format('COMMENT ON TABLE %I IS %L', r.relname, renamed);
  ELSE
   EXECUTE format('COMMENT ON COLUMN %I.%I IS %L', r.relname, r.attname, renamed);
  END IF;
 END LOOP;
END $rename$;"""


# Every function whose body names a table, a column or a lock key that moved,
# recreated under its new name with the body naming the new ones. The channel
# names stay: `capabilities_vault` and `capabilities_node_update`.
_FUNCTIONS = """\
CREATE OR REPLACE FUNCTION settings_guard() RETURNS trigger
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $guard$
BEGIN
 IF jsonb_typeof(NEW.value) = 'object' AND NEW.value <> '{}'::jsonb THEN
  RAISE EXCEPTION 'setting % holds an object with keys; a row holds a scalar, an array or {}',
   array_to_string(NEW.path, '.') USING ERRCODE = 'check_violation';
 END IF;
 IF EXISTS (SELECT 1 FROM settings s
  WHERE coalesce(s.agent_id, '') = coalesce(NEW.agent_id, '')
  AND s.capability = NEW.capability
  AND coalesce(s.node, '') = coalesce(NEW.node, '')
  AND s.path <> NEW.path
  AND (s.path[1:cardinality(NEW.path)] = NEW.path
   OR NEW.path[1:cardinality(s.path)] = s.path)) THEN
  RAISE EXCEPTION 'setting % overlaps another row of its document: a path never prefixes another',
   array_to_string(NEW.path, '.') USING ERRCODE = 'check_violation';
 END IF;
 RETURN NEW;
END $guard$;
CREATE OR REPLACE FUNCTION settings_changes_append_only() RETURNS trigger
 LANGUAGE plpgsql AS $trail$
BEGIN
 RAISE EXCEPTION 'settings_changes is append-only' USING ERRCODE = 'restrict_violation';
END $trail$;
CREATE OR REPLACE FUNCTION grants_owner() RETURNS trigger
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $owner$
DECLARE held text;
BEGIN
 SELECT owner_agent_id INTO held FROM connections
  WHERE capability = NEW.capability AND name = NEW.connection;
 IF held IS NOT NULL AND NEW.agent_id IS DISTINCT FROM held THEN
  RAISE EXCEPTION '% connection % is agent %''s own and is granted to no other agent',
   NEW.capability, NEW.connection, held USING ERRCODE = 'check_violation';
 END IF;
 RETURN NEW;
END $owner$;
CREATE OR REPLACE FUNCTION connections_owner() RETURNS trigger
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $owner$
BEGIN
 IF NEW.owner_agent_id IS NOT NULL AND EXISTS (SELECT 1 FROM grants
  WHERE capability = OLD.capability AND connection = OLD.name
  AND agent_id IS DISTINCT FROM NEW.owner_agent_id) THEN
  RAISE EXCEPTION
   '% connection % is granted to agents other than %, so it cannot be that agent''s own',
   OLD.capability, OLD.name, NEW.owner_agent_id USING ERRCODE = 'check_violation';
 END IF;
 RETURN NEW;
END $owner$;
CREATE OR REPLACE FUNCTION agent_nodes_node_fields() RETURNS trigger
 LANGUAGE plpgsql AS $fields$
BEGIN
 EXECUTE format('SELECT kind, address, target, last_seen_at, coolify_connection,
  coolify_server, coolify_resource, public_key FROM %I.nodes WHERE id = $1', tg_table_schema)
 INTO NEW.kind, NEW.address, NEW.target, NEW.last_seen_at, NEW.coolify_connection,
  NEW.coolify_server, NEW.coolify_resource, NEW.public_key
 USING NEW.node;
 RETURN NEW;
END $fields$;
CREATE OR REPLACE FUNCTION nodes_to_links() RETURNS trigger
 LANGUAGE plpgsql AS $links$
BEGIN
 EXECUTE format('UPDATE %I.agent_nodes SET node = node WHERE node = $1
  AND (kind, address, target, last_seen_at, coolify_connection, coolify_server,
   coolify_resource, public_key) IS DISTINCT FROM ($2, $3, $4, $5, $6, $7, $8, $9)',
  tg_table_schema)
 USING NEW.id, NEW.kind, NEW.address, NEW.target, NEW.last_seen_at,
  NEW.coolify_connection, NEW.coolify_server, NEW.coolify_resource, NEW.public_key;
 RETURN NULL;
END $links$;
CREATE OR REPLACE FUNCTION secrets_announce() RETURNS trigger
 LANGUAGE plpgsql AS $announce$
DECLARE agent text;
BEGIN
 IF tg_table_name = 'agents' THEN agent := new.id;
 ELSIF tg_op = 'DELETE' THEN agent := old.agent_id;
 ELSE agent := new.agent_id; END IF;
 IF to_regclass(format('%I.schema_channel', tg_table_schema)) IS NOT NULL THEN
  EXECUTE format('INSERT INTO %I.schema_channel AS c (channel, scope, version)
   VALUES (%L, $1, 1) ON CONFLICT (channel, scope) DO UPDATE SET version = c.version + 1',
   tg_table_schema, 'capabilities_vault') USING agent;
 END IF;
 RETURN NULL;
END $announce$;
CREATE OR REPLACE FUNCTION connections_label() RETURNS trigger
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $label$
BEGIN
 IF TG_OP = 'UPDATE' AND NEW.name IS DISTINCT FROM OLD.name THEN
  RAISE EXCEPTION '% connection % keeps its id; its label is what is renamed',
   OLD.capability, OLD.name USING ERRCODE = 'check_violation';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtext('connections:' || NEW.capability));
 IF EXISTS (SELECT 1 FROM connections
  WHERE capability = NEW.capability AND name <> NEW.name
  AND (label = NEW.name OR name = NEW.label OR label = NEW.label)) THEN
  RAISE EXCEPTION '% connection % or its label % is already another connection''s id or label',
   NEW.capability, NEW.name, NEW.label USING ERRCODE = 'unique_violation';
 END IF;
 RETURN NEW;
END $label$;
CREATE OR REPLACE FUNCTION agents_kind() RETURNS trigger
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $kind$
BEGIN
 IF TG_OP = 'UPDATE' AND OLD.kind = 'system' AND NEW.kind <> 'system' THEN
  RAISE EXCEPTION 'agent % is a system agent and stays one', OLD.id
   USING ERRCODE = 'check_violation';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtext('agents:kind'));
 IF NEW.slug IS NOT NULL AND EXISTS (SELECT 1 FROM agents
  WHERE slug = NEW.slug AND id <> NEW.id
  AND (kind = 'agent' OR NEW.kind = 'agent')) THEN
  RAISE EXCEPTION 'slug % is already another agent''s', NEW.slug
   USING ERRCODE = 'unique_violation';
 END IF;
 IF NEW.kind = 'system' AND (TG_OP = 'INSERT' OR OLD.kind <> 'system') THEN
  IF (SELECT count(*) FROM agent_nodes WHERE agent_id = NEW.id) > 1 THEN
   RAISE EXCEPTION 'agent % lives on more than one node, and a system agent lives on one',
    NEW.id USING ERRCODE = 'check_violation';
  END IF;
  IF EXISTS (SELECT 1 FROM agent_nodes l
   JOIN agent_nodes o ON o.node = l.node AND o.agent_id <> l.agent_id
   JOIN agents a ON a.id = o.agent_id AND a.kind = 'system'
   WHERE l.agent_id = NEW.id) THEN
   RAISE EXCEPTION 'the node of agent % already holds a system agent', NEW.id
    USING ERRCODE = 'unique_violation';
  END IF;
 END IF;
 RETURN NEW;
END $kind$;
CREATE OR REPLACE FUNCTION agent_nodes_system() RETURNS trigger
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $system$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM agents WHERE id = NEW.agent_id AND kind = 'system') THEN
  RETURN NEW;
 END IF;
 PERFORM pg_advisory_xact_lock(hashtext('agents:kind'));
 IF EXISTS (SELECT 1 FROM agent_nodes
  WHERE agent_id = NEW.agent_id AND node <> NEW.node
  AND (TG_OP = 'INSERT' OR node <> OLD.node)) THEN
  RAISE EXCEPTION 'agent % is a system agent, which lives on one node',
   NEW.agent_id USING ERRCODE = 'check_violation';
 END IF;
 IF EXISTS (SELECT 1 FROM agent_nodes l
  JOIN agents a ON a.id = l.agent_id AND a.kind = 'system'
  WHERE l.node = NEW.node AND l.agent_id <> NEW.agent_id) THEN
  RAISE EXCEPTION 'node % already holds a system agent', NEW.node
   USING ERRCODE = 'unique_violation';
 END IF;
 RETURN NEW;
END $system$;"""

# The comments that named the agent a project, worded for the agent; every
# other comment only had its table names moved.
_COMMENTS = """\
COMMENT ON TABLE agents IS 'The agent registry: one row per agent, keyed by its id
 (CAPABILITIES_PROJECT_ID). Written by the capabilities manager alone.';
COMMENT ON COLUMN agents.id IS 'The agent''s id, CAPABILITIES_PROJECT_ID (prj_<12 hex>, or an
 older UUID).';
COMMENT ON COLUMN agents.body_root IS 'The folder inside the agent''s folder that holds its
 body - its context, assets, routines and capabilities layers - as a relative path such as
 agent; null where the body sits at the agent''s folder itself.';
COMMENT ON COLUMN agent_nodes.folder IS 'The folder the agent lives in on this node, as an
 absolute path such as /app; null where it is not recorded. One folder on a node is one
 agent''s.';
COMMENT ON TABLE node_states IS 'What each node says of itself: one row per machine, written
 by that machine''s capabilities manager alone on a short beat and when it changes. The row
 belongs to the machine and is shared by every agent on it, as its row in nodes is, so it
 carries no agent. Read it directly: the node is reachable while fresh_until has not passed.';
COMMENT ON TABLE node_updates IS 'One row per update run of a node: asked for by anyone
 (requested), taken up by the node''s own capabilities manager (running), and its outcome. The
 row is the machine''s, as its row in nodes is, so it carries no agent. At most one row per
 node is requested or running; each change raises the version of channel
 capabilities_node_update for the node in schema_channel.';
COMMENT ON TABLE reference_versions IS 'Every version of each capability''s references for an
 agent: the file capabilities/<capability>/reference/<name>.md as a row. A reference with an
 active version is read from here before the agent''s files; one with none is retired.
 Immutable but for active, which a save clears as it adds the next.';
COMMENT ON COLUMN reference_versions.agent_id IS 'The agent''s id.';
COMMENT ON TABLE service_instances IS 'What each node actually runs: one row per (agent,
 capability, node) while something on that node supervises the service, deleted when it stops
 supervising it. Placement says where a service should run and the lease which node may run an
 exclusive one; this row says what runs and whether it works.';
COMMENT ON COLUMN service_instances.agent_id IS 'The agent''s id.';"""
_COMMENTS = _COMMENTS.replace("\n ", " ")  # each comment is one line

# The text every read of a stub fails with: where the table went and what to run.
STUB_MESSAGE = ("the store's core moved to schema major {major}: {old} is now {new}, and this "
                "code reads an older major; run `capabilities self-update`, then "
                "`capabilities update`")


# The legacy tables the store held when the step began, so a stub is left only
# under a name that held a table, never under one the replay made.
_HELD = "capabilities_contract.core_held"
_HOLD = (f"SELECT set_config('{_HELD}', coalesce(string_agg(c.relname, ','), ''), true)"
         " FROM pg_class c WHERE c.relnamespace = current_schema()::regnamespace"
         " AND c.relkind IN ('r', 'p') AND starts_with(c.relname, 'capabilities_');")


def _stubs() -> str:
    """A refusing stub under each moved table's old name the store held when the
    step began: a view with the old columns, under their old names and types,
    holding no data, whose every read fails with `STUB_MESSAGE` and which takes
    no write. A fresh store held none and gets none."""
    olds = _array([old for old, _new in CORE_RENAMES])
    news = _array([new for _old, new in CORE_RENAMES])
    agent_tables = _array(list(AGENT_ID_TABLES))
    message = STUB_MESSAGE.format(major=CORE_MAJOR, old="%s", new="%s").replace("'", "''")
    return f"""DO $stubs$
DECLARE
 olds text[] := {olds};
 news text[] := {news};
 held text[] := string_to_array(current_setting('{_HELD}'), ',');
 agent_tables text[] := {agent_tables};
 cols text;
BEGIN
 FOR i IN 1 .. array_length(olds, 1) LOOP
  CONTINUE WHEN NOT olds[i] = ANY (held);
  SELECT string_agg(format('CAST(NULL AS %s) AS %I', format_type(a.atttypid, a.atttypmod),
    CASE WHEN a.attname = 'agent_id' AND news[i] = ANY (agent_tables) THEN 'project_id'
     WHEN news[i] = 'connections' AND a.attname = 'owner_agent_id' THEN 'owner'
     ELSE a.attname END), ', ' ORDER BY a.attnum) INTO cols
   FROM pg_attribute a
   WHERE a.attrelid = format('%I.%I', current_schema(), news[i])::regclass
   AND a.attnum > 0 AND NOT a.attisdropped;
  EXECUTE format('CREATE VIEW %I AS SELECT %s WHERE CAST(CAST(%L AS text) AS integer) IS NULL',
   olds[i], cols, format('{message}', olds[i], news[i]));
 END LOOP;
END $stubs$;"""


# The ledger's history and the version of owner `capabilities` are the core's
# now; owner `capabilities` stays at major 2, where no release that migrates it
# goes on.
_BOOKS = f"""\
UPDATE schema_ledger SET owner = 'core' WHERE owner = '{LEGACY_OWNER}';
INSERT INTO schema_version (owner, major, minor) VALUES ('{LEGACY_OWNER}', {CORE_MAJOR}, 0)
 ON CONFLICT (owner) DO UPDATE SET major = EXCLUDED.major, minor = EXCLUDED.minor,
 updated_at = now();"""

# A release that migrates owner `capabilities` holds that owner's lock while it
# applies a step; the core's step waits for it, so the two never interleave.
_LOCK = (f"SELECT pg_advisory_xact_lock(hashtextextended('capabilities_contract:' ||"
         f" current_schema() || ':{LEGACY_OWNER}', 0));")

CORE_STEP_SQL = "\n".join((_LOCK, _HOLD, _replay(), _rename(), _FUNCTIONS, _COMMENTS, _stubs(),
                           _BOOKS))
