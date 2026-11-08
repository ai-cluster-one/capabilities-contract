"""The core's third step: every agent, node and connection reference is a
foreign key that says what its parent takes with it, and the store enforces
that an id never changes and that a parent is deleted only on purpose.

Until core 4.0 only `agent_nodes` and the `node_*` tables held a foreign key to
an agent or a node, each `ON UPDATE CASCADE ON DELETE CASCADE`, and every
other agent or node column held the id by value. This step, in one
transaction:

1. gives the store the functions every owner's step and guard uses
   (`store_state_*`, below);
2. guards `agents.id` and `nodes.id` against an update, as `connections.id`
   already is, and makes `agents`, `nodes` and `connections` refuse a
   `DELETE` unless the transaction-local setting `store.deleting_agent`,
   `store.deleting_node` or `store.deleting_connection` names the row (a
   connection is also deleted with the agent that owns it);
3. lets the core's own history guards (`settings_changes`,
   `reference_versions`) admit the cascade of such a delete and nothing else,
   and keeps the vault's announcement quiet under it;
4. keys every core agent and node column by its class (`store_state_keys`):
   an owned row goes with its agent or node (`ON DELETE CASCADE`), a recorded
   fact keeps its row and loses the pointer (`ON DELETE SET NULL`). The keys
   that said `ON UPDATE CASCADE` are made again without it. A reference that
   names an agent or a node the store no longer holds is settled first by the
   same class, every row it changes kept in `core_premig_m9`.

The step raises the core to major 4, so outside the store upgrade it is
applied only to an empty store. Never edit the step once released: a store
holds its checksum, and the functions it makes are the ones every owner's
step and guard calls.
"""

from __future__ import annotations

STEP_ID = "0041-keys"
MAJOR, MINOR = 4, 0

# The transaction-local settings that name what is being deleted, each a
# comma-separated list of ids. Only the manager's removal verbs set them.
DELETING_SETTINGS = {
    "agents": "store.deleting_agent",
    "nodes": "store.deleting_node",
    "connections": "store.deleting_connection",
}

# Each core column that names an agent or a node, with its parent and the
# class rule 3 gives it.
CORE_KEYS: tuple[tuple[str, str, str, str], ...] = (
    ("agent_nodes", "agent_id", "agents", "cascade"),
    ("connections", "owner_agent_id", "agents", "cascade"),
    ("grants", "agent_id", "agents", "cascade"),
    ("identifiers", "agent_id", "agents", "cascade"),
    ("node_login_expectations", "agent_id", "agents", "cascade"),
    ("node_logins", "agent_id", "agents", "cascade"),
    ("node_logs", "agent_id", "agents", "cascade"),
    ("node_session_expectations", "agent_id", "agents", "cascade"),
    ("node_sessions", "agent_id", "agents", "cascade"),
    ("policies", "agent_id", "agents", "cascade"),
    ("reference_versions", "agent_id", "agents", "cascade"),
    ("secrets", "agent_id", "agents", "cascade"),
    ("service_instances", "agent_id", "agents", "cascade"),
    ("service_leases", "agent_id", "agents", "cascade"),
    ("settings", "agent_id", "agents", "cascade"),
    ("settings_changes", "agent_id", "agents", "cascade"),
    ("settings_documents", "agent_id", "agents", "cascade"),
    ("agent_nodes", "node", "nodes", "cascade"),
    ("node_states", "node", "nodes", "cascade"),
    ("node_updates", "node", "nodes", "cascade"),
    ("node_logins", "node", "nodes", "cascade"),
    ("node_login_expectations", "node", "nodes", "cascade"),
    ("node_logs", "node", "nodes", "cascade"),
    ("node_sessions", "node", "nodes", "cascade"),
    ("node_session_expectations", "node", "nodes", "cascade"),
    ("policies", "node", "nodes", "cascade"),
    ("settings", "node", "nodes", "cascade"),
    ("settings_documents", "node", "nodes", "cascade"),
    ("identifiers", "node", "nodes", "cascade"),
    ("grants", "node", "nodes", "cascade"),
    ("service_instances", "node", "nodes", "cascade"),
    ("service_leases", "node", "nodes", "cascade"),
    ("settings_changes", "node", "nodes", "set null"),
)


def keys_array(keys: tuple[tuple[str, str, str, str], ...] | list) -> str:
    """`keys` as the SQL text array `store_state_keys` takes."""
    rows = ", ".join("ARRAY[" + ", ".join(f"'{v}'" for v in key) + "]" for key in keys)
    return f"ARRAY[{rows}]"


# What every owner's step and guard calls. Each sets its search path to the
# schema it is made in, so a guard reaches it as `<schema>.store_state_*`
# whatever the caller's path.
_FUNCTIONS = r"""
CREATE FUNCTION store_state_deleting() RETURNS boolean
 LANGUAGE sql STABLE AS $deleting$
 SELECT coalesce(current_setting('store.deleting_agent', true), '') <> ''
  OR coalesce(current_setting('store.deleting_node', true), '') <> ''
  OR coalesce(current_setting('store.deleting_connection', true), '') <> ''
$deleting$;
COMMENT ON FUNCTION store_state_deleting() IS 'Whether this transaction deletes an agent, a
 node or a connection on purpose: store.deleting_agent, store.deleting_node or
 store.deleting_connection names one. A notify trigger of a table such a delete cascades into
 stays quiet while it does.';
CREATE FUNCTION store_state_named(parent text, id text) RETURNS boolean
 LANGUAGE sql STABLE AS $named$
 SELECT id IS NOT NULL AND id = ANY (string_to_array(coalesce(current_setting(CASE parent
  WHEN 'agents' THEN 'store.deleting_agent' WHEN 'nodes' THEN 'store.deleting_node'
  WHEN 'connections' THEN 'store.deleting_connection' END, true), ''), ','))
$named$;
COMMENT ON FUNCTION store_state_named(text, text) IS 'Whether the deleting setting of
 parent (agents, nodes or connections) names id in this transaction.';
CREATE FUNCTION store_state_cascade(tab text, op text, o jsonb, n jsonb) RETURNS boolean
 LANGUAGE plpgsql VOLATILE SET search_path FROM CURRENT AS $cascade$
DECLARE
 k record;
 col text;
 gone boolean;
BEGIN
 IF NOT store_state_deleting() THEN
  RETURN false;
 END IF;
 IF op = 'DELETE' THEN
  FOR k IN SELECT a.attname AS col, p.relname AS parent FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid JOIN pg_class p ON p.oid = c.confrelid
    JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
    WHERE c.contype = 'f' AND c.confdeltype = 'c' AND cardinality(c.conkey) = 1
    AND t.relname = tab AND t.relnamespace = current_schema()::regnamespace LOOP
   IF o ->> k.col IS NULL THEN
    CONTINUE;
   END IF;
   IF k.parent IN ('agents', 'nodes', 'connections') THEN
    IF store_state_named(k.parent, o ->> k.col) THEN
     RETURN true;
    END IF;
   ELSE
    EXECUTE format('SELECT NOT EXISTS (SELECT 1 FROM %I WHERE id::text = $1)', k.parent)
     INTO gone USING o ->> k.col;
    IF gone THEN
     RETURN true;
    END IF;
   END IF;
  END LOOP;
  RETURN false;
 END IF;
 IF op <> 'UPDATE' OR o IS NULL OR n IS NULL OR o = n THEN
  RETURN false;
 END IF;
 FOR col IN SELECT e.key FROM jsonb_each(n) e WHERE e.value IS DISTINCT FROM o -> e.key LOOP
  IF n ->> col IS NOT NULL THEN
   RETURN false;
  END IF;
  SELECT p.relname AS parent INTO k FROM pg_constraint c
   JOIN pg_class t ON t.oid = c.conrelid JOIN pg_class p ON p.oid = c.confrelid
   JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
   WHERE c.contype = 'f' AND c.confdeltype = 'n' AND cardinality(c.conkey) = 1
   AND t.relname = tab AND t.relnamespace = current_schema()::regnamespace AND a.attname = col;
  IF NOT FOUND THEN
   RETURN false;
  END IF;
  IF k.parent IN ('agents', 'nodes', 'connections') THEN
   IF NOT store_state_named(k.parent, o ->> col) THEN
    RETURN false;
   END IF;
  ELSE
   EXECUTE format('SELECT NOT EXISTS (SELECT 1 FROM %I WHERE id::text = $1)', k.parent)
    INTO gone USING o ->> col;
   IF NOT gone THEN
    RETURN false;
   END IF;
  END IF;
 END LOOP;
 RETURN true;
END $cascade$;
COMMENT ON FUNCTION store_state_cascade(text, text, jsonb, jsonb) IS 'Whether a DELETE or an
 UPDATE of a row of tab (its old and new row as jsonb) is the cascade of deleting an agent, a
 node or a connection on purpose, and nothing else: a delete through a cascading key whose
 parent the deleting setting names, or whose parent row is gone; an update that only sets
 null the columns of set-null keys whose parent is named or gone. A guard that refuses every
 other delete or edit of its rows admits exactly these.';
CREATE FUNCTION store_state_capture() RETURNS trigger
 LANGUAGE plpgsql AS $capture$
BEGIN
 EXECUTE format('INSERT INTO %I.%I (source, op, row) VALUES ($1, $2, $3)', tg_table_schema,
  current_setting('store.premig')) USING tg_table_name, lower(tg_op), to_jsonb(old);
 RETURN NULL;
END $capture$;
COMMENT ON FUNCTION store_state_capture() IS 'Keeps the row a step changes or deletes, as it
 was, in the pre-image table store.premig names. store_state_keys attaches it while it
 settles references, and removes it again.';
CREATE FUNCTION store_state_keys(owner text, keys text[]) RETURNS void
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $keys$
DECLARE
 premig text := owner || '_premig_m9';
 tab text;
 col text;
 parent text;
 act text;
 con text;
 names text[] := '{}';
 gone text[];
 agents_gone text[] := '{}';
 nodes_gone text[] := '{}';
 connections_gone text[] := '{}';
 r record;
BEGIN
 EXECUTE format('CREATE TABLE IF NOT EXISTS %I (source text NOT NULL, op text NOT NULL
  CONSTRAINT %I CHECK (op IN (''update'', ''delete'')), row jsonb NOT NULL,
  saved_at timestamptz NOT NULL DEFAULT now())', premig, premig || '_op_check');
 EXECUTE format('COMMENT ON TABLE %I IS %L', premig, 'The pre-image of the 2026-11 foreign
 key step of ' || owner || ': every row the step deleted or changed because it named an agent
 or a node the store no longer held, as it was (op delete or update, source the table it was
 in). Written by that step alone; restored by primary key.');
 FOR i IN 1 .. coalesce(array_length(keys, 1), 0) LOOP
  tab := keys[i][1]; col := keys[i][2]; parent := keys[i][3]; act := keys[i][4];
  IF act NOT IN ('cascade', 'set null', 'restrict') THEN
   RAISE EXCEPTION 'key %.% has no class %', tab, col, act;
  END IF;
  con := NULL;
  FOR r IN SELECT c.conname FROM pg_constraint c JOIN pg_attribute a
    ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
    WHERE c.conrelid = format('%I', tab)::regclass AND c.contype = 'f'
    AND cardinality(c.conkey) = 1 AND a.attname = col LOOP
   con := r.conname;
   EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', tab, con);
  END LOOP;
  con := coalesce(con, left(tab || '_' || col || '_fkey', 63));
  names := names || con;
  IF act = 'set null' THEN
   EXECUTE format('ALTER TABLE %I ALTER COLUMN %I DROP NOT NULL', tab, col);
  END IF;
  EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (%I) REFERENCES %I (id)
   ON DELETE %s NOT VALID', tab, con, col, parent, upper(act));
  EXECUTE format('SELECT coalesce(array_agg(DISTINCT t.%I::text ORDER BY t.%I::text), ''{}'')
   FROM %I t WHERE t.%I IS NOT NULL AND NOT EXISTS (SELECT 1 FROM %I p WHERE p.id = t.%I)',
   col, col, tab, col, parent, col) INTO gone;
  IF cardinality(gone) = 0 THEN
   CONTINUE;
  END IF;
  IF act = 'restrict' THEN
   RAISE EXCEPTION '%.% pins rows to % the store does not hold: %', tab, col, parent,
    array_to_string(gone, ', ') USING ERRCODE = 'foreign_key_violation',
    HINT = 'pin each to a registered one, or clear the pin of a row that never runs';
  ELSIF parent = 'agents' THEN
   agents_gone := agents_gone || gone;
  ELSIF parent = 'nodes' THEN
   nodes_gone := nodes_gone || gone;
  ELSIF parent = 'connections' THEN
   connections_gone := connections_gone || gone;
  ELSE
   RAISE EXCEPTION '%.% names rows of % the store does not hold: %', tab, col, parent,
    array_to_string(gone, ', ') USING ERRCODE = 'foreign_key_violation';
  END IF;
 END LOOP;
 IF cardinality(agents_gone) + cardinality(nodes_gone) + cardinality(connections_gone) > 0 THEN
  PERFORM set_config('store.deleting_agent', array_to_string(ARRAY(SELECT DISTINCT unnest(
   agents_gone)), ','), true);
  PERFORM set_config('store.deleting_node', array_to_string(ARRAY(SELECT DISTINCT unnest(
   nodes_gone)), ','), true);
  PERFORM set_config('store.deleting_connection', array_to_string(ARRAY(SELECT DISTINCT
   unnest(connections_gone)), ','), true);
  PERFORM set_config('store.premig', premig, true);
  FOR r IN SELECT c.relname FROM pg_class c WHERE c.relnamespace = current_schema()::regnamespace
    AND c.relkind IN ('r', 'p') AND NOT c.relispartition AND c.relname NOT LIKE '%\_premig\_%'
    AND c.relname NOT LIKE 'schema\_%' ORDER BY c.relname LOOP
   EXECUTE format('CREATE TRIGGER store_state_capture AFTER UPDATE OR DELETE ON %I
    FOR EACH ROW EXECUTE FUNCTION store_state_capture()', r.relname);
  END LOOP;
  FOR i IN 1 .. coalesce(array_length(keys, 1), 0) LOOP
   tab := keys[i][1]; col := keys[i][2]; parent := keys[i][3]; act := keys[i][4];
   gone := CASE parent WHEN 'agents' THEN agents_gone WHEN 'nodes' THEN nodes_gone
    WHEN 'connections' THEN connections_gone ELSE '{}' END;
   IF cardinality(gone) = 0 OR act = 'restrict' THEN
    CONTINUE;
   ELSIF act = 'cascade' THEN
    EXECUTE format('DELETE FROM %I WHERE %I::text = ANY ($1)', tab, col) USING gone;
   ELSE
    EXECUTE format('UPDATE %I SET %I = NULL WHERE %I::text = ANY ($1)', tab, col, col)
     USING gone;
   END IF;
  END LOOP;
  -- A deferred trigger the settling queued fires now, still under the settings,
  -- so no table is left with pending events when its key is validated.
  SET CONSTRAINTS ALL IMMEDIATE;
  FOR r IN SELECT c.relname FROM pg_class c JOIN pg_trigger g ON g.tgrelid = c.oid
    WHERE c.relnamespace = current_schema()::regnamespace
    AND g.tgname = 'store_state_capture' ORDER BY c.relname LOOP
   EXECUTE format('DROP TRIGGER store_state_capture ON %I', r.relname);
  END LOOP;
  PERFORM set_config('store.deleting_agent', '', true);
  PERFORM set_config('store.deleting_node', '', true);
  PERFORM set_config('store.deleting_connection', '', true);
  PERFORM set_config('store.premig', '', true);
 END IF;
 FOR i IN 1 .. coalesce(array_length(keys, 1), 0) LOOP
  EXECUTE format('ALTER TABLE %I VALIDATE CONSTRAINT %I', keys[i][1], names[i]);
 END LOOP;
END $keys$;
COMMENT ON FUNCTION store_state_keys(text, text[]) IS 'An owner''s foreign key step: for
 each {table, column, parent, class} of keys - class cascade, set null or restrict - the
 column''s key to parent (id) in that class, any key it had on the column made again, added
 NOT VALID; every reference that names an agent, a node or a connection the store does not
 hold settled by its class (owned rows deleted, recorded columns set null), each row it
 changes kept in <owner>_premig_m9; then every key validated. A pinned (restrict) column
 that names a missing row, or any other missing parent, refuses the step naming it.';
"""

# An id never changes, and a parent is deleted only on purpose.
_GUARDS = r"""
CREATE FUNCTION agents_id() RETURNS trigger
 LANGUAGE plpgsql AS $id$
BEGIN
 IF NEW.id IS DISTINCT FROM OLD.id THEN
  RAISE EXCEPTION 'agent % keeps its id; its slug and name are what change', OLD.id
   USING ERRCODE = 'check_violation';
 END IF;
 RETURN NEW;
END $id$;
CREATE TRIGGER agents_id BEFORE UPDATE OF id ON agents
 FOR EACH ROW EXECUTE FUNCTION agents_id();
CREATE FUNCTION nodes_id() RETURNS trigger
 LANGUAGE plpgsql AS $id$
BEGIN
 IF NEW.id IS DISTINCT FROM OLD.id THEN
  RAISE EXCEPTION 'node % (%) keeps its id; its label is what changes', OLD.id, OLD.label
   USING ERRCODE = 'check_violation';
 END IF;
 RETURN NEW;
END $id$;
CREATE TRIGGER nodes_id BEFORE UPDATE OF id ON nodes
 FOR EACH ROW EXECUTE FUNCTION nodes_id();
CREATE FUNCTION agents_delete() RETURNS trigger
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $delete$
BEGIN
 IF NOT store_state_named('agents', OLD.id) THEN
  RAISE EXCEPTION 'agent % is deleted only by the manager, which names it in store.deleting_agent',
   OLD.id USING ERRCODE = 'restrict_violation';
 END IF;
 RETURN OLD;
END $delete$;
CREATE TRIGGER agents_delete BEFORE DELETE ON agents
 FOR EACH ROW EXECUTE FUNCTION agents_delete();
CREATE FUNCTION nodes_delete() RETURNS trigger
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $delete$
BEGIN
 IF NOT store_state_named('nodes', OLD.id) THEN
  RAISE EXCEPTION 'node % (%) is deleted only by the manager, which names it in store.deleting_node',
   OLD.id, OLD.label USING ERRCODE = 'restrict_violation';
 END IF;
 RETURN OLD;
END $delete$;
CREATE TRIGGER nodes_delete BEFORE DELETE ON nodes
 FOR EACH ROW EXECUTE FUNCTION nodes_delete();
CREATE FUNCTION connections_delete() RETURNS trigger
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $delete$
BEGIN
 IF NOT (store_state_named('connections', OLD.id)
         OR store_state_named('agents', OLD.owner_agent_id)) THEN
  RAISE EXCEPTION '% connection % (%) is deleted only by a removal verb, which names it in store.deleting_connection',
   OLD.capability, OLD.label, OLD.id USING ERRCODE = 'restrict_violation';
 END IF;
 RETURN OLD;
END $delete$;
CREATE TRIGGER connections_delete BEFORE DELETE ON connections
 FOR EACH ROW EXECUTE FUNCTION connections_delete();
CREATE OR REPLACE FUNCTION settings_changes_append_only() RETURNS trigger
 LANGUAGE plpgsql AS $guard$
DECLARE admitted boolean := false;
BEGIN
 IF tg_op IN ('DELETE', 'UPDATE') THEN
  EXECUTE format('SELECT %I.store_state_cascade($1, $2, $3, $4)', tg_table_schema)
   INTO admitted USING tg_table_name, tg_op, to_jsonb(OLD),
   CASE WHEN tg_op = 'UPDATE' THEN to_jsonb(NEW) END;
 END IF;
 IF admitted THEN
  RETURN CASE WHEN tg_op = 'DELETE' THEN OLD ELSE NEW END;
 END IF;
 RAISE EXCEPTION 'settings_changes is append-only' USING ERRCODE = 'restrict_violation';
END $guard$;
CREATE OR REPLACE FUNCTION reference_versions_guard() RETURNS trigger
 LANGUAGE plpgsql AS $guard$
DECLARE admitted boolean := false;
BEGIN
 IF tg_op IN ('DELETE', 'UPDATE') THEN
  EXECUTE format('SELECT %I.store_state_cascade($1, $2, $3, $4)', tg_table_schema)
   INTO admitted USING tg_table_name, tg_op, to_jsonb(OLD),
   CASE WHEN tg_op = 'UPDATE' THEN to_jsonb(NEW) END;
 END IF;
 IF admitted THEN
  RETURN CASE WHEN tg_op = 'DELETE' THEN OLD ELSE NEW END;
 END IF;
 IF tg_op IN ('DELETE', 'TRUNCATE') THEN
  RAISE EXCEPTION 'reference versions are never deleted: retire the reference'
   USING ERRCODE = 'check_violation';
 END IF;
 IF (to_jsonb(NEW) - 'active') IS DISTINCT FROM (to_jsonb(OLD) - 'active') THEN
  RAISE EXCEPTION 'a reference version is immutable: save a new version'
   USING ERRCODE = 'check_violation';
 END IF;
 IF NEW.active AND NOT OLD.active THEN
  RAISE EXCEPTION 'a reference version is not made active again: save its body as a new version'
   USING ERRCODE = 'check_violation';
 END IF;
 RETURN NEW;
END $guard$;
CREATE OR REPLACE FUNCTION secrets_announce() RETURNS trigger
 LANGUAGE plpgsql AS $announce$
DECLARE agent text;
BEGIN
 IF coalesce(current_setting('store.deleting_agent', true), '') <> ''
    OR coalesce(current_setting('store.deleting_node', true), '') <> ''
    OR coalesce(current_setting('store.deleting_connection', true), '') <> '' THEN
  RETURN NULL;
 END IF;
 IF tg_table_name = 'agents' THEN agent := NEW.id;
 ELSIF tg_op = 'DELETE' THEN agent := OLD.agent_id;
 ELSE agent := NEW.agent_id; END IF;
 IF to_regclass(format('%I.schema_channel', tg_table_schema)) IS NOT NULL THEN
  EXECUTE format('INSERT INTO %I.schema_channel AS c (channel, scope, version)
   VALUES (%L, $1, 1) ON CONFLICT (channel, scope) DO UPDATE SET version = c.version + 1',
   tg_table_schema, 'capabilities_vault') USING agent;
 END IF;
 RETURN NULL;
END $announce$;"""

_KEYS = f"SELECT store_state_keys('core', {keys_array(CORE_KEYS)});"

_COMMENTS = """\
COMMENT ON COLUMN agents.id IS 'The agent''s id, never changed (trigger agents_id): every
 row of the agent holds it with a foreign key, and the row goes with the agent unless it is
 another owner''s record. The agent is deleted only with store.deleting_agent naming it.';
COMMENT ON COLUMN nodes.id IS 'The node''s id, never changed (trigger nodes_id): every row
 of the node holds it with a foreign key; what the node owns goes with it, a record of what
 ran there loses the pointer, and a definition pinned to it refuses its removal. The node is
 deleted only with store.deleting_node naming it.';"""

_COMMENTS = _COMMENTS.replace("\n ", " ")  # each comment is one line

STEP_SQL = "\n".join((_FUNCTIONS.strip(), _GUARDS.strip(), _KEYS, _COMMENTS))


def deleting(conn, parent: str, *ids: str) -> None:
    """Name `ids` - of `parent`, `agents`, `nodes` or `connections` - as deleted on
    purpose for the rest of the open transaction, so the store admits deleting
    their rows and the cascade that follows. Only a removal verb calls it, right
    before its `DELETE`; outside a transaction it holds for no statement."""
    setting = DELETING_SETTINGS[parent]
    named = [i for i in ids if i]
    # Deferred triggers (notifications) run at COMMIT and read the setting
    # then: the pending ones run now, so the statements before a delete notify
    # outside the setting and the cascade's before it is cleared, inside it.
    conn.execute("SET CONSTRAINTS ALL IMMEDIATE")
    conn.execute("SELECT set_config(%s, %s, true)", (setting, ",".join(named)))
