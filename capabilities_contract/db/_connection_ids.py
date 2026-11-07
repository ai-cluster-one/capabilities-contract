"""The core's second step: every connection gets an opaque id, and every core
reference to a connection holds that id.

Until core 3.0 a connection was keyed by `(capability, name)`, its name being
the word it was added under, and every reference held that name. This step,
in one transaction:

1. gives each connection `id`, twelve lowercase hex characters minted once,
   unique across the store and its primary key, never changed (a guard trigger
   refuses an update of it), minted by the store for a writer that gives none;
2. makes `label` what the connection is called on every row - its name where
   it had none - not null and unique within its capability, and no label the
   id of any connection, so a word names a connection by id first, then by
   label, and never two;
3. keeps the name each connection had, beside its id, its capability and the
   label it had, in the pre-image `core_premig_connection_names`, which nothing
   writes again: the steps of other owners read it to convert their own
   columns, and a capability that kept state on disk under a connection's name
   reads it to find that state;
4. moves every core reference to `connection_id` (or, for a node made through a
   Coolify connection, `coolify_connection_id`) holding the id, with a foreign
   key to `connections (id)`: grants, node sessions and node session
   expectations, the nodes and their copies in agent_nodes, a top-level
   `connection` setting naming a connection of its own capability, and two new
   columns, `settings.connection_id` and `identifiers.ref_connection_id`. A
   node made through a connection the machine lent, which no row holds, keeps
   that connection's address in `coolify_address`;
5. drops the name: `connections.name` and every column that held it.

A node session, and the owner's word on one, may be of a connection the store
does not hold, one only a machine's files declare: such a row keeps that
connection's key in `file_connection` instead, exactly one of the two set, and
nothing is deleted. The step raises the core to major 3, so
outside the store upgrade it is applied only to an empty store. Never edit the
step once released: a store holds its checksum.
"""

from __future__ import annotations

STEP_ID = "0040-connection-ids"
MAJOR, MINOR = 3, 0

# The pre-image of the cutover: each connection's id and the name it had.
NAMES_TABLE = "core_premig_connection_names"

# What a new id is: the first twelve hex characters of a random UUID, which a
# version 4 UUID fills with random bits.
MINT = "substr(replace(gen_random_uuid()::text, '-', ''), 1, 12)"

_IDS = f"""\
DROP TRIGGER connections_label ON connections;
ALTER TABLE connections DROP CONSTRAINT connections_check;
ALTER TABLE connections ADD COLUMN id text;
DO $mint$
DECLARE r record; minted text;
BEGIN
 FOR r IN SELECT capability, name FROM connections ORDER BY capability, name LOOP
  LOOP
   minted := {MINT};
   EXIT WHEN NOT EXISTS (SELECT 1 FROM connections
    WHERE id = minted OR name = minted OR label = minted);
  END LOOP;
  UPDATE connections SET id = minted WHERE capability = r.capability AND name = r.name;
 END LOOP;
END $mint$;
CREATE TABLE {NAMES_TABLE} (
 id text PRIMARY KEY,
 capability text NOT NULL,
 name text NOT NULL,
 label text);
INSERT INTO {NAMES_TABLE} (id, capability, name, label)
 SELECT id, capability, name, label FROM connections;
UPDATE connections SET label = name WHERE label IS NULL;
ALTER TABLE connections ALTER COLUMN id SET NOT NULL,
 ALTER COLUMN id SET DEFAULT {MINT},
 ALTER COLUMN label SET NOT NULL,
 ADD CONSTRAINT connections_id_check CHECK (id ~ '^[0-9a-f]{{12}}$'),
 ADD CONSTRAINT connections_label_check CHECK (label <> '' AND label = btrim(label));
DROP INDEX connections_label;
CREATE UNIQUE INDEX connections_label ON connections (capability, label);"""

# Each reference moved to the id, its name column dropped with the key built on
# it, and the key rebuilt in the same place on the id.
_REFERENCES = """\
ALTER TABLE grants ADD COLUMN connection_id text;
UPDATE grants g SET connection_id = c.id FROM connections c
 WHERE c.capability = g.capability AND c.name = g.connection;
ALTER TABLE grants DROP CONSTRAINT grants_capability_connection_fkey;
DROP INDEX grants_key;
DROP INDEX grants_scope_key;
ALTER TABLE grants DROP COLUMN connection;
ALTER TABLE connections DROP CONSTRAINT connections_pkey;
ALTER TABLE connections ADD CONSTRAINT connections_pkey PRIMARY KEY (id);
ALTER TABLE grants ALTER COLUMN connection_id SET NOT NULL,
 ADD CONSTRAINT grants_connection_id_fkey FOREIGN KEY (connection_id)
  REFERENCES connections (id) ON DELETE CASCADE;
CREATE UNIQUE INDEX grants_key
 ON grants (agent_id, capability, connection_id, (coalesce(node, '')));
CREATE UNIQUE INDEX grants_scope_key
 ON grants ((coalesce(agent_id, '')), capability, connection_id, (coalesce(node, '')));
ALTER TABLE node_sessions ADD COLUMN connection_id text,
 ADD COLUMN file_connection text;
UPDATE node_sessions s SET connection_id = c.id FROM connections c
 WHERE c.capability = s.capability AND c.name = s.connection;
UPDATE node_sessions SET file_connection = connection WHERE connection_id IS NULL;
ALTER TABLE node_sessions DROP CONSTRAINT node_sessions_pkey;
ALTER TABLE node_sessions DROP COLUMN connection;
ALTER TABLE node_sessions
 ADD CONSTRAINT node_sessions_connection_id_fkey FOREIGN KEY (connection_id)
  REFERENCES connections (id) ON DELETE CASCADE,
 ADD CONSTRAINT node_sessions_file_connection_check
  CHECK (file_connection <> ''),
 ADD CONSTRAINT node_sessions_connection
  CHECK (num_nonnulls(connection_id, file_connection) = 1);
CREATE UNIQUE INDEX node_sessions_key
 ON node_sessions
 (agent_id, node, capability, (coalesce(connection_id, file_connection)));
ALTER TABLE node_session_expectations ADD COLUMN connection_id text,
 ADD COLUMN file_connection text;
UPDATE node_session_expectations s SET connection_id = c.id FROM connections c
 WHERE c.capability = s.capability AND c.name = s.connection;
UPDATE node_session_expectations SET file_connection = connection
 WHERE connection_id IS NULL;
ALTER TABLE node_session_expectations DROP CONSTRAINT node_session_expectations_pkey;
ALTER TABLE node_session_expectations DROP COLUMN connection;
ALTER TABLE node_session_expectations
 ADD CONSTRAINT node_session_expectations_connection_id_fkey FOREIGN KEY (connection_id)
  REFERENCES connections (id) ON DELETE CASCADE,
 ADD CONSTRAINT node_session_expectations_file_connection_check
  CHECK (file_connection <> ''),
 ADD CONSTRAINT node_session_expectations_connection
  CHECK (num_nonnulls(connection_id, file_connection) = 1);
CREATE UNIQUE INDEX node_session_expectations_key
 ON node_session_expectations
 (agent_id, node, capability, (coalesce(connection_id, file_connection)));
ALTER TABLE nodes ADD COLUMN coolify_connection_id text
  CONSTRAINT nodes_coolify_connection_id_fkey REFERENCES connections (id) ON DELETE SET NULL,
 ADD COLUMN coolify_address text CONSTRAINT nodes_coolify_address_check
  CHECK (coolify_address <> '');
ALTER TABLE agent_nodes ADD COLUMN coolify_connection_id text
  CONSTRAINT agent_nodes_coolify_connection_id_fkey REFERENCES connections (id)
  ON DELETE SET NULL,
 ADD COLUMN coolify_address text;"""

# The copy of a node's fields onto each of its links, and the owner checks,
# reading the id.
_FUNCTIONS = """\
CREATE OR REPLACE FUNCTION agent_nodes_node_fields() RETURNS trigger
 LANGUAGE plpgsql AS $fields$
BEGIN
 EXECUTE format('SELECT kind, address, target, last_seen_at, coolify_connection_id,
  coolify_address, coolify_server, coolify_resource, public_key FROM %I.nodes
  WHERE id = $1', tg_table_schema)
 INTO NEW.kind, NEW.address, NEW.target, NEW.last_seen_at, NEW.coolify_connection_id,
  NEW.coolify_address, NEW.coolify_server, NEW.coolify_resource, NEW.public_key
 USING NEW.node;
 RETURN NEW;
END $fields$;
CREATE OR REPLACE FUNCTION nodes_to_links() RETURNS trigger
 LANGUAGE plpgsql AS $links$
BEGIN
 EXECUTE format('UPDATE %I.agent_nodes SET node = node WHERE node = $1
  AND (kind, address, target, last_seen_at, coolify_connection_id, coolify_address,
   coolify_server, coolify_resource, public_key)
   IS DISTINCT FROM ($2, $3, $4, $5, $6, $7, $8, $9, $10)', tg_table_schema)
 USING NEW.id, NEW.kind, NEW.address, NEW.target, NEW.last_seen_at,
  NEW.coolify_connection_id, NEW.coolify_address, NEW.coolify_server,
  NEW.coolify_resource, NEW.public_key;
 RETURN NULL;
END $links$;
CREATE OR REPLACE FUNCTION grants_owner() RETURNS trigger
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $owner$
DECLARE held text; kind text; called text;
BEGIN
 SELECT owner_agent_id, capability, label INTO held, kind, called FROM connections
  WHERE id = NEW.connection_id;
 IF FOUND AND kind <> NEW.capability THEN
  RAISE EXCEPTION 'connection % (%) is a % connection, not a % one',
   NEW.connection_id, called, kind, NEW.capability USING ERRCODE = 'check_violation';
 END IF;
 IF held IS NOT NULL AND NEW.agent_id IS DISTINCT FROM held THEN
  RAISE EXCEPTION '% connection % is agent %''s own and is granted to no other agent',
   NEW.capability, called, held USING ERRCODE = 'check_violation';
 END IF;
 RETURN NEW;
END $owner$;
CREATE OR REPLACE FUNCTION connections_owner() RETURNS trigger
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $owner$
BEGIN
 IF NEW.owner_agent_id IS NOT NULL AND EXISTS (SELECT 1 FROM grants
  WHERE connection_id = OLD.id AND agent_id IS DISTINCT FROM NEW.owner_agent_id) THEN
  RAISE EXCEPTION
   '% connection % is granted to agents other than %, so it cannot be that agent''s own',
   OLD.capability, OLD.label, NEW.owner_agent_id USING ERRCODE = 'check_violation';
 END IF;
 RETURN NEW;
END $owner$;
CREATE OR REPLACE FUNCTION connections_label() RETURNS trigger
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $label$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtext('connections:ids'));
 IF NEW.label = NEW.id OR EXISTS (SELECT 1 FROM connections
  WHERE id <> NEW.id AND (id = NEW.label OR label = NEW.id)) THEN
  RAISE EXCEPTION '% connection label % or id % is already a connection''s id or label',
   NEW.capability, NEW.label, NEW.id USING ERRCODE = 'unique_violation';
 END IF;
 RETURN NEW;
END $label$;
CREATE TRIGGER connections_label BEFORE INSERT OR UPDATE OF label ON connections
 FOR EACH ROW EXECUTE FUNCTION connections_label();
CREATE FUNCTION connections_id() RETURNS trigger
 LANGUAGE plpgsql AS $id$
BEGIN
 IF NEW.id IS DISTINCT FROM OLD.id THEN
  RAISE EXCEPTION '% connection % keeps its id %; its label is what is renamed',
   OLD.capability, OLD.label, OLD.id USING ERRCODE = 'check_violation';
 END IF;
 RETURN NEW;
END $id$;
CREATE TRIGGER connections_id BEFORE UPDATE OF id ON connections
 FOR EACH ROW EXECUTE FUNCTION connections_id();"""

# A node made through a store connection holds its id; one made through a
# connection the machine lent, which no row holds, its address. The copies
# follow through the trigger.
_NODES = """\
UPDATE nodes n SET coolify_connection_id = c.id FROM connections c
 WHERE c.capability = 'coolify' AND c.name = n.coolify_connection;
UPDATE nodes SET coolify_address = coolify_connection
 WHERE coolify_connection IS NOT NULL AND coolify_connection_id IS NULL;
ALTER TABLE nodes DROP CONSTRAINT nodes_coolify;
ALTER TABLE nodes DROP COLUMN coolify_connection;
ALTER TABLE agent_nodes DROP COLUMN coolify_connection;
ALTER TABLE nodes ADD CONSTRAINT nodes_coolify CHECK (
 num_nonnulls(coolify_server, coolify_resource) IN (0, 2)
 AND num_nonnulls(coolify_connection_id, coolify_address) <= 1
 AND (coolify_server IS NOT NULL OR num_nonnulls(coolify_connection_id, coolify_address) = 0));"""

# A setting or an identifier that stands for a connection holds its id beside
# it. The core converts the one convention every capability shares, a
# top-level `connection` naming a connection of its own capability; a
# capability's own paths are its own step's.
_SETTINGS = """\
ALTER TABLE settings ADD COLUMN connection_id text
 CONSTRAINT settings_connection_id_fkey REFERENCES connections (id) ON DELETE CASCADE;
ALTER TABLE identifiers ADD COLUMN ref_connection_id text
 CONSTRAINT identifiers_ref_connection_id_fkey REFERENCES connections (id) ON DELETE CASCADE;
UPDATE settings s SET value = to_jsonb(c.id), connection_id = c.id FROM connections c
 WHERE s.path = ARRAY['connection'] AND jsonb_typeof(s.value) = 'string'
 AND c.capability = s.capability AND c.name = s.value #>> '{}';
UPDATE settings s SET value = to_jsonb(c.id), connection_id = c.id FROM connections c
 WHERE s.path = ARRAY['connection'] AND jsonb_typeof(s.value) = 'string'
 AND s.connection_id IS NULL AND c.capability = s.capability AND c.label = s.value #>> '{}';
ALTER TABLE connections DROP COLUMN name;"""

_COMMENTS = f"""\
COMMENT ON TABLE {NAMES_TABLE} IS 'The map of the 2026-11 connection id cutover (core step
 {STEP_ID}): one row per connection the store held before it, its new id beside the
 capability, the name it was keyed by and the label it had (null where it had none). Written
 by that step alone and never again; other owners'' steps read it to convert their columns,
 and a capability that kept state under a connection''s name reads it to find that state. It
 may be dropped once every node has moved its state.';
COMMENT ON TABLE connections IS 'What a connection is: one row per connection, keyed by its
 id and called by its label, its spec the entry interior with secret references only. A row
 is shared by the capability (owner null) or one agent''s own.';
COMMENT ON COLUMN connections.id IS 'The connection''s id: twelve lowercase hex characters
 minted when it is added, unique across the store, never changed, and what every grant,
 default pointer, node session and other reference holds.';
COMMENT ON COLUMN connections.label IS 'What the connection is called: the word it was added
 under until `<capability> connection rename` changes it. Unique within its capability, and
 never the id of any connection, so a word names a connection by its id, else by its label.';
COMMENT ON COLUMN grants.connection_id IS 'The connection''s id in connections; the grant
 goes with it.';
COMMENT ON COLUMN node_sessions.connection_id IS 'The id of the store connection the session
 is of; the row goes with the connection. Null for a connection only files hold.';
COMMENT ON COLUMN node_sessions.file_connection IS 'The key of the connection the session is
 of where only a machine''s files hold it, which no row of connections is; null for a store
 connection. Exactly one of connection_id and file_connection is set.';
COMMENT ON COLUMN node_session_expectations.connection_id IS 'The id of the store connection
 the word is about; the row goes with the connection. Null for a connection only files hold.';
COMMENT ON COLUMN node_session_expectations.file_connection IS 'The key of the connection the
 word is about where only a machine''s files hold it; null for a store connection. Exactly
 one of connection_id and file_connection is set.';
COMMENT ON COLUMN nodes.coolify_connection_id IS 'The id of the coolify connection the node
 was created through; its token stays in that connection. Null for a node that is not a
 Coolify resource, for one created through a connection the machine lent (coolify_address),
 and once that connection is removed.';
COMMENT ON COLUMN nodes.coolify_address IS 'The address of the coolify connection the
 machine lent that the node was created through, which no row of connections holds; null
 otherwise. At most one of coolify_connection_id and coolify_address is set.';
COMMENT ON COLUMN agent_nodes.coolify_connection_id IS 'A copy of
 nodes.coolify_connection_id kept by the store, as kind.';
COMMENT ON COLUMN agent_nodes.coolify_address IS 'A copy of nodes.coolify_address kept by
 the store, as kind.';
COMMENT ON COLUMN settings.connection_id IS 'The id of the connection this setting names, in
 a path segment or as its value, where it names one; the setting goes with the connection.';
COMMENT ON COLUMN identifiers.ref_connection_id IS 'The id of the connection this identifier
 stands for, which its value then holds (`<capability> ids set <label> --connection <word>`);
 the identifier goes with the connection. Null for an identifier that stands for none.';"""

_COMMENTS = _COMMENTS.replace("\n ", " ")  # each comment is one line

STEP_SQL = "\n".join((_IDS, _REFERENCES, _FUNCTIONS, _NODES, _SETTINGS, _COMMENTS))
