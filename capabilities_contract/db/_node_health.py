"""The core's ninth step: each agent's health on each of its nodes, read through one view.

It makes the view `agent_nodes_health`: one row per agent and node it lives
on (`agent_nodes`), saying the node's colour for the agent - `green`, all
works; `yellow`, it works with a minus; `red`, the agent has stopped there;
`disabled` for a disabled node, which expects nothing - and, item by item,
what needs action there, each with when its fact was checked. The colour
rule lives here and nowhere else: every reader reads the view.

Red: the node is silent past its `node_states.fresh_until`, from its last
report, or never reported; it cannot read the store, last seen before the
store moved to its major; the Claude or Codex sign-in the agent's services
need there (or the owner's word expects) is gone; a session or connection
the agent's placed service runs on is not live; a service of the agent
there is failing, unusable or held. Yellow: the GitHub sign-in expected
there is gone; a service is starting, stopping or waiting, degraded, or was
started before a setting it takes only on a start changed; a connection the
agent only uses now and then is refused there (`not_signed_in`) or misses
a key (`key_missing`); the node has an update it has not taken; its memory
or disk is at least 90% full.

It adds `service_instances.restart_settings`, the settings keys the service
takes only when it starts, as its capability declares them: the store holds
which settings changed and when, but not which of them a running service
adopts only on a start, so without it a restart could not be told from
nothing.

It announces every change of state in `node_logins`, `node_sessions` and
`service_instances` - never a rewrite of the same state, and never the
`node_states` beat - on the channel `agent_nodes_health`: the version
of (`agent_nodes_health`, agent id) is raised in `schema_channel` and
the channel notified with `{"schema", "agent_id", "node"}` as JSON, both in
the writer's transaction. A session deleted and written again in the same
transaction with the same state, as a node replaces its sessions, announces
nothing; one deleted for good is announced as its transaction commits.

The step adds a nullable column, a view, functions and triggers and changes
no row, so it is a minor step (core 4.6): it is applied wherever the core is
at major 4, outside the store upgrade, and a release that knows core 4.5
reads a store at 4.6 as a newer minor and reads and writes every row it did
before. The view names the core's major steps up to 4.0 by id, and reads a
store at a later major as reaching it when the core last recorded its
version, until that major's own step replaces the view. Never edit the step
once released: a store holds its checksum.
"""

from __future__ import annotations

STEP_ID = "0047-node-health"
MAJOR, MINOR = 4, 6
CHANNEL = "agent_nodes_health"
VIEW = "agent_nodes_health"

STEP_SQL = """\
ALTER TABLE service_instances ADD COLUMN restart_settings text[]
 CONSTRAINT service_instances_restart_settings_check
 CHECK (array_position(restart_settings, NULL) IS NULL
  AND array_position(restart_settings, '') IS NULL);
COMMENT ON COLUMN service_instances.restart_settings IS 'The settings keys this service \
takes only when it starts, as its capability declares them (apply restart), each a dotted \
key; written by its supervisor. A change of one of them in settings after started_at means \
the service needs a restart to take it. Null where not recorded: a row written before the \
store kept it (core 4.6), or by a supervisor that does not say.';
CREATE VIEW agent_nodes_health AS
SELECT b.agent_id, b.node,
 CASE WHEN b.disabled_at IS NOT NULL THEN 'disabled'
  WHEN EXISTS (SELECT 1 FROM jsonb_array_elements(i.items) x WHERE x ->> 'level' = 'red')
   THEN 'red'
  WHEN jsonb_array_length(i.items) > 0 THEN 'yellow'
  ELSE 'green' END AS health,
 b.fresh AND NOT b.cannot_read_store AS reachable,
 b.cannot_read_store, b.store_major, b.store_since, b.last_seen_at, b.reported_at,
 b.fresh_until, i.items, g.sign_ins, s.sessions
FROM (
 SELECT l.agent_id, l.node, n.disabled_at, st.reported_at, st.fresh_until,
  greatest(n.last_seen_at, st.reported_at) AS last_seen_at,
  v.major AS store_major, v.since AS store_since,
  coalesce(st.fresh_until > now(), false) AS fresh,
  coalesce(v.major > 1 AND v.since IS NOT NULL AND n.created_at < v.since
   AND coalesce(greatest(n.last_seen_at, st.reported_at) < v.since, true), false)
   AS cannot_read_store,
  st.update_available, st.update_checked_at, st.memory_used_bytes, st.memory_limit_bytes,
  st.disk_used_bytes, st.disk_total_bytes
 FROM agent_nodes l
 JOIN nodes n ON n.id = l.node
 LEFT JOIN node_states st ON st.node = l.node
 LEFT JOIN (
  SELECT c.major, CASE WHEN c.major > 4 THEN c.updated_at WHEN c.major > 1 THEN coalesce(
    (SELECT max(r.applied_at) FROM schema_ledger r WHERE r.owner = 'core'
     AND r.step IN ('0039-core', '0040-connection-ids', '0041-keys')),
    c.updated_at) END AS since
  FROM schema_version c WHERE c.owner = 'core') v ON true
) b
CROSS JOIN LATERAL (
 SELECT coalesce(jsonb_agg(jsonb_build_object('tool', t.tool, 'login', t.login,
   'needed', t.needed, 'override', t.override,
   'expected', b.disabled_at IS NULL AND coalesce(t.override, t.needed),
   'checked_at', t.checked_at) ORDER BY t.ord), '[]'::jsonb) AS sign_ins
 FROM (
  SELECT k.ord, k.tool,
   CASE k.tool WHEN 'claude' THEN o.claude_login WHEN 'codex' THEN o.codex_login
    ELSE o.gh_login END AS login,
   coalesce(CASE k.tool WHEN 'claude' THEN o.claude_needed WHEN 'codex' THEN o.codex_needed
    ELSE o.gh_needed END, false) AS needed,
   e.expected AS override, o.checked_at
  FROM (VALUES (1, 'claude'), (2, 'codex'), (3, 'gh')) k (ord, tool)
  LEFT JOIN node_logins o ON o.agent_id = b.agent_id AND o.node = b.node
  LEFT JOIN node_login_expectations e
   ON e.agent_id = b.agent_id AND e.node = b.node AND e.tool = k.tool) t
) g
CROSS JOIN LATERAL (
 SELECT coalesce(jsonb_agg(jsonb_build_object('capability', t.capability,
   'connection', t.key, 'connection_id', t.connection_id,
   'file_connection', t.file_connection, 'live', t.live, 'reason', t.reason,
   'reason_keys', t.reason_keys, 'checked_at', t.checked_at, 'reported', t.reported,
   'needed', t.needed, 'override', t.override,
   'expected', b.disabled_at IS NULL AND coalesce(t.override, t.needed))
   ORDER BY t.capability, t.key), '[]'::jsonb) AS sessions
 FROM (
  SELECT k.capability, k.key,
   coalesce(o.connection_id, e.connection_id) AS connection_id,
   coalesce(o.file_connection, e.file_connection) AS file_connection,
   o.live, o.reason, o.reason_keys, o.checked_at, o.agent_id IS NOT NULL AS reported,
   e.expected AS override,
   o.agent_id IS NOT NULL AND EXISTS (SELECT 1 FROM policies p
    WHERE p.agent_id = b.agent_id AND p.node = b.node AND p.capability = k.capability
    AND p.enabled AND p.service) AS needed
  FROM (
   SELECT x.capability, coalesce(x.connection_id, x.file_connection) AS key
    FROM node_sessions x WHERE x.agent_id = b.agent_id AND x.node = b.node
   UNION
   SELECT x.capability, coalesce(x.connection_id, x.file_connection)
    FROM node_session_expectations x WHERE x.agent_id = b.agent_id AND x.node = b.node) k
  LEFT JOIN node_sessions o ON o.agent_id = b.agent_id AND o.node = b.node
   AND o.capability = k.capability AND coalesce(o.connection_id, o.file_connection) = k.key
  LEFT JOIN node_session_expectations e ON e.agent_id = b.agent_id AND e.node = b.node
   AND e.capability = k.capability AND coalesce(e.connection_id, e.file_connection) = k.key) t
) s
CROSS JOIN LATERAL (
 SELECT coalesce(jsonb_agg(f.item ORDER BY f.ord, f.sort), '[]'::jsonb) AS items
 FROM (
  SELECT 1 AS ord, '1' AS sort, jsonb_build_object('kind', 'node', 'level', 'red',
    'action', 'restart_node',
    'reason', CASE WHEN b.reported_at IS NULL THEN 'not_reported' ELSE 'silent' END,
    'checked_at', b.reported_at) AS item
   WHERE NOT b.fresh
  UNION ALL
  SELECT 1, '2', jsonb_build_object('kind', 'node', 'level', 'red', 'action', 'update_node',
    'reason', 'cannot_read_store', 'checked_at', b.last_seen_at)
   WHERE b.cannot_read_store
  UNION ALL
  SELECT 1, '3', jsonb_build_object('kind', 'node', 'level', 'yellow', 'action', 'update',
    'reason', 'behind', 'checked_at', b.update_checked_at)
   WHERE b.update_available
  UNION ALL
  SELECT 1, '4', jsonb_build_object('kind', 'node', 'level', 'yellow', 'action', 'free_memory',
    'reason', 'memory_nearly_full', 'checked_at', b.reported_at)
   WHERE b.memory_limit_bytes > 0 AND b.memory_used_bytes >= 0.9 * b.memory_limit_bytes
  UNION ALL
  SELECT 1, '5', jsonb_build_object('kind', 'node', 'level', 'yellow', 'action', 'free_disk',
    'reason', 'disk_nearly_full', 'checked_at', b.reported_at)
   WHERE b.disk_total_bytes > 0 AND b.disk_used_bytes >= 0.9 * b.disk_total_bytes
  UNION ALL
  SELECT 2, lpad(x.ordinality::text, 9, '0'), jsonb_build_object('kind', 'sign_in',
    'level', CASE WHEN x.value ->> 'tool' = 'gh' THEN 'yellow' ELSE 'red' END,
    'action', 'sign_in', 'tool', x.value -> 'tool',
    'reason', coalesce(x.value ->> 'login', 'not_reported'),
    'expected', true, 'checked_at', x.value -> 'checked_at')
   FROM jsonb_array_elements(g.sign_ins) WITH ORDINALITY x
   WHERE (x.value ->> 'expected')::boolean
   AND coalesce(x.value ->> 'login', 'absent') IN ('signed_out', 'absent')
  UNION ALL
  SELECT 3, lpad(x.ordinality::text, 9, '0'), jsonb_build_object('kind', 'session',
    'level', CASE WHEN (x.value ->> 'expected')::boolean THEN 'red' ELSE 'yellow' END,
    'action', CASE x.value ->> 'reason' WHEN 'session_missing' THEN 'link'
     WHEN 'key_missing' THEN 'set_key' WHEN 'not_signed_in' THEN 'sign_in' ELSE 'check' END,
    'capability', x.value -> 'capability', 'connection', x.value -> 'connection',
    'reason', CASE WHEN (x.value ->> 'reported')::boolean THEN 'not_live'
     ELSE 'not_reported' END,
    'detail', x.value -> 'reason', 'expected', (x.value ->> 'expected')::boolean,
    'checked_at', x.value -> 'checked_at')
   FROM jsonb_array_elements(s.sessions) WITH ORDINALITY x
   WHERE (x.value ->> 'live')::boolean IS NOT TRUE
   AND ((x.value ->> 'expected')::boolean
    OR (x.value -> 'override' = 'null'::jsonb AND (x.value ->> 'reported')::boolean
     AND x.value ->> 'reason' IN ('not_signed_in', 'key_missing')))
  UNION ALL
  SELECT 4, i.capability, jsonb_build_object('kind', 'service',
    'level', CASE WHEN i.state IN ('failing', 'unusable', 'held') THEN 'red' ELSE 'yellow' END,
    'action', CASE WHEN i.state = 'unusable' AND i.problem_code = 'agent_not_raised'
      THEN 'raise_agent'
     WHEN i.state = 'unusable' THEN 'fix'
     WHEN i.state IN ('failing', 'held') THEN 'restart'
     WHEN i.state = 'degraded' THEN 'check_settings'
     ELSE 'wait' END,
    'capability', i.capability, 'state', i.state,
    'reason', CASE WHEN i.state = 'degraded' THEN 'skipped_settings'
     WHEN i.state IN ('starting', 'stopping') THEN i.state
     ELSE coalesce(i.problem_code, i.state) END,
    'checked_at', i.checked_at)
   FROM service_instances i WHERE i.agent_id = b.agent_id AND i.node = b.node
   AND (i.state IN ('failing', 'unusable', 'held', 'starting', 'stopping', 'degraded')
    OR (i.state = 'waiting' AND i.problem_code IS DISTINCT FROM 'lease_held_elsewhere'))
  UNION ALL
  SELECT 4, i.capability || '~', jsonb_build_object('kind', 'service', 'level', 'yellow',
    'action', 'restart', 'capability', i.capability, 'state', i.state,
    'reason', 'settings_changed', 'checked_at', i.checked_at)
   FROM service_instances i WHERE i.agent_id = b.agent_id AND i.node = b.node
   AND i.state IN ('ready', 'degraded') AND i.started_at IS NOT NULL
   AND EXISTS (SELECT 1 FROM settings_changes c, unnest(i.restart_settings) r (key)
    WHERE c.capability = i.capability AND (c.agent_id = i.agent_id OR c.agent_id IS NULL)
    AND (c.node = i.node OR c.node IS NULL) AND c.changed_at > i.started_at
    AND (array_to_string(c.path, '.') = r.key
     OR starts_with(array_to_string(c.path, '.'), r.key || '.')
     OR starts_with(r.key, array_to_string(c.path, '.') || '.')))
 ) f WHERE b.disabled_at IS NULL
) i;
COMMENT ON VIEW agent_nodes_health IS 'Each agent''s health on each node it lives on, one \
row per agent_nodes row: health green (all works), yellow (works with a minus), red (the \
agent has stopped there) or disabled (a disabled node, which expects nothing); reachable, \
false for a node silent past node_states.fresh_until or that cannot read the store; \
cannot_read_store, a node last seen (last_seen_at, the later of nodes.last_seen_at and \
node_states.reported_at) before the store reached store_major at store_since, unless it was \
registered since; items, what needs action there, each {kind node|sign_in|session|service, \
level red|yellow, action, reason, checked_at, and tool, capability, connection, state, \
detail or expected where they apply}; sign_ins, each tool''s login and whether it is \
needed, overridden by the owner and expected; sessions, each session reported or expected \
there with whether it is needed, overridden and expected. The one place the colour rule \
lives (core 4.6).';
CREATE FUNCTION agent_nodes_health_raise(schema text, agent text, node text) RETURNS void
 LANGUAGE plpgsql AS $raise$
BEGIN
 IF to_regclass(format('%I.schema_channel', schema)) IS NOT NULL THEN
  EXECUTE format('INSERT INTO %I.schema_channel AS c (channel, scope, version)
   VALUES (%L, $1, 1) ON CONFLICT (channel, scope) DO UPDATE SET version = c.version + 1',
   schema, 'agent_nodes_health') USING agent;
 END IF;
 PERFORM pg_notify('agent_nodes_health',
  json_build_object('schema', schema, 'agent_id', agent, 'node', node)::text);
END $raise$;
COMMENT ON FUNCTION agent_nodes_health_raise(text, text, text) IS 'Announces a change of \
an agent''s health on a node: raises the version of (agent_nodes_health, agent) in \
schema_channel and notifies agent_nodes_health with {schema, agent_id, node} as JSON, \
both in the caller''s transaction.';
CREATE FUNCTION agent_nodes_health_announce() RETURNS trigger
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $announce$
BEGIN
 IF tg_op = 'DELETE' THEN
  PERFORM agent_nodes_health_raise(tg_table_schema::text, OLD.agent_id, OLD.node);
 ELSE
  PERFORM agent_nodes_health_raise(tg_table_schema::text, NEW.agent_id, NEW.node);
 END IF;
 RETURN NULL;
END $announce$;
COMMENT ON FUNCTION agent_nodes_health_announce() IS 'Announces the agent and node of a \
row of node_logins or service_instances whose state changed.';
CREATE FUNCTION node_sessions_health() RETURNS trigger
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $sessions$
DECLARE
 gone jsonb := coalesce(nullif(current_setting('agent_nodes_health.sessions_gone',
  true), ''), '{}')::jsonb;
 key text;
 found boolean;
BEGIN
 IF tg_op = 'DELETE' THEN
  key := jsonb_build_array(OLD.agent_id, OLD.node, OLD.capability,
   coalesce(OLD.connection_id, OLD.file_connection))::text;
  IF tg_argv[0] = 'now' THEN
   PERFORM set_config('agent_nodes_health.sessions_gone', (gone
    || jsonb_build_object(key, jsonb_build_array(OLD.live, OLD.reason, OLD.reason_keys)))::text,
    true);
   RETURN NULL;
  END IF;
  EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.node_sessions WHERE agent_id = $1
   AND node = $2 AND capability = $3 AND coalesce(connection_id, file_connection) = $4)',
   tg_table_schema) INTO found
   USING OLD.agent_id, OLD.node, OLD.capability, coalesce(OLD.connection_id, OLD.file_connection);
  IF NOT found THEN
   PERFORM agent_nodes_health_raise(tg_table_schema::text, OLD.agent_id, OLD.node);
  END IF;
  RETURN NULL;
 END IF;
 IF tg_op = 'INSERT' THEN
  key := jsonb_build_array(NEW.agent_id, NEW.node, NEW.capability,
   coalesce(NEW.connection_id, NEW.file_connection))::text;
  IF gone ? key THEN
   PERFORM set_config('agent_nodes_health.sessions_gone', (gone - key)::text, true);
   IF gone -> key = jsonb_build_array(NEW.live, NEW.reason, NEW.reason_keys) THEN
    RETURN NULL;
   END IF;
  END IF;
 END IF;
 PERFORM agent_nodes_health_raise(tg_table_schema::text, NEW.agent_id, NEW.node);
 RETURN NULL;
END $sessions$;
COMMENT ON FUNCTION node_sessions_health() IS 'Announces a change of state of a row of \
node_sessions: an insert that does not write back the state a delete in the same \
transaction took away, an update that changes live, reason or reason_keys, and, as the \
transaction commits, a delete not written back.';
CREATE TRIGGER node_logins_health AFTER INSERT OR DELETE ON node_logins
 FOR EACH ROW EXECUTE FUNCTION agent_nodes_health_announce();
CREATE TRIGGER node_logins_health_change AFTER UPDATE ON node_logins
 FOR EACH ROW WHEN ((OLD.claude_login, OLD.codex_login, OLD.gh_login, OLD.claude_needed,
  OLD.codex_needed, OLD.gh_needed) IS DISTINCT FROM (NEW.claude_login, NEW.codex_login,
  NEW.gh_login, NEW.claude_needed, NEW.codex_needed, NEW.gh_needed))
 EXECUTE FUNCTION agent_nodes_health_announce();
CREATE TRIGGER service_instances_health AFTER INSERT OR DELETE ON service_instances
 FOR EACH ROW EXECUTE FUNCTION agent_nodes_health_announce();
CREATE TRIGGER service_instances_health_change AFTER UPDATE ON service_instances
 FOR EACH ROW WHEN ((OLD.state, OLD.problem_code, OLD.skipped_settings, OLD.started_at,
  OLD.restart_settings) IS DISTINCT FROM (NEW.state, NEW.problem_code, NEW.skipped_settings,
  NEW.started_at, NEW.restart_settings))
 EXECUTE FUNCTION agent_nodes_health_announce();
CREATE TRIGGER node_sessions_health AFTER INSERT OR DELETE ON node_sessions
 FOR EACH ROW EXECUTE FUNCTION node_sessions_health('now');
CREATE TRIGGER node_sessions_health_change AFTER UPDATE ON node_sessions
 FOR EACH ROW WHEN ((OLD.live, OLD.reason, OLD.reason_keys)
  IS DISTINCT FROM (NEW.live, NEW.reason, NEW.reason_keys))
 EXECUTE FUNCTION node_sessions_health('now');
CREATE CONSTRAINT TRIGGER node_sessions_health_gone AFTER DELETE ON node_sessions
 DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION node_sessions_health('deferred');"""
