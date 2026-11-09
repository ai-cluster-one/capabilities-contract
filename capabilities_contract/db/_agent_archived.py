"""The core's fifth step: an agent can be archived, and nothing starts for it then.

It adds `agents.archived_at` and `agents.archived_by`: the mark the
capabilities manager stamps once it has checked that nothing of the agent
runs, and clears on restore. `archived_by` is the actor as `user@node`,
never the empty string. A system agent (`agents.kind = 'system'`) never
carries the mark.

It makes the one function every owner's guard calls for an agent id:

    agents_archived_refuse(agent text) RETURNS void

It takes `FOR SHARE` on the agent's row, which conflicts with the row lock
an archiving transaction holds from its check to its stamp (`FOR UPDATE`,
or the `FOR NO KEY UPDATE` its `UPDATE agents SET archived_at` takes), so a
guarded write either waits for the archive to commit and is then refused,
or holds the archive back until it has committed and is then seen by the
archive's check. A foreign key's `FOR KEY SHARE` alone conflicts with
neither. Where the agent is archived it raises SQLSTATE `23R01`
(`AGENT_ARCHIVED_SQLSTATE`, class 23, so psycopg raises an
`IntegrityError` and never an `OperationalError`, which reads as a lost
connection) with a message that begins `agent_archived:`; a null agent and
an agent the store does not hold pass, the latter left to the foreign key.

It guards the core's own tables that start something for an agent, each
through the core trigger function `agents_archived_row()`, which calls the
function for the row's `agent_id`:

- `policies`: an insert or update that leaves the row placing a service
  (`service` true, which needs an agent and a node). Its trigger,
  `policies_unarchived`, fires after `policies_service_follows`, which
  sets `service` from `enabled` for a writer that leaves it out. Unplacing
  (`service` false) and a delete are not guarded.
- `service_leases`: every insert, `BEFORE INSERT`, so a lease upsert, which
  fires it whether it takes or renews, is refused. Releasing (`DELETE`) is
  not guarded.
- `service_instances`: every insert but one recording `stopping`, `BEFORE
  INSERT`: the supervisor writes its whole row through an upsert, so a
  supervisor that stops a service of an archived agent still says so, and
  then drops the row, which is not guarded.

An owner guards its own table in its own minor step declaring `core=(4, 2)`,
with a trigger function of its own name that calls the function for the
row's agent; a trigger `BEFORE INSERT` (an upsert fires it too):

    CREATE FUNCTION <owner>_<table>_unarchived() RETURNS trigger
     LANGUAGE plpgsql SET search_path FROM CURRENT AS $guard$
    BEGIN
     PERFORM agents_archived_refuse(NEW.agent_id);
     RETURN NEW;
    END $guard$;
    CREATE TRIGGER <owner>_<table>_unarchived BEFORE INSERT ON <owner>_<table>
     FOR EACH ROW EXECUTE FUNCTION <owner>_<table>_unarchived();

A table that reaches the agent through another row passes the agent that
row names, as `(SELECT agent_id FROM tasks_tasks WHERE id = NEW.task_id)`.

The step adds two nullable columns, a function and triggers and changes no
row, so it is a minor step (core 4.2): it is applied wherever the core is
at major 4, outside the store upgrade, and a release that knows core 4.1
reads a store at 4.2 as a newer minor. Never edit the step once released: a
store holds its checksum.
"""

from __future__ import annotations

STEP_ID = "0043-agent-archived"
MAJOR, MINOR = 4, 2

# The SQLSTATE the guard raises for an archived agent, and the word its
# message begins with: a caller tells the refusal from any other by either.
AGENT_ARCHIVED_SQLSTATE = "23R01"
AGENT_ARCHIVED_CODE = "agent_archived"

STEP_SQL = """\
ALTER TABLE agents ADD COLUMN archived_at timestamptz,
 ADD COLUMN archived_by text CONSTRAINT agents_archived_by_check CHECK (archived_by <> ''),
 ADD CONSTRAINT agents_archived_system
  CHECK (kind <> 'system' OR (archived_at IS NULL AND archived_by IS NULL));
CREATE FUNCTION agents_archived_refuse(agent text) RETURNS void
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $refuse$
DECLARE
 stamped timestamptz;
 actor text;
BEGIN
 IF agent IS NULL THEN
  RETURN;
 END IF;
 SELECT a.archived_at, a.archived_by INTO stamped, actor FROM agents a
  WHERE a.id = agent FOR SHARE;
 IF stamped IS NOT NULL THEN
  RAISE EXCEPTION 'agent_archived: agent % is archived, so nothing may start for it', agent
   USING ERRCODE = '23R01',
    DETAIL = format('archived at %s by %s', stamped, coalesce(actor, 'an unknown actor')),
    HINT = 'restore the agent first; stopping and removing what it runs stay allowed';
 END IF;
END $refuse$;
CREATE FUNCTION agents_archived_row() RETURNS trigger
 LANGUAGE plpgsql SET search_path FROM CURRENT AS $row$
BEGIN
 PERFORM agents_archived_refuse(NEW.agent_id);
 RETURN NEW;
END $row$;
CREATE TRIGGER policies_unarchived BEFORE INSERT OR UPDATE ON policies
 FOR EACH ROW WHEN (NEW.service) EXECUTE FUNCTION agents_archived_row();
CREATE TRIGGER service_leases_unarchived BEFORE INSERT ON service_leases
 FOR EACH ROW EXECUTE FUNCTION agents_archived_row();
CREATE TRIGGER service_instances_unarchived BEFORE INSERT ON service_instances
 FOR EACH ROW WHEN (NEW.state <> 'stopping') EXECUTE FUNCTION agents_archived_row();
COMMENT ON COLUMN agents.archived_at IS 'When the agent was archived: the capabilities \
manager stamps it once it has checked, under a lock on this row, that nothing of the agent \
runs, and clears it on restore. Null for an agent in use. While it is set, every guard that \
calls agents_archived_refuse refuses to start anything for the agent; its records stay. A \
system agent never carries it.';
COMMENT ON COLUMN agents.archived_by IS 'Who archived the agent, as user@node; null while \
archived_at is, never the empty string.';
COMMENT ON FUNCTION agents_archived_refuse(text) IS 'The guard every owner calls for an \
agent id before a write that starts or keeps something running for it: takes FOR SHARE on \
the agent''s row, which conflicts with the lock an archive holds from its check to its \
stamp, and raises SQLSTATE 23R01, its message beginning agent_archived:, where the agent is \
archived. A null agent and one the store does not hold pass.';
COMMENT ON FUNCTION agents_archived_row() IS 'The core''s trigger function that calls \
agents_archived_refuse for the row''s agent_id.';
COMMENT ON TRIGGER policies_unarchived ON policies IS 'Refuses placing a service (service \
true) for an archived agent; unplacing and deleting stay allowed. Fires after \
policies_service_follows, by name.';
COMMENT ON TRIGGER service_leases_unarchived ON service_leases IS 'Refuses taking or \
renewing a lease (every insert, an upsert included) for an archived agent; releasing stays \
allowed.';
COMMENT ON TRIGGER service_instances_unarchived ON service_instances IS 'Refuses recording \
a service of an archived agent in any state but stopping; dropping the row stays allowed.';"""
