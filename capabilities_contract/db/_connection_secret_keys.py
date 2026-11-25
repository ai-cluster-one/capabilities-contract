"""The core's eighth step: every connection records the names of the secrets it resolves.

It adds `connections.secret_keys`, the names of the secrets the connection
resolves - the keys its capability's own `connections` report marks secret,
each the name the agent's vault holds the value under - so one query answers
which connection uses which secret, without asking each capability.

The store cannot compute it: which of a spec's values name a secret, and
which a capability adds of its own, is that capability's code. The capability
writes it, from its own report, after each write of the row (the library's
store tier). The store keeps it honest: an update that changes a row's spec,
label or capability without setting `secret_keys` clears it to null, so a
writer that does not know it - an older release, the manager's import -
leaves it unknown rather than wrong. Null means not recorded for the row as
it is; a row the store held before this step is null until its capability
records it.

The step adds one nullable column and a trigger and changes no row, so it is a
minor step (core 4.5): it is applied wherever the core is at major 4, outside
the store upgrade, and a release that knows core 4.4 reads a store at 4.5 as
a newer minor and reads every row it read before. Never edit the step once
released: a store holds its checksum.
"""

from __future__ import annotations

STEP_ID = "0046-connection-secret-keys"
MAJOR, MINOR = 4, 5

STEP_SQL = """\
ALTER TABLE connections ADD COLUMN secret_keys text[]
 CONSTRAINT connections_secret_keys_check
 CHECK (array_position(secret_keys, NULL) IS NULL AND array_position(secret_keys, '') IS NULL);
CREATE FUNCTION connections_secret_keys() RETURNS trigger
 LANGUAGE plpgsql AS $keys$
BEGIN
 IF (NEW.spec IS DISTINCT FROM OLD.spec OR NEW.label IS DISTINCT FROM OLD.label
     OR NEW.capability IS DISTINCT FROM OLD.capability)
    AND NEW.secret_keys IS NOT DISTINCT FROM OLD.secret_keys THEN
  NEW.secret_keys := NULL;
 END IF;
 RETURN NEW;
END $keys$;
CREATE TRIGGER connections_secret_keys BEFORE UPDATE ON connections
 FOR EACH ROW EXECUTE FUNCTION connections_secret_keys();
COMMENT ON COLUMN connections.secret_keys IS 'The names of the secrets this connection \
resolves, as its capability''s own connections report names them (its keys marked secret): \
each the name the agent''s vault holds the value under. Written by the capability after each \
write of the row. Null where not recorded for the row as it is: an update that changes spec, \
label or capability without setting it clears it, and a row older than the store recording \
it (core 4.5) is null until its capability records it. An empty array is a connection that \
resolves no secret.';
COMMENT ON FUNCTION connections_secret_keys() IS 'Clears connections.secret_keys when an \
update changes spec, label or capability without setting it.';"""
