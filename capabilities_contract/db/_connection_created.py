"""The core's fourth step: every connection records when the store made its row.

It adds `connections.created_at`, which the store sets on every insert to the
moment of the inserting transaction, over whatever the writer gave, and keeps
as it is on every update, so no edit, rename or other write moves it and none
fills it in. A row the store held before this step keeps it null: no moment
it could be given would be true.

The step adds a column and a trigger and changes no row, so it is a minor step
(core 4.1): it is applied wherever the core is at major 4, outside the store
upgrade, and a release that knows core 4.0 reads a store at 4.1 as a newer
minor. It keeps an update's value rather than refusing one, because writers
that bring a row up to another whole - the dev lane's projection among them -
set every column they share. Never edit the step once released: a store holds
its checksum.
"""

from __future__ import annotations

STEP_ID = "0042-connection-created-at"
MAJOR, MINOR = 4, 1

STEP_SQL = """\
ALTER TABLE connections ADD COLUMN created_at timestamptz;
CREATE FUNCTION connections_created_at() RETURNS trigger
 LANGUAGE plpgsql AS $created$
BEGIN
 IF tg_op = 'INSERT' THEN
  NEW.created_at := now();
 ELSE
  NEW.created_at := OLD.created_at;
 END IF;
 RETURN NEW;
END $created$;
CREATE TRIGGER connections_created_at BEFORE INSERT OR UPDATE ON connections
 FOR EACH ROW EXECUTE FUNCTION connections_created_at();
COMMENT ON COLUMN connections.created_at IS 'When the store made this connection''s row: \
the time of the transaction that inserted it, set by the store over whatever the writer \
gave and never changed by an edit, a rename or any other update. A connection imported \
from files has the moment its row was made, not when its files were written. Null for a \
connection that predates the store recording it (core 4.1), which nothing fills in.';
COMMENT ON FUNCTION connections_created_at() IS 'Sets connections.created_at on insert \
and keeps it on update.';"""
