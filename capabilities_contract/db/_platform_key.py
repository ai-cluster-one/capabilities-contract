"""The core's seventh step: the store publishes the platform's public key and keeps
the platform's own copy of every secret.

It adds `store_state.platform_public_key`, the X25519 public key of the
platform keypair the capabilities manager makes on the machine it runs on,
in a file only its user reads, and never in the store. An agent pins it in
its own vault the first time a process holding the agent's key sees it, and
from then on opens an entry another than itself sealed only where it was
sent by that key.

It adds `platform_secrets`, the platform's own copy of every secret: a row
per name, either of a connection the store shares (`connection_id`) or of
one agent's own vault (`agent_id`), never both, each sealed for the
platform's public key with sender authentication. A shared connection's copy
is the one every granted entry is sealed from; an agent's own copy is sent
by that agent and is what the platform re-delivers when the agent's key is
replaced. The table keys a row by its own uuid and refers to its agent or
connection by id with a foreign key that takes the row with its parent; it
carries no announcement, since only the platform reads it.

The step adds a nullable column and a table and changes no row, so it is a
minor step (core 4.4): it is applied wherever the core is at major 4,
outside the store upgrade, and a release that knows core 4.3 reads a store
at 4.4 as a newer minor and reads every row it read before. Never edit the
step once released: a store holds its checksum.
"""

from __future__ import annotations

STEP_ID = "0045-platform-key"
MAJOR, MINOR = 4, 4

STEP_SQL = """\
ALTER TABLE store_state ADD COLUMN platform_public_key text
 CONSTRAINT store_state_platform_public_key_check
 CHECK (platform_public_key ~ '^[A-Za-z0-9_-]{43}$');
COMMENT ON COLUMN store_state.platform_public_key IS 'The platform''s public key: the \
X25519 public key of the keypair the capabilities manager keeps in a file of its own \
machine, URL-safe base64 of 32 bytes, never the private key. An agent pins it in its own \
vault on first sight and opens an entry another than itself sent only where this key \
sent it. Null until the platform keypair is made (core 4.4).';
CREATE TABLE platform_secrets (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 agent_id text REFERENCES agents (id) ON DELETE CASCADE CHECK (agent_id <> ''),
 connection_id text REFERENCES connections (id) ON DELETE CASCADE CHECK (connection_id <> ''),
 name text NOT NULL CHECK (name ~ '^[A-Za-z_][A-Za-z0-9_]{0,254}$'),
 ciphertext bytea NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now(),
 updated_by text CHECK (updated_by <> ''),
 CONSTRAINT platform_secrets_one_owner CHECK ((agent_id IS NULL) <> (connection_id IS NULL)));
CREATE UNIQUE INDEX platform_secrets_agent_name ON platform_secrets (agent_id, name)
 WHERE agent_id IS NOT NULL;
CREATE UNIQUE INDEX platform_secrets_connection_name ON platform_secrets (connection_id, name)
 WHERE connection_id IS NOT NULL;
COMMENT ON TABLE platform_secrets IS 'The platform''s own copy of every secret, one row per \
name of a connection the store shares or of one agent''s own vault, sealed for \
store_state.platform_public_key with sender authentication, so only the platform opens \
it. Every entry the platform delivers into an agent''s vault is sealed from it (core 4.4).';
COMMENT ON COLUMN platform_secrets.agent_id IS 'The agent whose own vault entry this copies, \
sent by that agent; null for a shared connection''s copy.';
COMMENT ON COLUMN platform_secrets.connection_id IS 'The connection the store shares whose \
secret this is, sent by the platform; null for an agent''s own copy.';
COMMENT ON COLUMN platform_secrets.name IS 'The environment variable name the secret \
answers under in the vault of every agent it is delivered to.';
COMMENT ON COLUMN platform_secrets.ciphertext IS 'Format 3: the format byte, the 32-byte \
X25519 public key of its sender, the 24-byte nonce, then the XChaCha20-Poly1305 \
ciphertext with its tag under the key the sender and the platform agree on.';"""
