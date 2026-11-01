"""A store as a release up to 0.41.0 left it - the manager's tables as owner
`capabilities`, at schema version 1.23 or an older minor - with a row in each
table, and the catalog of a schema to compare two stores by."""

from __future__ import annotations

from capabilities_contract.db import _legacy, _migrate, migrate

AGENT = "prj_000000000001"
PEER = "prj_000000000002"
NODE = "0a0b0c0d0e0f"
FP = "a" * 64

# Each legacy table and a row for it, in an order a foreign key allows. A
# table the store does not hold yet is passed over.
SEED = (
    ("capabilities_agents", "INSERT INTO capabilities_agents (id, name, slug) VALUES "
     f"('{AGENT}', 'Work', 'work'), ('{PEER}', 'Peer', 'peer')"),
    ("capabilities_nodes", "INSERT INTO capabilities_nodes (id, label, kind, address) "
     f"VALUES ('{NODE}', 'box', 'server', 'box.example.test')"),
    ("capabilities_agent_nodes", "INSERT INTO capabilities_agent_nodes (agent_id, node, "
     f"is_master) VALUES ('{AGENT}', '{NODE}', true)"),
    ("capabilities_connections", "INSERT INTO capabilities_connections (capability, name, "
     f"spec, owner) VALUES ('demo', 'home', '{{}}', '{AGENT}'), ('demo', 'work', '{{}}', NULL)"),
    ("capabilities_connection_grants", "INSERT INTO capabilities_connection_grants "
     f"(agent_id, capability, connection, is_default) VALUES ('{AGENT}', 'demo', 'home', true)"),
    ("capabilities_identifiers", "INSERT INTO capabilities_identifiers (agent_id, "
     f"capability, label, value) VALUES ('{AGENT}', 'demo', 'folder', '\"x\"')"),
    ("capabilities_policy", "INSERT INTO capabilities_policy (agent_id, capability, node, "
     f"enabled) VALUES ('{AGENT}', 'demo', NULL, true)"),
    ("capabilities_settings", "INSERT INTO capabilities_settings (agent_id, capability, "
     f"path, value, updated_by) VALUES ('{AGENT}', 'demo', '{{a,b}}', '1', 'user@box')"),
    ("capabilities_settings_documents", "INSERT INTO capabilities_settings_documents "
     f"(agent_id, capability, generation) VALUES ('{AGENT}', 'demo', 1)"),
    ("capabilities_settings_changes", "INSERT INTO capabilities_settings_changes (agent_id, "
     f"capability, action, path, new_value, changed_by) VALUES ('{AGENT}', 'demo', 'set', "
     "'{a,b}', '1', 'user@box')"),
    ("capabilities_references", "INSERT INTO capabilities_references (project_id, "
     f"capability, name, body, created_by) VALUES ('{AGENT}', 'demo', 'guide', 'body', "
     "'user@box')"),
    ("capabilities_service_instances", "INSERT INTO capabilities_service_instances "
     f"(project_id, capability, node, state) VALUES ('{AGENT}', 'demo', '{NODE}', 'ready')"),
    ("capabilities_vault", "INSERT INTO capabilities_vault (agent_id, name, ciphertext, "
     f"key_fingerprint) VALUES ('{AGENT}', 'DEMO_TOKEN', '\\x01', '{FP}')"),
    ("capabilities_node_states", "INSERT INTO capabilities_node_states (node, fresh_until) "
     f"VALUES ('{NODE}', now() + interval '1 minute')"),
    ("capabilities_node_logins", "INSERT INTO capabilities_node_logins (project_id, node) "
     f"VALUES ('{AGENT}', '{NODE}')"),
    ("capabilities_node_sessions", "INSERT INTO capabilities_node_sessions (project_id, "
     f"node, capability, connection, live) VALUES ('{AGENT}', '{NODE}', 'demo', 'home', true)"),
    ("capabilities_node_login_expectations", "INSERT INTO "
     "capabilities_node_login_expectations (project_id, node, tool, expected) VALUES "
     f"('{AGENT}', '{NODE}', 'gh', true)"),
    ("capabilities_node_session_expectations", "INSERT INTO "
     "capabilities_node_session_expectations (project_id, node, capability, connection, "
     f"expected) VALUES ('{AGENT}', '{NODE}', 'demo', 'home', false)"),
    ("capabilities_node_updates", "INSERT INTO capabilities_node_updates (node) "
     f"VALUES ('{NODE}')"),
    ("capabilities_node_logs", "INSERT INTO capabilities_node_logs (project_id, node, "
     f"source, lines) VALUES ('{AGENT}', '{NODE}', 'manager', '{{one,two}}')"),
    ("capabilities_service_leases", "INSERT INTO capabilities_service_leases (project_id, "
     f"capability, node, mode, expires_at) VALUES ('{AGENT}', 'demo', '{NODE}', 'own', "
     "now() + interval '1 minute')"),
)

# The pre-images the manager made beside the tables, outside any step.
PREIMAGES = ("capabilities_premig_m1", "capabilities_premig_m2", "capabilities_premig_m3")


def legacy_store(conn, monkeypatch, steps=None, version=(1, 23), schema=None,
                 preimages=True) -> dict[str, int]:
    """Migrate owner `capabilities` with `steps` (every legacy step by default)
    as a release without core steps did, seed a row in each table, and make the
    pre-images. Answers the rows each legacy table holds."""
    steps = list(_legacy.LEGACY_STEPS if steps is None else steps)
    with monkeypatch.context() as patched:
        patched.setattr(_migrate, "CORE_STEPS", ())
        migrate(conn, "capabilities", steps, major=version[0], minor=version[1], schema=schema)
    with conn.transaction():
        for table, sql in SEED:
            if conn.execute("SELECT to_regclass(%s)", (table,)).fetchone()[0] is not None:
                conn.execute(sql)
        if preimages:
            for name in PREIMAGES:
                conn.execute(f"CREATE TABLE {name} (id int PRIMARY KEY, note text)")
                conn.execute(f"INSERT INTO {name} VALUES (1, 'kept')")
        counts = {}
        for (table,) in conn.execute(
                "SELECT relname FROM pg_class WHERE relnamespace = current_schema()::regnamespace"
                " AND relkind = 'r' AND relname LIKE 'capabilities%'").fetchall():
            counts[table] = conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
    return counts


_CATALOG = {
    "column": """SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod),
        a.attnotnull, pg_get_expr(d.adbin, d.adrelid), a.attidentity, a.attgenerated,
        col_description(c.oid, a.attnum)
        FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
        LEFT JOIN pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
        WHERE c.relnamespace = %(s)s::regnamespace AND c.relkind = 'r' AND a.attnum > 0
        AND NOT a.attisdropped""",
    "relation": """SELECT relname, relkind, obj_description(oid, 'pg_class') FROM pg_class
        WHERE relnamespace = %(s)s::regnamespace AND relkind NOT IN ('t')""",
    "constraint": """SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid)
        FROM pg_constraint WHERE connamespace = %(s)s::regnamespace""",
    "index": """SELECT indexrelid::regclass::text, pg_get_indexdef(indexrelid) FROM pg_index
        WHERE indrelid IN (SELECT oid FROM pg_class WHERE relnamespace = %(s)s::regnamespace)""",
    "trigger": """SELECT tgname, pg_get_triggerdef(oid) FROM pg_trigger WHERE NOT tgisinternal
        AND tgrelid IN (SELECT oid FROM pg_class WHERE relnamespace = %(s)s::regnamespace)""",
    "function": """SELECT proname, pg_get_functiondef(oid), obj_description(oid, 'pg_proc')
        FROM pg_proc WHERE pronamespace = %(s)s::regnamespace""",
    "sequence": """SELECT c.relname, s.seqtypid::regtype::text, s.seqstart, s.seqincrement,
        s.seqmax, s.seqmin, s.seqcycle FROM pg_sequence s JOIN pg_class c ON c.oid = s.seqrelid
        WHERE c.relnamespace = %(s)s::regnamespace""",
}


def catalog(conn, schema: str) -> set[tuple]:
    """Every column, type, default, constraint, index, trigger, function,
    sequence and comment in `schema`, the schema's own name taken out."""
    out: set[tuple] = set()
    with conn.transaction():
        for kind, query in _CATALOG.items():
            for row in conn.execute(query, {"s": schema}).fetchall():
                out.add((kind, *(str(v).replace(f'"{schema}"', "<schema>")
                                 .replace(schema, "<schema>") for v in row)))
    return out
