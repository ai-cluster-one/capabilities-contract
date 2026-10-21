"""The shared capability code: the core, store and connections tiers every
capability of the capabilities package runs on.

The shared code is a library each capability depends on, not a specification
copied into each one. A capability declares this library in its PEP 723 header by
a version range (`capabilities-contract>=0.8,<1`) and binds the tiers it carries
where it defines its declarations:

    from capabilities_contract.capability import bind as _contract_bind
    _contract_bind(globals(), "core")
    _contract_bind(globals(), "store")
    _contract_bind(globals(), "connections")  # only with connections

`bind` executes a tier's source in the capability's own namespace, in place, so
the tier reads the capability's declarations and calls its hooks exactly as code
the capability wrote itself would, and a name the tier defines is the
capability's own name: a test that replaces one on the capability's module
replaces it for the tier too. A change to the shared code is a release of this
library, which every capability whose range admits it picks up with no edit of
its own; the capabilities manager checks that a capability declares a range it
supports (the package's SHEBANG.md, "The contract verbs").

THREE TIERS
===========
The shared code has three tiers, each one file under `tiers/`; the store tier is
also importable on its own as `capabilities_contract.capability.store`, for a
process that carries no capability (the manager, a bundled service):

  - **capability core** — the capability declaration surface (summary/manifest,
    references, guide, ids) plus the file/project/IO plumbing. EVERY capability
    carries it, connection-bearing or not.

  - **store** — the records adapter used by identifiers, policy, settings,
    connections and documents, kept in files, and a store-mode project's
    connections and grants, kept in its store. EVERY capability carries it
    because core calls into it.

  - **connections** — the credential cascade and connection resolver. Only a
    capability that implements connections binds this tier. Omitting it is the
    normal state for a connection-less capability.

A capability's archetype (API / CLI-wrapper / web-session) lives in the connections
tier; a connection-less capability has no archetype because it has no connection.

WHAT EACH CAPABILITY MUST DEFINE *BEFORE* IT BINDS A TIER (the tiers read
these module-level names; they are the only coupling):
    core/store:  NAME, SUMMARY, SCOPE, DOCS_BASE, STATE, INVENTORY,
                 POST_INSTALL, _CONFIG_HOME, _STATE_HOME
    connections: CREDENTIALS_ENV, CRED_KEYS, WRITE_VERBS, WRITE_DEFAULT
    plus the stdlib imports the helpers use: os, sys, json, Path, NoReturn.
Optionally, beside WRITE_DEFAULT, `MACHINE_READS`: a tuple of the read verbs
that, outside any project, use the machine's own connections read-only.
Absent or empty means none; the manager validates it where it validates a
capability. The verbs `LINK_METHODS` runs use them there the same way.
Optionally, the declarations a person is asked through (SHEBANG.md, "What a
person is asked for"): `CONN_FIELDS`, a connection entry's own fields, which
turns on `connection add|remove`; `SETUP_FIELDS`, the machine prerequisites,
which turns on `setup`; `LINK_METHODS`, the interactive ceremonies that link a
connection; and `SETTINGS`, where the capability's settings live and the keys
it declares, which turns on `settings`, with an optional
`_settings_check(scope, document)` in its own code returning the
problems its own reader finds in the whole document as it would read it.
Each is absent where it does not apply.
Optionally, beside STATE, `TABLES = True` when the capability keeps tables in
the machine's store, with a `_tables()` builder in its own code returning
`(steps, major, minor)` for the shared database library. Absent or false means
none, and `migrate` is then left to the CLI's own parser.
Optionally, `_migrate_files_mover(action, answers, all_answers)` in its own
code: how `migrate files` moves the capability's own configuration files of a
project (profiles, workers, definitions) into the store for `capabilities
migrate`. Absent means the capability has none of its own to move.

The bare `help` verb is dispatched by `_contract` and reads the CLI's help
body from a module-level `HELP` constant if defined, else the module docstring
(`__doc__`) — either wire is acceptable, and every capability already carries
one or the other. For a capability with the connections tier it then appends
where the project it runs in keeps connections, rendered from that project's
connections mode (`connections_mode`), so no help body states that home itself.
Last it appends the project's identifiers as a labelled
section rendered by `_render_ids_markdown` (the same format the manager's
`capabilities ids <NAME>` produces, so one home for the rendering).

`_contract`'s `inventory` verb calls `_inventory(network)` only when the
capability declares `INVENTORY`; that builder is per-capability and stays in
the capability's own code, while the envelope, the flag parsing and the empty
answer are shared so every capability reports in one shape.

`_contract`'s `connections` verb calls `_cmd_connections`, and every capability
defines its own `_cmd_connections` (its no-registry branch names that capability's
own primary key, or reports "no connections" for a core-only capability) — so
`_cmd_connections` stays in the capability's own code. Likewise per-capability
(shape varies, never shared): `_build_conn`/`_load_config`, `_resolve_conn`,
`_check_connection`, the doctor command, the declaration constants, the domain
verbs, argparse/`main`.

TWO DELIBERATE BEST-OF-BREED CHOICES baked into the tiers:
  - `_emit` is the empty-string-guarded variant (asana/callva/notion/telegram).
  - `_select_connection` also matches a connection by its own `address` field
    (generalized from mailbox); the loop never fires for connections without an
    `address`, so it is a no-op for every other capability.
"""

from __future__ import annotations
import __future__

from pathlib import Path

TIERS = ("core", "store", "connections")
_TIER_DIR = Path(__file__).resolve().parent / "tiers"
_SOURCES: dict[str, str] = {}


def tier_path(tier: str) -> Path:
    """The file a tier's source lives in."""
    if tier not in TIERS:
        raise ValueError(f"unknown capability tier {tier!r}; the tiers are {', '.join(TIERS)}")
    return _TIER_DIR / f"{tier}.py"


def bind(namespace: dict, *tiers: str) -> None:
    """Execute each named tier, in order, in `namespace` - a capability's
    `globals()`. The tier is compiled under the namespace's own
    `from __future__ import annotations`, as it would be were its text part of
    the capability's file."""
    flags = 0
    if namespace.get("annotations") is __future__.annotations:
        flags = __future__.annotations.compiler_flag
    for tier in tiers:
        path = tier_path(tier)
        source = _SOURCES.get(tier)
        if source is None:
            source = _SOURCES[tier] = path.read_text(encoding="utf-8")
        exec(compile(source, str(path), "exec", flags=flags, dont_inherit=True), namespace)


__all__ = ["TIERS", "bind", "tier_path"]
