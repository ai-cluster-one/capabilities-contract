"""The store tier as a module of its own, for a process that carries no
capability: the capabilities manager, a capability's bundled service, a test.

It is the same source a capability binds (`tiers/store.py`), executed here into
this module, compiled with `from __future__ import annotations`. It needs none
of a capability's declarations.

WHAT THIS TIER OWNS
===================
The records a *running* capability reads and writes: connections, grants,
identifiers, settings, the policy gate and documents. They are kept in files -
the project's envelope, then the user's config home - except in a project in
store mode, which keeps its connections, grants, identifiers and policy in the
contract's tables in its store (`StoreRecords`); a project that moved only its
connections and grants there keeps the rest in files. Which database that is,
like the database any runtime state lives in, is the shared database library's
answer alone (`capabilities_contract.db`); this tier only asks it.

Every connection this tier opens is a transaction connection (the library's
`connect(..., transaction=True)`), dialled at the store's transaction address
where its setting names one: the process's one working connection, which the
library lends for each read or write and keeps between them, so a command
connects once however many records it reads. What was read is served from the
adapter's cache for STORE_READ_SECONDS.

THREE RESOLUTION SEMANTICS, ALREADY IN THE DOCTRINE
===================================================
The precedence is always project over global, but *how* the scopes combine is
declared per collection:

  - MERGE  — per key; a key absent at the higher scope inherits the lower.
    This is rule 17 for the gate ("an absent project entry inherits the global
    entry"). Connections take it too, at the entry level: rule 18 keeps an
    identity atomic — taken whole from one scope, never assembled out of two —
    while letting a project add to the set it inherits rather than replace it.

  - FIRST  — the highest scope holding ANY entry wins, whole.

  - EXACT  — no cascade; a record belongs to exactly one scope and is read
    there (rule 16).

ONE WRITER PER COLLECTION
=========================
Rule 15 is addressed by `(capability, collection)` instead of by path: the
manager alone writes `policy`, a capability alone writes its own `identifier`
records, and `connection`, `grant`, `setting` and `document` records are
human-written through a CLI verb.

EXCEPTIONS ARE RAISED, NEVER PRINTED
====================================
This tier is a library, not a command. It raises `StoreError`; the carrying
capability maps that onto its own `_die` envelope and exit codes, so the error
surface stays the capability's own.
"""

from __future__ import annotations

from capabilities_contract.capability import bind

bind(globals(), "store")
