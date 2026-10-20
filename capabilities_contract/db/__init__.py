"""The shared database layer: resolve which database a project uses, connect bound to
its schema, migrate each owner's tables once under a ledger, report where they stand,
and announce and follow changes by polling.

Importing this module does not import psycopg; `connect`, `batch` and `migrate` do.
"""

from capabilities_contract.db._changes import FOLLOW_INTERVAL_SECONDS, Follower, announce
from capabilities_contract.db._connect import batch, connect, disconnect
from capabilities_contract.db._errors import DbError
from capabilities_contract.db._migrate import MigrateResult, MigrateStatus, Step, migrate, status
from capabilities_contract.db._setting import (
    DEFAULT_SCHEMA,
    KEYS,
    LEVELS,
    SETTING_FORMAT,
    Setting,
    resolve_setting,
    setting_path,
)

__all__ = [
    "DEFAULT_SCHEMA",
    "FOLLOW_INTERVAL_SECONDS",
    "KEYS",
    "LEVELS",
    "SETTING_FORMAT",
    "DbError",
    "Follower",
    "MigrateResult",
    "MigrateStatus",
    "Setting",
    "Step",
    "announce",
    "batch",
    "connect",
    "disconnect",
    "migrate",
    "resolve_setting",
    "setting_path",
    "status",
]
