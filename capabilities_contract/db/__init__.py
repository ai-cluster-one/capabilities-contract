"""The shared database layer: resolve which database a project uses, connect bound to
its schema, migrate each owner's tables once under a ledger, and report where they stand.

Importing this module does not import psycopg; `connect` and `migrate` do.
"""

from capabilities_contract.db._connect import connect
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
    "KEYS",
    "LEVELS",
    "SETTING_FORMAT",
    "DbError",
    "MigrateResult",
    "MigrateStatus",
    "Setting",
    "Step",
    "connect",
    "migrate",
    "resolve_setting",
    "setting_path",
    "status",
]
