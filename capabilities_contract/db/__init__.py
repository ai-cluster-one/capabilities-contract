"""The shared database layer: read the machine's store setting, connect bound to its
schema, migrate each owner's tables once under a ledger, and report where they stand.

Importing this module does not import psycopg; `connect` and `migrate` do.
"""

from capabilities_contract.db._connect import connect
from capabilities_contract.db._errors import DbError
from capabilities_contract.db._migrate import MigrateResult, MigrateStatus, Step, migrate, status
from capabilities_contract.db._setting import (
    DEFAULT_SCHEMA,
    SETTING_FORMAT,
    SETTING_SCHEMA_V1,
    SETTING_SCHEMA_V2,
    Setting,
    read_setting,
    setting_files,
    setting_path,
)

__all__ = [
    "DEFAULT_SCHEMA",
    "SETTING_FORMAT",
    "SETTING_SCHEMA_V1",
    "SETTING_SCHEMA_V2",
    "DbError",
    "MigrateResult",
    "MigrateStatus",
    "Setting",
    "Step",
    "connect",
    "migrate",
    "read_setting",
    "setting_files",
    "setting_path",
    "status",
]
