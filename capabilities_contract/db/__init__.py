"""The shared database layer: read the machine's store setting, connect bound to its
schema, and migrate each owner's tables once under a ledger.

Importing this module does not import psycopg; `connect` and `migrate` do.
"""

from capabilities_contract.db._connect import connect
from capabilities_contract.db._errors import DbError
from capabilities_contract.db._migrate import MigrateResult, Step, migrate
from capabilities_contract.db._setting import (
    DEFAULT_SCHEMA,
    SETTING_SCHEMA_V1,
    SETTING_SCHEMA_V2,
    Setting,
    read_setting,
    setting_files,
)

__all__ = [
    "DEFAULT_SCHEMA",
    "SETTING_SCHEMA_V1",
    "SETTING_SCHEMA_V2",
    "DbError",
    "MigrateResult",
    "Setting",
    "Step",
    "connect",
    "migrate",
    "read_setting",
    "setting_files",
]
