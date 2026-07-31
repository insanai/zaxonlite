"""zxlite: DB-API 2.0 driver for zaxonlite.

Connect to a local zaxonlite node data directory (or a remote cluster
DSN) and use the familiar `sqlite3`-shaped surface:

    import zxlite

    connection = zxlite.connect("./node-data")
    connection.execute("create table t(v text)")
    connection.execute("insert into t values (?)", ("hello",))
    print(connection.execute("select v from t").fetchall())
"""

from . import _zxlite
from .dbapi import (
    Connection,
    Cursor,
    DatabaseError,
    DataError,
    Error,
    IntegrityError,
    InterfaceError,
    InternalError,
    NotSupportedError,
    OperationalError,
    ProgrammingError,
    RemoteConnection,
    Warning,
    apilevel,
    connect,
    paramstyle,
    sqlite_version,
    sqlite_version_info,
    threadsafety,
)
from .rows import Row
from .server import Member, Server, start_server

__version__ = "0.2.2"

# ZDS 0010 invariant 13: the SDK and the native library must agree on
# the native major/minor version before any handle is opened.
_EXPECTED_NATIVE_VERSION = (0, 2)


def _check_native_version() -> None:
    """Refuse to import against a mismatched native zaxonlite."""
    text = _zxlite.version()
    try:
        found = tuple(int(part) for part in text.split(".")[:2])
    except ValueError:
        found = ()
    if found != _EXPECTED_NATIVE_VERSION:
        expected = ".".join(str(part) for part in _EXPECTED_NATIVE_VERSION)
        raise ImportError(
            f"zxlite {__version__} expects native zaxonlite "
            f"{expected}.x, but the loaded library reports {text!r}"
        )


_check_native_version()

__all__ = [
    "Connection",
    "Cursor",
    "DataError",
    "DatabaseError",
    "Error",
    "IntegrityError",
    "InterfaceError",
    "InternalError",
    "Member",
    "NotSupportedError",
    "OperationalError",
    "ProgrammingError",
    "RemoteConnection",
    "Row",
    "Server",
    "Warning",
    "__version__",
    "apilevel",
    "connect",
    "paramstyle",
    "sqlite_version",
    "sqlite_version_info",
    "start_server",
    "threadsafety",
]
