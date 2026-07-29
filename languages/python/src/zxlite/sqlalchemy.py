"""SQLAlchemy dialect for zxlite (ZDS 0010, Phase 5).

The dialect reuses SQLAlchemy's SQLite SQL compiler, type compiler,
identifier preparer, and schema reflection; it overrides DB-API module
loading, URL translation, transaction and savepoint hooks, isolation
handling, version discovery, and connection-pool defaults.

Local URLs name a data directory and connect in Gate C transactional
mode by default (`NullPool`: one checked-out connection owns the
zaxonlite directory lock):

    create_engine("zxlite:///relative/data-directory")
    create_engine("zxlite:////var/lib/zxlite/data-directory")

Remote URLs use repeated percent-encoded `seed=` query values, require
`isolation_level="AUTOCOMMIT"`, and default to `StaticPool` (the one
thread-safe logical connection already owns a bounded native socket
pool):

    create_engine(
        "zxlite:///?seed=db1.example%3A9901&seed=db2.example%3A9901",
        connect_args={"tls_ca": ..., "tls_cert": ..., "tls_key": ...},
        isolation_level="AUTOCOMMIT",
    )

Importing the base `zxlite` package never imports SQLAlchemy; this
module is loaded through the `sqlalchemy.dialects` entry point or an
explicit import.
"""

from __future__ import annotations

from types import ModuleType
from typing import Any
from urllib.parse import quote

from sqlalchemy.dialects.sqlite.base import SQLiteDialect
from sqlalchemy.engine import URL
from sqlalchemy.engine.interfaces import ConnectArgsType

import zxlite
from sqlalchemy import exc, pool
from zxlite.dbapi import Connection as ZxConnection
from zxlite.dbapi import RemoteConnection as ZxRemoteConnection

__all__ = ["ZxLiteDialect"]


def _is_remote_url(url: URL) -> bool:
    """Report whether `url` uses the remote seed= query form."""
    return "seed" in url.query


class ZxLiteDialect(SQLiteDialect):
    """SQLite-compatible dialect speaking the zxlite DB-API driver."""

    name = "zxlite"
    driver = "zxlite"
    supports_statement_cache = True
    # zxlite executemany reports total changes locally but the remote
    # path autocommits row by row; mirror pysqlite's conservative flag.
    supports_sane_multi_rowcount = False

    @classmethod
    def import_dbapi(cls) -> ModuleType:
        """Return the zxlite DB-API module."""
        return zxlite

    @classmethod
    def dbapi(cls) -> ModuleType:  # type: ignore[override]
        """Return the zxlite DB-API module (legacy spelling)."""
        return zxlite

    @classmethod
    def get_pool_class(cls, url: URL) -> type[pool.Pool]:
        """Pick NullPool locally, StaticPool for remote seed URLs."""
        if _is_remote_url(url):
            return pool.StaticPool
        return pool.NullPool

    def create_connect_args(self, url: URL) -> ConnectArgsType:
        """Translate a SQLAlchemy URL into `zxlite.connect` arguments."""
        if url.username or url.password:
            raise exc.ArgumentError(
                "zxlite URLs carry no credentials; use connect_args "
                "for auth_file and TLS paths"
            )
        if _is_remote_url(url):
            return self._create_remote_connect_args(url)
        return self._create_local_connect_args(url)

    def _create_local_connect_args(self, url: URL) -> ConnectArgsType:
        """Build local connect arguments (Gate C by default)."""
        if url.host:
            raise exc.ArgumentError(
                "remote zxlite SQLAlchemy URLs use the "
                "zxlite:///?seed=... query form, not a host"
            )
        if url.query:
            raise exc.ArgumentError("local zxlite URLs accept no query options")
        database = url.database or ""
        if not database:
            raise exc.ArgumentError(
                "local zxlite URLs need a data directory path: "
                "zxlite:///relative or zxlite:////absolute"
            )
        requested = (
            getattr(self, "_on_connect_isolation_level", None) or self.isolation_level
        )
        if requested == "AUTOCOMMIT":
            connect_args: dict[str, Any] = {}
        else:
            connect_args = {
                "isolation_level": "DEFERRED",
                "autocommit": False,
            }
        return (database,), connect_args

    def _create_remote_connect_args(self, url: URL) -> ConnectArgsType:
        """Rebuild the remote DSN from repeated seed= query values."""
        if url.host or url.database:
            raise exc.ArgumentError(
                "remote zxlite URLs must keep seeds in the query "
                "string: zxlite:///?seed=host%3Aport&..."
            )
        # create_engine(isolation_level=...) is stored as the
        # on-connect level, not as self.isolation_level.
        requested = (
            getattr(self, "_on_connect_isolation_level", None) or self.isolation_level
        )
        if requested != "AUTOCOMMIT":
            raise exc.ArgumentError(
                "remote zxlite engines require "
                "isolation_level='AUTOCOMMIT'; transactions need a "
                "local Gate C connection"
            )
        pairs: list[str] = []
        for key, values in url.normalized_query.items():
            for value in values:
                pairs.append(f"{key}={quote(value, safe='')}")
        dsn = "zxlite:///?" + "&".join(pairs)
        return (dsn,), {}

    # -- transactions --------------------------------------------------

    def get_isolation_level(self, dbapi_connection: Any) -> str:
        """Report the effective isolation without touching the node."""
        if isinstance(dbapi_connection, ZxRemoteConnection):
            return "AUTOCOMMIT"
        return "SERIALIZABLE"

    def get_isolation_level_values(self, dbapi_connection: Any) -> tuple[str, ...]:
        """Accept AUTOCOMMIT plus SQLite's serializable default."""
        return ("AUTOCOMMIT", "SERIALIZABLE")

    def set_isolation_level(self, dbapi_connection: Any, level: str) -> None:
        """Do nothing: the mode is fixed by the connect arguments.

        Remote connections are always autocommit and Gate C local
        connections always serialize; there is no per-connection knob
        to flip after connect.
        """

    @staticmethod
    def _raw_connection(connection: Any) -> ZxConnection:
        """Return the underlying zxlite connection for dialect hooks."""
        pooled = connection.connection
        return getattr(pooled, "dbapi_connection", pooled)

    def do_savepoint(self, connection: Any, name: str) -> None:
        """Create a savepoint through the zxlite internal ordinal API."""
        raw = self._raw_connection(connection)
        state = raw.__dict__
        counter = state.get("_zx_savepoint_counter", 0) + 1
        state["_zx_savepoint_counter"] = counter
        state.setdefault("_zx_savepoint_ids", {})[name] = counter
        raw._savepoint(counter)

    def do_release_savepoint(self, connection: Any, name: str) -> None:
        """Release a savepoint created by `do_savepoint`."""
        raw = self._raw_connection(connection)
        index = raw.__dict__.get("_zx_savepoint_ids", {}).pop(name, None)
        if index is None:
            raise exc.InvalidRequestError(f"unknown savepoint {name!r}")
        raw._release_savepoint(index)

    def do_rollback_to_savepoint(self, connection: Any, name: str) -> None:
        """Roll back to a savepoint created by `do_savepoint`."""
        raw = self._raw_connection(connection)
        index = raw.__dict__.get("_zx_savepoint_ids", {}).get(name)
        if index is None:
            raise exc.InvalidRequestError(f"unknown savepoint {name!r}")
        raw._rollback_to_savepoint(index)

    # -- discovery -----------------------------------------------------

    def _get_server_version_info(self, connection: Any) -> tuple[int, ...]:
        """Read the bundled SQLite version through the driver."""
        text = connection.exec_driver_sql("select sqlite_version()").scalar()
        return tuple(int(part) for part in str(text).split("."))


dialect = ZxLiteDialect
