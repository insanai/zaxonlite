"""Host a zaxonlite cluster member from Python.

`start_server()` opens the transport-owning native cluster handle and
returns a `Server` that owns its background service thread.  Server
ownership is deliberately separate from DB-API connection ownership:
a served node is reached with `zxlite.connect("unix:...")` or a
`zxlite://` DSN, never through the `Server` object itself.
"""

from __future__ import annotations

import os
import threading
import warnings
import weakref
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from . import _zxlite
from .dbapi import (
    NotSupportedError,
    ProgrammingError,
    _is_numeric_loopback,
    _map_native_error,
    _NativeWorker,
)

__all__ = ["Member", "Server", "start_server"]

_ROLE_CODES = {
    "data_voter": 0,
    "witness": 1,
    "standby": 2,
    "read_replica": 3,
    "gateway": 4,
}

_MAX_MEMBERS = 36


@dataclass(frozen=True)
class Member:
    """One cluster member: numeric id, endpoint, and role."""

    id: int
    endpoint: str
    role: Literal["data_voter", "witness", "standby", "read_replica", "gateway"] = (
        "data_voter"
    )


def _warn_unclosed(capsule: object, worker: _NativeWorker) -> None:
    """Close a leaked server from its finalizer with a ResourceWarning."""
    warnings.warn(
        "unclosed zxlite.Server; call close() or use a with-statement",
        ResourceWarning,
        stacklevel=2,
        source=capsule,
    )
    try:
        worker.call(_zxlite.cluster_close, capsule)
    finally:
        worker.stop()


class Server:
    """A running cluster member owned by this process.

    Instances come from `start_server()`.  `close()` asks the member
    to stop, joins its native background thread, and releases the
    directory lock; it is idempotent.
    """

    def __init__(
        self,
        capsule: object,
        worker: _NativeWorker,
        *,
        endpoint: str,
        node_id: int,
        members: tuple[Member, ...],
    ) -> None:
        """Wrap an already-open native cluster handle."""
        self._capsule = capsule
        self._worker = worker
        self._endpoint = endpoint
        self._node_id = node_id
        self._members = members
        self._closed = False
        self._close_lock = threading.Lock()
        self._finalizer = weakref.finalize(self, _warn_unclosed, capsule, worker)

    @property
    def endpoint(self) -> str:
        """Return this member's own endpoint."""
        return self._endpoint

    @property
    def node_id(self) -> int:
        """Return this member's node id."""
        return self._node_id

    @property
    def members(self) -> tuple[Member, ...]:
        """Return the full member registry this server was given."""
        return self._members

    @property
    def closed(self) -> bool:
        """Report whether the server has been closed."""
        return self._closed

    def close(self) -> None:
        """Stop the member, join its native thread, release the lock."""
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        self._finalizer.detach()
        try:
            self._worker.call(_zxlite.cluster_close, self._capsule)
        finally:
            self._worker.stop()

    def __enter__(self) -> Server:
        """Return the server for use in a with-statement."""
        return self

    def __exit__(self, *exc_info: object) -> bool:
        """Close the server when the with-block exits."""
        self.close()
        return False


def _validate_members(members: Sequence[Member], node_id: int) -> tuple[Member, ...]:
    """Validate the member registry shape and return it as a tuple."""
    registry = tuple(members)
    if not 1 <= len(registry) <= _MAX_MEMBERS:
        raise ProgrammingError(
            f"members must contain between 1 and {_MAX_MEMBERS} entries"
        )
    seen_ids: set[int] = set()
    seen_endpoints: set[str] = set()
    for member in registry:
        if not isinstance(member, Member):
            raise ProgrammingError("members must be zxlite.Member instances")
        if not isinstance(member.id, int) or member.id <= 0:
            raise ProgrammingError(
                f"member ids must be positive integers; got {member.id!r}"
            )
        if member.id in seen_ids:
            raise ProgrammingError(f"duplicate member id {member.id}")
        seen_ids.add(member.id)
        if member.role not in _ROLE_CODES:
            raise ProgrammingError(
                f"unknown member role {member.role!r}; expected one "
                f"of {sorted(_ROLE_CODES)}"
            )
        if not isinstance(member.endpoint, str) or not member.endpoint:
            raise ProgrammingError("member endpoints must be strings")
        if member.endpoint in seen_endpoints:
            raise ProgrammingError(f"duplicate member endpoint {member.endpoint!r}")
        seen_endpoints.add(member.endpoint)
    if node_id not in seen_ids:
        raise ProgrammingError(f"node_id {node_id} is not in the member registry")
    return registry


def start_server(
    *,
    directory: str | os.PathLike[str],
    node_id: int,
    members: Sequence[Member],
    cluster_id: str | None = None,
    auth_file: str | os.PathLike[str] | None = None,
    tls_ca: str | os.PathLike[str] | None = None,
    tls_cert: str | os.PathLike[str] | None = None,
    tls_key: str | os.PathLike[str] | None = None,
    startup_timeout: float = 10.0,
    allow_psk_only_loopback: bool = False,
) -> Server:
    """Start one cluster member and return its `Server` handle.

    The SDK validates the registry shape before native startup;
    zaxonlite remains authoritative for voter counts, roles, identity
    derivation, transport policy, directory locking, and recovery.
    A single member whose endpoint is `unix:<absolute path>` serves
    one local node over an owner-only Unix socket (POSIX only).
    """
    registry = _validate_members(members, node_id)
    endpoint_by_id = {member.id: member.endpoint for member in registry}
    own_endpoint = endpoint_by_id[node_id]

    unix_members = [
        member for member in registry if member.endpoint.startswith("unix:")
    ]
    tls_values = [value for value in (tls_ca, tls_cert, tls_key) if value is not None]
    if unix_members:
        if os.name == "nt":
            raise NotSupportedError(
                "unix-domain endpoints are not supported on Windows"
            )
        if len(registry) != 1:
            raise ProgrammingError("a unix endpoint requires a single-member registry")
        only = unix_members[0]
        if only.role == "gateway":
            raise ProgrammingError("a unix-served member may not be a gateway")
        if not only.endpoint[len("unix:") :].startswith("/"):
            raise ProgrammingError("unix endpoint path must be absolute")
        if tls_values or allow_psk_only_loopback:
            raise ProgrammingError(
                "a unix endpoint composes with neither TLS nor allow_psk_only_loopback"
            )
    if tls_values and len(tls_values) != 3:
        raise ProgrammingError(
            "tls_ca, tls_cert, and tls_key must be supplied together"
        )
    if allow_psk_only_loopback:
        if auth_file is None:
            raise ProgrammingError("allow_psk_only_loopback requires auth_file")
        if tls_values:
            raise ProgrammingError("allow_psk_only_loopback forbids TLS arguments")
        for member in registry:
            if not _is_numeric_loopback(member.endpoint):
                raise ProgrammingError(
                    f"allow_psk_only_loopback requires numeric "
                    f"loopback endpoints; got {member.endpoint!r}"
                )
    if not isinstance(startup_timeout, (int, float)) or (startup_timeout <= 0):
        raise ProgrammingError("startup_timeout must be positive seconds")

    native_members = tuple(
        (member.id, member.endpoint, _ROLE_CODES[member.role]) for member in registry
    )
    worker = _NativeWorker()
    try:
        capsule = worker.call(
            _zxlite.cluster_open,
            os.fspath(directory),
            node_id,
            native_members,
            cluster_id,
            os.fspath(auth_file) if auth_file is not None else None,
            os.fspath(tls_cert) if tls_cert is not None else None,
            os.fspath(tls_key) if tls_key is not None else None,
            os.fspath(tls_ca) if tls_ca is not None else None,
            int(startup_timeout * 1000),
            bool(allow_psk_only_loopback),
        )
    except _zxlite._ZxError as error:
        worker.stop()
        raise _map_native_error(error) from None
    except BaseException:
        worker.stop()
        raise
    return Server(
        capsule,
        worker,
        endpoint=own_endpoint,
        node_id=node_id,
        members=registry,
    )
