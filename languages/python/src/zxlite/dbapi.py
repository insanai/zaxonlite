"""DB-API 2.0 driver for zaxonlite.

Local targets open an embedded node directory.  Gate A connections are
autocommit-only; Gate C connections (`isolation_level="DEFERRED"`,
`autocommit=False`) hold a live local transaction between calls.
Remote targets (`zxlite://` DSNs and `unix:` sockets) connect a pooled
external client to an existing cluster and stay autocommit-only.

Concurrency model for local connections: all native calls serialize
through an ordered first-in-first-out ticket lane.  A write that cannot
enter the lane within the connection `timeout` raises
`OperationalError` with the stable category `"write_queue_timeout"`;
the statement provably never executed and a plain retry is safe.  Lane
contention never surfaces as a "database is locked" error.  Remote
connections rely on the native pool's own write lane and read slots.
"""

from __future__ import annotations

import os
import queue
import re
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from typing import Any
from urllib.parse import unquote

from . import _zxlite

__all__ = [
    "Connection",
    "Cursor",
    "DataError",
    "DatabaseError",
    "Error",
    "IntegrityError",
    "InterfaceError",
    "InternalError",
    "NotSupportedError",
    "OperationalError",
    "ProgrammingError",
    "RemoteConnection",
    "Warning",
    "apilevel",
    "connect",
    "paramstyle",
    "threadsafety",
]

apilevel = "2.0"
threadsafety = 2
paramstyle = "qmark"

# The SQLite amalgamation statically compiled into the native library
# (pinned in zaxonlite's build.zig.zon).  SQLAlchemy's SQLite dialect
# reads these attributes for feature gating; tests verify they match
# `select sqlite_version()` so a native bump cannot drift.
sqlite_version = "3.50.4"
sqlite_version_info = (3, 50, 4)

_RowFactory = Callable[["Cursor", tuple[Any, ...]], Any]
_Description = tuple[tuple[str, None, None, None, None, None, None], ...]

# Native error categories (`zaxonlite_last_error_category`), by value.
_CATEGORY_NAMES = {
    0: "none",
    1: "constraint",
    2: "busy",
    3: "interrupt",
    4: "misuse",
    5: "storage",
    6: "integrity",
    7: "availability",
    8: "session",
    9: "sql",
    10: "validation",
}

# Prefixes that classify a statement as a read for lane-admission and
# remote routing purposes; local routing is decided by the native
# describe() once the statement is admitted, and remote read routing
# falls back to the write path when the server reports a write.
_READ_PREFIXES = frozenset({"select", "values", "explain", "pragma"})

_REMOTE_READ_LEVELS = {"any": 0, "leader": 1, "linearizable": 2}
_REMOTE_READ_POLICIES = ("least_in_flight", "round_robin")

_RETURNING_PATTERN = re.compile(r"\breturning\b", re.IGNORECASE)


class Warning(Exception):  # noqa: A001 - name fixed by DB-API 2.0
    """Important driver warnings, per DB-API 2.0."""

    category: str | None = None


class Error(Exception):
    """Base class of all zxlite errors."""

    category: str | None = None


class InterfaceError(Error):
    """Errors related to the driver interface, not the database."""


class DatabaseError(Error):
    """Errors related to the database."""


class DataError(DatabaseError):
    """Errors due to problems with the processed data."""


class OperationalError(DatabaseError):
    """Errors related to the database's operation."""


class IntegrityError(DatabaseError):
    """Errors when the relational integrity is affected."""


class InternalError(DatabaseError):
    """Errors from internal database malfunction."""


class ProgrammingError(DatabaseError):
    """Errors caused by the application's use of the API."""


class NotSupportedError(DatabaseError):
    """Errors for requested features the driver does not support."""


def _diagnostic(title: str, message: str, hint: str) -> str:
    """Format one operating error using the repository's Elm-style shape."""
    return f"-- {title.upper()} --\n\n{message}\n\nHint: {hint}"


def _map_native_error(error: BaseException) -> Error:
    """Translate a native `_ZxError` into the DB-API hierarchy."""
    code = getattr(error, "code", None)
    category = getattr(error, "category", 0)
    message = getattr(error, "message", None) or str(error)
    if code == 2:
        exception_type: type[Error] = ProgrammingError
    elif code == 4:
        exception_type = OperationalError
    elif code == 3:
        exception_type = DatabaseError
    elif code == 1:
        exception_type = {
            1: IntegrityError,
            2: OperationalError,
            3: OperationalError,
            8: OperationalError,
            10: ProgrammingError,
        }.get(category, OperationalError)
    else:
        exception_type = OperationalError
    if exception_type is OperationalError and category in (5, 7):
        message = _diagnostic(
            "database unavailable",
            message,
            "Check the node status, storage, transport, and quorum, then retry.",
        )
    mapped = exception_type(message)
    mapped.category = _CATEGORY_NAMES.get(category, "none")
    return mapped


def _map_remote_error(error: BaseException) -> Error:
    """Translate a native remote `_ZxError` into the DB-API hierarchy.

    Remote database-identity failures (return code 3 / category 6)
    map to `InterfaceError` per the ZDS 0010 failure table: the wire
    endpoint is not the database this connection was pinned to.  A
    write-lane admission timeout (code 4, category busy, "write queue
    admission timed out") maps to `OperationalError` with the stable
    category `"write_queue_timeout"`, matching the local write lane:
    the statement never left the process and a plain retry is safe.
    """
    code = getattr(error, "code", None)
    category = getattr(error, "category", 0)
    if code == 3 or category == 6:
        message = getattr(error, "message", None) or str(error)
        mismatched = InterfaceError(
            _diagnostic(
                "database identity mismatch",
                message,
                "Verify the seed list, credentials, and expected_database_id.",
            )
        )
        mismatched.category = _CATEGORY_NAMES.get(category, "integrity")
        return mismatched
    mapped = _map_native_error(error)
    if (
        isinstance(mapped, OperationalError)
        and mapped.category == "busy"
        and "admission timed out" in str(mapped)
    ):
        mapped.category = "write_queue_timeout"
        mapped.args = (
            _diagnostic(
                "write queue timeout",
                "The write was not admitted before the configured timeout.",
                "A plain retry is safe; increase timeout or reduce "
                "concurrent writers if contention persists.",
            ),
        )
    return mapped


def _leading_keyword(sql: str) -> str:
    """Return the first SQL keyword, skipping whitespace and comments."""
    text = sql
    index = 0
    length = len(text)
    while index < length:
        if text[index].isspace():
            index += 1
        elif text.startswith("--", index):
            newline = text.find("\n", index)
            index = length if newline < 0 else newline + 1
        elif text.startswith("/*", index):
            closing = text.find("*/", index + 2)
            index = length if closing < 0 else closing + 2
        else:
            break
    start = index
    while index < length and (text[index].isalpha() or text[index] == "_"):
        index += 1
    return text[start:index].lower()


def _guess_is_write(sql: str) -> bool:
    """Classify a statement for lane admission without preparing it.

    Return False only for clearly read-shaped statements; every other
    statement conservatively takes the bounded write wait.  Local
    routing is decided by the native describe(), never by this guess.
    """
    return _leading_keyword(sql) not in _READ_PREFIXES


def _scan_sql(sql: str) -> tuple[bool, str]:
    """Scan `sql` outside literals, quoted identifiers, and comments.

    Return `(has_tail, stripped)` where `has_tail` reports a top-level
    semicolon followed by more content, and `stripped` is the SQL with
    every literal, quoted identifier, and comment blanked out (useful
    for keyword checks that must not match inside strings).  Local
    connections use the native describe() instead; this scanner guards
    the remote path, where the wire protocol carries one statement.
    """
    out = list(sql)

    def blank(start: int, stop: int) -> None:
        for position in range(start, min(stop, len(out))):
            out[position] = " "

    index = 0
    length = len(sql)
    seen_semicolon = False
    has_tail = False
    while index < length:
        character = sql[index]
        if character in "'\"`":
            start = index
            index += 1
            while index < length:
                if sql[index] == character:
                    if index + 1 < length and sql[index + 1] == character:
                        index += 2
                        continue
                    break
                index += 1
            index += 1
            blank(start, index)
        elif character == "[":
            closing = sql.find("]", index + 1)
            stop = length if closing < 0 else closing + 1
            blank(index, stop)
            index = stop
        elif sql.startswith("--", index):
            newline = sql.find("\n", index)
            stop = length if newline < 0 else newline + 1
            blank(index, stop)
            index = stop
        elif sql.startswith("/*", index):
            closing = sql.find("*/", index + 2)
            stop = length if closing < 0 else closing + 2
            blank(index, stop)
            index = stop
        elif character == ";":
            seen_semicolon = True
            index += 1
        elif character.isspace():
            index += 1
        else:
            if seen_semicolon:
                has_tail = True
            index += 1
    return has_tail, "".join(out)


def _sql_has_tail(sql: str) -> bool:
    """Report whether `sql` contains more than one statement."""
    has_tail, _ = _scan_sql(sql)
    return has_tail


def _sql_mentions_returning(sql: str) -> bool:
    """Report a RETURNING keyword outside literals and comments."""
    _, stripped = _scan_sql(sql)
    return _RETURNING_PATTERN.search(stripped) is not None


class _WriteLane:
    """Ordered first-in-first-out admission lane for one connection.

    Waiters queue on tickets under one condition variable; only the
    ticket at the head of the queue may proceed, so a sustained stream
    of writers cannot starve an earlier caller (a bare lock gives no
    such ordering guarantee).
    """

    #: Generous internal cap for waits that must not use the write
    #: timeout (reads and maintenance calls).
    READ_WAIT_CAP = 3600.0

    def __init__(self) -> None:
        """Create an empty lane."""
        self._condition = threading.Condition()
        self._tickets: deque[object] = deque()
        self._active = False

    @contextmanager
    def enter(self, *, write: bool, timeout: float) -> Iterator[None]:
        """Wait for lane admission in arrival order, then hold the lane.

        A write bounded by `timeout` that is not admitted in time raises
        `OperationalError` with category `"write_queue_timeout"`; the
        protected call was never started.
        """
        bound = timeout if write else self.READ_WAIT_CAP
        deadline = time.monotonic() + bound
        ticket = object()
        with self._condition:
            self._tickets.append(ticket)
            while self._active or self._tickets[0] is not ticket:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._tickets.remove(ticket)
                    self._condition.notify_all()
                    if write:
                        timed_out = OperationalError(
                            _diagnostic(
                                "write queue timeout",
                                "The write did not enter the connection "
                                f"lane within {bound:.3f} seconds. The "
                                "statement did not execute.",
                                "A plain retry is safe; increase timeout or "
                                "reduce concurrent writers if contention "
                                "persists.",
                            )
                        )
                        timed_out.category = "write_queue_timeout"
                        raise timed_out
                    stalled = OperationalError(
                        _diagnostic(
                            "connection lane stalled",
                            "A read waited beyond the internal connection cap.",
                            "Close the connection and inspect blocked native calls.",
                        )
                    )
                    stalled.category = "busy"
                    raise stalled
                self._condition.wait(remaining)
            self._tickets.popleft()
            self._active = True
        try:
            yield
        finally:
            with self._condition:
                self._active = False
                self._condition.notify_all()


# zaxonlite's replay and consensus paths need more stack than many
# hosts give a thread (CPython worker threads default to 512 KiB on
# macOS; some interpreter builds cap the main thread at 8 MiB), so
# every local native call runs on a dedicated big-stack thread.
_NATIVE_STACK_BYTES = 32 * 1024 * 1024

# `threading.stack_size` is process-global; serialize set/spawn/restore.
_STACK_SIZE_LOCK = threading.Lock()


class _NativeWorker:
    """One dedicated big-stack thread that runs a connection's native calls.

    The write lane already serializes callers, so the worker only ever
    holds one request at a time; it also gives the native handle a
    single executing thread for its whole life.
    """

    def __init__(self) -> None:
        """Spawn the worker thread with an enlarged stack."""
        self._requests: queue.SimpleQueue[
            tuple[
                Callable[..., Any],
                tuple[Any, ...],
                dict[str, Any],
                threading.Event,
            ]
            | None
        ] = queue.SimpleQueue()
        with _STACK_SIZE_LOCK:
            previous = threading.stack_size(_NATIVE_STACK_BYTES)
            try:
                self._thread = threading.Thread(
                    target=self._run, name="zxlite-native", daemon=True
                )
                self._thread.start()
            finally:
                threading.stack_size(previous)

    def _run(self) -> None:
        """Serve native call requests until stopped."""
        while True:
            request = self._requests.get()
            if request is None:
                return
            function, args, box, done = request
            try:
                box["value"] = function(*args)
            except BaseException as error:  # noqa: BLE001 - re-raised
                box["error"] = error
            done.set()

    def call(self, function: Callable[..., Any], *args: Any) -> Any:
        """Run `function(*args)` on the worker thread and return its result."""
        box: dict[str, Any] = {}
        done = threading.Event()
        self._requests.put((function, args, box, done))
        done.wait()
        if "error" in box:
            raise box["error"]
        return box["value"]

    def stop(self) -> None:
        """Ask the worker thread to exit after pending requests."""
        self._requests.put(None)


def _normalize_parameters(parameters: Any) -> tuple[Any, ...]:
    """Validate positional qmark parameters and return them as a tuple."""
    if isinstance(parameters, (str, bytes, bytearray, memoryview)):
        raise ProgrammingError(
            "parameters must be a sequence of values, not a single "
            "string or bytes-like object"
        )
    if not isinstance(parameters, Sequence):
        raise ProgrammingError("parameters must be a sequence of values")
    return tuple(parameters)


# --- remote DSN parsing ------------------------------------------------


_SINGLETON_OPTIONS = (
    "read_level",
    "read_policy",
    "freshness_ms",
    "pool_size",
    "connect_timeout_ms",
    "operation_timeout_ms",
    "expected_database_id",
)


def _strict_unquote(value: str, what: str) -> str:
    """Percent-decode `value`, rejecting malformed escapes."""
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise ProgrammingError(f"invalid percent encoding in {what}")
    return unquote(value, errors="strict")


def _validate_tcp_seed(seed: str) -> str:
    """Validate one host:port seed and return it unchanged."""
    if seed.startswith("["):
        closing = seed.find("]")
        if closing < 0 or not seed[closing + 1 :].startswith(":"):
            raise ProgrammingError(
                f"IPv6 seed must use [address]:port syntax: {seed!r}"
            )
        host = seed[1:closing]
        port_text = seed[closing + 2 :]
    else:
        host, separator, port_text = seed.rpartition(":")
        if not separator or ":" in host:
            raise ProgrammingError(
                f"seed must be host:port (IPv6 literals need brackets): {seed!r}"
            )
    if not host:
        raise ProgrammingError(f"seed has an empty host: {seed!r}")
    if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise ProgrammingError(f"seed has an invalid port: {seed!r}")
    return seed


def _validate_unix_endpoint(endpoint: str) -> str:
    """Validate one unix:<absolute-path> endpoint and return it."""
    path = endpoint[len("unix:") :]
    if os.name == "nt":
        raise NotSupportedError("unix-domain endpoints are not supported on Windows")
    if not path.startswith("/"):
        raise ProgrammingError(f"unix endpoint path must be absolute: {endpoint!r}")
    if "\x00" in path:
        raise ProgrammingError("unix endpoint path contains NUL")
    return endpoint


def _parse_unsigned(value: str, name: str) -> int:
    """Parse one unsigned integer DSN option."""
    if not value.isdigit():
        raise ProgrammingError(f"{name} must be an unsigned integer")
    return int(value)


def _parse_remote_dsn(dsn: str) -> dict[str, Any]:
    """Parse a zxlite:// DSN into seeds and validated options.

    Implements the ZDS 0010 grammar: the authority form with
    comma-separated seeds and the query form with repeated
    percent-encoded seed= values.  Rejection happens before any
    network activity.
    """
    if "#" in dsn:
        raise ProgrammingError("remote DSN must not contain a fragment")
    rest = dsn[len("zxlite://") :]
    authority, _, query = rest.partition("?")
    if authority.endswith("/"):
        authority = authority[:-1]
    if "/" in authority:
        raise ProgrammingError(
            "remote DSN must not contain a path (only an optional trailing slash)"
        )
    if "@" in authority:
        raise ProgrammingError("remote DSN must not contain userinfo")

    options: dict[str, Any] = {}
    query_seeds: list[str] = []
    if query:
        for pair in query.split("&"):
            if not pair:
                raise ProgrammingError("empty option in remote DSN query")
            key, separator, raw_value = pair.partition("=")
            if not separator:
                raise ProgrammingError(f"remote DSN option needs a value: {key!r}")
            value = _strict_unquote(raw_value, f"option {key!r}")
            if key == "seed":
                if authority:
                    raise ProgrammingError(
                        "seed= options require the zxlite:///? form "
                        "without authority seeds"
                    )
                query_seeds.append(value)
            elif key in _SINGLETON_OPTIONS:
                if key in options:
                    raise ProgrammingError(f"duplicate remote DSN option: {key!r}")
                options[key] = value
            else:
                raise ProgrammingError(f"unknown remote DSN option: {key!r}")

    if authority:
        seeds = [_strict_unquote(seed, "seed") for seed in authority.split(",")]
    else:
        seeds = query_seeds
    if not seeds or any(not seed for seed in seeds):
        raise ProgrammingError("remote DSN needs at least one seed")
    if len(seeds) > 36:
        raise ProgrammingError("remote DSN accepts at most 36 seeds")
    if len(set(seeds)) != len(seeds):
        raise ProgrammingError("remote DSN seeds must be unique")

    unix_seeds = [seed for seed in seeds if seed.startswith("unix:")]
    if unix_seeds:
        if authority:
            raise ProgrammingError("unix endpoints cannot appear in the authority form")
        if len(seeds) != 1:
            raise ProgrammingError("a unix endpoint must be the only seed")
        _validate_unix_endpoint(seeds[0])
    else:
        for seed in seeds:
            _validate_tcp_seed(seed)

    parsed: dict[str, Any] = {"seeds": tuple(seeds)}
    if "read_level" in options:
        if options["read_level"] not in _REMOTE_READ_LEVELS:
            raise ProgrammingError(
                f"read_level must be one of {sorted(_REMOTE_READ_LEVELS)}"
            )
        parsed["read_level"] = options["read_level"]
    if "read_policy" in options:
        if options["read_policy"] not in _REMOTE_READ_POLICIES:
            raise ProgrammingError(
                f"read_policy must be one of {sorted(_REMOTE_READ_POLICIES)}"
            )
        parsed["read_policy"] = options["read_policy"]
    for name in (
        "freshness_ms",
        "pool_size",
        "connect_timeout_ms",
        "operation_timeout_ms",
    ):
        if name in options:
            parsed[name] = _parse_unsigned(options[name], name)
    if "expected_database_id" in options:
        parsed["expected_database_id"] = options["expected_database_id"]
    return parsed


def _decode_database_id(value: Any) -> bytes:
    """Normalize an expected database identity to 16 raw bytes."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) != 16:
            raise ProgrammingError("expected_database_id bytes must have length 16")
        return raw
    if isinstance(value, str):
        text = value.strip().lower()
        if len(text) != 32 or any(
            character not in "0123456789abcdef" for character in text
        ):
            raise ProgrammingError("expected_database_id must be 32 hexadecimal digits")
        return bytes.fromhex(text)
    raise ProgrammingError(
        "expected_database_id must be a 32-hex-digit string or 16 bytes"
    )


def _is_numeric_loopback(endpoint: str) -> bool:
    """Report whether a TCP endpoint's host is numeric loopback."""
    if endpoint.startswith("["):
        host = endpoint[1 : endpoint.find("]")]
    else:
        host = endpoint.rpartition(":")[0]
    return host in ("127.0.0.1", "::1")


def _search_arguments(
    *,
    fts_table: str | None,
    vec_table: str | None,
    text: str | None,
    embedding: bytes | bytearray | memoryview | None,
    k: int,
    candidate_count: int | None,
    fusion: str,
    text_weight: float,
    vector_weight: float,
    metadata_table: str | None,
    metadata_id_column: str | None,
    metadata_columns: Sequence[str],
) -> dict[str, Any]:
    """Validate Python search types and build native keyword arguments."""
    fusion_codes = {"rrf": 0, "dbsf": 1}
    if fusion not in fusion_codes:
        raise ProgrammingError(f"fusion must be 'rrf' or 'dbsf', not {fusion!r}")
    if text is not None and not isinstance(text, str):
        raise ProgrammingError("text must be a str")
    if embedding is not None and not isinstance(
        embedding, (bytes, bytearray, memoryview)
    ):
        raise ProgrammingError(
            "embedding must be bytes, bytearray, or a contiguous "
            "memoryview of little-endian float32 values"
        )
    for name, value in (
        ("fts_table", fts_table),
        ("vec_table", vec_table),
        ("metadata_table", metadata_table),
        ("metadata_id_column", metadata_id_column),
    ):
        if value is not None and not isinstance(value, str):
            raise ProgrammingError(f"{name} must be a str")
    columns = tuple(metadata_columns)
    if any(not isinstance(column, str) for column in columns):
        raise ProgrammingError("metadata_columns must contain only str values")
    if not isinstance(k, int) or isinstance(k, bool):
        raise ProgrammingError("k must be an int")
    if candidate_count is not None and (
        not isinstance(candidate_count, int) or isinstance(candidate_count, bool)
    ):
        raise ProgrammingError("candidate_count must be an int")
    try:
        text_weight_value = float(text_weight)
        vector_weight_value = float(vector_weight)
    except (TypeError, ValueError):
        raise ProgrammingError("search weights must be real numbers") from None
    return {
        "fts_table": fts_table,
        "vec_table": vec_table,
        "text": text,
        "embedding": embedding,
        "k": k,
        "candidate_count": candidate_count,
        "fusion": fusion_codes[fusion],
        "text_weight": text_weight_value,
        "vector_weight": vector_weight_value,
        "metadata_table": metadata_table,
        "metadata_id_column": metadata_id_column,
        "metadata_columns": columns,
    }


def connect(
    target: str | os.PathLike[str],
    *,
    timeout: float = 5.0,
    isolation_level: str | None = None,
    check_same_thread: bool | None = None,
    autocommit: bool = True,
    tls_ca: str | None = None,
    tls_cert: str | None = None,
    tls_key: str | None = None,
    auth_file: str | None = None,
    allow_psk_only_loopback: bool = False,
    read_level: str | None = None,
    read_policy: str | None = None,
    freshness_ms: int | None = None,
    pool_size: int | None = None,
    connect_timeout_ms: int | None = None,
    operation_timeout_ms: int | None = None,
    expected_database_id: str | bytes | None = None,
) -> Connection | RemoteConnection:
    """Open a zaxonlite connection.

    A filesystem path opens the embedded local node.  Local
    connections accept `isolation_level=None` with `autocommit=True`
    (Gate A autocommit) or `isolation_level="DEFERRED"` with
    `autocommit=False` (Gate C live transactions).  A `zxlite://` DSN
    or `unix:` endpoint opens a pooled remote client connection, which
    is always autocommit; opening probes one seed (bounded by
    `connect_timeout_ms`) and fails when no seed authenticates and
    reports the pinned database identity.

    `timeout` bounds a write's wait for its connection's ordered write
    lane, never an SQLite file lock.  On expiry the raised
    `OperationalError` carries category `"write_queue_timeout"`, the
    statement never left the process, and a plain retry is safe; this
    holds for local and remote connections alike.

    `read_policy` accepts `"least_in_flight"` and `"round_robin"`;
    with single-call pool slots the two schedules coincide by
    construction, so the choice is currently a documented no-op.
    """
    path = os.fspath(target)
    if not isinstance(path, str):
        raise InterfaceError("target must be a str or PathLike path")

    if not path.startswith(("zxlite://", "unix:")):
        return _connect_local(
            path,
            timeout=timeout,
            isolation_level=isolation_level,
            check_same_thread=check_same_thread,
            autocommit=autocommit,
            tls_ca=tls_ca,
            tls_cert=tls_cert,
            tls_key=tls_key,
            auth_file=auth_file,
            allow_psk_only_loopback=allow_psk_only_loopback,
            read_level=read_level,
            read_policy=read_policy,
            freshness_ms=freshness_ms,
            pool_size=pool_size,
            connect_timeout_ms=connect_timeout_ms,
            operation_timeout_ms=operation_timeout_ms,
            expected_database_id=expected_database_id,
        )

    if isolation_level is not None or autocommit is not True:
        raise NotSupportedError(
            "remote connections are autocommit-only; transactions "
            "require a local Gate C connection"
        )
    if path.startswith("unix:"):
        _validate_unix_endpoint(path)
        parsed: dict[str, Any] = {"seeds": (path,)}
    else:
        parsed = _parse_remote_dsn(path)

    keyword_options: dict[str, Any] = {
        "read_level": read_level,
        "read_policy": read_policy,
        "freshness_ms": freshness_ms,
        "pool_size": pool_size,
        "connect_timeout_ms": connect_timeout_ms,
        "operation_timeout_ms": operation_timeout_ms,
        "expected_database_id": expected_database_id,
    }
    for name, value in keyword_options.items():
        if value is None:
            continue
        if name in parsed:
            raise ProgrammingError(
                f"{name} is specified both in the DSN and as a keyword argument"
            )
        parsed[name] = value

    effective_read_level = parsed.get("read_level") or "linearizable"
    if effective_read_level not in _REMOTE_READ_LEVELS:
        raise ProgrammingError(
            f"read_level must be one of {sorted(_REMOTE_READ_LEVELS)}"
        )
    effective_policy = parsed.get("read_policy")
    if effective_policy is not None and (effective_policy not in _REMOTE_READ_POLICIES):
        raise ProgrammingError(
            f"read_policy must be one of {sorted(_REMOTE_READ_POLICIES)}"
        )
    effective_freshness = parsed.get("freshness_ms")
    if effective_freshness is not None and effective_read_level != "any":
        raise ProgrammingError("freshness_ms is only meaningful with read_level=any")
    effective_pool = parsed.get("pool_size")
    if effective_pool is not None and not 1 <= int(effective_pool) <= 64:
        raise ProgrammingError("pool_size must be between 1 and 64")

    seeds: tuple[str, ...] = parsed["seeds"]
    unix_mode = seeds[0].startswith("unix:")
    tls_arguments = (tls_ca, tls_cert, tls_key)
    tls_supplied = [value for value in tls_arguments if value is not None]
    if tls_supplied and len(tls_supplied) != 3:
        raise ProgrammingError(
            "tls_ca, tls_cert, and tls_key must be supplied together"
        )
    if unix_mode and (tls_supplied or allow_psk_only_loopback):
        raise ProgrammingError(
            "a unix endpoint composes with neither TLS nor allow_psk_only_loopback"
        )
    if allow_psk_only_loopback:
        if auth_file is None:
            raise ProgrammingError("allow_psk_only_loopback requires auth_file")
        if tls_supplied:
            raise ProgrammingError("allow_psk_only_loopback forbids TLS arguments")
        for seed in seeds:
            if not _is_numeric_loopback(seed):
                raise ProgrammingError(
                    f"allow_psk_only_loopback requires numeric "
                    f"loopback seeds; got {seed!r}"
                )

    identity = parsed.get("expected_database_id")
    identity_bytes = _decode_database_id(identity) if identity is not None else None

    # `timeout` bounds a write's wait for the ordered write lane on
    # both connection kinds; remotely it becomes the native
    # write-admission bound (seconds to milliseconds, minimum 1 ms).
    admission_ms = max(1, int(timeout * 1000)) if timeout > 0 else 1

    return RemoteConnection(
        seeds,
        tls_ca=tls_ca,
        tls_cert=tls_cert,
        tls_key=tls_key,
        auth_file=auth_file,
        allow_psk_only_loopback=allow_psk_only_loopback,
        pool_size=int(effective_pool) if effective_pool else 0,
        connect_timeout_ms=int(parsed.get("connect_timeout_ms") or 0),
        operation_timeout_ms=int(parsed.get("operation_timeout_ms") or 0),
        expected_database_id=identity_bytes,
        read_level=effective_read_level,
        freshness_ms=int(effective_freshness or 0),
        check_same_thread=(False if check_same_thread is None else check_same_thread),
        write_admission_timeout_ms=admission_ms,
    )


def _connect_local(
    path: str,
    *,
    timeout: float,
    isolation_level: str | None,
    check_same_thread: bool | None,
    autocommit: bool,
    **remote_only: Any,
) -> Connection:
    """Open a local connection after rejecting remote-only options."""
    for name, value in remote_only.items():
        if name == "allow_psk_only_loopback":
            if value:
                raise NotSupportedError(f"{name} applies to remote connections")
        elif name == "read_level":
            if value not in (None, "linearizable"):
                raise NotSupportedError(
                    "local connections serve linearizable reads only"
                )
        elif value is not None:
            raise NotSupportedError(f"{name} applies to remote connections")
    if isolation_level is None and autocommit is True:
        transactional = False
    elif isolation_level == "DEFERRED" and autocommit is False:
        transactional = True
    else:
        raise NotSupportedError(
            "local connections accept isolation_level=None with "
            "autocommit=True (Gate A) or isolation_level='DEFERRED' "
            "with autocommit=False (Gate C)"
        )
    return Connection(
        path,
        timeout=timeout,
        check_same_thread=(True if check_same_thread is None else check_same_thread),
        transactional=transactional,
    )


class _BaseConnection:
    """Shared DB-API surface for local and remote connections."""

    row_factory: _RowFactory | None

    def __init__(self, *, check_same_thread: bool) -> None:
        """Initialize the shared connection state."""
        self.row_factory = None
        self._check_same_thread = bool(check_same_thread)
        self._owner_thread = threading.get_ident()
        self._total_changes = 0
        self._closed = False

    def _check(self) -> None:
        """Reject use after close or from a foreign thread."""
        if self._closed:
            raise ProgrammingError("Cannot operate on a closed database.")
        if self._check_same_thread and threading.get_ident() != self._owner_thread:
            raise ProgrammingError(
                f"zxlite objects created in a thread can only be used "
                f"in that same thread. The object was created in "
                f"thread id {self._owner_thread} and this is thread "
                f"id {threading.get_ident()}."
            )

    def cursor(self, factory: type[Cursor] | None = None) -> Cursor:
        """Return a new cursor for this connection."""
        self._check()
        cursor_type = factory if factory is not None else Cursor
        cursor = cursor_type(self)
        if not isinstance(cursor, Cursor):
            raise TypeError("factory must produce a zxlite Cursor")
        return cursor

    def execute(self, sql: str, parameters: Any = ()) -> Cursor:
        """Create a cursor, execute one statement, and return it."""
        return self.cursor().execute(sql, parameters)

    def executemany(self, sql: str, seq_of_parameters: Iterable[Any]) -> Cursor:
        """Create a cursor, run one statement over many rows, return it."""
        return self.cursor().executemany(sql, seq_of_parameters)

    def executescript(self, sql_script: str) -> Cursor:
        """Create a cursor, run a multi-statement script, return it."""
        return self.cursor().executescript(sql_script)

    @property
    def total_changes(self) -> int:
        """Total number of rows changed since the connection opened."""
        return self._total_changes

    @property
    def in_transaction(self) -> bool:
        """Report whether a transaction is open."""
        return False

    # Hooks implemented by each connection kind.

    def _cursor_execute(self, cursor: Cursor, sql: str, parameters: Any) -> None:
        """Execute one statement on behalf of `cursor`."""
        raise NotImplementedError

    def _cursor_executemany(
        self, cursor: Cursor, sql: str, seq_of_parameters: Iterable[Any]
    ) -> None:
        """Execute one statement over many rows on behalf of `cursor`."""
        raise NotImplementedError

    def _cursor_executescript(self, cursor: Cursor, sql_script: str) -> None:
        """Execute a script on behalf of `cursor`."""
        raise NotImplementedError

    @property
    def zaxonlite_version(self) -> str:
        """Return the native zaxonlite library version string."""
        return _zxlite.version()

    @property
    def sqlite_version(self) -> str:
        """Return the bundled SQLite version string."""
        return sqlite_version


class Connection(_BaseConnection):
    """One open zaxonlite node directory (local embedded node)."""

    def __init__(
        self,
        path: str,
        *,
        timeout: float = 5.0,
        check_same_thread: bool = True,
        transactional: bool = False,
    ) -> None:
        """Open the node data directory; prefer `zxlite.connect()`."""
        super().__init__(check_same_thread=check_same_thread)
        self._timeout = float(timeout)
        self._lane = _WriteLane()
        self._transactional = bool(transactional)
        self._in_tx = False
        self._worker = _NativeWorker()
        try:
            self._capsule = self._call(_zxlite.open, path)
        except BaseException:
            self._worker.stop()
            raise

    # -- plumbing -----------------------------------------------------

    def _call(self, function: Callable[..., Any], *args: Any) -> Any:
        """Invoke a native function on the worker and remap its errors."""
        try:
            return self._worker.call(function, *args)
        except _zxlite._ZxError as error:
            raise _map_native_error(error) from None

    def _resolve_parameters(
        self, sql: str, expected: int, parameters: Any
    ) -> tuple[Any, ...]:
        """Return the positional binding vector for one statement.

        A Mapping resolves `:name`, `@name`, and `$name` parameters
        through SQLite's own metadata; a sequence must match the
        statement's parameter count exactly.
        """
        if isinstance(parameters, Mapping):
            values = []
            for index in range(1, expected + 1):
                name = self._call(
                    _zxlite.statement_parameter_name,
                    self._capsule,
                    sql,
                    index,
                )
                if not name or name[0] not in ":@$":
                    raise ProgrammingError(
                        f"Binding {index} has no name, but you "
                        f"supplied a dictionary (which has only names)."
                    )
                key = name[1:]
                if key not in parameters:
                    raise ProgrammingError(
                        f"You did not supply a value for binding parameter {name}."
                    )
                values.append(parameters[key])
            return tuple(values)
        params = _normalize_parameters(parameters)
        if expected != len(params):
            raise ProgrammingError(
                f"Incorrect number of bindings supplied. The current "
                f"statement uses {expected}, and there are "
                f"{len(params)} supplied."
            )
        return params

    def _describe(self, sql: str) -> tuple[int, int, bool, bool]:
        """Prepare (without executing) and describe one statement."""
        return self._call(_zxlite.describe, self._capsule, sql)

    def _begin_if_needed(self) -> None:
        """Open the live transaction if none is active (Gate C)."""
        if not self._in_tx:
            self._call(_zxlite.live_begin, self._capsule)
            self._in_tx = True

    # -- DB-API surface ----------------------------------------------

    def commit(self) -> None:
        """Commit the open live transaction; a no-op in autocommit."""
        self._check()
        if not (self._transactional and self._in_tx):
            return
        with self._lane.enter(write=True, timeout=self._timeout):
            self._call(_zxlite.live_commit, self._capsule)
            self._in_tx = False

    def rollback(self) -> None:
        """Roll back the open live transaction; a no-op in autocommit."""
        self._check()
        if not (self._transactional and self._in_tx):
            return
        with self._lane.enter(write=True, timeout=self._timeout):
            self._call(_zxlite.live_rollback, self._capsule)
            self._in_tx = False

    def close(self) -> None:
        """Close the native handle; an open transaction rolls back."""
        if self._closed:
            return
        self._check()
        with self._lane.enter(write=False, timeout=self._timeout):
            self._closed = True
            try:
                if self._transactional and self._in_tx:
                    try:
                        self._call(_zxlite.live_rollback, self._capsule)
                    finally:
                        self._in_tx = False
                self._call(_zxlite.close, self._capsule)
            finally:
                self._worker.stop()

    def __enter__(self) -> Connection:
        """Return the connection for use in a with-statement."""
        self._check()
        return self

    def __exit__(self, exc_type: object, *exc_info: object) -> bool:
        """Commit on success or roll back on error, like `sqlite3`.

        The connection stays open, matching the standard library.
        """
        if not self._closed:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        return False

    @property
    def in_transaction(self) -> bool:
        """Report whether a live transaction is open."""
        return self._in_tx

    # -- cursor hooks -------------------------------------------------

    def _cursor_execute(self, cursor: Cursor, sql: str, parameters: Any) -> None:
        """Describe, route, and execute one statement for `cursor`."""
        with self._lane.enter(write=_guess_is_write(sql), timeout=self._timeout):
            parameter_count, _, read_only, has_tail = self._describe(sql)
            if has_tail:
                raise ProgrammingError(
                    "execute() accepts one statement; use executescript()"
                )
            params = self._resolve_parameters(sql, parameter_count, parameters)
            if self._transactional and (self._in_tx or not read_only):
                self._begin_if_needed()
                changes, lastrowid, _replayed, returning = self._call(
                    _zxlite.live_exec, self._capsule, sql, params
                )
                if read_only:
                    if returning is None:
                        returning = ((), ())
                    cursor._load_read_result(*returning)
                else:
                    cursor.rowcount = changes
                    self._total_changes += changes
                    if lastrowid is not None:
                        cursor.lastrowid = lastrowid
                    if returning is not None:
                        cursor._load_returning_result(*returning)
            elif read_only:
                column_names, rows = self._call(
                    _zxlite.query, self._capsule, sql, params
                )
                cursor._load_read_result(column_names, rows)
            else:
                changes, lastrowid, _replayed, returning = self._call(
                    _zxlite.exec, self._capsule, sql, params
                )
                cursor.rowcount = changes
                self._total_changes += changes
                if lastrowid is not None:
                    cursor.lastrowid = lastrowid
                if returning is not None:
                    cursor._load_returning_result(*returning)

    def _cursor_executemany(
        self, cursor: Cursor, sql: str, seq_of_parameters: Iterable[Any]
    ) -> None:
        """Run one DML statement over many rows as one atomic batch."""
        batches = list(seq_of_parameters)
        with self._lane.enter(write=True, timeout=self._timeout):
            parameter_count, _, read_only, has_tail = self._describe(sql)
            if has_tail:
                raise ProgrammingError(
                    "executemany() accepts one statement; use executescript()"
                )
            if read_only:
                raise ProgrammingError("executemany() can only execute DML statements.")
            resolved = [
                self._resolve_parameters(sql, parameter_count, parameters)
                for parameters in batches
            ]
            if not resolved:
                cursor.rowcount = 0
                return
            if self._transactional:
                self._begin_if_needed()
                total = 0
                for params in resolved:
                    changes, _, _, _ = self._call(
                        _zxlite.live_exec, self._capsule, sql, params
                    )
                    total += changes
                cursor.rowcount = total
                self._total_changes += total
                return
            transaction = self._call(_zxlite.begin, self._capsule)
            try:
                for params in resolved:
                    self._call(_zxlite.tx_exec, transaction, sql, params)
                changes = self._call(_zxlite.tx_commit, transaction)
            finally:
                self._call(_zxlite.tx_close, transaction)
            cursor.rowcount = changes
            self._total_changes += changes

    def _cursor_executescript(self, cursor: Cursor, sql_script: str) -> None:
        """Run a multi-statement script as one atomic one-shot batch.

        Like `sqlite3`, an open live transaction commits first.
        """
        with self._lane.enter(write=True, timeout=self._timeout):
            if self._transactional and self._in_tx:
                self._call(_zxlite.live_commit, self._capsule)
                self._in_tx = False
            changes = self._call(_zxlite.exec_script, self._capsule, sql_script)
            self._total_changes += changes

    # -- Gate C savepoints (internal; used by the SQLAlchemy dialect) --

    def _savepoint(self, index: int) -> None:
        """Create savepoint `index`, beginning a transaction if needed."""
        self._check()
        if not self._transactional:
            raise ProgrammingError(
                "savepoints require a Gate C transactional connection"
            )
        with self._lane.enter(write=True, timeout=self._timeout):
            self._begin_if_needed()
            self._call(_zxlite.live_savepoint, self._capsule, index)

    def _release_savepoint(self, index: int) -> None:
        """Release savepoint `index`."""
        self._check()
        with self._lane.enter(write=True, timeout=self._timeout):
            self._call(_zxlite.live_release_savepoint, self._capsule, index)

    def _rollback_to_savepoint(self, index: int) -> None:
        """Roll back to savepoint `index` without ending the transaction."""
        self._check()
        with self._lane.enter(write=True, timeout=self._timeout):
            self._call(_zxlite.live_rollback_to_savepoint, self._capsule, index)

    # -- zaxonlite-specific surface ----------------------------------

    def query(
        self,
        sql: str,
        parameters: Any = (),
        *,
        read_level: str | None = None,
        freshness_ms: int | None = None,
    ) -> Cursor:
        """Run a statement; local connections reject remote read options."""
        self._check()
        if read_level is not None or freshness_ms is not None:
            raise ProgrammingError(
                "read_level and freshness_ms apply to remote "
                "connections; a local connection rejects them"
            )
        return self.execute(sql, parameters)

    def snapshot(self) -> None:
        """Take an online snapshot and seal the journal epoch."""
        self._check()
        with self._lane.enter(write=True, timeout=self._timeout):
            self._call(_zxlite.snapshot, self._capsule)

    def backup(self, path: str | os.PathLike[str]) -> None:
        """Stream a consistent logical backup to `path`."""
        self._check()
        with self._lane.enter(write=True, timeout=self._timeout):
            self._call(_zxlite.backup, self._capsule, os.fspath(path))

    def integrity_check(self) -> None:
        """Verify the image, descriptor chain, and payloads."""
        self._check()
        with self._lane.enter(write=False, timeout=self._timeout):
            self._call(_zxlite.integrity_check, self._capsule)

    def open_session(self) -> int:
        """Open a replicated idempotent-retry session, returning its id."""
        self._check()
        with self._lane.enter(write=True, timeout=self._timeout):
            return self._call(_zxlite.session_open, self._capsule)

    def execute_idempotent(
        self, session: int, sequence: int, sql: str
    ) -> tuple[int, bool]:
        """Execute `sequence` for `session` exactly once.

        Return `(changes, replayed)`; retrying the last sequence
        replays the recorded result without executing SQL again.
        """
        self._check()
        with self._lane.enter(write=True, timeout=self._timeout):
            changes, replayed = self._call(
                _zxlite.exec_idempotent,
                self._capsule,
                session,
                sequence,
                sql,
            )
            if not replayed:
                self._total_changes += changes
            return changes, replayed

    def expire_sessions(self, retain: int) -> int:
        """Delete idle sessions, returning how many were removed."""
        self._check()
        with self._lane.enter(write=True, timeout=self._timeout):
            return self._call(_zxlite.expire_sessions, self._capsule, retain)

    def search(
        self,
        *,
        fts_table: str | None = None,
        vec_table: str | None = None,
        text: str | None = None,
        embedding: bytes | bytearray | memoryview | None = None,
        k: int = 10,
        candidate_count: int | None = None,
        fusion: str = "rrf",
        text_weight: float = 1.0,
        vector_weight: float = 1.0,
        metadata_table: str | None = None,
        metadata_id_column: str | None = None,
        metadata_columns: Sequence[str] = (),
        read_level: str | None = None,
        freshness_ms: int | None = None,
    ) -> Cursor:
        """Run a typed search (ZDS 0009) and return a materialized cursor.

        Lexical-only search requires `fts_table` and `text`;
        vector-only search requires `vec_table` and `embedding`;
        hybrid search supplies both branches.  Identifier, weight, and
        shape validation happens in the native planner.
        """
        self._check()
        if read_level is not None or freshness_ms is not None:
            raise ProgrammingError(
                "read_level and freshness_ms apply to remote "
                "connections; a local connection rejects them"
            )
        arguments = _search_arguments(
            fts_table=fts_table,
            vec_table=vec_table,
            text=text,
            embedding=embedding,
            k=k,
            candidate_count=candidate_count,
            fusion=fusion,
            text_weight=text_weight,
            vector_weight=vector_weight,
            metadata_table=metadata_table,
            metadata_id_column=metadata_id_column,
            metadata_columns=metadata_columns,
        )
        with self._lane.enter(write=False, timeout=self._timeout):
            column_names, rows = self._call(
                lambda: _zxlite.search(self._capsule, **arguments)
            )
        cursor = self.cursor()
        cursor._load_read_result(column_names, rows)
        return cursor


class RemoteConnection(_BaseConnection):
    """A pooled autocommit client connection to an existing cluster."""

    def __init__(
        self,
        seeds: tuple[str, ...],
        *,
        tls_ca: str | None = None,
        tls_cert: str | None = None,
        tls_key: str | None = None,
        auth_file: str | None = None,
        allow_psk_only_loopback: bool = False,
        pool_size: int = 0,
        connect_timeout_ms: int = 0,
        operation_timeout_ms: int = 0,
        expected_database_id: bytes | None = None,
        read_level: str = "linearizable",
        freshness_ms: int = 0,
        check_same_thread: bool = False,
        write_admission_timeout_ms: int = 0,
    ) -> None:
        """Open the remote pool; prefer `zxlite.connect()`.

        Opening eagerly probes one seed (bounded by
        `connect_timeout_ms`) and fails when no seed authenticates,
        reports the pinned database identity, and answers a client
        RPC; the remaining pool slots dial lazily.
        `write_admission_timeout_ms` bounds a write's wait for the
        ordered native write lane; a write that misses it raises
        `OperationalError` with category `"write_queue_timeout"`,
        never left the process, and is safe to retry plainly.
        """
        super().__init__(check_same_thread=check_same_thread)
        self._default_level = _REMOTE_READ_LEVELS[read_level]
        self._default_freshness = int(freshness_ms)
        try:
            self._capsule = _zxlite.remote_open(
                tuple(seeds),
                tls_ca,
                tls_cert,
                tls_key,
                auth_file,
                bool(allow_psk_only_loopback),
                int(pool_size),
                int(connect_timeout_ms),
                int(operation_timeout_ms),
                expected_database_id,
                int(write_admission_timeout_ms),
            )
        except _zxlite._ZxError as error:
            raise _map_remote_error(error) from None

    def _call(self, function: Callable[..., Any], *args: Any) -> Any:
        """Invoke a native remote function and remap its errors."""
        try:
            return function(*args)
        except _zxlite._ZxError as error:
            raise _map_remote_error(error) from None

    def commit(self) -> None:
        """Do nothing; every remote statement autocommits."""
        self._check()

    def rollback(self) -> None:
        """Do nothing; no transaction is ever open remotely."""
        self._check()

    def close(self) -> None:
        """Close the remote pool; further use raises an error."""
        if self._closed:
            return
        self._check()
        self._closed = True
        self._call(_zxlite.remote_close, self._capsule)

    def __enter__(self) -> RemoteConnection:
        """Return the connection for use in a with-statement."""
        self._check()
        return self

    def __exit__(self, *exc_info: object) -> bool:
        """Commit on exit (a no-op) and keep the connection open."""
        if not self._closed:
            self.commit()
        return False

    def resolve_pending(self) -> tuple[int, bool]:
        """Resolve the retained pending write to a definitive outcome.

        Return `(changes, replayed)` once the server reports success
        or an idempotent replay; raise the write-pending
        `OperationalError` while the fate stays unknown, and
        `ProgrammingError` when no write is pending.
        """
        self._check()
        return self._call(_zxlite.remote_resolve_pending, self._capsule)

    def query(
        self,
        sql: str,
        parameters: Any = (),
        *,
        read_level: str | None = None,
        freshness_ms: int | None = None,
    ) -> Cursor:
        """Run one read with optional per-call consistency overrides."""
        self._check()
        level = self._default_level
        if read_level is not None:
            if read_level not in _REMOTE_READ_LEVELS:
                raise ProgrammingError(
                    f"read_level must be one of {sorted(_REMOTE_READ_LEVELS)}"
                )
            level = _REMOTE_READ_LEVELS[read_level]
        freshness = (
            self._default_freshness if freshness_ms is None else int(freshness_ms)
        )
        if freshness and level != 0:
            raise ProgrammingError(
                "freshness_ms is only meaningful with read_level=any"
            )
        params = _normalize_parameters(parameters)
        cursor = self.cursor()
        column_names, rows = self._call(
            _zxlite.remote_query,
            self._capsule,
            sql,
            params,
            level,
            freshness,
        )
        cursor._load_read_result(column_names, rows)
        return cursor

    def search(
        self,
        *,
        fts_table: str | None = None,
        vec_table: str | None = None,
        text: str | None = None,
        embedding: bytes | bytearray | memoryview | None = None,
        k: int = 10,
        candidate_count: int | None = None,
        fusion: str = "rrf",
        text_weight: float = 1.0,
        vector_weight: float = 1.0,
        metadata_table: str | None = None,
        metadata_id_column: str | None = None,
        metadata_columns: Sequence[str] = (),
        read_level: str | None = None,
        freshness_ms: int | None = None,
    ) -> Cursor:
        """Run typed search through the remote native planner."""
        self._check()
        level = self._default_level
        if read_level is not None:
            if read_level not in _REMOTE_READ_LEVELS:
                raise ProgrammingError(
                    f"read_level must be one of {sorted(_REMOTE_READ_LEVELS)}"
                )
            level = _REMOTE_READ_LEVELS[read_level]
        freshness = (
            self._default_freshness if freshness_ms is None else int(freshness_ms)
        )
        if freshness and level != 0:
            raise ProgrammingError(
                "freshness_ms is only meaningful with read_level=any"
            )
        arguments = _search_arguments(
            fts_table=fts_table,
            vec_table=vec_table,
            text=text,
            embedding=embedding,
            k=k,
            candidate_count=candidate_count,
            fusion=fusion,
            text_weight=text_weight,
            vector_weight=vector_weight,
            metadata_table=metadata_table,
            metadata_id_column=metadata_id_column,
            metadata_columns=metadata_columns,
        )
        column_names, rows = self._call(
            lambda: _zxlite.remote_search(
                self._capsule,
                **arguments,
                level=level,
                freshness_ms=freshness,
            )
        )
        cursor = self.cursor()
        cursor._load_read_result(column_names, rows)
        return cursor

    def status_json(self) -> str:
        """Return raw status JSON from a healthy member (diagnostics)."""
        self._check()
        return self._call(_zxlite.remote_status_json, self._capsule)

    # -- cursor hooks -------------------------------------------------

    def _reject_write_hazards(self, sql: str) -> None:
        """Reject remote write shapes the native client cannot honor."""
        if _sql_has_tail(sql):
            raise ProgrammingError(
                "execute() accepts one statement; remote connections "
                "do not support executescript()"
            )
        if _sql_mentions_returning(sql):
            raise NotSupportedError(
                "RETURNING is not supported on remote connections; "
                "the replicated session result carries no rows"
            )

    def _execute_write(self, cursor: Cursor, sql: str, params: tuple[Any, ...]) -> None:
        """Run one write through the native remote write lane."""
        self._reject_write_hazards(sql)
        changes, lastrowid, _replayed = self._call(
            _zxlite.remote_exec, self._capsule, sql, params
        )
        cursor.rowcount = changes
        self._total_changes += changes
        if lastrowid is not None:
            cursor.lastrowid = lastrowid

    def _cursor_execute(self, cursor: Cursor, sql: str, parameters: Any) -> None:
        """Route one statement to the remote read or write path."""
        if isinstance(parameters, Mapping):
            raise ProgrammingError("named parameters require a local connection")
        params = _normalize_parameters(parameters)
        keyword = _leading_keyword(sql)
        if keyword in _READ_PREFIXES or keyword == "with":
            if _sql_has_tail(sql):
                raise ProgrammingError(
                    "execute() accepts one statement; remote "
                    "connections do not support executescript()"
                )
            try:
                column_names, rows = self._call(
                    _zxlite.remote_query,
                    self._capsule,
                    sql,
                    params,
                    self._default_level,
                    self._default_freshness,
                )
            except ProgrammingError as error:
                if error.category != "misuse":
                    raise
                # The server classified the statement as a write.
                self._execute_write(cursor, sql, params)
                return
            cursor._load_read_result(column_names, rows)
            return
        self._execute_write(cursor, sql, params)

    def _cursor_executemany(
        self, cursor: Cursor, sql: str, seq_of_parameters: Iterable[Any]
    ) -> None:
        """Run one DML statement over many rows as one atomic batch.

        The rows travel as one typed batch, one replicated transaction,
        and one session sequence: either every row applies or none
        does, matching a local connection.  `lastrowid` is left
        unchanged, per DB-API executemany semantics.
        """
        self._reject_write_hazards(sql)
        if _leading_keyword(sql) in _READ_PREFIXES:
            raise ProgrammingError("executemany() can only execute DML statements.")
        rows = []
        for parameters in seq_of_parameters:
            if isinstance(parameters, Mapping):
                raise ProgrammingError("named parameters require a local connection")
            rows.append(_normalize_parameters(parameters))
        if not rows:
            cursor.rowcount = 0
            return
        changes, _lastrowid, _replayed = self._call(
            _zxlite.remote_exec_batch, self._capsule, sql, tuple(rows)
        )
        cursor.rowcount = changes
        self._total_changes += changes

    def _cursor_executescript(self, cursor: Cursor, sql_script: str) -> None:
        """Reject scripts; the remote client executes one statement."""
        raise NotSupportedError(
            "executescript() is not supported on remote connections; "
            "execute one statement at a time"
        )


class Cursor:
    """A materialized DB-API cursor bound to one connection."""

    arraysize: int

    def __init__(self, connection: _BaseConnection) -> None:
        """Bind the cursor to `connection`; prefer `Connection.cursor`."""
        self.connection = connection
        self.arraysize = 1
        self.lastrowid: int | None = None
        self.rowcount: int = -1
        self.description: _Description | None = None
        self._row_factory: _RowFactory | None | object = _UNSET
        self._rows: list[tuple[Any, ...]] = []
        self._next_row = 0
        self._closed = False

    # -- plumbing -----------------------------------------------------

    @property
    def row_factory(self) -> _RowFactory | None:
        """Return the cursor's row factory, inheriting the connection's."""
        if self._row_factory is _UNSET:
            return self.connection.row_factory
        return self._row_factory  # type: ignore[return-value]

    @row_factory.setter
    def row_factory(self, factory: _RowFactory | None) -> None:
        """Override the row factory for this cursor only."""
        self._row_factory = factory

    def _check(self) -> None:
        """Reject use after close and delegate connection checks."""
        if self._closed:
            raise ProgrammingError("Cannot operate on a closed cursor.")
        self.connection._check()

    def _reset(self) -> None:
        """Discard any previous result set."""
        self.description = None
        self.rowcount = -1
        self._rows = []
        self._next_row = 0

    def _load_read_result(
        self,
        column_names: tuple[str, ...],
        rows: tuple[tuple[Any, ...], ...],
    ) -> None:
        """Install a materialized read result on this cursor."""
        self.description = tuple(
            (name, None, None, None, None, None, None) for name in column_names
        )
        self._rows = list(rows)
        self._next_row = 0
        self.rowcount = -1

    def _load_returning_result(
        self,
        column_names: tuple[str, ...],
        rows: tuple[tuple[Any, ...], ...],
    ) -> None:
        """Install RETURNING rows without resetting DML counters."""
        self.description = tuple(
            (name, None, None, None, None, None, None) for name in column_names
        )
        self._rows = list(rows)
        self._next_row = 0

    # -- execution ----------------------------------------------------

    def execute(self, sql: str, parameters: Any = ()) -> Cursor:
        """Execute one SQL statement with qmark or named parameters.

        A read materializes its rows before returning; a write runs as
        one replicated transaction (or joins the open Gate C
        transaction) and sets `rowcount` and, for INSERT and REPLACE,
        `lastrowid`.
        """
        self._check()
        if not isinstance(sql, str):
            raise ProgrammingError("sql must be a str")
        self._reset()
        self.connection._cursor_execute(self, sql, parameters)
        return self

    def executemany(self, sql: str, seq_of_parameters: Iterable[Any]) -> Cursor:
        """Run one DML statement over many rows.

        On a local connection the rows commit atomically as one batch;
        on a remote connection each row is one autocommit write.
        `lastrowid` is left unchanged either way.
        """
        self._check()
        if not isinstance(sql, str):
            raise ProgrammingError("sql must be a str")
        self._reset()
        self.connection._cursor_executemany(self, sql, seq_of_parameters)
        return self

    def executescript(self, sql_script: str) -> Cursor:
        """Run a multi-statement SQL script (local connections only)."""
        self._check()
        if not isinstance(sql_script, str):
            raise ProgrammingError("sql_script must be a str")
        self._reset()
        self.connection._cursor_executescript(self, sql_script)
        return self

    # -- fetching -----------------------------------------------------

    def _wrap(self, values: tuple[Any, ...]) -> Any:
        """Apply the effective row factory to one value tuple."""
        factory = self.row_factory
        if factory is None:
            return values
        return factory(self, values)

    def fetchone(self) -> Any:
        """Return the next row, or None when the result is exhausted."""
        self._check()
        if self._next_row >= len(self._rows):
            return None
        values = self._rows[self._next_row]
        self._next_row += 1
        return self._wrap(values)

    def fetchmany(self, size: int | None = None) -> list[Any]:
        """Return up to `size` rows (default `arraysize`)."""
        self._check()
        count = self.arraysize if size is None else size
        gathered: list[Any] = []
        for _ in range(count):
            row = self.fetchone()
            if row is None:
                break
            gathered.append(row)
        return gathered

    def fetchall(self) -> list[Any]:
        """Return every remaining row."""
        self._check()
        remaining = [self._wrap(values) for values in self._rows[self._next_row :]]
        self._next_row = len(self._rows)
        return remaining

    def __iter__(self) -> Cursor:
        """Return the cursor itself as a row iterator."""
        return self

    def __next__(self) -> Any:
        """Return the next row or stop the iteration."""
        row = self.fetchone()
        if row is None:
            raise StopIteration
        return row

    # -- lifecycle ----------------------------------------------------

    def close(self) -> None:
        """Close the cursor; the connection stays open."""
        self._closed = True
        self._rows = []
        self._next_row = 0

    def setinputsizes(self, sizes: Sequence[Any]) -> None:
        """Do nothing, per DB-API 2.0."""
        self._check()

    def setoutputsize(self, size: int, column: int | None = None) -> None:
        """Do nothing, per DB-API 2.0."""
        self._check()


_UNSET: Any = object()
