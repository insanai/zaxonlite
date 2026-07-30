"""Module globals, exception hierarchy, and connect() gatekeeping."""

import os
from collections.abc import Callable
from pathlib import Path

import pytest

import zxlite


def test_module_globals() -> None:
    assert zxlite.apilevel == "2.0"
    assert zxlite.threadsafety == 2
    assert zxlite.paramstyle == "qmark"


def test_exception_hierarchy() -> None:
    assert issubclass(zxlite.Warning, Exception)
    assert issubclass(zxlite.Error, Exception)
    assert issubclass(zxlite.InterfaceError, zxlite.Error)
    assert issubclass(zxlite.DatabaseError, zxlite.Error)
    for subclass in (
        zxlite.DataError,
        zxlite.OperationalError,
        zxlite.IntegrityError,
        zxlite.InternalError,
        zxlite.ProgrammingError,
        zxlite.NotSupportedError,
    ):
        assert issubclass(subclass, zxlite.DatabaseError)


def test_connect_returns_connection(tmp_path: Path) -> None:
    connection = zxlite.connect(tmp_path / "node")
    try:
        assert isinstance(connection, zxlite.Connection)
    finally:
        connection.close()


def test_remote_dsn_with_path_is_rejected() -> None:
    with pytest.raises(zxlite.ProgrammingError, match="path"):
        zxlite.connect("zxlite://host:4321/cluster")


@pytest.mark.skipif(os.name == "nt", reason="unix sockets are POSIX-only")
def test_unix_target_without_server_fails_at_connect(
    tmp_path: Path,
) -> None:
    # Opening eagerly probes one seed, so a dead endpoint fails the
    # connect() call itself instead of the first statement.
    with pytest.raises(zxlite.OperationalError):
        zxlite.connect(f"unix:{tmp_path}/absent.sock", connect_timeout_ms=500)


def test_remote_target_rejects_transactions() -> None:
    with pytest.raises(zxlite.NotSupportedError, match="autocommit"):
        zxlite.connect(
            "zxlite://127.0.0.1:1/",
            isolation_level="DEFERRED",
            autocommit=False,
        )


def test_isolation_level_not_supported(tmp_path: Path) -> None:
    with pytest.raises(zxlite.NotSupportedError):
        zxlite.connect(tmp_path / "node", isolation_level="DEFERRED")


def test_autocommit_false_not_supported(tmp_path: Path) -> None:
    with pytest.raises(zxlite.NotSupportedError):
        zxlite.connect(tmp_path / "node", autocommit=False)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"tls_ca": "ca.pem"},
        {"tls_cert": "cert.pem"},
        {"tls_key": "key.pem"},
        {"auth_file": "auth"},
        {"allow_psk_only_loopback": True},
        {"freshness_ms": 100},
        {"pool_size": 4},
        {"read_level": "bounded"},
    ],
)
def test_remote_options_not_supported(tmp_path: Path, kwargs: dict) -> None:
    with pytest.raises(zxlite.NotSupportedError):
        zxlite.connect(tmp_path / "node", **kwargs)


def test_second_open_of_locked_directory_fails(
    tmp_path: Path, make_connection: Callable[..., zxlite.Connection]
) -> None:
    connection = make_connection()
    # The factory numbers directories; reuse the first one directly.
    with pytest.raises(zxlite.OperationalError) as info:
        zxlite.connect(tmp_path / "node-1")
    assert "database is locked" not in str(info.value)
    connection.close()


def test_sqlite_version_constant_matches_native(
    tmp_path: Path,
) -> None:
    conn = zxlite.connect(tmp_path / "ver-node")
    try:
        live = conn.execute("select sqlite_version()").fetchone()[0]
    finally:
        conn.close()
    assert live == zxlite.sqlite_version
    assert zxlite.sqlite_version_info == tuple(int(part) for part in live.split("."))


def test_native_version_agreement_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import zxlite as package
    from zxlite import _zxlite

    package._check_native_version()  # matching versions pass
    monkeypatch.setattr(_zxlite, "version", lambda: "9.9.0")
    with pytest.raises(ImportError, match="expects native zaxonlite"):
        package._check_native_version()
    monkeypatch.setattr(_zxlite, "version", lambda: "bogus")
    with pytest.raises(ImportError):
        package._check_native_version()
