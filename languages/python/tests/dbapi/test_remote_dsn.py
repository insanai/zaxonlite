"""Strict remote DSN validation (no network activity on rejection)."""

import pytest

import zxlite
from zxlite.dbapi import _parse_remote_dsn


def test_authority_form_parses_seeds_and_options() -> None:
    parsed = _parse_remote_dsn(
        "zxlite://db1.example:9901,db2.example:9901,db3.example:9901/"
        "?read_level=linearizable&pool_size=8"
    )
    assert parsed["seeds"] == (
        "db1.example:9901",
        "db2.example:9901",
        "db3.example:9901",
    )
    assert parsed["read_level"] == "linearizable"
    assert parsed["pool_size"] == 8


def test_query_seed_form_parses() -> None:
    parsed = _parse_remote_dsn(
        "zxlite:///?seed=db1.example%3A9901&seed=db2.example%3A9901"
        "&read_level=any&freshness_ms=250"
    )
    assert parsed["seeds"] == ("db1.example:9901", "db2.example:9901")
    assert parsed["read_level"] == "any"
    assert parsed["freshness_ms"] == 250


def test_query_form_accepts_one_unix_seed() -> None:
    parsed = _parse_remote_dsn("zxlite:///?seed=unix%3A%2Frun%2Fzx.sock")
    assert parsed["seeds"] == ("unix:/run/zx.sock",)


def test_ipv6_seeds_require_brackets() -> None:
    parsed = _parse_remote_dsn("zxlite://[::1]:9901/")
    assert parsed["seeds"] == ("[::1]:9901",)
    with pytest.raises(zxlite.ProgrammingError, match="brackets"):
        _parse_remote_dsn("zxlite://::1:9901/")


@pytest.mark.parametrize(
    "dsn",
    [
        "zxlite://host:1/extra/path",
        "zxlite://user@host:1/",
        "zxlite://host:1/?frag=1#x",
        "zxlite://host:1/?unknown_option=1",
        "zxlite://host:1/?read_level=any&read_level=any",
        "zxlite://host:1/?read_level=bogus",
        "zxlite://host:1/?read_policy=bogus",
        "zxlite://host:1/?freshness_ms=abc",
        "zxlite://host:1/?pool_size=%zz",
        "zxlite://host/",
        "zxlite://host:0/",
        "zxlite://host:99999/",
        "zxlite://:9901/",
        "zxlite://host:1,host:1/",
        "zxlite:///?seed=unix%3Arelative.sock",
        "zxlite:///?seed=unix%3A%2Fa.sock&seed=host%3A1",
        "zxlite://host:1/?seed=other%3A2",
        "zxlite:///?read_level=any",
    ],
)
def test_invalid_dsns_rejected(dsn: str) -> None:
    with pytest.raises((zxlite.ProgrammingError, zxlite.Error)):
        _parse_remote_dsn(dsn)


def test_too_many_seeds_rejected() -> None:
    seeds = ",".join(f"h{i}:1" for i in range(37))
    with pytest.raises(zxlite.ProgrammingError, match="36"):
        _parse_remote_dsn(f"zxlite://{seeds}/")


def test_freshness_requires_any(tmp_path: object) -> None:
    with pytest.raises(zxlite.ProgrammingError, match="read_level=any"):
        zxlite.connect("zxlite://127.0.0.1:9901/?read_level=leader&freshness_ms=10")


def test_option_specified_twice_via_kwarg() -> None:
    with pytest.raises(zxlite.ProgrammingError, match="both"):
        zxlite.connect("zxlite://127.0.0.1:9901/?pool_size=4", pool_size=8)


def test_psk_kwarg_validation() -> None:
    with pytest.raises(zxlite.ProgrammingError, match="auth_file"):
        zxlite.connect("zxlite://127.0.0.1:9901/", allow_psk_only_loopback=True)
    with pytest.raises(zxlite.ProgrammingError, match="loopback"):
        zxlite.connect(
            "zxlite://example.com:9901/",
            auth_file="/tmp/psk",
            allow_psk_only_loopback=True,
        )


def test_tls_requires_all_three() -> None:
    with pytest.raises(zxlite.ProgrammingError, match="together"):
        zxlite.connect("zxlite://host:9901/", tls_ca="/tmp/ca.pem")


def test_expected_database_id_shapes() -> None:
    with pytest.raises(zxlite.ProgrammingError, match="hex"):
        zxlite.connect("zxlite://127.0.0.1:9901/", expected_database_id="xyz")
    with pytest.raises(zxlite.ProgrammingError, match="length 16"):
        zxlite.connect("zxlite://127.0.0.1:9901/", expected_database_id=b"short")


def test_pool_size_bounds() -> None:
    with pytest.raises(zxlite.ProgrammingError, match="between 1 and 64"):
        zxlite.connect("zxlite://127.0.0.1:9901/?pool_size=65")


def test_remote_admission_timeout_maps_to_write_queue_timeout() -> None:
    from zxlite.dbapi import _map_remote_error

    class FakeNativeError(Exception):
        pass

    error = FakeNativeError("write queue admission timed out")
    error.code = 4
    error.category = 2  # busy
    error.message = "write queue admission timed out"
    mapped = _map_remote_error(error)
    assert isinstance(mapped, zxlite.OperationalError)
    assert mapped.category == "write_queue_timeout"
    assert str(mapped).startswith("-- WRITE QUEUE TIMEOUT --")
    assert "\n\nHint: A plain retry is safe" in str(mapped)
    assert "database is locked" not in str(mapped)


def test_remote_integrity_maps_to_interface_error() -> None:
    from zxlite.dbapi import _map_remote_error

    class FakeNativeError(Exception):
        pass

    error = FakeNativeError("database identity mismatch")
    error.code = 3
    error.category = 6  # integrity
    error.message = "database identity mismatch"
    mapped = _map_remote_error(error)
    assert isinstance(mapped, zxlite.InterfaceError)
    assert str(mapped).startswith("-- DATABASE IDENTITY MISMATCH --")
    assert "\n\nHint:" in str(mapped)

    # An ordinary pending-write unavailability stays OperationalError.
    error.code = 4
    error.category = 7
    error.message = "write pending: call zaxonlite_remote_resolve_pending"
    unavailable = _map_remote_error(error)
    assert isinstance(unavailable, zxlite.OperationalError)
    assert str(unavailable).startswith("-- DATABASE UNAVAILABLE --")
    assert "\n\nHint:" in str(unavailable)
