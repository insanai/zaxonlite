"""Typed round-trips and qmark parameter binding rules."""

import pytest

import zxlite


@pytest.fixture
def table(conn: zxlite.Connection) -> zxlite.Connection:
    conn.execute("create table t(v)")
    return conn


def roundtrip(conn: zxlite.Connection, value: object) -> object:
    conn.execute("delete from t")
    conn.execute("insert into t values (?)", (value,))
    return conn.execute("select v from t").fetchone()[0]


def test_none_roundtrip(table: zxlite.Connection) -> None:
    assert roundtrip(table, None) is None


@pytest.mark.parametrize("value", [0, 1, -1, 42, 2**63 - 1, -(2**63)])
def test_integer_roundtrip(table: zxlite.Connection, value: int) -> None:
    result = roundtrip(table, value)
    assert isinstance(result, int)
    assert result == value


def test_bool_binds_as_integer(table: zxlite.Connection) -> None:
    assert roundtrip(table, True) == 1
    assert roundtrip(table, False) == 0


@pytest.mark.parametrize("value", [0.0, 1.5, -2.25, 1e300])
def test_real_roundtrip(table: zxlite.Connection, value: float) -> None:
    result = roundtrip(table, value)
    assert isinstance(result, float)
    assert result == value


@pytest.mark.parametrize(
    "value",
    [
        "plain",
        "",
        "embedded\x00nul",
        "quote ' and \" mix",
        "unicode é中☃",
    ],
)
def test_text_roundtrip(table: zxlite.Connection, value: str) -> None:
    result = roundtrip(table, value)
    assert isinstance(result, str)
    assert result == value


def test_empty_text_is_distinct_from_null(
    table: zxlite.Connection,
) -> None:
    assert roundtrip(table, "") == ""
    assert roundtrip(table, None) is None


@pytest.mark.parametrize("value", [b"", b"\x00\xff", b"blob bytes"])
def test_blob_roundtrip(table: zxlite.Connection, value: bytes) -> None:
    result = roundtrip(table, value)
    assert isinstance(result, bytes)
    assert result == value


def test_bytearray_and_memoryview_bind_as_blob(
    table: zxlite.Connection,
) -> None:
    assert roundtrip(table, bytearray(b"array")) == b"array"
    assert roundtrip(table, memoryview(b"view")) == b"view"


def test_integer_overflow_raises(table: zxlite.Connection) -> None:
    with pytest.raises(OverflowError):
        table.execute("insert into t values (?)", (2**63,))
    with pytest.raises(OverflowError):
        table.execute("insert into t values (?)", (-(2**63) - 1,))


def test_unsupported_parameter_type_raises(
    table: zxlite.Connection,
) -> None:
    with pytest.raises(zxlite.ProgrammingError):
        table.execute("insert into t values (?)", (object(),))
    with pytest.raises(zxlite.ProgrammingError):
        table.execute("insert into t values (?)", ([1, 2],))


def test_parameter_count_mismatch(table: zxlite.Connection) -> None:
    with pytest.raises(zxlite.ProgrammingError, match="bindings"):
        table.execute("insert into t values (?)", ())
    with pytest.raises(zxlite.ProgrammingError, match="bindings"):
        table.execute("insert into t values (?)", (1, 2))


def test_string_as_parameters_rejected(table: zxlite.Connection) -> None:
    with pytest.raises(zxlite.ProgrammingError):
        table.execute("insert into t values (?)", "abc")


def test_dict_parameters_rejected(table: zxlite.Connection) -> None:
    with pytest.raises(zxlite.ProgrammingError):
        table.execute("insert into t values (?)", {"v": 1})


def test_invalid_utf8_text_result_raises(
    conn: zxlite.Connection,
) -> None:
    with pytest.raises(zxlite.OperationalError, match="UTF-8"):
        conn.execute("select cast(x'ff01' as text)")


def test_storage_classes_preserved(conn: zxlite.Connection) -> None:
    conn.execute("create table typed(i integer, r real, t text, b blob, n integer)")
    conn.execute("insert into typed values (7, 1.5, 'text', X'00ff', NULL)")
    row = conn.execute("select * from typed").fetchone()
    assert row == (7, 1.5, "text", b"\x00\xff", None)
    assert isinstance(row[0], int)
    assert isinstance(row[1], float)
