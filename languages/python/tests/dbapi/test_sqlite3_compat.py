"""Compatibility oracle: zxlite behavior versus the stdlib sqlite3.

Each case runs the same operations against both drivers and compares
the observable outcome (values, description names, rowcount, lastrowid,
or the raised exception class name).  Only behavior zxlite supports in
Gate A participates.
"""

import sqlite3
from collections.abc import Callable, Iterator
from typing import Any

import pytest

import zxlite

Outcome = tuple[str, Any]


def observe(run: Callable[[Any], Any], connection: Any) -> Outcome:
    """Run one case and normalize its result or exception class name."""
    try:
        return ("ok", run(connection))
    except Exception as error:  # noqa: BLE001 - class name compared
        return ("error", type(error).__name__)


def case_typed_literals(connection: Any) -> Any:
    cursor = connection.execute("select 1, 1.5, 'x', x'00ff', NULL")
    return cursor.fetchall()


def case_parameter_roundtrip(connection: Any) -> Any:
    connection.execute("create table p(v)")
    for value in (None, 7, 1.5, "text", b"\x00\xff"):
        connection.execute("insert into p values (?)", (value,))
    return connection.execute("select v from p").fetchall()


def case_insert_rowcount_lastrowid(connection: Any) -> Any:
    connection.execute("create table r(a integer primary key, b text)")
    cursor = connection.cursor()
    cursor.execute("insert into r(b) values ('x')")
    return (cursor.rowcount, cursor.lastrowid)


def case_update_rowcount(connection: Any) -> Any:
    connection.execute("create table u(v text)")
    connection.execute("insert into u values ('a')")
    connection.execute("insert into u values ('b')")
    cursor = connection.execute("update u set v = 'c'")
    return cursor.rowcount


def case_select_rowcount_is_minus_one(connection: Any) -> Any:
    connection.execute("create table s(v text)")
    return connection.execute("select * from s").rowcount


def case_description_names(connection: Any) -> Any:
    cursor = connection.execute("select 1 as a, 2 as b")
    return [entry[0] for entry in cursor.description]


def case_zero_row_description(connection: Any) -> Any:
    connection.execute("create table z(col text)")
    cursor = connection.execute("select col from z")
    return (
        [entry[0] for entry in cursor.description],
        cursor.fetchall(),
    )


def case_multi_statement_rejected(connection: Any) -> Any:
    return connection.execute("select 1; select 2").fetchall()


def case_wrong_parameter_count(connection: Any) -> Any:
    connection.execute("create table w(v text)")
    return connection.execute("insert into w values (?)", ())


def case_unsupported_parameter_type(connection: Any) -> Any:
    connection.execute("create table b(v)")
    return connection.execute("insert into b values (?)", (object(),))


def case_executemany_rowcount(connection: Any) -> Any:
    connection.execute("create table m(v text)")
    cursor = connection.executemany(
        "insert into m values (?)", [("a",), ("b",), ("c",)]
    )
    return cursor.rowcount


def case_integrity_error_class(connection: Any) -> Any:
    connection.execute("create table i(v text unique)")
    connection.execute("insert into i values ('dup')")
    return connection.execute("insert into i values ('dup')")


def case_fetch_after_dml_is_none(connection: Any) -> Any:
    connection.execute("create table f(v text)")
    cursor = connection.execute("insert into f values ('x')")
    return cursor.fetchone()


CASES = [
    case_typed_literals,
    case_parameter_roundtrip,
    case_insert_rowcount_lastrowid,
    case_update_rowcount,
    case_select_rowcount_is_minus_one,
    case_description_names,
    case_zero_row_description,
    case_multi_statement_rejected,
    case_wrong_parameter_count,
    case_unsupported_parameter_type,
    case_executemany_rowcount,
    case_integrity_error_class,
    case_fetch_after_dml_is_none,
]


@pytest.fixture
def oracle() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(":memory:")
    yield connection
    connection.close()


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.__name__)
def test_matches_sqlite3(
    case: Callable[[Any], Any],
    conn: zxlite.Connection,
    oracle: sqlite3.Connection,
) -> None:
    expected = observe(case, oracle)
    actual = observe(case, conn)
    assert actual == expected
