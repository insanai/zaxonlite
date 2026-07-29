"""Cursor execution, description, fetch semantics, and row factories."""

import pytest

import zxlite


@pytest.fixture
def table(conn: zxlite.Connection) -> zxlite.Connection:
    conn.execute("create table t(a integer primary key, b text)")
    return conn


def test_execute_rejects_multiple_statements(
    table: zxlite.Connection,
) -> None:
    with pytest.raises(zxlite.ProgrammingError, match="executescript"):
        table.execute("insert into t(b) values ('x'); select 1")


def test_trailing_semicolon_is_one_statement(
    table: zxlite.Connection,
) -> None:
    assert table.execute("select 1;").fetchone() == (1,)


def test_executescript_runs_batch(conn: zxlite.Connection) -> None:
    cursor = conn.executescript(
        """
        create table a(v text);
        create table b(v text);
        insert into a values ('one');
        insert into b values ('two');
        """
    )
    assert cursor.rowcount == -1
    assert cursor.description is None
    assert conn.execute("select v from a").fetchall() == [("one",)]
    assert conn.execute("select v from b").fetchall() == [("two",)]


def test_description_on_populated_read(table: zxlite.Connection) -> None:
    table.execute("insert into t(b) values ('x')")
    cursor = table.execute("select a, b from t")
    assert cursor.description == (
        ("a", None, None, None, None, None, None),
        ("b", None, None, None, None, None, None),
    )
    assert cursor.rowcount == -1


def test_description_on_zero_row_read(table: zxlite.Connection) -> None:
    cursor = table.execute("select a, b from t where a = -1")
    assert cursor.description is not None
    assert [entry[0] for entry in cursor.description] == ["a", "b"]
    assert cursor.fetchall() == []


def test_description_none_for_plain_dml(table: zxlite.Connection) -> None:
    cursor = table.execute("insert into t(b) values ('x')")
    assert cursor.description is None
    assert cursor.fetchone() is None


def test_rowcount_and_lastrowid(table: zxlite.Connection) -> None:
    cursor = table.cursor()
    cursor.execute("insert into t(b) values ('x')")
    assert cursor.rowcount == 1
    assert cursor.lastrowid == 1
    cursor.execute("insert into t(b) values ('y')")
    assert cursor.lastrowid == 2
    cursor.execute("update t set b = 'z'")
    assert cursor.rowcount == 2
    assert cursor.lastrowid == 2  # unchanged by UPDATE
    cursor.execute("delete from t")
    assert cursor.rowcount == 2


def test_returning_rows_and_rowcount(table: zxlite.Connection) -> None:
    cursor = table.execute("insert into t(b) values (?) returning a, b", ("ret",))
    assert cursor.rowcount == 1
    assert cursor.lastrowid == 1
    assert cursor.description is not None
    assert [entry[0] for entry in cursor.description] == ["a", "b"]
    assert cursor.fetchall() == [(1, "ret")]


def test_fetch_semantics(table: zxlite.Connection) -> None:
    table.executemany("insert into t(b) values (?)", [(f"row{i}",) for i in range(5)])
    cursor = table.execute("select a from t order by a")
    assert cursor.fetchone() == (1,)
    assert cursor.fetchmany(2) == [(2,), (3,)]
    cursor.arraysize = 1
    assert cursor.fetchmany() == [(4,)]
    assert cursor.fetchall() == [(5,)]
    assert cursor.fetchone() is None
    assert cursor.fetchmany() == []
    assert cursor.fetchall() == []


def test_iteration(table: zxlite.Connection) -> None:
    table.executemany("insert into t(b) values (?)", [("a",), ("b",)])
    rows = [row for row in table.execute("select b from t order by a")]
    assert rows == [("a",), ("b",)]


def test_executemany_total_rowcount_and_lastrowid(
    table: zxlite.Connection,
) -> None:
    cursor = table.cursor()
    cursor.execute("insert into t(b) values ('seed')")
    seed_rowid = cursor.lastrowid
    cursor.executemany("insert into t(b) values (?)", [("m1",), ("m2",), ("m3",)])
    assert cursor.rowcount == 3
    assert cursor.lastrowid == seed_rowid  # executemany leaves it alone
    assert table.execute("select count(*) from t").fetchone() == (4,)


def test_executemany_empty_sequence(table: zxlite.Connection) -> None:
    cursor = table.cursor()
    cursor.executemany("insert into t(b) values (?)", [])
    assert cursor.rowcount == 0


def test_executemany_is_atomic(conn: zxlite.Connection) -> None:
    conn.execute("create table u(v text unique)")
    with pytest.raises(zxlite.Error) as info:
        conn.executemany("insert into u values (?)", [("a",), ("b",), ("a",)])
    assert isinstance(info.value, (zxlite.IntegrityError, zxlite.OperationalError))
    # The whole batch rolled back: no partial rows.
    assert conn.execute("select count(*) from u").fetchone() == (0,)


def test_executemany_rejects_reads(table: zxlite.Connection) -> None:
    with pytest.raises(zxlite.ProgrammingError):
        table.executemany("select * from t", [()])


def test_transaction_control_sql_is_rejected(
    table: zxlite.Connection,
) -> None:
    for sql in (
        "BEGIN",
        "begin immediate",
        "COMMIT",
        "ROLLBACK",
        "SAVEPOINT s1",
        "RELEASE s1",
    ):
        with pytest.raises((zxlite.ProgrammingError, zxlite.OperationalError)) as info:
            table.execute(sql)
        assert str(info.value)  # a clear message, never silent
        assert "database is locked" not in str(info.value)


def test_row_factory_on_connection(table: zxlite.Connection) -> None:
    table.execute("insert into t(b) values ('x')")
    table.row_factory = zxlite.Row
    row = table.execute("select a, b from t").fetchone()
    assert isinstance(row, zxlite.Row)
    assert row["a"] == 1
    assert row["B"] == "x"  # case-insensitive
    assert row.keys() == ["a", "b"]
    assert len(row) == 2
    assert list(row) == [1, "x"]


def test_row_factory_on_cursor_overrides(
    table: zxlite.Connection,
) -> None:
    table.execute("insert into t(b) values ('x')")
    table.row_factory = zxlite.Row
    cursor = table.cursor()
    cursor.row_factory = None
    cursor.execute("select a, b from t")
    assert cursor.fetchone() == (1, "x")


def test_row_equality_and_errors(table: zxlite.Connection) -> None:
    table.execute("insert into t(b) values ('x')")
    table.row_factory = zxlite.Row
    first = table.execute("select a, b from t").fetchone()
    second = table.execute("select a, b from t").fetchone()
    assert first == second
    assert hash(first) == hash(second)
    with pytest.raises(IndexError):
        first["missing"]
    with pytest.raises(TypeError):
        first[1.5]


def test_custom_row_factory_callable(table: zxlite.Connection) -> None:
    table.execute("insert into t(b) values ('x')")

    def dict_factory(cursor: zxlite.Cursor, row: tuple) -> dict[str, object]:
        names = [entry[0] for entry in cursor.description]
        return dict(zip(names, row, strict=True))

    cursor = table.cursor()
    cursor.row_factory = dict_factory
    cursor.execute("select a, b from t")
    assert cursor.fetchone() == {"a": 1, "b": "x"}


def test_closed_cursor_rejects_use(table: zxlite.Connection) -> None:
    cursor = table.execute("select 1")
    cursor.close()
    with pytest.raises(zxlite.ProgrammingError, match="closed cursor"):
        cursor.fetchone()
    with pytest.raises(zxlite.ProgrammingError, match="closed cursor"):
        cursor.execute("select 1")


def test_connection_shortcuts_return_cursor(
    table: zxlite.Connection,
) -> None:
    assert isinstance(table.execute("select 1"), zxlite.Cursor)
    assert isinstance(
        table.executemany("insert into t(b) values (?)", [("s",)]),
        zxlite.Cursor,
    )
    assert isinstance(table.executescript("select 1"), zxlite.Cursor)


def test_setinputsizes_and_setoutputsize_are_noops(
    table: zxlite.Connection,
) -> None:
    cursor = table.cursor()
    cursor.setinputsizes([None])
    cursor.setoutputsize(16)
    cursor.setoutputsize(16, 0)
