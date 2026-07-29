"""Gate C live local transactions and named dict binding."""

from pathlib import Path

import pytest

import zxlite


@pytest.fixture
def tx_conn(tmp_path: Path) -> zxlite.Connection:
    connection = zxlite.connect(
        tmp_path / "tx-node",
        isolation_level="DEFERRED",
        autocommit=False,
    )
    connection.execute("create table t(a integer primary key, b text)")
    connection.commit()
    yield connection
    try:
        connection.close()
    except zxlite.Error:
        pass


def test_implicit_begin_and_commit(tx_conn: zxlite.Connection) -> None:
    assert tx_conn.in_transaction is False
    tx_conn.execute("insert into t(b) values ('one')")
    assert tx_conn.in_transaction is True
    tx_conn.commit()
    assert tx_conn.in_transaction is False
    assert tx_conn.execute("select count(*) from t").fetchone() == (1,)


def test_rollback_discards_writes(tx_conn: zxlite.Connection) -> None:
    tx_conn.execute("insert into t(b) values ('gone')")
    assert tx_conn.in_transaction is True
    tx_conn.rollback()
    assert tx_conn.in_transaction is False
    assert tx_conn.execute("select count(*) from t").fetchone() == (0,)


def test_read_your_writes_inside_transaction(
    tx_conn: zxlite.Connection,
) -> None:
    tx_conn.execute("insert into t(b) values ('visible')")
    rows = tx_conn.execute("select b from t").fetchall()
    assert rows == [("visible",)]
    tx_conn.rollback()
    assert tx_conn.execute("select b from t").fetchall() == []


def test_reads_outside_transaction_do_not_begin(
    tx_conn: zxlite.Connection,
) -> None:
    tx_conn.execute("select count(*) from t").fetchone()
    assert tx_conn.in_transaction is False


def test_lastrowid_and_returning_inside_transaction(
    tx_conn: zxlite.Connection,
) -> None:
    cursor = tx_conn.execute("insert into t(b) values (?) returning a, b", ("ret",))
    assert tx_conn.in_transaction is True
    assert cursor.lastrowid == 1
    assert cursor.rowcount == 1
    assert cursor.fetchall() == [(1, "ret")]
    tx_conn.commit()
    assert tx_conn.execute("select b from t").fetchall() == [("ret",)]


def test_commit_is_durable_after_reopen(tmp_path: Path) -> None:
    directory = tmp_path / "durable-node"
    conn = zxlite.connect(directory, isolation_level="DEFERRED", autocommit=False)
    conn.execute("create table d(v text)")
    conn.execute("insert into d values ('kept')")
    conn.commit()
    conn.close()
    reopened = zxlite.connect(directory)
    try:
        assert reopened.execute("select v from d").fetchall() == [("kept",)]
    finally:
        reopened.close()


def test_close_with_open_transaction_rolls_back(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "close-node"
    conn = zxlite.connect(directory, isolation_level="DEFERRED", autocommit=False)
    conn.execute("create table c(v text)")
    conn.commit()
    conn.execute("insert into c values ('dropped')")
    assert conn.in_transaction is True
    conn.close()
    reopened = zxlite.connect(directory)
    try:
        assert reopened.execute("select count(*) from c").fetchone() == (0,)
    finally:
        reopened.close()


def test_context_manager_commits_or_rolls_back(
    tx_conn: zxlite.Connection,
) -> None:
    with tx_conn:
        tx_conn.execute("insert into t(b) values ('kept')")
    assert tx_conn.in_transaction is False
    with pytest.raises(RuntimeError):
        with tx_conn:
            tx_conn.execute("insert into t(b) values ('lost')")
            raise RuntimeError("boom")
    assert tx_conn.in_transaction is False
    assert tx_conn.execute("select b from t").fetchall() == [("kept",)]


def test_executemany_inside_transaction(
    tx_conn: zxlite.Connection,
) -> None:
    tx_conn.execute("insert into t(b) values ('first')")
    cursor = tx_conn.executemany("insert into t(b) values (?)", [("m1",), ("m2",)])
    assert cursor.rowcount == 2
    assert tx_conn.in_transaction is True
    tx_conn.rollback()
    assert tx_conn.execute("select count(*) from t").fetchone() == (0,)


def test_savepoints_via_internal_api(tx_conn: zxlite.Connection) -> None:
    tx_conn.execute("insert into t(b) values ('base')")
    tx_conn._savepoint(1)
    tx_conn.execute("insert into t(b) values ('inner')")
    assert tx_conn.execute("select count(*) from t").fetchone() == (2,)
    tx_conn._rollback_to_savepoint(1)
    assert tx_conn.execute("select count(*) from t").fetchone() == (1,)
    tx_conn._release_savepoint(1)
    tx_conn.commit()
    assert tx_conn.execute("select b from t").fetchall() == [("base",)]


def test_savepoint_requires_transactional_connection(
    tmp_path: Path,
) -> None:
    conn = zxlite.connect(tmp_path / "gate-a-node")
    try:
        with pytest.raises(zxlite.ProgrammingError, match="Gate C"):
            conn._savepoint(1)
    finally:
        conn.close()


def test_transaction_control_sql_still_rejected(
    tx_conn: zxlite.Connection,
) -> None:
    with pytest.raises((zxlite.ProgrammingError, zxlite.OperationalError)):
        tx_conn.execute("BEGIN")


@pytest.mark.parametrize("prefix", [":", "@", "$"])
def test_named_dict_binding(tx_conn: zxlite.Connection, prefix: str) -> None:
    tx_conn.execute(f"insert into t(b) values ({prefix}body)", {"body": "named"})
    rows = tx_conn.execute(
        f"select b from t where b = {prefix}body", {"body": "named"}
    ).fetchall()
    assert rows == [("named",)]
    tx_conn.rollback()


def test_named_dict_binding_missing_key(
    tx_conn: zxlite.Connection,
) -> None:
    with pytest.raises(zxlite.ProgrammingError, match="body"):
        tx_conn.execute("insert into t(b) values (:body)", {"other": 1})


def test_dict_binding_with_positional_placeholder(
    tx_conn: zxlite.Connection,
) -> None:
    with pytest.raises(zxlite.ProgrammingError, match="dictionary"):
        tx_conn.execute("insert into t(b) values (?)", {"b": "x"})


def test_executemany_with_dict_rows(tx_conn: zxlite.Connection) -> None:
    cursor = tx_conn.executemany(
        "insert into t(b) values (:body)",
        [{"body": "a"}, {"body": "b"}],
    )
    assert cursor.rowcount == 2
    tx_conn.commit()
    assert tx_conn.execute("select b from t order by a").fetchall() == [("a",), ("b",)]


def test_gate_a_connection_rejects_deferred_only(tmp_path: Path) -> None:
    with pytest.raises(zxlite.NotSupportedError):
        zxlite.connect(tmp_path / "n1", isolation_level="DEFERRED")
    with pytest.raises(zxlite.NotSupportedError):
        zxlite.connect(tmp_path / "n2", autocommit=False)
    with pytest.raises(zxlite.NotSupportedError):
        zxlite.connect(
            tmp_path / "n3",
            isolation_level="IMMEDIATE",
            autocommit=False,
        )
