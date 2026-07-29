"""Connection lifecycle, maintenance surface, and thread affinity."""

import threading
from collections.abc import Callable
from pathlib import Path

import pytest

import zxlite


def test_close_is_idempotent(conn: zxlite.Connection) -> None:
    conn.close()
    conn.close()


def test_operations_after_close_raise(conn: zxlite.Connection) -> None:
    conn.close()
    with pytest.raises(zxlite.ProgrammingError, match="closed"):
        conn.execute("select 1")
    with pytest.raises(zxlite.ProgrammingError, match="closed"):
        conn.cursor()
    with pytest.raises(zxlite.ProgrammingError, match="closed"):
        conn.commit()
    with pytest.raises(zxlite.ProgrammingError, match="closed"):
        conn.rollback()


def test_context_manager_keeps_connection_open(
    conn: zxlite.Connection,
) -> None:
    with conn as entered:
        assert entered is conn
        conn.execute("create table t(v text)")
    # Like sqlite3, the with-block commits (a no-op here) but does not
    # close the connection.
    assert conn.execute("select count(*) from t").fetchone() == (0,)


def test_commit_and_rollback_are_noops(conn: zxlite.Connection) -> None:
    conn.execute("create table t(v text)")
    conn.execute("insert into t values (?)", ("kept",))
    conn.rollback()
    assert conn.execute("select v from t").fetchall() == [("kept",)]
    conn.commit()


def test_in_transaction_is_false(conn: zxlite.Connection) -> None:
    assert conn.in_transaction is False
    conn.execute("create table t(v text)")
    assert conn.in_transaction is False


def test_total_changes_accumulates(conn: zxlite.Connection) -> None:
    assert conn.total_changes == 0
    conn.execute("create table t(v text)")
    conn.execute("insert into t values ('a')")
    conn.execute("insert into t values ('b')")
    conn.execute("update t set v = 'c'")
    assert conn.total_changes == 4


def test_snapshot_backup_integrity(conn: zxlite.Connection, tmp_path: Path) -> None:
    conn.execute("create table t(v text)")
    conn.execute("insert into t values ('x')")
    conn.snapshot()
    conn.integrity_check()
    backup_path = tmp_path / "backup.db"
    conn.backup(backup_path)
    assert backup_path.exists()
    assert backup_path.stat().st_size > 0


def test_sessions_replay_exactly_once(conn: zxlite.Connection) -> None:
    conn.execute("create table t(v text)")
    session = conn.open_session()
    assert session > 0
    changes, replayed = conn.execute_idempotent(
        session, 1, "insert into t values ('once')"
    )
    assert (changes, replayed) == (1, False)
    changes, replayed = conn.execute_idempotent(
        session, 1, "insert into t values ('once')"
    )
    assert (changes, replayed) == (1, True)
    assert conn.execute("select count(*) from t").fetchone() == (1,)


def test_session_sequence_gap_fails_without_executing(
    conn: zxlite.Connection,
) -> None:
    conn.execute("create table t(v text)")
    session = conn.open_session()
    with pytest.raises(zxlite.OperationalError) as info:
        conn.execute_idempotent(session, 7, "insert into t values ('gap')")
    assert info.value.category == "session"
    assert conn.execute("select count(*) from t").fetchone() == (0,)


def test_expire_sessions(conn: zxlite.Connection) -> None:
    conn.open_session()
    assert conn.expire_sessions(1000) == 0


def test_check_same_thread_default_rejects_foreign_thread(
    conn: zxlite.Connection,
) -> None:
    conn.execute("create table t(v text)")
    caught: list[BaseException] = []

    def use_from_thread() -> None:
        try:
            conn.execute("insert into t values ('x')")
        except BaseException as error:  # noqa: BLE001 - inspected below
            caught.append(error)

    worker = threading.Thread(target=use_from_thread)
    worker.start()
    worker.join()
    assert len(caught) == 1
    assert isinstance(caught[0], zxlite.ProgrammingError)
    assert "thread" in str(caught[0])


def test_check_same_thread_false_allows_sharing(
    make_connection: Callable[..., zxlite.Connection],
) -> None:
    conn = make_connection(check_same_thread=False)
    conn.execute("create table t(v text)")
    errors: list[BaseException] = []

    def use_from_thread() -> None:
        try:
            conn.execute("insert into t values ('shared')")
        except BaseException as error:  # noqa: BLE001 - inspected below
            errors.append(error)

    worker = threading.Thread(target=use_from_thread)
    worker.start()
    worker.join()
    assert errors == []
    assert conn.execute("select count(*) from t").fetchone() == (1,)
