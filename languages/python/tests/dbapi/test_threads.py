"""Write-lane behavior: fairness under load and bounded write waits."""

import threading
from collections.abc import Callable

import pytest

import zxlite

THREADS = 32
WRITES_PER_THREAD = 25


def test_concurrent_writers_apply_exactly_once(
    make_connection: Callable[..., zxlite.Connection],
) -> None:
    conn = make_connection(check_same_thread=False, timeout=300.0)
    conn.execute(
        "create table writes(thread integer, seq integer, unique(thread, seq))"
    )
    errors: list[BaseException] = []
    barrier = threading.Barrier(THREADS)

    def writer(thread_id: int) -> None:
        try:
            barrier.wait()
            for seq in range(WRITES_PER_THREAD):
                conn.execute(
                    "insert into writes(thread, seq) values (?, ?)",
                    (thread_id, seq),
                )
        except BaseException as error:  # noqa: BLE001 - inspected below
            errors.append(error)

    workers = [
        threading.Thread(target=writer, args=(thread_id,))
        for thread_id in range(THREADS)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    for error in errors:
        assert "database is locked" not in str(error)
    assert errors == []
    total = conn.execute("select count(*) from writes").fetchone()[0]
    distinct = conn.execute(
        "select count(distinct thread || '-' || seq) from writes"
    ).fetchone()[0]
    assert total == THREADS * WRITES_PER_THREAD
    assert distinct == THREADS * WRITES_PER_THREAD


def test_write_queue_timeout_is_typed_and_safe_to_retry(
    make_connection: Callable[..., zxlite.Connection],
) -> None:
    conn = make_connection(check_same_thread=False, timeout=0.05)
    conn.execute("create table q(v text)")

    held = threading.Event()
    release = threading.Event()

    def hold_lane() -> None:
        with conn._lane.enter(write=False, timeout=conn._timeout):
            held.set()
            release.wait(timeout=30.0)

    holder = threading.Thread(target=hold_lane)
    holder.start()
    assert held.wait(timeout=10.0)

    try:
        with pytest.raises(zxlite.OperationalError) as info:
            conn.execute("insert into q values ('only-once')")
        assert info.value.category == "write_queue_timeout"
        assert "database is locked" not in str(info.value)
        assert "retry is safe" in str(info.value)
    finally:
        release.set()
        holder.join()

    # The rejected statement never executed, so a plain retry inserts
    # the value exactly once.
    conn.execute("insert into q values ('only-once')")
    count = conn.execute("select count(*) from q where v = 'only-once'").fetchone()[0]
    assert count == 1


def test_reads_are_not_bound_by_the_write_timeout(
    make_connection: Callable[..., zxlite.Connection],
) -> None:
    conn = make_connection(check_same_thread=False, timeout=0.05)
    conn.execute("create table r(v text)")
    conn.execute("insert into r values ('x')")

    held = threading.Event()
    release = threading.Event()

    def hold_lane() -> None:
        with conn._lane.enter(write=False, timeout=conn._timeout):
            held.set()
            release.wait(timeout=30.0)

    holder = threading.Thread(target=hold_lane)
    holder.start()
    assert held.wait(timeout=10.0)

    result: list[object] = []

    def read() -> None:
        result.append(conn.execute("select v from r").fetchone())

    reader = threading.Thread(target=read)
    reader.start()
    # Give the read longer than the write timeout to prove it queues
    # instead of raising write_queue_timeout.
    reader.join(timeout=0.5)
    assert reader.is_alive()  # still patiently queued
    release.set()
    holder.join()
    reader.join(timeout=10.0)
    assert result == [("x",)]
