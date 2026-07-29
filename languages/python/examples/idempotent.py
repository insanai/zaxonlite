"""Exactly-once writes with replicated sessions.

A session gives every write a sequence number; retrying the same
sequence replays the recorded result instead of executing again.

    uv run python examples/idempotent.py
"""

import tempfile

import zxlite


def main() -> None:
    """Show that a retried sequence applies exactly once."""
    target = tempfile.mkdtemp(prefix="zxlite-example-") + "/node"
    connection = zxlite.connect(target)
    try:
        connection.execute("create table payments(amount integer)")
        session = connection.open_session()

        changes, replayed = connection.execute_idempotent(
            session, 1, "insert into payments values (100)"
        )
        print(f"first attempt:  changes={changes} replayed={replayed}")

        # A client that lost the response retries the same sequence.
        changes, replayed = connection.execute_idempotent(
            session, 1, "insert into payments values (100)"
        )
        print(f"retry:          changes={changes} replayed={replayed}")

        count = connection.execute("select count(*) from payments").fetchone()[0]
        print(f"rows in table:  {count} (exactly once)")
    finally:
        connection.close()


if __name__ == "__main__":
    main()
