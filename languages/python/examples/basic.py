"""Basic zxlite usage: connect, write, read, row factories.

Run with an empty or existing node directory:

    uv run python examples/basic.py ./example-node
"""

import sys
import tempfile

import zxlite


def main() -> None:
    """Create a table, insert rows, and read them back."""
    target = sys.argv[1] if len(sys.argv) > 1 else None
    if target is None:
        target = tempfile.mkdtemp(prefix="zxlite-example-") + "/node"
        print(f"using scratch node directory {target}")

    connection = zxlite.connect(target)
    try:
        connection.executescript(
            """
            create table if not exists notes(
                id integer primary key,
                body text not null
            );
            """
        )
        cursor = connection.execute(
            "insert into notes(body) values (?) returning id",
            ("written by examples/basic.py",),
        )
        (note_id,) = cursor.fetchone()
        print(f"inserted note {note_id} (lastrowid {cursor.lastrowid})")

        connection.row_factory = zxlite.Row
        for row in connection.execute("select id, body from notes order by id"):
            print(f"  {row['id']}: {row['body']}")

        print(f"total changes this connection: {connection.total_changes}")
    finally:
        connection.close()


if __name__ == "__main__":
    main()
