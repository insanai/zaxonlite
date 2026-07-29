"""Typed lexical search over an FTS5 table (ZDS 0009).

uv run python examples/search.py
"""

import tempfile

import zxlite


def main() -> None:
    """Index a few documents and run a typed lexical search."""
    target = tempfile.mkdtemp(prefix="zxlite-example-") + "/node"
    connection = zxlite.connect(target)
    try:
        connection.executescript(
            """
            create virtual table docs using fts5(body);
            insert into docs(body) values ('paxos replicates sqlite');
            insert into docs(body) values ('sqlite is an embedded database');
            insert into docs(body) values ('unrelated text entirely');
            """
        )
        cursor = connection.search(fts_table="docs", text="sqlite", k=5)
        names = [entry[0] for entry in cursor.description]
        print(f"columns: {names}")
        for row in cursor:
            print(f"  {row}")
    finally:
        connection.close()


if __name__ == "__main__":
    main()
