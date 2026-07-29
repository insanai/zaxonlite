"""Host a unix-socket server and connect to it remotely.

uv run python examples/server.py
"""

import tempfile

import zxlite


def main() -> None:
    """Serve one node over a unix socket and query it as a client."""
    scratch = tempfile.mkdtemp(prefix="zx-srv-")
    socket_path = f"{scratch}/example.sock"
    with zxlite.start_server(
        directory=f"{scratch}/node",
        node_id=1,
        members=[zxlite.Member(1, f"unix:{socket_path}")],
    ) as server:
        print(f"serving on {server.endpoint}")
        connection = zxlite.connect(server.endpoint)
        try:
            connection.execute("create table item(id integer primary key, value text)")
            connection.execute("insert into item(value) values (?)", ("served",))
            rows = connection.query(
                "select id, value from item", read_level="linearizable"
            ).fetchall()
            print(f"rows: {rows}")
        finally:
            connection.close()
    print("server closed, socket removed")


if __name__ == "__main__":
    main()
