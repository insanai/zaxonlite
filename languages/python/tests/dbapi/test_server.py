"""Hosted server: unix end-to-end, dev-PSK loopback, and validation."""

import os
import shutil
import socket
import tempfile
import warnings
from collections.abc import Iterator
from pathlib import Path

import pytest

import zxlite

posix_only = pytest.mark.skipif(os.name == "nt", reason="unix sockets are POSIX-only")


@pytest.fixture
def sock_dir() -> Iterator[Path]:
    """Yield a short-path directory: unix socket paths are length-capped."""
    directory = Path(tempfile.mkdtemp(prefix="zx-sock-"))
    yield directory
    shutil.rmtree(directory, ignore_errors=True)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _write_psk(tmp_path: Path) -> Path:
    auth_file = tmp_path / "cluster.psk"
    auth_file.write_bytes(os.urandom(48))
    auth_file.chmod(0o600)
    return auth_file


@posix_only
def test_unix_server_end_to_end(tmp_path: Path, sock_dir: Path) -> None:
    sock = sock_dir / "zx.sock"
    with zxlite.start_server(
        directory=tmp_path / "node",
        node_id=1,
        members=[zxlite.Member(1, f"unix:{sock}")],
    ) as server:
        assert server.endpoint == f"unix:{sock}"
        assert server.node_id == 1
        assert server.closed is False
        assert sock.exists()

        conn = zxlite.connect(server.endpoint)
        try:
            assert isinstance(conn, zxlite.RemoteConnection)
            conn.execute("create table item(id integer primary key, value text)")
            cursor = conn.execute("insert into item(value) values (?)", ("paxos",))
            assert cursor.rowcount == 1
            # Fresh remote writes report last_insert_rowid.  (Known
            # native quirk: the very first write on a new handle omits
            # it, so the second insert is the assertion target.)
            cursor = conn.execute("insert into item(value) values (?)", ("again",))
            assert cursor.lastrowid == 2
            rows = conn.execute("select id, value from item").fetchall()
            assert rows == [(1, "paxos"), (2, "again")]
            # Raw lexical search SQL works through the remote read path.
            conn.execute("create virtual table docs using fts5(body)")
            conn.execute(
                "insert into docs(body) values (?)",
                ("paxos replicates sqlite",),
            )
            conn.execute(
                "insert into docs(body) values (?)",
                ("unrelated text",),
            )
            found = conn.execute(
                "select body from docs where docs match ?", ("paxos",)
            ).fetchall()
            assert found == [("paxos replicates sqlite",)]
            assert "data-voter" in conn.status_json()
        finally:
            conn.close()
    assert server.closed is True
    assert not sock.exists()


@posix_only
def test_unix_server_refuses_preexisting_socket(tmp_path: Path, sock_dir: Path) -> None:
    sock = sock_dir / "taken.sock"
    holder = socket.socket(socket.AF_UNIX)
    holder.bind(str(sock))
    try:
        with pytest.raises(zxlite.Error):
            zxlite.start_server(
                directory=tmp_path / "node",
                node_id=1,
                members=[zxlite.Member(1, f"unix:{sock}")],
                startup_timeout=5.0,
            )
    finally:
        holder.close()


@posix_only
def test_unix_server_close_is_idempotent(tmp_path: Path, sock_dir: Path) -> None:
    server = zxlite.start_server(
        directory=tmp_path / "node",
        node_id=1,
        members=[zxlite.Member(1, f"unix:{sock_dir}/i.sock")],
    )
    server.close()
    server.close()
    assert server.closed is True


def test_dev_psk_single_node_end_to_end(tmp_path: Path) -> None:
    port = _free_port()
    auth_file = _write_psk(tmp_path)
    endpoint = f"127.0.0.1:{port}"
    with zxlite.start_server(
        directory=tmp_path / "node",
        node_id=1,
        members=[zxlite.Member(1, endpoint)],
        cluster_id="psk-single",
        auth_file=auth_file,
        allow_psk_only_loopback=True,
    ):
        conn = zxlite.connect(
            f"zxlite://{endpoint}/",
            auth_file=str(auth_file),
            allow_psk_only_loopback=True,
        )
        try:
            conn.execute("create table k(v text)")
            conn.execute("insert into k values (?)", ("psk",))
            assert conn.query(
                "select v from k", read_level="linearizable"
            ).fetchall() == [("psk",)]
            assert conn.query("select v from k", read_level="any").fetchall() == [
                ("psk",)
            ]
        finally:
            conn.close()


def test_remote_executescript_not_supported(tmp_path: Path) -> None:
    port = _free_port()
    auth_file = _write_psk(tmp_path)
    endpoint = f"127.0.0.1:{port}"
    with zxlite.start_server(
        directory=tmp_path / "node",
        node_id=1,
        members=[zxlite.Member(1, endpoint)],
        auth_file=auth_file,
        allow_psk_only_loopback=True,
    ):
        conn = zxlite.connect(
            f"zxlite://{endpoint}/",
            auth_file=str(auth_file),
            allow_psk_only_loopback=True,
        )
        try:
            with pytest.raises(zxlite.NotSupportedError):
                conn.executescript("select 1; select 2")
            with pytest.raises(zxlite.ProgrammingError):
                conn.execute("insert into a values (1); insert into a values (2)")
            with pytest.raises(zxlite.NotSupportedError, match="RETURNING"):
                conn.execute("insert into a(v) values (?) returning v", (1,))
            with pytest.raises(zxlite.NotSupportedError):
                conn.search(fts_table="docs", text="x")
        finally:
            conn.close()


def test_server_finalizer_warns(tmp_path: Path, sock_dir: Path) -> None:
    server = zxlite.start_server(
        directory=tmp_path / "node",
        node_id=1,
        members=[zxlite.Member(1, f"unix:{sock_dir}/w.sock")],
    )
    finalizer = server._finalizer
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        finalizer()  # what garbage collection would run
    assert any(issubclass(entry.category, ResourceWarning) for entry in caught)
    assert server._finalizer.alive is False


# --- validation failures (no native call) -----------------------------


def test_dev_psk_requires_auth_file(tmp_path: Path) -> None:
    with pytest.raises(zxlite.ProgrammingError, match="auth_file"):
        zxlite.start_server(
            directory=tmp_path / "node",
            node_id=1,
            members=[zxlite.Member(1, "127.0.0.1:9901")],
            allow_psk_only_loopback=True,
        )


def test_dev_psk_requires_numeric_loopback(tmp_path: Path) -> None:
    auth_file = _write_psk(tmp_path)
    with pytest.raises(zxlite.ProgrammingError, match="loopback"):
        zxlite.start_server(
            directory=tmp_path / "node",
            node_id=1,
            members=[zxlite.Member(1, "localhost:9901")],
            auth_file=auth_file,
            allow_psk_only_loopback=True,
        )


def test_unix_multi_member_rejected(tmp_path: Path) -> None:
    with pytest.raises(zxlite.ProgrammingError, match="single-member"):
        zxlite.start_server(
            directory=tmp_path / "node",
            node_id=1,
            members=[
                zxlite.Member(1, f"unix:{tmp_path}/a.sock"),
                zxlite.Member(2, "127.0.0.1:9901"),
            ],
        )


def test_unix_gateway_rejected(tmp_path: Path) -> None:
    with pytest.raises(zxlite.ProgrammingError, match="gateway"):
        zxlite.start_server(
            directory=tmp_path / "node",
            node_id=1,
            members=[zxlite.Member(1, f"unix:{tmp_path}/g.sock", role="gateway")],
        )


def test_unix_relative_path_rejected(tmp_path: Path) -> None:
    with pytest.raises(zxlite.ProgrammingError, match="absolute"):
        zxlite.start_server(
            directory=tmp_path / "node",
            node_id=1,
            members=[zxlite.Member(1, "unix:relative.sock")],
        )


def test_member_registry_shape(tmp_path: Path) -> None:
    with pytest.raises(zxlite.ProgrammingError, match="between 1 and"):
        zxlite.start_server(directory=tmp_path / "node", node_id=1, members=[])
    with pytest.raises(zxlite.ProgrammingError, match="duplicate"):
        zxlite.start_server(
            directory=tmp_path / "node",
            node_id=1,
            members=[
                zxlite.Member(1, "127.0.0.1:9901"),
                zxlite.Member(1, "127.0.0.1:9902"),
            ],
        )
    with pytest.raises(zxlite.ProgrammingError, match="positive"):
        zxlite.start_server(
            directory=tmp_path / "node",
            node_id=0,
            members=[zxlite.Member(0, "127.0.0.1:9901")],
        )
    with pytest.raises(zxlite.ProgrammingError, match="registry"):
        zxlite.start_server(
            directory=tmp_path / "node",
            node_id=9,
            members=[zxlite.Member(1, "127.0.0.1:9901")],
        )


def test_tls_requires_all_three(tmp_path: Path) -> None:
    with pytest.raises(zxlite.ProgrammingError, match="together"):
        zxlite.start_server(
            directory=tmp_path / "node",
            node_id=1,
            members=[zxlite.Member(1, "127.0.0.1:9901")],
            tls_ca=tmp_path / "ca.pem",
        )


def test_remote_executemany_is_atomic(tmp_path: Path) -> None:
    port = _free_port()
    auth_file = _write_psk(tmp_path)
    endpoint = f"127.0.0.1:{port}"
    with zxlite.start_server(
        directory=tmp_path / "node",
        node_id=1,
        members=[zxlite.Member(1, endpoint)],
        auth_file=auth_file,
        allow_psk_only_loopback=True,
    ):
        conn = zxlite.connect(
            f"zxlite://{endpoint}/",
            auth_file=str(auth_file),
            allow_psk_only_loopback=True,
        )
        try:
            conn.execute("create table b(v text unique)")
            cursor = conn.executemany(
                "insert into b values (?)", [("a",), ("b",), ("c",)]
            )
            assert cursor.rowcount == 3
            count = conn.execute("select count(*) from b").fetchone()[0]
            assert count == 3
            # One good row plus one duplicate: the whole batch rolls
            # back on the server, so neither row applies.
            with pytest.raises(zxlite.Error):
                conn.executemany("insert into b values (?)", [("fresh",), ("a",)])
            count = conn.execute("select count(*) from b").fetchone()[0]
            assert count == 3
            # Empty batches never reach the wire.
            empty = conn.executemany("insert into b values (?)", [])
            assert empty.rowcount == 0
        finally:
            conn.close()


def test_remote_returning_literal_is_not_a_false_positive(
    tmp_path: Path,
) -> None:
    port = _free_port()
    auth_file = _write_psk(tmp_path)
    endpoint = f"127.0.0.1:{port}"
    with zxlite.start_server(
        directory=tmp_path / "node",
        node_id=1,
        members=[zxlite.Member(1, endpoint)],
        auth_file=auth_file,
        allow_psk_only_loopback=True,
    ):
        conn = zxlite.connect(
            f"zxlite://{endpoint}/",
            auth_file=str(auth_file),
            allow_psk_only_loopback=True,
        )
        try:
            conn.execute("create table lit(v text)")
            # The word appears only inside a string literal (and a
            # comment): this must not trip the RETURNING rejection.
            cursor = conn.execute(
                "insert into lit(v) values ('returning') -- returning is just text here"
            )
            assert cursor.rowcount == 1
            rows = conn.execute("select v from lit").fetchall()
            assert rows == [("returning",)]
            # A real RETURNING clause is still rejected.
            with pytest.raises(zxlite.NotSupportedError):
                conn.execute("insert into lit(v) values (?) returning v", ("x",))
        finally:
            conn.close()


def test_remote_identity_mismatch_is_interface_error(
    tmp_path: Path,
) -> None:
    port = _free_port()
    auth_file = _write_psk(tmp_path)
    endpoint = f"127.0.0.1:{port}"
    with zxlite.start_server(
        directory=tmp_path / "node",
        node_id=1,
        members=[zxlite.Member(1, endpoint)],
        auth_file=auth_file,
        allow_psk_only_loopback=True,
    ):
        with pytest.raises(zxlite.InterfaceError):
            zxlite.connect(
                f"zxlite://{endpoint}/",
                auth_file=str(auth_file),
                allow_psk_only_loopback=True,
                expected_database_id="00" * 16,
            )


def test_remote_write_admission_timeout_category(tmp_path: Path) -> None:
    port = _free_port()
    auth_file = _write_psk(tmp_path)
    endpoint = f"127.0.0.1:{port}"
    with zxlite.start_server(
        directory=tmp_path / "node",
        node_id=1,
        members=[zxlite.Member(1, endpoint)],
        auth_file=auth_file,
        allow_psk_only_loopback=True,
    ):
        conn = zxlite.connect(
            f"zxlite://{endpoint}/",
            auth_file=str(auth_file),
            allow_psk_only_loopback=True,
            timeout=0.001,
        )
        try:
            conn.execute("create table adm(v text)")
        except zxlite.OperationalError as error:
            # With a 1 ms admission bound the write may time out at
            # the lane; that is exactly the contract under test.
            assert error.category == "write_queue_timeout"
            assert "database is locked" not in str(error)
            # The statement never left the process: a plain retry on a
            # patient connection succeeds from a clean slate.
        finally:
            conn.close()
        patient = zxlite.connect(
            f"zxlite://{endpoint}/",
            auth_file=str(auth_file),
            allow_psk_only_loopback=True,
        )
        try:
            patient.execute("create table if not exists adm(v text)")
            patient.execute("insert into adm values ('once')")
            count = patient.execute(
                "select count(*) from adm where v = 'once'"
            ).fetchone()[0]
            assert count == 1
        finally:
            patient.close()


def test_connection_version_properties(tmp_path: Path) -> None:
    from zxlite import _zxlite

    local = zxlite.connect(tmp_path / "ver-props-node")
    try:
        assert local.zaxonlite_version == _zxlite.version()
        assert local.sqlite_version == zxlite.sqlite_version
    finally:
        local.close()
    port = _free_port()
    auth_file = _write_psk(tmp_path)
    endpoint = f"127.0.0.1:{port}"
    with zxlite.start_server(
        directory=tmp_path / "node",
        node_id=1,
        members=[zxlite.Member(1, endpoint)],
        auth_file=auth_file,
        allow_psk_only_loopback=True,
    ):
        remote = zxlite.connect(
            f"zxlite://{endpoint}/",
            auth_file=str(auth_file),
            allow_psk_only_loopback=True,
        )
        try:
            assert remote.zaxonlite_version == _zxlite.version()
            assert remote.sqlite_version == zxlite.sqlite_version
        finally:
            remote.close()


def test_duplicate_member_endpoints_rejected(tmp_path: Path) -> None:
    with pytest.raises(zxlite.ProgrammingError, match="duplicate member endpoint"):
        zxlite.start_server(
            directory=tmp_path / "node",
            node_id=1,
            members=[
                zxlite.Member(1, "127.0.0.1:9901"),
                zxlite.Member(2, "127.0.0.1:9901"),
            ],
        )
