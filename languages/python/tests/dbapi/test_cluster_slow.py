"""Three-process dev-PSK loopback cluster (slow; run with -m slow).

The parent picks three free ports, writes one protected PSK file, and
spawns three fresh interpreters that each host one member via
`zxlite.start_server`.  The parent connects with all three seeds,
writes, reads linearizably, kills one member (quorum survives),
restarts it, and verifies catch-up.
"""

import os
import socket
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

import zxlite

pytestmark = pytest.mark.slow

CHILD_SCRIPT = textwrap.dedent(
    """
    import sys
    import zxlite

    directory, node_id, cluster_id, auth_file = sys.argv[1:5]
    endpoints = sys.argv[5:8]
    members = [
        zxlite.Member(index + 1, endpoint)
        for index, endpoint in enumerate(endpoints)
    ]
    server = zxlite.start_server(
        directory=directory,
        node_id=int(node_id),
        members=members,
        cluster_id=cluster_id,
        auth_file=auth_file,
        allow_psk_only_loopback=True,
        startup_timeout=30.0,
    )
    print("ready", flush=True)
    sys.stdin.readline()  # parent closes stdin (or writes) to stop us
    server.close()
    print("stopped", flush=True)
    """
)


def _free_ports(count: int) -> list[int]:
    probes = [socket.socket() for _ in range(count)]
    try:
        for probe in probes:
            probe.bind(("127.0.0.1", 0))
        return [probe.getsockname()[1] for probe in probes]
    finally:
        for probe in probes:
            probe.close()


def _spawn_member(
    tmp_path: Path,
    node_id: int,
    cluster_id: str,
    auth_file: Path,
    endpoints: list[str],
) -> subprocess.Popen[str]:
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            CHILD_SCRIPT,
            str(tmp_path / f"node-{node_id}"),
            str(node_id),
            cluster_id,
            str(auth_file),
            *endpoints,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    line = process.stdout.readline().strip()
    if line != "ready":
        process.kill()
        raise AssertionError(f"member {node_id} failed to start: {line!r}")
    return process


def _stop_member(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        try:
            process.stdin.write("stop\n")
            process.stdin.flush()
        except (BrokenPipeError, ValueError):
            pass
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def _query_settled(
    conn: "zxlite.RemoteConnection",
    sql: str,
    *,
    deadline_s: float = 30.0,
) -> list:
    """Run a linearizable read, retrying while the cluster settles.

    Right after election or a member restart a read can land on a
    member that has not applied an image yet; that surfaces as an
    OperationalError and is safe to retry.
    """
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return conn.query(sql, read_level="linearizable").fetchall()
        except zxlite.OperationalError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.5)


def test_three_process_psk_cluster(tmp_path: Path) -> None:
    ports = _free_ports(3)
    endpoints = [f"127.0.0.1:{port}" for port in ports]
    auth_file = tmp_path / "cluster.psk"
    auth_file.write_bytes(os.urandom(48))
    auth_file.chmod(0o600)
    cluster_id = "psk-three-proc"

    members: dict[int, subprocess.Popen[str]] = {}
    try:
        for node_id in (1, 2, 3):
            members[node_id] = _spawn_member(
                tmp_path, node_id, cluster_id, auth_file, endpoints
            )

        conn = zxlite.connect(
            "zxlite://" + ",".join(endpoints) + "/",
            auth_file=str(auth_file),
            allow_psk_only_loopback=True,
            operation_timeout_ms=30000,
        )
        try:
            conn.execute("create table votes(id integer primary key, v text)")
            conn.execute("insert into votes(v) values (?)", ("first",))
            rows = _query_settled(conn, "select v from votes")
            assert rows == [("first",)]

            # Terminate one member; two of three still form a quorum.
            _stop_member(members[3])
            conn.execute("insert into votes(v) values (?)", ("quorum",))
            rows = _query_settled(conn, "select count(*) from votes")
            assert rows == [(2,)]

            # Restart the stopped member; it must catch up.
            members[3] = _spawn_member(tmp_path, 3, cluster_id, auth_file, endpoints)
            conn.execute("insert into votes(v) values (?)", ("caught",))
            deadline = time.monotonic() + 30.0
            direct = zxlite.connect(
                f"zxlite://{endpoints[2]}/",
                auth_file=str(auth_file),
                allow_psk_only_loopback=True,
                read_level="any",
            )
            try:
                while True:
                    count = None
                    try:
                        count = direct.query(
                            "select count(*) from votes",
                            read_level="any",
                        ).fetchone()[0]
                    except zxlite.OperationalError:
                        pass  # not caught up: no image served yet
                    if count == 3:
                        break
                    if time.monotonic() > deadline:
                        raise AssertionError(
                            f"restarted member never caught up (count={count})"
                        )
                    time.sleep(0.5)
            finally:
                direct.close()
        finally:
            conn.close()
    finally:
        for process in members.values():
            _stop_member(process)
