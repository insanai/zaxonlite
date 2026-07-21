#!/usr/bin/env python3
"""Three-node order workload with follower, leader, and total-restart faults."""

import argparse
import datetime
import http.client
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time

from realworld_workload import (
    ExpectedState,
    INVARIANT_SQL,
    RqliteClient,
    SCHEMA,
    SEED_DATA,
    ZaxonClient,
    expected_values,
    generate_operations,
    rqlite_request_once,
    run_phase,
    values_from_rqlite,
    values_from_zaxon,
    verify_values,
    zaxon_call_once,
)


def command_version(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0:
        raise RuntimeError(f"version command failed: {command}: {output}")
    return output


def wait_port(endpoint, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(endpoint, timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"port did not become ready: {endpoint}")


class ProcessSet:
    """Own child processes and append-only diagnostic logs."""

    def __init__(self, run_dir, prefix):
        self.run_dir = run_dir
        self.prefix = prefix
        self.processes = [None, None, None]
        self.logs = [None, None, None]
        self.generations = [0, 0, 0]

    def spawn(self, index, command):
        if self.processes[index] is not None:
            raise RuntimeError(f"node {index + 1} is already running")
        self.generations[index] += 1
        log_path = self.run_dir / (
            f"{self.prefix}-{index + 1}-g{self.generations[index]}.log")
        log = log_path.open("ab", buffering=0)
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        self.processes[index] = process
        self.logs[index] = log

    def crash(self, index):
        process = self.processes[index]
        if process is None:
            return
        process.kill()
        process.wait(timeout=10)
        self.processes[index] = None
        self.logs[index].close()
        self.logs[index] = None

    def crash_all(self):
        for process in self.processes:
            if process is not None:
                process.kill()
        for index, process in enumerate(self.processes):
            if process is not None:
                process.wait(timeout=10)
                self.processes[index] = None
            if self.logs[index] is not None:
                self.logs[index].close()
                self.logs[index] = None

    def running_indices(self):
        return [
            index for index, process in enumerate(self.processes)
            if process is not None and process.poll() is None
        ]


class ZaxonCluster:
    system = "zaxonlite"

    def __init__(self, run_dir, binary, base_port):
        self.run_dir = run_dir
        self.binary = binary
        self.endpoints = [("127.0.0.1", base_port + index) for index in range(3)]
        self.children = ProcessSet(run_dir, "zaxon")
        self.ca_path = run_dir / "zaxon-ca.crt"
        self.client_cert = run_dir / "zaxon-client.crt"
        self.client_key = run_dir / "zaxon-client.key"
        self._generate_pki()
        self.tls_context = ssl.create_default_context(cafile=str(self.ca_path))
        self.tls_context.load_cert_chain(
            str(self.client_cert), str(self.client_key))

    def _openssl(self, *arguments):
        subprocess.run(
            ["openssl", *map(str, arguments)], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _generate_pki(self):
        ca_key = self.run_dir / "zaxon-ca.key"
        self._openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout",
                      "-out", ca_key)
        ca_key.chmod(0o600)
        self._openssl(
            "req", "-new", "-x509", "-key", ca_key, "-sha256", "-days", "1",
            "-subj", "/CN=zaxon-realworld-ca",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-out", self.ca_path)
        for name, common_name in [
                ("zaxon-node-1", "zaxon-node-1"),
                ("zaxon-node-2", "zaxon-node-2"),
                ("zaxon-node-3", "zaxon-node-3"),
                ("zaxon-client", "zaxon-client")]:
            key = self.run_dir / f"{name}.key"
            csr = self.run_dir / f"{name}.csr"
            cert = self.run_dir / f"{name}.crt"
            extensions = self.run_dir / f"{name}.ext"
            self._openssl("ecparam", "-name", "prime256v1", "-genkey",
                          "-noout", "-out", key)
            key.chmod(0o600)
            self._openssl("req", "-new", "-key", key, "-subj",
                          f"/CN={common_name}", "-out", csr)
            extensions.write_text(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\n"
                f"subjectAltName=DNS:{common_name}\n"
                "extendedKeyUsage=serverAuth,clientAuth\n",
                encoding="utf-8")
            self._openssl(
                "x509", "-req", "-in", csr, "-CA", self.ca_path,
                "-CAkey", ca_key, "-CAcreateserial", "-days", "1", "-sha256",
                "-extfile", extensions, "-out", cert)

    def data_dir(self, index):
        return self.run_dir / f"zaxon-{index + 1}"

    def start(self, index, initial=False):
        del initial
        peers = []
        for peer in range(3):
            if peer != index:
                host, port = self.endpoints[peer]
                peers.extend([
                    "--peer",
                    f"{peer + 1}@{host}:{port}/data-voter",
                ])
        host, port = self.endpoints[index]
        command = [
            self.binary,
            "serve",
            "--data", str(self.data_dir(index)),
            "--node", str(index + 1),
            "--listen", f"{host}:{port}",
            "--cluster-id", "realworld-failure-benchmark",
            "--tls-cert", str(self.run_dir / f"zaxon-node-{index + 1}.crt"),
            "--tls-key", str(self.run_dir / f"zaxon-node-{index + 1}.key"),
            "--tls-ca", str(self.ca_path),
            *peers,
        ]
        self.children.spawn(index, command)

    def start_initial(self):
        for index in range(3):
            self.start(index, initial=True)
        for endpoint in self.endpoints:
            wait_port(endpoint)
        self.wait_leader()

    def restart(self, index):
        self.start(index)
        wait_port(self.endpoints[index])

    def leader_index(self):
        for endpoint in self.endpoints:
            try:
                response = zaxon_call_once(
                    endpoint, {"op": "leader"}, self.tls_context,
                    self.endpoints.index(endpoint) + 1, timeout=1)
            except (OSError, EOFError, TimeoutError, ValueError):
                continue
            leader = response.get("leader")
            if isinstance(leader, dict) and isinstance(leader.get("id"), int):
                return leader["id"] - 1
        return None

    def wait_leader(self, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            leader = self.leader_index()
            if leader is not None and leader in self.children.running_indices():
                return leader
            time.sleep(0.05)
        raise TimeoutError("Zaxonlite did not elect a leader")

    def client_factory(self, worker_id):
        return ZaxonClient(self.endpoints, self.tls_context, worker_id)

    def setup(self):
        client = self.client_factory(0)
        try:
            for statement in (*SCHEMA, *SEED_DATA):
                client.execute(statement)
        finally:
            client.close()

    def local_values(self, index):
        response = zaxon_call_once(self.endpoints[index], {
            "op": "query",
            "level": "any",
            "sql": INVARIANT_SQL,
        }, self.tls_context, index + 1, timeout=2)
        if not response.get("ok"):
            raise RuntimeError(str(response))
        return values_from_zaxon(response)

    def linearizable_values(self):
        client = self.client_factory(0)
        try:
            response, _ = client.call({
                "op": "query",
                "level": "linearizable",
                "sql": INVARIANT_SQL,
            })
            return values_from_zaxon(response)
        finally:
            client.close()

    def wait_local_state(self, expected, indices=None, timeout=30):
        indices = self.children.running_indices() if indices is None else indices
        deadline = time.monotonic() + timeout
        last_error = None
        while time.monotonic() < deadline:
            actual = {}
            try:
                for index in indices:
                    values = self.local_values(index)
                    verify_values(values, expected)
                    actual[str(index + 1)] = values
                return actual
            except (OSError, EOFError, TimeoutError, RuntimeError, ValueError) as error:
                last_error = error
                time.sleep(0.05)
        raise TimeoutError(f"Zaxonlite nodes did not catch up: {last_error}")

    def integrity(self):
        reports = {}
        for index in self.children.running_indices():
            response = zaxon_call_once(
                self.endpoints[index], {"op": "integrity"},
                self.tls_context, index + 1, timeout=10)
            if not response.get("ok"):
                raise RuntimeError(f"Zaxonlite integrity failed: {response}")
            reports[str(index + 1)] = response
        return reports

    def cli_evidence(self):
        return None


class RqliteCluster:
    system = "rqlite"

    def __init__(self, run_dir, daemon, cli, base_port):
        self.run_dir = run_dir
        self.daemon = daemon
        self.cli = cli
        self.http_endpoints = [
            ("127.0.0.1", base_port + index) for index in range(3)
        ]
        self.raft_endpoints = [
            ("127.0.0.1", base_port + 100 + index) for index in range(3)
        ]
        self.children = ProcessSet(run_dir, "rqlite")

    @property
    def endpoints(self):
        return self.http_endpoints

    def data_dir(self, index):
        return self.run_dir / f"rqlite-{index + 1}"

    def start(self, index, initial=False):
        http_host, http_port = self.http_endpoints[index]
        raft_host, raft_port = self.raft_endpoints[index]
        command = [
            self.daemon,
            "-node-id", str(index + 1),
            "-http-addr", f"{http_host}:{http_port}",
            "-raft-addr", f"{raft_host}:{raft_port}",
        ]
        if initial and index != 0:
            join_host, join_port = self.raft_endpoints[0]
            command.extend(["-join", f"{join_host}:{join_port}"])
        command.append(str(self.data_dir(index)))
        self.children.spawn(index, command)

    def start_initial(self):
        self.start(0, initial=True)
        wait_port(self.http_endpoints[0])
        self.start(1, initial=True)
        self.start(2, initial=True)
        wait_port(self.http_endpoints[1])
        wait_port(self.http_endpoints[2])
        self.wait_cluster()

    def restart(self, index):
        self.start(index, initial=False)
        wait_port(self.http_endpoints[index])

    def nodes(self):
        for index in self.children.running_indices():
            host, port = self.http_endpoints[index]
            connection = http.client.HTTPConnection(host, port, timeout=1)
            try:
                connection.request("GET", "/nodes")
                response = connection.getresponse()
                body = response.read()
                if response.status != 200:
                    continue
                document = json.loads(body)
                return list(document.values())
            except (OSError, http.client.HTTPException, json.JSONDecodeError):
                continue
            finally:
                connection.close()
        return []

    def wait_cluster(self, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            nodes = self.nodes()
            if (len(nodes) == 3 and
                    all(node.get("reachable") is True and
                        node.get("voter") is True for node in nodes)):
                return
            time.sleep(0.05)
        raise TimeoutError("rqlite did not report three reachable voters")

    def leader_index(self):
        for node in self.nodes():
            if node.get("leader") is True:
                return int(node["id"]) - 1
        return None

    def wait_leader(self, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            leader = self.leader_index()
            if leader is not None and leader in self.children.running_indices():
                return leader
            time.sleep(0.05)
        raise TimeoutError("rqlite did not elect a leader")

    def client_factory(self, worker_id):
        return RqliteClient(self.http_endpoints, worker_id)

    def setup(self):
        client = self.client_factory(0)
        try:
            for statement in (*SCHEMA, *SEED_DATA):
                client.execute(statement)
        finally:
            client.close()

    def local_values(self, index):
        result = rqlite_request_once(
            self.http_endpoints[index], "/db/query?level=none", INVARIANT_SQL, 2)
        return values_from_rqlite(result)

    def linearizable_values(self):
        client = self.client_factory(0)
        try:
            result, _ = client.call("/db/query?level=strong", INVARIANT_SQL)
            return values_from_rqlite(result)
        finally:
            client.close()

    def wait_local_state(self, expected, indices=None, timeout=30):
        indices = self.children.running_indices() if indices is None else indices
        deadline = time.monotonic() + timeout
        last_error = None
        while time.monotonic() < deadline:
            actual = {}
            try:
                for index in indices:
                    values = self.local_values(index)
                    verify_values(values, expected)
                    actual[str(index + 1)] = values
                return actual
            except (OSError, TimeoutError, RuntimeError, ValueError,
                    http.client.HTTPException) as error:
                last_error = error
                time.sleep(0.05)
        raise TimeoutError(f"rqlite nodes did not catch up: {last_error}")

    def integrity(self):
        reports = {}
        for index in self.children.running_indices():
            result = rqlite_request_once(
                self.http_endpoints[index],
                "/db/query?level=none",
                "pragma integrity_check",
                10,
            )
            rows = result.get("values")
            if rows != [["ok"]]:
                raise RuntimeError(f"rqlite integrity failed on node {index + 1}: {rows}")
            reports[str(index + 1)] = {"sqlite_ok": True}
        return reports

    def cli_evidence(self):
        host, port = self.http_endpoints[self.wait_leader()]
        result = subprocess.run(
            [self.cli, "-H", host, "-p", str(port)],
            input=".nodes\n.quit\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
        if result.returncode != 0 or output.count("voter: true") != 3:
            raise RuntimeError(f"rqlite CLI membership verification failed: {output}")
        path = self.run_dir / "rqlite-cli-final-nodes.txt"
        path.write_text(output, encoding="utf-8")
        return {"reachable_voters": 3, "evidence_file": path.name}


def run_system(cluster, phase_operations, warmup_operations, concurrency, seed):
    expected = ExpectedState()
    next_order_id = 1
    result = {"system": cluster.system, "nodes": 3}
    try:
        started = time.perf_counter()
        cluster.start_initial()
        result["initial_startup_ms"] = (time.perf_counter() - started) * 1000

        started = time.perf_counter()
        cluster.setup()
        result["schema_and_seed_ms"] = (time.perf_counter() - started) * 1000

        warmup, next_order_id = generate_operations(
            warmup_operations, seed, next_order_id, expected)
        run_phase("warmup", warmup, cluster.client_factory, concurrency)

        phases = []
        baseline, next_order_id = generate_operations(
            phase_operations, seed + 1, next_order_id, expected)
        phases.append(run_phase(
            "healthy", baseline, cluster.client_factory, concurrency))
        verify_values(cluster.linearizable_values(), expected)
        cluster.wait_local_state(expected)

        leader = cluster.wait_leader()
        follower = next(index for index in cluster.children.running_indices()
                        if index != leader)
        cluster.children.crash(follower)
        follower_down, next_order_id = generate_operations(
            phase_operations, seed + 2, next_order_id, expected)
        follower_phase = run_phase(
            "one_follower_crashed",
            follower_down,
            cluster.client_factory,
            concurrency,
        )
        verify_values(cluster.linearizable_values(), expected)
        started = time.perf_counter()
        cluster.restart(follower)
        follower_state = cluster.wait_local_state(expected, [follower])
        follower_phase["restarted_node"] = follower + 1
        follower_phase["catch_up_ms"] = (time.perf_counter() - started) * 1000
        follower_phase["caught_up_state"] = follower_state
        phases.append(follower_phase)

        cluster.wait_local_state(expected)
        leader = cluster.wait_leader()
        cluster.children.crash(leader)
        leader_down, next_order_id = generate_operations(
            phase_operations, seed + 3, next_order_id, expected)
        leader_phase = run_phase(
            "leader_crashed",
            leader_down,
            cluster.client_factory,
            concurrency,
        )
        verify_values(cluster.linearizable_values(), expected)
        started = time.perf_counter()
        cluster.restart(leader)
        leader_state = cluster.wait_local_state(expected, [leader])
        leader_phase["crashed_node"] = leader + 1
        leader_phase["restarted_node_catch_up_ms"] = (
            time.perf_counter() - started) * 1000
        leader_phase["caught_up_state"] = leader_state
        phases.append(leader_phase)

        cluster.wait_local_state(expected)
        cluster.children.crash_all()
        started = time.perf_counter()
        for index in range(3):
            cluster.start(index, initial=False)
        for endpoint in cluster.endpoints:
            wait_port(endpoint)
        cluster.wait_leader()
        recovered_state = cluster.wait_local_state(expected)
        total_restart_ms = (time.perf_counter() - started) * 1000

        verify_values(cluster.linearizable_values(), expected)
        result["phases"] = phases
        result["total_cluster_restart"] = {
            "recovery_ms": total_restart_ms,
            "state": recovered_state,
        }
        result["correctness"] = {
            "expected": expected.as_dict(),
            "per_node": recovered_state,
            "integrity": cluster.integrity(),
        }
        evidence = cluster.cli_evidence()
        if evidence is not None:
            result["cli_evidence"] = evidence
        return result
    finally:
        cluster.children.crash_all()


def parse_args():
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--zaxon-bin",
        default=os.environ.get("ZAXON_BIN", str(script_dir.parent / "zig-out/bin/zaxon")),
    )
    parser.add_argument(
        "--rqlited-bin",
        default=os.environ.get("RQLITED_BIN", shutil.which("rqlited") or "rqlited"),
    )
    parser.add_argument(
        "--rqlite-cli",
        default=os.environ.get("RQLITE_CLI", shutil.which("rqlite") or "rqlite"),
    )
    parser.add_argument("--phase-operations", type=int, default=400)
    parser.add_argument("--warmup-operations", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--seed", type=int, default=20260720)
    parser.add_argument("--base-port", type=int, default=30000 + os.getpid() % 10000)
    parser.add_argument("--keep-run-dir", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.phase_operations < 1 or args.warmup_operations < 0:
        raise SystemExit("operation counts must be positive")
    if args.concurrency < 1 or args.concurrency > 32:
        raise SystemExit("concurrency must be between 1 and 32")
    for binary in (args.zaxon_bin, args.rqlited_bin, args.rqlite_cli):
        if not shutil.which(binary) and not Path(binary).is_file():
            raise SystemExit(f"required executable not found: {binary}")

    run_dir = Path(tempfile.mkdtemp(prefix="zaxon-rqlite-realworld-"))
    keep = args.keep_run_dir or os.environ.get("KEEP_RUN_DIR") == "1"
    success = False
    try:
        zaxon = ZaxonCluster(run_dir, args.zaxon_bin, args.base_port)
        rqlite = RqliteCluster(
            run_dir, args.rqlited_bin, args.rqlite_cli, args.base_port + 500)
        results = [
            run_system(
                zaxon,
                args.phase_operations,
                args.warmup_operations,
                args.concurrency,
                args.seed,
            ),
            run_system(
                rqlite,
                args.phase_operations,
                args.warmup_operations,
                args.concurrency,
                args.seed,
            ),
        ]
        document = {
            "format": 1,
            "run_at_utc": datetime.datetime.now(
                datetime.timezone.utc).isoformat(),
            "host": platform.platform(),
            "workload": {
                "name": "order processing with inventory and ledger fanout",
                "customers": 1000,
                "products": 500,
                "read_percent": 70,
                "write_percent": 30,
                "phase_operations": args.phase_operations,
                "warmup_operations": args.warmup_operations,
                "concurrency": args.concurrency,
                "seed": args.seed,
                "read_consistency": {
                    "zaxonlite": "linearizable quorum fence",
                    "rqlite": "linearizable ReadIndex-style fence",
                },
                "write_retry": "unique operation ID plus insert-or-ignore",
            },
            "failure_schedule": [
                "healthy",
                "crash one follower; continue traffic; restart and catch up",
                "crash leader; retry traffic; elect; restart and catch up",
                "crash all nodes; restart same identities; verify every copy",
            ],
            "tools": {
                "zaxon": {
                    "path": str(Path(args.zaxon_bin).resolve()),
                    "version": command_version([args.zaxon_bin, "version"]),
                },
                "rqlited": {
                    "path": str(Path(args.rqlited_bin).resolve()),
                    "version": command_version([args.rqlited_bin, "-version"]),
                },
                "rqlite_cli": {
                    "path": str(Path(args.rqlite_cli).resolve()),
                    "version": command_version([args.rqlite_cli, "-v"]),
                },
            },
            "results": results,
        }
        print(json.dumps(document, indent=2, sort_keys=True))
        success = True
    finally:
        if keep or not success:
            print(f"benchmark: artifacts preserved at {run_dir}", file=sys.stderr)
        else:
            shutil.rmtree(run_dir)


if __name__ == "__main__":
    main()
