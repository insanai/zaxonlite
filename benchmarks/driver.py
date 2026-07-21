#!/usr/bin/env python3
"""Common sequential durable-write driver for three-node comparisons."""

import argparse
import http.client
import json
import math
import socket
import ssl
import statistics
import struct
import time


def percentile(ordered, fraction):
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1))
    return ordered[index]


def summary(system, latencies, elapsed, operations, payload_bytes):
    ordered = sorted(latencies)
    return {
        "system": system,
        "nodes": 3,
        "workload": "sequential one-row durable autocommit",
        "operations": operations,
        "payload_bytes": payload_bytes,
        "seconds": elapsed,
        "operations_per_second": operations / elapsed,
        "latency_ms": {
            "p50": statistics.median(ordered) * 1000,
            "p95": percentile(ordered, 0.95) * 1000,
            "p99": percentile(ordered, 0.99) * 1000,
            "max": ordered[-1] * 1000,
        },
    }


class Zaxon:
    def __init__(self, address, tls_cert, tls_key, tls_ca):
        self.addresses = address.split(",")
        self.tls = ssl.create_default_context(cafile=tls_ca)
        self.tls.load_cert_chain(tls_cert, tls_key)
        self.address_index = 0
        self.socket = None
        self.connect(0)

    def connect(self, index):
        if self.socket is not None:
            self.socket.close()
        self.address_index = index
        host, port = self.addresses[index].rsplit(":", 1)
        raw = socket.create_connection((host, int(port)), timeout=10)
        self.socket = self.tls.wrap_socket(
            raw, server_hostname=f"zaxon-node-{index + 1}")
        hello = struct.pack("<HB", 6, 1)
        hello += struct.pack("<I", 0) + bytes(16) + struct.pack("<Q", 0)
        self.send_frame(1, hello)

    def close(self):
        if self.socket is not None:
            self.socket.close()

    def send_frame(self, kind, body):
        self.socket.sendall(struct.pack("<I", len(body) + 1) + bytes([kind]) + body)

    def receive_frame(self):
        length = struct.unpack("<I", receive_exact(self.socket, 4))[0]
        frame = receive_exact(self.socket, length)
        return frame[0], frame[1:]

    def call(self, request):
        for attempt in range(12):
            self.send_frame(11, json.dumps(
                request, separators=(",", ":")).encode())
            kind, body = self.receive_frame()
            if kind != 12:
                raise RuntimeError(f"unexpected Zaxon frame {kind}")
            response = json.loads(body)
            if response.get("ok"):
                return response
            if response.get("error") != "not_leader":
                raise RuntimeError(f"Zaxon request failed: {response}")
            leader = response.get("leader")
            if isinstance(leader, int) and 1 <= leader <= len(self.addresses):
                next_index = leader - 1
            else:
                next_index = (self.address_index + 1) % len(self.addresses)
                time.sleep(min(0.01 * (attempt + 1), 0.1))
            self.connect(next_index)
        raise RuntimeError("Zaxon leader did not become available")


def receive_exact(stream, length):
    chunks = bytearray()
    while len(chunks) < length:
        chunk = stream.recv(length - len(chunks))
        if not chunk:
            raise EOFError("connection closed")
        chunks.extend(chunk)
    return bytes(chunks)


def benchmark_zaxon(address, operations, warmup, payload_bytes, args):
    client = Zaxon(address, args.tls_cert, args.tls_key, args.tls_ca)
    try:
        client.call({"op": "exec", "sql":
                     "create table if not exists bench(k integer primary key, v blob)"})
        value = "x" * payload_bytes
        for index in range(warmup):
            client.call({"op": "exec", "sql":
                         f"insert into bench values ({-index - 1}, '{value}')"})
        latencies = []
        measured_started = time.perf_counter()
        for index in range(operations):
            started = time.perf_counter()
            client.call({"op": "exec", "sql":
                         f"insert into bench values ({index + 1}, '{value}')"})
            latencies.append(time.perf_counter() - started)
        elapsed = time.perf_counter() - measured_started
        result = client.call({
            "op": "query",
            "level": "linearizable",
            "sql": ("select count(*), count(*) filter (where v = '" + value +
                    "') from bench where k > 0"),
        })
        if ([int(value) for value in result["rows"][0]] !=
                [operations, operations]):
            raise RuntimeError("Zaxon verification mismatch")
        return summary("zaxonlite", latencies, elapsed, operations, payload_bytes)
    finally:
        client.close()


def benchmark_dqlite(address, operations, warmup, payload_bytes, _args):
    host, port = address.rsplit(":", 1)
    connection = http.client.HTTPConnection(host, int(port), timeout=10)
    value = b"x" * payload_bytes
    try:
        for index in range(warmup):
            put(connection, f"warmup-{index}", value)
        latencies = []
        measured_started = time.perf_counter()
        for index in range(operations):
            started = time.perf_counter()
            put(connection, f"measured-{index}", value)
            latencies.append(time.perf_counter() - started)
        elapsed = time.perf_counter() - measured_started
        for index in range(operations):
            response = get(connection, f"measured-{index}")
            if response != value:
                raise RuntimeError(
                    f"dqlite verification mismatch at measured-{index}")
        return summary("dqlite", latencies, elapsed, operations, payload_bytes)
    finally:
        connection.close()


def benchmark_rqlite(address, operations, warmup, payload_bytes, _args):
    host, port = address.rsplit(":", 1)
    connection = http.client.HTTPConnection(host, int(port), timeout=30)
    value = "x" * payload_bytes
    try:
        rqlite_sql(connection, "/db/execute",
                   "create table if not exists bench(k integer primary key, v blob)")
        for index in range(warmup):
            rqlite_sql(connection, "/db/execute",
                       f"insert into bench values ({-index - 1}, '{value}')")
        latencies = []
        measured_started = time.perf_counter()
        for index in range(operations):
            started = time.perf_counter()
            rqlite_sql(connection, "/db/execute",
                       f"insert into bench values ({index + 1}, '{value}')")
            latencies.append(time.perf_counter() - started)
        elapsed = time.perf_counter() - measured_started
        result = rqlite_sql(
            connection,
            "/db/query?level=strong",
            ("select count(*), count(*) filter (where v = '" + value +
             "') from bench where k > 0"),
        )
        values = result.get("values", [])
        if (not values or
                [int(value) for value in values[0]] != [operations, operations]):
            raise RuntimeError("rqlite verification mismatch")
        return summary("rqlite", latencies, elapsed, operations, payload_bytes)
    finally:
        connection.close()


def rqlite_sql(connection, endpoint, sql):
    body = json.dumps([sql], separators=(",", ":")).encode()
    connection.request(
        "POST",
        endpoint,
        body=body,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        },
    )
    response = connection.getresponse()
    response_body = response.read()
    if response.status != 200:
        raise RuntimeError(
            f"rqlite request failed: {response.status} {response_body!r}")
    document = json.loads(response_body)
    if document.get("error"):
        raise RuntimeError(f"rqlite request failed: {document['error']}")
    results = document.get("results")
    if not isinstance(results, list) or len(results) != 1:
        raise RuntimeError(f"unexpected rqlite response: {document}")
    result = results[0]
    if result.get("error"):
        raise RuntimeError(f"rqlite SQL failed: {result['error']}")
    return result


def put(connection, key, value):
    connection.request("PUT", f"/{key}", body=value,
                       headers={"Content-Length": str(len(value))})
    response = connection.getresponse()
    body = response.read()
    if response.status != 200:
        raise RuntimeError(f"dqlite PUT failed: {response.status} {body!r}")


def get(connection, key):
    connection.request("GET", f"/{key}")
    response = connection.getresponse()
    body = response.read()
    if response.status != 200:
        raise RuntimeError(f"dqlite GET failed: {response.status} {body!r}")
    return body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("system", choices=("zaxonlite", "dqlite", "rqlite"))
    parser.add_argument("address")
    parser.add_argument("--operations", type=int, default=1000)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--payload-bytes", type=int, default=256)
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    parser.add_argument("--tls-ca")
    args = parser.parse_args()
    if args.operations <= 0 or args.warmup < 0 or args.payload_bytes < 1:
        parser.error("operation counts and payload size must be positive")
    if args.system == "zaxonlite" and not all(
            (args.tls_cert, args.tls_key, args.tls_ca)):
        parser.error("zaxonlite requires --tls-cert, --tls-key, and --tls-ca")
    functions = {
        "zaxonlite": benchmark_zaxon,
        "dqlite": benchmark_dqlite,
        "rqlite": benchmark_rqlite,
    }
    function = functions[args.system]
    print(json.dumps(function(args.address, args.operations, args.warmup,
                              args.payload_bytes, args), sort_keys=True))


if __name__ == "__main__":
    main()
