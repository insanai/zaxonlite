#!/usr/bin/env python3
"""Deterministic order-processing workload shared by product controllers."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import http.client
import json
import math
import random
import socket
import statistics
import struct
import time


CUSTOMERS = 1000
PRODUCTS = 500
INITIAL_STOCK = 10000
TRANSIENT_ZAXON_ERRORS = {
    "ambiguous",
    "not_leader",
    "retry",
    "timeout",
    "unavailable",
}
TRANSIENT_RQLITE_TEXT = (
    "connection",
    "leader",
    "not ready",
    "timeout",
    "unavailable",
)


SCHEMA = (
    """create table customers(
        id integer primary key,
        email text not null unique,
        region text not null,
        tier integer not null,
        created_at integer not null
    )""",
    """create table products(
        id integer primary key,
        sku text not null unique,
        name text not null,
        price_cents integer not null check(price_cents > 0),
        stock integer not null check(stock >= 0)
    )""",
    """create table orders(
        id integer primary key,
        operation_id text not null unique,
        customer_id integer not null references customers(id),
        product_id integer not null references products(id),
        quantity integer not null check(quantity > 0),
        unit_price_cents integer not null,
        status text not null,
        metadata text not null,
        created_at integer not null
    )""",
    """create table order_lines(
        order_id integer primary key references orders(id),
        product_id integer not null,
        quantity integer not null,
        line_total_cents integer not null
    )""",
    """create table order_ledger(
        operation_id text primary key,
        order_id integer not null unique,
        amount_cents integer not null,
        recorded_at integer not null
    )""",
    "create index orders_customer_time on orders(customer_id, created_at desc)",
    "create index order_lines_product on order_lines(product_id)",
    """create trigger order_fanout after insert on orders begin
        insert into order_lines(order_id, product_id, quantity, line_total_cents)
            values(new.id, new.product_id, new.quantity,
                   new.quantity * new.unit_price_cents);
        update products set stock = stock - new.quantity
            where id = new.product_id;
        insert into order_ledger(operation_id, order_id, amount_cents, recorded_at)
            values(new.operation_id, new.id,
                   new.quantity * new.unit_price_cents, new.created_at);
    end""",
)

SEED_DATA = (
    f"""with recursive n(x) as (
        values(1) union all select x + 1 from n where x < {CUSTOMERS}
    ) insert into customers(id, email, region, tier, created_at)
      select x, printf('customer-%04d@example.test', x),
             case x % 4 when 0 then 'apac' when 1 then 'amer'
                          when 2 then 'emea' else 'latam' end,
             1 + (x % 3), 1700000000 + x from n""",
    f"""with recursive n(x) as (
        values(1) union all select x + 1 from n where x < {PRODUCTS}
    ) insert into products(id, sku, name, price_cents, stock)
      select x, printf('SKU-%05d', x), printf('Catalog product %05d', x),
             500 + (x * 17), {INITIAL_STOCK} from n""",
)

INVARIANT_SQL = f"""select
    (select count(*) from orders),
    (select count(*) from order_lines),
    (select count(*) from order_ledger),
    (select count(distinct operation_id) from orders),
    (select coalesce(sum({INITIAL_STOCK} - stock), 0) from products),
    (select coalesce(sum(line_total_cents), 0) from order_lines),
    (select count(*) from products where stock < 0)
"""


@dataclass(frozen=True)
class Operation:
    kind: str
    label: str
    sql: str


@dataclass
class ExpectedState:
    orders: int = 0
    units: int = 0
    revenue_cents: int = 0

    def record_order(self, product_id, quantity):
        self.orders += 1
        self.units += quantity
        self.revenue_cents += quantity * product_price(product_id)

    def as_dict(self):
        return {
            "orders": self.orders,
            "order_lines": self.orders,
            "ledger_entries": self.orders,
            "distinct_operations": self.orders,
            "units_sold": self.units,
            "revenue_cents": self.revenue_cents,
            "negative_stock_rows": 0,
        }


def product_price(product_id):
    return 500 + product_id * 17


def generate_operations(count, seed, first_order_id, expected):
    """Return a deterministic 30%-write, 70%-read operation list."""
    rng = random.Random(seed)
    operations = []
    next_order_id = first_order_id
    for sequence in range(count):
        selector = rng.randrange(100)
        if selector < 30:
            product_id = 1 + rng.randrange(PRODUCTS)
            customer_id = 1 + rng.randrange(CUSTOMERS)
            quantity = 1 + rng.randrange(4)
            operations.append(Operation(
                "write",
                "place_order",
                order_sql(next_order_id, customer_id, product_id, quantity),
            ))
            expected.record_order(product_id, quantity)
            next_order_id += 1
        elif selector < 55:
            product_id = 1 + rng.randrange(PRODUCTS)
            operations.append(Operation(
                "read",
                "inventory_point",
                inventory_query(product_id),
            ))
        elif selector < 90:
            customer_id = 1 + rng.randrange(CUSTOMERS)
            operations.append(Operation(
                "read",
                "customer_history",
                customer_query(customer_id),
            ))
        else:
            operations.append(Operation("read", "sales_dashboard", DASHBOARD_QUERY))
    return operations, next_order_id


def order_sql(order_id, customer_id, product_id, quantity):
    metadata = (
        '{"channel":"web","currency":"USD","warehouse":"primary",'
        '"campaign":"benchmark","delivery":"standard"}'
    )
    return f"""insert or ignore into orders(
        id, operation_id, customer_id, product_id, quantity,
        unit_price_cents, status, metadata, created_at
    ) select {order_id}, 'order-op-{order_id}', {customer_id}, p.id, {quantity},
             p.price_cents, 'confirmed', '{metadata}', {1701000000 + order_id}
      from products p where p.id = {product_id} and p.stock >= {quantity}"""


def inventory_query(product_id):
    return f"""select p.id, p.sku, p.name, p.price_cents, p.stock,
        coalesce(sum(ol.quantity), 0) as units_sold
      from products p left join order_lines ol on ol.product_id = p.id
      where p.id = {product_id} group by p.id"""


def customer_query(customer_id):
    return f"""select o.id, o.status, o.created_at,
        sum(ol.line_total_cents) as total_cents
      from orders o join order_lines ol on ol.order_id = o.id
      where o.customer_id = {customer_id}
      group by o.id order by o.created_at desc limit 20"""


DASHBOARD_QUERY = """select count(*) as orders,
    coalesce(sum(ol.line_total_cents), 0) as revenue_cents,
    coalesce(avg(ol.line_total_cents), 0) as average_order_cents,
    count(distinct o.customer_id) as active_customers
  from orders o join order_lines ol on ol.order_id = o.id"""


def percentile(ordered, fraction):
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1))
    return ordered[index]


def latency_summary(values):
    if not values:
        return None
    ordered = sorted(values)
    return {
        "p50": statistics.median(ordered) * 1000,
        "p95": percentile(ordered, 0.95) * 1000,
        "p99": percentile(ordered, 0.99) * 1000,
        "max": ordered[-1] * 1000,
    }


def run_phase(name, operations, client_factory, concurrency):
    """Run a fixed operation list and return retry-inclusive latency metrics."""
    partitions = [[] for _ in range(concurrency)]
    for index, operation in enumerate(operations):
        partitions[index % concurrency].append(operation)

    phase_started = time.perf_counter()

    def run_partition(worker_id, partition):
        client = client_factory(worker_id)
        records = []
        try:
            for operation in partition:
                started = time.perf_counter()
                if operation.kind == "write":
                    attempts = client.execute(operation.sql)
                else:
                    attempts = client.query(operation.sql)
                records.append({
                    "kind": operation.kind,
                    "label": operation.label,
                    "latency": time.perf_counter() - started,
                    "attempts": attempts,
                    "completed": time.perf_counter(),
                })
        finally:
            client.close()
        return records

    records = []
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(run_partition, index, partition)
            for index, partition in enumerate(partitions)
        ]
        for future in futures:
            records.extend(future.result())

    elapsed = time.perf_counter() - phase_started
    reads = [record["latency"] for record in records if record["kind"] == "read"]
    writes = [record["latency"] for record in records if record["kind"] == "write"]
    return {
        "name": name,
        "operations": len(records),
        "reads": len(reads),
        "writes": len(writes),
        "concurrency": concurrency,
        "seconds": elapsed,
        "operations_per_second": len(records) / elapsed,
        "retry_attempts": sum(record["attempts"] - 1 for record in records),
        "time_to_first_success_ms": (
            min(record["completed"] for record in records) - phase_started
        ) * 1000,
        "latency_ms": {
            "all": latency_summary([record["latency"] for record in records]),
            "reads": latency_summary(reads),
            "writes": latency_summary(writes),
        },
    }


def receive_exact(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise EOFError("connection closed")
        data.extend(chunk)
    return bytes(data)


class ZaxonWireConnection:
    def __init__(self, endpoint, timeout=5):
        self.endpoint = endpoint
        self.socket = socket.create_connection(endpoint, timeout=timeout)
        hello = struct.pack("<HB", 4, 1)
        hello += struct.pack("<I", 0) + bytes(16) + struct.pack("<Q", 0)
        self.send_frame(1, hello)

    def close(self):
        self.socket.close()

    def send_frame(self, kind, body):
        self.socket.sendall(struct.pack("<I", len(body) + 1) + bytes([kind]) + body)

    def call(self, request):
        body = json.dumps(request, separators=(",", ":")).encode()
        self.send_frame(11, body)
        length = struct.unpack("<I", receive_exact(self.socket, 4))[0]
        frame = receive_exact(self.socket, length)
        if not frame or frame[0] != 12:
            raise RuntimeError("unexpected Zaxon response frame")
        return json.loads(frame[1:])


def zaxon_call_once(endpoint, request, timeout=5):
    connection = ZaxonWireConnection(endpoint, timeout)
    try:
        return connection.call(request)
    finally:
        connection.close()


class ZaxonClient:
    def __init__(self, endpoints, start_index=0, retry_timeout=30):
        self.endpoints = endpoints
        self.index = start_index % len(endpoints)
        self.retry_timeout = retry_timeout
        self.connection = None

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def _rotate(self, preferred=None):
        self.close()
        if preferred is None:
            self.index = (self.index + 1) % len(self.endpoints)
        else:
            self.index = preferred % len(self.endpoints)

    def call(self, request):
        deadline = time.monotonic() + self.retry_timeout
        attempts = 0
        last_error = None
        while time.monotonic() < deadline:
            attempts += 1
            try:
                if self.connection is None:
                    self.connection = ZaxonWireConnection(self.endpoints[self.index])
                response = self.connection.call(request)
            except (EOFError, OSError, TimeoutError, ValueError) as error:
                last_error = error
                self._rotate()
                time.sleep(min(0.02 * attempts, 0.2))
                continue
            if response.get("ok"):
                return response, attempts
            code = response.get("error")
            if code not in TRANSIENT_ZAXON_ERRORS:
                raise RuntimeError(f"Zaxon request failed: {response}")
            last_error = RuntimeError(str(response))
            preferred = None
            leader = response.get("leader")
            if isinstance(leader, dict) and isinstance(leader.get("id"), int):
                leader_id = leader["id"]
                if 1 <= leader_id <= len(self.endpoints):
                    preferred = leader_id - 1
            elif isinstance(leader, int) and 1 <= leader <= len(self.endpoints):
                preferred = leader - 1
            self._rotate(preferred)
            time.sleep(min(0.02 * attempts, 0.2))
        raise TimeoutError(f"Zaxon request did not recover: {last_error}")

    def execute(self, sql):
        _, attempts = self.call({"op": "exec", "sql": sql})
        return attempts

    def query(self, sql):
        _, attempts = self.call({
            "op": "query",
            "level": "linearizable",
            "sql": sql,
        })
        return attempts


def rqlite_request_once(endpoint, path, sql, timeout=5):
    connection = http.client.HTTPConnection(endpoint[0], endpoint[1], timeout=timeout)
    try:
        body = json.dumps([sql], separators=(",", ":")).encode()
        connection.request("POST", path, body=body, headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        })
        response = connection.getresponse()
        response_body = response.read()
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}: {response_body!r}")
        document = json.loads(response_body)
        results = document.get("results")
        if document.get("error") or not isinstance(results, list) or len(results) != 1:
            raise RuntimeError(f"unexpected rqlite response: {document}")
        if results[0].get("error"):
            raise RuntimeError(f"rqlite SQL failed: {results[0]['error']}")
        return results[0]
    finally:
        connection.close()


class RqliteClient:
    def __init__(self, endpoints, start_index=0, retry_timeout=30):
        self.endpoints = endpoints
        self.index = start_index % len(endpoints)
        self.retry_timeout = retry_timeout
        self.connection = None

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def _rotate(self):
        self.close()
        self.index = (self.index + 1) % len(self.endpoints)

    def call(self, path, sql):
        deadline = time.monotonic() + self.retry_timeout
        attempts = 0
        last_error = None
        body = json.dumps([sql], separators=(",", ":")).encode()
        while time.monotonic() < deadline:
            attempts += 1
            try:
                if self.connection is None:
                    host, port = self.endpoints[self.index]
                    self.connection = http.client.HTTPConnection(host, port, timeout=5)
                self.connection.request("POST", path, body=body, headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                })
                response = self.connection.getresponse()
                response_body = response.read()
                if response.status >= 500:
                    raise OSError(f"HTTP {response.status}: {response_body!r}")
                if response.status != 200:
                    raise RuntimeError(
                        f"HTTP {response.status}: {response_body!r}")
                document = json.loads(response_body)
                error = document.get("error")
                results = document.get("results")
                if error:
                    raise OSError(str(error))
                if not isinstance(results, list) or len(results) != 1:
                    raise RuntimeError(f"unexpected rqlite response: {document}")
                result = results[0]
                if result.get("error"):
                    text = str(result["error"])
                    if any(fragment in text.lower() for fragment in TRANSIENT_RQLITE_TEXT):
                        raise OSError(text)
                    raise RuntimeError(f"rqlite SQL failed: {text}")
                return result, attempts
            except (EOFError, OSError, TimeoutError, http.client.HTTPException,
                    json.JSONDecodeError) as error:
                last_error = error
                self._rotate()
                time.sleep(min(0.02 * attempts, 0.2))
        raise TimeoutError(f"rqlite request did not recover: {last_error}")

    def execute(self, sql):
        _, attempts = self.call("/db/execute", sql)
        return attempts

    def query(self, sql):
        _, attempts = self.call(
            "/db/query?level=linearizable&linearizable_timeout=2s", sql)
        return attempts


def values_from_zaxon(response):
    rows = response.get("rows")
    if not rows:
        raise RuntimeError(f"Zaxon query returned no rows: {response}")
    return [int(value) for value in rows[0]]


def values_from_rqlite(result):
    rows = result.get("values")
    if not rows:
        raise RuntimeError(f"rqlite query returned no rows: {result}")
    return [int(value) for value in rows[0]]


def expected_values(expected):
    return [
        expected.orders,
        expected.orders,
        expected.orders,
        expected.orders,
        expected.units,
        expected.revenue_cents,
        0,
    ]


def verify_values(actual, expected):
    wanted = expected_values(expected)
    if actual != wanted:
        raise RuntimeError(f"invariant mismatch: actual={actual} expected={wanted}")
