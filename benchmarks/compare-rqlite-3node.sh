#!/bin/sh
set -eu

# Fair scope: three voters, loopback TCP, one sequential persistent client,
# one-row autocommit writes, equal payload bytes, excluded warmup, durable node
# directories, strong verification reads, and no queued-write batching.

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
zaxon_bin=${ZAXON_BIN:-"$script_dir/../zig-out/bin/zaxon"}
rqlited_bin=${RQLITED_BIN:-rqlited}
rqlite_cli=${RQLITE_CLI:-rqlite}
python_bin=${PYTHON:-python3}
operations=${OPERATIONS:-1000}
warmup=${WARMUP:-100}
payload_bytes=${PAYLOAD_BYTES:-256}
base_port=${BASE_PORT:-$((32000 + ($$ % 8000)))}
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/zaxon-rqlite-bench.XXXXXX")

pids=""
cleanup() {
    status=$?
    trap - EXIT
    for pid in $pids; do kill "$pid" 2>/dev/null || true; done
    for pid in $pids; do wait "$pid" 2>/dev/null || true; done
    if [ "$status" -ne 0 ] || [ "${KEEP_RUN_DIR:-0}" = "1" ]; then
        echo "benchmark: artifacts preserved at $run_dir" >&2
    else
        rm -rf "$run_dir"
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "benchmark: missing required command: $1" >&2
        exit 2
    }
}

require_command "$python_bin"
require_command "$rqlited_bin"
require_command "$rqlite_cli"
if [ ! -x "$zaxon_bin" ]; then
    echo "benchmark: build zaxon first or set ZAXON_BIN" >&2
    exit 2
fi

command -v "$rqlited_bin" >"$run_dir/rqlited.path"
command -v "$rqlite_cli" >"$run_dir/rqlite-cli.path"
printf '%s\n' "$zaxon_bin" >"$run_dir/zaxon.path"
"$rqlited_bin" -version >"$run_dir/rqlited.version" 2>&1
"$rqlite_cli" -v >"$run_dir/rqlite-cli.version" 2>&1
"$zaxon_bin" version >"$run_dir/zaxon.version" 2>&1

wait_port() {
    "$python_bin" - "$1" "$2" <<'PY'
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
for _ in range(400):
    try:
        socket.create_connection((host, port), 0.1).close()
        raise SystemExit(0)
    except OSError:
        time.sleep(0.05)
raise SystemExit("port did not become ready")
PY
}

wait_rqlite_cluster() {
    "$python_bin" - "$1" <<'PY'
import json, sys, time, urllib.request
url = f"http://127.0.0.1:{sys.argv[1]}/nodes"
for _ in range(400):
    try:
        with urllib.request.urlopen(url, timeout=0.2) as response:
            document = json.load(response)
        nodes = list(document.values()) if isinstance(document, dict) else document
        if (isinstance(nodes, list) and len(nodes) == 3 and
                all(node.get("reachable") is True and
                    node.get("voter") is True for node in nodes)):
            raise SystemExit(0)
    except Exception:
        pass
    time.sleep(0.05)
raise SystemExit("rqlite cluster did not report three reachable voters")
PY
}

start_zaxon() {
    index=$1
    port=$((base_port + index - 1))
    args=""
    peer=1
    while [ "$peer" -le 3 ]; do
        if [ "$peer" -ne "$index" ]; then
            peer_port=$((base_port + peer - 1))
            args="$args --peer ${peer}@127.0.0.1:${peer_port}/data-voter"
        fi
        peer=$((peer + 1))
    done
    # Word splitting is intentional for the generated peer argument pairs.
    # shellcheck disable=SC2086
    "$zaxon_bin" serve --data "$run_dir/zaxon-$index" --node "$index" \
        --listen "127.0.0.1:$port" --cluster-id fair-3node-rqlite $args \
        >"$run_dir/zaxon-$index.log" 2>&1 &
    pids="$pids $!"
}

start_rqlite() {
    index=$1
    http_port=$((base_port + 100 + index - 1))
    raft_port=$((base_port + 200 + index - 1))
    join_args=""
    if [ "$index" -ne 1 ]; then
        join_args="-join 127.0.0.1:$((base_port + 200))"
    fi
    # Word splitting is intentional for the optional join argument pair.
    # shellcheck disable=SC2086
    "$rqlited_bin" -node-id "$index" \
        -http-addr "127.0.0.1:$http_port" \
        -raft-addr "127.0.0.1:$raft_port" $join_args \
        "$run_dir/rqlite-$index" >"$run_dir/rqlite-$index.log" 2>&1 &
    pids="$pids $!"
}

start_zaxon 1
start_zaxon 2
start_zaxon 3
wait_port 127.0.0.1 "$base_port"
wait_port 127.0.0.1 "$((base_port + 1))"
wait_port 127.0.0.1 "$((base_port + 2))"

start_rqlite 1
wait_port 127.0.0.1 "$((base_port + 100))"
start_rqlite 2
start_rqlite 3
wait_port 127.0.0.1 "$((base_port + 101))"
wait_port 127.0.0.1 "$((base_port + 102))"
wait_rqlite_cluster "$((base_port + 100))"

# Exercise the requested system-installed CLI before and after the load. The
# common Python driver performs timing so both products expose the same JSON
# percentile and verification contract.
printf '.nodes\n.quit\n' | "$rqlite_cli" -H 127.0.0.1 \
    -p "$((base_port + 100))" >"$run_dir/rqlite-cli-nodes.txt"

common_args="--operations $operations --warmup $warmup --payload-bytes $payload_bytes"
zaxon_addresses="127.0.0.1:$base_port,127.0.0.1:$((base_port + 1)),127.0.0.1:$((base_port + 2))"
# shellcheck disable=SC2086
"$python_bin" "$script_dir/driver.py" zaxonlite "$zaxon_addresses" \
    $common_args >"$run_dir/zaxon.json"
# shellcheck disable=SC2086
"$python_bin" "$script_dir/driver.py" rqlite \
    "127.0.0.1:$((base_port + 100))" $common_args >"$run_dir/rqlite.json"

printf 'SELECT count(*) AS measured_rows FROM bench WHERE k > 0;\n.quit\n' | \
    "$rqlite_cli" -H 127.0.0.1 -p "$((base_port + 100))" \
    >"$run_dir/rqlite-cli-verification.txt"

"$python_bin" - "$run_dir" <<'PY'
import datetime, json, pathlib, platform, sys
run_dir = pathlib.Path(sys.argv[1])
with (run_dir / "zaxon.json").open(encoding="utf-8") as stream:
    zaxon = json.load(stream)
with (run_dir / "rqlite.json").open(encoding="utf-8") as stream:
    rqlite = json.load(stream)
def contents(name):
    return (run_dir / name).read_text(encoding="utf-8").strip()
print(json.dumps({
    "format": 1,
    "host": platform.platform(),
    "run_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "rules": {
        "nodes": 3,
        "durability": "persistent quorum state and node directories",
        "client": "one sequential persistent connection",
        "transaction": "one row per autocommit",
        "queued_writes": False,
        "warmup_excluded": True,
        "verification": "strong count and exact-payload predicate",
    },
    "tools": {
        "zaxon": {
            "path": contents("zaxon.path"),
            "version": contents("zaxon.version"),
        },
        "rqlited": {
            "path": contents("rqlited.path"),
            "version": contents("rqlited.version"),
        },
        "rqlite_cli": {
            "path": contents("rqlite-cli.path"),
            "version": contents("rqlite-cli.version"),
            "used_for": "cluster membership and final row verification",
        },
    },
    "results": [zaxon, rqlite],
}, indent=2, sort_keys=True))
PY
