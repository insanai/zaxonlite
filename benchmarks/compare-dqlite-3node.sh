#!/bin/sh
set -eu

# Fair scope: three voters, loopback TCP, one sequential client, one-row
# autocommit writes, equal payload bytes, warmup excluded, and post-run
# verification. Both systems persist consensus state in per-node directories;
# dqlite uses its current supported default SQLite materialization.

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
zaxon_bin=${ZAXON_BIN:-"$script_dir/../zig-out/bin/zaxon"}
dqlite_demo=${DQLITE_DEMO:-dqlite-demo}
python_bin=${PYTHON:-python3}
operations=${OPERATIONS:-1000}
warmup=${WARMUP:-100}
payload_bytes=${PAYLOAD_BYTES:-256}
base_port=${BASE_PORT:-$((32000 + ($$ % 10000)))}
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/zaxon-dqlite-bench.XXXXXX")

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
if [ ! -x "$zaxon_bin" ]; then
    echo "benchmark: build zaxon first or set ZAXON_BIN" >&2
    exit 2
fi
require_command "$dqlite_demo"
require_command openssl

# Production Zaxon TCP is mTLS-only. Keep the comparison self-contained with
# an ephemeral CA and one identity per node plus one client identity.
openssl ecparam -name prime256v1 -genkey -noout -out "$run_dir/ca.key"
chmod 600 "$run_dir/ca.key"
openssl req -new -x509 -key "$run_dir/ca.key" -sha256 -days 1 \
    -subj /CN=zaxon-benchmark-ca \
    -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign,cRLSign \
    -out "$run_dir/ca.crt"
issue_cert() {
    name=$1
    common_name=$2
    openssl ecparam -name prime256v1 -genkey -noout -out "$run_dir/$name.key"
    chmod 600 "$run_dir/$name.key"
    openssl req -new -key "$run_dir/$name.key" -subj "/CN=$common_name" \
        -out "$run_dir/$name.csr"
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectAltName=DNS:%s\nextendedKeyUsage=serverAuth,clientAuth\n' \
        "$common_name" >"$run_dir/$name.ext"
    openssl x509 -req -in "$run_dir/$name.csr" -CA "$run_dir/ca.crt" \
        -CAkey "$run_dir/ca.key" -CAcreateserial -days 1 -sha256 \
        -extfile "$run_dir/$name.ext" -out "$run_dir/$name.crt"
}
issue_cert n1 zaxon-node-1
issue_cert n2 zaxon-node-2
issue_cert n3 zaxon-node-3
issue_cert client zaxon-client

wait_port() {
    "$python_bin" - "$1" "$2" <<'PY'
import socket, sys, time
host, port = sys.argv[1], int(sys.argv[2])
for _ in range(200):
    try:
        socket.create_connection((host, port), 0.1).close()
        raise SystemExit(0)
    except OSError:
        time.sleep(0.05)
raise SystemExit("port did not become ready")
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
        --listen "127.0.0.1:$port" --cluster-id fair-3node $args \
        --tls-cert "$run_dir/n$index.crt" \
        --tls-key "$run_dir/n$index.key" --tls-ca "$run_dir/ca.crt" \
        >"$run_dir/zaxon-$index.log" 2>&1 &
    pids="$pids $!"
}

start_dqlite() {
    index=$1
    api_port=$((base_port + 100 + index - 1))
    db_port=$((base_port + 200 + index - 1))
    if [ "$index" -eq 1 ]; then
        join_args=""
    else
        join_args="--join 127.0.0.1:$((base_port + 200))"
    fi
    # Do not pass the removed dqlite disk-mode option. Current dqlite keeps its
    # SQLite image in memory while persisting Raft state and snapshots; those
    # are the durability mechanism being compared with Zaxonlite's Paxos log.
    # shellcheck disable=SC2086
    "$dqlite_demo" --api "127.0.0.1:$api_port" \
        --db "127.0.0.1:$db_port" --dir "$run_dir/dqlite-$index" \
        $join_args >"$run_dir/dqlite-$index.log" 2>&1 &
    pids="$pids $!"
}

start_zaxon 1
start_zaxon 2
start_zaxon 3
wait_port 127.0.0.1 "$base_port"

start_dqlite 1
wait_port 127.0.0.1 "$((base_port + 100))"
start_dqlite 2
start_dqlite 3
wait_port 127.0.0.1 "$((base_port + 101))"
wait_port 127.0.0.1 "$((base_port + 102))"

common_args="--operations $operations --warmup $warmup --payload-bytes $payload_bytes"
zaxon_addresses="127.0.0.1:$base_port,127.0.0.1:$((base_port + 1)),127.0.0.1:$((base_port + 2))"
# shellcheck disable=SC2086
"$python_bin" "$script_dir/driver.py" zaxonlite "$zaxon_addresses" \
    $common_args --tls-cert "$run_dir/client.crt" \
    --tls-key "$run_dir/client.key" --tls-ca "$run_dir/ca.crt" \
    >"$run_dir/zaxon.json"
# shellcheck disable=SC2086
"$python_bin" "$script_dir/driver.py" dqlite \
    "127.0.0.1:$((base_port + 100))" $common_args >"$run_dir/dqlite.json"

"$python_bin" - "$run_dir/zaxon.json" "$run_dir/dqlite.json" <<'PY'
import json, platform, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    zaxon = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    dqlite = json.load(stream)
print(json.dumps({
    "format": 1,
    "host": platform.platform(),
    "rules": {
        "nodes": 3,
        "durability": "persistent quorum state and node directories",
        "client": "one sequential persistent connection",
        "transaction": "one row per autocommit",
        "warmup_excluded": True,
        "verification": True,
    },
    "pins": {
        "libdqlite": "v1.18.7 (91e3e2f90874e4ec3b45cde965f266342846531b)",
        "go_dqlite": "v3.0.4 (d046c957251f7c77565d878eab950de4ff3bba5b)",
    },
    "results": [zaxon, dqlite],
}, indent=2, sort_keys=True))
PY
