# Three-node product comparisons

These end-to-end harnesses use one sequential persistent client, one-row
autocommit writes, identical payload sizes, excluded warmup, persistent node
directories, and post-run verification. They do not claim identical front-end
overhead: Zaxonlite uses its framed RPC while rqlite uses HTTP and dqlite uses
its demo API. They are product comparisons, not consensus-only
microbenchmarks.

## rqlite using the installed tools

`compare-rqlite-3node.sh` starts three Zaxonlite data voters and three rqlite
voters. By default it resolves the system-installed `rqlited` and `rqlite`
binaries from `PATH`, records both paths and versions, uses the CLI's `.nodes`
command to prove that all three members are reachable voters, and uses the CLI
again for final row verification. The timed load uses the common Python driver
so both products produce the same p50/p95/p99/max and throughput JSON contract.
`rqbench` is deliberately not the headline load generator because it does not
provide that matching percentile and verification contract.

Writes go to the initial leader, use no queued-write batching, and wait for
ordinary consensus acknowledgement. Verification uses a linearizable Zaxonlite
query and a rqlite `level=strong` query, checking both the measured row count
and exact payload predicate. The benchmark validates live acknowledged state;
the products' separate restart/crash tests remain the recovery evidence.

Run it on macOS or Linux:

```sh
cd zaxonlite
zig build -Doptimize=ReleaseFast
benchmarks/compare-rqlite-3node.sh > rqlite-comparison.json
```

The 20 July 2026 development run used Homebrew rqlite v10.2.7 / SQLite 3.53.2
on Darwin arm64. It is a single-host observation, not a portable performance
claim; rerun the harness on target hardware before making a capacity decision.
The raw finalized run is
[`results/rqlite-v10.2.7-darwin-arm64-2026-07-20.json`](results/rqlite-v10.2.7-darwin-arm64-2026-07-20.json).

## Real-world failure and recovery simulation

`compare-rqlite-realworld-3node.py` runs each product in isolation with three
voters and the same deterministic order-processing workload. It creates 1,000
customers and 500 products, then drives four clients across all endpoints with
70% linearizable reads and 30% retry-safe order writes. Each order atomically
fans out through SQLite triggers to an order line, an inventory decrement, and
an accounting-ledger entry.

The measured schedule contains 400 healthy operations, 400 operations after an
abrupt follower crash, and 400 operations immediately after an abrupt leader
crash. The controller restarts and locally verifies each crashed node, then
crashes all three members, restarts the same identities and directories, and
verifies every copy again. It checks order/line/ledger counts, unique operation
IDs, inventory units, revenue, nonnegative stock, and SQLite integrity.
Zaxonlite additionally checks its chain and payload store. rqlite membership is
confirmed through the installed CLI.

rqlite uses `linearizable`, not its deliberately expensive `strong`, for
measured reads. `strong` is used only as a final verification barrier. Writes
use a unique operation ID plus `insert or ignore`, making retry after an
ambiguous leader crash safe on both products.

```sh
cd zaxonlite
zig build -Doptimize=ReleaseFast
python3 benchmarks/compare-rqlite-realworld-3node.py \
  > realworld-comparison.json
```

Tune with `--phase-operations`, `--warmup-operations`, `--concurrency`,
`--seed`, and the binary-path options shown by `--help`. Set `KEEP_RUN_DIR=1`
or pass `--keep-run-dir` to retain every node directory and process log.
The recorded full result is
[`results/realworld-rqlite-v10.2.7-darwin-arm64-2026-07-20.json`](results/realworld-rqlite-v10.2.7-darwin-arm64-2026-07-20.json).
The consecutive validation run is retained as
[`results/realworld-rqlite-v10.2.7-darwin-arm64-2026-07-20-repeat-summary.json`](results/realworld-rqlite-v10.2.7-darwin-arm64-2026-07-20-repeat-summary.json).

## dqlite (deferred execution)

This harness compares three Zaxonlite data voters with three dqlite voters.
Its execution remains deferred until a supported Linux host has the pinned
dqlite fixture; the harness itself remains available.

“Persistent” means each product retains the quorum state needed to recover
acknowledged writes in per-node directories. Current dqlite intentionally uses
an in-memory SQLite materialization backed by durable Raft state and snapshots;
its removed `--disk` mode must not be enabled. Zaxonlite uses a reproducible
SQLite image backed by its durable Paxos journal. This is a durability-matched
comparison, not a claim that the storage engines are identical.

The reference versions are libdqlite `v1.18.7`
(`91e3e2f90874e4ec3b45cde965f266342846531b`) and go-dqlite `v3.0.4`
(`d046c957251f7c77565d878eab950de4ff3bba5b`). Upstream dqlite requires Linux.
The harness verifies every measured dqlite key and the complete measured
Zaxonlite row count after timing.
Build `dqlite-demo` from that go-dqlite revision against the pinned libdqlite,
then run:

```sh
cd zaxonlite
zig build -Doptimize=ReleaseFast
DQLITE_DEMO=/path/to/dqlite-demo \
  benchmarks/compare-dqlite-3node.sh > comparison.json
```

Tune only through recorded environment variables: `OPERATIONS`, `WARMUP`,
`PAYLOAD_BYTES`, `BASE_PORT`, `ZAXON_BIN`, `RQLITED_BIN`, `RQLITE_CLI`,
`DQLITE_DEMO`, and `PYTHON`. Failed runs preserve their generated directories
and logs; `KEEP_RUN_DIR=1` also preserves a successful run.
