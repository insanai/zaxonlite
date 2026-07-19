# zaxonlite

An embeddable SQLite service replicated by the [paxos-zig](..) Multi-Paxos
library. Link one Zig library (or the C ABI), open one data directory, and
get a durable SQL store — as a single node today and as a three-voter TCP
cluster with the same API and the same on-disk layout. The companion CLI
is `zaxon`.

Product plan and safety argument:
[`../docs/zaxonlite-product-plan.typ`](../docs/zaxonlite-product-plan.typ).
The full book (architecture, formats, operations, verification):
`zig build book-zaxonlite` at the repository root →
`docs/zaxonlite/zaxonlite.pdf`.

## What is implemented

- **WAL frame replication, not SQL replay.** The leader executes each
  transaction once; `sqlite3_wal_hook` plus direct `-wal` reads capture
  exactly the committed frames, and consensus decides the page images.
  Nondeterministic SQL is safe by construction; replicas converge to
  byte-identical files (verified by digest across cluster members).
- **Journal is authoritative.** Every protocol write is framed,
  checksummed, appended, and fsynced before `confirmWritesDurable()`; a
  write is acknowledged only after its slot commits *and* carries the
  client's own batch. The SQLite image is materialized state: delete
  `current.db` and the node rebuilds it from snapshot plus suffix.
- **Three voters over TCP.** `zaxon serve` runs peer handshake with
  identity/epoch checks, payload-before-vote gating on ordered streams,
  follower offline apply, leadership-change image resync, in-epoch
  catch-up, and cross-epoch snapshot transfer with digest-verified
  install.
- **Exactly-once sessions.** Session state rides inside the captured
  transaction; retries replay recorded results across restarts and
  leader failover. Idle sessions expire over a replicated activity
  window.
- **Read levels.** `any` (local, possibly stale, labeled), `leader`, and
  `linearizable` via a quorum read fence — ballot-equality probes with no
  log append and no disk sync per read.
- **Snapshots and epoch rollover.** Online checkpoints seal 256-slot
  epochs via decided stop signs; every member builds a byte-identical
  generation; rollover is crash-resumable; GC keeps bounded state.
- **Crash matrix automation.** Failpoints (`_exit` at chosen write-path
  points, armed via RPC in test mode) power a three-process scenario that
  kills the leader after quorum choice and proves exactly-once retry.
- **C ABI.** `libzaxonlite.a` + `include/zaxonlite.h` with a compiled C
  smoke test.

## Build and test

Requires Zig 0.16 and (for the book) Typst. SQLite 3.50.4 is a pinned
`build.zig.zon` dependency; the parent Paxos library is a path dependency.

```sh
cd zaxonlite
zig build test            # unit + single-process integration suites
zig build test-single     # durability integration tests only
zig build test-cluster    # 3-process scenario (-Dcluster-runs=N)
zig build test-cli        # CLI contract
zig build test-cabi       # C ABI smoke test
zig build fuzz            # seeded property fuzzing (-Dfuzz-iterations, -Dfuzz-seed)
zig build soak            # sustained mixed load (-Dsoak-seconds)
zig build benchmark       # ReleaseFast write/read/recovery benchmarks
zig build                 # produces zig-out/bin/zaxon and libzaxonlite.a
```

From the repository root: `zig build test-zaxonlite`, `zig build zaxon`,
`zig build book-zaxonlite`.

## Library

```zig
const zaxonlite = @import("zaxonlite");

var node = try zaxonlite.Node.open(gpa, io, .{ .directory = "./data" });
defer node.close();

_ = try node.exec("create table items(id integer primary key, v text)");

const session = try node.openSession();
_ = try node.execIdempotent(session, 1, "insert into items(v) values ('tea')");

var rows = try node.query(gpa, "select id, v from items order by id");
defer rows.deinit();
```

C:

```c
#include <zaxonlite.h>
zaxonlite *db;
zaxonlite_open("./data", &db);
int64_t changes;
zaxonlite_exec(db, "insert into items(v) values ('tea')", &changes);
zaxonlite_close(db);
```

## CLI

Embedded mode (`--data`) or client mode (`--connect`, follows leader
redirects):

```sh
# one durable node behind TCP
zaxon serve --data ./d1 --node 1 --listen 127.0.0.1:9901

# three voters
zaxon serve --data ./n1 --node 1 --listen 127.0.0.1:9901 \
    --peer 2@127.0.0.1:9902 --peer 3@127.0.0.1:9903
# ... and symmetrically for nodes 2 and 3

zaxon wait   --connect 127.0.0.1:9901 --leader
zaxon exec   --connect 127.0.0.1:9901,127.0.0.1:9902 --sql "insert ..."
zaxon exec   --connect ... --session 1 --sequence 7 --sql "insert ..."
zaxon query  --connect ... --sql "select count(*) from t" --level linearizable
zaxon status --connect 127.0.0.1:9902 --json
zaxon snapshot --connect ...
zaxon integrity-check --data ./d1
zaxon backup --data ./d1 --to ./backup.db
```

Exit codes: `0` ok, `1` SQL/session error, `2` usage, `3` integrity
failure, `4` unavailable (locked, corrupt, or no reachable leader).

## Data directory layout

```text
data/
  LOCK                     # exclusive process lock
  identity                 # node/database IDs, current configuration
  paxos-<config>.log       # framed, checksummed protocol journal
  payloads/aa/<hash>       # immutable frame payloads by SHA-256
  snapshots/<config>/      # db image + manifest per sealed epoch
  CURRENT                  # installed snapshot pointer
  current.db               # materialized SQLite image (rebuildable)
```
