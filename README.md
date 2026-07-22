# zaxonlite

An embeddable SQLite service replicated by the [paxos-zig](..) Multi-Paxos
library. Link one Zig library (or the C ABI), open one data directory, and
get a durable SQL store as one node or a transport-owning cluster. The
`zaxon serve` reference host, Zig `Embedded` facade, and C cluster facade all
run the same Paxos/SQLite node and on-disk layout. The companion CLI is `zaxon`.

Product plan and safety argument:
[`../docs/zds/records/0002-zaxonlite-product-plan.typ`](../docs/zds/records/0002-zaxonlite-product-plan.typ).
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
  Rebuild always discards the working image and validates the snapshot digest;
  interrupted epoch rollover and snapshot installation are resumable.
- **Voters and learners over TCP.** One to nine configured voters run Paxos;
  an allocator-backed registry can also contain standbys and read replicas,
  which learn chosen entries without changing quorum size. `zaxon serve` runs
  peer handshake with mutual TLS 1.3 for production, canonical per-node identities,
  optional in-TLS PSK/HMAC, identity/epoch checks, ordered durable payload
  prestaging with a bounded missing-value gate (including Phase-1 recovery),
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
- **Snapshots and epoch rollover.** Online checkpoints seal 2,048-slot
  epochs via decided stop signs; every member builds a byte-identical
  generation; rollover is crash-resumable; GC keeps bounded state.
- **Crash matrix automation.** Failpoints (`_exit` at chosen write-path
  points, armed by environment or RPC in test mode) cover five real one-node
  process crashes; the cluster scenario kills the leader after quorum choice.
- **Prepared/explicit transactions.** Zig and C APIs bind null, integer, real,
  text, and BLOB values. A copied, bounded multi-call builder commits as one
  replicated SQLite transaction.
- **Operations.** Authenticated remote backup streams ordered chunks with an
  end-to-end digest. JSON configuration follows CLI > environment > file
  precedence; membership inspection and journal-authoritative recovery are CLI
  commands. Human failures use Elm-style boundary, explanation, and `Hint:`
  diagnostics; machine RPC failures retain stable JSON codes.
- **C ABI.** `libzaxonlite.a` + `include/zaxonlite.h` with a compiled smoke test.
- **Explicit node types.** `data-voter` proposes/votes/serves SQL; `witness`
  votes but cannot campaign or serve SQL; `standby` keeps a promotion-eligible
  SQLite copy; `read-replica` keeps a read copy; `gateway` is a stateless,
  end-to-end TCP router with no Paxos or SQLite state.
- **Bounded local reads.** A learner receives leader progress heartbeats;
  `--level any --freshness-ms N` refuses a local snapshot when leader contact
  is older than `N` or the reported decided slot is not yet applied.
- **Adverse schedules.** A real TCP test combines frame loss, semantic
  duplication, pair reordering, seven-byte fragmentation, and delayed journal
  sync. A separate role test drives voters, witness, and both learner types.
- **Fair comparison harnesses.** `benchmarks/compare-rqlite-3node.sh` uses the
  system-installed rqlite v10 tools and `compare-dqlite-3node.sh` retains the
  pinned Linux fixture. Both compare three durable voters per system with equal
  payloads, excluded warmup, verified results, persistent client connections,
  percentile latency, and JSON output.
- **Failure/recovery product simulation.** The deterministic order-processing
  harness runs four clients with linearizable reads and idempotent writes,
  crashes a follower and leader under traffic, catches each up, restarts the
  full three-node cluster, and proves inventory, revenue, ledger, uniqueness,
  per-node convergence, and integrity for Zaxonlite and installed rqlite.

Security boundary: protocol v6 requires mutual TLS 1.3 for every production TCP
listener. Peer certificate common names bind configured node IDs and TLS
encrypts SQL, results, payloads, and snapshots. The optional provider-file PSK
adds sequenced HMAC protection inside TLS. For a one-machine quickstart,
`--dev-psk` explicitly permits PSK-only TCP only when the listener and every
peer are numeric loopback; it has no confidentiality or unique node identity.
Plaintext TCP remains failpoint-gated. Local single-node service uses an
owner-only Unix-domain socket. An authenticated operator can
ask a deliberately configured issuer for a short-lived, single-use bundle;
`zaxon enroll` generates the node's P-256 key and CSR locally and atomically
installs the returned certificate. Static membership remains the transport
authorization boundary. Database, WAL, journal, snapshot, and backup files are
plaintext; deployments that need protection from offline media access use OS
full-disk or filesystem encryption.

Current limits: one logical writer, one to nine statically configured voters,
runtime-sized non-voting nodes, no automatic voter replacement, and a maximum
transaction payload of 64 MiB minus authenticated framing. The current
durability path is POSIX-only because it requires parent-directory `fsync`;
Windows returns an unsupported-durability error rather than weakening the
guarantee. The exhaustive
10,000-crash/100-run stress gates and 1 GiB recovery target are explicitly
deferred; the checked recovery fixture is 1 MiB.

## Build and test

Requires Zig 0.16, system OpenSSL 3, and (for the book) Typst. SQLite 3.50.4
is a pinned `build.zig.zon` dependency; the parent Paxos library is a path
dependency. Cross-builds pass `-Dopenssl-prefix` for the target OpenSSL SDK.

```sh
cd zaxonlite
zig build test            # unit + single-process integration suites
zig build test-single     # durability integration tests only
zig build test-crash      # spawned-process crash matrix
zig build test-cluster    # 3-process scenario (-Dcluster-runs=N)
zig build test-roles      # voters, witness, standby, read replica
zig build test-gateway    # stateless end-to-end gateway
zig build test-fault-network # loss/duplicate/reorder/partial/slow sync
zig build test-cli        # CLI contract
zig build test-cabi       # C ABI smoke test
zig build fuzz            # seeded property fuzzing (-Dfuzz-iterations, -Dfuzz-seed)
zig build soak            # sustained mixed load (-Dsoak-seconds)
zig build benchmark       # ReleaseFast write/read/recovery benchmarks
zig build                 # produces zig-out/bin/zaxon and libzaxonlite.a
```

From the repository root: `zig build test-zaxonlite`, `zig build zaxon`,
`zig build book-zaxonlite`.

API documentation: `zig build docs` (in this directory) writes the generated
reference to `zig-out/docs/api`; because the output is a WASM application that
browsers refuse to load from `file://`, use `zig build docs-serve` and open
<http://localhost:8000>.

The rqlite comparisons run with installed `rqlited` and `rqlite` binaries. The
dqlite execution is deferred and remains Linux-only. See
[`benchmarks/README.md`](benchmarks/README.md) for exact commands and limits.

Remote role-aware local read:

```sh
zaxon query --connect 127.0.0.1:9904 --sql 'select * from items' \
  --level any --freshness-ms 2000 --tls-cert client.crt \
  --tls-key client.key --tls-ca ca.crt
```

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

var transaction = zaxonlite.Transaction.init(gpa);
defer transaction.deinit();
try transaction.exec("insert into items(v) values (?1)", &.{.{ .text = "tea" }});
_ = try node.execTransaction(&transaction);
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
# one durable local node, authorized by owner-only socket permissions
zaxon serve --data ./d1 --node 1 --listen unix:./zaxon.sock

# quickstart-only three-voter transport (repeat symmetrically for n2/n3)
openssl rand -hex 32 > demo.psk && chmod 600 demo.psk
zaxon serve --data ./n1 --node 1 --listen 127.0.0.1:9901 \
    --peer 2@127.0.0.1:9902 --peer 3@127.0.0.1:9903 \
    --auth-file ./demo.psk --dev-psk

# three voters (repeat with n2/n3 identities on the other members)
zaxon serve --data ./n1 --node 1 --listen 127.0.0.1:9901 \
    --peer 2@127.0.0.1:9902/data-voter \
    --peer 3@127.0.0.1:9903/data-voter \
    --tls-cert n1.crt --tls-key n1.key --tls-ca ca.crt
# ... and symmetrically for nodes 2 and 3

# add a non-voting read replica to every node's bootstrap registry
zaxon serve --data ./r4 --node 4 --role read-replica \
    --listen 127.0.0.1:9904 \
    --peer 1@127.0.0.1:9901/data-voter \
    --peer 2@127.0.0.1:9902/data-voter \
    --peer 3@127.0.0.1:9903/data-voter \
    --tls-cert n4.crt --tls-key n4.key --tls-ca ca.crt

# Every client TCP command likewise supplies its client identity:
#   --tls-cert client.crt --tls-key client.key --tls-ca ca.crt

zaxon wait   --connect 127.0.0.1:9901 --leader
zaxon exec   --connect 127.0.0.1:9901,127.0.0.1:9902 --sql "insert ..."
zaxon exec   --connect ... --session 1 --sequence 7 --sql "insert ..."
zaxon query  --connect ... --sql "select count(*) from t" --level linearizable
zaxon status --connect 127.0.0.1:9902 --json
zaxon snapshot --connect ...
zaxon integrity-check --data ./d1
zaxon backup --data ./d1 --to ./backup.db
zaxon backup --connect ... --tls-cert client.crt --tls-key client.key \
    --tls-ca ca.crt --to ./backup.db
zaxon members --connect ...
zaxon recover --data ./d1
```

See [`../docs/zds/records/0004-zaxonlite-format.typ`](../docs/zds/records/0004-zaxonlite-format.typ) for the
wire/disk compatibility policy and upgrade procedure.

`zaxon sql` opens the interactive shell (embedded or client mode). On a
terminal it is a rich REPL — readline-style editing, arrow-key history with
`ctrl+r` search, SQL keyword highlighting, aligned tables with an expanded
mode and a pager, `.help` for the command list — built on the
[libvaxis](https://github.com/rockorager/libvaxis) terminal layer per
[ZDS 0005](../docs/zds/records/0005-zaxon-interactive-shell.typ). Piped or
scripted invocations keep the historical plain line-reader output
byte-for-byte.

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
