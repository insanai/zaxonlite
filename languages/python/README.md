# zxlite

zxlite is the Python driver for zaxonlite, an embeddable SQLite service
replicated by Multi-Paxos. It looks and feels like the standard library
sqlite3 module: you connect, you execute SQL with qmark parameters, you
fetch rows. Underneath, every committed write is one complete
replicated transaction recorded in the zaxonlite journal.

The package now covers three gates from ZDS 0010, and it is worth being
plain about what each one is:

- Gate A: local autocommit connections. Every statement is its own
  replicated transaction.
- Gate B: remote cluster connections and a Python-hosted server.
  Remote connections are autocommit-only by design.
- Gate C: local live transactions (isolation_level="DEFERRED",
  autocommit=False), savepoints, named parameters, and a SQLAlchemy
  dialect.

## Install

Release wheels support CPython 3.12 and newer on Linux x86-64, macOS
x86-64 and arm64, and Windows x86-64. Unix socket endpoints are
POSIX-only; Windows applications use local or clustered TCP endpoints.

Source builds compile the native extension against the zaxonlite
static library. You need Zig 0.16 on PATH, OpenSSL 3, and the zaxonlite
source tree (the build walks up from this directory to find it, also
accepts a sibling checkout named zaxonlite, or an explicit
ZAXONLITE_ROOT). Windows source builds set `ZXLITE_OPENSSL_PREFIX` to
an x64 MSVC-compatible static OpenSSL SDK, such as vcpkg's
`x64-windows-static` installation.

On Windows, protect data directories, TLS keys, and PSK provider files with
an owner-only NTFS ACL. The native library validates regular files and
rejects symlinks there, but Windows has no POSIX mode bits for its usual
owner/group/world permission check.

    cd languages/python
    uv sync

The development loop is uv run pytest, uv run ruff format, and
uv run ruff check. The three-process cluster test is marked slow and
runs with uv run pytest -m slow.

## Local connections

    import zxlite

    connection = zxlite.connect("./node-data")
    connection.execute("create table notes(id integer primary key, body text)")
    cursor = connection.execute(
        "insert into notes(body) values (?) returning id", ("hello",)
    )
    print(cursor.fetchone())   # (1,)

By default a local connection is Gate A: autocommit, commit() and
rollback() are no-ops, and BEGIN/COMMIT/SAVEPOINT inside SQL text are
rejected by the native guard.

### Live transactions (Gate C)

    db = zxlite.connect(
        "./node-data", isolation_level="DEFERRED", autocommit=False
    )
    db.execute("insert into notes(body) values (?)", ("draft",))
    print(db.in_transaction)          # True: implicit begin on first write
    print(db.execute("select count(*) from notes").fetchone())  # visible
    db.rollback()                     # nothing was replicated

The semantics follow sqlite3: the first write statement opens the
transaction, reads inside it observe uncommitted writes, commit()
replicates the whole transaction as one WAL transition and acknowledges
only after the decided slot is applied, and rollback() publishes
nothing. Closing with an open transaction rolls back. RETURNING and
lastrowid work inside transactions. Live transactions are restricted to
a single-member local node.

Named parameters work on local connections: pass a dict and use :name,
@name, or $name placeholders. SQLite resolves the names; the driver
never rewrites SQL.

## Hosting a server and connecting remotely (Gate B)

    from zxlite import Member, start_server

    with start_server(
        directory="/tmp/example-node",
        node_id=1,
        members=[Member(1, "unix:/tmp/example.sock")],
    ) as server:
        with zxlite.connect(server.endpoint) as db:
            db.execute("create table item(id integer primary key, v text)")

A single member with a unix:<absolute path> endpoint serves one local
node over an owner-only Unix socket (POSIX only; the server refuses a
pre-existing socket path and removes its own on shutdown). TCP clusters
take one identical member list per process plus per-node directories;
production TCP requires tls_ca, tls_cert, and tls_key together. The
development-only PSK mode (allow_psk_only_loopback=True plus an
auth_file) is restricted to numeric loopback addresses everywhere and
is never a production transport.

Remote connections accept DSNs:

    db = zxlite.connect(
        "zxlite://db1:9901,db2:9901,db3:9901/?read_level=linearizable",
        tls_ca=..., tls_cert=..., tls_key=...,
    )

Options: read_level (any, leader, linearizable), read_policy,
freshness_ms (only with any), pool_size (1..64), connect_timeout_ms,
operation_timeout_ms, expected_database_id. The repeated
zxlite:///?seed=... form exists for SQLAlchemy URLs. Invalid DSNs are
rejected before any network activity.

Remote semantics, stated honestly:

- Autocommit only. Writes travel one native write lane with a
  replicated session and monotonic sequences, so a retried write
  applies exactly once even across leader changes.
- If a write's fate is unknown at the operation deadline, further
  writes fail with a "write pending" OperationalError until
  Connection.resolve_pending() reaches a definitive outcome.
- Reads run on a bounded pool of independent connections at your
  chosen consistency level; connection.query(sql, params,
  read_level=..., freshness_ms=...) overrides per call.
- RETURNING, executescript(), and named parameters are not supported
  remotely. Typed search and raw FTS5 search SQL both use the remote
  read pool at the requested consistency level.
- executemany() travels as one typed batch, one replicated
  transaction, and one session sequence: every row applies or none
  does, exactly like a local batch.
- Fresh writes report lastrowid; a replayed (retried) write carries
  only its change count.
- connect() probes one seed eagerly (bounded by connect_timeout_ms),
  so a dead or identity-mismatched endpoint fails at connect time; a
  database identity mismatch raises InterfaceError.
- The connect() timeout parameter bounds write admission to the
  native write lane, with the same "write_queue_timeout" category and
  the same guarantee as local connections: on expiry the statement
  never left the process and a plain retry is safe.

## SQLAlchemy (Gate C)

Install the extra: zxlite[sqlalchemy] (SQLAlchemy 2.0/2.1).

    from sqlalchemy import create_engine

    engine = create_engine("zxlite:////var/lib/zxlite/data")

Local engines default to Gate C transactional connections on a
NullPool: one checked-out connection owns the zaxonlite directory
lock, and a second concurrent open raises OperationalError rather than
pretending to be a second SQLite file connection. create_all,
reflection, Core CRUD, bound parameters, autoincrement keys,
RETURNING, ORM unit of work, rollback, and nested (savepoint)
transactions are covered by tests.

Remote engines use the seed= URL form, require
isolation_level="AUTOCOMMIT", and default to StaticPool:

    engine = create_engine(
        "zxlite:///?seed=db1%3A9901&seed=db2%3A9901",
        connect_args={"tls_ca": ..., "tls_cert": ..., "tls_key": ...},
        isolation_level="AUTOCOMMIT",
    )

## How writes queue

sqlite3 exposes SQLite file-lock contention: a second writer gets
"database is locked" and every application writes its own retry loop.
zxlite behaves like a server database instead. Every local connection
has one ordered write lane; concurrent writers wait in arrival order
and each receives its own result. The connect() timeout parameter
bounds how long a write waits for its turn on that lane, not a file
lock. If the wait expires you get OperationalError with category
"write_queue_timeout", the statement provably never executed, and a
plain retry is safe. No zxlite error ever says "database is locked"
because another zxlite write was ahead of you. Remote connections
queue on the native pool's ordered write lane with the same contract
and the same error category.

By default a local connection may only be used from the thread that
created it (check_same_thread=True, like sqlite3); remote connections
default to check_same_thread=False and are thread-safe.

## Beyond the DB-API

Local Connection carries the zaxonlite-specific surface: snapshot(),
backup(path), integrity_check(), open_session() /
execute_idempotent(session, sequence, sql) for exactly-once retry,
expire_sessions(retain), and typed search(...) per ZDS 0009 (lexical
FTS5, vector, or hybrid with rrf/dbsf fusion; embeddings are raw
little-endian float32 bytes). Remote Connection exposes the same typed
search with read_level and freshness_ms overrides, and adds
resolve_pending() and status_json().

## Semantics worth knowing

- execute() accepts exactly one statement; use executescript() for
  scripts (local only). The local check uses SQLite preparation
  metadata; the remote check uses a conservative scanner because the
  wire protocol carries one statement.
- rowcount is the change count for DML and -1 for reads. lastrowid
  updates only after a local INSERT or REPLACE.
- Type mapping is exactly sqlite3's: None, int, float, str, bytes in;
  NULL, INTEGER, REAL, TEXT, BLOB out. Integers must fit in signed
  64 bits or OverflowError is raised. Invalid UTF-8 in a TEXT result
  raises OperationalError.
- Mapped exceptions carry a stable .category string such as
  "constraint", "validation", or "write_queue_timeout".
- Operating failures use the repository's Elm-style boundary,
  explanation, and Hint format. SQL and programming errors retain
  sqlite-shaped wording; branch on .category rather than message text.

## Not supported

create_function, aggregates, collations, load_extension, ATTACH,
serialize/deserialize, blobopen, set_authorizer, trace callbacks,
interrupt, text_factory, adapters, and converters. See ZDS 0010 for
reasons; most are deliberate product boundaries, not omissions.

## License

MIT, same as zaxonlite.
