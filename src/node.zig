//! The embedded zaxonlite node host.
//!
//! One node owns one data directory: a framed protocol journal, a
//! content-addressed payload store, snapshots, and a materialized SQLite
//! image. The journal plus payloads are authoritative; the SQLite file is
//! reconstructed from snapshot plus committed journal suffix on every open.
//!
//! Ordering contract per write:
//!   execute -> capture frames -> persist payload -> Paxos append ->
//!   journal + required sync -> confirmWritesDurable -> committed -> acknowledge.
//! The payload install flushes to the drive; the journal fsync is the one
//! storage barrier per write and makes both power-loss durable together
//! (see durability.zig on group fsync).
//! Promise and accept records require that barrier. A later commit-only
//! marker is reconstructible from the durable accepting quorum, so Zaxonlite
//! does not duplicate it in the authoritative journal. This matches classic
//! Paxos: a restart re-learns the chosen value from the accepting quorum.
//!
//! Cluster shape: the same node type serves one-member and multi-member
//! configurations. Only the current leader keeps a live SQLite writer
//! connection (the capture connection); every other member applies
//! committed payloads offline, page by page, to the materialized image.
//! Protocol messages addressed to peers accumulate in `outbox`; the
//! transport host (`server.zig`) drains it after every protocol call.  The
//! sole pipelined exception is a phase-two `accept` request: it may leave
//! after the journal append while the leader's barrier is in progress,
//! because it asks a follower to persist a vote and asserts no durable fact
//! about the leader.  Promise evidence, vote acknowledgements, commits, and
//! client replies still remain behind the local barrier.

const std = @import("std");
const Io = std.Io;
const paxos = @import("paxos");

const command = @import("command.zig");
const types = @import("types.zig");
const journal_mod = @import("journal.zig");
const payload_store_mod = @import("payload_store.zig");
const checkpoint_proof = @import("checkpoint_proof.zig");
const sqlite = @import("sqlite.zig");
const search_api = @import("search_api.zig");
const zaxon_search = @import("zaxon_search");
const guard_mod = @import("guard.zig");
const wal = @import("wal.zig");
const failpoint = @import("failpoint.zig");
const durability = @import("durability.zig");
const prepared = @import("prepared.zig");
const registry = @import("registry.zig");
const roles = @import("roles.zig");

const Journal = journal_mod.Journal;
const PayloadStore = payload_store_mod.PayloadStore;
const Log = types.Log;

const db_file_name = "current.db";
const wal_file_name = "current.db-wal";
const shm_file_name = "current.db-shm";
const identity_file_name = "identity";
const current_file_name = "CURRENT";
const lock_file_name = "LOCK";
const pending_operation_file_name = "PENDING-OP";
const deleted_file_tombstone = ".ZX-DELETED";
const join_file_name = "JOIN";
const install_tmp_dir = "snapshots/tmp-install";

/// Reserve slots so a checkpoint stop sign always fits in the epoch.
const capacity_reserve = 4;

pub const OpenOptions = struct {
    /// Node data directory; created when missing.
    directory: []const u8,
    node_id: paxos.NodeId = 1,
    /// Full voting membership including this node. Empty means a
    /// single-member configuration of just `node_id`. Order does not
    /// matter; membership is canonicalized to ascending node IDs.
    members: []const paxos.NodeId = &.{},
    /// Election priority carried in this node's ballots.
    leader_priority: u32 = 0,
    /// Database identity for a freshly created directory. Cluster members
    /// must agree on it; `null` draws a random one (single-node default).
    database_id: ?u128 = null,
    /// Product role. Only data voters and witnesses appear in `members`.
    role: roles.Role = .data_voter,
    /// Full product registry (IDs, roles, endpoints) for a network-hosted
    /// cluster. Non-null bootstraps and then enforces the durable decided
    /// registry; null (embedded and local hosts) keeps membership fixed by
    /// flags and writes no registry file.
    registry_nodes: ?[]const registry.NodeRecord = null,
    /// Test-only delay injected immediately before each journal sync.
    test_storage_delay_ms: u64 = 0,
    /// SQLite-managed mapped-I/O limit for every connection this node
    /// opens. Zero (the default) disables mmap; a nonzero value is an
    /// explicit operator opt-in bounded at 1 GiB (ZDS 0009).
    mmap_size: u64 = 0,
};

pub const SessionError = error{
    UnknownSession,
    SequenceGap,
    ResultExpired,
};

pub const ExecResult = struct {
    changes: i64,
    slot: paxos.Slot,
    replayed: bool = false,
    /// Set when the caller's statements observably updated SQLite's last
    /// insert rowid; absent for updates, deletes, DDL, and replays.
    last_insert_rowid: ?i64 = null,
};

pub const Status = struct {
    node_id: paxos.NodeId,
    database_id: u128,
    configuration_id: u64,
    role: []const u8,
    node_type: []const u8,
    leader: ?paxos.NodeId,
    ballot: paxos.Ballot,
    decided_slot: paxos.Slot,
    applied_slot: paxos.Slot,
    journal_records: u64,
    epoch_capacity: u64,
    chain: command.HashBytes,
    page_size: u32,
    snapshot: ?[16]u8,
    /// Search capability manifest (ZDS 0009).
    fts5_enabled: bool,
    sqlite_vec_version: []const u8,
    search_feature_version: i64,
    simd_backend: []const u8,
    /// The mapped-I/O limit SQLite accepted on the most recent
    /// connection; zero when mmap is disabled or unsupported.
    mmap_size: i64,
    candidate_hard_limit: u32,
};

/// Hard ceiling for vector KNN candidate counts (ZDS 0009). The typed
/// search API enforces it; raw SQL treats it as a documented contract
/// backed by the query row, byte, and VM-step budgets.
pub const candidate_hard_limit: u32 = search_api.candidate_hard_limit;

pub const IntegrityReport = struct {
    sqlite_ok: bool,
    chain_ok: bool,
    payloads_ok: bool,

    pub fn ok(self: IntegrityReport) bool {
        return self.sqlite_ok and self.chain_ok and self.payloads_ok;
    }
};

const Identity = struct {
    node_id: paxos.NodeId,
    database_id: u128,
    configuration_id: u64,
    role: roles.Role,
};

pub const QueryResult = struct {
    arena: std.heap.ArenaAllocator,
    columns: []const []const u8,
    rows: []const []const ?[]const u8,

    pub fn deinit(self: *QueryResult) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Typed query result: one tagged SQLite value per cell. This is the
/// source form; the text `QueryResult` and every JSON encoding are
/// presentation adapters derived from it.
pub const TypedResult = struct {
    arena: std.heap.ArenaAllocator,
    columns: []const []const u8,
    rows: []const []const prepared.Value,

    pub fn deinit(self: *TypedResult) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Optional write-result capture: typed `RETURNING` rows and the last
/// insert rowid observed for the caller's statements.
pub const WriteCapture = struct {
    gpa: std.mem.Allocator,
    returning: ?TypedResult = null,
    last_insert_rowid: ?i64 = null,
};

/// Prepared-statement facts a host needs before executing: parameter
/// count, result shape, read-only classification, and whether the input
/// holds a trailing second statement.
pub const StatementInfo = struct {
    parameter_count: u32,
    column_count: u32,
    read_only: bool,
    has_tail: bool,
};

/// Optional result and SQLite VM budgets. Zero means unlimited, which remains
/// the default for trusted embedded callers. Network hosts pass conservative
/// non-zero limits so one query cannot monopolize memory or CPU indefinitely.
pub const QueryLimits = struct {
    max_rows: usize = 0,
    max_bytes: usize = 0,
    max_vm_steps: u64 = 0,
};

const QueryProgress = struct {
    callbacks_remaining: u64,
};

fn queryProgress(context: ?*anyopaque) callconv(.c) c_int {
    const progress: *QueryProgress = @ptrCast(@alignCast(context.?));
    if (progress.callbacks_remaining == 0) return 1;
    progress.callbacks_remaining -= 1;
    return 0;
}

/// Host callback used to release protocol-core messages explicitly
/// classified as safe before the current journal barrier.  The callback is
/// optional so the embedded storage node remains transport-independent.
pub const PreDurableOutboxHook = struct {
    context: *anyopaque,
    run: *const fn (context: *anyopaque) anyerror!void,
};

pub const Node = struct {
    gpa: std.mem.Allocator,
    io: Io,
    dir: Io.Dir,
    lock_file: Io.File,
    identity: Identity,
    store: PayloadStore,
    journal: Journal,
    log: *Log.Node,
    effects: *Log.Effects,
    inbox: []Log.Envelope,
    /// Envelopes addressed to peers. Most are appended after the backing
    /// journal writes are durable; phase-two accepts may be appended during
    /// the barrier and released through `pre_durable_outbox_hook`.
    outbox: std.ArrayList(Log.Envelope) = .empty,
    pre_durable_outbox_hook: ?PreDurableOutboxHook = null,
    db: sqlite.Db,
    db_path: [:0]u8,
    /// True while the live SQLite writer (capture) connection is open.
    db_open: bool = false,
    /// Authorizer state for the live connection. Application statements
    /// are screened; zaxonlite's own statements run in internal scope.
    guard: guard_mod.Guard = .{},
    /// True when this node was opened as a one-member configuration.
    single: bool,
    product_role: roles.Role,
    capabilities: roles.Capabilities,
    /// The durable decided registry, present on network-hosted nodes. It
    /// is the single membership authority after bootstrap.
    decided_registry: ?registry.Decided = null,
    /// One-shot enrollment binding retained until the fetched registry is
    /// verified and installed.
    join_descriptor: ?JoinDescriptor = null,
    members: [types.log_options.max_members]paxos.NodeId,
    member_count: u16,
    leader_priority: u32,
    committed_frames: u32 = 0,
    captured_frames: u32 = 0,
    page_size: u32 = 4096,
    applied_slot: paxos.Slot = 0,
    last_chain: command.HashBytes,
    last_data_slot: paxos.Slot = 0,
    /// Batch identity of the write currently captured in the live WAL but
    /// not yet decided. Any other decision while this is set means the
    /// live image speculated wrongly and must be resynced.
    capture_batch_id: ?u128 = null,
    /// Set when the live image no longer matches the decided log; the
    /// host must call `resyncImage` before serving.
    needs_resync: bool = false,
    /// Result of the most recent local append (see `lastAppend`).
    last_append: ExecResult = .{ .changes = 0, .slot = 0 },
    /// Set when a decided stop sign awaits epoch rollover. The slot the
    /// stop sign occupies comes from the log's own latch (`Log.stopSlot`).
    rollover_pending: bool = false,
    /// The server defers a new-epoch campaign until its transport generation
    /// matches the decided registry. Embedded hosts activate immediately.
    rollover_campaign_pending: bool = false,
    /// Copy of the SQLite error message from a failed write transaction,
    /// captured before the rollback statement clears it.
    saved_error: [512]u8 = undefined,
    saved_error_len: usize = 0,
    /// Extended SQLite result code captured with `saved_error`.
    saved_error_code: i32 = 0,
    /// Gate C (ZDS 0010): true while a caller holds a live SQLite
    /// transaction on the writer connection. Single-member nodes only.
    live_transaction: bool = false,
    /// Total-change baseline recorded at `beginLive`.
    live_changes_base: i64 = 0,
    /// Batch identity reserved at `beginLive` and replicated at commit.
    live_batch_id_bytes: [16]u8 = undefined,
    /// Set after a journal/payload durability failure. A cluster host must
    /// stop voting and serving; continuing after a failed fsync would violate
    /// the effects contract.
    fatal_storage_error: bool = false,
    test_storage_delay_ms: u64 = 0,
    /// Operator-selected mapped-I/O limit applied to every connection.
    mmap_size: u64 = 0,
    /// The limit SQLite actually accepted on the most recent connection.
    effective_mmap_size: i64 = 0,
    /// Recorded search-feature version of the served image; zero means
    /// the image predates the search feature.
    search_feature_version: i64 = 0,
    /// Cached `vec_version()` of the statically linked sqlite-vec.
    sqlite_vec_version_buffer: [32]u8 = undefined,
    sqlite_vec_version_len: usize = 0,

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    pub fn open(gpa: std.mem.Allocator, io: Io, options: OpenOptions) !*Node {
        const self = try gpa.create(Node);
        errdefer gpa.destroy(self);

        const capabilities = options.role.capabilities();
        if (!capabilities.stores_log) return error.RoleHasNoLocalStore;
        var member_storage: [types.log_options.max_members]paxos.NodeId = undefined;
        var members = try canonicalFlagMembers(&options, capabilities, &member_storage);
        // Iterating opens carry a real descriptor on every platform; a
        // non-iterating open is `O_PATH` on Linux, which `fchmod` and
        // `fsync` reject. This handle is chmodded here and synced on
        // every storage barrier.
        var dir = try Io.Dir.cwd().createDirPathOpen(io, options.directory, .{
            .permissions = @enumFromInt(0o700),
            .open_options = .{ .iterate = true },
        });
        errdefer dir.close(io);
        try dir.setPermissions(io, @enumFromInt(0o700));

        // One process per data directory.
        const lock_file = try dir.createFile(io, lock_file_name, .{
            .read = true,
            .truncate = false,
        });
        errdefer lock_file.close(io);
        if (!try lock_file.tryLock(io, .exclusive)) return error.NodeLocked;

        // Under the lock, so the probe's scratch names cannot race another
        // process, and before any storage exists to be made durable.
        try durability.probePathnameSemantics(io, dir);

        // The durable decided registry is authoritative once it exists.
        // Loading fails closed: a present but unreadable registry stops the
        // open instead of falling back to flags or re-derivation.
        var decided_registry = try registry.load(io, dir, gpa);

        // An enrolled replacement carries a join descriptor: the decided
        // database identity it must adopt instead of deriving one from its
        // flags, and the registry digest it will fetch and verify.
        var join = try readJoinDescriptor(gpa, io, dir);

        // The database identity derived from bootstrap flags applies only
        // while no registry exists; afterwards the decided registry carries
        // it, so changed flags cannot re-derive a new database.
        const expected_database_id: ?u128 = if (decided_registry) |*decided|
            decided.database_id
        else if (join) |descriptor|
            descriptor.database_id
        else
            options.database_id;

        const identity = try loadOrCreateIdentity(
            gpa,
            io,
            dir,
            options.node_id,
            expected_database_id,
            options.role,
        );

        if (decided_registry) |*decided| {
            if (decided.database_id != identity.database_id) {
                return error.RegistryMismatch;
            }
            if (join) |descriptor| {
                if (descriptor.database_id != decided.database_id or
                    descriptor.configuration_id != decided.configuration_id or
                    !std.mem.eql(u8, &descriptor.registry_digest, &decided.digest()))
                {
                    return error.RegistryMismatch;
                }
                try durableDeleteFile(io, dir, join_file_name);
                join = null;
            }
            members = decided.voterIds(&member_storage);
        } else if (join != null) {
            // A joining replacement must not invent a registry: it fetches
            // and verifies the decided one during snapshot install.
        } else if (options.registry_nodes) |records| {
            // First boot of a network-hosted node: persist the bootstrap
            // registry. The pointer write commits it; a crash in between
            // simply re-runs this idempotent bootstrap.
            const bootstrapped = try registry.Decided.bootstrapAt(
                identity.database_id,
                identity.configuration_id,
                records,
            );
            try registry.storeBlob(io, dir, &bootstrapped);
            try registry.activatePointer(io, dir, bootstrapped.configuration_id);
            decided_registry = bootstrapped;
            members = bootstrapped.voterIds(&member_storage);
        }

        var found_self = false;
        for (members) |member| {
            if (member == options.node_id) found_self = true;
        }
        if (found_self != capabilities.votes) return error.RoleMembershipMismatch;
        const single = capabilities.votes and members.len == 1;

        var store = try PayloadStore.init(io, dir);
        errdefer store.deinit();

        const log = try gpa.create(Log.Node);
        errdefer gpa.destroy(log);
        const effects = try gpa.create(Log.Effects);
        errdefer gpa.destroy(effects);
        effects.init();
        const inbox = try gpa.alloc(Log.Envelope, effects.messages.len);
        errdefer gpa.free(inbox);

        const db_path = try std.fmt.allocPrintSentinel(
            gpa,
            "{s}/{s}",
            .{ options.directory, db_file_name },
            0,
        );
        errdefer gpa.free(db_path);

        self.* = .{
            .gpa = gpa,
            .io = io,
            .dir = dir,
            .lock_file = lock_file,
            .identity = identity,
            .store = store,
            .journal = undefined,
            .log = log,
            .effects = effects,
            .inbox = inbox,
            .db = undefined,
            .db_path = db_path,
            .single = single,
            .product_role = options.role,
            .capabilities = capabilities,
            .decided_registry = decided_registry,
            .join_descriptor = join,
            .members = [_]paxos.NodeId{0} ** types.log_options.max_members,
            .member_count = @intCast(members.len),
            .leader_priority = options.leader_priority,
            .last_chain = command.genesisChain(identity.database_id),
            .test_storage_delay_ms = options.test_storage_delay_ms,
            .mmap_size = options.mmap_size,
        };
        @memcpy(self.members[0..members.len], members);

        // Restore or initialize the protocol node from the epoch journal.
        var membership: Log.Membership = undefined;
        try membership.init(members);
        const durable = try gpa.create(Log.DurableState);
        defer gpa.destroy(durable);
        durable.* = .{};

        var replay_info: journal_mod.ReplayInfo = undefined;
        if (Journal.open(
            io,
            gpa,
            dir,
            identity.configuration_id,
            durable,
            &replay_info,
        )) |opened| {
            self.journal = opened;
            if (capabilities.votes) {
                try self.log.restoreWithPriority(
                    identity.node_id,
                    identity.configuration_id,
                    &membership,
                    durable,
                    options.leader_priority,
                );
            } else {
                try self.log.restoreLearner(
                    identity.node_id,
                    identity.configuration_id,
                    &membership,
                    durable,
                );
            }
        } else |err| switch (err) {
            error.FileNotFound => {
                self.journal = try Journal.create(io, dir, identity.configuration_id);
                if (capabilities.votes) {
                    try self.log.initWithPriority(
                        identity.node_id,
                        identity.configuration_id,
                        &membership,
                        options.leader_priority,
                    );
                } else {
                    try self.log.initLearner(
                        identity.node_id,
                        identity.configuration_id,
                        &membership,
                    );
                }
            },
            else => return err,
        }
        errdefer self.journal.close();

        // Resume a snapshot transfer that durably installed CURRENT but
        // crashed before advancing identity. Equality is also possible: a
        // member can have reached the sealed epoch without learning its stop
        // sign. A normal checkpoint interruption has the stop sign and is
        // completed by the regular rollover path below.
        if (try self.currentSnapshotName()) |snapshot_name| {
            const sealed = try self.validateSnapshotGeneration(snapshot_name);
            if (sealed > self.identity.configuration_id or
                (sealed == self.identity.configuration_id and
                    self.log.isReconfigured() == null))
            {
                if (sealed == std.math.maxInt(u64)) return error.ConfigurationMismatch;
                try self.activateInstalledSnapshot(sealed + 1, &membership);
            } else if (!(sealed == self.identity.configuration_id and
                self.log.isReconfigured() != null))
            {
                if (sealed == std.math.maxInt(u64) or
                    sealed + 1 != self.identity.configuration_id)
                {
                    return error.ConfigurationMismatch;
                }
            }
        }

        self.log.core.setCampaignEnabled(capabilities.campaigns);
        if (single and capabilities.campaigns) {
            // Volatile leadership: campaign on every open. A one-member
            // quorum completes phase one immediately.
            try self.log.campaign(.noop, self.effects);
            try self.consumeEffectsRecovery();
        }

        // Materialize the image first: a pending rollover needs the fully
        // applied database to rebuild its snapshot generation.
        try self.rebuildMaterializedImage();

        // A decided stop sign from a previous run means the epoch rollover
        // never completed; finish it before serving.
        if (self.log.isReconfigured() != null) {
            try self.completeClusterRollover();
            try self.rebuildMaterializedImage();
        }
        try self.reconcilePendingOperation();

        if (single and capabilities.serves_writes) {
            try self.openLiveDatabase();
            try self.bootstrapSchema();
        }
        try self.validateMaterializedBatch();

        // A mixed binary whose search feature manifest is incompatible
        // fails closed before serving anything (ZDS 0009).
        try self.verifySearchFeatureVersion();

        if (sqlite.vecVersion(&self.sqlite_vec_version_buffer)) |text| {
            self.sqlite_vec_version_len = text.len;
        } else |_| {
            self.sqlite_vec_version_len = 0;
        }

        return self;
    }

    pub fn close(self: *Node) void {
        const gpa = self.gpa;
        if (self.db_open) self.db.close();
        self.journal.close();
        self.store.deinit();
        self.lock_file.unlock(self.io);
        self.lock_file.close(self.io);
        self.dir.close(self.io);
        self.outbox.deinit(gpa);
        gpa.free(self.db_path);
        gpa.free(self.inbox);
        gpa.destroy(self.effects);
        gpa.destroy(self.log);
        gpa.destroy(self);
    }

    // ------------------------------------------------------------------
    // Cluster surface used by the transport host
    // ------------------------------------------------------------------

    pub fn isLeader(self: *const Node) bool {
        return self.log.core.role == .leader;
    }

    pub fn isVoter(self: *const Node) bool {
        return self.capabilities.votes;
    }

    pub fn role(self: *const Node) roles.Role {
        return self.product_role;
    }

    pub fn currentLeader(self: *const Node) ?paxos.NodeId {
        return self.log.currentLeader();
    }

    /// True when the current epoch is close enough to its slot bound that
    /// the host must checkpoint before appending another command.
    pub fn epochNearlyFull(self: *const Node) bool {
        return self.log.decidedThrough() + capacity_reserve >=
            types.log_options.max_entries;
    }

    /// Processes one protocol message from a peer.
    pub fn stepEnvelope(self: *Node, envelope: Log.Envelope) !void {
        try self.log.step(envelope, self.effects);
        try self.consumeEffects();
    }

    /// Learns a voter-certified chosen entry. The commit is journaled and
    /// synced before it is applied to the SQLite materialization.
    pub fn learnChosen(
        self: *Node,
        from: paxos.NodeId,
        slot: paxos.Slot,
        entry: types.Entry,
    ) !void {
        try self.log.learnChosen(from, slot, entry, self.effects);
        try self.consumeEffects();
    }

    /// Advances protocol timers (election, heartbeat, retransmission).
    pub fn tickProtocol(self: *Node) !void {
        try self.log.tick(.noop, self.effects);
        try self.consumeEffects();
    }

    /// Repairs protocol traffic after the transport reconnects to a peer.
    pub fn peerReconnected(self: *Node, peer: paxos.NodeId) !void {
        try self.log.reconnected(peer, self.effects);
        try self.consumeEffects();
    }

    /// Requests decided entries this node is missing from `peer`.
    pub fn requestCatchUp(self: *Node, peer: paxos.NodeId) !void {
        try self.log.requestCatchUp(peer, self.applied_slot + 1, self.effects);
        try self.consumeEffects();
    }

    /// Starts phase one immediately (used by hosts that manage elections).
    pub fn campaign(self: *Node) !void {
        try self.log.campaign(.noop, self.effects);
        try self.consumeEffects();
    }

    // ------------------------------------------------------------------
    // Public SQL surface
    // ------------------------------------------------------------------

    /// Executes one write transaction and replicates its WAL frames.
    /// In a one-member configuration the result is committed and applied
    /// on return; in a cluster the host must await `applied_slot`.
    pub fn exec(self: *Node, sql: [:0]const u8) !ExecResult {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        return self.writeTransaction(.application, sql, null);
    }

    /// Executes one prepared statement as a replicated SQLite transaction.
    /// Parameter bytes are borrowed only for the duration of this call.
    pub fn execPrepared(
        self: *Node,
        sql: []const u8,
        values: []const prepared.Value,
    ) !ExecResult {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        const statements = [_]prepared.Statement{.{
            .sql = sql,
            .values = values,
        }};
        return self.writePreparedTransaction(.application, &statements, null);
    }

    /// Executes one prepared statement as a replicated transaction and
    /// captures the structured write result: the change count, the last
    /// insert rowid when the statement set one, and typed `RETURNING` rows
    /// when the statement produces them. The returned rows complete before
    /// the write is acknowledged; the caller owns `out_returning`.
    pub fn execPreparedResult(
        self: *Node,
        gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
        out_returning: *?TypedResult,
    ) !ExecResult {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        out_returning.* = null;
        var capture = WriteCapture{ .gpa = gpa };
        errdefer if (capture.returning) |*rows| rows.deinit();
        const statements = [_]prepared.Statement{.{
            .sql = sql,
            .values = values,
        }};
        var result = try self.writeRequest(
            .application,
            .{ .prepared = &statements },
            null,
            &capture,
        );
        result.last_insert_rowid = capture.last_insert_rowid;
        out_returning.* = capture.returning;
        return result;
    }

    /// Executes one prepared statement once per parameter vector in `batch`
    /// as ONE replicated transaction (the typed client RPC's atomic
    /// `executemany`). Every statement shares `sql`; the reported change
    /// count is the whole batch's total, and any per-row failure rolls the
    /// entire transaction back. The caller bounds `batch` (the wire path
    /// enforces `prepared.maximum_statements`).
    pub fn execPreparedBatch(
        self: *Node,
        sql: []const u8,
        batch: []const []const prepared.Value,
    ) !ExecResult {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        if (batch.len == 0) return error.EmptyTransaction;
        const statements = try self.gpa.alloc(prepared.Statement, batch.len);
        defer self.gpa.free(statements);
        for (batch, statements) |values, *statement| {
            statement.* = .{ .sql = sql, .values = values };
        }
        return self.writePreparedTransaction(.application, statements, null);
    }

    /// Commits a completed multi-call transaction builder as one replicated
    /// WAL transition. A builder is single-use even when execution fails,
    /// preventing accidental retry without an idempotent session.
    pub fn execTransaction(
        self: *Node,
        transaction: *prepared.Transaction,
    ) !ExecResult {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        try transaction.markFinished();
        return self.writePreparedTransaction(.application, transaction.slice(), null);
    }

    /// Opens a replicated client session for idempotent retry.
    pub fn openSession(self: *Node) !u64 {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        const next_id = 1 + try self.metaInt("session_counter");
        const sql = try std.fmt.allocPrintSentinel(
            self.gpa,
            \\update __zaxon_meta set value = {d} where key = 'session_counter';
            \\update __zaxon_meta set value = cast(value as integer) + 1
            \\  where key = 'write_seq';
            \\insert into __zaxon_sessions(id, next_sequence, last_sequence,
            \\  last_changes, last_activity_slot) values ({d}, 1, null, null,
            \\  (select cast(value as integer) from __zaxon_meta
            \\   where key = 'write_seq'));
        ,
            .{ next_id, next_id },
            0,
        );
        defer self.gpa.free(sql);
        _ = try self.writeTransaction(.internal, sql, null);
        return @intCast(next_id);
    }

    pub const SessionCheck = union(enum) {
        /// The sequence is the permitted next one; execute it.
        execute,
        /// The sequence equals the last executed one; return this result.
        replay: ExecResult,
    };

    /// Validates a session sequence against the replicated session table
    /// without executing anything.
    pub fn checkSession(
        self: *Node,
        session_id: u64,
        sequence: u64,
    ) !SessionCheck {
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        var lease = try self.readLease();
        defer lease.release();
        var stmt = try lease.db.prepare(
            "select next_sequence, last_sequence, last_changes " ++
                "from __zaxon_sessions where id = ?1",
        );
        defer stmt.finalize();
        try stmt.bindInt64(1, @intCast(session_id));
        if (!try stmt.step()) return error.UnknownSession;
        const next_sequence: u64 = @intCast(stmt.columnInt64(0));
        const last_sequence: ?u64 = if (stmt.isColumnNull(1))
            null
        else
            @intCast(stmt.columnInt64(1));
        const last_changes = stmt.columnInt64(2);

        if (last_sequence) |last| {
            if (sequence == last) {
                return .{ .replay = .{
                    .changes = last_changes,
                    .slot = 0,
                    .replayed = true,
                } };
            }
        }
        if (sequence < next_sequence) return error.ResultExpired;
        if (sequence > next_sequence) return error.SequenceGap;
        return .execute;
    }

    /// Executes `sequence` for `session_id` exactly once. Retrying the last
    /// sequence returns the recorded result without executing SQL; older or
    /// out-of-order sequences fail without executing SQL.
    pub fn execIdempotent(
        self: *Node,
        session_id: u64,
        sequence: u64,
        sql: [:0]const u8,
    ) !ExecResult {
        switch (try self.checkSession(session_id, sequence)) {
            .replay => |result| return result,
            .execute => {},
        }
        return self.writeTransaction(.application, sql, .{
            .session_id = session_id,
            .sequence = sequence,
        });
    }

    /// Prepared-statement variant of `execIdempotent` for the typed client
    /// RPC: same session and sequence semantics, positional bound values.
    /// A fresh execution reports the last insert rowid when the statement
    /// set one; a replay retains only the change count (the session table
    /// does not persist the rowid yet).
    pub fn execIdempotentPrepared(
        self: *Node,
        session_id: u64,
        sequence: u64,
        sql: []const u8,
        values: []const prepared.Value,
    ) !ExecResult {
        switch (try self.checkSession(session_id, sequence)) {
            .replay => |result| return result,
            .execute => {},
        }
        const statements = [_]prepared.Statement{.{
            .sql = sql,
            .values = values,
        }};
        return self.execIdempotentStatements(&statements, session_id, sequence);
    }

    /// Batch variant of `execIdempotentPrepared` for the typed client
    /// RPC's atomic `executemany`: every parameter vector in `batch` binds
    /// the same `sql`, the whole batch is ONE replicated transaction under
    /// ONE session sequence, and the recorded result is the batch's total
    /// change count.
    pub fn execIdempotentPreparedBatch(
        self: *Node,
        session_id: u64,
        sequence: u64,
        sql: []const u8,
        batch: []const []const prepared.Value,
    ) !ExecResult {
        if (batch.len == 0) return error.EmptyTransaction;
        switch (try self.checkSession(session_id, sequence)) {
            .replay => |result| return result,
            .execute => {},
        }
        const statements = try self.gpa.alloc(prepared.Statement, batch.len);
        defer self.gpa.free(statements);
        for (batch, statements) |values, *statement| {
            statement.* = .{ .sql = sql, .values = values };
        }
        return self.execIdempotentStatements(statements, session_id, sequence);
    }

    /// Shared session-write tail: one replicated transaction with the
    /// session update, capturing the last insert rowid for fresh
    /// executions. Any captured `RETURNING` rows are discarded; the
    /// session RPC does not retain them for replay.
    fn execIdempotentStatements(
        self: *Node,
        statements: []const prepared.Statement,
        session_id: u64,
        sequence: u64,
    ) !ExecResult {
        var capture = WriteCapture{ .gpa = self.gpa };
        defer if (capture.returning) |*rows| rows.deinit();
        var result = try self.writeRequest(
            .application,
            .{ .prepared = statements },
            .{ .session_id = session_id, .sequence = sequence },
            &capture,
        );
        result.last_insert_rowid = capture.last_insert_rowid;
        return result;
    }

    /// Deletes sessions whose last activity is more than `retain` session
    /// writes behind the newest session write.
    pub fn expireSessions(self: *Node, retain: u64) !ExecResult {
        const sql = try std.fmt.allocPrintSentinel(
            self.gpa,
            \\delete from __zaxon_sessions where last_activity_slot <
            \\  (select cast(value as integer) from __zaxon_meta
            \\   where key = 'write_seq') - {d};
        ,
            .{retain},
            0,
        );
        defer self.gpa.free(sql);
        return self.writeTransaction(.internal, sql, null);
    }

    /// Runs a read-only query. The result owns its memory via an arena.
    /// On a member without the live writer connection this opens a
    /// short-lived connection against the materialized image.
    pub fn query(self: *Node, gpa: std.mem.Allocator, sql: []const u8) !QueryResult {
        return self.queryPrepared(gpa, sql, &.{});
    }

    pub fn queryWithLimits(
        self: *Node,
        gpa: std.mem.Allocator,
        sql: []const u8,
        limits: QueryLimits,
    ) !QueryResult {
        return self.queryPreparedWithLimits(gpa, sql, &.{}, limits);
    }

    /// Runs one read-only prepared query and returns copied result values.
    pub fn queryPrepared(
        self: *Node,
        gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
    ) !QueryResult {
        return self.queryPreparedWithLimits(gpa, sql, values, .{});
    }

    /// Typed hybrid search (ZDS 0009): validates the request — including
    /// the 4096 candidate cap — builds the canonical lexical, vector, or
    /// fused statement, and runs it through the standard read path so
    /// leases, guards, and query budgets apply unchanged.
    pub fn search(
        self: *Node,
        gpa: std.mem.Allocator,
        request: search_api.Request,
        limits: QueryLimits,
    ) !QueryResult {
        const plan = try search_api.plan(gpa, request);
        defer plan.deinit(gpa);
        return self.queryPreparedWithLimits(gpa, plan.sql, plan.values(), limits);
    }

    /// Typed search over the same validated planner as `search`.
    pub fn searchTyped(
        self: *Node,
        gpa: std.mem.Allocator,
        request: search_api.Request,
        limits: QueryLimits,
    ) !TypedResult {
        const plan = try search_api.plan(gpa, request);
        defer plan.deinit(gpa);
        return self.queryPreparedTypedWithLimits(gpa, plan.sql, plan.values(), limits);
    }

    /// Runs one read-only prepared query and returns tagged SQLite values.
    pub fn queryPreparedTyped(
        self: *Node,
        gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
    ) !TypedResult {
        return self.queryPreparedTypedWithLimits(gpa, sql, values, .{});
    }

    /// Legacy text presentation of the typed read path. Integer and real
    /// cells are rendered exactly as SQLite's own text conversion renders
    /// them, so existing JSON consumers keep byte-identical responses.
    pub fn queryPreparedWithLimits(
        self: *Node,
        gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
        limits: QueryLimits,
    ) !QueryResult {
        var typed = try self.queryPreparedTypedWithLimits(gpa, sql, values, limits);
        errdefer typed.deinit();
        const alloc = typed.arena.allocator();
        const rows = try alloc.alloc([]const ?[]const u8, typed.rows.len);
        for (typed.rows, rows) |typed_row, *text_row| {
            const cells = try alloc.alloc(?[]const u8, typed_row.len);
            for (typed_row, cells) |value, *cell| {
                cell.* = switch (value) {
                    .null_value => null,
                    .integer => |number| try std.fmt.allocPrint(
                        alloc,
                        "{d}",
                        .{number},
                    ),
                    .real => |number| blk: {
                        var buffer: [32]u8 = undefined;
                        break :blk try alloc.dupe(
                            u8,
                            sqlite.formatReal(&buffer, number),
                        );
                    },
                    .text => |bytes| bytes,
                    .blob => |bytes| bytes,
                };
            }
            text_row.* = cells;
        }
        return .{ .arena = typed.arena, .columns = typed.columns, .rows = rows };
    }

    pub fn queryPreparedTypedWithLimits(
        self: *Node,
        gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
        limits: QueryLimits,
    ) !TypedResult {
        if (!self.capabilities.serves_reads) return error.RoleCannotRead;
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        var lease = try self.readLease();
        defer lease.release();

        // Reads are application statements too: the reserved namespace and
        // checkpoint pragmas must stay unreachable. A short-lived lease
        // connection gets its own guard; the live connection reuses the
        // node's. The guard outlives the statement because the lease is
        // released (and any owned connection closed) before this returns.
        var lease_guard = guard_mod.Guard{};
        const read_guard: *guard_mod.Guard = if (lease.owned) blk: {
            lease_guard.install(&lease.db);
            break :blk &lease_guard;
        } else &self.guard;
        read_guard.scope = .application;
        defer read_guard.scope = .internal;

        // A VM-instruction budget is deterministic and SQLite-native. It is
        // intentionally optional: embedded callers and approved migrations
        // can retain SQLite's normal unlimited behavior.
        const progress_granularity: u64 = 1_000;
        var progress = QueryProgress{
            .callbacks_remaining = if (limits.max_vm_steps == 0)
                0
            else
                @max(@as(u64, 1), (limits.max_vm_steps +| progress_granularity - 1) /
                    progress_granularity),
        };
        if (limits.max_vm_steps != 0) {
            lease.db.setProgressHandler(
                @intCast(progress_granularity),
                queryProgress,
                &progress,
            );
        }
        defer if (limits.max_vm_steps != 0) {
            lease.db.setProgressHandler(0, null, null);
        };

        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const alloc = arena.allocator();

        var stmt = lease.db.prepare(sql) catch |err| {
            self.saveErrorFrom(&lease.db);
            return err;
        };
        defer stmt.finalize();
        if (!stmt.isReadOnly()) return error.WriteInReadQuery;
        try prepared.bind(&stmt, values);

        const column_count = stmt.columnCount();
        const columns = try alloc.alloc([]const u8, column_count);
        var result_bytes: usize = 0;
        for (columns, 0..) |*column, index| {
            const name = stmt.columnName(@intCast(index));
            result_bytes = std.math.add(usize, result_bytes, name.len) catch
                return error.QueryResultTooLarge;
            if (limits.max_bytes != 0 and result_bytes > limits.max_bytes) {
                return error.QueryResultTooLarge;
            }
            column.* = try alloc.dupe(u8, name);
        }

        var rows: std.ArrayList([]const prepared.Value) = .empty;
        while (stmt.step() catch |err| {
            self.saveErrorFrom(&lease.db);
            return err;
        }) {
            if (limits.max_rows != 0 and rows.items.len >= limits.max_rows) {
                return error.QueryRowLimit;
            }
            const row = try alloc.alloc(prepared.Value, column_count);
            for (row, 0..) |*cell, index| {
                const column: u32 = @intCast(index);
                // Integers and reals count as their storage width; text and
                // blob count their byte length, as the text path always did.
                const cell_bytes: usize = switch (stmt.columnValueType(column)) {
                    .null => 0,
                    .integer, .real => 8,
                    .text => stmt.columnText(column).len,
                    .blob => stmt.columnBlob(column).len,
                };
                result_bytes = std.math.add(
                    usize,
                    result_bytes,
                    cell_bytes,
                ) catch return error.QueryResultTooLarge;
                if (limits.max_bytes != 0 and result_bytes > limits.max_bytes) {
                    return error.QueryResultTooLarge;
                }
                cell.* = switch (stmt.columnValueType(column)) {
                    .null => .null_value,
                    .integer => .{ .integer = stmt.columnInt64(column) },
                    .real => .{ .real = stmt.columnDouble(column) },
                    .text => .{
                        .text = try alloc.dupe(u8, stmt.columnText(column)),
                    },
                    .blob => .{
                        .blob = try alloc.dupe(u8, stmt.columnBlob(column)),
                    },
                };
            }
            try rows.append(alloc, row);
        }

        return .{
            .arena = arena,
            .columns = columns,
            .rows = try rows.toOwnedSlice(alloc),
        };
    }

    /// Copies the name of one bound parameter (1-based index) into
    /// `buffer` and returns its length; zero for positional parameters.
    /// Resolved by SQLite itself so `:name`, `@name`, and `$name` all work
    /// without the host parsing SQL.
    pub fn statementParameterName(
        self: *Node,
        sql: []const u8,
        index: u32,
        buffer: []u8,
    ) !usize {
        if (!self.capabilities.serves_reads) return error.RoleCannotRead;
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        var lease = try self.readLease();
        defer lease.release();

        var lease_guard = guard_mod.Guard{};
        const read_guard: *guard_mod.Guard = if (lease.owned) blk: {
            lease_guard.install(&lease.db);
            break :blk &lease_guard;
        } else &self.guard;
        read_guard.scope = .application;
        defer read_guard.scope = .internal;

        var stmt = lease.db.prepare(sql) catch |err| {
            self.saveErrorFrom(&lease.db);
            return err;
        };
        defer stmt.finalize();
        if (index == 0 or index > stmt.parameterCount()) {
            return error.ParameterCountMismatch;
        }
        const name = stmt.parameterName(index) orelse return 0;
        const len = @min(name.len, buffer.len);
        @memcpy(buffer[0..len], name[0..len]);
        return len;
    }

    /// Prepares (without executing) the first statement of `sql` under the
    /// application guard and reports its shape. Hosts use this to reject
    /// multi-statement `execute()` input and to size parameter binding.
    pub fn statementInfo(self: *Node, sql: []const u8) !StatementInfo {
        if (!self.capabilities.serves_reads) return error.RoleCannotRead;
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        var lease = try self.readLease();
        defer lease.release();

        var lease_guard = guard_mod.Guard{};
        const read_guard: *guard_mod.Guard = if (lease.owned) blk: {
            lease_guard.install(&lease.db);
            break :blk &lease_guard;
        } else &self.guard;
        read_guard.scope = .application;
        defer read_guard.scope = .internal;

        var first = lease.db.prepareWithTail(sql) catch |err| {
            self.saveErrorFrom(&lease.db);
            return err;
        };
        defer first.stmt.finalize();
        const tail = std.mem.trim(u8, first.tail, " \t\r\n;");
        return .{
            .parameter_count = first.stmt.parameterCount(),
            .column_count = first.stmt.columnCount(),
            .read_only = first.stmt.isReadOnly(),
            .has_tail = tail.len != 0,
        };
    }

    pub fn lastSqliteMessage(self: *const Node) []const u8 {
        if (self.saved_error_len > 0) return self.saved_error[0..self.saved_error_len];
        if (self.db_open) return self.db.errmsg();
        return "no live database connection";
    }

    // ------------------------------------------------------------------
    // Operations surface
    // ------------------------------------------------------------------

    pub fn status(self: *Node) Status {
        // The gate caches the version at open, which precedes lazy schema
        // bootstrap on hosts and page-applied bootstrap on followers;
        // refresh while it still reads zero.
        if (self.search_feature_version == 0) {
            if (self.schemaReady() catch false) {
                self.search_feature_version =
                    self.metaInt("search_feature_version") catch 0;
            }
        }
        var snapshot_name: ?[16]u8 = null;
        if (self.dir.readFileAlloc(self.io, current_file_name, self.gpa, .limited(64))) |bytes| {
            defer self.gpa.free(bytes);
            const trimmed = std.mem.trim(u8, bytes, " \n");
            if (trimmed.len == 16) {
                snapshot_name = trimmed[0..16].*;
            }
        } else |_| {}
        return .{
            .node_id = self.identity.node_id,
            .database_id = self.identity.database_id,
            .configuration_id = self.identity.configuration_id,
            .role = @tagName(self.log.core.role),
            .node_type = self.product_role.name(),
            .leader = self.log.currentLeader(),
            .ballot = self.log.core.ballot,
            .decided_slot = self.log.decidedThrough(),
            .applied_slot = self.applied_slot,
            .journal_records = self.journal.next_sequence - 1,
            .epoch_capacity = types.log_options.max_entries,
            .chain = self.last_chain,
            .page_size = self.page_size,
            .snapshot = snapshot_name,
            .fts5_enabled = sqlite.compileOptionUsed("ENABLE_FTS5"),
            .sqlite_vec_version = self.sqliteVecVersion(),
            .search_feature_version = self.search_feature_version,
            .simd_backend = zaxon_search.vector.backend.name(),
            .mmap_size = self.effective_mmap_size,
            .candidate_hard_limit = candidate_hard_limit,
        };
    }

    fn sqliteVecVersion(self: *const Node) []const u8 {
        return self.sqlite_vec_version_buffer[0..self.sqlite_vec_version_len];
    }

    pub fn memberIds(self: *const Node) []const paxos.NodeId {
        return self.members[0..self.member_count];
    }

    /// The durable decided registry, or null for embedded and local nodes
    /// whose membership stays fixed by flags.
    pub fn decidedRegistry(self: *const Node) ?*const registry.Decided {
        if (self.decided_registry) |*decided| return decided;
        return null;
    }

    /// Installs the transport host's pre-barrier outbox drain. The host must
    /// serialize node transitions until the callback returns and the storage
    /// barrier completes; `server.zig` does so with its node mutex.
    pub fn setPreDurableOutboxHook(
        self: *Node,
        hook: ?PreDurableOutboxHook,
    ) void {
        self.pre_durable_outbox_hook = hook;
    }

    /// Takes an online snapshot, seals the epoch, and starts the next one.
    /// Requires the one-member configuration, where the checkpoint decision
    /// is immediate. Cluster hosts use `prepareCheckpoint` and complete the
    /// rollover once the stop sign commits.
    pub fn snapshot(self: *Node) !void {
        std.debug.assert(self.single);
        try self.prepareCheckpoint();
        if (self.log.isReconfigured() == null) return error.CheckpointNotDecided;
        try self.completeClusterRollover();
    }

    /// Materializes the epoch into a snapshot generation and proposes the
    /// stop sign that seals the epoch. Leader only; no write may be in
    /// flight. In a cluster the decision arrives asynchronously.
    pub fn prepareCheckpoint(self: *Node) !void {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        if (!self.db_open) try self.ensureWriter();
        if (self.db.inTransaction()) return error.TransactionOpen;
        if (self.capture_batch_id != null) return error.WriteInFlight;

        // 1. Materialize every committed frame into the main database file
        //    and reset WAL capture.
        try self.db.checkpointTruncate();
        self.committed_frames = 0;
        self.captured_frames = 0;

        // 2. Build the snapshot generation under a temporary name.
        const metadata = try self.buildSnapshotGeneration(self.applied_slot, null);

        // 3. Propose the stop sign that seals this epoch.
        _ = try self.log.checkpoint(metadata.slice(), self.effects);
        try self.consumeEffects();
    }

    const SnapshotMetadata = struct {
        buffer: [types.log_options.max_metadata_bytes]u8,
        len: usize,

        fn slice(self: *const SnapshotMetadata) []const u8 {
            return self.buffer[0..self.len];
        }
    };

    pub const PendingOperationPhase = enum { prepared, proposed };

    /// The durably recorded in-flight replacement request. `prepared`
    /// means membership has not changed and the request may be retried or
    /// cancelled; `proposed` means the stop sign is in Paxos and a timeout
    /// does not mean failure.
    pub const PendingOperation = struct {
        operation_id: u64,
        expected_configuration_id: u64,
        old_node_id: paxos.NodeId,
        new_node_id: paxos.NodeId,
        endpoint: [registry.max_endpoint_bytes]u8,
        endpoint_len: u8,
        phase: PendingOperationPhase,

        pub fn endpointSlice(self: *const PendingOperation) []const u8 {
            return self.endpoint[0..self.endpoint_len];
        }

        pub fn matches(
            self: *const PendingOperation,
            request: *const registry.ReplacementRequest,
        ) bool {
            return self.operation_id == request.operation_id and
                self.expected_configuration_id == request.expected_configuration_id and
                self.old_node_id == request.old_node_id and
                self.new_node_id == request.new_node_id and
                std.mem.eql(u8, self.endpointSlice(), request.new_endpoint);
        }

        fn toRequest(self: *const PendingOperation) registry.ReplacementRequest {
            return .{
                .operation_id = self.operation_id,
                .expected_configuration_id = self.expected_configuration_id,
                .old_node_id = self.old_node_id,
                .new_node_id = self.new_node_id,
                .new_endpoint = self.endpointSlice(),
            };
        }
    };

    /// Reads the durable pending replacement record, if one exists.
    pub fn pendingOperation(self: *Node) !?PendingOperation {
        const bytes = self.dir.readFileAlloc(
            self.io,
            pending_operation_file_name,
            self.gpa,
            .limited(512),
        ) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer self.gpa.free(bytes);
        const format = manifestValue(bytes, "format") orelse
            return error.CorruptPendingOperation;
        if (!std.mem.eql(u8, format, "1")) return error.CorruptPendingOperation;
        const operation_text = manifestValue(bytes, "operation_id") orelse
            return error.CorruptPendingOperation;
        const expected_text = manifestValue(bytes, "expected_configuration_id") orelse
            return error.CorruptPendingOperation;
        const old_text = manifestValue(bytes, "old_node_id") orelse
            return error.CorruptPendingOperation;
        const new_text = manifestValue(bytes, "new_node_id") orelse
            return error.CorruptPendingOperation;
        const endpoint_text = manifestValue(bytes, "endpoint") orelse
            return error.CorruptPendingOperation;
        const phase_text = manifestValue(bytes, "phase") orelse
            return error.CorruptPendingOperation;
        registry.validateEndpoint(endpoint_text) catch
            return error.CorruptPendingOperation;
        var pending = PendingOperation{
            .operation_id = std.fmt.parseInt(u64, operation_text, 10) catch
                return error.CorruptPendingOperation,
            .expected_configuration_id = std.fmt.parseInt(u64, expected_text, 10) catch
                return error.CorruptPendingOperation,
            .old_node_id = std.fmt.parseInt(paxos.NodeId, old_text, 10) catch
                return error.CorruptPendingOperation,
            .new_node_id = std.fmt.parseInt(paxos.NodeId, new_text, 10) catch
                return error.CorruptPendingOperation,
            .endpoint = [_]u8{0} ** registry.max_endpoint_bytes,
            .endpoint_len = @intCast(endpoint_text.len),
            .phase = std.meta.stringToEnum(PendingOperationPhase, phase_text) orelse
                return error.CorruptPendingOperation,
        };
        @memcpy(pending.endpoint[0..endpoint_text.len], endpoint_text);
        return pending;
    }

    fn persistPendingOperation(
        self: *Node,
        request: *const registry.ReplacementRequest,
        phase: PendingOperationPhase,
    ) !void {
        var buffer: [512]u8 = undefined;
        const contents = std.fmt.bufPrint(
            &buffer,
            "format=1\noperation_id={d}\nexpected_configuration_id={d}\n" ++
                "old_node_id={d}\nnew_node_id={d}\nendpoint={s}\nphase={s}\n",
            .{
                request.operation_id,
                request.expected_configuration_id,
                request.old_node_id,
                request.new_node_id,
                request.new_endpoint,
                @tagName(phase),
            },
        ) catch unreachable;
        try atomicWriteFile(self.io, self.dir, pending_operation_file_name, contents);
    }

    fn clearPendingOperation(self: *Node) !void {
        try durableDeleteFile(self.io, self.dir, pending_operation_file_name);
    }

    /// Repairs the scratch phase after a crash. A durable accepted stop
    /// proves that proposal submission completed even if the phase-file
    /// update did not. Without that evidence, `prepared` remains retryable.
    fn reconcilePendingOperation(self: *Node) !void {
        const pending = (try self.pendingOperation()) orelse return;
        if (pending.phase == .proposed) return;
        const stop = self.log.pendingStopSign() orelse return;
        const parsed = try parseStopMetadata(stop.metadataSlice());
        const seed = parsed.seed orelse {
            try self.clearPendingOperation();
            return;
        };
        if (seed.operation_id != pending.operation_id or
            seed.old_node_id != pending.old_node_id or
            seed.new_node_id != pending.new_node_id or
            !std.mem.eql(u8, seed.endpointSlice(), pending.endpointSlice()))
        {
            try self.clearPendingOperation();
            return;
        }
        const request = pending.toRequest();
        try self.persistPendingOperation(&request, .proposed);
    }

    /// Prepares and proposes a decided one-for-one voter replacement.
    /// Leader only. The stop sign carries the candidate registry digest
    /// and the replacement seed, so every survivor reconstructs the same
    /// next registry without the network.
    pub fn prepareReplacement(
        self: *Node,
        request: *const registry.ReplacementRequest,
    ) !void {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        if (self.fatal_storage_error) return error.StorageFailed;
        const decided = self.decidedRegistry() orelse
            return error.NoDecidedRegistry;
        if (try self.pendingOperation()) |pending| {
            if (!pending.matches(request)) return error.OperationConflict;
            if (pending.phase == .proposed) return error.OperationAlreadyProposed;
        }
        switch (try decided.validateRequest(request)) {
            .fresh => {},
            .retry => return error.OperationAlreadyComplete,
        }
        if (self.needs_resync) try self.resyncImage();
        if (!self.db_open) try self.ensureWriter();
        if (self.db.inTransaction()) return error.TransactionOpen;
        if (self.capture_batch_id != null) return error.WriteInFlight;

        // The request is durable before anything is proposed, so an
        // ambiguous crash resolves by operation ID.
        try self.persistPendingOperation(request, .prepared);
        failpoint.hit("after_pending_op");

        // Materialize every committed frame and reset WAL capture.
        try self.db.checkpointTruncate();
        self.committed_frames = 0;
        self.captured_frames = 0;

        const metadata = try self.buildSnapshotGeneration(self.applied_slot, request);
        failpoint.hit("after_replacement_checkpoint");

        const next = try decided.successor(request);
        var voter_buffer: [types.log_options.max_members]paxos.NodeId = undefined;
        const next_voters = next.voterIds(&voter_buffer);
        _ = try self.log.reconfigure(
            next.configuration_id,
            next_voters,
            metadata.slice(),
            self.effects,
        );
        try self.consumeEffects();
        failpoint.hit("after_replacement_submission");
        try self.persistPendingOperation(request, .proposed);
        failpoint.hit("after_replacement_proposed");
    }

    /// Copies the fully materialized database into `snapshots/<name>` with
    /// a manifest, and returns the stop-sign metadata naming it. The
    /// database file must be fully checkpointed (leader) or fully applied
    /// offline (follower). `manifest_applied_slot` is the highest slot the
    /// image covers, excluding the stop sign itself, so every member
    /// renders a byte-identical manifest.
    fn buildSnapshotGeneration(
        self: *Node,
        manifest_applied_slot: paxos.Slot,
        pending_request: ?*const registry.ReplacementRequest,
    ) !SnapshotMetadata {
        var name_buffer: [16]u8 = undefined;
        const snapshot_name = std.fmt.bufPrint(
            &name_buffer,
            "{x:0>16}",
            .{self.identity.configuration_id},
        ) catch unreachable;
        var tmp_path_buffer: [64]u8 = undefined;
        const tmp_path = std.fmt.bufPrint(
            &tmp_path_buffer,
            "snapshots/tmp-{s}",
            .{snapshot_name},
        ) catch unreachable;
        var final_path_buffer: [64]u8 = undefined;
        const final_path = std.fmt.bufPrint(
            &final_path_buffer,
            "snapshots/{s}",
            .{snapshot_name},
        ) catch unreachable;

        self.dir.deleteTree(self.io, tmp_path) catch {};
        self.dir.deleteTree(self.io, final_path) catch {};
        var tmp_dir = try self.dir.createDirPathOpen(self.io, tmp_path, .{});
        defer tmp_dir.close(self.io);

        try self.dir.copyFile(db_file_name, tmp_dir, "db", self.io, .{});
        {
            const snapshot_db = try tmp_dir.openFile(
                self.io,
                "db",
                .{ .mode = .read_write },
            );
            defer snapshot_db.close(self.io);
            try durability.syncFile(self.io, snapshot_db);
        }
        const db_digest = try fileSha256(self.io, tmp_dir, "db");

        const manifest = try self.renderManifest(manifest_applied_slot, db_digest);
        defer self.gpa.free(manifest);
        try atomicWriteFile(self.io, tmp_dir, "manifest", manifest);
        try self.dir.rename(tmp_path, self.dir, final_path, self.io);
        // The snapshot becomes authoritative only when the stop sign
        // naming it is journaled and synced; that barrier, on this volume,
        // is what persists this entry where a directory cannot be flushed.
        try durability.syncChildDirectory(self.io, self.dir, "snapshots");

        var metadata = SnapshotMetadata{ .buffer = undefined, .len = 0 };
        const manifest_digest = PayloadStore.hashOf(manifest);
        const rendered = blk: {
            const decided = self.decidedRegistry() orelse {
                // Registry-less embedded and local hosts keep zx1.
                if (pending_request != null) return error.CorruptStopSign;
                break :blk std.fmt.bufPrint(
                    &metadata.buffer,
                    "zx1 {s} {s}",
                    .{ snapshot_name, &std.fmt.bytesToHex(manifest_digest, .lower) },
                ) catch unreachable;
            };
            // Bind the canonical next registry into the stop metadata.
            const next = if (pending_request) |request|
                try decided.successor(request)
            else
                try decided.checkpointSuccessor();
            const registry_digest = next.digest();
            if (pending_request) |request| {
                break :blk std.fmt.bufPrint(
                    &metadata.buffer,
                    "zx2 {s} {s} {s} {x:0>16} {x:0>8} {x:0>8} {s}",
                    .{
                        snapshot_name,
                        &std.fmt.bytesToHex(manifest_digest, .lower),
                        &std.fmt.bytesToHex(registry_digest, .lower),
                        request.operation_id,
                        request.old_node_id,
                        request.new_node_id,
                        request.new_endpoint,
                    },
                ) catch unreachable;
            }
            break :blk std.fmt.bufPrint(
                &metadata.buffer,
                "zx2 {s} {s} {s}",
                .{
                    snapshot_name,
                    &std.fmt.bytesToHex(manifest_digest, .lower),
                    &std.fmt.bytesToHex(registry_digest, .lower),
                },
            ) catch unreachable;
        };
        metadata.len = rendered.len;
        return metadata;
    }

    fn renderManifest(
        self: *Node,
        applied_slot: paxos.Slot,
        db_digest: [32]u8,
    ) ![]u8 {
        return std.fmt.allocPrint(self.gpa,
            \\format=1
            \\database_id={x:0>32}
            \\sealed_configuration_id={d}
            \\applied_slot={d}
            \\chain={s}
            \\db_sha256={s}
            \\
        , .{
            self.identity.database_id,
            self.identity.configuration_id,
            applied_slot,
            &std.fmt.bytesToHex(self.last_chain, .lower),
            &std.fmt.bytesToHex(db_digest, .lower),
        });
    }

    /// Streams a consistent logical backup into `destination`.
    pub fn backup(self: *Node, destination: []const u8) !void {
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        var lease = try self.readLease();
        defer lease.release();
        var stmt = lease.db.prepare("vacuum into ?1") catch |err| {
            self.saveErrorFrom(&lease.db);
            return err;
        };
        defer stmt.finalize();
        try stmt.bindText(1, destination);
        _ = stmt.step() catch |err| {
            self.saveErrorFrom(&lease.db);
            return err;
        };
    }

    pub const BackupHandle = struct {
        node: *Node,
        file: Io.File,
        size: u64,
        sha256: [32]u8,
        name: [64]u8,
        name_length: usize,

        pub fn close(self: *BackupHandle) void {
            self.file.close(self.node.io);
            self.node.dir.deleteFile(
                self.node.io,
                self.name[0..self.name_length],
            ) catch {};
            self.* = undefined;
        }
    };

    /// Creates an immutable logical backup for bounded streaming. The caller
    /// must close the returned handle, which removes the temporary image.
    pub fn openBackup(self: *Node) !BackupHandle {
        var random_bytes: [8]u8 = undefined;
        self.io.random(&random_bytes);
        const nonce = std.mem.readInt(u64, &random_bytes, .little);
        var name: [64]u8 = undefined;
        const rendered = std.fmt.bufPrint(
            &name,
            ".remote-backup-{x}.db",
            .{nonce},
        ) catch unreachable;
        self.dir.deleteFile(self.io, rendered) catch {};
        const directory = std.fs.path.dirname(self.db_path) orelse ".";
        var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const destination = try std.fmt.bufPrint(
            &path_buffer,
            "{s}/{s}",
            .{ directory, rendered },
        );
        try self.backup(destination);
        errdefer self.dir.deleteFile(self.io, rendered) catch {};
        const file = try self.dir.openFile(self.io, rendered, .{});
        errdefer file.close(self.io);
        return .{
            .node = self,
            .file = file,
            .size = try file.length(self.io),
            .sha256 = try fileSha256(self.io, self.dir, rendered),
            .name = name,
            .name_length = rendered.len,
        };
    }

    /// A deterministic digest of the logical database content, computed
    /// from a `VACUUM INTO` image. Nodes with identical applied history
    /// produce identical digests.
    pub fn contentHash(self: *Node) ![32]u8 {
        var name_buffer: [64]u8 = undefined;
        const tmp_name = std.fmt.bufPrint(
            &name_buffer,
            ".content-hash-{d}.db",
            .{self.identity.node_id},
        ) catch unreachable;
        self.dir.deleteFile(self.io, tmp_name) catch {};
        const directory = std.fs.path.dirname(self.db_path) orelse ".";
        var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const destination = try std.fmt.bufPrint(
            &path_buffer,
            "{s}/{s}",
            .{ directory, tmp_name },
        );
        try self.backup(destination);
        defer self.dir.deleteFile(self.io, tmp_name) catch {};
        return fileSha256(self.io, self.dir, tmp_name);
    }

    /// Verifies the SQLite image, the descriptor chain, and payload
    /// availability for the committed suffix.
    pub fn integrityCheck(self: *Node) !IntegrityReport {
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        var report = IntegrityReport{
            .sqlite_ok = blk: {
                var lease = self.readLease() catch |err| {
                    // A fresh member with no decided writes has no image.
                    break :blk err == error.NoDatabaseImage and
                        self.log.decidedThrough() == 0;
                };
                defer lease.release();
                break :blk lease.db.integrityCheckOk() catch false;
            },
            .chain_ok = true,
            .payloads_ok = true,
        };
        var chain = self.epochBaseChain() catch {
            report.chain_ok = false;
            return report;
        };
        var data_slot: paxos.Slot = 0;
        var slot: paxos.Slot = 1;
        const decided = self.log.decidedThrough();
        while (slot <= decided) : (slot += 1) {
            const entry = self.log.read(slot) orelse break;
            switch (entry) {
                .command => |cmd| switch (cmd) {
                    .transaction_batch => |batch| {
                        if (batch.database_id != self.identity.database_id or
                            batch.base_data_slot != data_slot or
                            !std.mem.eql(u8, &batch.base_chain_hash, &chain) or
                            !command.chainValid(batch))
                        {
                            report.chain_ok = false;
                        }
                        chain = batch.result_chain_hash;
                        const payload = self.store.load(self.gpa, batch.payload_hash) catch {
                            report.payloads_ok = false;
                            continue;
                        };
                        defer self.gpa.free(payload);
                        _ = self.validateBatchPayload(batch, payload) catch {
                            report.payloads_ok = false;
                            continue;
                        };
                        data_slot = slot;
                    },
                    else => {},
                },
                .stop => {},
            }
        }
        return report;
    }

    // ------------------------------------------------------------------
    // Write path
    // ------------------------------------------------------------------

    const SessionUpdate = struct {
        session_id: u64,
        sequence: u64,
    };

    const WriteRequest = union(enum) {
        raw: [:0]const u8,
        prepared: []const prepared.Statement,
    };

    /// Opens the live writer (capture) connection. The materialized image
    /// must be current; the host calls this when it holds leadership.
    pub fn ensureWriter(self: *Node) !void {
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        if (self.db_open) return;
        std.debug.assert(!self.needs_resync);
        try self.openLiveDatabase();
    }

    /// Closes the live writer connection and discards its WAL, then
    /// rebuilds the materialized image from the decided log. Used when
    /// leadership is lost with speculative frames in the WAL, or when a
    /// decision contradicted the live image.
    pub fn resyncImage(self: *Node) !void {
        if (self.db_open) {
            self.db.close();
            self.db_open = false;
        }
        self.capture_batch_id = null;
        try self.rebuildMaterializedImage();
        self.needs_resync = false;
    }

    /// True when the replicated bootstrap schema exists in the image.
    pub fn schemaReady(self: *Node) !bool {
        var lease = self.readLease() catch return false;
        defer lease.release();
        var stmt = try lease.db.prepare(
            "select 1 from sqlite_master where name = '__zaxon_meta'",
        );
        defer stmt.finalize();
        return try stmt.step();
    }

    /// The replicated schema-bootstrap statement batch. Callers free it.
    pub fn bootstrapSql(self: *Node, gpa: std.mem.Allocator) ![:0]u8 {
        return std.fmt.allocPrintSentinel(
            gpa,
            \\create table __zaxon_meta(key text primary key, value) without rowid;
            \\create table __zaxon_sessions(
            \\  id integer primary key,
            \\  next_sequence integer not null,
            \\  last_sequence integer,
            \\  last_changes integer,
            \\  last_activity_slot integer not null default 0);
            \\insert into __zaxon_meta(key, value) values
            \\  ('schema_version', '1'),
            \\  ('search_feature_version', '1'),
            \\  ('database_id', '{x:0>32}'),
            \\  ('session_counter', '0'),
            \\  ('write_seq', '0');
        ,
            .{self.identity.database_id},
            0,
        );
    }

    /// Executes one SQL batch inside a captured transaction and appends
    /// the resulting descriptor to the replicated log. Returns once the
    /// descriptor is journaled; in a one-member configuration the slot is
    /// also committed and applied on return.
    fn writeTransaction(
        self: *Node,
        scope: guard_mod.Scope,
        sql: [:0]const u8,
        session: ?SessionUpdate,
    ) !ExecResult {
        return self.writeRequest(scope, .{ .raw = sql }, session, null);
    }

    fn writePreparedTransaction(
        self: *Node,
        scope: guard_mod.Scope,
        statements: []const prepared.Statement,
        session: ?SessionUpdate,
    ) !ExecResult {
        return self.writeRequest(scope, .{ .prepared = statements }, session, null);
    }

    fn writeRequest(
        self: *Node,
        scope: guard_mod.Scope,
        request: WriteRequest,
        session: ?SessionUpdate,
        capture: ?*WriteCapture,
    ) !ExecResult {
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        if (self.rollover_pending) {
            if (!self.single) return error.LogSealed;
            try self.completeClusterRollover();
        }
        if (self.single) try self.ensureEpochCapacity();
        // Never execute SQL that cannot be appended: a sealed log would
        // otherwise leave a committed SQLite transaction with no slot.
        if (self.log.stop_pending or self.log.isReconfigured() != null) {
            return error.LogSealed;
        }
        try self.ensureWriter();
        if (self.capture_batch_id != null) return error.WriteInFlight;
        if (self.live_transaction) return error.TransactionOpen;

        var batch_id_bytes: [16]u8 = undefined;
        self.io.random(&batch_id_bytes);

        // Execute the transaction. The replicated session and batch marker
        // rows are updated inside the same SQLite transaction, so captured
        // frames carry them atomically with the user's changes.
        try self.db.exec("begin immediate");
        errdefer self.db.exec("rollback") catch {};

        const changes_before = self.totalChanges();
        const rowid_before = self.db.lastInsertRowId();
        self.saved_error_len = 0;
        {
            // Only the caller's SQL runs in its scope; the metadata and
            // commit statements below are always internal.
            self.guard.scope = scope;
            defer self.guard.scope = .internal;
            const execution = switch (request) {
                .raw => |sql| self.db.exec(sql),
                .prepared => |statements| if (capture) |sink|
                    self.executePreparedCapture(statements, sink)
                else
                    prepared.execute(&self.db, statements),
            };
            execution catch |err| {
                self.saveErrorFrom(&self.db);
                return err;
            };
        }
        // Read the rowid before the session and batch-marker inserts below
        // overwrite it with reserved-table bookkeeping.
        if (capture) |sink| {
            const rowid_after = self.db.lastInsertRowId();
            if (rowid_after != rowid_before) sink.last_insert_rowid = rowid_after;
        }
        if (scope == .application) {
            // The authorizer already denied contract-changing statements;
            // this cheap re-check keeps capture robust to anything the
            // deny list missed before the frames are extracted.
            guard_mod.verifyCaptureContract(
                &self.db,
                self.page_size,
                &self.committed_frames,
            ) catch |err| {
                self.saveErrorText("application SQL broke the capture contract");
                return err;
            };
        }
        const changes: i64 = self.totalChanges() - changes_before;
        return self.sealCapturedTransaction(batch_id_bytes, changes, session);
    }

    /// Commits the open writer transaction, captures its WAL frames, and
    /// replicates them as one transaction batch. Shared by the one-shot
    /// write path and Gate C live-transaction commit. A failure after the
    /// SQLite commit marks the image for resync.
    fn sealCapturedTransaction(
        self: *Node,
        batch_id_bytes: [16]u8,
        changes: i64,
        session: ?SessionUpdate,
    ) !ExecResult {
        const batch_id = std.mem.readInt(u128, &batch_id_bytes, .little);
        var committed_without_log = false;
        errdefer if (committed_without_log) {
            self.capture_batch_id = null;
            self.needs_resync = true;
        };

        if (session) |update| {
            try self.db.exec(
                "update __zaxon_meta set value = cast(value as integer) + 1 " ++
                    "where key = 'write_seq'",
            );
            var stmt = try self.db.prepare(
                "update __zaxon_sessions set next_sequence = ?1, " ++
                    "last_sequence = ?2, last_changes = ?3, " ++
                    "last_activity_slot = (select cast(value as integer) " ++
                    "from __zaxon_meta where key = 'write_seq') where id = ?4",
            );
            defer stmt.finalize();
            try stmt.bindInt64(1, @intCast(update.sequence + 1));
            try stmt.bindInt64(2, @intCast(update.sequence));
            try stmt.bindInt64(3, changes);
            try stmt.bindInt64(4, @intCast(update.session_id));
            _ = try stmt.step();
        }
        {
            const batch_id_hex = std.fmt.bytesToHex(batch_id_bytes, .lower);
            var stmt = try self.db.prepare(
                "insert or replace into __zaxon_meta(key, value) " ++
                    "values ('batch_id', ?1)",
            );
            defer stmt.finalize();
            try stmt.bindText(1, &batch_id_hex);
            _ = try stmt.step();
        }
        try self.db.exec("commit");
        committed_without_log = true;

        // Capture the committed frames and persist them as one payload.
        if (self.committed_frames <= self.captured_frames) {
            return error.CaptureLost;
        }
        var frames = try wal.readCommittedFrames(
            self.io,
            self.gpa,
            self.dir,
            wal_file_name,
            self.page_size,
            self.captured_frames,
            self.committed_frames,
        );
        defer frames.deinit(self.gpa);
        self.captured_frames = self.committed_frames;

        const transactions = [_]wal.Transaction{.{
            .session_id = if (session) |update| update.session_id else 0,
            .sequence = if (session) |update| update.sequence else 0,
            .first_frame = 0,
            .frame_count = @intCast(frames.infos.len),
            .change_count = changes,
        }};
        const payload = try wal.encodePayload(
            self.gpa,
            self.identity.database_id,
            &transactions,
            &frames,
        );
        defer self.gpa.free(payload);
        if (payload.len > command.max_payload_bytes) {
            return error.TransactionTooLarge;
        }
        failpoint.hit("before_payload_sync");
        const payload_hash = self.store.put(payload) catch |err| {
            self.fatal_storage_error = true;
            return err;
        };
        failpoint.hit("after_payload_sync");

        var batch = command.TransactionBatch{
            .database_id = self.identity.database_id,
            .batch_id = batch_id,
            .base_data_slot = self.last_data_slot,
            .base_chain_hash = self.last_chain,
            .result_chain_hash = undefined,
            .payload_hash = payload_hash,
            .payload_bytes = payload.len,
            .transaction_count = 1,
            .frame_count = @intCast(frames.infos.len),
        };
        batch.result_chain_hash = command.chainStep(batch.base_chain_hash, batch);

        // Replicate: journal + fsync happen inside consumeEffects before any
        // dependent message or acknowledgement.
        const slot = self.log.append(
            .{ .transaction_batch = batch },
            self.effects,
        ) catch |err| {
            // The SQLite transaction is committed locally but has no log
            // slot; the image must be resynced from the decided log.
            self.needs_resync = true;
            return err;
        };
        self.capture_batch_id = batch_id;
        try self.consumeEffects();
        committed_without_log = false;
        if (self.single and self.applied_slot < slot) return error.CommitIncomplete;
        const result = ExecResult{ .changes = changes, .slot = slot };
        self.last_append = result;
        return result;
    }

    /// Batch identity of the in-flight captured write, if any. The host
    /// uses it to confirm that the decided value at the awaited slot is
    /// this write and not a competing leader's.
    pub fn pendingBatchId(self: *const Node) ?u128 {
        return self.capture_batch_id;
    }

    // ------------------------------------------------------------------
    // Gate C: live transactions (single-member nodes only)
    // ------------------------------------------------------------------

    pub const LiveStatementResult = struct {
        changes: i64,
        last_insert_rowid: ?i64,
    };

    /// Opens a live SQLite transaction on the writer connection. Later
    /// `liveExec` calls observe earlier uncommitted writes; nothing is
    /// replicated until `commitLive`. Restricted to a single-member node,
    /// which cannot lose leadership while the caller holds the transaction.
    pub fn beginLive(self: *Node) !void {
        if (!self.single) return error.ClusterTransactionUnsupported;
        if (!self.capabilities.serves_writes) return error.RoleCannotWrite;
        if (self.live_transaction) return error.TransactionOpen;
        if (self.fatal_storage_error) return error.StorageFailed;
        if (self.needs_resync) try self.resyncImage();
        if (self.rollover_pending) try self.completeClusterRollover();
        try self.ensureEpochCapacity();
        if (self.log.stop_pending or self.log.isReconfigured() != null) {
            return error.LogSealed;
        }
        try self.ensureWriter();
        if (self.capture_batch_id != null) return error.WriteInFlight;

        self.io.random(&self.live_batch_id_bytes);
        self.saved_error_len = 0;
        try self.db.exec("begin immediate");
        self.live_changes_base = self.totalChanges();
        self.live_transaction = true;
    }

    /// Executes one statement inside the live transaction under the
    /// application guard. Read statements run on the writer connection and
    /// observe uncommitted writes; DML `RETURNING` rows are captured into
    /// `out_returning`, which the caller owns.
    pub fn liveExec(
        self: *Node,
        gpa: std.mem.Allocator,
        sql: []const u8,
        values: []const prepared.Value,
        out_returning: *?TypedResult,
    ) !LiveStatementResult {
        if (!self.live_transaction) return error.NoTransaction;
        out_returning.* = null;
        var capture = WriteCapture{ .gpa = gpa };
        errdefer if (capture.returning) |*rows| rows.deinit();
        const changes_before = self.totalChanges();
        const rowid_before = self.db.lastInsertRowId();
        self.saved_error_len = 0;
        {
            self.guard.scope = .application;
            defer self.guard.scope = .internal;
            const statements = [_]prepared.Statement{.{
                .sql = sql,
                .values = values,
            }};
            self.executePreparedCapture(&statements, &capture) catch |err| {
                self.saveErrorFrom(&self.db);
                // A conflict-rollback or similar abort can end the whole
                // transaction inside SQLite; reflect that state so the
                // host sees the transaction as closed.
                if (!self.db.inTransaction()) self.live_transaction = false;
                return err;
            };
        }
        const rowid_after = self.db.lastInsertRowId();
        out_returning.* = capture.returning;
        return .{
            .changes = self.totalChanges() - changes_before,
            .last_insert_rowid = if (rowid_after != rowid_before)
                rowid_after
            else
                null,
        };
    }

    /// Host-managed savepoint operations. Names are SDK-generated ordinal
    /// identifiers executed under internal scope, so arbitrary application
    /// transaction-control SQL stays denied.
    pub fn liveSavepoint(self: *Node, index: u32) !void {
        try self.liveSavepointControl("savepoint zx_sp_{d}", index);
    }

    pub fn liveReleaseSavepoint(self: *Node, index: u32) !void {
        try self.liveSavepointControl("release zx_sp_{d}", index);
    }

    pub fn liveRollbackToSavepoint(self: *Node, index: u32) !void {
        try self.liveSavepointControl("rollback to zx_sp_{d}", index);
    }

    fn liveSavepointControl(
        self: *Node,
        comptime format: []const u8,
        index: u32,
    ) !void {
        if (!self.live_transaction) return error.NoTransaction;
        var buffer: [48]u8 = undefined;
        const sql = std.fmt.bufPrintZ(&buffer, format, .{index}) catch
            unreachable;
        self.db.exec(sql) catch |err| {
            self.saveErrorFrom(&self.db);
            return err;
        };
    }

    /// Commits the live transaction: verifies the capture contract, seals
    /// the batch marker, commits SQLite, and acknowledges only when the
    /// captured transition is decided and applied. The returned change
    /// count follows SQLite's total-changes semantics: work undone by a
    /// savepoint rollback still counts; per-statement counts from
    /// `liveExec` are the precise ones.
    pub fn commitLive(self: *Node) !ExecResult {
        if (!self.live_transaction) return error.NoTransaction;
        if (self.log.stop_pending or self.log.isReconfigured() != null) {
            return error.LogSealed;
        }
        const changes = self.totalChanges() - self.live_changes_base;
        self.live_transaction = false;
        errdefer self.db.exec("rollback") catch {};
        guard_mod.verifyCaptureContract(
            &self.db,
            self.page_size,
            &self.committed_frames,
        ) catch |err| {
            self.saveErrorText("application SQL broke the capture contract");
            return err;
        };
        return self.sealCapturedTransaction(
            self.live_batch_id_bytes,
            changes,
            null,
        );
    }

    /// Rolls the live transaction back; nothing is replicated. A rollback
    /// failure marks the image for resync so the connection cannot reuse
    /// an unknown writer state.
    pub fn rollbackLive(self: *Node) !void {
        if (!self.live_transaction) return error.NoTransaction;
        self.live_transaction = false;
        self.db.exec("rollback") catch |err| {
            self.saveErrorFrom(&self.db);
            self.needs_resync = true;
            return err;
        };
    }

    /// True while a Gate C live transaction is open on this node.
    pub fn inLiveTransaction(self: *const Node) bool {
        return self.live_transaction;
    }

    /// Executes prepared statements like `prepared.execute`, additionally
    /// collecting typed rows from the last row-producing statement (a DML
    /// `RETURNING` clause in the single-statement caller).
    fn executePreparedCapture(
        self: *Node,
        statements: []const prepared.Statement,
        capture: *WriteCapture,
    ) !void {
        for (statements) |statement| {
            var stmt = try self.db.prepare(statement.sql);
            defer stmt.finalize();
            try prepared.bind(&stmt, statement.values);
            const column_count = stmt.columnCount();
            if (column_count == 0) {
                while (try stmt.step()) {}
                continue;
            }
            if (capture.returning) |*previous| previous.deinit();
            capture.returning = null;
            var arena = std.heap.ArenaAllocator.init(capture.gpa);
            errdefer arena.deinit();
            const alloc = arena.allocator();
            const columns = try alloc.alloc([]const u8, column_count);
            for (columns, 0..) |*column, index| {
                column.* = try alloc.dupe(u8, stmt.columnName(@intCast(index)));
            }
            var rows: std.ArrayList([]const prepared.Value) = .empty;
            while (try stmt.step()) {
                const row = try alloc.alloc(prepared.Value, column_count);
                for (row, 0..) |*cell, index| {
                    const column: u32 = @intCast(index);
                    cell.* = switch (stmt.columnValueType(column)) {
                        .null => .null_value,
                        .integer => .{ .integer = stmt.columnInt64(column) },
                        .real => .{ .real = stmt.columnDouble(column) },
                        .text => .{
                            .text = try alloc.dupe(u8, stmt.columnText(column)),
                        },
                        .blob => .{
                            .blob = try alloc.dupe(u8, stmt.columnBlob(column)),
                        },
                    };
                }
                try rows.append(alloc, row);
            }
            capture.returning = .{
                .arena = arena,
                .columns = columns,
                .rows = try rows.toOwnedSlice(alloc),
            };
        }
    }

    /// The result of the most recent append made through this node. Hosts
    /// use it to await commitment of compound operations (session open)
    /// whose public API does not surface the slot.
    pub fn lastAppend(self: *const Node) ExecResult {
        return self.last_append;
    }

    fn ensureEpochCapacity(self: *Node) !void {
        if (self.epochNearlyFull()) {
            try self.snapshot();
        }
    }

    fn totalChanges(self: *Node) i64 {
        return self.db.totalChanges64();
    }

    /// The newest replicated search-feature version this binary serves
    /// (ZDS 0009). Version 1: FTS5, statically linked sqlite-vec, and the
    /// Zig fusion and distance SQL functions.
    pub const supported_search_feature_version: i64 = 1;

    /// Refuses to serve an image whose recorded search-feature version is
    /// newer than this binary implements. An image without the key
    /// predates the feature and serves normally; a directory without an
    /// image (witness, fresh member) has nothing to gate.
    fn verifySearchFeatureVersion(self: *Node) !void {
        if (!(self.schemaReady() catch false)) return;
        const stored = self.metaInt("search_feature_version") catch |err|
            switch (err) {
                error.MetaMissing => 0,
                else => return err,
            };
        self.search_feature_version = stored;
        if (stored > supported_search_feature_version) {
            self.saveErrorText(
                "image search-feature version is newer than this binary",
            );
            return error.SearchFeatureTooNew;
        }
    }

    /// Records search-feature version 1 in an image that predates it, as
    /// one replicated internal-scope write. Idempotent; an operator runs
    /// this only after every member serves a compatible binary (ZDS 0009
    /// rolling-upgrade rule). New databases record it at bootstrap.
    pub fn enableSearchFeature(self: *Node) !ExecResult {
        const result = try self.writeTransaction(
            .internal,
            "insert into __zaxon_meta(key, value) " ++
                "values ('search_feature_version', '1') " ++
                "on conflict(key) do nothing",
            null,
        );
        self.search_feature_version = supported_search_feature_version;
        return result;
    }

    fn metaInt(self: *Node, key: []const u8) !i64 {
        var lease = try self.readLease();
        defer lease.release();
        var stmt = try lease.db.prepare(
            "select value from __zaxon_meta where key = ?1",
        );
        defer stmt.finalize();
        try stmt.bindText(1, key);
        if (!try stmt.step()) return error.MetaMissing;
        return std.fmt.parseInt(i64, stmt.columnText(0), 10) catch error.MetaMissing;
    }

    fn saveErrorFrom(self: *Node, db: *const sqlite.Db) void {
        self.saveErrorText(db.errmsg());
        self.saved_error_code = db.extendedErrcode();
    }

    fn saveErrorText(self: *Node, message: []const u8) void {
        self.saved_error_len = @min(message.len, self.saved_error.len);
        @memcpy(
            self.saved_error[0..self.saved_error_len],
            message[0..self.saved_error_len],
        );
        self.saved_error_code = 0;
    }

    /// SQLite extended result code of the most recent saved SQL error, or
    /// the live connection's when nothing is saved. Hosts derive stable
    /// error categories from it instead of parsing message text.
    pub fn lastSqliteExtendedCode(self: *const Node) i32 {
        if (self.saved_error_len > 0) return self.saved_error_code;
        if (self.db_open) return self.db.extendedErrcode();
        return 0;
    }

    // ------------------------------------------------------------------
    // Read lease: the live connection, or a short-lived one
    // ------------------------------------------------------------------

    const ReadLease = struct {
        node: *Node,
        db: sqlite.Db,
        owned: bool,

        fn release(self: *ReadLease) void {
            if (self.owned) self.db.close();
            self.* = undefined;
        }
    };

    fn readLease(self: *Node) !ReadLease {
        if (self.db_open) {
            return .{ .node = self, .db = self.db, .owned = false };
        }
        self.dir.access(self.io, db_file_name, .{}) catch {
            return error.NoDatabaseImage;
        };
        const db = try sqlite.Db.openWithOptions(
            self.db_path,
            .{ .mmap_size = self.mmap_size },
        );
        self.effective_mmap_size = db.effective_mmap_size;
        return .{ .node = self, .db = db, .owned = true };
    }

    // ------------------------------------------------------------------
    // Effect handling
    // ------------------------------------------------------------------

    /// Applies one batch of protocol effects: journal writes, fsync,
    /// confirm, deliver self-addressed messages, queue peer messages, and
    /// account committed entries.
    fn consumeEffects(self: *Node) !void {
        while (true) {
            const writes = self.effects.writesSlice();
            if (writes.len > 0) {
                const requires_barrier = self.effects.requiresPowerLossBarrier();
                if (requires_barrier) {
                    self.journal.appendWrites(writes) catch |err| {
                        self.fatal_storage_error = true;
                        return err;
                    };
                    failpoint.hit("after_accept_append");

                    // Phase-two requests do not claim the leader's local vote
                    // is durable. Queue and release only those requests now so
                    // follower barriers overlap this node's barrier. The host
                    // mutex prevents a reply from entering the core early.
                    var early = self.effects.preDurableMessages();
                    var queued_early = false;
                    while (early.next()) |envelope| {
                        std.debug.assert(envelope.to != self.identity.node_id);
                        try self.outbox.append(self.gpa, envelope);
                        queued_early = true;
                    }
                    if (queued_early) {
                        if (self.pre_durable_outbox_hook) |hook| {
                            hook.run(hook.context) catch |err| {
                                // The request may already have reached a peer.
                                // Make the local vote durable before returning
                                // the transport failure to the host.
                                self.delayStorage();
                                self.journal.sync() catch |sync_err| {
                                    self.fatal_storage_error = true;
                                    return sync_err;
                                };
                                self.effects.confirmWritesDurable();
                                return err;
                            };
                        }
                    }
                    self.delayStorage();
                    self.journal.sync() catch |err| {
                        self.fatal_storage_error = true;
                        return err;
                    };
                    failpoint.hit("after_accept_sync");
                }
            }
            self.effects.confirmWritesDurable();
            if (self.effects.committedSlice().len > 0) {
                // Legacy failpoint name retained for crash-matrix stability.
                // Commit-only markers are now derived and need no second sync;
                // this boundary means chosen-before-materialized-apply.
                failpoint.hit("after_commit_sync_before_apply");
            }

            var pending: usize = 0;
            for (self.effects.messagesSlice()) |envelope| {
                // Already queued above when this transition had writes.
                if (self.effects.requiresPowerLossBarrier()) switch (envelope.message) {
                    .accept => continue,
                    else => {},
                };
                if (envelope.to == self.identity.node_id) {
                    self.inbox[pending] = envelope;
                    pending += 1;
                } else {
                    try self.outbox.append(self.gpa, envelope);
                }
            }
            self.accountCommitted(self.effects.committedSlice()) catch |err| {
                self.fatal_storage_error = true;
                return err;
            };
            self.effects.reset();
            if (pending == 0) return;
            for (self.inbox[0..pending]) |envelope| {
                try self.log.step(envelope, self.effects);
            }
        }
    }

    /// Effect handling during recovery, before chain state is rebuilt:
    /// committed entries are not accounted (rebuild does that from the log).
    fn consumeEffectsRecovery(self: *Node) !void {
        while (true) {
            const writes = self.effects.writesSlice();
            if (writes.len > 0) {
                self.journal.appendWrites(writes) catch |err| {
                    self.fatal_storage_error = true;
                    return err;
                };
                self.delayStorage();
                self.journal.sync() catch |err| {
                    self.fatal_storage_error = true;
                    return err;
                };
            }
            self.effects.confirmWritesDurable();
            var pending: usize = 0;
            for (self.effects.messagesSlice()) |envelope| {
                if (envelope.to == self.identity.node_id) {
                    self.inbox[pending] = envelope;
                    pending += 1;
                } else {
                    try self.outbox.append(self.gpa, envelope);
                }
            }
            self.effects.reset();
            if (pending == 0) return;
            for (self.inbox[0..pending]) |envelope| {
                try self.log.step(envelope, self.effects);
            }
        }
    }

    fn accountCommitted(self: *Node, committed: []const Log.Committed) !void {
        for (committed) |entry| {
            switch (entry.value) {
                .command => |cmd| switch (cmd) {
                    .noop, .read_barrier => {
                        if (self.capture_batch_id != null) {
                            // Our captured write lost its slot; the live
                            // WAL contains frames the log never decided.
                            self.capture_batch_id = null;
                            self.needs_resync = true;
                        }
                    },
                    .transaction_batch => |batch| {
                        if (batch.database_id != self.identity.database_id or
                            !std.mem.eql(u8, &batch.base_chain_hash, &self.last_chain) or
                            batch.base_data_slot != self.last_data_slot or
                            !command.chainValid(batch))
                        {
                            return error.ChainMismatch;
                        }
                        if (self.capture_batch_id) |pending| {
                            self.capture_batch_id = null;
                            if (pending != batch.batch_id) {
                                self.needs_resync = true;
                            }
                            // A matching batch is already materialized in
                            // the live WAL of the capture connection.
                        } else if (self.db_open) {
                            // A decision this live connection never
                            // captured: the image is stale.
                            self.needs_resync = true;
                        } else {
                            failpoint.hit("before_apply");
                            try self.applyBatchOffline(batch);
                        }
                        self.last_chain = batch.result_chain_hash;
                        self.last_data_slot = entry.slot;
                    },
                },
                .stop => {
                    if (self.capture_batch_id != null) {
                        self.capture_batch_id = null;
                        self.needs_resync = true;
                    }
                    self.rollover_pending = true;
                },
            }
            self.applied_slot = entry.slot;
        }
    }

    fn delayStorage(self: *Node) void {
        if (self.test_storage_delay_ms == 0) return;
        self.io.sleep(
            .fromMilliseconds(@intCast(self.test_storage_delay_ms)),
            .awake,
        ) catch {};
    }

    /// True when the host must run `resyncImage` before further service.
    pub fn needsResync(self: *const Node) bool {
        return self.needs_resync;
    }

    pub fn storageFailed(self: *const Node) bool {
        return self.fatal_storage_error;
    }

    /// Applies one committed payload offline to the materialized image.
    fn applyBatchOffline(self: *Node, batch: command.TransactionBatch) !void {
        const payload = self.store.load(self.gpa, batch.payload_hash) catch {
            return error.PayloadMissing;
        };
        defer self.gpa.free(payload);
        const view = try self.validateBatchPayload(batch, payload);
        // Stale working artifacts from a previous read connection.
        self.dir.deleteFile(self.io, wal_file_name) catch {};
        self.dir.deleteFile(self.io, shm_file_name) catch {};
        const file = try self.dir.createFile(self.io, db_file_name, .{
            .read = true,
            .truncate = false,
        });
        defer file.close(self.io);
        try wal.applyPayload(self.io, file, &view);
        // `current.db` is a materialized cache, rebuilt from the snapshot,
        // accepted journal records, and payload store on every open. The page
        // writes need to finish before local reads, but do not require a
        // second power-loss barrier per chosen transaction.
    }

    /// Cross-checks the fixed Paxos descriptor against the immutable payload.
    /// A valid content hash alone is not enough: descriptor counts, database
    /// identity, and page geometry are part of the replicated transition.
    fn validateBatchPayload(
        self: *Node,
        batch: command.TransactionBatch,
        payload: []const u8,
    ) !wal.PayloadView {
        if (batch.database_id != self.identity.database_id) {
            return error.DatabaseMismatch;
        }
        if (payload.len != batch.payload_bytes) return error.PayloadCorrupt;
        const view = try wal.PayloadView.parse(payload);
        if (view.database_id != batch.database_id) return error.DatabaseMismatch;
        if (view.transaction_count != batch.transaction_count or
            view.frame_count != batch.frame_count or
            view.page_size != self.page_size)
        {
            return error.PayloadDescriptorMismatch;
        }
        return view;
    }

    // ------------------------------------------------------------------
    // Recovery
    // ------------------------------------------------------------------

    /// Rebuilds the materialized SQLite image from the snapshot base plus
    /// every committed transaction payload of the current epoch, applying
    /// pages offline in slot order.
    fn rebuildMaterializedImage(self: *Node) !void {
        std.debug.assert(!self.db_open);
        // SQLite's own WAL is a working artifact, never authoritative.
        self.dir.deleteFile(self.io, wal_file_name) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        self.dir.deleteFile(self.io, shm_file_name) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };

        // The image is never an input to recovery. Reusing it would allow a
        // speculative or corrupted page inherited from the snapshot base but
        // untouched by this epoch's suffix to survive replay.
        self.dir.deleteFile(self.io, db_file_name) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        var snapshot_covers_current_epoch = false;
        if (try self.currentSnapshotName()) |name| {
            const sealed_configuration = try self.snapshotSealedConfiguration(name);
            if (sealed_configuration == self.identity.configuration_id) {
                // Crash after CURRENT installation but before identity/journal
                // rollover: this generation already covers the sealed epoch.
                if (self.log.isReconfigured() == null) return error.CorruptManifest;
                snapshot_covers_current_epoch = true;
            } else if (sealed_configuration == std.math.maxInt(u64) or
                sealed_configuration + 1 != self.identity.configuration_id)
            {
                return error.ConfigurationMismatch;
            }
            var snapshot_db_path_buffer: [64]u8 = undefined;
            const snapshot_db_path = std.fmt.bufPrint(
                &snapshot_db_path_buffer,
                "snapshots/{s}/db",
                .{&name},
            ) catch unreachable;
            try self.dir.copyFile(snapshot_db_path, self.dir, db_file_name, self.io, .{});
        }

        self.last_chain = try self.epochBaseChain();
        self.last_data_slot = 0;
        self.applied_slot = 0;
        self.rollover_pending = false;

        const decided = self.log.decidedThrough();
        if (decided == 0) return;

        if (snapshot_covers_current_epoch) {
            self.applied_slot = decided;
            self.rollover_pending = true;
            return;
        }

        const file = try self.dir.createFile(self.io, db_file_name, .{
            .read = true,
            .truncate = false,
        });
        defer file.close(self.io);

        var slot: paxos.Slot = 1;
        while (slot <= decided) : (slot += 1) {
            const entry = self.log.read(slot) orelse return error.MissingCommitted;
            switch (entry) {
                .command => |cmd| switch (cmd) {
                    .noop, .read_barrier => {},
                    .transaction_batch => |batch| {
                        if (batch.database_id != self.identity.database_id or
                            !std.mem.eql(u8, &batch.base_chain_hash, &self.last_chain) or
                            batch.base_data_slot != self.last_data_slot or
                            !command.chainValid(batch))
                        {
                            return error.ChainMismatch;
                        }
                        const payload = self.store.load(self.gpa, batch.payload_hash) catch {
                            // A committed descriptor without payload bytes:
                            // this node must not serve.
                            return error.PayloadMissing;
                        };
                        defer self.gpa.free(payload);
                        const view = try self.validateBatchPayload(batch, payload);
                        try wal.applyPayload(self.io, file, &view);
                        self.last_chain = batch.result_chain_hash;
                        self.last_data_slot = slot;
                    },
                },
                .stop => {
                    self.rollover_pending = true;
                },
            }
            self.applied_slot = slot;
        }
        try durability.syncFile(self.io, file);
    }

    fn openLiveDatabase(self: *Node) !void {
        self.db = try sqlite.Db.openWithOptions(
            self.db_path,
            .{ .mmap_size = self.mmap_size },
        );
        self.effective_mmap_size = self.db.effective_mmap_size;
        errdefer self.db.close();
        try self.db.exec("pragma page_size = 4096");
        try self.db.exec("pragma journal_mode = wal");
        try self.db.exec("pragma wal_autocheckpoint = 0");
        try self.db.exec("pragma synchronous = normal");
        try self.db.exec("pragma foreign_keys = on");
        self.committed_frames = 0;
        self.captured_frames = 0;
        self.db.trackCommittedFrames(&self.committed_frames);
        self.page_size = try self.db.pageSize();
        // The guard outlives the connection: it is embedded in this Node,
        // and every application statement below runs through it.
        self.guard.scope = .internal;
        self.guard.install(&self.db);
        self.db_open = true;
    }

    fn bootstrapSchema(self: *Node) !void {
        _ = try self.bootstrapSchemaIfMissing();
    }

    /// Replicates the schema bootstrap batch when it is absent. Runs in
    /// internal scope: bootstrap creates the reserved `__zaxon_*` tables
    /// that the application authorizer denies. An already present schema
    /// returns a replayed result, so a raced bootstrap is harmless.
    pub fn bootstrapSchemaIfMissing(self: *Node) !ExecResult {
        if (try self.schemaReady()) {
            return .{ .changes = 0, .slot = 0, .replayed = true };
        }
        const sql = try self.bootstrapSql(self.gpa);
        defer self.gpa.free(sql);
        return self.writeTransaction(.internal, sql, null);
    }

    /// After rebuild, the materialized image's recorded batch marker must
    /// match the last committed transaction batch of the epoch.
    fn validateMaterializedBatch(self: *Node) !void {
        if (self.last_data_slot == 0) return;
        const entry = self.log.read(self.last_data_slot) orelse return error.MissingCommitted;
        const batch = entry.command.transaction_batch;
        var batch_id_bytes: [16]u8 = undefined;
        std.mem.writeInt(u128, &batch_id_bytes, batch.batch_id, .little);
        const expected = std.fmt.bytesToHex(batch_id_bytes, .lower);

        var lease = try self.readLease();
        defer lease.release();
        var stmt = try lease.db.prepare(
            "select value from __zaxon_meta where key = 'batch_id'",
        );
        defer stmt.finalize();
        if (!try stmt.step()) return error.StateMismatch;
        if (!std.mem.eql(u8, stmt.columnText(0), &expected)) {
            return error.StateMismatch;
        }
    }

    /// The chain identity at the base of the current epoch: the snapshot
    /// manifest's chain, or the genesis chain for a fresh database.
    fn epochBaseChain(self: *Node) !command.HashBytes {
        if (try self.currentSnapshotName()) |name| {
            var manifest_path_buffer: [64]u8 = undefined;
            const manifest_path = std.fmt.bufPrint(
                &manifest_path_buffer,
                "snapshots/{s}/manifest",
                .{&name},
            ) catch unreachable;
            const manifest = try self.dir.readFileAlloc(
                self.io,
                manifest_path,
                self.gpa,
                .limited(4096),
            );
            defer self.gpa.free(manifest);
            const chain_hex = manifestValue(manifest, "chain") orelse
                return error.CorruptManifest;
            if (chain_hex.len != 64) return error.CorruptManifest;
            var chain: command.HashBytes = undefined;
            _ = std.fmt.hexToBytes(&chain, chain_hex) catch return error.CorruptManifest;
            return chain;
        }
        return command.genesisChain(self.identity.database_id);
    }

    fn snapshotSealedConfiguration(self: *Node, name: [16]u8) !u64 {
        var manifest_path_buffer: [64]u8 = undefined;
        const manifest_path = std.fmt.bufPrint(
            &manifest_path_buffer,
            "snapshots/{s}/manifest",
            .{&name},
        ) catch unreachable;
        const manifest = try self.dir.readFileAlloc(
            self.io,
            manifest_path,
            self.gpa,
            .limited(4096),
        );
        defer self.gpa.free(manifest);
        const sealed_text = manifestValue(manifest, "sealed_configuration_id") orelse
            return error.CorruptManifest;
        return std.fmt.parseInt(u64, sealed_text, 10) catch
            error.CorruptManifest;
    }

    /// Validates every field that binds an installed snapshot generation to
    /// this database and verifies the image digest before it can become a
    /// recovery base. Returns the sealed (previous) configuration ID.
    fn validateSnapshotGeneration(self: *Node, name: [16]u8) !u64 {
        var directory_path_buffer: [64]u8 = undefined;
        const directory_path = std.fmt.bufPrint(
            &directory_path_buffer,
            "snapshots/{s}",
            .{&name},
        ) catch unreachable;
        var snapshot_dir = try self.dir.openDir(self.io, directory_path, .{});
        defer snapshot_dir.close(self.io);
        const manifest = try snapshot_dir.readFileAlloc(
            self.io,
            "manifest",
            self.gpa,
            .limited(4096),
        );
        defer self.gpa.free(manifest);

        const format = manifestValue(manifest, "format") orelse
            return error.CorruptManifest;
        if (!std.mem.eql(u8, format, "1")) return error.CorruptManifest;
        const database_text = manifestValue(manifest, "database_id") orelse
            return error.CorruptManifest;
        const database_id = std.fmt.parseInt(u128, database_text, 16) catch
            return error.CorruptManifest;
        if (database_id != self.identity.database_id) return error.DatabaseMismatch;
        const sealed_text = manifestValue(manifest, "sealed_configuration_id") orelse
            return error.CorruptManifest;
        const sealed = std.fmt.parseInt(u64, sealed_text, 10) catch
            return error.CorruptManifest;
        var expected_name_buffer: [16]u8 = undefined;
        const expected_name = std.fmt.bufPrint(
            &expected_name_buffer,
            "{x:0>16}",
            .{sealed},
        ) catch unreachable;
        if (!std.mem.eql(u8, expected_name, &name)) return error.CorruptManifest;
        const applied = manifestValue(manifest, "applied_slot") orelse
            return error.CorruptManifest;
        _ = std.fmt.parseInt(paxos.Slot, applied, 10) catch
            return error.CorruptManifest;
        const chain_hex = manifestValue(manifest, "chain") orelse
            return error.CorruptManifest;
        var chain: command.HashBytes = undefined;
        if (chain_hex.len != chain.len * 2) return error.CorruptManifest;
        _ = std.fmt.hexToBytes(&chain, chain_hex) catch return error.CorruptManifest;
        const digest_hex = manifestValue(manifest, "db_sha256") orelse
            return error.CorruptManifest;
        var expected_digest: [32]u8 = undefined;
        if (digest_hex.len != expected_digest.len * 2) return error.CorruptManifest;
        _ = std.fmt.hexToBytes(&expected_digest, digest_hex) catch
            return error.CorruptManifest;
        const actual_digest = try fileSha256(self.io, snapshot_dir, "db");
        if (!std.mem.eql(u8, &actual_digest, &expected_digest)) {
            return error.SnapshotDigestMismatch;
        }
        return sealed;
    }

    /// Switches an interrupted receiver to the empty epoch immediately after
    /// its verified snapshot. The old journal remains as a recovery fallback
    /// and is collected by a later successful rollover.
    fn activateInstalledSnapshot(
        self: *Node,
        configuration_id: u64,
        membership: *const Log.Membership,
    ) !void {
        var new_journal = Journal.create(
            self.io,
            self.dir,
            configuration_id,
        ) catch |err| switch (err) {
            error.PathAlreadyExists => blk: {
                const durable = try self.gpa.create(Log.DurableState);
                defer self.gpa.destroy(durable);
                durable.* = .{};
                var info: journal_mod.ReplayInfo = undefined;
                var opened = try Journal.open(
                    self.io,
                    self.gpa,
                    self.dir,
                    configuration_id,
                    durable,
                    &info,
                );
                if (info.record_count != 0) {
                    opened.close();
                    return error.ConfigurationMismatch;
                }
                break :blk opened;
            },
            else => return err,
        };
        var journal_installed = false;
        errdefer if (!journal_installed) new_journal.close();

        // A crash advanced CURRENT before the identity file; the registry
        // pointer sits between them in the recovery order, so it may also
        // need to advance before identity moves.
        if (self.decidedRegistry()) |decided| {
            if (decided.configuration_id < configuration_id) {
                var name_buffer: [16]u8 = undefined;
                const sealed_name = std.fmt.bufPrint(
                    &name_buffer,
                    "{x:0>16}",
                    .{configuration_id - 1},
                ) catch unreachable;
                var proof_path_buffer: [64]u8 = undefined;
                const proof_path = std.fmt.bufPrint(
                    &proof_path_buffer,
                    "snapshots/{s}/proof",
                    .{sealed_name},
                ) catch unreachable;
                const proof_bytes = try self.dir.readFileAlloc(
                    self.io,
                    proof_path,
                    self.gpa,
                    .limited(4096),
                );
                defer self.gpa.free(proof_bytes);
                const proof = try checkpoint_proof.decode(proof_bytes);
                const parsed = try parseStopMetadata(proof.metadataSlice());
                const next = try reconstructNextRegistry(
                    decided,
                    &parsed,
                    configuration_id,
                );
                try registry.storeBlob(self.io, self.dir, &next);
                try registry.activatePointer(self.io, self.dir, next.configuration_id);
                self.decided_registry = next;
            }
        }

        try writeIdentity(self.io, self.dir, .{
            .node_id = self.identity.node_id,
            .database_id = self.identity.database_id,
            .configuration_id = configuration_id,
            .role = self.identity.role,
        });
        self.journal.close();
        self.journal = new_journal;
        journal_installed = true;
        self.identity.configuration_id = configuration_id;
        try self.initLogForRole(configuration_id, membership);
    }

    fn currentSnapshotName(self: *Node) !?[16]u8 {
        const bytes = self.dir.readFileAlloc(
            self.io,
            current_file_name,
            self.gpa,
            .limited(64),
        ) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        defer self.gpa.free(bytes);
        const trimmed = std.mem.trim(u8, bytes, " \n");
        if (trimmed.len != 16) return error.CorruptCurrentPointer;
        return trimmed[0..16].*;
    }

    // ------------------------------------------------------------------
    // Epoch rollover
    // ------------------------------------------------------------------

    /// Completes a decided checkpoint on any member. A follower first
    /// materializes its own snapshot generation from the offline image;
    /// the leader (or a one-member node) already built it while preparing
    /// the checkpoint.
    pub fn completeClusterRollover(self: *Node) !void {
        try self.completeClusterRolloverDeferred();
        try self.activateRollover();
    }

    /// Installs the next epoch without emitting its first campaign. A
    /// transport host calls `activateRollover` only after publishing the
    /// matching peer generation.
    pub fn completeClusterRolloverDeferred(self: *Node) !void {
        const stop = self.log.isReconfigured() orelse return error.NoStopSign;
        if (!self.db_open) {
            try self.buildFollowerSnapshot(&stop);
        }
        try self.completeRollover();
    }

    pub fn activateRollover(self: *Node) !void {
        if (!self.rollover_campaign_pending) return;
        self.rollover_campaign_pending = false;
        try self.log.campaign(.noop, self.effects);
        try self.consumeEffects();
    }

    /// Builds this member's snapshot generation for a decided stop sign
    /// from the fully applied materialized image, and verifies that its
    /// manifest digest matches the decided metadata. Deterministic page
    /// application makes the generation byte-identical to the leader's.
    fn buildFollowerSnapshot(self: *Node, stop: *const Log.StopSign) !void {
        const parsed = try parseStopMetadata(stop.metadataSlice());

        // Already built (crash between build and rollover completion).
        var manifest_path_buffer: [64]u8 = undefined;
        const manifest_path = std.fmt.bufPrint(
            &manifest_path_buffer,
            "snapshots/{s}/manifest",
            .{&parsed.name},
        ) catch unreachable;
        if (self.dir.access(self.io, manifest_path, .{})) |_| {
            return;
        } else |_| {}

        // Every slot before the stop sign is applied; the image file is
        // the canonical checkpointed database. The manifest records the
        // slot before the stop sign, matching the proposer's view.
        const stop_slot = self.log.stopSlot() orelse return error.NoStopSign;
        if (self.applied_slot < stop_slot) return error.NotCaughtUp;
        // A follower reproduces the leader's metadata exactly, including
        // the replacement seed the chosen stop sign carries.
        const request: ?registry.ReplacementRequest = if (parsed.seed) |*seed| .{
            .operation_id = seed.operation_id,
            .expected_configuration_id = self.identity.configuration_id,
            .old_node_id = seed.old_node_id,
            .new_node_id = seed.new_node_id,
            .new_endpoint = seed.endpointSlice(),
        } else null;
        const metadata = try self.buildSnapshotGeneration(
            stop_slot - 1,
            if (request) |*live| live else null,
        );
        if (!std.mem.eql(u8, metadata.slice(), stop.metadataSlice())) {
            return error.SnapshotDigestMismatch;
        }
    }

    /// The bounded replacement seed carried by zx2 stop metadata. It makes
    /// the next registry a pure function of the current registry and the
    /// chosen stop sign, so survivors reconstruct it without the network.
    const StopSeed = struct {
        operation_id: u64,
        old_node_id: paxos.NodeId,
        new_node_id: paxos.NodeId,
        endpoint: [registry.max_endpoint_bytes]u8,
        endpoint_len: u8,

        fn endpointSlice(self: *const StopSeed) []const u8 {
            return self.endpoint[0..self.endpoint_len];
        }
    };

    const StopMetadata = struct {
        name: [16]u8,
        manifest_hash: [32]u8,
        /// Digest of the canonical next decided registry; null for `zx1`
        /// metadata written by registry-less embedded and local hosts.
        registry_digest: ?[32]u8,
        /// Present only for a decided voter replacement.
        seed: ?StopSeed,
    };

    fn parseStopMetadata(metadata: []const u8) !StopMetadata {
        var parts = std.mem.tokenizeScalar(u8, metadata, ' ');
        const tag = parts.next() orelse return error.CorruptStopSign;
        const versioned = std.mem.eql(u8, tag, "zx2");
        if (!versioned and !std.mem.eql(u8, tag, "zx1")) {
            return error.CorruptStopSign;
        }
        const snapshot_name = parts.next() orelse return error.CorruptStopSign;
        if (snapshot_name.len != 16) return error.CorruptStopSign;
        const manifest_hash_hex = parts.next() orelse return error.CorruptStopSign;
        if (manifest_hash_hex.len != 64) return error.CorruptStopSign;
        var result = StopMetadata{
            .name = snapshot_name[0..16].*,
            .manifest_hash = undefined,
            .registry_digest = null,
            .seed = null,
        };
        _ = std.fmt.hexToBytes(&result.manifest_hash, manifest_hash_hex) catch
            return error.CorruptStopSign;
        if (versioned) {
            const registry_hex = parts.next() orelse return error.CorruptStopSign;
            if (registry_hex.len != 64) return error.CorruptStopSign;
            var registry_digest: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&registry_digest, registry_hex) catch
                return error.CorruptStopSign;
            result.registry_digest = registry_digest;
            if (parts.next()) |operation_hex| {
                if (operation_hex.len != 16) return error.CorruptStopSign;
                const old_hex = parts.next() orelse return error.CorruptStopSign;
                if (old_hex.len != 8) return error.CorruptStopSign;
                const new_hex = parts.next() orelse return error.CorruptStopSign;
                if (new_hex.len != 8) return error.CorruptStopSign;
                const endpoint = parts.next() orelse return error.CorruptStopSign;
                registry.validateEndpoint(endpoint) catch
                    return error.CorruptStopSign;
                var seed = StopSeed{
                    .operation_id = std.fmt.parseInt(u64, operation_hex, 16) catch
                        return error.CorruptStopSign,
                    .old_node_id = std.fmt.parseInt(paxos.NodeId, old_hex, 16) catch
                        return error.CorruptStopSign,
                    .new_node_id = std.fmt.parseInt(paxos.NodeId, new_hex, 16) catch
                        return error.CorruptStopSign,
                    .endpoint = [_]u8{0} ** registry.max_endpoint_bytes,
                    .endpoint_len = @intCast(endpoint.len),
                };
                @memcpy(seed.endpoint[0..endpoint.len], endpoint);
                result.seed = seed;
            }
        }
        if (parts.next() != null) return error.CorruptStopSign;
        return result;
    }

    /// Reconstructs and verifies the decided next registry named by stop
    /// metadata. Deterministic: a same-member rollover is the checkpoint
    /// successor, a replacement applies the metadata seed, and a lagging
    /// member first fast-forwards through unchanged-member epochs. The
    /// digest bound into the chosen stop sign is the only acceptance test.
    fn reconstructNextRegistry(
        decided: *const registry.Decided,
        parsed: *const StopMetadata,
        next_configuration: u64,
    ) !registry.Decided {
        const expected_digest = parsed.registry_digest orelse
            return error.CorruptStopSign;
        var base = decided.*;
        if (base.configuration_id == next_configuration) {
            // The pointer already advanced in a previous crashed rollover.
            if (!std.mem.eql(u8, &base.digest(), &expected_digest)) {
                return error.RegistryDigestMismatch;
            }
            return base;
        }
        const sealed = next_configuration - 1;
        if (base.configuration_id < sealed) {
            base.predecessor_configuration_id = sealed - 1;
            base.configuration_id = sealed;
        }
        const next = blk: {
            if (parsed.seed) |*seed| {
                const request = registry.ReplacementRequest{
                    .operation_id = seed.operation_id,
                    .expected_configuration_id = base.configuration_id,
                    .old_node_id = seed.old_node_id,
                    .new_node_id = seed.new_node_id,
                    .new_endpoint = seed.endpointSlice(),
                };
                break :blk base.successor(&request) catch
                    return error.RegistryDigestMismatch;
            }
            break :blk base.checkpointSuccessor() catch
                return error.RegistryDigestMismatch;
        };
        if (next.configuration_id != next_configuration) {
            return error.RegistryDigestMismatch;
        }
        if (!std.mem.eql(u8, &next.digest(), &expected_digest)) {
            return error.RegistryDigestMismatch;
        }
        return next;
    }

    /// Finishes a decided checkpoint: installs the snapshot pointer, starts
    /// the next epoch's journal, switches the protocol node to the new
    /// configuration, and garbage-collects covered files.
    fn completeRollover(self: *Node) !void {
        const stop = self.log.isReconfigured() orelse return error.NoStopSign;
        const stop_slot = self.log.stopSlot() orelse return error.NoStopSign;
        const parsed = try parseStopMetadata(stop.metadataSlice());

        // A voter the chosen stop sign removed must not enter the next
        // configuration. It stays permanently sealed, and the allocation
        // fence retires its ID forever.
        if (self.capabilities.votes) {
            var still_member = false;
            for (stop.membersSlice()) |member| {
                if (member == self.identity.node_id) still_member = true;
            }
            if (!still_member) return error.RetiredByReconfiguration;
        }

        // The snapshot generation must exist and match the decided digest.
        var manifest_path_buffer: [64]u8 = undefined;
        const manifest_path = std.fmt.bufPrint(
            &manifest_path_buffer,
            "snapshots/{s}/manifest",
            .{&parsed.name},
        ) catch unreachable;
        const manifest = try self.dir.readFileAlloc(
            self.io,
            manifest_path,
            self.gpa,
            .limited(4096),
        );
        defer self.gpa.free(manifest);
        const manifest_digest = PayloadStore.hashOf(manifest);
        if (!std.mem.eql(u8, &manifest_digest, &parsed.manifest_hash)) {
            return error.SnapshotDigestMismatch;
        }
        const sealed_configuration = try self.validateSnapshotGeneration(parsed.name);
        if (sealed_configuration != self.identity.configuration_id) {
            return error.ConfigurationMismatch;
        }

        // Reconstruct, verify, and durably store the decided next registry
        // before any pointer advances. The digest bound into the chosen
        // stop sign is the only acceptance test; a mismatch stops the
        // rollover instead of activating a divergent registry.
        var next_registry: ?registry.Decided = null;
        if (self.decidedRegistry()) |decided| {
            const next = try reconstructNextRegistry(
                decided,
                &parsed,
                stop.configuration_id,
            );
            try registry.storeBlob(self.io, self.dir, &next);
            failpoint.hit("after_registry_blob");
            next_registry = next;
        } else if (parsed.registry_digest != null) {
            // A registry-less host must not blindly accept registry-bound
            // metadata it cannot verify.
            return error.CorruptStopSign;
        }

        // Retain the exact already-chosen stop sign beside the image. This
        // is deliberately not a signature over a locally materialized
        // SQLite file and does not add a consensus round: all fields below
        // are either the chosen stop value or values bound by its manifest
        // digest. A lagging receiver asks a read quorum to confirm the
        // canonical proof digest before installing the transferred image.
        const proof = try checkpoint_proof.create(
            self.identity.database_id,
            self.identity.configuration_id,
            stop.configuration_id,
            stop_slot,
            stop_slot - 1,
            self.last_chain,
            manifest_digest,
            parsed.registry_digest orelse checkpoint_proof.no_registry_digest,
            self.members[0..self.member_count],
            stop.membersSlice(),
            stop.metadataSlice(),
        );
        var snapshot_path_buffer: [64]u8 = undefined;
        const snapshot_path = std.fmt.bufPrint(
            &snapshot_path_buffer,
            "snapshots/{s}",
            .{&parsed.name},
        ) catch unreachable;
        var snapshot_dir = try self.dir.openDir(self.io, snapshot_path, .{});
        defer snapshot_dir.close(self.io);
        try atomicWriteFile(self.io, snapshot_dir, "proof", proof.slice());

        // Collect payload hashes still referenced by the sealed epoch before
        // its in-memory state is replaced; they stay until its journal is
        // garbage-collected.
        var retained = std.AutoHashMap([32]u8, void).init(self.gpa);
        defer retained.deinit();
        try self.collectReferencedPayloads(&retained);

        const was_leader = self.log.core.role == .leader;

        // Install the snapshot pointer first: a crash before the identity
        // update replays the sealed epoch and re-runs this function.
        try atomicWriteFile(self.io, self.dir, current_file_name, &parsed.name);

        // The registry pointer advances after the snapshot pointer and
        // before the identity file, extending the recovery order: a crash
        // on either side of it converges through this same function.
        if (next_registry) |*next| {
            try registry.activatePointer(self.io, self.dir, next.configuration_id);
            failpoint.hit("after_registry_pointer");
        }

        const old_configuration = self.identity.configuration_id;
        const new_configuration = stop.configuration_id;

        var new_journal = Journal.create(
            self.io,
            self.dir,
            new_configuration,
        ) catch |err| switch (err) {
            error.PathAlreadyExists => blk: {
                // A previous rollover attempt crashed after creating the
                // file; it can only be empty or already truncated.
                const durable = try self.gpa.create(Log.DurableState);
                defer self.gpa.destroy(durable);
                durable.* = .{};
                var info: journal_mod.ReplayInfo = undefined;
                var opened = try Journal.open(
                    self.io,
                    self.gpa,
                    self.dir,
                    new_configuration,
                    durable,
                    &info,
                );
                if (info.record_count != 0) {
                    opened.close();
                    return error.ConfigurationMismatch;
                }
                break :blk opened;
            },
            else => return err,
        };
        var journal_installed = false;
        errdefer if (!journal_installed) new_journal.close();

        try writeIdentity(self.io, self.dir, .{
            .node_id = self.identity.node_id,
            .database_id = self.identity.database_id,
            .configuration_id = new_configuration,
            .role = self.identity.role,
        });
        self.identity.configuration_id = new_configuration;

        self.journal.close();
        self.journal = new_journal;
        journal_installed = true;

        // The chosen stop sign is the membership authority for the next
        // configuration: the host's member array follows it, so snapshot
        // installation and proof validation can never read a stale set.
        const stop_members = stop.membersSlice();
        @memcpy(self.members[0..stop_members.len], stop_members);
        self.member_count = @intCast(stop_members.len);
        if (next_registry) |next| self.decided_registry = next;

        var membership: Log.Membership = undefined;
        try membership.init(stop_members);
        try self.initLogForRole(new_configuration, &membership);
        self.applied_slot = 0;
        self.last_data_slot = 0;
        self.rollover_pending = false;
        self.last_chain = try self.epochBaseChain();
        self.rollover_campaign_pending =
            self.capabilities.campaigns and (self.single or was_leader);

        // The decided registry ring now records the operation outcome; the
        // scratch pending record has served its purpose.
        try self.clearPendingOperation();

        try self.garbageCollect(old_configuration, &retained);
    }

    // ------------------------------------------------------------------
    // Snapshot install (lagging member joining a newer epoch)
    // ------------------------------------------------------------------

    /// Directory that accumulates a snapshot transfer in progress.
    pub fn beginSnapshotInstall(self: *Node) !Io.Dir {
        self.dir.deleteTree(self.io, install_tmp_dir) catch {};
        return self.dir.createDirPathOpen(self.io, install_tmp_dir, .{});
    }

    /// Installs a transferred snapshot generation and jumps this member to
    /// `configuration_id` with an empty journal. The transfer directory
    /// must contain the database image under `db`; `manifest` is the
    /// generation manifest bytes.
    pub fn installSnapshot(
        self: *Node,
        configuration_id: u64,
        name: [16]u8,
        manifest: []const u8,
        proof_bytes: []const u8,
        registry_blob: ?[]const u8,
    ) !void {
        if (configuration_id <= self.identity.configuration_id) {
            self.dir.deleteTree(self.io, install_tmp_dir) catch {};
            return error.StaleSnapshot;
        }

        // Validate the already-chosen stop evidence before trusting the
        // transferred image. The transport host separately confirms this
        // proof digest with a voter quorum.
        _ = try self.validateCheckpointProof(
            proof_bytes,
            configuration_id,
            name,
            manifest,
        );

        // Validate the transferred image against the manifest.
        const format = manifestValue(manifest, "format") orelse
            return error.CorruptManifest;
        if (!std.mem.eql(u8, format, "1")) return error.CorruptManifest;
        const database_text = manifestValue(manifest, "database_id") orelse
            return error.CorruptManifest;
        const database_id = std.fmt.parseInt(u128, database_text, 16) catch
            return error.CorruptManifest;
        if (database_id != self.identity.database_id) return error.DatabaseMismatch;
        const sealed_text = manifestValue(manifest, "sealed_configuration_id") orelse
            return error.CorruptManifest;
        const sealed_configuration = std.fmt.parseInt(u64, sealed_text, 10) catch
            return error.CorruptManifest;
        if (sealed_configuration == std.math.maxInt(u64) or
            sealed_configuration + 1 != configuration_id)
        {
            return error.ConfigurationMismatch;
        }
        var expected_name_buffer: [16]u8 = undefined;
        const expected_name = std.fmt.bufPrint(
            &expected_name_buffer,
            "{x:0>16}",
            .{sealed_configuration},
        ) catch unreachable;
        if (!std.mem.eql(u8, expected_name, &name)) return error.CorruptManifest;
        const applied_text = manifestValue(manifest, "applied_slot") orelse
            return error.CorruptManifest;
        _ = std.fmt.parseInt(paxos.Slot, applied_text, 10) catch
            return error.CorruptManifest;
        const chain_hex = manifestValue(manifest, "chain") orelse
            return error.CorruptManifest;
        var snapshot_chain: command.HashBytes = undefined;
        if (chain_hex.len != snapshot_chain.len * 2) return error.CorruptManifest;
        _ = std.fmt.hexToBytes(&snapshot_chain, chain_hex) catch
            return error.CorruptManifest;
        const digest_hex = manifestValue(manifest, "db_sha256") orelse
            return error.CorruptManifest;
        var expected_digest: [32]u8 = undefined;
        if (digest_hex.len != 64) return error.CorruptManifest;
        _ = std.fmt.hexToBytes(&expected_digest, digest_hex) catch
            return error.CorruptManifest;
        {
            var tmp_dir = try self.dir.openDir(self.io, install_tmp_dir, .{});
            defer tmp_dir.close(self.io);
            const actual = try fileSha256(self.io, tmp_dir, "db");
            if (!std.mem.eql(u8, &actual, &expected_digest)) {
                return error.SnapshotDigestMismatch;
            }
            try atomicWriteFile(self.io, tmp_dir, "manifest", manifest);
            try atomicWriteFile(self.io, tmp_dir, "proof", proof_bytes);
        }

        // Advance the decided registry along with the installed epoch. The
        // stop metadata inside the proof binds the target registry digest;
        // a member with a predecessor registry reconstructs the next one
        // locally, while a joining replacement verifies the fetched blob
        // against that quorum-confirmed digest. Both fail closed.
        var next_registry: ?registry.Decided = null;
        if (self.decidedRegistry()) |decided| {
            const proof = try checkpoint_proof.decode(proof_bytes);
            const parsed = try parseStopMetadata(proof.metadataSlice());
            const next = try reconstructNextRegistry(
                decided,
                &parsed,
                configuration_id,
            );
            try registry.storeBlob(self.io, self.dir, &next);
            failpoint.hit("after_registry_blob");
            next_registry = next;
        } else if (registry_blob) |blob| {
            const proof = try checkpoint_proof.decode(proof_bytes);
            const parsed = try parseStopMetadata(proof.metadataSlice());
            const expected_registry_digest = parsed.registry_digest orelse
                return error.CorruptRegistry;
            if (blob.len <= 32) return error.CorruptRegistry;
            const encoded = blob[0 .. blob.len - 32];
            const blob_digest = PayloadStore.hashOf(encoded);
            if (!std.mem.eql(u8, &blob_digest, blob[blob.len - 32 ..]) or
                !std.mem.eql(u8, &blob_digest, &expected_registry_digest) or
                !std.mem.eql(u8, &blob_digest, &proof.next_registry_digest))
            {
                return error.RegistryDigestMismatch;
            }
            if (self.join_descriptor) |descriptor| {
                if (descriptor.database_id != self.identity.database_id or
                    descriptor.configuration_id != configuration_id or
                    !std.mem.eql(u8, &descriptor.registry_digest, &blob_digest))
                {
                    return error.RegistryMismatch;
                }
            }
            const decided = registry.Decided.decode(encoded) catch
                return error.CorruptRegistry;
            if (decided.configuration_id != configuration_id or
                decided.database_id != self.identity.database_id)
            {
                return error.CorruptRegistry;
            }
            var voter_buffer: [types.log_options.max_members]paxos.NodeId = undefined;
            if (!std.mem.eql(
                paxos.NodeId,
                decided.voterIds(&voter_buffer),
                proof.nextMembersSlice(),
            )) {
                return error.CorruptRegistry;
            }
            try registry.storeBlob(self.io, self.dir, &decided);
            failpoint.hit("after_registry_blob");
            next_registry = decided;
        } else {
            // Without a registry of its own or a fetched blob, this node
            // may only install registry-less state; a registry-bound
            // transfer must wait for the fetch to arrive.
            const proof = try checkpoint_proof.decode(proof_bytes);
            if (!std.mem.eql(
                u8,
                &proof.next_registry_digest,
                &checkpoint_proof.no_registry_digest,
            )) {
                return error.RegistryUnavailable;
            }
        }

        var final_path_buffer: [64]u8 = undefined;
        const final_path = std.fmt.bufPrint(
            &final_path_buffer,
            "snapshots/{s}",
            .{&name},
        ) catch unreachable;
        self.dir.deleteTree(self.io, final_path) catch {};
        try self.dir.rename(install_tmp_dir, self.dir, final_path, self.io);
        // The `current` pointer written immediately below is the barrier
        // that persists this entry; nothing reads the snapshot until it
        // names one.
        try durability.syncChildDirectory(self.io, self.dir, "snapshots");
        try atomicWriteFile(self.io, self.dir, current_file_name, &name);
        if (next_registry) |*next| {
            try registry.activatePointer(self.io, self.dir, next.configuration_id);
            failpoint.hit("after_registry_pointer");
        }

        // The old epoch is sealed and fully covered by this snapshot; its
        // journal and any prior ones are obsolete.
        if (self.db_open) {
            self.db.close();
            self.db_open = false;
        }
        self.journal.close();
        try self.deleteAllJournals();
        try writeIdentity(self.io, self.dir, .{
            .node_id = self.identity.node_id,
            .database_id = self.identity.database_id,
            .configuration_id = configuration_id,
            .role = self.identity.role,
        });
        self.identity.configuration_id = configuration_id;
        self.journal = try Journal.create(self.io, self.dir, configuration_id);

        if (next_registry) |next| {
            self.decided_registry = next;
            var voter_buffer: [types.log_options.max_members]paxos.NodeId = undefined;
            const voters = next.voterIds(&voter_buffer);
            @memcpy(self.members[0..voters.len], voters);
            self.member_count = @intCast(voters.len);
            self.join_descriptor = null;
            try durableDeleteFile(self.io, self.dir, join_file_name);
        }

        var membership: Log.Membership = undefined;
        try membership.init(self.members[0..self.member_count]);
        try self.initLogForRole(configuration_id, &membership);
        self.capture_batch_id = null;
        self.needs_resync = false;
        self.rollover_pending = false;

        self.dir.deleteFile(self.io, db_file_name) catch {};
        try self.rebuildMaterializedImage();
    }

    /// Reads one stored decided-registry blob (canonical bytes plus digest
    /// trailer) for a member serving a joining replacement's fetch.
    pub fn readRegistryBlob(
        self: *Node,
        gpa: std.mem.Allocator,
        configuration_id: u64,
    ) ![]u8 {
        var path_buffer: [32]u8 = undefined;
        const path = registry.blobPath(&path_buffer, configuration_id);
        return self.dir.readFileAlloc(
            self.io,
            path,
            gpa,
            .limited(registry.max_encoded_bytes + 32),
        );
    }

    fn initLogForRole(
        self: *Node,
        configuration_id: u64,
        membership: *const Log.Membership,
    ) !void {
        if (self.capabilities.votes) {
            try self.log.initWithPriority(
                self.identity.node_id,
                configuration_id,
                membership,
                self.leader_priority,
            );
            self.log.core.setCampaignEnabled(self.capabilities.campaigns);
        } else {
            try self.log.initLearner(
                self.identity.node_id,
                configuration_id,
                membership,
            );
        }
    }

    fn deleteAllJournals(self: *Node) !void {
        var listing = try self.dir.openDir(self.io, ".", .{ .iterate = true });
        defer listing.close(self.io);
        var names: std.ArrayList([26]u8) = .empty;
        defer names.deinit(self.gpa);
        var iterator = listing.iterate();
        while (try iterator.next(self.io)) |entry| {
            if (entry.kind != .file) continue;
            if (entry.name.len != 26) continue;
            if (!std.mem.startsWith(u8, entry.name, "paxos-")) continue;
            if (!std.mem.endsWith(u8, entry.name, ".log")) continue;
            try names.append(self.gpa, entry.name[0..26].*);
        }
        for (names.items) |name| {
            self.dir.deleteFile(self.io, &name) catch {};
        }
    }

    fn collectReferencedPayloads(
        self: *Node,
        retained: *std.AutoHashMap([32]u8, void),
    ) !void {
        for (self.log.core.durable.accepted) |accepted| {
            const vote = accepted orelse continue;
            switch (vote.value) {
                .command => |cmd| switch (cmd) {
                    .transaction_batch => |batch| try retained.put(batch.payload_hash, {}),
                    else => {},
                },
                .stop => {},
            }
        }
        for (self.log.core.durable.committed) |committed| {
            const value = committed orelse continue;
            switch (value) {
                .command => |cmd| switch (cmd) {
                    .transaction_batch => |batch| try retained.put(batch.payload_hash, {}),
                    else => {},
                },
                .stop => {},
            }
        }
    }

    /// Retention policy: keep the current epoch journal, the sealed epoch's
    /// journal as a fallback generation, the two newest snapshots, and every
    /// payload referenced by a retained journal. Everything older is covered
    /// by the installed snapshot.
    fn garbageCollect(
        self: *Node,
        sealed_configuration: u64,
        retained_payloads: *std.AutoHashMap([32]u8, void),
    ) !void {
        // Journals older than the sealed epoch.
        var configuration = sealed_configuration;
        while (configuration > 1) {
            configuration -= 1;
            var name_buffer: [26]u8 = undefined;
            const name = journal_mod.fileName(&name_buffer, configuration);
            self.dir.deleteFile(self.io, name) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => return err,
            };
        }

        // Snapshots other than the two newest generations.
        if (sealed_configuration > 1) {
            var snapshots_dir = self.dir.openDir(self.io, "snapshots", .{
                .iterate = true,
            }) catch return;
            defer snapshots_dir.close(self.io);
            var names: std.ArrayList([16]u8) = .empty;
            defer names.deinit(self.gpa);
            var iterator = snapshots_dir.iterate();
            while (try iterator.next(self.io)) |entry| {
                if (entry.kind != .directory) continue;
                if (entry.name.len != 16) {
                    // Abandoned tmp-* generation from a crashed snapshot.
                    snapshots_dir.deleteTree(self.io, entry.name) catch {};
                    continue;
                }
                try names.append(self.gpa, entry.name[0..16].*);
            }
            std.mem.sort([16]u8, names.items, {}, struct {
                fn lessThan(_: void, a: [16]u8, b: [16]u8) bool {
                    return std.mem.order(u8, &a, &b) == .lt;
                }
            }.lessThan);
            if (names.items.len > 2) {
                for (names.items[0 .. names.items.len - 2]) |name| {
                    snapshots_dir.deleteTree(self.io, &name) catch {};
                }
            }
        }

        // Registry blobs other than the two newest generations; the
        // pointer names the newest and the sealed epoch keeps its blob as
        // the fallback, mirroring snapshot retention.
        if (self.decided_registry != null) {
            var registries_dir = self.dir.openDir(self.io, registry.directory_name, .{
                .iterate = true,
            }) catch return;
            defer registries_dir.close(self.io);
            var blob_names: std.ArrayList([16]u8) = .empty;
            defer blob_names.deinit(self.gpa);
            var blob_iterator = registries_dir.iterate();
            while (try blob_iterator.next(self.io)) |entry| {
                if (entry.kind != .file or entry.name.len != 16) continue;
                try blob_names.append(self.gpa, entry.name[0..16].*);
            }
            std.mem.sort([16]u8, blob_names.items, {}, struct {
                fn lessThan(_: void, a: [16]u8, b: [16]u8) bool {
                    return std.mem.order(u8, &a, &b) == .lt;
                }
            }.lessThan);
            if (blob_names.items.len > 2) {
                for (blob_names.items[0 .. blob_names.items.len - 2]) |name| {
                    registries_dir.deleteFile(self.io, &name) catch {};
                }
            }
        }

        // Payloads not referenced by any retained journal. The current
        // epoch is empty right after rollover, so the sealed epoch's
        // references (collected before reinit) are the live set.
        var payloads_dir = self.store.dir.openDir(self.io, ".", .{ .iterate = true }) catch return;
        defer payloads_dir.close(self.io);
        var shard_iterator = payloads_dir.iterate();
        while (try shard_iterator.next(self.io)) |shard| {
            if (shard.kind != .directory or shard.name.len != 2) continue;
            var shard_name: [2]u8 = shard.name[0..2].*;
            var shard_dir = payloads_dir.openDir(self.io, &shard_name, .{
                .iterate = true,
            }) catch continue;
            defer shard_dir.close(self.io);
            var object_iterator = shard_dir.iterate();
            while (try object_iterator.next(self.io)) |object| {
                if (object.kind != .file or object.name.len != 62) continue;
                var hex: [64]u8 = undefined;
                @memcpy(hex[0..2], &shard_name);
                @memcpy(hex[2..], object.name[0..62]);
                var digest: [32]u8 = undefined;
                _ = std.fmt.hexToBytes(&digest, &hex) catch continue;
                if (!retained_payloads.contains(digest)) {
                    shard_dir.deleteFile(self.io, object.name) catch {};
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Snapshot transfer source (serving a lagging peer)
    // ------------------------------------------------------------------

    pub const SnapshotHandle = struct {
        configuration_id: u64,
        name: [16]u8,
        manifest: []u8,
        proof: []u8,
        db_size: u64,
        file: Io.File,

        pub fn close(self: *SnapshotHandle, io: Io, gpa: std.mem.Allocator) void {
            self.file.close(io);
            gpa.free(self.manifest);
            gpa.free(self.proof);
            self.* = undefined;
        }
    };

    /// Opens the installed snapshot generation for streaming to a peer.
    pub fn openCurrentSnapshot(self: *Node) !SnapshotHandle {
        const name = (try self.currentSnapshotName()) orelse
            return error.NoSnapshot;
        var dir_path_buffer: [64]u8 = undefined;
        const dir_path = std.fmt.bufPrint(
            &dir_path_buffer,
            "snapshots/{s}",
            .{&name},
        ) catch unreachable;
        var snapshot_dir = try self.dir.openDir(self.io, dir_path, .{});
        defer snapshot_dir.close(self.io);
        const manifest = try snapshot_dir.readFileAlloc(
            self.io,
            "manifest",
            self.gpa,
            .limited(4096),
        );
        errdefer self.gpa.free(manifest);
        const proof = try snapshot_dir.readFileAlloc(
            self.io,
            "proof",
            self.gpa,
            .limited(checkpoint_proof.max_encoded_bytes),
        );
        errdefer self.gpa.free(proof);
        _ = try self.validateCheckpointProof(
            proof,
            self.identity.configuration_id,
            name,
            manifest,
        );
        const file = try snapshot_dir.openFile(self.io, "db", .{});
        errdefer file.close(self.io);
        return .{
            .configuration_id = self.identity.configuration_id,
            .name = name,
            .manifest = manifest,
            .proof = proof,
            .db_size = try file.length(self.io),
            .file = file,
        };
    }

    /// Validates the canonical stop proof and returns the digest peers use
    /// for quorum confirmation. This checks logical Paxos state (epoch,
    /// voters, stop slot, chain, exact metadata) and the manifest digest;
    /// the database file itself is verified separately against the manifest.
    pub fn validateCheckpointProof(
        self: *const Node,
        proof_bytes: []const u8,
        configuration_id: u64,
        name: [16]u8,
        manifest: []const u8,
    ) ![32]u8 {
        const proof = try checkpoint_proof.decode(proof_bytes);
        if (proof.database_id != self.identity.database_id or
            proof.next_configuration_id != configuration_id or
            proof.sealed_configuration_id + 1 != configuration_id)
        {
            return error.InvalidCheckpointProof;
        }
        // The receiver must recognize its own decided voter set on one
        // side of the transition: a lagging survivor holds the sealed set,
        // an installing replacement holds the next set. The registry
        // digest below binds the authoritative next membership.
        const own_members = self.members[0..self.member_count];
        const sealed_matches = std.mem.eql(
            paxos.NodeId,
            proof.sealedMembersSlice(),
            own_members,
        );
        const next_matches = std.mem.eql(
            paxos.NodeId,
            proof.nextMembersSlice(),
            own_members,
        );
        if (!sealed_matches and !next_matches) {
            return error.InvalidCheckpointProof;
        }

        const parsed = try parseStopMetadata(proof.metadataSlice());
        if (!std.mem.eql(u8, &parsed.name, &name)) {
            return error.InvalidCheckpointProof;
        }
        // The registry digest inside the metadata and the proof field must
        // agree; registry-less hosts carry the all-zero digest.
        if (parsed.registry_digest) |expected| {
            if (!std.mem.eql(u8, &proof.next_registry_digest, &expected)) {
                return error.InvalidCheckpointProof;
            }
        } else if (!std.mem.eql(
            u8,
            &proof.next_registry_digest,
            &checkpoint_proof.no_registry_digest,
        )) {
            return error.InvalidCheckpointProof;
        }
        const manifest_digest = PayloadStore.hashOf(manifest);
        if (!std.mem.eql(u8, &manifest_digest, &proof.manifest_sha256) or
            !std.mem.eql(u8, &manifest_digest, &parsed.manifest_hash))
        {
            return error.InvalidCheckpointProof;
        }

        const database_text = manifestValue(manifest, "database_id") orelse
            return error.InvalidCheckpointProof;
        const database_id = std.fmt.parseInt(u128, database_text, 16) catch
            return error.InvalidCheckpointProof;
        const sealed_text = manifestValue(
            manifest,
            "sealed_configuration_id",
        ) orelse return error.InvalidCheckpointProof;
        const sealed = std.fmt.parseInt(u64, sealed_text, 10) catch
            return error.InvalidCheckpointProof;
        const applied_text = manifestValue(manifest, "applied_slot") orelse
            return error.InvalidCheckpointProof;
        const applied = std.fmt.parseInt(paxos.Slot, applied_text, 10) catch
            return error.InvalidCheckpointProof;
        const chain_hex = manifestValue(manifest, "chain") orelse
            return error.InvalidCheckpointProof;
        var chain: [32]u8 = undefined;
        if (chain_hex.len != chain.len * 2) return error.InvalidCheckpointProof;
        _ = std.fmt.hexToBytes(&chain, chain_hex) catch
            return error.InvalidCheckpointProof;
        if (database_id != proof.database_id or
            sealed != proof.sealed_configuration_id or
            applied != proof.applied_slot or
            proof.stop_slot != applied + 1 or
            !std.mem.eql(u8, &chain, &proof.chain))
        {
            return error.InvalidCheckpointProof;
        }
        return checkpoint_proof.digest(proof_bytes);
    }

    /// Returns the digest of this node's retained proof for a sealed epoch.
    /// Used only to answer another member's quorum-confirmation probe.
    pub fn currentCheckpointProofDigest(
        self: *Node,
        sealed_configuration_id: u64,
    ) ![32]u8 {
        var handle = try self.openCurrentSnapshot();
        defer handle.close(self.io, self.gpa);
        const proof = try checkpoint_proof.decode(handle.proof);
        if (proof.sealed_configuration_id != sealed_configuration_id) {
            return error.ConfigurationMismatch;
        }
        return checkpoint_proof.digest(handle.proof);
    }
};

// ----------------------------------------------------------------------
// Identity file
// ----------------------------------------------------------------------

/// The one-shot descriptor `zaxon enroll` writes for a joining
/// replacement: the decided database identity and the registry digest the
/// node fetches and verifies before it can participate.
pub const JoinDescriptor = struct {
    database_id: u128,
    configuration_id: u64,
    registry_digest: [32]u8,
};

fn readJoinDescriptor(
    gpa: std.mem.Allocator,
    io: Io,
    dir: Io.Dir,
) !?JoinDescriptor {
    const bytes = dir.readFileAlloc(io, join_file_name, gpa, .limited(512)) catch |err|
        switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
    defer gpa.free(bytes);
    const format = manifestValue(bytes, "format") orelse
        return error.CorruptJoinDescriptor;
    if (!std.mem.eql(u8, format, "1")) return error.CorruptJoinDescriptor;
    const database_text = manifestValue(bytes, "database_id") orelse
        return error.CorruptJoinDescriptor;
    const configuration_text = manifestValue(bytes, "configuration_id") orelse
        return error.CorruptJoinDescriptor;
    const digest_text = manifestValue(bytes, "registry_digest") orelse
        return error.CorruptJoinDescriptor;
    if (digest_text.len != 64) return error.CorruptJoinDescriptor;
    var descriptor = JoinDescriptor{
        .database_id = std.fmt.parseInt(u128, database_text, 16) catch
            return error.CorruptJoinDescriptor,
        .configuration_id = std.fmt.parseInt(u64, configuration_text, 10) catch
            return error.CorruptJoinDescriptor,
        .registry_digest = undefined,
    };
    _ = std.fmt.hexToBytes(&descriptor.registry_digest, digest_text) catch
        return error.CorruptJoinDescriptor;
    return descriptor;
}

/// Writes the join descriptor into a (possibly not yet created) data
/// directory. Called by `zaxon enroll` before the node's first start.
pub fn writeJoinDescriptor(
    io: Io,
    directory: []const u8,
    descriptor: JoinDescriptor,
) !void {
    var dir = try Io.Dir.cwd().createDirPathOpen(io, directory, .{
        .permissions = @enumFromInt(0o700),
        .open_options = .{ .iterate = true },
    });
    defer dir.close(io);
    var buffer: [256]u8 = undefined;
    const contents = std.fmt.bufPrint(
        &buffer,
        "format=1\ndatabase_id={x:0>32}\nconfiguration_id={d}\n" ++
            "registry_digest={s}\n",
        .{
            descriptor.database_id,
            descriptor.configuration_id,
            &std.fmt.bytesToHex(descriptor.registry_digest, .lower),
        },
    ) catch unreachable;
    try atomicWriteFile(io, dir, join_file_name, contents);
}

/// Resolves the flag-provided membership for `Node.open`. Proofs and the
/// registry encode voter sets in canonical ascending order, so flag order
/// must not matter.
fn canonicalFlagMembers(
    options: *const OpenOptions,
    capabilities: roles.Capabilities,
    storage: *[types.log_options.max_members]paxos.NodeId,
) ![]const paxos.NodeId {
    if (options.members.len == 0 and capabilities.votes) {
        storage[0] = options.node_id;
        return storage[0..1];
    }
    if (options.members.len == 0) return error.VotersRequired;
    if (options.members.len > types.log_options.max_members) {
        return error.TooManyMembers;
    }
    @memcpy(storage[0..options.members.len], options.members);
    std.mem.sort(
        paxos.NodeId,
        storage[0..options.members.len],
        {},
        std.sort.asc(paxos.NodeId),
    );
    return storage[0..options.members.len];
}

fn loadOrCreateIdentity(
    gpa: std.mem.Allocator,
    io: Io,
    dir: Io.Dir,
    node_id: paxos.NodeId,
    fixed_database_id: ?u128,
    requested_role: roles.Role,
) !Identity {
    const bytes = dir.readFileAlloc(io, identity_file_name, gpa, .limited(4096)) catch |err|
        switch (err) {
            error.FileNotFound => {
                const database_id = fixed_database_id orelse blk: {
                    var database_id_bytes: [16]u8 = undefined;
                    io.random(&database_id_bytes);
                    break :blk std.mem.readInt(u128, &database_id_bytes, .little);
                };
                const identity = Identity{
                    .node_id = node_id,
                    .database_id = database_id,
                    .configuration_id = 1,
                    .role = requested_role,
                };
                try writeIdentity(io, dir, identity);
                return identity;
            },
            else => return err,
        };
    defer gpa.free(bytes);

    const format = manifestValue(bytes, "format") orelse return error.CorruptIdentity;
    if (!std.mem.eql(u8, format, "1") and !std.mem.eql(u8, format, "2")) {
        return error.CorruptIdentity;
    }
    const node_text = manifestValue(bytes, "node_id") orelse return error.CorruptIdentity;
    const database_text = manifestValue(bytes, "database_id") orelse return error.CorruptIdentity;
    const configuration_text = manifestValue(bytes, "configuration_id") orelse
        return error.CorruptIdentity;
    const persisted_role = if (std.mem.eql(u8, format, "2")) blk: {
        const role_text = manifestValue(bytes, "role") orelse
            return error.CorruptIdentity;
        break :blk roles.Role.parse(role_text) catch return error.CorruptIdentity;
    } else roles.Role.data_voter;

    const identity = Identity{
        .node_id = std.fmt.parseInt(paxos.NodeId, node_text, 10) catch
            return error.CorruptIdentity,
        .database_id = std.fmt.parseInt(u128, database_text, 16) catch
            return error.CorruptIdentity,
        .configuration_id = std.fmt.parseInt(u64, configuration_text, 10) catch
            return error.CorruptIdentity,
        .role = persisted_role,
    };
    if (identity.node_id != node_id) return error.NodeIdMismatch;
    if (identity.role != requested_role) return error.NodeRoleMismatch;
    if (fixed_database_id) |fixed| {
        if (identity.database_id != fixed) return error.DatabaseMismatch;
    }
    return identity;
}

fn writeIdentity(io: Io, dir: Io.Dir, identity: Identity) !void {
    var buffer: [256]u8 = undefined;
    const contents = std.fmt.bufPrint(
        &buffer,
        \\format=2
        \\node_id={d}
        \\database_id={x:0>32}
        \\configuration_id={d}
        \\role={s}
        \\
    ,
        .{
            identity.node_id,
            identity.database_id,
            identity.configuration_id,
            identity.role.name(),
        },
    ) catch unreachable;
    try atomicWriteFile(io, dir, identity_file_name, contents);
}

/// Reads `key=value` lines from a small text file body.
pub fn manifestValue(bytes: []const u8, key: []const u8) ?[]const u8 {
    var lines = std.mem.tokenizeScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        const separator = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        if (std.mem.eql(u8, line[0..separator], key)) {
            return std.mem.trim(u8, line[separator + 1 ..], " \r");
        }
    }
    return null;
}

fn atomicWriteFile(io: Io, dir: Io.Dir, name: []const u8, contents: []const u8) !void {
    var atomic = try dir.createFileAtomic(io, name, .{ .replace = true });
    defer atomic.deinit(io);
    try atomic.file.writePositionalAll(io, contents, 0);
    try durability.syncFile(io, atomic.file);
    try atomic.replace(io);
    try durability.syncPathnameTransition(io, dir, name);
}

/// Makes removal durable on every supported platform. Renaming to a live
/// tombstone gives Windows a file handle it can flush for the namespace
/// transition. A leftover tombstone is harmless and is removed best-effort.
fn durableDeleteFile(io: Io, dir: Io.Dir, name: []const u8) !void {
    dir.deleteFile(io, deleted_file_tombstone) catch {};
    dir.rename(name, dir, deleted_file_tombstone, io) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    try durability.syncPathnameTransition(io, dir, deleted_file_tombstone);
    dir.deleteFile(io, deleted_file_tombstone) catch return;
    try durability.syncDirectory(dir);
}

fn fileSha256(io: Io, dir: Io.Dir, name: []const u8) ![32]u8 {
    const file = try dir.openFile(io, name, .{});
    defer file.close(io);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (true) {
        const read = try file.readPositionalAll(io, &buffer, offset);
        if (read == 0) break;
        hasher.update(buffer[0..read]);
        offset += read;
        if (read < buffer.len) break;
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

const node_testing = std.testing;

test "an image with a newer search-feature version refuses to serve" {
    const gpa = node_testing.allocator;
    var tmp = node_testing.tmpDir(.{});
    defer tmp.cleanup();
    var buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(node_testing.io, &buffer);
    const dir = try std.fmt.allocPrint(gpa, "{s}/node", .{buffer[0..len]});
    defer gpa.free(dir);

    {
        const node = try Node.open(gpa, node_testing.io, .{ .directory = dir });
        defer node.close();
        // A fresh database records the supported version at bootstrap.
        try node_testing.expectEqual(
            Node.supported_search_feature_version,
            node.status().search_feature_version,
        );
        // Simulate a future binary having activated version 2 through the
        // replicated internal write path.
        _ = try node.writeTransaction(
            .internal,
            "update __zaxon_meta set value = '2' " ++
                "where key = 'search_feature_version'",
            null,
        );
    }
    // This binary must fail closed rather than serve the newer image.
    try node_testing.expectError(
        error.SearchFeatureTooNew,
        Node.open(gpa, node_testing.io, .{ .directory = dir }),
    );
}
