//! The `zaxon serve` transport host: one node behind a TCP endpoint.
//!
//! Thread shape: the serve thread accepts connections; every accepted
//! connection gets a reader thread; every peer gets one sender thread that
//! owns the outgoing connection and its bounded frame queue; one tick
//! thread advances protocol timers. One mutex guards the node and all
//! host bookkeeping; blocking work under it (journal fsync, SQLite) is the
//! write path's natural serialization.
//!
//! Ordering guarantees preserved here:
//! * `Node.consumeEffects` keeps every durable claim behind the journal
//!   barrier. Phase-two `accept` requests are the narrow exception: the
//!   server queues them after append and while the leader barrier runs, so
//!   follower barriers overlap it. The node mutex prevents their replies
//!   from being processed until the leader vote is durable.
//! * A payload is queued immediately before any dependent envelope on the
//!   ordered stream. The receiver stores it before reading the envelope and
//!   independently gates any reordered/missing-payload envelope, so Phase-1
//!   recovery and every counted vote have recoverable bytes.
//! * A client write is acknowledged only after its slot commits and the
//!   decided value at that slot is the client's own batch.

const std = @import("std");
const Io = std.Io;
const paxos = @import("paxos");

const command = @import("command.zig");
const types = @import("types.zig");
const wire = @import("wire.zig");
const transport_auth = @import("transport_auth.zig");
const tls = @import("tls.zig");
const node_mod = @import("node.zig");
const payload_store_mod = @import("payload_store.zig");
const checkpoint_proof = @import("checkpoint_proof.zig");
const enrollment = @import("enrollment.zig");
const failpoint = @import("failpoint.zig");
const roles = @import("roles.zig");
const diagnostic = @import("diagnostic.zig");
const durability = @import("durability.zig");
const configuration = @import("configuration.zig");

const Node = node_mod.Node;
const Log = types.Log;

pub const PeerAddress = struct {
    id: paxos.NodeId,
    host: []const u8,
    port: u16,
    role: roles.Role = .data_voter,
};

pub const ServeOptions = struct {
    directory: []const u8,
    node_id: paxos.NodeId,
    listen_host: []const u8 = "127.0.0.1",
    listen_port: u16 = 0,
    /// Unix-domain socket path for single-node local service. When set,
    /// the server listens here instead of TCP and relies on the socket's
    /// filesystem permissions for local authorization. Configured peers
    /// are rejected: cluster links require network transport.
    listen_unix: ?[]const u8 = null,
    /// Permission bits applied to the socket path immediately after
    /// binding. Owner-only by default; widen to 0o660 for group access.
    listen_unix_mode: u16 = 0o600,
    /// Runtime node registry, including this node. Empty means one local
    /// data voter. Only data voters and witnesses enter Paxos membership.
    members: []const PeerAddress = &.{},
    /// Shared database identity; derived from the member list when null.
    database_id: ?u128 = null,
    /// Shared transport secret loaded by the host from a protected provider.
    /// When present, mutual PSK authentication and per-frame integrity run
    /// inside the mandatory production TLS channel.
    auth_secret: ?[]const u8 = null,
    /// Explicit local-development transport: PSK authentication and frame
    /// integrity without TLS, accepted only when the listener and every peer
    /// use the numeric loopback address. This has no confidentiality or
    /// per-node identity and must not be exposed beyond one machine.
    allow_psk_only_loopback: bool = false,
    /// Optional mutual TLS 1.3 identity for every TCP connection: this
    /// node's certificate/key and the cluster CA. Peer certificates must
    /// chain to the CA and name `zaxon-node-<id>` matching their hello.
    tls: ?tls.Config = null,
    /// Optional cluster CA private key used only to redeem one-time
    /// enrollment tokens and sign node CSRs. When absent, the listener keeps
    /// strict handshake-level mTLS and exposes no enrollment operation.
    enrollment_ca_key: ?[]const u8 = null,
    /// Optional operator-managed denylist. Each non-comment line is one
    /// configured node ID. Reloads close live inbound and outbound links.
    revocation_file: ?[]const u8 = null,
    /// Explicit escape hatch for deterministic local test harnesses. It is
    /// rejected unless failpoints are enabled and is never a production
    /// transport mode.
    allow_insecure_test_tcp: bool = false,
    /// Maximum concurrently served connections (peers, clients, and
    /// transfer streams together). 0 derives a small-cluster default from
    /// the member registry; admission never grows past the limit.
    max_connections: usize = 0,
    /// Milliseconds an accepted connection may spend completing hello and
    /// authentication before the server closes it. 0 disables the
    /// deadline (tests with deterministic schedules use that).
    handshake_timeout_ms: u64 = 10_000,
    /// Established connections that receive no frame for this long are
    /// closed. Peer heartbeats keep healthy cluster links active. Zero
    /// disables the bound for a deterministic test schedule.
    idle_timeout_ms: u64 = 300_000,
    /// Inbound connections concurrently authenticated as one configured
    /// peer. Two permits a reconnect to overlap a dying old socket.
    max_connections_per_peer: usize = 2,
    /// Upper bound for one declared snapshot or backup transfer.
    max_transfer_bytes: u64 = wire.max_transfer_bytes,
    /// Remote query result caps. Embedded Node calls remain unlimited unless
    /// their caller explicitly supplies QueryLimits.
    max_query_rows: usize = 10_000,
    max_query_bytes: usize = 16 * 1024 * 1024,
    /// Approximate SQLite VM instruction budget; 0 explicitly disables it.
    max_query_vm_steps: u64 = 10_000_000,
    /// Honor `failpoint` RPCs (test controllers only).
    enable_failpoints: bool = false,
    tick_ms: u64 = 25,
    /// Deterministic test-only adverse schedules. Rejected unless
    /// `enable_failpoints` is also true.
    test_faults: TestFaults = .{},
};

pub const TestFaults = struct {
    drop_every: u32 = 0,
    duplicate_every: u32 = 0,
    reorder_pairs: bool = false,
    fragment_bytes: u32 = 0,
    storage_delay_ms: u64 = 0,

    fn enabled(self: TestFaults) bool {
        return self.drop_every != 0 or self.duplicate_every != 0 or
            self.reorder_pairs or self.fragment_bytes != 0 or
            self.storage_delay_ms != 0;
    }
};

/// Milliseconds a client operation may wait before reporting a timeout.
const op_timeout_ms: u64 = 10_000;
const held_hash_limit = 64;
const held_per_hash = 8;
const sender_queue_limit = 4096;
const sender_queue_byte_limit: usize = 128 * 1024 * 1024;
const snapshot_chunk_bytes: usize = 1024 * 1024;
const max_revoked_nodes: usize = 4 * types.log_options.max_members;

/// Derives a deterministic shared database identity from the member list.
pub fn deriveDatabaseId(members: []const PeerAddress, cluster_id: ?[]const u8) u128 {
    var ids: [types.log_options.max_members]paxos.NodeId = undefined;
    var count: usize = 0;
    for (members) |member| {
        if (!member.role.capabilities().votes) continue;
        if (count == ids.len) break;
        ids[count] = member.id;
        count += 1;
    }
    std.mem.sort(paxos.NodeId, ids[0..count], {}, std.sort.asc(paxos.NodeId));
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("zaxonlite.cluster.v1");
    for (ids[0..count]) |id| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, id, .little);
        hasher.update(&bytes);
    }
    if (cluster_id) |text| hasher.update(text);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return std.mem.readInt(u128, digest[0..16], .little);
}

pub fn serve(
    gpa: std.mem.Allocator,
    io: Io,
    options: ServeOptions,
    err_out: *Io.Writer,
) !u8 {
    if (options.test_faults.enabled() and !options.enable_failpoints) {
        return reportConfig(err_out, "test fault schedules require --enable-failpoints");
    }
    if (options.allow_insecure_test_tcp and !options.enable_failpoints) {
        return reportConfig(
            err_out,
            "insecure test TCP requires --enable-failpoints",
        );
    }
    if (options.allow_psk_only_loopback and options.allow_insecure_test_tcp) {
        return reportConfig(
            err_out,
            "choose either development PSK or insecure test TCP, not both",
        );
    }
    if (options.auth_secret) |secret| {
        if (secret.len < 32) {
            return reportConfig(
                err_out,
                "transport secret must contain at least 32 bytes",
            );
        }
    }
    if (options.allow_psk_only_loopback) {
        if (options.auth_secret == null) {
            return reportConfig(err_out, "--dev-psk requires --auth-file");
        }
        if (options.tls != null) {
            return reportConfig(
                err_out,
                "--dev-psk is PSK-only; omit it when mTLS is configured",
            );
        }
        if (options.listen_unix != null or
            !isNumericLoopback(options.listen_host))
        {
            return reportConfig(
                err_out,
                "--dev-psk is loopback-only; use 127.0.0.1 or ::1",
            );
        }
        for (options.members) |member| {
            if (!isNumericLoopback(member.host)) {
                return reportConfig(
                    err_out,
                    "--dev-psk accepts only loopback peer addresses",
                );
            }
        }
    }
    if (options.tls) |config| {
        configuration.validatePrivateFile(io, config.key_path) catch |err| {
            try diagnostic.write(
                err_out,
                "unsafe TLS private key",
                @errorName(err),
                "Use a regular, non-symlink key file with mode 0600.",
            );
            try err_out.flush();
            return 4;
        };
    }
    if (options.enrollment_ca_key) |ca_key_path| {
        if (options.tls == null or options.listen_unix != null) {
            return reportConfig(
                err_out,
                "enrollment requires a TLS TCP listener",
            );
        }
        configuration.validatePrivateFile(io, ca_key_path) catch |err| {
            try diagnostic.write(
                err_out,
                "unsafe enrollment CA private key",
                @errorName(err),
                "Use a regular, non-symlink CA key file with mode 0600.",
            );
            try err_out.flush();
            return 4;
        };
        tls.validateIssuer(options.tls.?.ca_path, ca_key_path) catch |err| {
            try diagnostic.write(
                err_out,
                "enrollment issuer failed",
                @errorName(err),
                "Use the private key matching --tls-ca, or omit " ++
                    "--enrollment-ca-key on nodes that do not issue tokens.",
            );
            try err_out.flush();
            return 4;
        };
    }
    if (options.listen_unix != null and options.members.len > 1) {
        return reportConfig(
            err_out,
            "a unix socket serves one local node; peers require TCP",
        );
    }
    if (options.listen_unix == null) {
        if (options.tls == null and !options.allow_insecure_test_tcp and
            !options.allow_psk_only_loopback)
        {
            try diagnostic.write(
                err_out,
                "mutual TLS required",
                "Every production TCP listener requires a node certificate " ++
                    "from the cluster CA. A PSK alone does not provide " ++
                    "confidentiality or a unique node identity.",
                "Provide --tls-cert/--tls-key/--tls-ca. For a local tutorial, " ++
                    "pair an owner-only --auth-file with --dev-psk, or serve " ++
                    "one local node through --listen unix:<path>.",
            );
            try err_out.flush();
            return 4;
        }
    }

    var member_ids: [types.log_options.max_members]paxos.NodeId = undefined;
    var member_count: usize = 0;
    var campaigner_count: usize = 0;
    var self_role: roles.Role = .data_voter;
    var found_self = options.members.len == 0;
    var seen_ids = std.AutoHashMap(paxos.NodeId, void).init(gpa);
    defer seen_ids.deinit();
    for (options.members) |member| {
        if (member.id == 0) return reportConfig(err_out, "node IDs must be non-zero");
        const inserted = seen_ids.getOrPut(member.id) catch
            return reportConfig(err_out, "cannot allocate the node registry");
        if (inserted.found_existing) {
            return reportConfig(err_out, "node ID appears more than once");
        }
        if (member.id == options.node_id) {
            if (found_self) return reportConfig(err_out, "node ID appears more than once");
            found_self = true;
            self_role = member.role;
        }
        if (!member.role.capabilities().votes) continue;
        if (member.role.capabilities().campaigns) campaigner_count += 1;
        if (member_count >= member_ids.len) {
            return reportConfig(err_out, "too many Paxos voters (maximum is 9)");
        }
        member_ids[member_count] = member.id;
        member_count += 1;
    }
    if (!found_self) return reportConfig(err_out, "this node is absent from --node registry");
    if (options.members.len > 0 and member_count == 0) {
        return reportConfig(err_out, "at least one Paxos voter is required");
    }
    if (options.members.len > 0 and campaigner_count == 0) {
        return reportConfig(err_out, "at least one data voter must be able to campaign");
    }
    if (self_role == .gateway) {
        return reportConfig(err_out, "gateway nodes use the gateway command");
    }
    if (member_count == 0) {
        member_ids[0] = options.node_id;
        member_count = 1;
    }
    std.mem.sort(paxos.NodeId, member_ids[0..member_count], {}, std.sort.asc(paxos.NodeId));

    const node = Node.open(gpa, io, .{
        .directory = options.directory,
        .node_id = options.node_id,
        .members = member_ids[0..member_count],
        .leader_priority = options.node_id,
        .database_id = options.database_id,
        .role = self_role,
        .test_storage_delay_ms = options.test_faults.storage_delay_ms,
    }) catch |err| {
        try diagnostic.write(
            err_out,
            "node open failed",
            @errorName(err),
            "Check the role-pinned identity and durable files before retrying.",
        );
        try err_out.flush();
        return 4;
    };

    var server = Server{
        .gpa = gpa,
        .io = io,
        .node = node,
        .options = options,
        .held = std.AutoHashMap(command.HashBytes, Held).init(gpa),
    };
    defer server.deinit();
    if (options.revocation_file != null) {
        server.reloadRevocationsLocked() catch |err| {
            try diagnostic.write(
                err_out,
                "revocation file invalid",
                @errorName(err),
                "Use one configured non-zero node ID per line; comments " ++
                    "start with #.",
            );
            try err_out.flush();
            return 4;
        };
    }

    if (options.tls) |tls_config| {
        server.tls_server = (if (options.enrollment_ca_key != null)
            tls.Context.initEnrollmentServer(tls_config)
        else
            tls.Context.initServer(tls_config)) catch |err| {
            try diagnostic.write(
                err_out,
                "tls identity failed",
                @errorName(err),
                "Check that --tls-cert, --tls-key, and --tls-ca name " ++
                    "readable PEM files and that the key matches the " ++
                    "certificate.",
            );
            try err_out.flush();
            return 4;
        };
        server.tls_client = tls.Context.initClient(tls_config) catch |err| {
            try diagnostic.write(
                err_out,
                "tls identity failed",
                @errorName(err),
                "Check that --tls-cert, --tls-key, and --tls-ca name " ++
                    "readable PEM files and that the key matches the " ++
                    "certificate.",
            );
            try err_out.flush();
            return 4;
        };
    }

    if (options.listen_unix) |socket_path| {
        server.listener = listenUnixSocket(
            io,
            socket_path,
            options.listen_unix_mode,
        ) catch |err| {
            try diagnostic.write(
                err_out,
                "unix socket listen failed",
                @errorName(err),
                "Remove a stale socket path only after confirming no server " ++
                    "owns it, and check the directory's permissions.",
            );
            try err_out.flush();
            return 4;
        };
    } else {
        const address = std.Io.net.IpAddress.parse(
            options.listen_host,
            options.listen_port,
        ) catch {
            try diagnostic.write(
                err_out,
                "invalid listen address",
                options.listen_host,
                "Use a numeric loopback or network address and a valid port.",
            );
            try err_out.flush();
            return 2;
        };
        server.listener = address.listen(io, .{ .reuse_address = true }) catch |err| {
            try diagnostic.write(
                err_out,
                "listen failed",
                @errorName(err),
                "Check address ownership, port availability, and permissions.",
            );
            try err_out.flush();
            return 4;
        };
    }
    // Orderly shutdown removes the socket path so the next start does not
    // find a stale one; an unlink-refusing crash leaves it for the
    // operator, which the listen diagnostic above explains.
    defer if (options.listen_unix) |socket_path| {
        Io.Dir.cwd().deleteFile(io, socket_path) catch {};
    };

    try writeStartupSummary(&server, self_role, err_out);

    // One sender per peer.
    for (options.members) |member| {
        if (member.id == options.node_id) continue;
        if (!member.role.capabilities().stores_log) continue;
        // Voters distribute chosen values to every storage node. Learners
        // only need return paths to voters for payload ACKs and requests;
        // learner-to-learner links carry no protocol information.
        if (!self_role.capabilities().votes and
            !member.role.capabilities().votes)
        {
            continue;
        }
        const sender = try gpa.create(PeerSender);
        sender.* = .{ .server = &server, .peer = member };
        sender.stored_payloads = std.AutoHashMap(command.HashBytes, void).init(gpa);
        try server.senders.append(gpa, sender);
    }
    server.node.setPreDurableOutboxHook(.{
        .context = &server,
        .run = drainPreDurableOutbox,
    });
    for (server.senders.items) |sender| {
        sender.thread = try std.Thread.spawn(.{}, PeerSender.run, .{sender});
    }
    const ticker = try std.Thread.spawn(.{}, Server.tickLoop, .{&server});

    // Accept loop. The `stop` RPC sets the shutdown flag and then dials
    // the listener once (`wakeAcceptLoop`) so a blocked `accept` returns
    // on every platform; the admission gate refuses that connection.
    var listener = server.listener.?;
    while (!server.isShutdown()) {
        const stream = listener.accept(io) catch |err| switch (err) {
            error.SocketNotListening, error.Canceled => break,
            error.ConnectionAborted => continue,
            else => break,
        };
        server.noteHandlerStarted(stream) catch {
            stream.close(io);
            continue;
        };
        const handler = std.Thread.spawn(
            .{},
            Server.handleConnectionTracked,
            .{ &server, stream },
        ) catch {
            server.noteHandlerFinished(stream);
            var s = stream;
            s.close(io);
            continue;
        };
        handler.detach();
    }

    std.log.info("node {d}: shutting down", .{options.node_id});
    server.shutdown();
    ticker.join();
    for (server.senders.items) |sender| {
        sender.thread.join();
    }
    server.waitForHandlers();
    std.log.info("node {d}: stopped", .{options.node_id});
    return 0;
}

fn isNumericLoopback(host: []const u8) bool {
    return std.mem.eql(u8, host, "127.0.0.1") or
        std.mem.eql(u8, host, "::1");
}

fn writeStartupSummary(
    server: *const Server,
    role: roles.Role,
    err_out: *Io.Writer,
) !void {
    const options = server.options;
    const member_count = if (options.members.len == 0) 1 else options.members.len;
    const transport = if (options.listen_unix != null)
        "owner-only Unix socket"
    else if (options.tls != null and options.auth_secret != null)
        "mTLS 1.3 + PSK"
    else if (options.tls != null)
        "mTLS 1.3"
    else if (options.allow_psk_only_loopback)
        "development PSK (loopback only)"
    else
        "INSECURE TEST TCP";

    try err_out.print(
        "\n" ++
            "zaxon node {d}\n" ++
            "  state       starting; waiting for a leader\n" ++
            "  role        {s}\n" ++
            "  data        {s}\n",
        .{ options.node_id, role.name(), options.directory },
    );
    if (options.listen_unix) |path| {
        try err_out.print("  listen      unix:{s}\n", .{path});
    } else {
        try err_out.print(
            "  listen      {s}:{d}\n",
            .{ options.listen_host, options.listen_port },
        );
    }
    try err_out.print(
        "  transport   {s}\n" ++
            "  cluster     {d} member(s), configuration {d}\n" ++
            "  durability  {s} sync\n\n",
        .{
            transport,
            member_count,
            server.node.identity.configuration_id,
            @tagName(durability.syncMode()),
        },
    );
    try err_out.flush();
}

/// Runs from `Node.consumeEffects` while the caller already owns the server
/// mutex. `drainOutbox` only takes per-sender queue locks, allowing sender
/// threads to put the accept requests on the wire during the journal barrier.
fn drainPreDurableOutbox(context: *anyopaque) anyerror!void {
    const server: *Server = @ptrCast(@alignCast(context));
    try server.drainOutbox();
}

/// Binds the local Unix-domain service socket. A pre-existing path is
/// refused rather than unlinked: silently replacing it could hijack a
/// live server's clients or delete an unrelated file, so a stale socket
/// needs explicit operator removal. `bind` remains the authoritative
/// existence check (`AddressInUse`); the probe only improves the
/// diagnostic. Permissions are narrowed immediately after binding, so
/// the socket should still live in an operator-owned directory.
fn listenUnixSocket(
    io: Io,
    path: []const u8,
    mode: u16,
) !std.Io.net.Server {
    const address = try std.Io.net.UnixAddress.init(path);
    var exists = true;
    Io.Dir.cwd().access(io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => exists = false,
        else => return err,
    };
    if (exists) return error.SocketPathExists;
    var listener = try address.listen(io, .{});
    errdefer listener.deinit(io);
    var path_z_buffer: [std.Io.net.UnixAddress.max_len + 1]u8 = undefined;
    const path_z = std.fmt.bufPrintZ(&path_z_buffer, "{s}", .{path}) catch
        return error.NameTooLong;
    if (std.c.fchmodat(std.posix.AT.FDCWD, path_z, mode, 0) != 0) {
        return error.PermissionChangeFailed;
    }
    return listener;
}

fn reportConfig(err_out: *Io.Writer, message: []const u8) !u8 {
    try diagnostic.write(
        err_out,
        "invalid cluster configuration",
        message,
        "Give every node the same role registry and a unique non-zero ID.",
    );
    try err_out.flush();
    return 2;
}

const Held = struct {
    envelopes: [held_per_hash]Log.Envelope = undefined,
    count: usize = 0,
    from: paxos.NodeId = 0,
};

const WriteOutcome = enum { pending, committed, conflict };

const WriteWaiter = struct {
    slot: paxos.Slot,
    batch_id: u128,
    outcome: WriteOutcome = .pending,
    cond: std.Io.Condition = .init,
};

const FenceWaiter = struct {
    id: u64,
    ballot: paxos.Ballot,
    fence_slot: paxos.Slot,
    acked: [types.log_options.max_members]paxos.NodeId =
        [_]paxos.NodeId{0} ** types.log_options.max_members,
    ack_count: usize = 0,
    needed: usize,
    failed: bool = false,
    done: bool = false,
    cond: std.Io.Condition = .init,

    fn noteAck(self: *FenceWaiter, member: paxos.NodeId) void {
        for (self.acked[0..self.ack_count]) |seen| {
            if (seen == member) return;
        }
        if (self.ack_count >= self.acked.len) return;
        self.acked[self.ack_count] = member;
        self.ack_count += 1;
    }
};

const CheckpointProofWaiter = struct {
    nonce: u64,
    sealed_configuration_id: u64,
    digest: [32]u8,
    acked: [types.log_options.max_members]paxos.NodeId =
        [_]paxos.NodeId{0} ** types.log_options.max_members,
    ack_count: usize = 0,
    needed: usize,

    fn noteAck(self: *CheckpointProofWaiter, member: paxos.NodeId) void {
        for (self.acked[0..self.ack_count]) |seen| {
            if (seen == member) return;
        }
        if (self.ack_count >= self.acked.len) return;
        self.acked[self.ack_count] = member;
        self.ack_count += 1;
    }
};

const WaitWaiter = struct {
    min_applied: paxos.Slot,
    need_leader: bool,
    done: bool = false,
    cond: std.Io.Condition = .init,

    fn satisfied(self: *const WaitWaiter, node: *Node) bool {
        if (node.applied_slot < self.min_applied) return false;
        if (self.need_leader and node.currentLeader() == null) return false;
        return true;
    }
};

pub const Server = struct {
    gpa: std.mem.Allocator,
    io: Io,
    node: *Node,
    options: ServeOptions,
    mutex: std.Io.Mutex = .init,
    /// Kept separate from `mutex`: checkpoint replies must be recordable
    /// while the snapshot receiver waits for its voter read quorum.
    proof_mutex: std.Io.Mutex = .init,
    proof_waiter: ?*CheckpointProofWaiter = null,
    next_proof_nonce: u64 = 1,
    listener: ?std.Io.net.Server = null,
    senders: std.ArrayList(*PeerSender) = .empty,
    held: std.AutoHashMap(command.HashBytes, Held),
    held_total: usize = 0,
    write_waiter: ?*WriteWaiter = null,
    writer_busy: bool = false,
    writer_cond: std.Io.Condition = .init,
    fences: std.ArrayList(*FenceWaiter) = .empty,
    next_fence_id: u64 = 1,
    waiters: std.ArrayList(*WaitWaiter) = .empty,
    rollover_cond: std.Io.Condition = .init,
    checkpoint_started: bool = false,
    observed_leader_decided: paxos.Slot = 0,
    /// Last voter that supplied a certified chosen value to this learner.
    /// Learners do not participate in leader election, so the Paxos core
    /// intentionally has no local leader observation for them.
    learner_leader: ?paxos.NodeId = null,
    learner_last_contact_tick: ?u64 = null,
    last_learner_heartbeat_tick: ?u64 = null,
    snapshot_source: ?paxos.NodeId = null,
    snapshot_requested_tick: u64 = 0,
    tick_count: u64 = 0,
    failed: bool = false,
    shutdown_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    stop_response_sent: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    handler_count: usize = 0,
    handler_cond: std.Io.Condition = .init,
    active_connections: std.ArrayList(TrackedConnection) = .empty,
    /// Present when `options.tls` is set: responder identity for accepted
    /// connections and initiator identity for peer dialing.
    tls_server: ?tls.Context = null,
    tls_client: ?tls.Context = null,
    revoked_nodes: [max_revoked_nodes]paxos.NodeId =
        [_]paxos.NodeId{0} ** max_revoked_nodes,
    revoked_count: usize = 0,
    /// Last leadership state already reported to the operator. Startup
    /// prints the initial waiting state; later transitions are concise.
    reported_leader: ?paxos.NodeId = null,
    leader_candidate: ?paxos.NodeId = null,
    leader_candidate_ticks: u8 = 0,

    const TrackedConnection = struct {
        stream: std.Io.net.Stream,
        /// Absolute tick-clock millisecond by which hello and
        /// authentication must have completed; 0 once established (or
        /// when the deadline is disabled).
        handshake_deadline_ms: u64,
        idle_deadline_ms: u64 = 0,
        credential_node_id: ?paxos.NodeId = null,
    };

    fn deinit(self: *Server) void {
        for (self.senders.items) |sender| {
            sender.deinit();
            self.gpa.destroy(sender);
        }
        self.senders.deinit(self.gpa);
        self.fences.deinit(self.gpa);
        self.waiters.deinit(self.gpa);
        self.active_connections.deinit(self.gpa);
        self.held.deinit();
        if (self.listener) |*listener| listener.deinit(self.io);
        if (self.tls_server) |*context| context.deinit();
        if (self.tls_client) |*context| context.deinit();
        self.node.close();
    }

    fn isShutdown(self: *Server) bool {
        return self.shutdown_flag.load(.acquire);
    }

    fn peerRevokedLocked(self: *const Server, peer: paxos.NodeId) bool {
        for (self.revoked_nodes[0..self.revoked_count]) |revoked| {
            if (revoked == peer) return true;
        }
        return false;
    }

    fn peerRevoked(self: *Server, peer: paxos.NodeId) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.peerRevokedLocked(peer);
    }

    /// Replaces revocation state atomically from a small, deliberately
    /// boring text file. Called with `mutex` held after startup.
    fn reloadRevocationsLocked(self: *Server) !void {
        const path = self.options.revocation_file orelse return;
        const bytes = try Io.Dir.cwd().readFileAlloc(
            self.io,
            path,
            self.gpa,
            .limited(16 * 1024),
        );
        defer self.gpa.free(bytes);
        var next = [_]paxos.NodeId{0} ** max_revoked_nodes;
        var count: usize = 0;
        var lines = std.mem.splitScalar(u8, bytes, '\n');
        while (lines.next()) |raw_line| {
            const before_comment = if (std.mem.indexOfScalar(u8, raw_line, '#')) |index|
                raw_line[0..index]
            else
                raw_line;
            const line = std.mem.trim(u8, before_comment, " \t\r");
            if (line.len == 0) continue;
            const id = std.fmt.parseInt(paxos.NodeId, line, 10) catch
                return error.InvalidRevocationFile;
            if (id == 0 or id == self.options.node_id) {
                return error.InvalidRevocationFile;
            }
            if (self.addressOf(id) == null or count == next.len) {
                return error.InvalidRevocationFile;
            }
            for (next[0..count]) |seen| {
                if (seen == id) return error.InvalidRevocationFile;
            }
            next[count] = id;
            count += 1;
        }
        self.revoked_nodes = next;
        self.revoked_count = count;
    }

    /// Consensus membership remains static in this release; this transport
    /// denylist is the immediate operational override for a compromised node.
    fn evictRevokedLocked(self: *Server) void {
        for (self.active_connections.items) |connection| {
            const peer = connection.credential_node_id orelse continue;
            if (self.peerRevokedLocked(peer)) {
                connection.stream.shutdown(self.io, .both) catch {};
            }
        }
        for (self.senders.items) |sender| {
            if (self.peerRevokedLocked(sender.peer.id)) sender.disconnect();
        }
    }

    /// Milliseconds elapsed since `start_tick`, measured in ticks.
    fn elapsedMs(self: *const Server, start_tick: u64) u64 {
        return (self.tick_count -| start_tick) * self.options.tick_ms;
    }

    /// Wakes every blocked waiter so it re-checks its condition and its
    /// deadline. Called once per tick with the mutex held.
    fn wakeWaiters(self: *Server) void {
        self.writer_cond.broadcast(self.io);
        self.rollover_cond.broadcast(self.io);
        if (self.write_waiter) |waiter| waiter.cond.signal(self.io);
        for (self.fences.items) |fence| fence.cond.signal(self.io);
        for (self.waiters.items) |waiter| waiter.cond.signal(self.io);
    }

    /// Wakes the serve thread out of a blocked `accept`. Closing the
    /// listening socket interrupts `accept` only on BSD kernels; Linux
    /// leaves the thread blocked forever. Connecting to our own listener
    /// and hanging up wakes it everywhere: the admission gate refuses the
    /// connection during shutdown and the serve loop re-checks the flag
    /// before the next accept. The listener itself is closed by `deinit`
    /// after the serve loop exits, so no thread races the descriptor.
    fn wakeAcceptLoop(self: *Server) void {
        if (self.options.listen_unix) |path| {
            const address = std.Io.net.UnixAddress.init(path) catch return;
            var stream = address.connect(self.io) catch return;
            stream.close(self.io);
            return;
        }
        const address = std.Io.net.IpAddress.parse(
            self.options.listen_host,
            self.options.listen_port,
        ) catch return;
        var stream = address.connect(self.io, .{ .mode = .stream }) catch return;
        stream.close(self.io);
    }

    fn shutdown(self: *Server) void {
        const client_requested = self.shutdown_flag.load(.acquire);
        self.shutdown_flag.store(true, .release);
        if (client_requested) {
            var attempts: usize = 0;
            while (!self.stop_response_sent.load(.acquire) and attempts < 250) {
                self.io.sleep(.fromMilliseconds(1), .awake) catch {};
                attempts += 1;
            }
        }
        self.mutex.lockUncancelable(self.io);
        for (self.active_connections.items) |connection| {
            connection.stream.shutdown(self.io, .both) catch {};
        }
        self.mutex.unlock(self.io);
        for (self.senders.items) |sender| {
            sender.mutex.lockUncancelable(self.io);
            sender.cond.broadcast(self.io);
            sender.mutex.unlock(self.io);
        }
    }

    /// Admission limit for concurrent connections. The default is sized
    /// from the configured registry — every peer link plus headroom for
    /// operator clients and transfer streams — never from internet-scale
    /// assumptions.
    fn connectionLimit(self: *const Server) usize {
        if (self.options.max_connections != 0) return self.options.max_connections;
        return 4 * self.options.members.len + 16;
    }

    fn noteHandlerStarted(self: *Server, stream: std.Io.net.Stream) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        // Refusing at admission keeps every accepted connection's thread
        // and descriptors accountable to the documented limit, and stops
        // new work from starting during shutdown.
        if (self.isShutdown()) return error.ShuttingDown;
        if (self.handler_count >= self.connectionLimit()) {
            return error.ConnectionLimit;
        }
        const deadline = if (self.options.handshake_timeout_ms == 0)
            0
        else
            self.tick_count * self.options.tick_ms + self.options.handshake_timeout_ms;
        try self.active_connections.append(self.gpa, .{
            .stream = stream,
            .handshake_deadline_ms = deadline,
        });
        self.handler_count += 1;
    }

    /// Marks a connection as established after hello and authentication,
    /// clearing its handshake deadline.
    fn noteHandshakeComplete(
        self: *Server,
        stream: std.Io.net.Stream,
        credential_node_id: ?paxos.NodeId,
    ) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (credential_node_id) |id| {
            var count: usize = 0;
            for (self.active_connections.items) |connection| {
                if (connection.credential_node_id == id) count += 1;
            }
            if (self.options.max_connections_per_peer != 0 and
                count >= self.options.max_connections_per_peer)
            {
                return error.PeerConnectionLimit;
            }
        }
        const now_ms = self.tick_count * self.options.tick_ms;
        for (self.active_connections.items) |*connection| {
            if (connection.stream.socket.handle == stream.socket.handle) {
                connection.handshake_deadline_ms = 0;
                connection.idle_deadline_ms = if (self.options.idle_timeout_ms == 0)
                    0
                else
                    now_ms + self.options.idle_timeout_ms;
                connection.credential_node_id = credential_node_id;
                break;
            }
        }
    }

    fn noteConnectionActivity(self: *Server, stream: std.Io.net.Stream) void {
        if (self.options.idle_timeout_ms == 0) return;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const deadline = self.tick_count * self.options.tick_ms +
            self.options.idle_timeout_ms;
        for (self.active_connections.items) |*connection| {
            if (connection.stream.socket.handle == stream.socket.handle) {
                connection.idle_deadline_ms = deadline;
                break;
            }
        }
    }

    fn noteHandlerFinished(self: *Server, stream: std.Io.net.Stream) void {
        self.mutex.lockUncancelable(self.io);
        std.debug.assert(self.handler_count > 0);
        self.handler_count -= 1;
        for (self.active_connections.items, 0..) |connection, index| {
            if (connection.stream.socket.handle == stream.socket.handle) {
                _ = self.active_connections.swapRemove(index);
                break;
            }
        }
        self.handler_cond.signal(self.io);
        self.mutex.unlock(self.io);
    }

    /// Shuts down sockets that have not completed hello and
    /// authentication before their deadline; the blocked handler thread
    /// then fails its read and releases the connection. Runs once per
    /// tick with the mutex held.
    fn closeExpiredConnections(self: *Server) void {
        const now_ms = self.tick_count * self.options.tick_ms;
        for (self.active_connections.items) |connection| {
            const handshake_expired = connection.handshake_deadline_ms != 0 and
                now_ms >= connection.handshake_deadline_ms;
            const idle_expired = connection.handshake_deadline_ms == 0 and
                connection.idle_deadline_ms != 0 and
                now_ms >= connection.idle_deadline_ms;
            if (handshake_expired or idle_expired) {
                connection.stream.shutdown(self.io, .both) catch {};
            }
        }
    }

    fn waitForHandlers(self: *Server) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        while (self.handler_count > 0) {
            self.handler_cond.waitUncancelable(self.io, &self.mutex);
        }
    }

    fn senderFor(self: *Server, peer: paxos.NodeId) ?*PeerSender {
        for (self.senders.items) |sender| {
            if (sender.peer.id == peer) return sender;
        }
        return null;
    }

    fn addressOf(self: *Server, peer: paxos.NodeId) ?PeerAddress {
        for (self.options.members) |member| {
            if (member.id == peer) return member;
        }
        return null;
    }

    fn knownLeader(self: *const Server) ?paxos.NodeId {
        return self.node.currentLeader() orelse self.learner_leader;
    }

    // ------------------------------------------------------------------
    // The pump: reconcile host state after any node transition.
    // Must run with `mutex` held.
    // ------------------------------------------------------------------

    fn pump(self: *Server) void {
        self.pumpFallible() catch |err| {
            std.log.err("node host failure: {s}", .{@errorName(err)});
            self.failed = true;
            self.failEverything();
        };
    }

    fn pumpFallible(self: *Server) !void {
        const previous_configuration = self.node.identity.configuration_id;

        try self.drainOutbox();
        try self.drainLearners();
        try self.heartbeatLearners();

        if (self.node.needsResync()) {
            // Any in-flight write is now of unknown fate.
            if (self.write_waiter) |waiter| {
                if (waiter.outcome == .pending) {
                    waiter.outcome = .conflict;
                    waiter.cond.signal(self.io);
                }
                self.write_waiter = null;
            }
            try self.node.resyncImage();
        }

        // Complete a decided epoch rollover once everything before the
        // stop sign is applied.
        if (self.node.rollover_pending and self.node.log.isReconfigured() != null) {
            if (self.node.completeClusterRollover()) |_| {
                self.checkpoint_started = false;
                self.observed_leader_decided = 0;
                try self.drainOutbox();
            } else |err| switch (err) {
                error.SnapshotDigestMismatch, error.NotCaughtUp => {
                    // Fall back to a full snapshot transfer from the leader.
                    if (self.node.currentLeader()) |leader| {
                        if (leader != self.node.identity.node_id) {
                            self.requestSnapshot(leader);
                        }
                    }
                },
                else => return err,
            }
        }
        if (self.node.identity.configuration_id != previous_configuration) {
            for (self.senders.items) |sender| sender.learned_through = 0;
            self.learner_leader = null;
            self.learner_last_contact_tick = null;
            self.rollover_cond.broadcast(self.io);
        }

        // Write waiter resolution.
        if (self.write_waiter) |waiter| {
            if (waiter.outcome == .pending and self.node.applied_slot >= waiter.slot) {
                waiter.outcome = .conflict;
                if (self.node.log.read(waiter.slot)) |entry| {
                    switch (entry) {
                        .command => |cmd| switch (cmd) {
                            .transaction_batch => |batch| {
                                if (batch.batch_id == waiter.batch_id) {
                                    waiter.outcome = .committed;
                                }
                            },
                            else => {},
                        },
                        .stop => {},
                    }
                }
                waiter.cond.signal(self.io);
                self.write_waiter = null;
            }
        }

        // Fence resolution: a fence fails as soon as the ballot moves.
        var index: usize = 0;
        while (index < self.fences.items.len) {
            const fence = self.fences.items[index];
            if (!fence.ballot.eql(self.node.log.core.ballot) or
                self.node.log.core.role != .leader)
            {
                fence.failed = true;
            }
            const complete = fence.failed or
                (fence.ack_count >= fence.needed and
                    self.node.applied_slot >= fence.fence_slot);
            if (complete) {
                fence.done = true;
                fence.cond.signal(self.io);
                _ = self.fences.swapRemove(index);
                continue;
            }
            index += 1;
        }

        // Observable-condition waiters.
        index = 0;
        while (index < self.waiters.items.len) {
            const waiter = self.waiters.items[index];
            if (waiter.satisfied(self.node)) {
                waiter.done = true;
                waiter.cond.signal(self.io);
                _ = self.waiters.swapRemove(index);
                continue;
            }
            index += 1;
        }
    }

    fn failEverything(self: *Server) void {
        if (self.write_waiter) |waiter| {
            if (waiter.outcome == .pending) waiter.outcome = .conflict;
            waiter.cond.signal(self.io);
            self.write_waiter = null;
        }
        for (self.fences.items) |fence| {
            fence.failed = true;
            fence.done = true;
            fence.cond.signal(self.io);
        }
        self.fences.clearRetainingCapacity();
        for (self.waiters.items) |waiter| {
            waiter.done = true;
            waiter.cond.signal(self.io);
        }
        self.waiters.clearRetainingCapacity();
    }

    /// Moves every outbox envelope into its peer's sender. A missing payload
    /// is queued immediately before its dependent envelope on the ordered TCP
    /// stream, allowing follower storage work to overlap the leader barrier.
    /// The receiver remains authoritative: a separately arriving or reordered
    /// envelope stays in its bounded missing-payload gate until storage ends.
    fn drainOutbox(self: *Server) !void {
        const configuration_id = self.node.identity.configuration_id;
        for (self.node.outbox.items) |envelope| {
            const sender = self.senderFor(envelope.to) orelse continue;
            var payload_precedes_envelope = false;
            if (wire.envelopePayloadHash(envelope)) |hash| {
                if (sender.hasPayloadAck(hash)) {
                    payload_precedes_envelope = true;
                } else {
                    if (self.node.store.load(self.gpa, hash)) |payload| {
                        defer self.gpa.free(payload);
                        const frame = try wire.frameAlloc(
                            self.gpa,
                            .payload_data,
                            &.{ &hash, payload },
                        );
                        if (!sender.enqueueChecked(frame)) continue;
                        payload_precedes_envelope = true;
                    } else |_| {
                        // Never send a descriptor whose bytes we cannot
                        // serve; the peer would stall. Skip the envelope;
                        // retransmission retries once the store recovers.
                        continue;
                    }
                }
            }
            var envelope_buffer: [wire.max_envelope_size]u8 = undefined;
            const encoded = wire.encodeEnvelope(envelope, &envelope_buffer);
            var config_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &config_bytes, configuration_id, .little);
            const frame = try wire.frameAlloc(
                self.gpa,
                .envelope,
                &.{ &config_bytes, encoded },
            );
            if (wire.envelopePayloadHash(envelope)) |hash| {
                if (payload_precedes_envelope) {
                    sender.enqueue(frame);
                } else {
                    _ = sender.gatePayload(hash, frame);
                }
            } else {
                sender.enqueue(frame);
            }
        }
        self.node.outbox.clearRetainingCapacity();
    }

    /// Streams the chosen prefix to non-voting storage nodes. These frames
    /// are not votes: a learner accepts them only from a configured voter,
    /// journals them durably, and applies them in contiguous slot order.
    fn drainLearners(self: *Server) !void {
        if (!self.node.isLeader()) return;
        for (self.senders.items) |sender| {
            if (sender.peer.role.capabilities().votes) continue;
            if (!sender.peer.role.capabilities().stores_log) continue;
            while (sender.learned_through < self.node.applied_slot) {
                const slot = sender.learned_through + 1;
                const entry = self.node.log.read(slot) orelse break;
                if (entryPayloadHash(entry)) |hash| {
                    if (!sender.hasPayloadAck(hash)) {
                        const payload = self.node.store.load(self.gpa, hash) catch break;
                        const offer = blk: {
                            defer self.gpa.free(payload);
                            break :blk try wire.frameAlloc(
                                self.gpa,
                                .payload_data,
                                &.{ &hash, payload },
                            );
                        };
                        if (!sender.enqueueChecked(offer)) break;
                    }
                }
                var commit_buffer: [wire.LearnerCommit.encoded_max]u8 = undefined;
                const encoded = (wire.LearnerCommit{
                    .configuration_id = self.node.identity.configuration_id,
                    .slot = slot,
                    .entry = entry,
                }).encode(&commit_buffer);
                const frame = try wire.frameAlloc(
                    self.gpa,
                    .learner_commit,
                    &.{encoded},
                );
                const accepted = if (entryPayloadHash(entry)) |hash|
                    sender.gatePayload(hash, frame)
                else
                    sender.enqueueChecked(frame);
                if (!accepted) break;
                sender.learned_through = slot;
            }
        }
    }

    fn heartbeatLearners(self: *Server) !void {
        if (!self.node.isLeader()) return;
        if (self.last_learner_heartbeat_tick == self.tick_count) return;
        if (self.tick_count % 20 != 0) return;
        self.last_learner_heartbeat_tick = self.tick_count;
        var buffer: [wire.LearnerHeartbeat.encoded_size]u8 = undefined;
        const encoded = (wire.LearnerHeartbeat{
            .configuration_id = self.node.identity.configuration_id,
            .decided_through = self.node.log.decidedThrough(),
        }).encode(&buffer);
        for (self.senders.items) |sender| {
            if (sender.peer.role.capabilities().votes or
                !sender.peer.role.capabilities().stores_log)
            {
                continue;
            }
            const frame = try wire.frameAlloc(
                self.gpa,
                .learner_heartbeat,
                &.{encoded},
            );
            sender.enqueue(frame);
        }
    }

    fn entryPayloadHash(entry: types.Entry) ?command.HashBytes {
        return switch (entry) {
            .command => |cmd| switch (cmd) {
                .transaction_batch => |batch| batch.payload_hash,
                else => null,
            },
            .stop => null,
        };
    }

    fn requestSnapshot(self: *Server, from: paxos.NodeId) void {
        if (self.snapshot_source != null and
            self.tick_count < self.snapshot_requested_tick + 400)
        {
            return;
        }
        const sender = self.senderFor(from) orelse return;
        self.snapshot_source = from;
        self.snapshot_requested_tick = self.tick_count;
        const frame = wire.frameAlloc(self.gpa, .snapshot_request, &.{}) catch return;
        sender.enqueue(frame);
    }

    // ------------------------------------------------------------------
    // Tick thread
    // ------------------------------------------------------------------

    fn tickLoop(self: *Server) void {
        while (!self.isShutdown()) {
            self.io.sleep(.fromMilliseconds(@intCast(self.options.tick_ms)), .awake) catch {};
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.failed) continue;
            self.tick_count += 1;
            if (self.options.revocation_file != null and
                self.tick_count % 40 == 0)
            {
                self.reloadRevocationsLocked() catch |err| {
                    std.log.warn(
                        "revocation reload retained prior state: {s}",
                        .{@errorName(err)},
                    );
                };
                self.evictRevokedLocked();
            }
            self.node.tickProtocol() catch |err| {
                std.log.err("tick failure: {s}", .{@errorName(err)});
                self.failed = true;
                self.failEverything();
                continue;
            };
            self.pump();
            self.reportLeaderChangeLocked();
            self.wakeWaiters();
            self.closeExpiredConnections();

            // A member that observes a further-ahead leader asks for the
            // decided suffix it is missing.
            if (self.tick_count % 20 == 0 and !self.node.isLeader()) {
                if (self.node.currentLeader()) |leader| {
                    if (leader != self.node.identity.node_id and
                        self.observed_leader_decided > self.node.log.decidedThrough())
                    {
                        self.node.requestCatchUp(leader) catch {};
                        self.pump();
                    }
                }
            }
        }
    }

    /// Called with the server mutex held after a protocol transition.
    fn reportLeaderChangeLocked(self: *Server) void {
        const leader = self.knownLeader();
        if (leader != self.leader_candidate) {
            self.leader_candidate = leader;
            self.leader_candidate_ticks = 1;
            return;
        }
        if (self.leader_candidate_ticks < 3) {
            self.leader_candidate_ticks += 1;
            if (self.leader_candidate_ticks < 3) return;
        }
        if (leader == self.reported_leader) return;
        self.reported_leader = leader;
        if (leader) |id| {
            if (id == self.node.identity.node_id) {
                std.log.info(
                    "node {d}: became leader; writes are ready",
                    .{self.node.identity.node_id},
                );
            } else {
                std.log.info(
                    "node {d}: leader is node {d}; follower is ready",
                    .{ self.node.identity.node_id, id },
                );
            }
        } else {
            std.log.warn(
                "node {d}: leader lost; waiting for voter quorum",
                .{self.node.identity.node_id},
            );
        }
    }

    // ------------------------------------------------------------------
    // Connection handling
    // ------------------------------------------------------------------

    fn handleConnection(self: *Server, stream_const: std.Io.net.Stream) void {
        var stream = stream_const;
        defer stream.close(self.io);
        var read_buffer: [64 * 1024]u8 = undefined;
        var write_buffer: [64 * 1024]u8 = undefined;

        if (self.tls_server) |*context| {
            var tls_stream = if (self.options.enrollment_ca_key != null)
                tls.Stream.acceptOptionalPeer(
                    context,
                    stream,
                    &read_buffer,
                    &write_buffer,
                ) catch return
            else
                tls.Stream.accept(
                    context,
                    stream,
                    &read_buffer,
                    &write_buffer,
                ) catch return;
            defer tls_stream.deinit();
            self.serveConnection(
                stream,
                &tls_stream.reader,
                &tls_stream.writer,
                if (tls_stream.hasPeerCertificate())
                    tls_stream.peerCommonName()
                else
                    null,
            );
            return;
        }
        var stream_reader = stream.reader(self.io, &read_buffer);
        var stream_writer = stream.writer(self.io, &write_buffer);
        self.serveConnection(
            stream,
            &stream_reader.interface,
            &stream_writer.interface,
            null,
        );
    }

    /// Speaks the frame protocol over an established transport.
    /// `peer_certificate_name` is the verified TLS common name, when TLS
    /// is active; a peer hello must claim exactly the node id the
    /// certificate was issued for.
    fn serveConnection(
        self: *Server,
        stream: std.Io.net.Stream,
        reader: *Io.Reader,
        writer: *Io.Writer,
        peer_certificate_name: ?[]const u8,
    ) void {
        const header = wire.readFrameHeader(reader) catch return;
        if (header.kind != .hello or header.body_len != wire.Hello.encoded_size) return;
        const hello_body = wire.readFrameBody(self.gpa, reader, header) catch return;
        defer self.gpa.free(hello_body);
        const hello = wire.Hello.decode(hello_body) catch {
            return;
        };
        if (self.tls_server != null and peer_certificate_name == null and
            hello.kind != .enrollment)
        {
            return;
        }
        if (hello.kind == .enrollment and self.options.enrollment_ca_key == null) {
            return;
        }
        const credential_node_id = if (peer_certificate_name) |certificate_name|
            tls.parseNodeCommonName(certificate_name)
        else
            null;
        if (hello.kind == .peer and self.peerRevoked(hello.node_id)) return;
        if (hello.kind == .client and credential_node_id != null and
            self.peerRevoked(credential_node_id.?))
        {
            return;
        }
        if (peer_certificate_name) |certificate_name| {
            if (hello.kind == .peer) {
                var expected_buffer: [tls.max_common_name]u8 = undefined;
                const expected = tls.nodeCommonName(&expected_buffer, hello.node_id);
                if (!std.mem.eql(u8, certificate_name, expected)) return;
            }
        }

        var authenticated = if (hello.kind != .enrollment and self.options.auth_secret != null)
            transport_auth.accept(
                self.gpa,
                self.io,
                reader,
                writer,
                self.options.auth_secret.?,
                hello_body,
            ) catch return
        else
            null;
        self.noteHandshakeComplete(
            stream,
            switch (hello.kind) {
                .peer => hello.node_id,
                .client => credential_node_id,
                .enrollment => null,
            },
        ) catch return;

        switch (hello.kind) {
            .peer => self.peerLoop(stream, reader, hello, if (authenticated) |*session|
                session
            else
                null) catch {},
            .client => self.clientLoop(stream, reader, writer, if (authenticated) |*session|
                session
            else
                null) catch {},
            .enrollment => self.enrollmentExchange(stream, reader, writer, hello) catch {},
        }
    }

    /// A certificate-less connection can execute exactly this one exchange.
    /// The CSR is verified before the token is consumed; consumption is an
    /// atomic, directory-synced rename before signing or returning a cert.
    fn enrollmentExchange(
        self: *Server,
        stream: std.Io.net.Stream,
        reader: *Io.Reader,
        writer: *Io.Writer,
        hello: wire.Hello,
    ) !void {
        const header = wire.readFrameHeader(reader) catch {
            return self.writeEnrollmentRefused(writer);
        };
        if (header.kind != .enrollment_request or
            header.body_len > wire.EnrollmentRequest.max_encoded_size)
        {
            return self.writeEnrollmentRefused(writer);
        }
        const body = wire.readFrameBody(self.gpa, reader, header) catch {
            return self.writeEnrollmentRefused(writer);
        };
        defer self.gpa.free(body);
        self.noteConnectionActivity(stream);
        const request = wire.EnrollmentRequest.decode(body) catch {
            return self.writeEnrollmentRefused(writer);
        };
        if (hello.node_id != request.node_id or
            hello.database_id != request.database_id or
            request.database_id != self.node.identity.database_id or
            !self.isConfiguredNode(request.node_id) or
            self.peerRevoked(request.node_id))
        {
            return self.writeEnrollmentRefused(writer);
        }
        tls.validateNodeCsr(request.csr, request.node_id) catch {
            return self.writeEnrollmentRefused(writer);
        };
        enrollment.consumeToken(
            self.gpa,
            self.io,
            self.options.directory,
            request.secret,
            request.node_id,
            self.node.identity.node_id,
            self.node.identity.database_id,
        ) catch return self.writeEnrollmentRefused(writer);

        var serial_bytes: [8]u8 = undefined;
        self.io.random(&serial_bytes);
        const certificate = tls.issueNodeCertificate(
            self.gpa,
            request.csr,
            request.node_id,
            self.options.tls.?.ca_path,
            self.options.enrollment_ca_key.?,
            std.mem.readInt(u64, &serial_bytes, .little),
            enrollment.certificate_validity_seconds,
        ) catch return self.writeEnrollmentRefused(writer);
        defer self.gpa.free(certificate);
        var response_buffer: [wire.EnrollmentResponse.max_encoded_size]u8 = undefined;
        const response = wire.EnrollmentResponse{
            .status = .ok,
            .certificate = certificate,
        };
        try wire.writeFrame(
            writer,
            .enrollment_response,
            try response.encode(&response_buffer),
        );
        try writer.flush();
    }

    fn writeEnrollmentRefused(self: *Server, writer: *Io.Writer) !void {
        _ = self;
        var response_buffer: [wire.EnrollmentResponse.max_encoded_size]u8 = undefined;
        const response = wire.EnrollmentResponse{ .status = .refused };
        try wire.writeFrame(
            writer,
            .enrollment_response,
            try response.encode(&response_buffer),
        );
        try writer.flush();
    }

    fn isConfiguredNode(self: *const Server, node_id: paxos.NodeId) bool {
        for (self.options.members) |member| {
            if (member.id == node_id and member.role != .gateway) return true;
        }
        return self.options.members.len == 0 and self.node.identity.node_id == node_id;
    }

    fn handleConnectionTracked(self: *Server, stream: std.Io.net.Stream) void {
        defer self.noteHandlerFinished(stream);
        self.handleConnection(stream);
    }

    // ------------------------------------------------------------------
    // Peer connections (inbound: we receive what the peer sends)
    // ------------------------------------------------------------------

    const InstallState = struct {
        dir: ?Io.Dir = null,
        file: ?Io.File = null,
        configuration_id: u64 = 0,
        db_size: u64 = 0,
        received: u64 = 0,
        name: [16]u8 = undefined,
        manifest: ?[]u8 = null,
        proof: ?[]u8 = null,

        fn reset(self: *InstallState, io: Io, gpa: std.mem.Allocator) void {
            if (self.file) |file| file.close(io);
            if (self.dir) |*dir| dir.close(io);
            if (self.manifest) |manifest| gpa.free(manifest);
            if (self.proof) |proof| gpa.free(proof);
            self.* = .{};
        }
    };

    fn peerLoop(
        self: *Server,
        stream: std.Io.net.Stream,
        reader: *Io.Reader,
        hello: wire.Hello,
        authenticated: ?*transport_auth.Session,
    ) !void {
        {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (hello.database_id != self.node.identity.database_id) {
                return error.DatabaseMismatch;
            }
            var known = false;
            for (self.options.members) |member| {
                if (member.id == hello.node_id) known = true;
            }
            if (!known) return error.NotMember;
            if (hello.configuration_id > self.node.identity.configuration_id) {
                self.requestSnapshot(hello.node_id);
            }
        }

        var install = InstallState{};
        defer install.reset(self.io, self.gpa);

        while (!self.isShutdown()) {
            const frame = try self.readConnectionFrame(
                stream,
                reader,
                authenticated,
            );
            const body = frame.body;
            defer self.gpa.free(body);
            switch (frame.kind) {
                .envelope => try self.onEnvelopeFrame(body, hello.node_id),
                .payload_data => try self.onPayloadData(body, hello.node_id),
                .payload_stored => self.onPayloadStored(body, hello.node_id),
                .payload_request => self.onPayloadRequest(body, hello.node_id),
                .fence_request => self.onFenceRequest(body, hello.node_id),
                .fence_ack => self.onFenceAck(body, hello.node_id),
                .snapshot_request => self.onSnapshotRequest(hello.node_id),
                .snapshot_begin => try self.onSnapshotBegin(
                    body,
                    &install,
                    hello.node_id,
                ),
                .snapshot_chunk => try self.onSnapshotChunk(body, &install),
                .snapshot_end => try self.onSnapshotEnd(&install, hello.node_id),
                .checkpoint_proof_request => self.onCheckpointProofRequest(
                    body,
                    hello.node_id,
                ),
                .checkpoint_proof_reply => self.onCheckpointProofReply(
                    body,
                    hello.node_id,
                ),
                .learner_commit => try self.onLearnerCommit(body, hello.node_id),
                .learner_heartbeat => try self.onLearnerHeartbeat(
                    body,
                    hello.node_id,
                ),
                else => return error.InvalidFrame,
            }
        }
    }

    fn onEnvelopeFrame(self: *Server, body: []const u8, from: paxos.NodeId) !void {
        if (body.len < 8) return error.InvalidFrame;
        const frame_configuration = std.mem.readInt(u64, body[0..8], .little);
        const envelope = try wire.decodeEnvelope(body[8..]);
        if (envelope.from != from or envelope.to != self.node.identity.node_id) {
            return error.InvalidFrame;
        }

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failed) return;

        const local_configuration = self.node.identity.configuration_id;
        if (frame_configuration < local_configuration) return;
        if (frame_configuration > local_configuration) {
            // The cluster moved to an epoch we have not completed.
            if (!self.node.rollover_pending) {
                self.requestSnapshot(from);
            }
            return;
        }

        switch (envelope.message) {
            .heartbeat => |m| {
                if (m.decided_through > self.observed_leader_decided) {
                    self.observed_leader_decided = m.decided_through;
                }
            },
            else => {},
        }

        // Payload-before-vote: never process an accept or commit whose
        // payload bytes are not durable locally.
        if (wire.envelopePayloadHash(envelope)) |hash| {
            if (self.node.store.verify(hash)) |_| {} else |_| {
                self.holdEnvelope(hash, envelope, from);
                if (self.senderFor(from)) |sender| {
                    const frame = wire.frameAlloc(
                        self.gpa,
                        .payload_request,
                        &.{&hash},
                    ) catch return;
                    sender.enqueue(frame);
                }
                return;
            }
        }

        self.node.stepEnvelope(envelope) catch |err| {
            std.log.warn("step failure: {s}", .{@errorName(err)});
            self.failed = true;
            self.failEverything();
            return;
        };
        self.pump();
    }

    fn onLearnerCommit(self: *Server, body: []const u8, from: paxos.NodeId) !void {
        const commit = try wire.LearnerCommit.decode(body);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failed or self.node.isVoter()) return error.InvalidFrame;
        // Only a configured voter may certify a chosen slot to a learner; a
        // standby or read replica replays state but never certifies it.
        const source = self.addressOf(from) orelse return error.NotMember;
        if (!source.role.capabilities().votes) return error.InvalidFrame;
        if (commit.configuration_id < self.node.identity.configuration_id) return;
        if (commit.configuration_id > self.node.identity.configuration_id) {
            self.requestSnapshot(from);
            return;
        }
        if (entryPayloadHash(commit.entry)) |hash| {
            self.node.store.verify(hash) catch return error.PayloadMissing;
        }
        try self.node.learnChosen(from, commit.slot, commit.entry);
        self.learner_leader = from;
        self.learner_last_contact_tick = self.tick_count;
        self.pump();
    }

    fn onLearnerHeartbeat(
        self: *Server,
        body: []const u8,
        from: paxos.NodeId,
    ) !void {
        const heartbeat = try wire.LearnerHeartbeat.decode(body);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failed or self.node.isVoter()) return error.InvalidFrame;
        const source = self.addressOf(from) orelse return error.NotMember;
        if (!source.role.capabilities().votes) return error.InvalidFrame;
        if (heartbeat.configuration_id < self.node.identity.configuration_id) return;
        if (heartbeat.configuration_id > self.node.identity.configuration_id) {
            self.requestSnapshot(from);
            return;
        }
        if (heartbeat.decided_through > self.observed_leader_decided) {
            self.observed_leader_decided = heartbeat.decided_through;
        }
        self.learner_leader = from;
        self.learner_last_contact_tick = self.tick_count;
    }

    fn holdEnvelope(
        self: *Server,
        hash: command.HashBytes,
        envelope: Log.Envelope,
        from: paxos.NodeId,
    ) void {
        if (!self.held.contains(hash)) {
            // Bounded queue: drop; retransmission recovers.
            if (self.held_total >= held_hash_limit) return;
            self.held.put(hash, .{}) catch return;
            self.held_total += 1;
        }
        const held_entry = self.held.getPtr(hash) orelse return;
        held_entry.from = from;
        if (held_entry.count < held_entry.envelopes.len) {
            held_entry.envelopes[held_entry.count] = envelope;
            held_entry.count += 1;
        }
    }

    fn onPayloadData(self: *Server, body: []const u8, from: paxos.NodeId) !void {
        if (body.len < 32) return error.InvalidFrame;
        const payload = body[32..];
        const digest = payload_store_mod.PayloadStore.hashOf(payload);
        if (!std.mem.eql(u8, body[0..32], &digest)) return error.InvalidFrame;

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failed) return;
        _ = self.node.store.put(payload) catch |err| {
            std.log.warn("payload store failure: {s}", .{@errorName(err)});
            self.failed = true;
            self.failEverything();
            return;
        };

        // Emitted only after PayloadStore.put has flushed and atomically
        // installed (or verified) the content-addressed object. Power-loss
        // durability follows at this node's next journal barrier, which
        // precedes any vote or recovered value referencing the payload;
        // the ack itself only gates the sender's envelope release.
        if (self.senderFor(from)) |sender| {
            const ack = wire.frameAlloc(self.gpa, .payload_stored, &.{&digest}) catch
                return;
            sender.enqueue(ack);
        }
        if (self.held.fetchRemove(digest)) |entry| {
            self.held_total -= 1;
            for (entry.value.envelopes[0..entry.value.count]) |envelope| {
                self.node.stepEnvelope(envelope) catch |err| {
                    std.log.warn("step failure: {s}", .{@errorName(err)});
                    self.failed = true;
                    self.failEverything();
                    return;
                };
            }
            self.pump();
        }
    }

    fn onPayloadStored(self: *Server, body: []const u8, from: paxos.NodeId) void {
        if (body.len != 32) return;
        var hash: command.HashBytes = undefined;
        @memcpy(&hash, body[0..32]);
        const sender = self.senderFor(from) orelse return;
        sender.ackPayload(hash);
    }

    fn onPayloadRequest(self: *Server, body: []const u8, from: paxos.NodeId) void {
        if (body.len != 32) return;
        var hash: command.HashBytes = undefined;
        @memcpy(&hash, body[0..32]);
        const sender = self.senderFor(from) orelse return;

        self.mutex.lockUncancelable(self.io);
        const payload = self.node.store.load(self.gpa, hash) catch {
            self.mutex.unlock(self.io);
            return;
        };
        self.mutex.unlock(self.io);
        defer self.gpa.free(payload);
        const frame = wire.frameAlloc(self.gpa, .payload_data, &.{ &hash, payload }) catch
            return;
        sender.enqueue(frame);
    }

    fn onFenceRequest(self: *Server, body: []const u8, from: paxos.NodeId) void {
        const request = wire.FenceRequest.decode(body) catch return;
        const sender = self.senderFor(from) orelse return;

        self.mutex.lockUncancelable(self.io);
        const promised = self.node.log.core.durable.promised;
        const ok = request.ballot.eql(promised);
        self.mutex.unlock(self.io);

        const ack = wire.FenceAck{
            .fence_id = request.fence_id,
            .ok = ok,
            .promised = promised,
        };
        var ack_buffer: [wire.FenceAck.encoded_size]u8 = undefined;
        const encoded = ack.encode(&ack_buffer);
        const frame = wire.frameAlloc(self.gpa, .fence_ack, &.{encoded}) catch return;
        sender.enqueue(frame);
    }

    fn onFenceAck(self: *Server, body: []const u8, from: paxos.NodeId) void {
        const ack = wire.FenceAck.decode(body) catch return;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.fences.items) |fence| {
            if (fence.id != ack.fence_id) continue;
            if (ack.ok and ack.promised.eql(fence.ballot)) {
                fence.noteAck(from);
            } else {
                fence.failed = true;
            }
            break;
        }
        self.pump();
    }

    fn onSnapshotRequest(self: *Server, from: paxos.NodeId) void {
        const sender = self.senderFor(from) orelse return;

        self.mutex.lockUncancelable(self.io);
        var handle = self.node.openCurrentSnapshot() catch {
            self.mutex.unlock(self.io);
            return;
        };
        self.mutex.unlock(self.io);
        defer handle.close(self.io, self.gpa);

        const begin = wire.SnapshotBegin{
            .configuration_id = handle.configuration_id,
            .name = handle.name,
            .db_size = handle.db_size,
            .manifest = handle.manifest,
            .proof = handle.proof,
        };
        var begin_buffer: [wire.SnapshotBegin.max_encoded_size]u8 = undefined;
        const begin_encoded = begin.encode(&begin_buffer);
        const begin_frame = wire.frameAlloc(self.gpa, .snapshot_begin, &.{begin_encoded}) catch
            return;
        if (!sender.enqueueBackpressure(begin_frame)) return;

        var offset: u64 = 0;
        const chunk = self.gpa.alloc(u8, snapshot_chunk_bytes) catch return;
        defer self.gpa.free(chunk);
        while (offset < handle.db_size) {
            const read = handle.file.readPositionalAll(self.io, chunk, offset) catch return;
            if (read == 0) break;
            var offset_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &offset_bytes, offset, .little);
            const frame = wire.frameAlloc(
                self.gpa,
                .snapshot_chunk,
                &.{ &offset_bytes, chunk[0..read] },
            ) catch return;
            if (!sender.enqueueBackpressure(frame)) return;
            offset += read;
        }
        const end_frame = wire.frameAlloc(self.gpa, .snapshot_end, &.{}) catch return;
        _ = sender.enqueueBackpressure(end_frame);
    }

    fn onSnapshotBegin(
        self: *Server,
        body: []const u8,
        install: *InstallState,
        from: paxos.NodeId,
    ) !void {
        const begin = try wire.SnapshotBegin.decode(body);
        install.reset(self.io, self.gpa);

        self.mutex.lockUncancelable(self.io);
        if (begin.configuration_id <= self.node.identity.configuration_id) {
            self.mutex.unlock(self.io);
            return;
        }
        if (begin.db_size == 0 or begin.db_size > self.options.max_transfer_bytes) {
            self.mutex.unlock(self.io);
            return error.InvalidFrame;
        }
        const proof_digest = self.node.validateCheckpointProof(
            begin.proof,
            begin.configuration_id,
            begin.name,
            begin.manifest,
        ) catch |err| {
            self.mutex.unlock(self.io);
            return err;
        };
        self.mutex.unlock(self.io);

        const proof = try checkpoint_proof.decode(begin.proof);
        try self.confirmCheckpointProof(
            proof.sealed_configuration_id,
            proof_digest,
            from,
        );

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        // Another handler may have advanced us while the quorum probe was
        // in flight. Never let an older transfer replace newer local state.
        if (begin.configuration_id <= self.node.identity.configuration_id) return;
        var dir = try self.node.beginSnapshotInstall();
        errdefer dir.close(self.io);
        const file = try dir.createFile(self.io, "db", .{ .read = true });
        install.dir = dir;
        install.file = file;
        install.configuration_id = begin.configuration_id;
        install.db_size = begin.db_size;
        install.received = 0;
        install.name = begin.name;
        install.manifest = try self.gpa.dupe(u8, begin.manifest);
        errdefer {
            self.gpa.free(install.manifest.?);
            install.manifest = null;
        }
        install.proof = try self.gpa.dupe(u8, begin.proof);
    }

    fn onSnapshotChunk(self: *Server, body: []const u8, install: *InstallState) !void {
        const chunk = try wire.SnapshotChunk.decode(body);
        const file = install.file orelse return;
        const chunk_end = std.math.add(u64, chunk.offset, chunk.bytes.len) catch
            return error.InvalidFrame;
        if (chunk.offset != install.received or
            chunk.bytes.len == 0 or
            chunk.bytes.len > snapshot_chunk_bytes or
            chunk_end > install.db_size)
        {
            return error.InvalidFrame;
        }
        try file.writePositionalAll(self.io, chunk.bytes, chunk.offset);
        install.received += chunk.bytes.len;
    }

    fn onSnapshotEnd(self: *Server, install: *InstallState, from: paxos.NodeId) !void {
        const file = install.file orelse return;
        if (install.received != install.db_size) return error.InvalidFrame;
        try durability.syncFile(self.io, file);
        file.close(self.io);
        install.file = null;
        if (install.dir) |*dir| dir.close(self.io);
        install.dir = null;
        const manifest = install.manifest orelse return;
        const proof = install.proof orelse return;
        defer {
            self.gpa.free(manifest);
            install.manifest = null;
            self.gpa.free(proof);
            install.proof = null;
        }

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.snapshot_source = null;
        self.node.installSnapshot(
            install.configuration_id,
            install.name,
            manifest,
            proof,
        ) catch |err| {
            std.log.warn("snapshot install failed: {s}", .{@errorName(err)});
            return;
        };
        self.observed_leader_decided = 0;
        self.node.requestCatchUp(from) catch {};
        self.pump();
    }

    fn confirmCheckpointProof(
        self: *Server,
        sealed_configuration_id: u64,
        digest: [32]u8,
        source: paxos.NodeId,
    ) !void {
        var voter_count: usize = 0;
        for (self.options.members) |member| {
            if (member.role.capabilities().votes) voter_count += 1;
        }
        if (voter_count == 0) return error.CheckpointProofQuorum;

        self.proof_mutex.lockUncancelable(self.io);
        if (self.proof_waiter != null) {
            self.proof_mutex.unlock(self.io);
            return error.CheckpointProofBusy;
        }
        var nonce = self.next_proof_nonce;
        self.next_proof_nonce +%= 1;
        if (self.next_proof_nonce == 0) self.next_proof_nonce = 1;
        if (nonce == 0) nonce = 1;
        var waiter = CheckpointProofWaiter{
            .nonce = nonce,
            .sealed_configuration_id = sealed_configuration_id,
            .digest = digest,
            .needed = voter_count / 2 + 1,
        };
        // SnapshotBegin itself is a matching report from its authenticated
        // source. Count it exactly once when that source is a configured
        // voter, then probe the remaining voters independently.
        if (self.addressOf(source)) |member| {
            if (member.role.capabilities().votes) waiter.noteAck(source);
        }
        self.proof_waiter = &waiter;
        self.proof_mutex.unlock(self.io);
        defer {
            self.proof_mutex.lockUncancelable(self.io);
            if (self.proof_waiter == &waiter) self.proof_waiter = null;
            self.proof_mutex.unlock(self.io);
        }

        var probe_buffer: [wire.CheckpointProofProbe.encoded_size]u8 = undefined;
        const encoded = (wire.CheckpointProofProbe{
            .nonce = nonce,
            .sealed_configuration_id = sealed_configuration_id,
            .digest = digest,
        }).encode(&probe_buffer);
        for (self.senders.items) |sender| {
            if (!sender.peer.role.capabilities().votes) continue;
            const frame = try wire.frameAlloc(
                self.gpa,
                .checkpoint_proof_request,
                &.{encoded},
            );
            sender.enqueue(frame);
        }

        var elapsed_ms: u64 = 0;
        while (elapsed_ms < 2_000) : (elapsed_ms += 1) {
            self.proof_mutex.lockUncancelable(self.io);
            const confirmed = waiter.ack_count >= waiter.needed;
            self.proof_mutex.unlock(self.io);
            if (confirmed) return;
            if (self.isShutdown()) return error.Shutdown;
            self.io.sleep(.fromMilliseconds(1), .awake) catch
                return error.CheckpointProofQuorum;
        }
        return error.CheckpointProofQuorum;
    }

    fn onCheckpointProofRequest(
        self: *Server,
        body: []const u8,
        from: paxos.NodeId,
    ) void {
        const probe = wire.CheckpointProofProbe.decode(body) catch return;
        const sender = self.senderFor(from) orelse return;
        self.mutex.lockUncancelable(self.io);
        const local = self.node.currentCheckpointProofDigest(
            probe.sealed_configuration_id,
        ) catch {
            self.mutex.unlock(self.io);
            return;
        };
        self.mutex.unlock(self.io);
        if (!std.mem.eql(u8, &local, &probe.digest)) return;

        var reply_buffer: [wire.CheckpointProofProbe.encoded_size]u8 = undefined;
        const encoded = probe.encode(&reply_buffer);
        const frame = wire.frameAlloc(
            self.gpa,
            .checkpoint_proof_reply,
            &.{encoded},
        ) catch return;
        sender.enqueue(frame);
    }

    fn onCheckpointProofReply(
        self: *Server,
        body: []const u8,
        from: paxos.NodeId,
    ) void {
        const probe = wire.CheckpointProofProbe.decode(body) catch return;
        const member = self.addressOf(from) orelse return;
        if (!member.role.capabilities().votes) return;
        self.proof_mutex.lockUncancelable(self.io);
        defer self.proof_mutex.unlock(self.io);
        const waiter = self.proof_waiter orelse return;
        if (waiter.nonce != probe.nonce or
            waiter.sealed_configuration_id != probe.sealed_configuration_id or
            !std.mem.eql(u8, &waiter.digest, &probe.digest))
        {
            return;
        }
        waiter.noteAck(from);
    }

    // ------------------------------------------------------------------
    // Client connections
    // ------------------------------------------------------------------

    fn clientLoop(
        self: *Server,
        stream: std.Io.net.Stream,
        reader: *Io.Reader,
        writer: *Io.Writer,
        authenticated: ?*transport_auth.Session,
    ) !void {
        while (!self.isShutdown()) {
            const frame = try self.readConnectionFrame(
                stream,
                reader,
                authenticated,
            );
            if (frame.kind != .rpc_request) return error.InvalidFrame;
            const body = frame.body;
            defer self.gpa.free(body);

            if (isBackupRequest(self.gpa, body)) {
                try self.streamBackup(writer, authenticated);
                continue;
            }

            var response: std.Io.Writer.Allocating = .init(self.gpa);
            defer {
                @memset(response.writer.buffer, 0);
                response.deinit();
            }
            self.dispatch(body, &response.writer) catch |err| {
                response.clearRetainingCapacity();
                writeErrorResponse(&response.writer, "internal", @errorName(err)) catch {};
            };
            if (authenticated) |session| {
                try session.writeFrame(writer, .rpc_response, response.written());
            } else {
                try wire.writeFrame(writer, .rpc_response, response.written());
            }
            try writer.flush();
            if (self.isShutdown()) {
                self.stop_response_sent.store(true, .release);
                return;
            }
        }
    }

    fn readConnectionFrame(
        self: *Server,
        stream: std.Io.net.Stream,
        reader: *Io.Reader,
        authenticated: ?*transport_auth.Session,
    ) !transport_auth.Frame {
        const frame = if (authenticated) |session|
            try session.readFrame(self.gpa, reader)
        else blk: {
            const header = try wire.readFrameHeader(reader);
            const body = try wire.readFrameBody(self.gpa, reader, header);
            break :blk transport_auth.Frame{ .kind = header.kind, .body = body };
        };
        self.noteConnectionActivity(stream);
        return frame;
    }

    fn writeConnectionFrame(
        writer: *Io.Writer,
        authenticated: ?*transport_auth.Session,
        kind: wire.FrameKind,
        body: []const u8,
    ) !void {
        if (authenticated) |session| {
            try session.writeFrame(writer, kind, body);
        } else {
            try wire.writeFrame(writer, kind, body);
        }
    }

    fn streamBackup(
        self: *Server,
        writer: *Io.Writer,
        authenticated: ?*transport_auth.Session,
    ) !void {
        self.mutex.lockUncancelable(self.io);
        if (self.failed or !self.node.isLeader()) {
            self.mutex.unlock(self.io);
            return self.writeBackupError(writer, authenticated, "not_leader");
        }
        if (!self.node.single) {
            self.awaitReadFence() catch {
                self.mutex.unlock(self.io);
                return self.writeBackupError(writer, authenticated, "retry");
            };
        }
        var backup = self.node.openBackup() catch |err| {
            self.mutex.unlock(self.io);
            return self.writeBackupError(writer, authenticated, @errorName(err));
        };
        self.mutex.unlock(self.io);
        defer backup.close();

        var begin_buffer: [wire.BackupBegin.encoded_size]u8 = undefined;
        const begin = (wire.BackupBegin{
            .size = backup.size,
            .sha256 = backup.sha256,
        }).encode(&begin_buffer);
        try writeConnectionFrame(writer, authenticated, .backup_begin, begin);
        var bytes: [snapshot_chunk_bytes]u8 = undefined;
        var offset: u64 = 0;
        while (offset < backup.size) {
            const count = try backup.file.readPositionalAll(self.io, &bytes, offset);
            if (count == 0) return error.UnexpectedEndOfStream;
            var offset_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &offset_bytes, offset, .little);
            var frame: [8 + snapshot_chunk_bytes]u8 = undefined;
            @memcpy(frame[0..8], &offset_bytes);
            @memcpy(frame[8..][0..count], bytes[0..count]);
            try writeConnectionFrame(
                writer,
                authenticated,
                .backup_chunk,
                frame[0 .. 8 + count],
            );
            offset += count;
        }
        try writeConnectionFrame(writer, authenticated, .backup_end, &.{});
        try writer.flush();
    }

    fn writeBackupError(
        self: *Server,
        writer: *Io.Writer,
        authenticated: ?*transport_auth.Session,
        code: []const u8,
    ) !void {
        var response: std.Io.Writer.Allocating = .init(self.gpa);
        defer response.deinit();
        try writeErrorResponse(&response.writer, code, "backup unavailable");
        try writeConnectionFrame(
            writer,
            authenticated,
            .rpc_response,
            response.written(),
        );
        try writer.flush();
    }

    const Request = struct {
        op: []const u8 = "",
        sql: ?[]const u8 = null,
        session: ?u64 = null,
        sequence: ?u64 = null,
        level: ?[]const u8 = null,
        applied: ?u64 = null,
        leader: ?bool = null,
        timeout_ms: ?u64 = null,
        freshness_ms: ?u64 = null,
        retain: ?u64 = null,
        name: ?[]const u8 = null,
        node_id: ?u32 = null,
        ttl_seconds: ?u64 = null,
    };

    fn dispatch(self: *Server, body: []const u8, out: *Io.Writer) !void {
        const parsed = std.json.parseFromSlice(Request, self.gpa, body, .{
            .ignore_unknown_fields = true,
        }) catch {
            return writeErrorResponse(out, "bad_request", "malformed request");
        };
        defer parsed.deinit();
        const request = parsed.value;

        if (std.mem.eql(u8, request.op, "status")) {
            return self.opStatus(out);
        } else if (std.mem.eql(u8, request.op, "members")) {
            return self.opMembers(out);
        } else if (std.mem.eql(u8, request.op, "leader")) {
            return self.opLeader(out);
        } else if (std.mem.eql(u8, request.op, "exec")) {
            return self.opExec(request, out);
        } else if (std.mem.eql(u8, request.op, "query")) {
            return self.opQuery(request, out);
        } else if (std.mem.eql(u8, request.op, "session")) {
            return self.opSession(out);
        } else if (std.mem.eql(u8, request.op, "wait")) {
            return self.opWait(request, out);
        } else if (std.mem.eql(u8, request.op, "snapshot")) {
            return self.opSnapshot(out);
        } else if (std.mem.eql(u8, request.op, "integrity")) {
            return self.opIntegrity(out);
        } else if (std.mem.eql(u8, request.op, "hash")) {
            return self.opHash(out);
        } else if (std.mem.eql(u8, request.op, "expire-sessions")) {
            return self.opExpireSessions(request, out);
        } else if (std.mem.eql(u8, request.op, "issue-enrollment-token")) {
            return self.opIssueEnrollmentToken(request, out);
        } else if (std.mem.eql(u8, request.op, "failpoint")) {
            return self.opFailpoint(request, out);
        } else if (std.mem.eql(u8, request.op, "stop")) {
            self.shutdown_flag.store(true, .release);
            self.wakeAcceptLoop();
            return out.writeAll("{\"ok\":true}");
        }
        return writeErrorResponse(out, "bad_request", "unknown op");
    }

    fn opIssueEnrollmentToken(
        self: *Server,
        request: Request,
        out: *Io.Writer,
    ) !void {
        if (self.options.enrollment_ca_key == null) {
            return writeErrorResponse(
                out,
                "enrollment_disabled",
                "this node is not an enrollment issuer",
            );
        }
        const node_id = request.node_id orelse return writeErrorResponse(
            out,
            "bad_request",
            "node_id is required",
        );
        const ttl_seconds = request.ttl_seconds orelse enrollment.default_ttl_seconds;
        if (ttl_seconds == 0 or ttl_seconds > enrollment.maximum_ttl_seconds or
            !self.isConfiguredNode(node_id) or node_id == self.node.identity.node_id or
            self.peerRevoked(node_id))
        {
            return writeErrorResponse(
                out,
                "bad_request",
                "target must be a non-revoked configured peer and TTL at most 24 hours",
            );
        }
        const issued = enrollment.issueToken(
            self.io,
            self.options.directory,
            node_id,
            self.node.identity.node_id,
            self.node.identity.database_id,
            ttl_seconds,
        ) catch |err| return writeErrorResponse(
            out,
            "enrollment_unavailable",
            @errorName(err),
        );
        const token_hex = std.fmt.bytesToHex(issued.secret, .lower);
        try out.print(
            "{{\"ok\":true,\"node_id\":{d},\"issuer_node_id\":{d}," ++
                "\"database_id\":\"{x:0>32}\",\"expires_unix_seconds\":{d}," ++
                "\"token\":\"{s}\"}}",
            .{
                node_id,
                self.node.identity.node_id,
                self.node.identity.database_id,
                issued.expires_unix_seconds,
                &token_hex,
            },
        );
    }

    fn opStatus(self: *Server, out: *Io.Writer) !void {
        self.mutex.lockUncancelable(self.io);
        const status = self.node.status();
        const leader = self.knownLeader();
        self.mutex.unlock(self.io);
        const chain_hex = std.fmt.bytesToHex(status.chain, .lower);
        try out.print(
            "{{\"ok\":true,\"node_id\":{d},\"database_id\":\"{x:0>32}\"," ++
                "\"configuration_id\":{d},\"role\":\"{s}\"," ++
                "\"node_type\":\"{s}\",\"leader\":{?d}," ++
                "\"ballot\":{{\"round\":{d},\"priority\":{d},\"node\":{d}}}," ++
                "\"decided_slot\":{d},\"applied_slot\":{d}," ++
                "\"journal_records\":{d},\"epoch_capacity\":{d}," ++
                "\"chain\":\"{s}\",\"page_size\":{d},\"snapshot\":",
            .{
                status.node_id,          status.database_id,
                status.configuration_id, status.role,
                status.node_type,        leader,
                status.ballot.round,     status.ballot.priority,
                status.ballot.node,      status.decided_slot,
                status.applied_slot,     status.journal_records,
                status.epoch_capacity,   &chain_hex,
                status.page_size,
            },
        );
        if (status.snapshot) |name| {
            try out.print("\"{s}\"}}", .{&name});
        } else {
            try out.writeAll("null}");
        }
    }

    fn opMembers(self: *Server, out: *Io.Writer) !void {
        self.mutex.lockUncancelable(self.io);
        const leader = self.knownLeader();
        const self_id = self.node.identity.node_id;
        self.mutex.unlock(self.io);
        try out.writeAll(
            "{\"ok\":true,\"voter_membership\":\"static\",\"nodes\":[",
        );
        for (self.options.members, 0..) |member, index| {
            if (index > 0) try out.writeAll(",");
            const capabilities = member.role.capabilities();
            try out.print(
                "{{\"id\":{d},\"host\":\"{s}\",\"port\":{d}," ++
                    "\"role\":\"{s}\",\"votes\":{},\"campaigns\":{}," ++
                    "\"stores_log\":{},\"serves_reads\":{}," ++
                    "\"serves_writes\":{},\"promotion_eligible\":{}," ++
                    "\"self\":{},\"leader\":{}}}",
                .{
                    member.id,
                    member.host,
                    member.port,
                    member.role.name(),
                    capabilities.votes,
                    capabilities.campaigns,
                    capabilities.stores_log,
                    capabilities.serves_reads,
                    capabilities.serves_writes,
                    capabilities.promotion_eligible,
                    member.id == self_id,
                    leader != null and member.id == leader.?,
                },
            );
        }
        try out.writeAll("]}");
    }

    fn opLeader(self: *Server, out: *Io.Writer) !void {
        self.mutex.lockUncancelable(self.io);
        const leader = self.knownLeader();
        self.mutex.unlock(self.io);
        if (leader) |id| {
            if (self.addressOf(id)) |address| {
                return out.print(
                    "{{\"ok\":true,\"leader\":{{\"id\":{d},\"host\":\"{s}\",\"port\":{d}}}}}",
                    .{ id, address.host, address.port },
                );
            }
            return out.print("{{\"ok\":true,\"leader\":{{\"id\":{d}}}}}", .{id});
        }
        try out.writeAll("{\"ok\":true,\"leader\":null}");
    }

    fn writeNotLeader(self: *Server, out: *Io.Writer) !void {
        self.mutex.lockUncancelable(self.io);
        const leader = self.knownLeader();
        const self_id = self.node.identity.node_id;
        self.mutex.unlock(self.io);
        if (leader) |id| {
            if (id != self_id) {
                if (self.addressOf(id)) |address| {
                    return out.print(
                        "{{\"ok\":false,\"error\":\"not_leader\"," ++
                            "\"leader\":{{\"id\":{d},\"host\":\"{s}\",\"port\":{d}}}}}",
                        .{ id, address.host, address.port },
                    );
                }
            }
        }
        try out.writeAll("{\"ok\":false,\"error\":\"not_leader\",\"leader\":null}");
    }

    const WriteError = error{
        NotLeader,
        Ambiguous,
        OpTimeout,
        Unavailable,
    };

    const ExecOutcome = node_mod.ExecResult;

    /// Runs one replicated write to completion: appends under the writer
    /// gate, then blocks until the slot commits and carries our batch.
    fn runWrite(
        self: *Server,
        comptime run: anytype,
        context: anytype,
    ) anyerror!ExecOutcome {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failed) return error.Unavailable;

        // One replicated write at a time; a dependent slot is never built
        // before its predecessor is chosen.
        var start_tick: u64 = self.tick_count;
        while (self.writer_busy) {
            if (self.elapsedMs(start_tick) > op_timeout_ms) return error.OpTimeout;
            self.writer_cond.waitUncancelable(self.io, &self.mutex);
        }
        self.writer_busy = true;
        defer {
            self.writer_busy = false;
            self.writer_cond.signal(self.io);
        }

        if (!self.node.isLeader()) return error.NotLeader;

        // Roll the epoch before it fills; wait out an in-progress rollover.
        start_tick = self.tick_count;
        while (self.node.epochNearlyFull() or self.node.rollover_pending or
            self.node.log.stop_pending)
        {
            if (self.node.isLeader() and !self.checkpoint_started and
                !self.node.rollover_pending and !self.node.log.stop_pending)
            {
                try self.node.prepareCheckpoint();
                self.checkpoint_started = true;
                self.pump();
                continue;
            }
            if (self.elapsedMs(start_tick) > op_timeout_ms) return error.OpTimeout;
            self.rollover_cond.waitUncancelable(self.io, &self.mutex);
            if (self.failed) return error.Unavailable;
            if (!self.node.isLeader()) return error.NotLeader;
        }

        self.node.ensureWriter() catch return error.Unavailable;

        const result: ExecOutcome = run(self.node, context) catch |err| {
            if (self.node.needsResync() and !self.node.storageFailed()) {
                self.node.resyncImage() catch {
                    self.failed = true;
                    self.failEverything();
                };
            }
            if (self.node.storageFailed()) {
                self.failed = true;
                self.failEverything();
            }
            return err;
        };
        if (result.replayed) return result;

        if (self.node.single) {
            failpoint.hit("before_client_reply");
            return result;
        }
        self.pump();

        var waiter = WriteWaiter{
            .slot = result.slot,
            .batch_id = self.node.pendingBatchId() orelse {
                // Already decided (accounting ran inside consumeEffects).
                if (self.node.applied_slot >= result.slot) {
                    failpoint.hit("before_client_reply");
                    return result;
                }
                return error.Ambiguous;
            },
        };
        self.write_waiter = &waiter;
        self.pump();
        start_tick = self.tick_count;
        while (waiter.outcome == .pending) {
            if (self.elapsedMs(start_tick) > op_timeout_ms) {
                if (self.write_waiter == &waiter) self.write_waiter = null;
                return error.OpTimeout;
            }
            waiter.cond.waitUncancelable(self.io, &self.mutex);
        }
        switch (waiter.outcome) {
            .committed => {
                failpoint.hit("before_client_reply");
                return result;
            },
            else => return error.Ambiguous,
        }
    }

    fn opExec(self: *Server, request: Request, out: *Io.Writer) !void {
        const sql_text = request.sql orelse
            return writeErrorResponse(out, "bad_request", "exec needs sql");
        if ((request.session == null) != (request.sequence == null)) {
            return writeErrorResponse(
                out,
                "bad_request",
                "session and sequence go together",
            );
        }
        const sql = try self.gpa.dupeZ(u8, sql_text);
        defer self.gpa.free(sql);

        if (try self.ensureSchemaForWrite(out) == null) return;

        const Ctx = struct {
            sql: [:0]const u8,
            session: ?u64,
            sequence: ?u64,
        };
        const outcome = self.runWrite(struct {
            fn run(node: *Node, context: Ctx) !ExecOutcome {
                if (context.session) |session| {
                    return node.execIdempotent(session, context.sequence.?, context.sql);
                }
                return node.exec(context.sql);
            }
        }.run, Ctx{
            .sql = sql,
            .session = request.session,
            .sequence = request.sequence,
        }) catch |err| return self.writeWriteError(err, out);

        try out.print(
            "{{\"ok\":true,\"changes\":{d},\"slot\":{d},\"replayed\":{}}}",
            .{ outcome.changes, outcome.slot, outcome.replayed },
        );
    }

    /// Bootstraps the replicated schema when absent. Returns null when a
    /// response was already written (error path).
    fn ensureSchemaForWrite(self: *Server, out: *Io.Writer) !?void {
        self.mutex.lockUncancelable(self.io);
        const ready = self.node.schemaReady() catch false;
        if (ready) {
            self.mutex.unlock(self.io);
            return {};
        }
        if (!self.node.isLeader()) {
            self.mutex.unlock(self.io);
            try self.writeNotLeader(out);
            return null;
        }
        self.mutex.unlock(self.io);

        // Bootstrap must bypass the application authorizer: it creates the
        // reserved `__zaxon_*` tables that application SQL cannot touch.
        _ = self.runWrite(struct {
            fn run(node: *Node, context: void) !ExecOutcome {
                _ = context;
                return node.bootstrapSchemaIfMissing();
            }
        }.run, {}) catch |err| {
            try self.writeWriteError(err, out);
            return null;
        };
        return {};
    }

    fn writeWriteError(self: *Server, err: anyerror, out: *Io.Writer) !void {
        switch (err) {
            error.NotLeader => try self.writeNotLeader(out),
            error.Ambiguous => try writeErrorResponse(
                out,
                "ambiguous",
                "write fate unknown; retry idempotently",
            ),
            error.OpTimeout => try writeErrorResponse(out, "timeout", "operation timed out"),
            error.Unavailable => try writeErrorResponse(out, "unavailable", "node failed"),
            error.SqliteError, error.SqliteBusy => {
                self.mutex.lockUncancelable(self.io);
                var message_buffer: [512]u8 = undefined;
                const raw = self.node.lastSqliteMessage();
                const len = @min(raw.len, message_buffer.len);
                @memcpy(message_buffer[0..len], raw[0..len]);
                self.mutex.unlock(self.io);
                try writeSqlError(out, message_buffer[0..len]);
            },
            error.UnknownSession, error.SequenceGap, error.ResultExpired => {
                try writeErrorResponse(out, "session", @errorName(err));
            },
            error.LogSealed => try writeErrorResponse(out, "retry", "epoch rolling over"),
            error.TransactionTooLarge => try writeErrorResponse(
                out,
                "too_large",
                "transaction payload exceeds the 64 MiB wire limit",
            ),
            error.StorageFailed => try writeErrorResponse(
                out,
                "unavailable",
                "durable storage failed; node stopped",
            ),
            else => try writeErrorResponse(out, "internal", @errorName(err)),
        }
    }

    fn opQuery(self: *Server, request: Request, out: *Io.Writer) !void {
        const sql = request.sql orelse
            return writeErrorResponse(out, "bad_request", "query needs sql");
        if (sql.len > 1024 * 1024) {
            return writeErrorResponse(out, "too_large", "query SQL exceeds 1 MiB");
        }
        const Level = enum { any, leader, linearizable };
        const level: Level = blk: {
            const text = request.level orelse break :blk .linearizable;
            if (std.mem.eql(u8, text, "any")) break :blk .any;
            if (std.mem.eql(u8, text, "leader")) break :blk .leader;
            if (std.mem.eql(u8, text, "linearizable")) break :blk .linearizable;
            return writeErrorResponse(out, "bad_request", "unknown level");
        };

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failed) return writeErrorResponse(out, "unavailable", "node failed");

        if (level != .any and !self.node.isLeader()) {
            self.mutex.unlock(self.io);
            defer self.mutex.lockUncancelable(self.io);
            return self.writeNotLeader(out);
        }

        if (request.freshness_ms != null and level != .any) {
            return writeErrorResponse(
                out,
                "bad_request",
                "freshness_ms requires level any",
            );
        }
        if (request.freshness_ms) |maximum| {
            if (!self.node.isVoter()) {
                const contact = self.learner_last_contact_tick orelse
                    return writeErrorResponse(
                        out,
                        "stale",
                        "learner has not contacted a leader",
                    );
                if (self.elapsedMs(contact) > maximum or
                    self.node.applied_slot < self.observed_leader_decided)
                {
                    return writeErrorResponse(
                        out,
                        "stale",
                        "learner exceeds the requested freshness bound",
                    );
                }
            }
        }

        if (level == .linearizable and !self.node.single) {
            self.awaitReadFence() catch |err| switch (err) {
                error.ReadFenceTimeout => return writeErrorResponse(
                    out,
                    "timeout",
                    "fence timed out",
                ),
                error.ReadFenceLeadershipChanged => return writeErrorResponse(
                    out,
                    "retry",
                    "leadership changed during fence",
                ),
                else => return err,
            };
        }

        var result = self.node.queryWithLimits(self.gpa, sql, .{
            .max_rows = self.options.max_query_rows,
            .max_bytes = self.options.max_query_bytes,
            .max_vm_steps = self.options.max_query_vm_steps,
        }) catch |err| {
            if (err == error.RoleCannotRead) {
                return writeErrorResponse(
                    out,
                    "forbidden",
                    "this node type does not serve SQLite reads",
                );
            }
            const message = switch (err) {
                error.WriteInReadQuery => "statement is not read-only; use exec",
                error.NoDatabaseImage => "no database image on this member yet",
                error.QueryRowLimit => "query exceeded the remote row limit",
                error.QueryResultTooLarge => "query exceeded the remote byte limit",
                error.SqliteInterrupted => "query exceeded the SQLite VM budget",
                else => self.node.lastSqliteMessage(),
            };
            return writeSqlError(out, message);
        };
        defer result.deinit();

        try out.writeAll("{\"ok\":true,\"columns\":[");
        for (result.columns, 0..) |column, index| {
            if (index > 0) try out.writeAll(",");
            try writeJsonString(out, column);
        }
        try out.writeAll("],\"rows\":[");
        for (result.rows, 0..) |row, row_index| {
            if (row_index > 0) try out.writeAll(",");
            try out.writeAll("[");
            for (row, 0..) |cell, index| {
                if (index > 0) try out.writeAll(",");
                if (cell) |text| {
                    try writeJsonString(out, text);
                } else {
                    try out.writeAll("null");
                }
            }
            try out.writeAll("]");
        }
        try out.print("],\"level\":\"{s}\"}}", .{@tagName(level)});
    }

    /// Confirms this exact Paxos ballot with a distinct-member read quorum.
    /// The server mutex must be held; condition waits release it temporarily.
    fn awaitReadFence(self: *Server) !void {
        var fence = FenceWaiter{
            .id = self.next_fence_id,
            .ballot = self.node.log.core.ballot,
            .fence_slot = self.node.log.decidedThrough(),
            .needed = self.node.log.core.membership.readQuorum(),
        };
        fence.noteAck(self.node.identity.node_id);
        self.next_fence_id += 1;
        try self.fences.append(self.gpa, &fence);

        var request_buffer: [wire.FenceRequest.encoded_size]u8 = undefined;
        const encoded = (wire.FenceRequest{
            .ballot = fence.ballot,
            .fence_id = fence.id,
            .fence_slot = fence.fence_slot,
        }).encode(&request_buffer);
        for (self.senders.items) |sender| {
            const frame = try wire.frameAlloc(self.gpa, .fence_request, &.{encoded});
            sender.enqueue(frame);
        }
        self.pump();

        const start_tick = self.tick_count;
        while (!fence.done) {
            if (self.elapsedMs(start_tick) > op_timeout_ms) {
                self.removeFence(&fence);
                return error.ReadFenceTimeout;
            }
            fence.cond.waitUncancelable(self.io, &self.mutex);
        }
        if (fence.failed) return error.ReadFenceLeadershipChanged;
    }

    fn removeFence(self: *Server, fence: *FenceWaiter) void {
        for (self.fences.items, 0..) |candidate, index| {
            if (candidate == fence) {
                _ = self.fences.swapRemove(index);
                return;
            }
        }
    }

    fn opSession(self: *Server, out: *Io.Writer) !void {
        if (try self.ensureSchemaForWrite(out) == null) return;

        var session_id: u64 = 0;
        _ = self.runWrite(struct {
            fn run(node: *Node, context: *u64) !ExecOutcome {
                context.* = try node.openSession();
                return node.lastAppend();
            }
        }.run, &session_id) catch |err| return self.writeWriteError(err, out);
        try out.print("{{\"ok\":true,\"session_id\":{d}}}", .{session_id});
    }

    fn opExpireSessions(self: *Server, request: Request, out: *Io.Writer) !void {
        const retain = request.retain orelse
            return writeErrorResponse(out, "bad_request", "expire-sessions needs retain");
        if (try self.ensureSchemaForWrite(out) == null) return;
        const outcome = self.runWrite(struct {
            fn run(node: *Node, context: u64) !ExecOutcome {
                return node.expireSessions(context);
            }
        }.run, retain) catch |err| return self.writeWriteError(err, out);
        try out.print("{{\"ok\":true,\"expired\":{d}}}", .{outcome.changes});
    }

    fn opWait(self: *Server, request: Request, out: *Io.Writer) !void {
        const timeout_ms = request.timeout_ms orelse op_timeout_ms;
        var waiter = WaitWaiter{
            .min_applied = @intCast(request.applied orelse 0),
            .need_leader = request.leader orelse false,
        };

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (waiter.satisfied(self.node)) {
            return self.writeWaitResponse(out);
        }
        try self.waiters.append(self.gpa, &waiter);
        const start_tick = self.tick_count;
        while (!waiter.done) {
            waiter.cond.waitUncancelable(self.io, &self.mutex);
            if (waiter.done) break;
            if (waiter.satisfied(self.node)) {
                waiter.done = true;
                for (self.waiters.items, 0..) |candidate, index| {
                    if (candidate == &waiter) {
                        _ = self.waiters.swapRemove(index);
                        break;
                    }
                }
                break;
            }
            if (self.elapsedMs(start_tick) >= timeout_ms) {
                for (self.waiters.items, 0..) |candidate, index| {
                    if (candidate == &waiter) {
                        _ = self.waiters.swapRemove(index);
                        break;
                    }
                }
                return writeErrorResponse(out, "timeout", "condition not reached");
            }
        }
        return self.writeWaitResponse(out);
    }

    fn writeWaitResponse(self: *Server, out: *Io.Writer) !void {
        // Caller holds the mutex.
        try out.print(
            "{{\"ok\":true,\"applied_slot\":{d},\"decided_slot\":{d}," ++
                "\"leader\":{?d},\"configuration_id\":{d}}}",
            .{
                self.node.applied_slot,
                self.node.log.decidedThrough(),
                self.node.currentLeader(),
                self.node.identity.configuration_id,
            },
        );
    }

    fn opSnapshot(self: *Server, out: *Io.Writer) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failed) {
            return writeErrorResponse(out, "unavailable", "node failed");
        }
        if (!self.node.isLeader()) {
            self.mutex.unlock(self.io);
            defer self.mutex.lockUncancelable(self.io);
            return self.writeNotLeader(out);
        }
        if (self.node.single) {
            self.node.snapshot() catch |err| {
                return writeErrorResponse(out, "internal", @errorName(err));
            };
            self.pump();
            return out.print(
                "{{\"ok\":true,\"configuration_id\":{d}}}",
                .{self.node.identity.configuration_id},
            );
        }
        const before = self.node.identity.configuration_id;
        if (!self.checkpoint_started and !self.node.rollover_pending) {
            self.node.prepareCheckpoint() catch |err| {
                return writeErrorResponse(out, "internal", @errorName(err));
            };
            self.checkpoint_started = true;
            self.pump();
        }
        const start_tick = self.tick_count;
        while (self.node.identity.configuration_id == before) {
            if (self.elapsedMs(start_tick) > op_timeout_ms) {
                return writeErrorResponse(out, "timeout", "rollover incomplete");
            }
            self.rollover_cond.waitUncancelable(self.io, &self.mutex);
        }
        return out.print(
            "{{\"ok\":true,\"configuration_id\":{d}}}",
            .{self.node.identity.configuration_id},
        );
    }

    fn opIntegrity(self: *Server, out: *Io.Writer) !void {
        self.mutex.lockUncancelable(self.io);
        const report = self.node.integrityCheck() catch |err| {
            self.mutex.unlock(self.io);
            return writeErrorResponse(out, "internal", @errorName(err));
        };
        self.mutex.unlock(self.io);
        try out.print(
            "{{\"ok\":{},\"sqlite_ok\":{},\"chain_ok\":{},\"payloads_ok\":{}}}",
            .{ report.ok(), report.sqlite_ok, report.chain_ok, report.payloads_ok },
        );
    }

    fn opHash(self: *Server, out: *Io.Writer) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const content = self.node.contentHash() catch |err| {
            return writeErrorResponse(out, "internal", @errorName(err));
        };
        const chain_hex = std.fmt.bytesToHex(self.node.last_chain, .lower);
        const content_hex = std.fmt.bytesToHex(content, .lower);
        try out.print(
            "{{\"ok\":true,\"chain\":\"{s}\",\"content\":\"{s}\",\"applied_slot\":{d}}}",
            .{ &chain_hex, &content_hex, self.node.applied_slot },
        );
    }

    fn opFailpoint(self: *Server, request: Request, out: *Io.Writer) !void {
        if (!self.options.enable_failpoints) {
            return writeErrorResponse(out, "bad_request", "failpoints disabled");
        }
        const name = request.name orelse "";
        failpoint.arm(name);
        try out.writeAll("{\"ok\":true}");
    }
};

// ----------------------------------------------------------------------
// Peer sender: one outgoing connection per peer
// ----------------------------------------------------------------------

const PeerSender = struct {
    server: *Server,
    peer: PeerAddress,
    thread: std.Thread = undefined,
    mutex: std.Io.Mutex = .init,
    cond: std.Io.Condition = .init,
    queue: std.ArrayList([]u8) = .empty,
    queue_bytes: usize = 0,
    gated: std.ArrayList(GatedFrame) = .empty,
    gated_bytes: usize = 0,
    connected: bool = false,
    active_stream: ?std.Io.net.Stream = null,
    stored_payloads: std.AutoHashMap(command.HashBytes, void) = undefined,
    /// Highest current-epoch chosen slot queued on this connection.
    learned_through: paxos.Slot = 0,
    enqueued_count: u64 = 0,

    const GatedFrame = struct {
        hash: command.HashBytes,
        frame: []u8,
    };

    fn deinit(self: *PeerSender) void {
        for (self.queue.items) |frame| self.server.gpa.free(frame);
        for (self.gated.items) |item| self.server.gpa.free(item.frame);
        self.queue.deinit(self.server.gpa);
        self.gated.deinit(self.server.gpa);
        self.stored_payloads.deinit();
    }

    /// Takes ownership of `frame`. Drops when disconnected or over bounds;
    /// protocol retransmission recovers dropped frames.
    fn enqueue(self: *PeerSender, frame: []u8) void {
        _ = self.enqueueChecked(frame);
    }

    /// Takes ownership and reports whether the frame entered the bounded
    /// queue. The caller uses this for payload offers so it never records an
    /// offer that was actually dropped.
    fn enqueueChecked(self: *PeerSender, frame: []u8) bool {
        const io = self.server.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return self.enqueueLocked(frame);
    }

    /// Snapshot chunks are an ordered stream and cannot rely on Paxos
    /// retransmission. Waits for bounded queue capacity, transferring
    /// ownership on both success and failure.
    fn enqueueBackpressure(self: *PeerSender, frame: []u8) bool {
        const io = self.server.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        while (self.connected and !self.server.isShutdown() and
            (self.queue.items.len + self.gated.items.len >= sender_queue_limit or
                self.queue_bytes + self.gated_bytes + frame.len > sender_queue_byte_limit))
        {
            self.cond.waitUncancelable(io, &self.mutex);
        }
        if (!self.connected or self.server.isShutdown()) {
            self.server.gpa.free(frame);
            return false;
        }
        return self.enqueueLocked(frame);
    }

    fn enqueueLocked(self: *PeerSender, frame: []u8) bool {
        self.enqueued_count += 1;
        const faults = self.server.options.test_faults;
        if (faults.drop_every != 0 and
            self.enqueued_count % faults.drop_every == 0)
        {
            self.server.gpa.free(frame);
            return false;
        }
        if (!self.connected or
            self.queue.items.len + self.gated.items.len >= sender_queue_limit or
            self.queue_bytes + self.gated_bytes + frame.len > sender_queue_byte_limit)
        {
            self.server.gpa.free(frame);
            return false;
        }
        self.queue.append(self.server.gpa, frame) catch {
            self.server.gpa.free(frame);
            return false;
        };
        self.queue_bytes += frame.len;
        if (faults.reorder_pairs and self.queue.items.len >= 2 and
            self.enqueued_count % 2 == 0)
        {
            const last = self.queue.items.len - 1;
            std.mem.swap([]u8, &self.queue.items[last - 1], &self.queue.items[last]);
        }
        if (faults.duplicate_every != 0 and
            self.enqueued_count % faults.duplicate_every == 0 and
            self.queue.items.len + self.gated.items.len < sender_queue_limit and
            self.queue_bytes + self.gated_bytes + frame.len <= sender_queue_byte_limit)
        {
            if (self.server.gpa.dupe(u8, frame)) |duplicate| {
                if (self.queue.append(self.server.gpa, duplicate)) |_| {
                    self.queue_bytes += duplicate.len;
                } else |_| {
                    self.server.gpa.free(duplicate);
                }
            } else |_| {}
        }
        self.cond.signal(self.server.io);
        return true;
    }

    /// Holds an encoded Paxos envelope until this connection has received a
    /// durable storage acknowledgement for `hash`.
    fn gatePayload(self: *PeerSender, hash: command.HashBytes, frame: []u8) bool {
        const io = self.server.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.stored_payloads.contains(hash)) {
            return self.enqueueLocked(frame);
        }
        if (!self.connected or
            self.queue.items.len + self.gated.items.len >= sender_queue_limit or
            self.queue_bytes + self.gated_bytes + frame.len > sender_queue_byte_limit)
        {
            self.server.gpa.free(frame);
            return false;
        }
        self.gated.append(self.server.gpa, .{ .hash = hash, .frame = frame }) catch {
            self.server.gpa.free(frame);
            return false;
        };
        self.gated_bytes += frame.len;
        return true;
    }

    /// Records one per-connection storage ACK and releases every matching
    /// envelope. Duplicate ACKs are idempotent.
    fn ackPayload(self: *PeerSender, hash: command.HashBytes) void {
        const io = self.server.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.stored_payloads.put(hash, {}) catch return;
        var index: usize = 0;
        while (index < self.gated.items.len) {
            if (!std.mem.eql(u8, &self.gated.items[index].hash, &hash)) {
                index += 1;
                continue;
            }
            const item = self.gated.orderedRemove(index);
            self.gated_bytes -= item.frame.len;
            _ = self.enqueueLocked(item.frame);
        }
    }

    fn hasPayloadAck(self: *PeerSender, hash: command.HashBytes) bool {
        const io = self.server.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return self.stored_payloads.contains(hash);
    }

    fn isConnected(self: *PeerSender) bool {
        const io = self.server.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return self.connected;
    }

    fn disconnect(self: *PeerSender) void {
        const io = self.server.io;
        self.mutex.lockUncancelable(io);
        self.connected = false;
        if (self.active_stream) |stream| stream.shutdown(io, .both) catch {};
        self.cond.broadcast(io);
        self.mutex.unlock(io);
    }

    fn run(self: *PeerSender) void {
        const io = self.server.io;
        while (!self.server.isShutdown()) {
            if (self.server.peerRevoked(self.peer.id)) {
                io.sleep(.fromMilliseconds(200), .awake) catch {};
                continue;
            }
            const address = std.Io.net.IpAddress.parse(
                self.peer.host,
                self.peer.port,
            ) catch return;
            var stream = address.connect(io, .{ .mode = .stream }) catch {
                io.sleep(.fromMilliseconds(200), .awake) catch {};
                continue;
            };
            defer stream.close(io);
            var read_buffer: [64 * 1024]u8 = undefined;
            var write_buffer: [64 * 1024]u8 = undefined;
            var net_reader: std.Io.net.Stream.Reader = undefined;
            var net_writer: std.Io.net.Stream.Writer = undefined;
            var tls_stream: tls.Stream = undefined;
            var tls_active = false;
            defer if (tls_active) tls_stream.deinit();
            const reader: *Io.Reader, const writer: *Io.Writer = blk: {
                if (self.server.tls_client) |*context| {
                    tls_stream = tls.Stream.connect(
                        context,
                        stream,
                        &read_buffer,
                        &write_buffer,
                    ) catch {
                        io.sleep(.fromMilliseconds(200), .awake) catch {};
                        continue;
                    };
                    tls_active = true;
                    // The dialed member must present the certificate
                    // issued for its configured node id, not merely any
                    // certificate from the cluster CA.
                    var expected_buffer: [tls.max_common_name]u8 = undefined;
                    const expected = tls.nodeCommonName(
                        &expected_buffer,
                        self.peer.id,
                    );
                    if (!std.mem.eql(u8, tls_stream.peerCommonName(), expected)) {
                        io.sleep(.fromMilliseconds(200), .awake) catch {};
                        continue;
                    }
                    break :blk .{ &tls_stream.reader, &tls_stream.writer };
                }
                net_reader = stream.reader(io, &read_buffer);
                net_writer = stream.writer(io, &write_buffer);
                break :blk .{ &net_reader.interface, &net_writer.interface };
            };

            // Handshake, then repair protocol traffic to this peer.
            var authenticated: ?transport_auth.Session = null;
            {
                self.server.mutex.lockUncancelable(self.server.io);
                const hello = wire.Hello{
                    .version = wire.protocol_version,
                    .kind = .peer,
                    .node_id = self.server.node.identity.node_id,
                    .database_id = self.server.node.identity.database_id,
                    .configuration_id = self.server.node.identity.configuration_id,
                };
                self.server.mutex.unlock(self.server.io);
                var hello_buffer: [wire.Hello.encoded_size]u8 = undefined;
                const encoded = hello.encode(&hello_buffer);
                wire.writeFrame(writer, .hello, encoded) catch continue;
                writer.flush() catch continue;
                if (self.server.options.auth_secret) |secret| {
                    authenticated = transport_auth.connect(
                        self.server.gpa,
                        reader,
                        writer,
                        secret,
                        encoded,
                    ) catch continue;
                }
            }
            if (self.server.peerRevoked(self.peer.id)) continue;

            self.mutex.lockUncancelable(io);
            self.connected = true;
            self.active_stream = stream;
            self.stored_payloads.clearRetainingCapacity();
            for (self.gated.items) |item| self.server.gpa.free(item.frame);
            self.gated.clearRetainingCapacity();
            self.gated_bytes = 0;
            self.mutex.unlock(io);

            std.log.info(
                "node {d}: connected to peer {d}",
                .{ self.server.node.identity.node_id, self.peer.id },
            );

            {
                self.server.mutex.lockUncancelable(self.server.io);
                self.learned_through = 0;
                if (self.server.node.isVoter() and
                    self.peer.role.capabilities().votes)
                {
                    self.server.node.peerReconnected(self.peer.id) catch |err| {
                        std.log.err("reconnect repair failed: {s}", .{@errorName(err)});
                        self.server.failed = true;
                        self.server.failEverything();
                    };
                }
                if (!self.server.failed) self.server.pump();
                self.server.mutex.unlock(self.server.io);
            }

            send_loop: while (!self.server.isShutdown()) {
                self.mutex.lockUncancelable(io);
                while (self.queue.items.len == 0 and self.connected) {
                    if (self.server.isShutdown()) {
                        self.mutex.unlock(io);
                        break :send_loop;
                    }
                    self.cond.waitUncancelable(io, &self.mutex);
                }
                if (!self.connected) {
                    self.mutex.unlock(io);
                    break :send_loop;
                }
                const frame = self.queue.orderedRemove(0);
                self.queue_bytes -= frame.len;
                const flush_now = self.queue.items.len == 0;
                self.cond.broadcast(io);
                self.mutex.unlock(io);

                defer self.server.gpa.free(frame);
                if (authenticated) |*session| {
                    session.writeSerializedFrame(writer, frame) catch
                        break :send_loop;
                } else {
                    self.writePlainFrame(writer, frame) catch break :send_loop;
                }
                if (flush_now) writer.flush() catch break :send_loop;
            }

            self.mutex.lockUncancelable(io);
            self.connected = false;
            self.active_stream = null;
            for (self.queue.items) |frame| self.server.gpa.free(frame);
            self.queue.clearRetainingCapacity();
            self.queue_bytes = 0;
            for (self.gated.items) |item| self.server.gpa.free(item.frame);
            self.gated.clearRetainingCapacity();
            self.gated_bytes = 0;
            self.stored_payloads.clearRetainingCapacity();
            self.cond.broadcast(io);
            self.mutex.unlock(io);
            io.sleep(.fromMilliseconds(100), .awake) catch {};
        }
    }

    fn writePlainFrame(
        self: *PeerSender,
        writer: *Io.Writer,
        frame: []const u8,
    ) !void {
        const fragment = self.server.options.test_faults.fragment_bytes;
        if (fragment == 0) return writer.writeAll(frame);
        var offset: usize = 0;
        while (offset < frame.len) {
            const end = @min(frame.len, offset + @as(usize, fragment));
            try writer.writeAll(frame[offset..end]);
            try writer.flush();
            offset = end;
        }
    }
};

// ----------------------------------------------------------------------
// JSON helpers
// ----------------------------------------------------------------------

fn writeErrorResponse(out: *Io.Writer, code: []const u8, message: []const u8) !void {
    try out.print("{{\"ok\":false,\"error\":\"{s}\",\"message\":", .{code});
    try writeJsonString(out, message);
    try out.writeAll("}");
}

fn writeSqlError(out: *Io.Writer, message: []const u8) !void {
    try out.writeAll("{\"ok\":false,\"error\":\"sql\",\"message\":");
    try writeJsonString(out, message);
    try out.writeAll("}");
}

fn isBackupRequest(gpa: std.mem.Allocator, body: []const u8) bool {
    const Operation = struct { op: []const u8 = "" };
    const parsed = std.json.parseFromSlice(Operation, gpa, body, .{
        .ignore_unknown_fields = true,
    }) catch return false;
    defer parsed.deinit();
    return std.mem.eql(u8, parsed.value.op, "backup");
}

pub fn writeJsonString(out: *Io.Writer, text: []const u8) !void {
    try out.writeAll("\"");
    for (text) |byte| {
        switch (byte) {
            '"' => try out.writeAll("\\\""),
            '\\' => try out.writeAll("\\\\"),
            '\n' => try out.writeAll("\\n"),
            '\r' => try out.writeAll("\\r"),
            '\t' => try out.writeAll("\\t"),
            else => {
                if (byte < 0x20) {
                    try out.print("\\u{x:0>4}", .{byte});
                } else {
                    try out.writeAll(&.{byte});
                }
            },
        }
    }
    try out.writeAll("\"");
}

test "derive database id is order independent" {
    const a = [_]PeerAddress{
        .{ .id = 1, .host = "h", .port = 1 },
        .{ .id = 2, .host = "h", .port = 2 },
        .{ .id = 3, .host = "h", .port = 3 },
    };
    const b = [_]PeerAddress{ a[2], a[0], a[1] };
    try std.testing.expectEqual(
        deriveDatabaseId(&a, null),
        deriveDatabaseId(&b, null),
    );
    try std.testing.expect(deriveDatabaseId(&a, "x") != deriveDatabaseId(&a, null));
}

test "connection admission is sized for a small cluster" {
    const members = [_]PeerAddress{
        .{ .id = 1, .host = "h", .port = 1 },
        .{ .id = 2, .host = "h", .port = 2 },
        .{ .id = 3, .host = "h", .port = 3 },
    };
    var server: Server = undefined;
    server.options = .{
        .directory = ".",
        .node_id = 1,
        .listen_port = 0,
        .members = &members,
    };
    try std.testing.expectEqual(@as(usize, 4 * 3 + 16), server.connectionLimit());
    server.options.max_connections = 5;
    try std.testing.expectEqual(@as(usize, 5), server.connectionLimit());
    server.options.members = &.{};
    server.options.max_connections = 0;
    try std.testing.expectEqual(@as(usize, 16), server.connectionLimit());
}

test "read fence counts each member once" {
    var fence = FenceWaiter{
        .id = 1,
        .ballot = .{ .round = 3, .priority = 1, .node = 1 },
        .fence_slot = 9,
        .needed = 2,
    };
    fence.noteAck(1);
    fence.noteAck(2);
    fence.noteAck(2);
    try std.testing.expectEqual(@as(usize, 2), fence.ack_count);
    try std.testing.expectEqual(@as(paxos.NodeId, 1), fence.acked[0]);
    try std.testing.expectEqual(@as(paxos.NodeId, 2), fence.acked[1]);
}

test "payload gate releases envelopes only after storage ack" {
    var server: Server = undefined;
    server.gpa = std.testing.allocator;
    server.io = std.testing.io;

    var sender = PeerSender{
        .server = &server,
        .peer = .{ .id = 2, .host = "127.0.0.1", .port = 1 },
        .connected = true,
    };
    sender.stored_payloads = std.AutoHashMap(command.HashBytes, void).init(
        std.testing.allocator,
    );
    defer sender.deinit();

    const hash = [_]u8{0xab} ** 32;
    const frame = try std.testing.allocator.dupe(u8, "encoded envelope");
    _ = sender.gatePayload(hash, frame);
    try std.testing.expectEqual(@as(usize, 0), sender.queue.items.len);
    try std.testing.expectEqual(@as(usize, 1), sender.gated.items.len);

    sender.ackPayload(hash);
    try std.testing.expectEqual(@as(usize, 1), sender.queue.items.len);
    try std.testing.expectEqual(@as(usize, 0), sender.gated.items.len);
    sender.ackPayload(hash);
    try std.testing.expectEqual(@as(usize, 1), sender.queue.items.len);
}
