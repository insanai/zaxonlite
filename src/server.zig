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
//! * `Node.consumeEffects` fsyncs the journal before an envelope reaches
//!   the outbox, so draining the outbox to sender queues keeps
//!   sync-before-send.
//! * A payload is pushed on the same ordered stream before any accept or
//!   commit that references it, and a receiver never steps such an
//!   envelope until the payload is durable in its store — so every vote
//!   counted by a quorum has the payload bytes persisted at the voter.
//! * A client write is acknowledged only after its slot commits and the
//!   decided value at that slot is the client's own batch.

const std = @import("std");
const Io = std.Io;
const paxos = @import("paxos");

const command = @import("command.zig");
const types = @import("types.zig");
const wire = @import("wire.zig");
const node_mod = @import("node.zig");
const payload_store_mod = @import("payload_store.zig");
const failpoint = @import("failpoint.zig");

const Node = node_mod.Node;
const Log = types.Log;

pub const PeerAddress = struct {
    id: paxos.NodeId,
    host: []const u8,
    port: u16,
};

pub const ServeOptions = struct {
    directory: []const u8,
    node_id: paxos.NodeId,
    listen_host: []const u8 = "127.0.0.1",
    listen_port: u16,
    /// Full voting membership, including this node. Empty means a
    /// one-member configuration.
    members: []const PeerAddress = &.{},
    /// Shared database identity; derived from the member list when null.
    database_id: ?u128 = null,
    /// Honor `failpoint` RPCs (test controllers only).
    enable_failpoints: bool = false,
    tick_ms: u64 = 25,
};

/// Milliseconds a client operation may wait before reporting a timeout.
const op_timeout_ms: u64 = 10_000;
const held_hash_limit = 64;
const held_per_hash = 8;
const sender_queue_limit = 4096;
const sender_queue_byte_limit: usize = 128 * 1024 * 1024;
const snapshot_chunk_bytes: usize = 1024 * 1024;

/// Derives a deterministic shared database identity from the member list.
pub fn deriveDatabaseId(members: []const PeerAddress, cluster_id: ?[]const u8) u128 {
    var ids: [types.log_options.max_members]paxos.NodeId = undefined;
    var count: usize = 0;
    for (members) |member| {
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
    var member_ids: [types.log_options.max_members]paxos.NodeId = undefined;
    var member_count: usize = 0;
    for (options.members) |member| {
        member_ids[member_count] = member.id;
        member_count += 1;
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
    }) catch |err| {
        try err_out.print("zaxon: cannot open node: {s}\n", .{@errorName(err)});
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

    const address = std.Io.net.IpAddress.parse(
        options.listen_host,
        options.listen_port,
    ) catch {
        try err_out.print("zaxon: invalid listen address\n", .{});
        try err_out.flush();
        return 2;
    };
    server.listener = address.listen(io, .{ .reuse_address = true }) catch |err| {
        try err_out.print("zaxon: cannot listen: {s}\n", .{@errorName(err)});
        try err_out.flush();
        return 4;
    };

    // One sender per peer.
    for (options.members) |member| {
        if (member.id == options.node_id) continue;
        const sender = try gpa.create(PeerSender);
        sender.* = .{ .server = &server, .peer = member };
        sender.sent_payloads = std.AutoHashMap(command.HashBytes, void).init(gpa);
        try server.senders.append(gpa, sender);
    }
    for (server.senders.items) |sender| {
        sender.thread = try std.Thread.spawn(.{}, PeerSender.run, .{sender});
    }
    const ticker = try std.Thread.spawn(.{}, Server.tickLoop, .{&server});

    // Accept loop. The local copy shares the socket handle; the `stop`
    // RPC closes it, which unblocks `accept`.
    var listener = server.listener.?;
    while (!server.isShutdown()) {
        const stream = listener.accept(io) catch |err| switch (err) {
            error.SocketNotListening, error.Canceled => break,
            error.ConnectionAborted => continue,
            else => break,
        };
        const handler = std.Thread.spawn(
            .{},
            Server.handleConnection,
            .{ &server, stream },
        ) catch {
            var s = stream;
            s.close(io);
            continue;
        };
        handler.detach();
    }

    server.shutdown();
    ticker.join();
    for (server.senders.items) |sender| {
        sender.thread.join();
    }
    return 0;
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
    acks: usize,
    needed: usize,
    failed: bool = false,
    done: bool = false,
    cond: std.Io.Condition = .init,
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
    snapshot_source: ?paxos.NodeId = null,
    snapshot_requested_tick: u64 = 0,
    tick_count: u64 = 0,
    failed: bool = false,
    shutdown_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    fn deinit(self: *Server) void {
        for (self.senders.items) |sender| {
            sender.deinit();
            self.gpa.destroy(sender);
        }
        self.senders.deinit(self.gpa);
        self.fences.deinit(self.gpa);
        self.waiters.deinit(self.gpa);
        self.held.deinit();
        if (self.listener) |*listener| listener.deinit(self.io);
        self.node.close();
    }

    fn isShutdown(self: *Server) bool {
        return self.shutdown_flag.load(.acquire);
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

    fn shutdown(self: *Server) void {
        self.shutdown_flag.store(true, .release);
        for (self.senders.items) |sender| {
            sender.mutex.lockUncancelable(self.io);
            sender.cond.signal(self.io);
            sender.mutex.unlock(self.io);
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
                (fence.acks >= fence.needed and
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

    /// Moves every outbox envelope into its peer's sender queue, pushing
    /// referenced payload bytes ahead of the envelope on the same stream.
    fn drainOutbox(self: *Server) !void {
        const configuration_id = self.node.identity.configuration_id;
        for (self.node.outbox.items) |envelope| {
            const sender = self.senderFor(envelope.to) orelse continue;
            if (wire.envelopePayloadHash(envelope)) |hash| {
                if (!sender.wasPayloadSent(hash)) {
                    if (self.node.store.load(self.gpa, hash)) |payload| {
                        defer self.gpa.free(payload);
                        const frame = try wire.frameAlloc(
                            self.gpa,
                            .payload_data,
                            &.{ &hash, payload },
                        );
                        sender.enqueue(frame);
                        sender.markPayloadSent(hash);
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
            sender.enqueue(frame);
        }
        self.node.outbox.clearRetainingCapacity();
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
            self.node.tickProtocol() catch |err| {
                std.log.err("tick failure: {s}", .{@errorName(err)});
                self.failed = true;
                self.failEverything();
                continue;
            };
            self.pump();
            self.wakeWaiters();

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

    // ------------------------------------------------------------------
    // Connection handling
    // ------------------------------------------------------------------

    fn handleConnection(self: *Server, stream_const: std.Io.net.Stream) void {
        var stream = stream_const;
        defer stream.close(self.io);
        var read_buffer: [64 * 1024]u8 = undefined;
        var stream_reader = stream.reader(self.io, &read_buffer);
        const reader = &stream_reader.interface;
        var write_buffer: [64 * 1024]u8 = undefined;
        var stream_writer = stream.writer(self.io, &write_buffer);
        const writer = &stream_writer.interface;

        const header = wire.readFrameHeader(reader) catch return;
        if (header.kind != .hello) return;
        const hello_body = wire.readFrameBody(self.gpa, reader, header) catch return;
        const hello = wire.Hello.decode(hello_body) catch {
            self.gpa.free(hello_body);
            return;
        };
        self.gpa.free(hello_body);

        switch (hello.kind) {
            .peer => self.peerLoop(reader, hello) catch {},
            .client => self.clientLoop(reader, writer) catch {},
        }
    }

    // ------------------------------------------------------------------
    // Peer connections (inbound: we receive what the peer sends)
    // ------------------------------------------------------------------

    const InstallState = struct {
        dir: ?Io.Dir = null,
        file: ?Io.File = null,
        configuration_id: u64 = 0,
        name: [16]u8 = undefined,
        manifest: ?[]u8 = null,

        fn reset(self: *InstallState, io: Io, gpa: std.mem.Allocator) void {
            if (self.file) |file| file.close(io);
            if (self.dir) |*dir| dir.close(io);
            if (self.manifest) |manifest| gpa.free(manifest);
            self.* = .{};
        }
    };

    fn peerLoop(self: *Server, reader: *Io.Reader, hello: wire.Hello) !void {
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
            const header = try wire.readFrameHeader(reader);
            const body = try wire.readFrameBody(self.gpa, reader, header);
            defer self.gpa.free(body);
            switch (header.kind) {
                .envelope => try self.onEnvelopeFrame(body, hello.node_id),
                .payload_data => try self.onPayloadData(body),
                .payload_request => self.onPayloadRequest(body, hello.node_id),
                .fence_request => self.onFenceRequest(body, hello.node_id),
                .fence_ack => self.onFenceAck(body),
                .snapshot_request => self.onSnapshotRequest(hello.node_id),
                .snapshot_begin => try self.onSnapshotBegin(body, &install),
                .snapshot_chunk => try self.onSnapshotChunk(body, &install),
                .snapshot_end => try self.onSnapshotEnd(&install, hello.node_id),
                else => return error.InvalidFrame,
            }
        }
    }

    fn onEnvelopeFrame(self: *Server, body: []const u8, from: paxos.NodeId) !void {
        if (body.len < 8) return error.InvalidFrame;
        const frame_configuration = std.mem.readInt(u64, body[0..8], .little);
        const envelope = try wire.decodeEnvelope(body[8..]);

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
            if (!self.node.store.contains(hash)) {
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
        };
        self.pump();
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

    fn onPayloadData(self: *Server, body: []const u8) !void {
        if (body.len < 32) return error.InvalidFrame;
        const payload = body[32..];
        const digest = payload_store_mod.PayloadStore.hashOf(payload);
        if (!std.mem.eql(u8, body[0..32], &digest)) return error.InvalidFrame;

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failed) return;
        _ = self.node.store.put(payload) catch |err| {
            std.log.warn("payload store failure: {s}", .{@errorName(err)});
            return;
        };
        if (self.held.fetchRemove(digest)) |entry| {
            self.held_total -= 1;
            for (entry.value.envelopes[0..entry.value.count]) |envelope| {
                self.node.stepEnvelope(envelope) catch |err| {
                    std.log.warn("step failure: {s}", .{@errorName(err)});
                };
            }
            self.pump();
        }
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

    fn onFenceAck(self: *Server, body: []const u8) void {
        const ack = wire.FenceAck.decode(body) catch return;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        for (self.fences.items) |fence| {
            if (fence.id != ack.fence_id) continue;
            if (ack.ok and ack.promised.eql(fence.ballot)) {
                fence.acks += 1;
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
        };
        var begin_buffer: [wire.SnapshotBegin.max_encoded_size]u8 = undefined;
        const begin_encoded = begin.encode(&begin_buffer);
        const begin_frame = wire.frameAlloc(self.gpa, .snapshot_begin, &.{begin_encoded}) catch
            return;
        sender.enqueue(begin_frame);

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
            sender.enqueue(frame);
            offset += read;
        }
        const end_frame = wire.frameAlloc(self.gpa, .snapshot_end, &.{}) catch return;
        sender.enqueue(end_frame);
    }

    fn onSnapshotBegin(self: *Server, body: []const u8, install: *InstallState) !void {
        const begin = try wire.SnapshotBegin.decode(body);
        install.reset(self.io, self.gpa);

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (begin.configuration_id <= self.node.identity.configuration_id) return;
        var dir = try self.node.beginSnapshotInstall();
        errdefer dir.close(self.io);
        const file = try dir.createFile(self.io, "db", .{ .read = true });
        install.dir = dir;
        install.file = file;
        install.configuration_id = begin.configuration_id;
        install.name = begin.name;
        install.manifest = try self.gpa.dupe(u8, begin.manifest);
    }

    fn onSnapshotChunk(self: *Server, body: []const u8, install: *InstallState) !void {
        const chunk = try wire.SnapshotChunk.decode(body);
        const file = install.file orelse return;
        try file.writePositionalAll(self.io, chunk.bytes, chunk.offset);
    }

    fn onSnapshotEnd(self: *Server, install: *InstallState, from: paxos.NodeId) !void {
        const file = install.file orelse return;
        try file.sync(self.io);
        file.close(self.io);
        install.file = null;
        if (install.dir) |*dir| dir.close(self.io);
        install.dir = null;
        const manifest = install.manifest orelse return;
        defer {
            self.gpa.free(manifest);
            install.manifest = null;
        }

        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.snapshot_source = null;
        self.node.installSnapshot(
            install.configuration_id,
            install.name,
            manifest,
        ) catch |err| {
            std.log.warn("snapshot install failed: {s}", .{@errorName(err)});
            return;
        };
        self.observed_leader_decided = 0;
        self.node.requestCatchUp(from) catch {};
        self.pump();
    }

    // ------------------------------------------------------------------
    // Client connections
    // ------------------------------------------------------------------

    fn clientLoop(self: *Server, reader: *Io.Reader, writer: *Io.Writer) !void {
        while (!self.isShutdown()) {
            const header = try wire.readFrameHeader(reader);
            if (header.kind != .rpc_request) return error.InvalidFrame;
            const body = try wire.readFrameBody(self.gpa, reader, header);
            defer self.gpa.free(body);

            var response: std.Io.Writer.Allocating = .init(self.gpa);
            defer response.deinit();
            self.dispatch(body, &response.writer) catch |err| {
                response.clearRetainingCapacity();
                writeErrorResponse(&response.writer, "internal", @errorName(err)) catch {};
            };
            try wire.writeFrame(writer, .rpc_response, response.written());
            try writer.flush();
        }
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
        retain: ?u64 = null,
        name: ?[]const u8 = null,
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
        } else if (std.mem.eql(u8, request.op, "failpoint")) {
            return self.opFailpoint(request, out);
        } else if (std.mem.eql(u8, request.op, "stop")) {
            self.shutdown_flag.store(true, .release);
            if (self.listener) |*listener| {
                listener.socket.close(self.io);
                self.listener = null;
            }
            return out.writeAll("{\"ok\":true}");
        }
        return writeErrorResponse(out, "bad_request", "unknown op");
    }

    fn opStatus(self: *Server, out: *Io.Writer) !void {
        self.mutex.lockUncancelable(self.io);
        const status = self.node.status();
        self.mutex.unlock(self.io);
        const chain_hex = std.fmt.bytesToHex(status.chain, .lower);
        try out.print(
            "{{\"ok\":true,\"node_id\":{d},\"database_id\":\"{x:0>32}\"," ++
                "\"configuration_id\":{d},\"role\":\"{s}\",\"leader\":{?d}," ++
                "\"ballot\":{{\"round\":{d},\"priority\":{d},\"node\":{d}}}," ++
                "\"decided_slot\":{d},\"applied_slot\":{d}," ++
                "\"journal_records\":{d},\"epoch_capacity\":{d}," ++
                "\"chain\":\"{s}\",\"page_size\":{d},\"snapshot\":",
            .{
                status.node_id,          status.database_id,
                status.configuration_id, status.role,
                status.leader,           status.ballot.round,
                status.ballot.priority,  status.ballot.node,
                status.decided_slot,     status.applied_slot,
                status.journal_records,  status.epoch_capacity,
                &chain_hex,              status.page_size,
            },
        );
        if (status.snapshot) |name| {
            try out.print("\"{s}\"}}", .{&name});
        } else {
            try out.writeAll("null}");
        }
    }

    fn opLeader(self: *Server, out: *Io.Writer) !void {
        self.mutex.lockUncancelable(self.io);
        const leader = self.node.currentLeader();
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
        const leader = self.node.currentLeader();
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

        const result: ExecOutcome = try run(self.node, context);
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
        const sql = self.node.bootstrapSql(self.gpa) catch {
            self.mutex.unlock(self.io);
            try writeErrorResponse(out, "unavailable", "bootstrap failed");
            return null;
        };
        self.mutex.unlock(self.io);
        defer self.gpa.free(sql);

        _ = self.runWrite(struct {
            fn run(node: *Node, context: [:0]const u8) !ExecOutcome {
                if (try node.schemaReady()) {
                    return .{ .changes = 0, .slot = 0, .replayed = true };
                }
                return node.exec(context);
            }
        }.run, @as([:0]const u8, sql)) catch |err| {
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
            else => try writeErrorResponse(out, "internal", @errorName(err)),
        }
    }

    fn opQuery(self: *Server, request: Request, out: *Io.Writer) !void {
        const sql = request.sql orelse
            return writeErrorResponse(out, "bad_request", "query needs sql");
        const Level = enum { any, leader, linearizable };
        const level: Level = blk: {
            const text = request.level orelse break :blk .leader;
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

        if (level == .linearizable and !self.node.single) {
            var fence = FenceWaiter{
                .id = self.next_fence_id,
                .ballot = self.node.log.core.ballot,
                .fence_slot = self.node.log.decidedThrough(),
                .acks = 1,
                .needed = self.node.log.core.membership.readQuorum(),
            };
            self.next_fence_id += 1;
            try self.fences.append(self.gpa, &fence);

            var request_buffer: [wire.FenceRequest.encoded_size]u8 = undefined;
            const encoded = (wire.FenceRequest{
                .ballot = fence.ballot,
                .fence_id = fence.id,
            }).encode(&request_buffer);
            for (self.senders.items) |sender| {
                const frame = wire.frameAlloc(self.gpa, .fence_request, &.{encoded}) catch
                    continue;
                sender.enqueue(frame);
            }
            self.pump();

            const start_tick = self.tick_count;
            while (!fence.done) {
                if (self.elapsedMs(start_tick) > op_timeout_ms) {
                    for (self.fences.items, 0..) |candidate, index| {
                        if (candidate == &fence) {
                            _ = self.fences.swapRemove(index);
                            break;
                        }
                    }
                    return writeErrorResponse(out, "timeout", "fence timed out");
                }
                fence.cond.waitUncancelable(self.io, &self.mutex);
            }
            if (fence.failed) {
                return writeErrorResponse(
                    out,
                    "retry",
                    "leadership changed during fence",
                );
            }
        }

        var result = self.node.query(self.gpa, sql) catch |err| {
            const message = switch (err) {
                error.WriteInReadQuery => "statement is not read-only; use exec",
                error.NoDatabaseImage => "no database image on this member yet",
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
    connected: bool = false,
    sent_payloads: std.AutoHashMap(command.HashBytes, void) = undefined,

    fn deinit(self: *PeerSender) void {
        for (self.queue.items) |frame| self.server.gpa.free(frame);
        self.queue.deinit(self.server.gpa);
        self.sent_payloads.deinit();
    }

    /// Takes ownership of `frame`. Drops when disconnected or over bounds;
    /// protocol retransmission recovers dropped frames.
    fn enqueue(self: *PeerSender, frame: []u8) void {
        const io = self.server.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (!self.connected or
            self.queue.items.len >= sender_queue_limit or
            self.queue_bytes + frame.len > sender_queue_byte_limit)
        {
            self.server.gpa.free(frame);
            return;
        }
        self.queue.append(self.server.gpa, frame) catch {
            self.server.gpa.free(frame);
            return;
        };
        self.queue_bytes += frame.len;
        self.cond.signal(io);
    }

    fn wasPayloadSent(self: *PeerSender, hash: command.HashBytes) bool {
        const io = self.server.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        return self.sent_payloads.contains(hash);
    }

    fn markPayloadSent(self: *PeerSender, hash: command.HashBytes) void {
        const io = self.server.io;
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.sent_payloads.put(hash, {}) catch {};
    }

    fn run(self: *PeerSender) void {
        const io = self.server.io;
        while (!self.server.isShutdown()) {
            const address = std.Io.net.IpAddress.parse(
                self.peer.host,
                self.peer.port,
            ) catch return;
            var stream = address.connect(io, .{ .mode = .stream }) catch {
                io.sleep(.fromMilliseconds(200), .awake) catch {};
                continue;
            };
            defer stream.close(io);
            var write_buffer: [64 * 1024]u8 = undefined;
            var stream_writer = stream.writer(io, &write_buffer);
            const writer = &stream_writer.interface;

            // Handshake, then repair protocol traffic to this peer.
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
            }

            self.mutex.lockUncancelable(io);
            self.connected = true;
            self.sent_payloads.clearRetainingCapacity();
            self.mutex.unlock(io);

            {
                self.server.mutex.lockUncancelable(self.server.io);
                self.server.node.peerReconnected(self.peer.id) catch {};
                self.server.pump();
                self.server.mutex.unlock(self.server.io);
            }

            send_loop: while (!self.server.isShutdown()) {
                self.mutex.lockUncancelable(io);
                while (self.queue.items.len == 0) {
                    if (self.server.isShutdown()) {
                        self.mutex.unlock(io);
                        break :send_loop;
                    }
                    self.cond.waitUncancelable(io, &self.mutex);
                }
                const frame = self.queue.orderedRemove(0);
                self.queue_bytes -= frame.len;
                const flush_now = self.queue.items.len == 0;
                self.mutex.unlock(io);

                defer self.server.gpa.free(frame);
                writer.writeAll(frame) catch break :send_loop;
                if (flush_now) writer.flush() catch break :send_loop;
            }

            self.mutex.lockUncancelable(io);
            self.connected = false;
            for (self.queue.items) |frame| self.server.gpa.free(frame);
            self.queue.clearRetainingCapacity();
            self.queue_bytes = 0;
            self.mutex.unlock(io);
            io.sleep(.fromMilliseconds(100), .awake) catch {};
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
