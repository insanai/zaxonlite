//! Deterministic host waits: no ticker exists in this fixture.
const std = @import("std");
const Io = std.Io;
const Node = @import("node.zig").Node;
const deadlines = @import("net_deadline.zig");
const waits = @import("server_waiters.zig");

pub fn check(comptime Server: type, comptime api: anytype) !void {
    const Harness = struct {
        server: *Server,
        mode: enum { writer, frontier, applied, pending, fence },
        result: ?anyerror = null,
        done: Io.Event = .unset,

        fn never(_: *Node, _: void) !@import("node.zig").ExecResult {
            return error.ExecutedAfterCancellation;
        }

        fn unsettled(_: *const Node) bool {
            return false;
        }

        fn run(self: *@This()) void {
            defer self.done.set(self.server.io);
            self.perform() catch |err| {
                self.result = err;
            };
        }

        fn perform(self: *@This()) !void {
            const server = self.server;
            switch (self.mode) {
                .writer => _ = try api.write(server, never, {}),
                .frontier => {
                    server.mutex.lockUncancelable(server.io);
                    defer server.mutex.unlock(server.io);
                    try api.frontier(server, unsettled, 0);
                },
                .pending => try awaitPending(server),
                .fence => try awaitFence(server),
                .applied => {
                    var out: Io.Writer.Allocating = .init(std.testing.allocator);
                    defer out.deinit();
                    try api.wait(server, .{ .op = "wait", .applied = 999 }, &out.writer);
                    const unavailable = std.mem.indexOf(u8, out.written(), "unavailable");
                    try std.testing.expect(unavailable != null);
                },
            }
        }

        fn parked(self: *@This()) bool {
            const s = self.server;
            return switch (self.mode) {
                .writer => s.writer_queue_head != null,
                .frontier => s.frontier_waiters != 0,
                .applied => s.waiters.items.len != 0,
                .pending => s.write_waiter != null,
                .fence => s.fences.items.len != 0,
            };
        }
    };
    for ([_]bool{ false, true }) |failure| {
        for (std.enums.values(@FieldType(Harness, "mode"))) |mode| {
            try checkOne(Server, api, Harness, mode, failure);
        }
    }
}

fn checkOne(
    comptime Server: type,
    comptime api: anytype,
    comptime Harness: type,
    mode: @FieldType(Harness, "mode"),
    failure: bool,
) !void {
    const io = std.testing.io;
    var node: Node = undefined;
    var log: @typeInfo(@TypeOf(node.log)).pointer.child = undefined;
    node.log = &log;
    log.core.role = .leader;
    node.applied_slot = 0;
    var server = Server{
        .gpa = std.testing.allocator,
        .io = io,
        .node = &node,
        .options = .{ .directory = "", .node_id = 1 },
        .membership = undefined,
        .transport_configuration_id = 1,
        .held = undefined,
        .writer_gate_busy = true,
    };
    defer server.waiters.deinit(std.testing.allocator);
    defer server.fences.deinit(std.testing.allocator);
    var worker = Harness{ .server = &server, .mode = mode };
    const thread = try std.Thread.spawn(.{}, Harness.run, .{&worker});
    // Checking registration with the owning mutex proves the waiter has
    // released that mutex in its condition wait; no scheduling guess is needed.
    const end = deadlines.after(io, 2000);
    while (true) {
        server.mutex.lockUncancelable(io);
        if (worker.parked()) break;
        server.mutex.unlock(io);
        if (deadlines.expired(io, end)) std.c._exit(1);
        io.sleep(.fromMilliseconds(1), .awake) catch {};
    }
    if (failure) {
        server.failed = true;
        api.fail(&server);
    } else {
        server.shutdown_flag.store(true, .release);
        api.wake(&server);
        // Exercise a granted ticket waking concurrently with shutdown.
        if (mode == .writer) api.release(&server);
    }
    server.mutex.unlock(io);
    while (!worker.done.isSet()) {
        if (deadlines.expired(io, end)) std.c._exit(1);
        worker.done.waitTimeout(io, .{ .deadline = end }) catch {};
    }
    thread.join();
    if (mode == .applied) {
        try std.testing.expectEqual(@as(?anyerror, null), worker.result);
    } else {
        const expected = if (mode == .pending) error.Ambiguous else error.Unavailable;
        try std.testing.expectEqual(@as(?anyerror, expected), worker.result);
    }
    try std.testing.expect(server.write_waiter == null);
    try std.testing.expectEqual(@as(usize, 0), server.fences.items.len);
    try std.testing.expect(server.writer_queue_head == null);
    try std.testing.expect(server.writer_queue_tail == null);
    try std.testing.expectEqual(@as(u32, 0), server.frontier_waiters);
    try std.testing.expectEqual(@as(usize, 0), server.waiters.items.len);
    try std.testing.expectEqual(@as(u64, 0), server.tick_count);
}

fn awaitPending(server: anytype) !void {
    server.mutex.lockUncancelable(server.io);
    defer server.mutex.unlock(server.io);
    var waiter = waits.WriteWaiter{ .slot = 1, .batch_id = 1 };
    server.write_waiter = &waiter;
    defer server.write_waiter = null;
    try waiter.awaitOutcome(server, 0, 10_000);
}

fn awaitFence(server: anytype) !void {
    server.mutex.lockUncancelable(server.io);
    defer server.mutex.unlock(server.io);
    var fence = waits.FenceWaiter{
        .id = 1,
        .ballot = .{ .round = 1, .priority = 1, .node = 1 },
        .fence_slot = 1,
        .needed = 2,
    };
    try server.fences.append(server.gpa, &fence);
    defer server.fences.clearRetainingCapacity();
    try fence.awaitQuorum(server, 0, 10_000);
}
