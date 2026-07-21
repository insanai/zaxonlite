//! Real-TCP adverse schedule: peer frame loss, duplication, reordering,
//! one-byte fragmentation, and delayed durable sync in one three-voter run.

const std = @import("std");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");

pub fn main(init: std.process.Init) !u8 {
    // Logic and process-crash coverage need no power-loss flush latency.
    zaxonlite.durability.setSyncMode(.os);
    const gpa = init.gpa;
    const io = init.io;
    var tmp = try Temp.init(gpa, io);
    defer tmp.deinit();

    var addresses: [3][]u8 = undefined;
    defer for (addresses) |address| gpa.free(address);
    var members: [3]zaxonlite.EmbeddedMember = undefined;
    for (&members, &addresses, 0..) |*member, *address, index| {
        address.* = try std.fmt.allocPrint(gpa, "127.0.0.1:{d}", .{try freePort(io)});
        member.* = .{ .id = @intCast(index + 1), .address = address.* };
    }
    const faults = [_]zaxonlite.server.TestFaults{
        .{ .reorder_pairs = true, .fragment_bytes = 7 },
        .{ .drop_every = 11 },
        .{ .duplicate_every = 7, .storage_delay_ms = 5 },
    };
    var nodes = [_]?*zaxonlite.Embedded{null} ** 3;
    defer {
        var index = nodes.len;
        while (index > 0) {
            index -= 1;
            if (nodes[index]) |node| node.close();
        }
    }
    for (&nodes, faults, 0..) |*node, schedule, index| {
        const directory = try std.fmt.allocPrint(
            gpa,
            "{s}/node-{d}",
            .{ tmp.path, index + 1 },
        );
        defer gpa.free(directory);
        node.* = try zaxonlite.Embedded.open(gpa, io, .{
            .directory = directory,
            .node_id = @intCast(index + 1),
            .members = &members,
            .cluster_id = "fault-cluster",
            .enable_test_faults = true,
            .allow_insecure_test_tcp = true,
            .test_faults = schedule,
        });
    }

    try retryExec(io, nodes[0].?, "create table f(id integer primary key, v text)");
    var sql_buffer: [128]u8 = undefined;
    for (0..30) |index| {
        const sql = std.fmt.bufPrint(
            &sql_buffer,
            "insert into f(v) values ('value-{d}')",
            .{index},
        ) catch unreachable;
        try retryExec(io, nodes[index % nodes.len].?, sql);
    }
    for (members) |member| try expectCount(gpa, io, member.address, 30);
    std.debug.print("fault cluster: loss/duplicate/reorder/fragment/slow-sync passed\n", .{});
    return 0;
}

fn retryExec(io: Io, node: *zaxonlite.Embedded, sql: []const u8) !void {
    var elapsed: u64 = 0;
    while (elapsed < 30_000) : (elapsed += 100) {
        if (node.exec(sql)) |_| return else |_| {}
        io.sleep(.fromMilliseconds(100), .awake) catch {};
    }
    return error.ClusterWriteTimeout;
}

fn expectCount(
    gpa: std.mem.Allocator,
    io: Io,
    address: []const u8,
    expected: usize,
) !void {
    const endpoint = try zaxonlite.client.Endpoint.parse(address);
    var elapsed: u64 = 0;
    while (elapsed < 30_000) : (elapsed += 100) {
        const connection = zaxonlite.client.Connection.open(gpa, io, endpoint) catch
            continue;
        const response = connection.call(
            "{\"op\":\"query\",\"sql\":\"select count(*) from f\"," ++
                "\"level\":\"any\"}",
        ) catch {
            connection.close();
            continue;
        };
        connection.close();
        defer gpa.free(response);
        var expected_text_buffer: [32]u8 = undefined;
        const expected_text = std.fmt.bufPrint(
            &expected_text_buffer,
            "[[\"{d}\"]]",
            .{expected},
        ) catch unreachable;
        if (std.mem.indexOf(u8, response, expected_text) != null) return;
        io.sleep(.fromMilliseconds(100), .awake) catch {};
    }
    return error.ReplicaCatchUpTimeout;
}

fn freePort(io: Io) !u16 {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try address.listen(io, .{ .reuse_address = true });
    const port = listener.socket.address.getPort();
    listener.deinit(io);
    return port;
}

const Temp = struct {
    gpa: std.mem.Allocator,
    io: Io,
    path: []u8,

    fn init(gpa: std.mem.Allocator, io: Io) !Temp {
        var random: [8]u8 = undefined;
        io.random(&random);
        const path = try std.fmt.allocPrint(
            gpa,
            ".zig-cache/tmp/zx-fault-{x}",
            .{std.mem.readInt(u64, &random, .little)},
        );
        try Io.Dir.cwd().createDirPath(io, path);
        return .{ .gpa = gpa, .io = io, .path = path };
    }

    fn deinit(self: *Temp) void {
        Io.Dir.cwd().deleteTree(self.io, self.path) catch {};
        self.gpa.free(self.path);
    }
};
