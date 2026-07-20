//! Multi-process-equivalent embedded test for voter, witness, standby, and
//! read-replica behavior. Each facade owns a real TCP server and data dir.

const std = @import("std");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");

const secret = "role-cluster-test-secret-32-bytes";
const member_count = 6;

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    var tmp = try Temp.init(gpa, io);
    defer tmp.deinit();

    var addresses: [member_count][]u8 = undefined;
    defer for (addresses) |address| gpa.free(address);
    var members: [member_count]zaxonlite.EmbeddedMember = undefined;
    const roles = [_]zaxonlite.Role{
        .data_voter,
        .data_voter,
        .data_voter,
        .witness,
        .standby,
        .read_replica,
    };
    for (&members, &addresses, roles, 0..) |*member, *address, role, index| {
        address.* = try std.fmt.allocPrint(gpa, "127.0.0.1:{d}", .{try freePort(io)});
        member.* = .{
            .id = @intCast(index + 1),
            .address = address.*,
            .role = role,
        };
    }

    var nodes = [_]?*zaxonlite.Embedded{null} ** member_count;
    defer {
        var index = nodes.len;
        while (index > 0) {
            index -= 1;
            if (nodes[index]) |node| node.close();
        }
    }
    for (&nodes, 0..) |*node, index| {
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
            .cluster_id = "role-cluster",
            .auth_secret = secret,
        });
    }

    try retryExec(io, nodes[0].?, "create table role_test(value text)");
    try retryExec(io, nodes[1].?, "insert into role_test values ('chosen')");
    try expectReplica(io, gpa, members[4].address, "standby");
    try expectReplica(io, gpa, members[5].address, "read-replica");
    try expectCannotRead(gpa, io, members[3].address);
    for (nodes[0..3]) |*node| {
        if (node.*) |value| {
            value.close();
            node.* = null;
        }
    }
    io.sleep(.fromMilliseconds(750), .awake) catch {};
    try expectStale(gpa, io, members[5].address);
    std.debug.print("role cluster: voters, witness, and learners passed\n", .{});
    return 0;
}

fn retryExec(io: Io, node: *zaxonlite.Embedded, sql: []const u8) !void {
    var elapsed: u64 = 0;
    while (elapsed < 20_000) : (elapsed += 100) {
        if (node.exec(sql)) |_| return else |_| {}
        io.sleep(.fromMilliseconds(100), .awake) catch {};
    }
    return error.ClusterWriteTimeout;
}

fn expectReplica(
    io: Io,
    gpa: std.mem.Allocator,
    address: []const u8,
    expected_type: []const u8,
) !void {
    const endpoint = try zaxonlite.client.Endpoint.parse(address);
    var elapsed: u64 = 0;
    while (elapsed < 20_000) : (elapsed += 100) {
        const connection = zaxonlite.client.Connection.openWithSecret(
            gpa,
            io,
            endpoint,
            secret,
        ) catch {
            io.sleep(.fromMilliseconds(100), .awake) catch {};
            continue;
        };
        defer connection.close();
        const status = connection.call("{\"op\":\"status\"}") catch continue;
        defer gpa.free(status);
        if (std.mem.indexOf(u8, status, expected_type) == null) {
            return error.WrongNodeType;
        }
        if (std.mem.indexOf(u8, status, "\"leader\":null") != null) {
            io.sleep(.fromMilliseconds(100), .awake) catch {};
            continue;
        }
        const response = connection.call(
            "{\"op\":\"query\",\"sql\":\"select value from role_test\"," ++
                "\"level\":\"any\",\"freshness_ms\":2000}",
        ) catch continue;
        defer gpa.free(response);
        if (std.mem.indexOf(u8, response, "chosen") != null) return;
        io.sleep(.fromMilliseconds(100), .awake) catch {};
    }
    return error.ReplicaCatchUpTimeout;
}

fn expectCannotRead(gpa: std.mem.Allocator, io: Io, address: []const u8) !void {
    const endpoint = try zaxonlite.client.Endpoint.parse(address);
    const connection = try zaxonlite.client.Connection.openWithSecret(
        gpa,
        io,
        endpoint,
        secret,
    );
    defer connection.close();
    const response = try connection.call(
        "{\"op\":\"query\",\"sql\":\"select 1\",\"level\":\"any\"}",
    );
    defer gpa.free(response);
    if (std.mem.indexOf(u8, response, "\"error\":\"forbidden\"") == null) {
        return error.WitnessServedRead;
    }
}

fn expectStale(gpa: std.mem.Allocator, io: Io, address: []const u8) !void {
    const endpoint = try zaxonlite.client.Endpoint.parse(address);
    const connection = try zaxonlite.client.Connection.openWithSecret(
        gpa,
        io,
        endpoint,
        secret,
    );
    defer connection.close();
    const response = try connection.call(
        "{\"op\":\"query\",\"sql\":\"select value from role_test\"," ++
            "\"level\":\"any\",\"freshness_ms\":100}",
    );
    defer gpa.free(response);
    if (std.mem.indexOf(u8, response, "\"error\":\"stale\"") == null) {
        return error.StaleReplicaServedBoundedRead;
    }
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
            ".zig-cache/tmp/zx-role-{x}",
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
