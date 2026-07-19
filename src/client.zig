//! The zaxon RPC client: one JSON request/response per round trip, with
//! leader-redirect following. Shared by the CLI and the integration test
//! controllers.

const std = @import("std");
const Io = std.Io;
const wire = @import("wire.zig");

pub const Endpoint = struct {
    host: []const u8,
    port: u16,

    /// Parses `host:port`.
    pub fn parse(text: []const u8) !Endpoint {
        const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse
            return error.InvalidEndpoint;
        const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch
            return error.InvalidEndpoint;
        if (colon == 0) return error.InvalidEndpoint;
        return .{ .host = text[0..colon], .port = port };
    }
};

/// One connected client conversation with a single server.
pub const Connection = struct {
    gpa: std.mem.Allocator,
    io: Io,
    stream: std.Io.net.Stream,
    reader: std.Io.net.Stream.Reader,
    writer: std.Io.net.Stream.Writer,
    read_buffer: []u8,
    write_buffer: []u8,

    pub fn open(gpa: std.mem.Allocator, io: Io, endpoint: Endpoint) !*Connection {
        const self = try gpa.create(Connection);
        errdefer gpa.destroy(self);
        const read_buffer = try gpa.alloc(u8, 64 * 1024);
        errdefer gpa.free(read_buffer);
        const write_buffer = try gpa.alloc(u8, 64 * 1024);
        errdefer gpa.free(write_buffer);

        const address = try std.Io.net.IpAddress.parse(endpoint.host, endpoint.port);
        var stream = try address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);

        self.* = .{
            .gpa = gpa,
            .io = io,
            .stream = stream,
            .reader = undefined,
            .writer = undefined,
            .read_buffer = read_buffer,
            .write_buffer = write_buffer,
        };
        self.reader = self.stream.reader(io, self.read_buffer);
        self.writer = self.stream.writer(io, self.write_buffer);

        // Client handshake.
        const hello = wire.Hello{
            .version = wire.protocol_version,
            .kind = .client,
            .node_id = 0,
            .database_id = 0,
            .configuration_id = 0,
        };
        var hello_buffer: [wire.Hello.encoded_size]u8 = undefined;
        try wire.writeFrame(&self.writer.interface, .hello, hello.encode(&hello_buffer));
        try self.writer.interface.flush();
        return self;
    }

    pub fn close(self: *Connection) void {
        self.stream.close(self.io);
        self.gpa.free(self.read_buffer);
        self.gpa.free(self.write_buffer);
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    /// Sends one JSON request and returns the owned JSON response body.
    pub fn call(self: *Connection, request: []const u8) ![]u8 {
        try wire.writeFrame(&self.writer.interface, .rpc_request, request);
        try self.writer.interface.flush();
        const header = try wire.readFrameHeader(&self.reader.interface);
        if (header.kind != .rpc_response) return error.InvalidFrame;
        return wire.readFrameBody(self.gpa, &self.reader.interface, header);
    }
};

pub const CallResult = struct {
    /// Owned JSON response body.
    body: []u8,
    /// The endpoint that answered (after redirects).
    endpoint: Endpoint,
};

/// Calls `request` against the first reachable endpoint, following
/// `not_leader` redirects up to `max_hops`. When `require_leader` is
/// false the first reachable endpoint's answer is returned as-is.
pub fn callCluster(
    gpa: std.mem.Allocator,
    io: Io,
    endpoints: []const Endpoint,
    request: []const u8,
    require_leader: bool,
) !CallResult {
    var redirect_host_buffer: [256]u8 = undefined;
    var redirect: ?Endpoint = null;
    var attempt: usize = 0;
    const max_attempts = 12;

    while (attempt < max_attempts) : (attempt += 1) {
        const endpoint = redirect orelse
            endpoints[attempt % endpoints.len];
        redirect = null;

        const connection = Connection.open(gpa, io, endpoint) catch {
            io.sleep(.fromMilliseconds(150), .awake) catch {};
            continue;
        };
        defer connection.close();
        const body = connection.call(request) catch {
            io.sleep(.fromMilliseconds(150), .awake) catch {};
            continue;
        };

        if (!require_leader) return .{ .body = body, .endpoint = endpoint };

        // Follow a leader hint when the answering node declines.
        const parsed = std.json.parseFromSlice(std.json.Value, gpa, body, .{}) catch {
            return .{ .body = body, .endpoint = endpoint };
        };
        defer parsed.deinit();
        const object = switch (parsed.value) {
            .object => |*obj| obj,
            else => return .{ .body = body, .endpoint = endpoint },
        };
        const ok = object.get("ok") orelse
            return .{ .body = body, .endpoint = endpoint };
        if (ok == .bool and ok.bool) return .{ .body = body, .endpoint = endpoint };
        const code = object.get("error") orelse
            return .{ .body = body, .endpoint = endpoint };
        if (code != .string or !std.mem.eql(u8, code.string, "not_leader")) {
            return .{ .body = body, .endpoint = endpoint };
        }
        if (object.get("leader")) |leader|
            switch (leader) {
                .object => |leader_object| {
                    const host = leader_object.get("host");
                    const port = leader_object.get("port");
                    if (host != null and port != null and
                        host.? == .string and port.? == .integer)
                    {
                        const len = @min(host.?.string.len, redirect_host_buffer.len);
                        @memcpy(redirect_host_buffer[0..len], host.?.string[0..len]);
                        redirect = .{
                            .host = redirect_host_buffer[0..len],
                            .port = @intCast(port.?.integer),
                        };
                    }
                },
                else => {},
            };
        gpa.free(body);
        io.sleep(.fromMilliseconds(150), .awake) catch {};
    }
    return error.NoLeaderReachable;
}

test "endpoint parsing" {
    const endpoint = try Endpoint.parse("127.0.0.1:9901");
    try std.testing.expectEqualStrings("127.0.0.1", endpoint.host);
    try std.testing.expectEqual(@as(u16, 9901), endpoint.port);
    try std.testing.expectError(error.InvalidEndpoint, Endpoint.parse("nope"));
    try std.testing.expectError(error.InvalidEndpoint, Endpoint.parse(":123"));
}
