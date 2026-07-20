//! The zaxon RPC client: one JSON request/response per round trip, with
//! leader-redirect following. Shared by the CLI and the integration test
//! controllers.

const std = @import("std");
const Io = std.Io;
const wire = @import("wire.zig");
const transport_auth = @import("transport_auth.zig");
const durability = @import("durability.zig");

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
    authenticated: ?transport_auth.Session = null,

    pub fn open(gpa: std.mem.Allocator, io: Io, endpoint: Endpoint) !*Connection {
        return openWithSecret(gpa, io, endpoint, null);
    }

    pub fn openWithSecret(
        gpa: std.mem.Allocator,
        io: Io,
        endpoint: Endpoint,
        secret: ?[]const u8,
    ) !*Connection {
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
        if (secret) |bytes| {
            self.authenticated = try transport_auth.connect(
                gpa,
                &self.reader.interface,
                &self.writer.interface,
                bytes,
                &hello_buffer,
            );
        }
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
        try self.writeRequest(request);
        const frame = try self.readFrame();
        if (frame.kind != .rpc_response) {
            self.gpa.free(frame.body);
            return error.InvalidFrame;
        }
        return frame.body;
    }

    fn writeRequest(self: *Connection, request: []const u8) !void {
        if (self.authenticated) |*session| {
            try session.writeFrame(&self.writer.interface, .rpc_request, request);
        } else {
            try wire.writeFrame(&self.writer.interface, .rpc_request, request);
        }
        try self.writer.interface.flush();
    }

    fn readFrame(self: *Connection) !transport_auth.Frame {
        if (self.authenticated) |*session| {
            return session.readFrame(self.gpa, &self.reader.interface);
        }
        const header = try wire.readFrameHeader(&self.reader.interface);
        return .{
            .kind = header.kind,
            .body = try wire.readFrameBody(self.gpa, &self.reader.interface, header),
        };
    }

    /// Streams a server-side consistent backup to an atomically installed
    /// destination and verifies its declared SHA-256 before rename.
    pub fn backupTo(self: *Connection, destination: []const u8) !void {
        const directory_name = std.fs.path.dirname(destination) orelse ".";
        const file_name = std.fs.path.basename(destination);
        if (file_name.len == 0) return error.InvalidBackupPath;
        var directory = if (std.fs.path.isAbsolute(directory_name))
            try Io.Dir.openDirAbsolute(self.io, directory_name, .{})
        else
            try Io.Dir.cwd().openDir(self.io, directory_name, .{});
        defer directory.close(self.io);
        if (directory.access(self.io, file_name, .{})) |_| {
            return error.BackupDestinationExists;
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }

        var random_bytes: [8]u8 = undefined;
        self.io.random(&random_bytes);
        const nonce = std.mem.readInt(u64, &random_bytes, .little);
        const temporary_name = try std.fmt.allocPrint(
            self.gpa,
            ".{s}.zaxon-{x}.tmp",
            .{ file_name, nonce },
        );
        defer self.gpa.free(temporary_name);
        var file = try directory.createFile(self.io, temporary_name, .{
            .read = true,
            .exclusive = true,
        });
        var file_open = true;
        var keep_temporary = true;
        defer {
            if (file_open) file.close(self.io);
            if (keep_temporary) directory.deleteFile(self.io, temporary_name) catch {};
        }

        try self.writeRequest("{\"op\":\"backup\"}");
        const begin_frame = try self.readFrame();
        defer self.gpa.free(begin_frame.body);
        if (begin_frame.kind == .rpc_response) return error.RemoteBackupRejected;
        if (begin_frame.kind != .backup_begin) return error.InvalidFrame;
        const begin = try wire.BackupBegin.decode(begin_frame.body);
        if (begin.size == 0 or begin.size > 1024 * 1024 * 1024 * 1024) {
            return error.InvalidBackupSize;
        }

        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        var received: u64 = 0;
        while (true) {
            const frame = try self.readFrame();
            defer self.gpa.free(frame.body);
            if (frame.kind == .backup_end) break;
            if (frame.kind != .backup_chunk or frame.body.len <= 8) {
                return error.InvalidFrame;
            }
            const offset = std.mem.readInt(u64, frame.body[0..8], .little);
            const bytes = frame.body[8..];
            const end = std.math.add(u64, offset, bytes.len) catch
                return error.InvalidFrame;
            if (offset != received or end > begin.size) return error.InvalidFrame;
            try file.writePositionalAll(self.io, bytes, offset);
            hasher.update(bytes);
            received = end;
        }
        if (received != begin.size) return error.UnexpectedEndOfStream;
        var actual: [32]u8 = undefined;
        hasher.final(&actual);
        if (!std.mem.eql(u8, &actual, &begin.sha256)) return error.BackupDigestMismatch;
        try file.sync(self.io);
        file.close(self.io);
        file_open = false;
        try directory.rename(temporary_name, directory, file_name, self.io);
        try durability.syncDirectory(directory);
        keep_temporary = false;
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
    return callClusterWithSecret(
        gpa,
        io,
        endpoints,
        request,
        require_leader,
        null,
    );
}

pub fn callClusterWithSecret(
    gpa: std.mem.Allocator,
    io: Io,
    endpoints: []const Endpoint,
    request: []const u8,
    require_leader: bool,
    secret: ?[]const u8,
) !CallResult {
    var redirect_host_buffer: [256]u8 = undefined;
    var redirect: ?Endpoint = null;
    var attempt: usize = 0;
    const max_attempts = 12;

    while (attempt < max_attempts) : (attempt += 1) {
        const endpoint = redirect orelse
            endpoints[attempt % endpoints.len];
        redirect = null;

        const connection = Connection.openWithSecret(gpa, io, endpoint, secret) catch {
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
