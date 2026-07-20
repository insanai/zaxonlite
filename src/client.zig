//! The zaxon RPC client: one JSON request/response per round trip, with
//! leader-redirect following. Shared by the CLI and the integration test
//! controllers.

const std = @import("std");
const Io = std.Io;
const wire = @import("wire.zig");
const transport_auth = @import("transport_auth.zig");
const tls = @import("tls.zig");
const durability = @import("durability.zig");

/// How a client authenticates its connections: the PSK secret, a mutual
/// TLS identity, both (the PSK handshake then runs inside TLS), or
/// neither for loopback/unix development use.
pub const Transport = struct {
    secret: ?[]const u8 = null,
    tls: ?*const tls.Context = null,
};

pub const Endpoint = struct {
    host: []const u8,
    port: u16 = 0,
    /// When set, `host`/`port` are unused and the connection dials this
    /// Unix-domain socket path instead of TCP.
    unix_path: ?[]const u8 = null,

    /// Parses `host:port` or `unix:<path>`.
    pub fn parse(text: []const u8) !Endpoint {
        if (std.mem.startsWith(u8, text, "unix:")) {
            const path = text["unix:".len..];
            if (path.len == 0) return error.InvalidEndpoint;
            return .{ .host = path, .unix_path = path };
        }
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
    /// Set when the connection runs over mutual TLS; `reader`/`writer`
    /// are then unused and the TLS interfaces carry all frames.
    tls_stream: ?*tls.Stream = null,

    pub fn open(gpa: std.mem.Allocator, io: Io, endpoint: Endpoint) !*Connection {
        return openWithTransport(gpa, io, endpoint, .{});
    }

    pub fn openWithSecret(
        gpa: std.mem.Allocator,
        io: Io,
        endpoint: Endpoint,
        secret: ?[]const u8,
    ) !*Connection {
        return openWithTransport(gpa, io, endpoint, .{ .secret = secret });
    }

    pub fn openWithTransport(
        gpa: std.mem.Allocator,
        io: Io,
        endpoint: Endpoint,
        transport: Transport,
    ) !*Connection {
        const self = try gpa.create(Connection);
        errdefer gpa.destroy(self);
        const read_buffer = try gpa.alloc(u8, 64 * 1024);
        errdefer gpa.free(read_buffer);
        const write_buffer = try gpa.alloc(u8, 64 * 1024);
        errdefer gpa.free(write_buffer);

        var stream = if (endpoint.unix_path) |path| blk: {
            const address = try std.Io.net.UnixAddress.init(path);
            break :blk try address.connect(io);
        } else blk: {
            const address = try std.Io.net.IpAddress.parse(
                endpoint.host,
                endpoint.port,
            );
            break :blk try address.connect(io, .{ .mode = .stream });
        };
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
        if (transport.tls) |context| {
            const tls_stream = try gpa.create(tls.Stream);
            errdefer gpa.destroy(tls_stream);
            tls_stream.* = try tls.Stream.connect(
                context,
                stream,
                read_buffer,
                write_buffer,
            );
            self.tls_stream = tls_stream;
        } else {
            self.reader = self.stream.reader(io, self.read_buffer);
            self.writer = self.stream.writer(io, self.write_buffer);
        }
        errdefer if (self.tls_stream) |tls_stream| {
            tls_stream.deinit();
            gpa.destroy(tls_stream);
        };

        // Client handshake.
        const hello = wire.Hello{
            .version = wire.protocol_version,
            .kind = .client,
            .node_id = 0,
            .database_id = 0,
            .configuration_id = 0,
        };
        var hello_buffer: [wire.Hello.encoded_size]u8 = undefined;
        try wire.writeFrame(self.writerInterface(), .hello, hello.encode(&hello_buffer));
        try self.writerInterface().flush();
        if (transport.secret) |bytes| {
            self.authenticated = try transport_auth.connect(
                gpa,
                self.readerInterface(),
                self.writerInterface(),
                bytes,
                &hello_buffer,
            );
        }
        return self;
    }

    fn readerInterface(self: *Connection) *Io.Reader {
        if (self.tls_stream) |tls_stream| return &tls_stream.reader;
        return &self.reader.interface;
    }

    fn writerInterface(self: *Connection) *Io.Writer {
        if (self.tls_stream) |tls_stream| return &tls_stream.writer;
        return &self.writer.interface;
    }

    pub fn close(self: *Connection) void {
        if (self.tls_stream) |tls_stream| {
            tls_stream.deinit();
            self.gpa.destroy(tls_stream);
        }
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
            try session.writeFrame(self.writerInterface(), .rpc_request, request);
        } else {
            try wire.writeFrame(self.writerInterface(), .rpc_request, request);
        }
        try self.writerInterface().flush();
    }

    fn readFrame(self: *Connection) !transport_auth.Frame {
        if (self.authenticated) |*session| {
            return session.readFrame(self.gpa, self.readerInterface());
        }
        const header = try wire.readFrameHeader(self.readerInterface());
        return .{
            .kind = header.kind,
            .body = try wire.readFrameBody(self.gpa, self.readerInterface(), header),
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
        if (begin.size == 0 or begin.size > wire.max_transfer_bytes) {
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
        try durability.syncFile(self.io, file);
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
    /// The endpoint that answered (after redirects). Always one of the
    /// caller's configured endpoints, borrowing its memory.
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
    return callClusterWithTransport(
        gpa,
        io,
        endpoints,
        request,
        require_leader,
        .{ .secret = secret },
    );
}

pub fn callClusterWithTransport(
    gpa: std.mem.Allocator,
    io: Io,
    endpoints: []const Endpoint,
    request: []const u8,
    require_leader: bool,
    transport: Transport,
) !CallResult {
    var redirect: ?Endpoint = null;
    var attempt: usize = 0;
    const max_attempts = 12;

    while (attempt < max_attempts) : (attempt += 1) {
        const endpoint = redirect orelse
            endpoints[attempt % endpoints.len];
        redirect = null;

        const connection = Connection.openWithTransport(
            gpa,
            io,
            endpoint,
            transport,
        ) catch {
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
        // A leader hint is followed only when it names one of the
        // caller's configured endpoints: a redirect must not send the
        // client outside its known cluster. An unmatched hint falls back
        // to round-robin over the configured list.
        if (object.get("leader")) |leader|
            switch (leader) {
                .object => |leader_object| {
                    const host = leader_object.get("host");
                    const port = leader_object.get("port");
                    if (host != null and port != null and
                        host.? == .string and port.? == .integer and
                        port.?.integer >= 0 and
                        port.?.integer <= std.math.maxInt(u16))
                    {
                        const hinted_port: u16 = @intCast(port.?.integer);
                        for (endpoints) |candidate| {
                            if (candidate.unix_path != null) continue;
                            if (candidate.port == hinted_port and
                                std.mem.eql(u8, candidate.host, host.?.string))
                            {
                                redirect = candidate;
                                break;
                            }
                        }
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

    const unix = try Endpoint.parse("unix:/run/zaxon.sock");
    try std.testing.expectEqualStrings("/run/zaxon.sock", unix.unix_path.?);
    try std.testing.expectError(error.InvalidEndpoint, Endpoint.parse("unix:"));
}
