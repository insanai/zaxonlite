//! Transport-owning embedded Zaxonlite facade.
//!
//! Each facade owns one SQLite/Paxos node, its listener, peer senders, tick
//! loop, and client routing. Applications create one facade in each process;
//! the same API works for one through nine voters plus any number of
//! non-voting replicas. Total node count is a runtime registry concern.

const std = @import("std");
const Io = std.Io;
const client = @import("client.zig");
const node_mod = @import("node.zig");
const server = @import("server.zig");
const roles = @import("roles.zig");
const types = @import("types.zig");
const gateway = @import("gateway.zig");

pub const Member = struct {
    id: u32,
    address: []const u8,
    role: roles.Role = .data_voter,
};

pub const OpenOptions = struct {
    directory: []const u8,
    node_id: u32,
    members: []const Member,
    cluster_id: ?[]const u8 = null,
    auth_secret: ?[]const u8 = null,
    startup_timeout_ms: u64 = 10_000,
    enable_test_faults: bool = false,
    test_faults: server.TestFaults = .{},
};

pub const Embedded = struct {
    gpa: std.mem.Allocator,
    io: Io,
    arena: std.heap.ArenaAllocator,
    serve_options: server.ServeOptions,
    gateway_options: gateway.Options,
    gateway_mode: bool,
    gateway_shutdown: std.atomic.Value(bool) = .init(false),
    endpoints: []client.Endpoint,
    self_endpoint: client.Endpoint,
    auth_secret: ?[]const u8,
    thread: std.Thread,
    finished: std.atomic.Value(bool) = .init(false),
    exit_code: std.atomic.Value(u8) = .init(255),

    pub fn open(
        gpa: std.mem.Allocator,
        io: Io,
        options: OpenOptions,
    ) !*Embedded {
        if (options.members.len == 0) return error.InvalidMemberCount;
        var voter_count: usize = 0;
        var campaigner_count: usize = 0;
        var ids = std.AutoHashMap(u32, void).init(gpa);
        defer ids.deinit();
        for (options.members) |member| {
            if (member.id == 0) return error.InvalidNodeId;
            const inserted = try ids.getOrPut(member.id);
            if (inserted.found_existing) return error.DuplicateNodeId;
            if (member.role.capabilities().votes) voter_count += 1;
            if (member.role.capabilities().campaigns) campaigner_count += 1;
        }
        if (voter_count == 0 or voter_count > types.log_options.max_members) {
            return error.InvalidVoterCount;
        }
        if (campaigner_count == 0) return error.CampaignerRequired;
        const self = try gpa.create(Embedded);
        errdefer gpa.destroy(self);
        self.* = undefined;
        self.gpa = gpa;
        self.io = io;
        self.arena = std.heap.ArenaAllocator.init(gpa);
        errdefer self.arena.deinit();
        const allocator = self.arena.allocator();

        const directory = try allocator.dupe(u8, options.directory);
        const peers = try allocator.alloc(server.PeerAddress, options.members.len);
        const endpoints = try allocator.alloc(client.Endpoint, options.members.len);
        const backends = try allocator.alloc(client.Endpoint, options.members.len);
        var backend_count: usize = 0;
        var self_endpoint: ?client.Endpoint = null;
        var self_role: ?roles.Role = null;
        for (options.members, 0..) |member, index| {
            const address = try allocator.dupe(u8, member.address);
            const endpoint = try client.Endpoint.parse(address);
            peers[index] = .{
                .id = member.id,
                .host = endpoint.host,
                .port = endpoint.port,
                .role = member.role,
            };
            endpoints[index] = endpoint;
            const capabilities = member.role.capabilities();
            if (capabilities.serves_reads or capabilities.serves_writes) {
                backends[backend_count] = endpoint;
                backend_count += 1;
            }
            if (member.id == options.node_id) {
                self_endpoint = endpoint;
                self_role = member.role;
            }
        }
        const own = self_endpoint orelse return error.NotMember;
        const own_role = self_role orelse return error.NotMember;
        const secret = if (options.auth_secret) |bytes|
            try allocator.dupe(u8, bytes)
        else
            null;
        const cluster_id = if (options.cluster_id) |text|
            try allocator.dupe(u8, text)
        else
            null;

        self.serve_options = .{
            .directory = directory,
            .node_id = options.node_id,
            .listen_host = own.host,
            .listen_port = own.port,
            .members = peers,
            .database_id = server.deriveDatabaseId(peers, cluster_id),
            .auth_secret = secret,
            .enable_failpoints = options.enable_test_faults,
            .test_faults = options.test_faults,
        };
        self.gateway_shutdown = .init(false);
        self.gateway_options = .{
            .listen_host = own.host,
            .listen_port = own.port,
            .backends = backends[0..backend_count],
            .authenticated = secret != null,
            .shutdown_flag = &self.gateway_shutdown,
        };
        self.gateway_mode = own_role == .gateway;
        self.endpoints = endpoints;
        self.self_endpoint = own;
        self.auth_secret = secret;
        self.finished = .init(false);
        self.exit_code = .init(255);
        self.thread = try std.Thread.spawn(.{}, runServer, .{self});
        errdefer self.thread.join();
        try self.waitUntilListening(options.startup_timeout_ms);
        return self;
    }

    fn waitUntilListening(self: *Embedded, timeout_ms: u64) !void {
        var elapsed_ms: u64 = 0;
        while (elapsed_ms <= timeout_ms) : (elapsed_ms += 25) {
            if (self.finished.load(.acquire)) return error.ServerStartupFailed;
            if (self.gateway_mode) {
                const address = std.Io.net.IpAddress.parse(
                    self.self_endpoint.host,
                    self.self_endpoint.port,
                ) catch return error.InvalidEndpoint;
                var stream = address.connect(self.io, .{ .mode = .stream }) catch {
                    self.io.sleep(.fromMilliseconds(25), .awake) catch {};
                    continue;
                };
                stream.close(self.io);
                return;
            }
            const connection = client.Connection.openWithSecret(
                self.gpa,
                self.io,
                self.self_endpoint,
                self.auth_secret,
            ) catch {
                self.io.sleep(.fromMilliseconds(25), .awake) catch {};
                continue;
            };
            const response = connection.call("{\"op\":\"status\"}") catch {
                connection.close();
                continue;
            };
            self.gpa.free(response);
            connection.close();
            return;
        }
        return error.ServerStartupTimeout;
    }

    fn runServer(self: *Embedded) void {
        var buffer: [1024]u8 = undefined;
        var discarding: Io.Writer.Discarding = .init(&buffer);
        const code = if (self.gateway_mode)
            gateway.serve(
                self.gpa,
                self.io,
                self.gateway_options,
                &discarding.writer,
            ) catch 4
        else
            server.serve(
                self.gpa,
                self.io,
                self.serve_options,
                &discarding.writer,
            ) catch 4;
        self.exit_code.store(code, .release);
        self.finished.store(true, .release);
    }

    pub fn close(self: *Embedded) void {
        if (!self.finished.load(.acquire)) {
            if (self.gateway_mode) {
                self.gateway_shutdown.store(true, .release);
                const address = std.Io.net.IpAddress.parse(
                    self.self_endpoint.host,
                    self.self_endpoint.port,
                ) catch null;
                if (address) |value| {
                    var stream = value.connect(self.io, .{ .mode = .stream }) catch null;
                    if (stream) |*open_stream| open_stream.close(self.io);
                }
                self.thread.join();
                self.arena.deinit();
                const gpa = self.gpa;
                gpa.destroy(self);
                return;
            }
            if (client.Connection.openWithSecret(
                self.gpa,
                self.io,
                self.self_endpoint,
                self.auth_secret,
            )) |connection| {
                if (connection.call("{\"op\":\"stop\"}")) |body| {
                    self.gpa.free(body);
                } else |_| {}
                connection.close();
            } else |_| {}
        }
        self.thread.join();
        self.arena.deinit();
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    pub fn call(self: *Embedded, request: []const u8, leader: bool) ![]u8 {
        const result = try client.callClusterWithSecret(
            self.gpa,
            self.io,
            self.endpoints,
            request,
            leader,
            self.auth_secret,
        );
        return result.body;
    }

    pub fn exec(self: *Embedded, sql: []const u8) !node_mod.ExecResult {
        var request: Io.Writer.Allocating = .init(self.gpa);
        defer request.deinit();
        try request.writer.writeAll("{\"op\":\"exec\",\"sql\":");
        try server.writeJsonString(&request.writer, sql);
        try request.writer.writeAll("}");
        const body = try self.call(request.written(), true);
        defer self.gpa.free(body);
        const parsed = try parseObject(self.gpa, body);
        defer parsed.deinit();
        try requireOk(&parsed.value);
        return .{
            .changes = objectInt(&parsed.value, "changes") orelse 0,
            .slot = @intCast(objectInt(&parsed.value, "slot") orelse 0),
            .replayed = objectBool(&parsed.value, "replayed") orelse false,
        };
    }

    pub fn query(
        self: *Embedded,
        gpa: std.mem.Allocator,
        sql: []const u8,
    ) !node_mod.QueryResult {
        var request: Io.Writer.Allocating = .init(self.gpa);
        defer request.deinit();
        try request.writer.writeAll("{\"op\":\"query\",\"sql\":");
        try server.writeJsonString(&request.writer, sql);
        try request.writer.writeAll(",\"level\":\"linearizable\"}");
        const body = try self.call(request.written(), true);
        defer self.gpa.free(body);
        const parsed = try parseObject(self.gpa, body);
        defer parsed.deinit();
        try requireOk(&parsed.value);
        return copyQueryResult(gpa, &parsed.value);
    }
};

const ParsedObject = std.json.Parsed(std.json.Value);

fn parseObject(gpa: std.mem.Allocator, body: []const u8) !ParsedObject {
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, body, .{});
    if (parsed.value != .object) {
        parsed.deinit();
        return error.InvalidResponse;
    }
    return parsed;
}

fn requireOk(value: *const std.json.Value) !void {
    const ok = value.object.get("ok") orelse return error.InvalidResponse;
    if (ok != .bool or !ok.bool) return error.RemoteOperationFailed;
}

fn objectInt(value: *const std.json.Value, key: []const u8) ?i64 {
    const field = value.object.get(key) orelse return null;
    return if (field == .integer) field.integer else null;
}

fn objectBool(value: *const std.json.Value, key: []const u8) ?bool {
    const field = value.object.get(key) orelse return null;
    return if (field == .bool) field.bool else null;
}

fn copyQueryResult(gpa: std.mem.Allocator, value: *const std.json.Value) !node_mod.QueryResult {
    const source_columns = value.object.get("columns") orelse return error.InvalidResponse;
    const source_rows = value.object.get("rows") orelse return error.InvalidResponse;
    if (source_columns != .array or source_rows != .array) return error.InvalidResponse;
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const allocator = arena.allocator();
    const columns = try allocator.alloc([]const u8, source_columns.array.items.len);
    for (source_columns.array.items, columns) |source, *destination| {
        if (source != .string) return error.InvalidResponse;
        destination.* = try allocator.dupe(u8, source.string);
    }
    const rows = try allocator.alloc([]const ?[]const u8, source_rows.array.items.len);
    for (source_rows.array.items, rows) |source_row, *destination_row| {
        if (source_row != .array) return error.InvalidResponse;
        const row = try allocator.alloc(?[]const u8, source_row.array.items.len);
        for (source_row.array.items, row) |source, *destination| {
            destination.* = switch (source) {
                .null => null,
                .string => |text| try allocator.dupe(u8, text),
                else => return error.InvalidResponse,
            };
        }
        destination_row.* = row;
    }
    return .{ .arena = arena, .columns = columns, .rows = rows };
}
