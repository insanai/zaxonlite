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
const tls = @import("tls.zig");
const roles = @import("roles.zig");
const types = @import("types.zig");
const gateway = @import("gateway.zig");

/// Upper bound for one static member registry, voters plus learners.
/// Callers (the C ABI in particular) check declared counts against this
/// before allocating or copying any list.
pub const max_registry_members = 4 * types.log_options.max_members;

/// One static cluster member. Every process must pass the identical member
/// list to `Embedded.open`; membership cannot change while the cluster runs.
pub const Member = struct {
    /// Non-zero, unique across the list, and never reused for a different
    /// logical member (a reused id could vote twice for one identity).
    id: u32,
    /// `host:port` TCP endpoint this member listens on. Borrowed during
    /// `open` and copied; the caller may free it once `open` returns.
    address: []const u8,
    role: roles.Role = .data_voter,
};

/// Options for `Embedded.open`. All slices are copied into the facade's own
/// arena, so the caller keeps ownership and may free them after `open`.
pub const OpenOptions = struct {
    /// Node data directory (journal, payloads, snapshots, SQLite image);
    /// created when missing. One directory belongs to exactly one node.
    directory: []const u8,
    /// This process's member id; must appear in `members`.
    node_id: u32,
    /// Full static membership including this node. Voter count must be
    /// between one and the compiled maximum, and at least one member must
    /// be able to campaign, or `open` fails before starting anything.
    members: []const Member,
    /// Optional salt for the derived database identity, letting two
    /// clusters with identical member lists refuse each other's peers.
    cluster_id: ?[]const u8 = null,
    /// Optional provider-file secret layered inside TLS for an additional
    /// sequenced HMAC. It is not a substitute for `tls` in production.
    auth_secret: ?[]const u8 = null,
    /// Mutual TLS identity for every TCP connection made or accepted by
    /// this member. Production TCP requires all three provider paths.
    tls: ?tls.Config = null,
    /// Optional CA private-key provider for this member to act as the
    /// one-time-token/CSR enrollment issuer. Most members leave it null.
    enrollment_ca_key: ?[]const u8 = null,
    /// How long `open` waits for the spawned server to accept connections
    /// before failing with `error.ServerStartupTimeout`.
    startup_timeout_ms: u64 = 10_000,
    /// Test-only crash and delay injection; never enable in production.
    enable_test_faults: bool = false,
    /// Test harness escape hatch for plaintext/PSK TCP. Production callers
    /// must use the CLI mTLS host or a local Unix-domain socket.
    allow_insecure_test_tcp: bool = false,
    test_faults: server.TestFaults = .{},
};

/// One in-process cluster member: the node (or gateway), its TCP listener,
/// peer senders, and tick loop run on a background thread owned by this
/// facade. Create with `open`, destroy with `close`; the struct is
/// heap-allocated and must not be copied or accessed after `close`.
///
/// Safety comes from the node underneath: every acknowledged write is
/// journaled and fsynced before its reply leaves the process. Liveness is
/// not guaranteed: with no elected leader or no quorum, calls fail or time
/// out rather than weakening durability.
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
    tls_client: ?tls.Context,
    client_mutex: std.Io.Mutex = .init,
    cluster: client.ClusterConnection,
    thread: std.Thread,
    finished: std.atomic.Value(bool) = .init(false),
    exit_code: std.atomic.Value(u8) = .init(255),

    /// Validates the member list, copies all option slices, spawns the server
    /// thread, and blocks until this member answers on its own endpoint or
    /// `options.startup_timeout_ms` elapses (`error.ServerStartupTimeout`);
    /// a server thread that exits during startup is `error.ServerStartupFailed`.
    /// Membership faults (`InvalidMemberCount`, `InvalidNodeId`,
    /// `DuplicateNodeId`, `InvalidVoterCount`, `CampaignerRequired`,
    /// `NotMember`) are reported before any thread or file is touched.
    ///
    /// The returned facade is allocated from `gpa` and owned by the caller;
    /// release it with `close`, never with `gpa.destroy`. `gpa` and `io` must
    /// outlive the facade. Startup replays the local journal, so a node with
    /// existing state is durable-consistent before `open` returns.
    fn validateOpenOptions(gpa: std.mem.Allocator, options: OpenOptions) !void {
        if (options.members.len == 0 or options.members.len > max_registry_members) {
            return error.InvalidMemberCount;
        }
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
    }

    pub fn open(
        gpa: std.mem.Allocator,
        io: Io,
        options: OpenOptions,
    ) !*Embedded {
        try validateOpenOptions(gpa, options);

        const self = try gpa.create(Embedded);
        errdefer gpa.destroy(self);
        self.* = undefined;
        self.gpa = gpa;
        self.io = io;
        self.arena = std.heap.ArenaAllocator.init(gpa);
        errdefer self.arena.deinit();

        try self.initEmbeddedState(options);
        self.client_mutex = .init;
        self.cluster = client.ClusterConnection.init(
            gpa,
            io,
            self.endpoints,
            self.transport(),
        );
        errdefer self.cluster.deinit();
        self.finished = .init(false);
        self.exit_code = .init(255);
        self.thread = try std.Thread.spawn(.{}, runServer, .{self});
        errdefer self.thread.join();
        try self.waitUntilListening(options.startup_timeout_ms);
        return self;
    }

    fn initEmbeddedState(self: *Embedded, options: OpenOptions) !void {
        const allocator = self.arena.allocator();
        const directory = try allocator.dupe(u8, options.directory);
        const parsed_members = try parseOpenMembers(allocator, options.members, options.node_id);
        const own = parsed_members.self_endpoint orelse return error.NotMember;
        const own_role = parsed_members.self_role orelse return error.NotMember;
        const peers = parsed_members.peers;
        const endpoints = parsed_members.endpoints;
        const backends = parsed_members.backends;
        const backend_count = parsed_members.backend_count;
        const secret = if (options.auth_secret) |bytes| try allocator.dupe(u8, bytes) else null;
        const cluster_id = if (options.cluster_id) |text| try allocator.dupe(u8, text) else null;
        const tls_config: ?tls.Config = if (options.tls) |config| .{
            .cert_path = try allocator.dupe(u8, config.cert_path),
            .key_path = try allocator.dupe(u8, config.key_path),
            .ca_path = try allocator.dupe(u8, config.ca_path),
        } else null;
        const enrollment_ca_key = if (options.enrollment_ca_key) |path|
            try allocator.dupe(u8, path)
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
            .tls = tls_config,
            .enrollment_ca_key = enrollment_ca_key,
            .enable_failpoints = options.enable_test_faults or options.allow_insecure_test_tcp,
            .allow_insecure_test_tcp = options.allow_insecure_test_tcp,
            .test_faults = options.test_faults,
        };
        self.gateway_shutdown = .init(false);
        self.gateway_options = .{
            .listen_host = own.host,
            .listen_port = own.port,
            .backends = backends[0..backend_count],
            .shutdown_flag = &self.gateway_shutdown,
        };
        self.gateway_mode = own_role == .gateway;
        self.endpoints = endpoints;
        self.self_endpoint = own;
        self.auth_secret = secret;
        self.tls_client = null;
        if (tls_config) |config| {
            self.tls_client = try tls.Context.initClient(config);
        }
        errdefer if (self.tls_client) |*context| context.deinit();
    }

    const ParsedMembers = struct {
        peers: []server.PeerAddress,
        endpoints: []client.Endpoint,
        backends: []client.Endpoint,
        backend_count: usize,
        self_endpoint: ?client.Endpoint,
        self_role: ?roles.Role,
    };

    fn parseOpenMembers(
        allocator: std.mem.Allocator,
        members: []const Member,
        self_node_id: u32,
    ) !ParsedMembers {
        const peers = try allocator.alloc(server.PeerAddress, members.len);
        const endpoints = try allocator.alloc(client.Endpoint, members.len);
        const backends = try allocator.alloc(client.Endpoint, members.len);
        var backend_count: usize = 0;
        var self_endpoint: ?client.Endpoint = null;
        var self_role: ?roles.Role = null;
        for (members, 0..) |member, index| {
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
            if (member.id == self_node_id) {
                self_endpoint = endpoint;
                self_role = member.role;
            }
        }
        return .{
            .peers = peers,
            .endpoints = endpoints,
            .backends = backends,
            .backend_count = backend_count,
            .self_endpoint = self_endpoint,
            .self_role = self_role,
        };
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
            const connection = client.Connection.openWithTransport(
                self.gpa,
                self.io,
                self.self_endpoint,
                self.transport(),
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

    fn transport(self: *Embedded) client.Transport {
        return .{
            .secret = self.auth_secret,
            .tls = if (self.tls_client) |*context| context else null,
        };
    }

    /// Requests a server stop, joins the background thread, and frees the
    /// facade and everything it copied; `self` is invalid afterwards. There
    /// is nothing to flush here: every acknowledged write was already synced
    /// before its reply, and a request still in flight when `close` runs may
    /// or may not have committed — its caller must treat the outcome as
    /// unknown. Never returns an error; a node that cannot be reached for a
    /// clean stop is joined after its own exit.
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
                self.cluster.deinit();
                if (self.tls_client) |*context| context.deinit();
                self.arena.deinit();
                const gpa = self.gpa;
                gpa.destroy(self);
                return;
            }
            if (client.Connection.openWithTransport(
                self.gpa,
                self.io,
                self.self_endpoint,
                self.transport(),
            )) |connection| {
                if (connection.call("{\"op\":\"stop\"}")) |body| {
                    self.gpa.free(body);
                } else |_| {}
                connection.close();
            } else |_| {}
        }
        self.thread.join();
        self.cluster.deinit();
        if (self.tls_client) |*context| context.deinit();
        self.arena.deinit();
        const gpa = self.gpa;
        gpa.destroy(self);
    }

    /// Sends one raw JSON RPC request to the cluster: the first reachable
    /// member answers, and when `leader` is true, `not_leader` redirects are
    /// followed to the current leader first. Fails when no member is
    /// reachable (a liveness failure; nothing durable is affected).
    ///
    /// Returns the JSON response body allocated from the `gpa` given to
    /// `open`; the caller must free it with that same allocator. The body is
    /// returned as-is — including `{"ok":false,...}` error responses.
    pub fn call(self: *Embedded, request: []const u8, leader: bool) ![]u8 {
        self.client_mutex.lockUncancelable(self.io);
        defer self.client_mutex.unlock(self.io);
        const result = try self.cluster.call(request, leader);
        return result.body;
    }

    /// Executes `sql` as one replicated write on the leader. Returns only
    /// after the transaction's slot is decided and its journal record is
    /// fsynced, per the write-before-send rule; the result is a plain value
    /// that owns no memory. A server-side refusal is
    /// `error.RemoteOperationFailed` and a malformed reply is
    /// `error.InvalidResponse`.
    ///
    /// A transport failure does not mean the write did not commit: this path
    /// has no session identity, so retrying may apply the statement twice.
    /// Use the session RPCs (via `call`) when exactly-once retries matter.
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

    /// Runs `sql` at the `linearizable` read level: the leader fences the
    /// read on a quorum, so the result reflects every write acknowledged
    /// before the call began. No journal append or disk sync happens per
    /// read. Reads at weaker levels are not offered here; issue them through
    /// `call` so the staleness label is explicit.
    ///
    /// Columns and rows are copied into an arena inside the returned
    /// `QueryResult`, allocated from the `gpa` argument (which may differ
    /// from the open-time allocator); the caller owns the result and must
    /// call `deinit` exactly once. Cell values arrive as text or null.
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
