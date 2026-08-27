//! The beyond-retention state-transfer integration controller (ZDS 0011).
//!
//! Spawns a three-voter mTLS cluster with test-sized journal segments,
//! drives enough decisions to rotate and physically reclaim history below
//! a certified chosen trim, then replaces a voter. The replacement joins
//! with nothing, and the reclaimed prefix forces the anchor-pinned state
//! transfer instead of range catch-up. The join runs a crash ladder: the
//! receiver dies at every transfer failpoint in sequence, the sender dies
//! once while pinning its image, and the final clean start must converge
//! from the durable anchor it already installed.
//!
//! Usage: transfer-cluster-test <path-to-zaxon>

const std = @import("std");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");
const client = zaxonlite.client;
const tls = zaxonlite.tls;

const Endpoint = client.Endpoint;

/// Test-only journal geometry: segments rotate every 256 records, so a
/// few hundred writes produce several sealed segments to reclaim.
const segment_records = "256";
const seed_rows = 600;

const NodeProc = struct {
    id: u32,
    port: u16,
    directory: []const u8,
    log_path: []const u8,
    cert: []const u8,
    key: []const u8,
    child: ?std.process.Child = null,
};

const Cluster = struct {
    gpa: std.mem.Allocator,
    io: Io,
    zaxon: []const u8,
    root: []const u8,
    ca_path: []const u8,
    ca_key_path: []const u8,
    nodes: [4]NodeProc,
    replacement_port: u16,
    admin: tls.Context,

    fn endpointOf(self: *Cluster, index: usize) Endpoint {
        return .{ .host = "127.0.0.1", .port = self.nodes[index].port };
    }

    /// Spawns one node. `peer_ids`/`peer_ports` describe its --peer flags;
    /// `env_failpoint` arms a crash inside the process via /usr/bin/env.
    fn spawnNode(
        self: *Cluster,
        index: usize,
        peer_ids: []const u32,
        peer_ports: []const u16,
        env_failpoint: ?[]const u8,
    ) !void {
        const node = &self.nodes[index];
        std.debug.assert(node.child == null);

        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(self.gpa);
        var scratch: std.ArrayList([]u8) = .empty;
        defer {
            for (scratch.items) |item| self.gpa.free(item);
            scratch.deinit(self.gpa);
        }

        if (env_failpoint) |failpoint| {
            const assignment = try std.fmt.allocPrint(
                self.gpa,
                "ZAXON_FAILPOINT={s}",
                .{failpoint},
            );
            try scratch.append(self.gpa, assignment);
            try argv.appendSlice(self.gpa, &.{ "/usr/bin/env", assignment });
        }
        try argv.appendSlice(self.gpa, &.{ self.zaxon, "serve", "--data", node.directory });
        const node_text = try std.fmt.allocPrint(self.gpa, "{d}", .{node.id});
        try scratch.append(self.gpa, node_text);
        try argv.appendSlice(self.gpa, &.{ "--node", node_text });
        const listen_text = try std.fmt.allocPrint(
            self.gpa,
            "127.0.0.1:{d}",
            .{node.port},
        );
        try scratch.append(self.gpa, listen_text);
        try argv.appendSlice(self.gpa, &.{ "--listen", listen_text });
        for (peer_ids, peer_ports) |peer_id, peer_port| {
            const peer_text = try std.fmt.allocPrint(
                self.gpa,
                "{d}@127.0.0.1:{d}",
                .{ peer_id, peer_port },
            );
            try scratch.append(self.gpa, peer_text);
            try argv.appendSlice(self.gpa, &.{ "--peer", peer_text });
        }
        try argv.appendSlice(self.gpa, &.{
            "--tls-cert", node.cert,
            "--tls-key",  node.key,
            "--tls-ca",   self.ca_path,
        });
        try argv.appendSlice(self.gpa, &.{
            "--enrollment-ca-key", self.ca_key_path,
        });
        try argv.appendSlice(self.gpa, &.{ "--admin", "ops" });
        try argv.appendSlice(self.gpa, &.{ "--sync", "os" });
        try argv.append(self.gpa, "--enable-failpoints");
        try argv.appendSlice(self.gpa, &.{ "--segment-records", segment_records });

        const log_file = try Io.Dir.cwd().createFile(self.io, node.log_path, .{});
        node.child = try std.process.spawn(self.io, .{
            .argv = argv.items,
            .stdin = .ignore,
            .stdout = .{ .file = log_file },
            .stderr = .{ .file = log_file },
        });
        log_file.close(self.io);
    }

    fn killNode(self: *Cluster, index: usize) void {
        const node = &self.nodes[index];
        if (node.child) |*child| {
            child.kill(self.io);
            node.child = null;
            self.io.sleep(.fromMilliseconds(250), .awake) catch {};
        }
    }

    fn waitNodeExit(self: *Cluster, index: usize) void {
        const node = &self.nodes[index];
        if (node.child) |*child| {
            _ = child.wait(self.io) catch {};
            node.child = null;
            self.io.sleep(.fromMilliseconds(250), .awake) catch {};
        }
    }

    fn killAll(self: *Cluster) void {
        for (0..self.nodes.len) |index| self.killNode(index);
    }
};

var progress_step: []const u8 = "init";

fn step(name: []const u8) void {
    progress_step = name;
    std.debug.print("== {s}\n", .{name});
}

fn fail(cluster: *Cluster, comptime format: []const u8, args: anytype) noreturn {
    std.debug.print(
        "FAILED at step '{s}': " ++ format ++ "\n",
        .{progress_step} ++ args,
    );
    for (cluster.nodes) |node| {
        std.debug.print("---- node {d} log tail ----\n", .{node.id});
        const body = Io.Dir.cwd().readFileAlloc(
            cluster.io,
            node.log_path,
            cluster.gpa,
            .limited(1 << 20),
        ) catch continue;
        defer cluster.gpa.free(body);
        const start = if (body.len > 4000) body.len - 4000 else 0;
        std.debug.print("{s}\n", .{body[start..]});
    }
    cluster.killAll();
    std.process.exit(1);
}

fn rpcTry(cluster: *Cluster, endpoint: Endpoint, request: []const u8) ?[]u8 {
    const connection = client.Connection.openWithTransport(
        cluster.gpa,
        cluster.io,
        endpoint,
        .{ .tls = &cluster.admin },
    ) catch return null;
    defer connection.close();
    return connection.call(request) catch null;
}

const Parsed = std.json.Parsed(std.json.Value);

fn parse(cluster: *Cluster, body: []const u8) Parsed {
    return std.json.parseFromSlice(std.json.Value, cluster.gpa, body, .{}) catch
        fail(cluster, "malformed JSON response: {s}", .{body});
}

fn field(parsed: *const Parsed, name: []const u8) ?std.json.Value {
    return switch (parsed.value) {
        .object => |object| object.get(name),
        else => null,
    };
}

fn fieldInt(parsed: *const Parsed, name: []const u8) ?i64 {
    const value = field(parsed, name) orelse return null;
    return switch (value) {
        .integer => |n| n,
        else => null,
    };
}

fn isOk(parsed: *const Parsed) bool {
    const value = field(parsed, "ok") orelse return false;
    return value == .bool and value.bool;
}

/// Sends `request` to any endpoint until an ok response arrives, retrying
/// through elections and the membership handover's write pause.
fn mustCallAny(
    cluster: *Cluster,
    endpoints: []const Endpoint,
    request: []const u8,
    deadline_ms: u64,
) []u8 {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        for (endpoints) |endpoint| {
            const body = rpcTry(cluster, endpoint, request) orelse continue;
            const parsed = parse(cluster, body);
            defer parsed.deinit();
            if (isOk(&parsed)) return body;
            cluster.gpa.free(body);
        }
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "rpc deadline exceeded: {s}", .{request});
}

/// Reads one integer status field from one node, or null while the node
/// is unreachable or not ok.
fn statusInt(cluster: *Cluster, endpoint: Endpoint, name: []const u8) ?i64 {
    const body = rpcTry(cluster, endpoint, "{\"op\":\"status\"}") orelse
        return null;
    defer cluster.gpa.free(body);
    const parsed = parse(cluster, body);
    defer parsed.deinit();
    if (!isOk(&parsed)) return null;
    return fieldInt(&parsed, name);
}

/// Polls one status field until `minimum` is reached.
fn waitStatusAtLeast(
    cluster: *Cluster,
    endpoint: Endpoint,
    name: []const u8,
    minimum: i64,
    deadline_ms: u64,
) i64 {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        if (statusInt(cluster, endpoint, name)) |value| {
            if (value >= minimum) return value;
        }
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "status {s} never reached {d} at port {d}", .{
        name,
        minimum,
        endpoint.port,
    });
}

fn waitForConfiguration(
    cluster: *Cluster,
    endpoint: Endpoint,
    configuration_id: i64,
    deadline_ms: u64,
) void {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        if (statusInt(cluster, endpoint, "configuration_id")) |id| {
            if (id == configuration_id) return;
        }
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "timeout waiting for configuration {d} at port {d}", .{
        configuration_id,
        endpoint.port,
    });
}

fn waitForLeader(cluster: *Cluster, endpoint: Endpoint, deadline_ms: u64) u32 {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        if (statusInt(cluster, endpoint, "leader")) |leader| {
            return @intCast(leader);
        }
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "timeout waiting for a leader at port {d}", .{endpoint.port});
}

/// The linearizable row count of table t as observed through `endpoint`.
fn countRows(cluster: *Cluster, endpoint: Endpoint, deadline_ms: u64) i64 {
    const endpoints = [_]Endpoint{endpoint};
    const body = mustCallAny(
        cluster,
        &endpoints,
        "{\"op\":\"query\",\"sql\":\"select count(*) from t\"," ++
            "\"level\":\"linearizable\"}",
        deadline_ms,
    );
    defer cluster.gpa.free(body);
    const parsed = parse(cluster, body);
    defer parsed.deinit();
    const rows = field(&parsed, "rows") orelse
        fail(cluster, "count reply missing rows: {s}", .{body});
    if (rows != .array or rows.array.items.len != 1) {
        fail(cluster, "unexpected count shape: {s}", .{body});
    }
    const first = rows.array.items[0];
    if (first != .array or first.array.items.len != 1) {
        fail(cluster, "unexpected count row shape: {s}", .{body});
    }
    return switch (first.array.items[0]) {
        .integer => |n| n,
        .string => |text| std.fmt.parseInt(i64, text, 10) catch
            fail(cluster, "unparsable count: {s}", .{body}),
        else => fail(cluster, "unexpected count cell: {s}", .{body}),
    };
}

fn runProgram(io: Io, argv: []const []const u8) !void {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) return error.ProgramFailed;
}

fn generateTlsIdentity(
    gpa: std.mem.Allocator,
    io: Io,
    dir: []const u8,
    name: []const u8,
    signer: ?[]const u8,
    common_name: []const u8,
) !void {
    const key = try std.fmt.allocPrint(gpa, "{s}/{s}.key", .{ dir, name });
    defer gpa.free(key);
    const crt = try std.fmt.allocPrint(gpa, "{s}/{s}.crt", .{ dir, name });
    defer gpa.free(crt);
    const subject = try std.fmt.allocPrint(gpa, "/CN={s}", .{common_name});
    defer gpa.free(subject);
    try runProgram(io, &.{
        "openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout",
        "-out",    key,
    });
    const signing = signer orelse {
        try runProgram(io, &.{
            "openssl", "req", "-x509", "-new", "-key",  key,
            "-out",    crt,   "-days", "2",    "-subj", subject,
        });
        return;
    };
    const csr = try std.fmt.allocPrint(gpa, "{s}/{s}.csr", .{ dir, name });
    defer gpa.free(csr);
    const signer_key = try std.fmt.allocPrint(gpa, "{s}/{s}.key", .{ dir, signing });
    defer gpa.free(signer_key);
    const signer_crt = try std.fmt.allocPrint(gpa, "{s}/{s}.crt", .{ dir, signing });
    defer gpa.free(signer_crt);
    try runProgram(io, &.{
        "openssl", "req", "-new", "-key", key, "-out", csr, "-subj", subject,
    });
    try runProgram(io, &.{
        "openssl", "x509",     "-req",   "-in",      csr,
        "-CA",     signer_crt, "-CAkey", signer_key, "-CAcreateserial",
        "-out",    crt,        "-days",  "2",
    });
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;

    var iterator = std.process.Args.Iterator.init(init.minimal.args);
    defer iterator.deinit();
    _ = iterator.next();
    const zaxon = iterator.next() orelse {
        std.debug.print("usage: transfer-cluster-test <path-to-zaxon>\n", .{});
        return 2;
    };

    var random_bytes: [8]u8 = undefined;
    io.random(&random_bytes);
    const nonce = std.mem.readInt(u64, &random_bytes, .little);
    const base_port: u16 = @intCast(45000 + (nonce % 500) * 8);

    const root = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/zx-transfer-{x}", .{nonce});
    defer gpa.free(root);
    try Io.Dir.cwd().createDirPath(io, root);
    defer Io.Dir.cwd().deleteTree(io, root) catch {};

    step("generate cluster CA, node, and admin certificates");
    try generateTlsIdentity(gpa, io, root, "ca", null, "zaxon-transfer-test-ca");
    inline for (.{ 1, 2, 3 }) |node_id| {
        const name = std.fmt.comptimePrint("node{d}", .{node_id});
        const common = std.fmt.comptimePrint("zaxon-node-{d}", .{node_id});
        try generateTlsIdentity(gpa, io, root, name, "ca", common);
    }
    try generateTlsIdentity(gpa, io, root, "admin", "ca", "zaxon-admin-ops");

    const ca_path = try std.fmt.allocPrint(gpa, "{s}/ca.crt", .{root});
    defer gpa.free(ca_path);
    const ca_key_path = try std.fmt.allocPrint(gpa, "{s}/ca.key", .{root});
    defer gpa.free(ca_key_path);
    const admin_cert = try std.fmt.allocPrint(gpa, "{s}/admin.crt", .{root});
    defer gpa.free(admin_cert);
    const admin_key = try std.fmt.allocPrint(gpa, "{s}/admin.key", .{root});
    defer gpa.free(admin_key);

    var cluster = Cluster{
        .gpa = gpa,
        .io = io,
        .zaxon = zaxon,
        .root = root,
        .ca_path = ca_path,
        .ca_key_path = ca_key_path,
        .nodes = undefined,
        .replacement_port = base_port + 4,
        .admin = try tls.Context.initClient(.{
            .cert_path = admin_cert,
            .key_path = admin_key,
            .ca_path = ca_path,
        }),
    };
    inline for (.{ 0, 1, 2 }) |index| {
        const node_id: u32 = index + 1;
        cluster.nodes[index] = .{
            .id = node_id,
            .port = base_port + index + 1,
            .directory = try std.fmt.allocPrint(gpa, "{s}/n{d}", .{ root, node_id }),
            .log_path = try std.fmt.allocPrint(gpa, "{s}/n{d}.log", .{ root, node_id }),
            .cert = try std.fmt.allocPrint(gpa, "{s}/node{d}.crt", .{ root, node_id }),
            .key = try std.fmt.allocPrint(gpa, "{s}/node{d}.key", .{ root, node_id }),
        };
    }
    cluster.nodes[3] = .{
        .id = 4,
        .port = cluster.replacement_port,
        .directory = try std.fmt.allocPrint(gpa, "{s}/n4", .{root}),
        .log_path = try std.fmt.allocPrint(gpa, "{s}/n4.log", .{root}),
        .cert = try std.fmt.allocPrint(gpa, "{s}/n4-id/node.crt", .{root}),
        .key = try std.fmt.allocPrint(gpa, "{s}/n4-id/node.key", .{root}),
    };
    defer for (cluster.nodes) |node| {
        gpa.free(node.directory);
        gpa.free(node.log_path);
        gpa.free(node.cert);
        gpa.free(node.key);
    };
    defer cluster.killAll();

    try runScenario(&cluster);
    std.debug.print("transfer cluster test: scenario complete\n", .{});
    return 0;
}

fn runScenario(cluster: *Cluster) !void {
    const gpa = cluster.gpa;
    const io = cluster.io;
    const initial_ids = [_]u32{ 1, 2, 3 };
    const initial_ports = [_]u16{
        cluster.nodes[0].port,
        cluster.nodes[1].port,
        cluster.nodes[2].port,
    };

    step("start the three-voter cluster with test-sized segments");
    try cluster.spawnNode(0, &initial_ids, &initial_ports, null);
    try cluster.spawnNode(1, &initial_ids, &initial_ports, null);
    try cluster.spawnNode(2, &initial_ids, &initial_ports, null);
    const endpoints = [_]Endpoint{
        cluster.endpointOf(0),
        cluster.endpointOf(1),
        cluster.endpointOf(2),
    };
    _ = waitForLeader(cluster, endpoints[0], 30_000);

    step("write enough rows to rotate several journal segments");
    gpa.free(mustCallAny(
        cluster,
        &endpoints,
        "{\"op\":\"exec\",\"sql\":\"create table t(id integer primary key, v text)\"}",
        30_000,
    ));
    for (0..seed_rows) |_| {
        gpa.free(mustCallAny(
            cluster,
            &endpoints,
            "{\"op\":\"exec\",\"sql\":\"insert into t(v) values ('seed')\"}",
            30_000,
        ));
    }

    step("anchor every voter and reclaim history below the chosen trim");
    for (0..endpoints.len) |index| {
        gpa.free(mustCallAny(
            cluster,
            endpoints[index .. index + 1],
            "{\"op\":\"anchor\"}",
            30_000,
        ));
    }
    for (endpoints) |endpoint| {
        _ = waitStatusAtLeast(cluster, endpoint, "chosen_trim_slot", 1, 60_000);
        _ = waitStatusAtLeast(cluster, endpoint, "retained_first_slot", 2, 60_000);
    }

    step("replace voter 3; survivors activate the next configuration");
    var replace_buffer: [192]u8 = undefined;
    const replace_request = std.fmt.bufPrint(
        &replace_buffer,
        "{{\"op\":\"replace-voter\",\"operation\":1," ++
            "\"expected_config\":1,\"old_node\":3,\"new_node\":4," ++
            "\"endpoint\":\"127.0.0.1:{d}\"}}",
        .{cluster.replacement_port},
    ) catch unreachable;
    gpa.free(mustCallAny(cluster, &endpoints, replace_request, 60_000));
    waitForConfiguration(cluster, endpoints[0], 2, 60_000);
    waitForConfiguration(cluster, endpoints[1], 2, 60_000);

    step("enroll the replacement voter");
    const token_path = try std.fmt.allocPrint(gpa, "{s}/n4-token", .{cluster.root});
    defer gpa.free(token_path);
    const identity_dir = try std.fmt.allocPrint(gpa, "{s}/n4-id", .{cluster.root});
    defer gpa.free(identity_dir);
    {
        var endpoint_buffer: [32]u8 = undefined;
        const issuer = std.fmt.bufPrint(
            &endpoint_buffer,
            "127.0.0.1:{d}",
            .{cluster.nodes[0].port},
        ) catch unreachable;
        const admin_cert = try std.fmt.allocPrint(gpa, "{s}/admin.crt", .{cluster.root});
        defer gpa.free(admin_cert);
        const admin_key = try std.fmt.allocPrint(gpa, "{s}/admin.key", .{cluster.root});
        defer gpa.free(admin_key);
        runProgram(io, &.{
            cluster.zaxon,   "enroll-token", "--connect",  issuer,
            "--node",        "4",            "--to",       token_path,
            "--ttl-seconds", "300",          "--tls-cert", admin_cert,
            "--tls-key",     admin_key,      "--tls-ca",   cluster.ca_path,
        }) catch fail(cluster, "enroll-token failed", .{});
        runProgram(io, &.{
            cluster.zaxon,    "enroll",     "--token-file", token_path,
            "--identity-dir", identity_dir, "--data",       cluster.nodes[3].directory,
        }) catch fail(cluster, "enroll failed", .{});
    }

    try runJoinLadder(cluster, &endpoints);
}

/// A few writes through the survivors. Real clusters are never idle, and
/// traffic is what lets a freshly spawned joiner discover the leader:
/// its first accepted vote adopts the leader's ballot, and the
/// heartbeats that follow keep it current. Without it an idle cluster
/// leaves a campaign-held joiner with no leader to escalate to.
fn trickle(cluster: *Cluster, endpoints: []const Endpoint) void {
    for (0..3) |_| {
        cluster.gpa.free(mustCallAny(
            cluster,
            endpoints,
            "{\"op\":\"exec\",\"sql\":\"insert into t(v) values ('trickle')\"}",
            60_000,
        ));
    }
}

/// The join crash ladder: every receiver transfer failpoint in sequence,
/// one sender death mid-pin, then a clean convergence from the durable
/// anchor plus a restart. Each rung respawns node 4 and waits for the
/// armed failpoint to kill it; the retry after each crash must be
/// idempotent because the reclaimed prefix leaves no other source.
fn runJoinLadder(cluster: *Cluster, endpoints: []const Endpoint) !void {
    const gpa = cluster.gpa;
    const updated_ids = [_]u32{ 1, 2, 4 };
    const updated_ports = [_]u16{
        cluster.nodes[0].port,
        cluster.nodes[1].port,
        cluster.replacement_port,
    };

    step("receiver dies after staging the transferred image");
    try cluster.spawnNode(3, &updated_ids, &updated_ports, "after_transfer_stage");
    trickle(cluster, endpoints);
    cluster.waitNodeExit(3);

    step("receiver dies after the digest check, before the install rename");
    try cluster.spawnNode(3, &updated_ids, &updated_ports, "before_transfer_install");
    trickle(cluster, endpoints);
    cluster.waitNodeExit(3);

    step("sender dies pinning its image; another voter completes the send");
    const leader = waitForLeader(cluster, endpoints[0], 30_000);
    const leader_index: usize = leader - 1;
    gpa.free(mustCallAny(
        cluster,
        endpoints[leader_index .. leader_index + 1],
        "{\"op\":\"failpoint\",\"name\":\"after_transfer_pin\"}",
        30_000,
    ));
    try cluster.spawnNode(3, &updated_ids, &updated_ports, "after_transfer_install");
    trickle(cluster, endpoints);
    cluster.waitNodeExit(leader_index);
    try cluster.spawnNode(
        leader_index,
        &updated_ids,
        &updated_ports,
        null,
    );
    cluster.waitNodeExit(3);

    step("receiver dies after publishing the durable anchor");
    // The install rename already happened, but no anchor bound the image,
    // so the previous restart discarded it and transferred again; this
    // rung crashes after the anchor is durable.
    try cluster.spawnNode(3, &updated_ids, &updated_ports, "after_transfer_anchor");
    trickle(cluster, endpoints);
    cluster.waitNodeExit(3);

    step("clean start converges from the installed anchor");
    try cluster.spawnNode(3, &updated_ids, &updated_ports, null);
    const receiver = cluster.endpointOf(3);
    waitForConfiguration(cluster, receiver, 2, 60_000);
    const anchor_slot = waitStatusAtLeast(
        cluster,
        receiver,
        "durable_state_slot",
        1,
        120_000,
    );
    for (0..2) |survivor| {
        const retained = statusInt(
            cluster,
            endpoints[survivor],
            "retained_first_slot",
        ) orelse fail(cluster, "survivor status unavailable", .{});
        if (retained <= 1) {
            fail(cluster, "survivor retained genesis; transfer was not forced", .{});
        }
    }

    step("the transferred replica serves the same data and accepts writes");
    const active = [_]Endpoint{
        cluster.endpointOf(0),
        cluster.endpointOf(1),
        receiver,
    };
    const applied = waitStatusAtLeast(
        cluster,
        receiver,
        "applied_slot",
        anchor_slot,
        120_000,
    );
    _ = applied;
    gpa.free(mustCallAny(
        cluster,
        active[2..3],
        "{\"op\":\"exec\",\"sql\":\"insert into t(v) values ('post-transfer')\"}",
        60_000,
    ));
    // Trickle writes may be retried through a dying leader, so the exact
    // total varies; the invariants are replica equality and the full
    // seed prefix surviving the transfer.
    const baseline = countRows(cluster, active[0], 60_000);
    if (baseline < seed_rows + 1) {
        fail(cluster, "only {d} rows survived; the seed prefix is short", .{
            baseline,
        });
    }
    for (active[1..]) |endpoint| {
        const count = countRows(cluster, endpoint, 60_000);
        if (count != baseline) {
            fail(cluster, "port {d} sees {d} rows, port {d} sees {d}", .{
                endpoint.port,
                count,
                active[0].port,
                baseline,
            });
        }
    }

    step("the transferred replica survives its own restart");
    cluster.killNode(3);
    try cluster.spawnNode(3, &updated_ids, &updated_ports, null);
    waitForConfiguration(cluster, receiver, 2, 60_000);
    gpa.free(mustCallAny(
        cluster,
        active[2..3],
        "{\"op\":\"exec\",\"sql\":\"insert into t(v) values ('post-restart')\"}",
        60_000,
    ));
    const after = countRows(cluster, active[0], 60_000);
    if (after < baseline + 1) {
        fail(cluster, "restart lost rows: {d} then {d}", .{ baseline, after });
    }
    for (active[1..]) |endpoint| {
        const count = countRows(cluster, endpoint, 60_000);
        if (count != after) {
            fail(cluster, "after restart port {d} sees {d}, expected {d}", .{
                endpoint.port,
                count,
                after,
            });
        }
    }
}
