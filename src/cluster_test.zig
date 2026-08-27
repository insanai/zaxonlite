//! The three-process cluster integration controller.
//!
//! Spawns three `zaxon serve` processes on loopback ports with independent
//! data directories and drives the mandatory scenario over the client RPC
//! protocol: election, replicated writes through every endpoint, follower
//! stop/catch-up, logical hash comparison, a leader SIGKILL failpoint with
//! exactly-once session retry, a configuration change with a stopped
//! follower (snapshot transfer), image rebuild, and total restart.
//!
//! Every wait is deadline-based on observable conditions. On failure the
//! controller prints each node's status and recent log tail, then exits 1.
//!
//! Usage: cluster-test <path-to-zaxon> [runs]

const std = @import("std");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");
const client = zaxonlite.client;

const Endpoint = client.Endpoint;
const cluster_secret = "cluster-test-secret-32-bytes-minimum";

const NodeProc = struct {
    id: u32,
    port: u16,
    directory: []const u8,
    log_path: []const u8,
    child: ?std.process.Child = null,
};

const Cluster = struct {
    gpa: std.mem.Allocator,
    io: Io,
    zaxon: []const u8,
    root: []const u8,
    auth_file: []const u8,
    nodes: [3]NodeProc,
    endpoints: [3]Endpoint,
    host_buffers: [3][32]u8 = undefined,

    fn endpointList(self: *Cluster) []const Endpoint {
        return &self.endpoints;
    }

    fn spawnNode(self: *Cluster, index: usize, extra_env: bool) !void {
        const node = &self.nodes[index];
        std.debug.assert(node.child == null);

        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(self.gpa);
        var scratch: std.ArrayList([]u8) = .empty;
        defer {
            for (scratch.items) |item| self.gpa.free(item);
            scratch.deinit(self.gpa);
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
        for (self.nodes) |peer| {
            if (peer.id == node.id) continue;
            const peer_text = try std.fmt.allocPrint(
                self.gpa,
                "{d}@127.0.0.1:{d}",
                .{ peer.id, peer.port },
            );
            try scratch.append(self.gpa, peer_text);
            try argv.appendSlice(self.gpa, &.{ "--peer", peer_text });
        }
        try argv.append(self.gpa, "--enable-failpoints");
        try argv.append(self.gpa, "--dev-psk");
        try argv.appendSlice(self.gpa, &.{ "--auth-file", self.auth_file });
        // The scenario exercises process crashes, which lose nothing under
        // either sync policy; skip the full-flush latency.
        try argv.appendSlice(self.gpa, &.{ "--sync", "os" });
        _ = extra_env;

        // Each (re)start truncates the node's log; on failure we dump the
        // most recent generation, which is the interesting one.
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
        }
    }

    fn waitNodeExit(self: *Cluster, index: usize) void {
        const node = &self.nodes[index];
        if (node.child) |*child| {
            _ = child.wait(self.io) catch {};
            node.child = null;
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
    std.debug.print("FAILED at step '{s}': " ++ format ++ "\n", .{progress_step} ++ args);
    dumpDiagnostics(cluster);
    std.process.exit(1);
}

fn dumpDiagnostics(cluster: *Cluster) void {
    for (cluster.endpoints, 0..) |endpoint, index| {
        std.debug.print("--- node {d} status\n", .{cluster.nodes[index].id});
        if (rpcTry(cluster, endpoint, "{\"op\":\"status\"}")) |body| {
            defer cluster.gpa.free(body);
            std.debug.print("{s}\n", .{body});
        } else {
            std.debug.print("(unreachable)\n", .{});
        }
    }
    for (cluster.nodes) |node| {
        std.debug.print("--- log tail {s}\n", .{node.log_path});
        const contents = Io.Dir.cwd().readFileAlloc(
            cluster.io,
            node.log_path,
            cluster.gpa,
            .limited(1 << 20),
        ) catch continue;
        defer cluster.gpa.free(contents);
        const tail = if (contents.len > 4096)
            contents[contents.len - 4096 ..]
        else
            contents;
        std.debug.print("{s}\n", .{tail});
    }
}

// ----------------------------------------------------------------------
// RPC helpers
// ----------------------------------------------------------------------

fn rpcTry(cluster: *Cluster, endpoint: Endpoint, request: []const u8) ?[]u8 {
    const connection = client.Connection.openWithSecret(
        cluster.gpa,
        cluster.io,
        endpoint,
        cluster_secret,
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

fn fieldString(
    cluster: *Cluster,
    parsed: *const Parsed,
    name: []const u8,
) []const u8 {
    const value = field(parsed, name) orelse
        fail(cluster, "response missing field {s}", .{name});
    return switch (value) {
        .string => |text| text,
        else => fail(cluster, "field {s} is not a string", .{name}),
    };
}

fn isOk(parsed: *const Parsed) bool {
    const value = field(parsed, "ok") orelse return false;
    return value == .bool and value.bool;
}

/// Calls through the cluster with redirect-following; fails the run on
/// error responses (other than the codes listed in `tolerate`).
fn mustCall(
    cluster: *Cluster,
    request: []const u8,
    deadline_ms: u64,
) []u8 {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        var result = client.callClusterWithSecret(
            cluster.gpa,
            cluster.io,
            cluster.endpointList(),
            request,
            true,
            cluster_secret,
        ) catch {
            elapsed += 500;
            cluster.io.sleep(.fromMilliseconds(500), .awake) catch {};
            continue;
        };
        const parsed = parse(cluster, result.body);
        defer parsed.deinit();
        if (isOk(&parsed)) return result.takeBody(cluster.gpa);
        // Retryable outcomes during elections and rollovers.
        const code = fieldString(cluster, &parsed, "error");
        if (std.mem.eql(u8, code, "retry") or
            std.mem.eql(u8, code, "timeout") or
            std.mem.eql(u8, code, "not_leader") or
            std.mem.eql(u8, code, "unavailable") or
            std.mem.eql(u8, code, "ambiguous"))
        {
            result.deinit(cluster.gpa);
            elapsed += 250;
            cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
            continue;
        }
        fail(cluster, "rpc failed: {s} -> {s}", .{ request, result.body });
    }
    fail(cluster, "rpc deadline exceeded: {s}", .{request});
}

fn waitFor(
    cluster: *Cluster,
    endpoint: Endpoint,
    comptime predicate: anytype,
    context: anytype,
    deadline_ms: u64,
    what: []const u8,
) void {
    var elapsed: u64 = 0;
    while (elapsed <= deadline_ms) {
        if (rpcTry(cluster, endpoint, "{\"op\":\"status\"}")) |body| {
            defer cluster.gpa.free(body);
            const parsed = parse(cluster, body);
            defer parsed.deinit();
            if (predicate(&parsed, context)) return;
        }
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "timeout waiting for {s} at {s}:{d}", .{
        what,
        endpoint.host,
        endpoint.port,
    });
}

fn hasLeader(parsed: *const Parsed, _: void) bool {
    const value = field(parsed, "leader") orelse return false;
    return value == .integer;
}

fn appliedAtLeast(parsed: *const Parsed, target: i64) bool {
    const applied = fieldInt(parsed, "applied_slot") orelse return false;
    return applied >= target;
}

fn trimmedAtLeast(parsed: *const Parsed, target: i64) bool {
    const trimmed = fieldInt(parsed, "chosen_trim_slot") orelse return false;
    return trimmed >= target;
}

fn configurationAtLeast(parsed: *const Parsed, target: i64) bool {
    const configuration = fieldInt(parsed, "configuration_id") orelse return false;
    return configuration >= target;
}

fn leaderEndpoint(cluster: *Cluster) Endpoint {
    var elapsed: u64 = 0;
    while (elapsed <= 10_000) {
        for (cluster.endpoints) |endpoint| {
            if (rpcTry(cluster, endpoint, "{\"op\":\"status\"}")) |body| {
                defer cluster.gpa.free(body);
                const parsed = parse(cluster, body);
                defer parsed.deinit();
                const role = fieldString(cluster, &parsed, "role");
                if (std.mem.eql(u8, role, "leader")) return endpoint;
            }
        }
        elapsed += 250;
        cluster.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
    fail(cluster, "no leader found", .{});
}

fn leaderIndex(cluster: *Cluster) usize {
    const endpoint = leaderEndpoint(cluster);
    for (cluster.endpoints, 0..) |candidate, index| {
        if (candidate.port == endpoint.port) return index;
    }
    unreachable;
}

fn execSql(cluster: *Cluster, sql: []const u8, deadline_ms: u64) void {
    var request: std.Io.Writer.Allocating = .init(cluster.gpa);
    defer request.deinit();
    request.writer.writeAll("{\"op\":\"exec\",\"sql\":") catch unreachable;
    writeJsonString(&request.writer, sql);
    request.writer.writeAll("}") catch unreachable;
    const body = mustCall(cluster, request.written(), deadline_ms);
    cluster.gpa.free(body);
}

fn writeJsonString(out: *Io.Writer, text: []const u8) void {
    out.writeAll("\"") catch unreachable;
    for (text) |byte| {
        switch (byte) {
            '"' => out.writeAll("\\\"") catch unreachable,
            '\\' => out.writeAll("\\\\") catch unreachable,
            '\n' => out.writeAll("\\n") catch unreachable,
            else => out.writeAll(&.{byte}) catch unreachable,
        }
    }
    out.writeAll("\"") catch unreachable;
}

/// Counts rows through the default read level, which is linearizable.
fn linearizableCount(cluster: *Cluster, deadline_ms: u64) i64 {
    const body = mustCall(
        cluster,
        "{\"op\":\"query\",\"sql\":\"select count(*) from t\"}",
        deadline_ms,
    );
    defer cluster.gpa.free(body);
    return firstCell(cluster, body);
}

fn firstCell(cluster: *Cluster, body: []const u8) i64 {
    const parsed = parse(cluster, body);
    defer parsed.deinit();
    const rows = field(&parsed, "rows") orelse fail(cluster, "no rows", .{});
    if (rows != .array or rows.array.items.len == 0) {
        fail(cluster, "empty result: {s}", .{body});
    }
    const row = rows.array.items[0];
    if (row != .array or row.array.items.len == 0) {
        fail(cluster, "empty row: {s}", .{body});
    }
    const cell = row.array.items[0];
    return switch (cell) {
        .string => |text| std.fmt.parseInt(i64, text, 10) catch
            fail(cluster, "non-integer cell {s}", .{text}),
        .integer => |n| n,
        else => fail(cluster, "unexpected cell type", .{}),
    };
}

const NodeDigest = struct {
    chain: [64]u8,
    content: [64]u8,
    applied: i64,
};

fn nodeDigest(cluster: *Cluster, endpoint: Endpoint) NodeDigest {
    const body = rpcTry(cluster, endpoint, "{\"op\":\"hash\"}") orelse
        fail(cluster, "hash rpc unreachable at port {d}", .{endpoint.port});
    defer cluster.gpa.free(body);
    const parsed = parse(cluster, body);
    defer parsed.deinit();
    if (!isOk(&parsed)) fail(cluster, "hash rpc failed: {s}", .{body});
    var digest: NodeDigest = undefined;
    const chain = fieldString(cluster, &parsed, "chain");
    const content = fieldString(cluster, &parsed, "content");
    if (chain.len != 64 or content.len != 64) {
        fail(cluster, "bad hash lengths: {s}", .{body});
    }
    @memcpy(&digest.chain, chain);
    @memcpy(&digest.content, content);
    digest.applied = fieldInt(&parsed, "applied_slot") orelse -1;
    return digest;
}

fn expectAllDigestsEqual(cluster: *Cluster, what: []const u8) void {
    const first = nodeDigest(cluster, cluster.endpoints[0]);
    for (cluster.endpoints[1..], 1..) |endpoint, index| {
        const digest = nodeDigest(cluster, endpoint);
        if (!std.mem.eql(u8, &first.chain, &digest.chain) or
            !std.mem.eql(u8, &first.content, &digest.content))
        {
            fail(cluster, "{s}: node {d} diverges: chain {s} vs {s}, " ++
                "content {s} vs {s}", .{
                what,
                cluster.nodes[index].id,
                first.chain,
                digest.chain,
                first.content,
                digest.content,
            });
        }
    }
}

fn expectIntegrityAll(cluster: *Cluster) void {
    for (cluster.endpoints) |endpoint| {
        const body = rpcTry(cluster, endpoint, "{\"op\":\"integrity\"}") orelse
            fail(cluster, "integrity rpc unreachable at {d}", .{endpoint.port});
        defer cluster.gpa.free(body);
        const parsed = parse(cluster, body);
        defer parsed.deinit();
        if (!isOk(&parsed)) fail(cluster, "integrity failed: {s}", .{body});
    }
}

fn waitAllApplied(cluster: *Cluster, target: i64, deadline_ms: u64) void {
    for (cluster.endpoints) |endpoint| {
        waitFor(cluster, endpoint, appliedAtLeast, target, deadline_ms, "applied slot");
    }
}

// ----------------------------------------------------------------------
// Free port discovery
// ----------------------------------------------------------------------

fn freePort(io: Io) !u16 {
    const address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try address.listen(io, .{ .reuse_address = true });
    const port = listener.socket.address.getPort();
    listener.deinit(io);
    return port;
}

// ----------------------------------------------------------------------
// Scenario
// ----------------------------------------------------------------------

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;

    var iterator = std.process.Args.Iterator.init(init.minimal.args);
    defer iterator.deinit();
    _ = iterator.next();
    const zaxon = iterator.next() orelse {
        std.debug.print("usage: cluster-test <path-to-zaxon> [runs]\n", .{});
        return 2;
    };
    const runs = blk: {
        const text = iterator.next() orelse break :blk @as(usize, 1);
        break :blk std.fmt.parseInt(usize, text, 10) catch 1;
    };

    for (0..runs) |run_index| {
        std.debug.print("=== cluster run {d}/{d}\n", .{ run_index + 1, runs });
        try runScenario(gpa, io, zaxon, run_index);
    }
    std.debug.print("cluster test: all {d} run(s) passed\n", .{runs});
    return 0;
}

fn runScenario(
    gpa: std.mem.Allocator,
    io: Io,
    zaxon: []const u8,
    run_index: usize,
) !void {
    var random_bytes: [8]u8 = undefined;
    io.random(&random_bytes);
    const nonce = std.mem.readInt(u64, &random_bytes, .little);

    const root = try std.fmt.allocPrint(
        gpa,
        ".zig-cache/tmp/zx-cluster-{x}-{d}",
        .{ nonce, run_index },
    );
    defer gpa.free(root);
    try Io.Dir.cwd().createDirPath(io, root);
    defer Io.Dir.cwd().deleteTree(io, root) catch {};
    const auth_file = try std.fmt.allocPrint(gpa, "{s}/auth.secret", .{root});
    defer gpa.free(auth_file);
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = auth_file,
        .data = cluster_secret,
        .flags = .{ .permissions = @enumFromInt(0o600) },
    });

    var cluster = Cluster{
        .gpa = gpa,
        .io = io,
        .zaxon = zaxon,
        .root = root,
        .auth_file = auth_file,
        .nodes = undefined,
        .endpoints = undefined,
    };

    for (0..3) |index| {
        const id: u32 = @intCast(index + 1);
        const port = try freePort(io);
        cluster.nodes[index] = .{
            .id = id,
            .port = port,
            .directory = try std.fmt.allocPrint(gpa, "{s}/n{d}", .{ root, id }),
            .log_path = try std.fmt.allocPrint(gpa, "{s}/n{d}.log", .{ root, id }),
        };
        const host = std.fmt.bufPrint(
            &cluster.host_buffers[index],
            "127.0.0.1",
            .{},
        ) catch unreachable;
        cluster.endpoints[index] = .{ .host = host, .port = port };
    }
    defer for (cluster.nodes) |node| {
        gpa.free(node.directory);
        gpa.free(node.log_path);
    };
    defer cluster.killAll();

    step("start three nodes");
    for (0..3) |index| try cluster.spawnNode(index, false);

    step("wait for one leader");
    for (cluster.endpoints) |endpoint| {
        waitFor(&cluster, endpoint, hasLeader, {}, 15_000, "leader knowledge");
    }

    step("reject a client with the wrong transport secret");
    if (client.Connection.openWithSecret(
        gpa,
        io,
        cluster.endpoints[0],
        "wrong-transport-secret-32-bytes!",
    )) |connection| {
        connection.close();
        fail(&cluster, "wrong transport secret was accepted", .{});
    } else |_| {}

    const members_body = rpcTry(
        &cluster,
        cluster.endpoints[0],
        "{\"op\":\"members\"}",
    ) orelse fail(&cluster, "members RPC unavailable", .{});
    defer gpa.free(members_body);
    if (std.mem.indexOf(
        u8,
        members_body,
        "\"voter_membership\":\"decided\"",
    ) == null) {
        fail(&cluster, "members RPC malformed: {s}", .{members_body});
    }

    step("create schema");
    execSql(&cluster, "create table t(a integer primary key, b text)", 15_000);

    step("create multimodal search schema and rows (ZDS 0009)");
    execSql(
        &cluster,
        "create table media(id integer primary key, title text); " ++
            "create virtual table media_fts using fts5(body); " ++
            "create virtual table media_vec using vec0(" ++
            "item_id integer primary key, " ++
            "embedding float[8], embedding_coarse bit[8]);",
        15_000,
    );
    execSql(
        &cluster,
        "insert into media(id, title) values " ++
            "(1, 'paxos replicates sqlite'), (2, 'vectors rank media'); " ++
            "insert into media_fts(rowid, body) values " ++
            "(1, 'paxos replicates sqlite'), (2, 'vectors rank media'); " ++
            "insert into media_vec(item_id, embedding, embedding_coarse) values " ++
            "(1, vec_f32('[1,0,0,0,0,0,0,0]'), " ++
            "vec_quantize_binary(vec_f32('[1,-1,-1,-1,-1,-1,-1,-1]'))), " ++
            "(2, vec_f32('[0,1,0,0,0,0,0,0]'), " ++
            "vec_quantize_binary(vec_f32('[-1,1,-1,-1,-1,-1,-1,-1]')));",
        15_000,
    );

    step("open sessions");
    const session_body = mustCall(&cluster, "{\"op\":\"session\"}", 10_000);
    const session_id: u64 = blk: {
        const parsed = parse(&cluster, session_body);
        defer parsed.deinit();
        break :blk @intCast(fieldInt(&parsed, "session_id") orelse
            fail(&cluster, "no session id", .{}));
    };
    cluster.gpa.free(session_body);

    step("submit requests 1..100 through all three endpoints");
    // Sessioned writes interleaved with plain writes, submitted to every
    // endpoint in turn (followers redirect to the leader).
    var sequence: u64 = 0;
    for (0..100) |index| {
        const target = cluster.endpoints[index % 3];
        var request: std.Io.Writer.Allocating = .init(gpa);
        defer request.deinit();
        if (index % 2 == 0) {
            sequence += 1;
            request.writer.print(
                "{{\"op\":\"exec\",\"sql\":\"insert into t(b) values ('w{d}')\"," ++
                    "\"session\":{d},\"sequence\":{d}}}",
                .{ index, session_id, sequence },
            ) catch unreachable;
        } else {
            request.writer.print(
                "{{\"op\":\"exec\",\"sql\":\"insert into t(b) values ('w{d}')\"}}",
                .{index},
            ) catch unreachable;
        }
        // Submit first to the chosen endpoint; on redirect the shared
        // helper walks to the leader.
        if (rpcTry(&cluster, target, request.written())) |body| {
            const parsed = parse(&cluster, body);
            const ok = isOk(&parsed);
            var not_leader = false;
            if (!ok) {
                const code = fieldString(&cluster, &parsed, "error");
                not_leader = std.mem.eql(u8, code, "not_leader");
            }
            parsed.deinit();
            cluster.gpa.free(body);
            if (ok) continue;
            if (!not_leader) fail(&cluster, "write {d} failed", .{index});
        }
        const body = mustCall(&cluster, request.written(), 15_000);
        cluster.gpa.free(body);
    }

    step("verify linearizable count = 100");
    const count_100 = linearizableCount(&cluster, 15_000);
    if (count_100 != 100) fail(&cluster, "expected 100 rows, got {d}", .{count_100});

    step("verify session sequences occur exactly once");
    {
        const body = mustCall(
            &cluster,
            "{\"op\":\"query\",\"sql\":\"select count(*) from t where b like 'w%'\"," ++
                "\"level\":\"linearizable\"}",
            10_000,
        );
        cluster.gpa.free(body);
    }

    step("stream and verify an authenticated remote backup");
    const backup_path = try std.fmt.allocPrintSentinel(
        gpa,
        "{s}/remote-backup.db",
        .{root},
        0,
    );
    defer gpa.free(backup_path);
    const backup_connection = try client.Connection.openWithSecret(
        gpa,
        io,
        leaderEndpoint(&cluster),
        cluster_secret,
    );
    try backup_connection.backupTo(backup_path);
    backup_connection.close();
    var backup_db = try zaxonlite.sqlite.Db.open(backup_path);
    defer backup_db.close();
    try std.testing.expect(try backup_db.integrityCheckOk());
    var backup_count = try backup_db.prepare("select count(*) from t");
    defer backup_count.finalize();
    try std.testing.expect(try backup_count.step());
    try std.testing.expectEqual(@as(i64, 100), backup_count.columnInt64(0));

    step("stop one follower");
    const leader_before = leaderIndex(&cluster);
    const stopped_follower = (leader_before + 1) % 3;
    cluster.killNode(stopped_follower);

    step("insert 101..150 through the leader");
    for (100..150) |index| {
        var request: std.Io.Writer.Allocating = .init(gpa);
        defer request.deinit();
        request.writer.print(
            "{{\"op\":\"exec\",\"sql\":\"insert into t(b) values ('w{d}')\"}}",
            .{index},
        ) catch unreachable;
        const body = mustCall(&cluster, request.written(), 15_000);
        cluster.gpa.free(body);
    }
    const count_150 = linearizableCount(&cluster, 15_000);
    if (count_150 != 150) fail(&cluster, "expected 150 rows, got {d}", .{count_150});

    step("restart follower and wait for catch-up");
    try cluster.spawnNode(stopped_follower, false);
    const leader_status = mustCall(&cluster, "{\"op\":\"status\"}", 10_000);
    const leader_applied = blk: {
        const parsed = parse(&cluster, leader_status);
        defer parsed.deinit();
        break :blk fieldInt(&parsed, "applied_slot") orelse 0;
    };
    cluster.gpa.free(leader_status);
    waitAllApplied(&cluster, leader_applied, 30_000);

    step("compare logical database hashes on all three nodes");
    expectAllDigestsEqual(&cluster, "after catch-up");

    step("hybrid search answers identically on every endpoint");
    {
        // Every node applied the same pages, so the coarse bit scan plus
        // exact rerank must return byte-identical results everywhere.
        const hybrid =
            "{\"op\":\"query\",\"level\":\"any\",\"freshness_ms\":60000," ++
            "\"sql\":\"with coarse as (select item_id, embedding " ++
            "from media_vec where embedding_coarse match " ++
            "vec_quantize_binary(vec_f32('[1,-1,-1,-1,-1,-1,-1,-1]')) " ++
            "and k = 2) select item_id from coarse order by " ++
            "zaxon_vec_distance_cosine(embedding, " ++
            "vec_f32('[1,0,0,0,0,0,0,0]')), item_id\"}";
        var reference: ?[]u8 = null;
        defer if (reference) |body| cluster.gpa.free(body);
        for (cluster.endpoints) |endpoint| {
            const body = rpcTry(&cluster, endpoint, hybrid) orelse
                fail(&cluster, "hybrid query unreachable at port {d}", .{endpoint.port});
            if (std.mem.indexOf(u8, body, "\"ok\":true") == null) {
                fail(&cluster, "hybrid query failed: {s}", .{body});
            }
            if (reference) |expected| {
                if (!std.mem.eql(u8, expected, body)) {
                    fail(&cluster, "hybrid results diverge: {s}", .{body});
                }
                cluster.gpa.free(body);
            } else {
                reference = body;
            }
        }
    }

    step("typed search op round-trips on every endpoint");
    {
        // Base64 of the little-endian float32 vector [1,0,0,0,0,0,0,0].
        const typed =
            "{\"op\":\"search\",\"level\":\"any\",\"freshness_ms\":60000," ++
            "\"vec_table\":\"media_vec\"," ++
            "\"embedding\":\"AACAPwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"," ++
            "\"k\":2,\"candidate_count\":64,\"metadata_table\":\"media\"," ++
            "\"metadata_columns\":[\"title\"]}";
        for (cluster.endpoints) |endpoint| {
            const body = rpcTry(&cluster, endpoint, typed) orelse
                fail(&cluster, "search op unreachable at port {d}", .{endpoint.port});
            defer cluster.gpa.free(body);
            if (std.mem.indexOf(u8, body, "\"ok\":true") == null or
                std.mem.indexOf(u8, body, "[\"1\",") == null or
                std.mem.indexOf(u8, body, "\"paxos replicates sqlite\"") == null)
            {
                fail(&cluster, "search op failed: {s}", .{body});
            }
        }
        // The candidate cap rejects before any SQL runs.
        const over_cap =
            "{\"op\":\"search\",\"vec_table\":\"media_vec\"," ++
            "\"embedding\":\"AACAPwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"," ++
            "\"k\":2,\"candidate_count\":4097}";
        const body = rpcTry(&cluster, cluster.endpoints[0], over_cap) orelse
            fail(&cluster, "search cap rpc unreachable", .{});
        defer cluster.gpa.free(body);
        if (std.mem.indexOf(u8, body, "candidate_count must be") == null) {
            fail(&cluster, "candidate cap not enforced: {s}", .{body});
        }
    }

    step("status reports the search capability manifest");
    {
        const body = mustCall(&cluster, "{\"op\":\"status\"}", 10_000);
        defer cluster.gpa.free(body);
        for ([_][]const u8{
            "\"fts5_enabled\":true",
            "\"sqlite_vec_version\":\"v0.1.9\"",
            "\"search_feature_version\":1",
            "\"simd_backend\":\"",
            "\"mmap_size\":0",
            "\"candidate_hard_limit\":4096",
        }) |needle| {
            if (std.mem.indexOf(u8, body, needle) == null) {
                fail(&cluster, "status missing {s}: {s}", .{ needle, body });
            }
        }
    }

    step("arm leader failpoint: after quorum choice, before client reply");
    const leader_now = leaderIndex(&cluster);
    {
        const body = rpcTry(
            &cluster,
            cluster.endpoints[leader_now],
            "{\"op\":\"failpoint\",\"name\":\"before_client_reply\"}",
        ) orelse fail(&cluster, "failpoint rpc failed", .{});
        cluster.gpa.free(body);
    }

    step("submit session write; leader dies before replying");
    sequence += 1;
    {
        var request: std.Io.Writer.Allocating = .init(gpa);
        defer request.deinit();
        request.writer.print(
            "{{\"op\":\"exec\",\"sql\":\"insert into t(b) values ('fp')\"," ++
                "\"session\":{d},\"sequence\":{d}}}",
            .{ session_id, sequence },
        ) catch unreachable;
        // The direct call dies with the leader; that is the point.
        if (rpcTry(&cluster, cluster.endpoints[leader_now], request.written())) |body| {
            cluster.gpa.free(body);
        }
        cluster.waitNodeExit(leader_now);

        step("retry the same session sequence at the new leader");
        const body = mustCall(&cluster, request.written(), 30_000);
        defer cluster.gpa.free(body);
        const parsed = parse(&cluster, body);
        defer parsed.deinit();
        if (!isOk(&parsed)) fail(&cluster, "retry failed: {s}", .{body});
    }

    step("assert session sequence applied exactly once");
    {
        const body = mustCall(
            &cluster,
            "{\"op\":\"query\",\"sql\":\"select count(*) from t where b = 'fp'\"," ++
                "\"level\":\"linearizable\"}",
            15_000,
        );
        defer cluster.gpa.free(body);
        const applied_once = firstCell(&cluster, body);
        if (applied_once != 1) {
            fail(&cluster, "failpoint write applied {d} times", .{applied_once});
        }
    }

    step("restart the killed leader");
    try cluster.spawnNode(leader_now, false);

    step("state anchor with a stopped follower (journal catch-up)");
    const lag_follower = (leaderIndex(&cluster) + 1) % 3;
    cluster.killNode(lag_follower);
    execSql(&cluster, "insert into t(b) values ('pre-roll')", 15_000);
    {
        const body = mustCall(&cluster, "{\"op\":\"anchor\"}", 20_000);
        cluster.gpa.free(body);
    }
    execSql(&cluster, "insert into t(b) values ('post-roll')", 15_000);
    try cluster.spawnNode(lag_follower, false);
    // The restarted node catches up from the retained journal (ZDS 0011):
    // slots are global, the configuration never changes, and history the
    // survivors released from their windows is served from segments.
    {
        const leader_status_2 = mustCall(&cluster, "{\"op\":\"status\"}", 10_000);
        const parsed = parse(&cluster, leader_status_2);
        const target_configuration = fieldInt(&parsed, "configuration_id") orelse 0;
        const target_applied = fieldInt(&parsed, "applied_slot") orelse 0;
        parsed.deinit();
        cluster.gpa.free(leader_status_2);
        if (target_configuration != 1) {
            fail(&cluster, "configuration changed to {d}", .{target_configuration});
        }
        waitFor(
            &cluster,
            cluster.endpoints[lag_follower],
            appliedAtLeast,
            target_applied,
            30_000,
            "catch-up after restart",
        );
    }
    expectAllDigestsEqual(&cluster, "after journal catch-up");

    step("conservative trim advances once every data replica reported");
    for (cluster.endpoints) |endpoint| {
        waitFor(&cluster, endpoint, trimmedAtLeast, 1, 30_000, "chosen trim");
    }

    step("delete a follower image; node rebuilds from anchor plus suffix");
    const rebuild_follower = (leaderIndex(&cluster) + 2) % 3;
    cluster.killNode(rebuild_follower);
    {
        const db_path = try std.fmt.allocPrint(
            gpa,
            "{s}/current.db",
            .{cluster.nodes[rebuild_follower].directory},
        );
        defer gpa.free(db_path);
        Io.Dir.cwd().deleteFile(io, db_path) catch {};
    }
    try cluster.spawnNode(rebuild_follower, false);
    {
        const status_body = mustCall(&cluster, "{\"op\":\"status\"}", 10_000);
        const parsed = parse(&cluster, status_body);
        const target_applied = fieldInt(&parsed, "applied_slot") orelse 0;
        parsed.deinit();
        cluster.gpa.free(status_body);
        waitFor(
            &cluster,
            cluster.endpoints[rebuild_follower],
            appliedAtLeast,
            target_applied,
            30_000,
            "rebuild from the retained journal",
        );
    }
    expectAllDigestsEqual(&cluster, "after image rebuild");

    step("stop all nodes without graceful shutdown");
    cluster.killAll();

    step("restart all from the same directories");
    for (0..3) |index| try cluster.spawnNode(index, false);
    for (cluster.endpoints) |endpoint| {
        waitFor(&cluster, endpoint, hasLeader, {}, 20_000, "leader after restart");
    }

    step("assert every acknowledged write is present exactly once");
    const final_count = linearizableCount(&cluster, 20_000);
    // 150 rows + the failpoint row + pre-roll + post-roll.
    if (final_count != 153) {
        fail(&cluster, "expected 153 rows after restart, got {d}", .{final_count});
    }
    {
        const body = mustCall(
            &cluster,
            "{\"op\":\"query\",\"sql\":\"select count(*) from t where b='fp'\"," ++
                "\"level\":\"linearizable\"}",
            10_000,
        );
        defer cluster.gpa.free(body);
        if (firstCell(&cluster, body) != 1) {
            fail(&cluster, "failpoint row duplicated after restart", .{});
        }
    }

    step("run integrity checks and compare logical hashes");
    {
        // Wait for every node to reach the leader's applied slot first.
        const status_body = mustCall(&cluster, "{\"op\":\"status\"}", 10_000);
        const parsed = parse(&cluster, status_body);
        const target_applied = fieldInt(&parsed, "applied_slot") orelse 0;
        parsed.deinit();
        cluster.gpa.free(status_body);
        waitAllApplied(&cluster, target_applied, 30_000);
    }
    expectIntegrityAll(&cluster);
    expectAllDigestsEqual(&cluster, "after total restart");

    step("stop cluster");
    cluster.killAll();
    std.debug.print("scenario complete\n", .{});
}
