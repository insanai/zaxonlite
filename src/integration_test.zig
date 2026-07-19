//! Single-process durability integration tests for zaxonlite.
//!
//! These drive the real node host against real files: restart recovery,
//! journal-authoritative rebuild, torn-tail truncation, idempotent session
//! retry, snapshot epoch rollover, and materialized-image convergence.

const std = @import("std");
const zaxonlite = @import("zaxonlite");

const testing = std.testing;
const Node = zaxonlite.Node;

const TestDir = struct {
    tmp: std.testing.TmpDir,
    path: []u8,

    fn init(gpa: std.mem.Allocator) !TestDir {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();
        var buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const len = try tmp.dir.realPath(testing.io, &buffer);
        const path = try gpa.dupe(u8, buffer[0..len]);
        return .{ .tmp = tmp, .path = path };
    }

    fn deinit(self: *TestDir, gpa: std.mem.Allocator) void {
        gpa.free(self.path);
        self.tmp.cleanup();
    }

    fn nodeDir(self: *const TestDir, gpa: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(gpa, "{s}/node", .{self.path});
    }
};

fn openNode(directory: []const u8) !*Node {
    return Node.open(testing.allocator, testing.io, .{ .directory = directory });
}

fn countItems(node: *Node) !i64 {
    var result = try node.query(testing.allocator, "select count(*) from items");
    defer result.deinit();
    try testing.expectEqual(@as(usize, 1), result.rows.len);
    return std.fmt.parseInt(i64, result.rows[0][0].?, 10);
}

test "node persists across close and reopen" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        const result = try node.exec("insert into items(v) values ('tea'), ('coffee')");
        try testing.expectEqual(@as(i64, 2), result.changes);
        try testing.expectEqual(@as(i64, 2), try countItems(node));
    }
    {
        const node = try openNode(dir);
        defer node.close();
        try testing.expectEqual(@as(i64, 2), try countItems(node));
        _ = try node.exec("insert into items(v) values ('water')");
        try testing.expectEqual(@as(i64, 3), try countItems(node));

        const report = try node.integrityCheck();
        try testing.expect(report.ok());
    }
}

test "journal is authoritative: materialized image rebuilds from scratch" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        _ = try node.exec("insert into items(v) values ('tea'), ('coffee'), ('water')");
        _ = try node.exec("update items set v = v || '!' where id = 2");
        _ = try node.exec("delete from items where id = 3");
    }

    // Destroy the materialized SQLite image; only journal + payloads remain.
    var node_dir = try std.Io.Dir.cwd().openDir(testing.io, dir, .{});
    defer node_dir.close(testing.io);
    try node_dir.deleteFile(testing.io, "current.db");

    {
        const node = try openNode(dir);
        defer node.close();
        try testing.expectEqual(@as(i64, 2), try countItems(node));
        var result = try node.query(gpa, "select v from items order by id");
        defer result.deinit();
        try testing.expectEqualStrings("tea", result.rows[0][0].?);
        try testing.expectEqualStrings("coffee!", result.rows[1][0].?);
        const report = try node.integrityCheck();
        try testing.expect(report.ok());
    }
}

test "a stale materialized image converges to the journal state" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    var node_dir_handle: ?std.Io.Dir = null;
    defer if (node_dir_handle) |*handle| handle.close(testing.io);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        _ = try node.exec("insert into items(v) values ('tea')");
    }

    // Save an old copy of the image, write more, then put the old copy back:
    // the equivalent of a crash that lost recent checkpointed pages.
    node_dir_handle = try std.Io.Dir.cwd().openDir(testing.io, dir, .{});
    const node_dir = node_dir_handle.?;
    try node_dir.copyFile("current.db", node_dir, "stale.db", testing.io, .{});

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("insert into items(v) values ('coffee'), ('water')");
        try testing.expectEqual(@as(i64, 3), try countItems(node));
    }

    try node_dir.deleteFile(testing.io, "current.db");
    try node_dir.rename("stale.db", node_dir, "current.db", testing.io);

    {
        const node = try openNode(dir);
        defer node.close();
        try testing.expectEqual(@as(i64, 3), try countItems(node));
        const report = try node.integrityCheck();
        try testing.expect(report.ok());
    }
}

test "torn journal tail is truncated and the node reopens" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        _ = try node.exec("insert into items(v) values ('tea')");
    }

    // Append a partial record to the epoch journal, as a crashed append
    // would leave behind.
    var node_dir = try std.Io.Dir.cwd().openDir(testing.io, dir, .{});
    defer node_dir.close(testing.io);
    const journal_name = "paxos-0000000000000001.log";
    const file = try node_dir.openFile(testing.io, journal_name, .{ .mode = .read_write });
    const end = try file.length(testing.io);
    try file.writePositionalAll(testing.io, &.{ 0x4a, 0x58, 0x01 }, end);
    file.close(testing.io);

    {
        const node = try openNode(dir);
        defer node.close();
        try testing.expectEqual(@as(i64, 1), try countItems(node));
        _ = try node.exec("insert into items(v) values ('coffee')");
        try testing.expectEqual(@as(i64, 2), try countItems(node));
    }
}

test "idempotent sessions execute a sequence exactly once" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");

        const session = try node.openSession();
        const first = try node.execIdempotent(session, 1, "insert into items(v) values ('tea')");
        try testing.expectEqual(@as(i64, 1), first.changes);
        try testing.expect(!first.replayed);

        // An ambiguous retry of the same sequence returns the recorded
        // result and never applies twice.
        const retry = try node.execIdempotent(session, 1, "insert into items(v) values ('tea')");
        try testing.expect(retry.replayed);
        try testing.expectEqual(@as(i64, 1), retry.changes);
        try testing.expectEqual(@as(i64, 1), try countItems(node));

        try testing.expectError(
            error.SequenceGap,
            node.execIdempotent(session, 5, "insert into items(v) values ('x')"),
        );
        try testing.expectError(
            error.UnknownSession,
            node.execIdempotent(session + 999, 1, "insert into items(v) values ('x')"),
        );

        _ = try node.execIdempotent(session, 2, "insert into items(v) values ('coffee')");
        try testing.expectError(
            error.ResultExpired,
            node.execIdempotent(session, 1, "insert into items(v) values ('x')"),
        );
        try testing.expectEqual(@as(i64, 2), try countItems(node));
    }

    // Retry safety must survive restart: session state is replicated.
    {
        const node = try openNode(dir);
        defer node.close();
        const retry = try node.execIdempotent(1, 2, "insert into items(v) values ('coffee')");
        try testing.expect(retry.replayed);
        try testing.expectEqual(@as(i64, 2), try countItems(node));
    }
}

test "snapshot seals the epoch and recovery uses snapshot plus suffix" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        _ = try node.exec("insert into items(v) values ('tea'), ('coffee')");

        try node.snapshot();
        try testing.expectEqual(@as(u64, 2), node.identity.configuration_id);
        try testing.expectEqual(@as(u32, 0), node.log.decidedThrough());

        _ = try node.exec("insert into items(v) values ('water')");
        try testing.expectEqual(@as(i64, 3), try countItems(node));
    }

    // Normal restart after a snapshot.
    {
        const node = try openNode(dir);
        defer node.close();
        try testing.expectEqual(@as(i64, 3), try countItems(node));
        try testing.expectEqual(@as(u64, 2), node.identity.configuration_id);
    }

    // Rebuild with no materialized image: snapshot base plus epoch suffix.
    var node_dir = try std.Io.Dir.cwd().openDir(testing.io, dir, .{});
    defer node_dir.close(testing.io);
    try node_dir.deleteFile(testing.io, "current.db");
    {
        const node = try openNode(dir);
        defer node.close();
        try testing.expectEqual(@as(i64, 3), try countItems(node));
        const report = try node.integrityCheck();
        try testing.expect(report.ok());
    }

    // Several snapshot generations: old epochs and unreferenced payloads
    // are garbage-collected, and the node keeps working.
    {
        const node = try openNode(dir);
        defer node.close();
        try node.snapshot();
        _ = try node.exec("insert into items(v) values ('mate')");
        try node.snapshot();
        _ = try node.exec("insert into items(v) values ('cocoa')");
        try testing.expectEqual(@as(i64, 5), try countItems(node));

        // The first epoch's journal must be gone by now.
        try testing.expectError(
            error.FileNotFound,
            node_dir.access(testing.io, "paxos-0000000000000001.log", .{}),
        );
    }
    {
        const node = try openNode(dir);
        defer node.close();
        try testing.expectEqual(@as(i64, 5), try countItems(node));
        const report = try node.integrityCheck();
        try testing.expect(report.ok());
    }
}

test "epoch capacity triggers automatic snapshot rollover" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    _ = try node.exec("create table items(id integer primary key, v text)");

    // Push well past one epoch's capacity (256 slots).
    var buffer: [96]u8 = undefined;
    for (0..300) |index| {
        const sql = try std.fmt.bufPrintZ(
            &buffer,
            "insert into items(v) values ('row-{d}')",
            .{index},
        );
        _ = try node.exec(sql);
    }
    try testing.expectEqual(@as(i64, 300), try countItems(node));
    try testing.expect(node.identity.configuration_id > 1);
    const report = try node.integrityCheck();
    try testing.expect(report.ok());
}

test "failed SQL rolls back and replicates nothing" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text not null)");
        const decided_before = node.log.decidedThrough();
        try testing.expectError(
            error.SqliteError,
            node.exec("insert into items(v) values (null)"),
        );
        try testing.expectEqual(decided_before, node.log.decidedThrough());
        _ = try node.exec("insert into items(v) values ('tea')");
        try testing.expectEqual(@as(i64, 1), try countItems(node));
    }
    {
        const node = try openNode(dir);
        defer node.close();
        try testing.expectEqual(@as(i64, 1), try countItems(node));
    }
}

test "write statements are rejected on the read path" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    _ = try node.exec("create table items(id integer primary key, v text)");
    try testing.expectError(
        error.WriteInReadQuery,
        node.query(gpa, "insert into items(v) values ('nope')"),
    );
}

test "a second process cannot open a locked node directory" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    try testing.expectError(error.NodeLocked, openNode(dir));
}

test "idle sessions expire after the retention window" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    var idle_session: u64 = 0;
    var busy_session: u64 = 0;
    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");

        idle_session = try node.openSession();
        _ = try node.execIdempotent(idle_session, 1, "insert into items(v) values ('old')");

        // A busy session generates activity while the idle one stays quiet.
        busy_session = try node.openSession();
        var sequence: u64 = 1;
        while (sequence <= 8) : (sequence += 1) {
            _ = try node.execIdempotent(
                busy_session,
                sequence,
                "insert into items(v) values ('busy')",
            );
        }

        // Retain only the most recent 3 session-write activities: the idle
        // session falls outside the window and is deleted; the busy stays.
        const expired = try node.expireSessions(3);
        try testing.expectEqual(@as(i64, 1), expired.changes);

        try testing.expectError(
            error.UnknownSession,
            node.execIdempotent(idle_session, 2, "insert into items(v) values ('x')"),
        );
        _ = try node.execIdempotent(
            busy_session,
            9,
            "insert into items(v) values ('still-live')",
        );
    }

    // Expiry is itself replicated: it survives restart.
    const reopened = try openNode(dir);
    defer reopened.close();
    try testing.expectError(
        error.UnknownSession,
        reopened.execIdempotent(idle_session, 2, "insert into items(v) values ('x')"),
    );
    const replay = try reopened.execIdempotent(
        busy_session,
        9,
        "insert into items(v) values ('still-live')",
    );
    try testing.expect(replay.replayed);
}
