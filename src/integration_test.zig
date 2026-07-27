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

test "prepared explicit transaction is one durable replicated transition" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec(
            "create table items(id integer primary key, v text, amount real, raw blob)",
        );
        var transaction = zaxonlite.Transaction.init(gpa);
        defer transaction.deinit();
        try transaction.exec(
            "insert into items(v, amount, raw) values (?1, ?2, ?3)",
            &.{
                .{ .text = "tea" },
                .{ .real = 2.5 },
                .{ .blob = &.{ 0, 1, 2, 255 } },
            },
        );
        try transaction.exec(
            "insert into items(v, amount, raw) values (?1, ?2, ?3)",
            &.{
                .{ .text = "coffee" },
                .{ .null_value = {} },
                .{ .blob = "beans" },
            },
        );
        const result = try node.execTransaction(&transaction);
        try testing.expectEqual(@as(i64, 2), result.changes);

        var query = try node.queryPrepared(
            gpa,
            "select v, hex(raw) from items where amount > ?1 order by id",
            &.{.{ .real = 2.0 }},
        );
        defer query.deinit();
        try testing.expectEqual(@as(usize, 1), query.rows.len);
        try testing.expectEqualStrings("tea", query.rows[0][0].?);
        try testing.expectEqualStrings("000102FF", query.rows[0][1].?);
    }

    const reopened = try openNode(dir);
    defer reopened.close();
    try testing.expectEqual(@as(i64, 2), try countItems(reopened));
    const report = try reopened.integrityCheck();
    try testing.expect(report.ok());
}

test "remote-style query budgets bound rows bytes and SQLite work" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);
    const node = try openNode(dir);
    defer node.close();

    try testing.expectError(
        error.QueryRowLimit,
        node.queryWithLimits(
            gpa,
            "with recursive n(x) as (values(1) union all " ++
                "select x+1 from n where x<10) select x from n",
            .{ .max_rows = 3 },
        ),
    );
    try testing.expectError(
        error.QueryResultTooLarge,
        node.queryWithLimits(gpa, "select printf('%100s', 'x')", .{
            .max_bytes = 16,
        }),
    );
    try testing.expectError(
        error.SqliteInterrupted,
        node.queryWithLimits(
            gpa,
            "with recursive n(x) as (values(1) union all " ++
                "select x+1 from n where x<1000000) select sum(x) from n",
            .{ .max_vm_steps = 1_000 },
        ),
    );

    // Clearing the progress handler after interruption is part of the
    // contract: subsequent ordinary embedded reads remain unlimited.
    var result = try node.query(gpa, "select 42");
    defer result.deinit();
    try testing.expectEqualStrings("42", result.rows[0][0].?);
}

test "one MiB payload survives journal-only image recovery" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);
    const payload = try gpa.alloc(u8, 1024 * 1024);
    defer gpa.free(payload);
    for (payload, 0..) |*byte, index| byte.* = @truncate(index *% 131);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table large_payload(value blob)");
        _ = try node.execPrepared(
            "insert into large_payload values (?1)",
            &.{.{ .blob = payload }},
        );
    }
    var node_dir = try std.Io.Dir.cwd().openDir(testing.io, dir, .{});
    defer node_dir.close(testing.io);
    try node_dir.deleteFile(testing.io, "current.db");

    const recovered = try openNode(dir);
    defer recovered.close();
    var result = try recovered.query(
        gpa,
        "select length(value), hex(substr(value, 1, 4)) from large_payload",
    );
    defer result.deinit();
    try testing.expectEqualStrings("1048576", result.rows[0][0].?);
    try testing.expectEqualStrings("00830689", result.rows[0][1].?);
    try testing.expect((try recovered.integrityCheck()).ok());
}

test "a data directory cannot silently change learner role" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);
    const voters = [_]u32{ 1, 2 };
    {
        const node = try Node.open(gpa, testing.io, .{
            .directory = dir,
            .node_id = 3,
            .members = &voters,
            .database_id = 77,
            .role = .standby,
        });
        node.close();
    }
    try testing.expectError(
        error.NodeRoleMismatch,
        Node.open(gpa, testing.io, .{
            .directory = dir,
            .node_id = 3,
            .members = &voters,
            .database_id = 77,
            .role = .read_replica,
        }),
    );
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

test "recovery discards a corrupt materialized image even with an empty suffix" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        _ = try node.exec("insert into items(v) values ('snapshot-only')");
        try node.snapshot();
        try testing.expectEqual(@as(u32, 0), node.log.decidedThrough());
    }

    // Damage a page in the non-authoritative working image. The current
    // epoch has no suffix entries that could happen to overwrite it.
    var node_dir = try std.Io.Dir.cwd().openDir(testing.io, dir, .{});
    defer node_dir.close(testing.io);
    const file = try node_dir.openFile(
        testing.io,
        "current.db",
        .{ .mode = .read_write },
    );
    try file.writePositionalAll(testing.io, "not sqlite", 0);
    try file.sync(testing.io);
    file.close(testing.io);

    const reopened = try openNode(dir);
    defer reopened.close();
    try testing.expectEqual(@as(i64, 1), try countItems(reopened));
    const report = try reopened.integrityCheck();
    try testing.expect(report.ok());
}

test "recovery completes rollover after CURRENT advances before identity" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    var database_id: u128 = 0;
    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        _ = try node.exec("insert into items(v) values ('durable')");
        database_id = node.identity.database_id;
        try node.snapshot();
        try testing.expectEqual(@as(u64, 2), node.identity.configuration_id);
    }

    // Recreate the durable prefix immediately after CURRENT was installed:
    // the sealed epoch-1 journal and snapshot exist, while identity still
    // names epoch 1; the next-epoch journal has not been created yet.
    var node_dir = try std.Io.Dir.cwd().openDir(testing.io, dir, .{});
    defer node_dir.close(testing.io);
    var identity_buffer: [256]u8 = undefined;
    const identity = std.fmt.bufPrint(
        &identity_buffer,
        "format=1\nnode_id=1\ndatabase_id={x:0>32}\nconfiguration_id=1\n",
        .{database_id},
    ) catch unreachable;
    const file = try node_dir.createFile(testing.io, "identity", .{
        .read = true,
        .truncate = true,
    });
    try file.writePositionalAll(testing.io, identity, 0);
    try file.sync(testing.io);
    file.close(testing.io);
    // At the represented crash point the next-epoch journal has not received
    // any protocol writes. Remove the later campaign record produced by the
    // fully completed setup run.
    try node_dir.deleteFile(testing.io, "paxos-0000000000000002.log");

    const reopened = try openNode(dir);
    defer reopened.close();
    try testing.expectEqual(@as(u64, 2), reopened.identity.configuration_id);
    try testing.expectEqual(@as(i64, 1), try countItems(reopened));
    const report = try reopened.integrityCheck();
    try testing.expect(report.ok());
}

test "recovery completes interrupted snapshot install without a stop sign" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    var database_id: u128 = 0;
    {
        const node = try openNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        _ = try node.exec("insert into items(v) values ('transferred')");
        database_id = node.identity.database_id;
        try node.snapshot();
    }

    var node_dir = try std.Io.Dir.cwd().openDir(testing.io, dir, .{});
    defer node_dir.close(testing.io);
    var identity_buffer: [256]u8 = undefined;
    const identity = std.fmt.bufPrint(
        &identity_buffer,
        "format=1\nnode_id=1\ndatabase_id={x:0>32}\nconfiguration_id=1\n",
        .{database_id},
    ) catch unreachable;
    {
        const file = try node_dir.createFile(testing.io, "identity", .{
            .read = true,
            .truncate = true,
        });
        try file.writePositionalAll(testing.io, identity, 0);
        try file.sync(testing.io);
        file.close(testing.io);
    }
    // A receiver that installed the snapshot but never learned the sealing
    // stop sign has an empty old journal.
    try node_dir.deleteFile(testing.io, "paxos-0000000000000001.log");
    try node_dir.deleteFile(testing.io, "paxos-0000000000000002.log");
    const empty = try node_dir.createFile(
        testing.io,
        "paxos-0000000000000001.log",
        .{ .read = true },
    );
    try empty.sync(testing.io);
    empty.close(testing.io);

    const reopened = try openNode(dir);
    defer reopened.close();
    try testing.expectEqual(@as(u64, 2), reopened.identity.configuration_id);
    try testing.expectEqual(@as(i64, 1), try countItems(reopened));
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

    // Push past one bounded 2048-slot epoch.
    var buffer: [96]u8 = undefined;
    for (0..2075) |index| {
        const sql = try std.fmt.bufPrintZ(
            &buffer,
            "insert into items(v) values ('row-{d}')",
            .{index},
        );
        _ = try node.exec(sql);
    }
    try testing.expectEqual(@as(i64, 2075), try countItems(node));
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

test "application SQL cannot break the replication contract" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    _ = try node.exec("create table items(id integer primary key, v text)");

    // Transaction control, attachment, reserved metadata, and capture
    // pragmas are denied through the public write surface without leaving
    // side effects; ordinary SQL keeps working afterwards.
    const denied = [_][:0]const u8{
        "commit",
        "rollback",
        "savepoint s1",
        "attach database ':memory:' as extra",
        "insert into __zaxon_meta values ('k', 'v')",
        "delete from __zaxon_sessions",
        "drop table __zaxon_meta",
        "pragma wal_autocheckpoint = 100",
        "pragma wal_checkpoint",
        "pragma journal_mode = delete",
        "insert into items(v) values ('a'); commit",
    };
    for (denied) |sql| {
        try testing.expectError(error.SqliteError, node.exec(sql));
    }
    try testing.expectEqual(@as(i64, 0), try countItems(node));

    // Read queries observe the same boundary.
    try testing.expectError(
        error.SqliteError,
        node.query(gpa, "select * from __zaxon_meta"),
    );

    _ = try node.exec("insert into items(v) values ('tea')");
    try testing.expectEqual(@as(i64, 1), try countItems(node));

    // Sessions still work: their metadata writes are internal scope.
    const session = try node.openSession();
    _ = try node.execIdempotent(session, 1, "insert into items(v) values ('b')");
    try testing.expectEqual(@as(i64, 2), try countItems(node));

    const report = try node.integrityCheck();
    try testing.expect(report.ok());
}

const registry = zaxonlite.registry;

fn testRegistryRecords() [3]registry.NodeRecord {
    return .{
        registry.NodeRecord.init(1, .data_voter, "127.0.0.1:9901") catch unreachable,
        registry.NodeRecord.init(2, .data_voter, "127.0.0.1:9902") catch unreachable,
        registry.NodeRecord.init(3, .data_voter, "127.0.0.1:9903") catch unreachable,
    };
}

test "network bootstrap persists the decided registry and pins flags" {
    const gpa = testing.allocator;
    const io = testing.io;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);
    const voters = [_]u32{ 1, 2, 3 };
    const records = testRegistryRecords();

    var digest: [32]u8 = undefined;
    {
        const node = try Node.open(gpa, io, .{
            .directory = dir,
            .node_id = 1,
            .members = &voters,
            .database_id = 77,
            .registry_nodes = &records,
        });
        defer node.close();
        const decided = node.decidedRegistry().?;
        try testing.expectEqual(@as(u64, 1), decided.configuration_id);
        try testing.expectEqual(@as(u128, 77), decided.database_id);
        try testing.expectEqual(@as(u32, 3), decided.highest_allocated_node_id);
        digest = decided.digest();
    }
    try test_dir.tmp.dir.access(io, "node/REGISTRY", .{});
    try test_dir.tmp.dir.access(io, "node/registries/0000000000000001", .{});

    // Reopen with matching flags: the same decided registry loads.
    {
        const node = try Node.open(gpa, io, .{
            .directory = dir,
            .node_id = 1,
            .members = &voters,
            .database_id = 77,
            .registry_nodes = &records,
        });
        defer node.close();
        try testing.expectEqualSlices(
            u8,
            &digest,
            &node.decidedRegistry().?.digest(),
        );
    }

    // Once the registry exists, the database identity comes from it: a
    // conflicting derived flag is ignored, never re-derived.
    {
        const node = try Node.open(gpa, io, .{
            .directory = dir,
            .node_id = 1,
            .members = &voters,
            .database_id = 88,
            .registry_nodes = &records,
        });
        defer node.close();
        try testing.expectEqual(
            @as(u128, 77),
            node.decidedRegistry().?.database_id,
        );
    }

    // Once present, the durable registry also owns membership. Stale
    // bootstrap flags cannot prevent crash recovery or alter its digest.
    var moved = records;
    moved[2] = registry.NodeRecord.init(3, .data_voter, "127.0.0.1:9999") catch
        unreachable;
    for ([_][]const registry.NodeRecord{ &moved, records[0..2] }) |stale| {
        const node = try Node.open(gpa, io, .{
            .directory = dir,
            .node_id = 1,
            .members = &voters,
            .database_id = 77,
            .registry_nodes = stale,
        });
        defer node.close();
        try testing.expectEqualSlices(
            u8,
            &digest,
            &node.decidedRegistry().?.digest(),
        );
    }

    // Crash window: a missing pointer after the blob write re-runs the
    // idempotent bootstrap and converges to the same digest.
    try test_dir.tmp.dir.deleteFile(io, "node/REGISTRY");
    {
        const node = try Node.open(gpa, io, .{
            .directory = dir,
            .node_id = 1,
            .members = &voters,
            .database_id = 77,
            .registry_nodes = &records,
        });
        defer node.close();
        try testing.expectEqualSlices(
            u8,
            &digest,
            &node.decidedRegistry().?.digest(),
        );
    }
    try test_dir.tmp.dir.access(io, "node/REGISTRY", .{});

    // A present but corrupt pointer fails closed instead of re-deriving.
    try test_dir.tmp.dir.writeFile(io, .{
        .sub_path = "node/REGISTRY",
        .data = "zz",
    });
    try testing.expectError(error.CorruptRegistryPointer, Node.open(gpa, io, .{
        .directory = dir,
        .node_id = 1,
        .members = &voters,
        .database_id = 77,
        .registry_nodes = &records,
    }));
}

test "embedded and local nodes write no registry" {
    const gpa = testing.allocator;
    const io = testing.io;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    const node = try openNode(dir);
    defer node.close();
    try testing.expect(node.decidedRegistry() == null);
    try testing.expectError(
        error.FileNotFound,
        test_dir.tmp.dir.access(io, "node/REGISTRY", .{}),
    );
}

test "flag membership is canonicalized to ascending node ids" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    // Checkpoint proofs and the decided registry encode voter sets in
    // ascending order; flag order must not decide whether rollover works.
    const node = try Node.open(gpa, testing.io, .{
        .directory = dir,
        .node_id = 2,
        .members = &.{ 3, 1, 2 },
        .database_id = 42,
    });
    defer node.close();
    try testing.expectEqualSlices(u32, &.{ 1, 2, 3 }, node.memberIds());
}

fn openRegistryNode(dir: []const u8) !*Node {
    const records = [_]registry.NodeRecord{
        registry.NodeRecord.init(1, .data_voter, "127.0.0.1:9901") catch unreachable,
    };
    return Node.open(testing.allocator, testing.io, .{
        .directory = dir,
        .node_id = 1,
        .members = &.{1},
        .database_id = 42,
        .registry_nodes = &records,
    });
}

test "snapshot rollover advances the decided registry with the epoch" {
    const gpa = testing.allocator;
    const io = testing.io;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    {
        const node = try openRegistryNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        _ = try node.exec("insert into items(v) values ('epoch one')");
        try node.snapshot();
        try testing.expectEqual(@as(u64, 2), node.identity.configuration_id);
        const decided = node.decidedRegistry().?;
        try testing.expectEqual(@as(u64, 2), decided.configuration_id);
        try testing.expectEqual(@as(u64, 1), decided.predecessor_configuration_id);
        try testing.expectEqual(@as(u128, 42), decided.database_id);
    }
    {
        const pointer = try test_dir.tmp.dir.readFileAlloc(
            io,
            "node/REGISTRY",
            gpa,
            .limited(64),
        );
        defer gpa.free(pointer);
        try testing.expectEqualStrings("0000000000000002", pointer);
    }

    // A second rollover retires the oldest registry blob, mirroring
    // snapshot retention: the pointer target plus one fallback remain.
    {
        const node = try openRegistryNode(dir);
        defer node.close();
        try testing.expectEqual(@as(u64, 2), node.decidedRegistry().?.configuration_id);
        _ = try node.exec("insert into items(v) values ('epoch two')");
        try node.snapshot();
        try testing.expectEqual(@as(u64, 3), node.decidedRegistry().?.configuration_id);
        try testing.expectEqual(@as(i64, 2), try countItems(node));
    }
    try test_dir.tmp.dir.access(io, "node/registries/0000000000000002", .{});
    try test_dir.tmp.dir.access(io, "node/registries/0000000000000003", .{});
    try testing.expectError(
        error.FileNotFound,
        test_dir.tmp.dir.access(io, "node/registries/0000000000000001", .{}),
    );
}

test "recovery completes registry rollover after CURRENT advances" {
    const gpa = testing.allocator;
    const io = testing.io;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    var database_id: u128 = 0;
    {
        const node = try openRegistryNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        _ = try node.exec("insert into items(v) values ('durable')");
        database_id = node.identity.database_id;
        try node.snapshot();
        try testing.expectEqual(@as(u64, 2), node.identity.configuration_id);
    }

    // Recreate the crash window after CURRENT was installed but before the
    // REGISTRY pointer and identity advanced: both still name epoch 1 and
    // the next-epoch journal does not exist yet.
    var node_dir = try std.Io.Dir.cwd().openDir(testing.io, dir, .{});
    defer node_dir.close(testing.io);
    var identity_buffer: [256]u8 = undefined;
    const identity = std.fmt.bufPrint(
        &identity_buffer,
        "format=2\nnode_id=1\ndatabase_id={x:0>32}\nconfiguration_id=1\nrole=data-voter\n",
        .{database_id},
    ) catch unreachable;
    {
        const file = try node_dir.createFile(testing.io, "identity", .{
            .read = true,
            .truncate = true,
        });
        try file.writePositionalAll(testing.io, identity, 0);
        try file.sync(testing.io);
        file.close(testing.io);
    }
    try node_dir.writeFile(io, .{
        .sub_path = "REGISTRY",
        .data = "0000000000000001",
    });
    try node_dir.deleteFile(testing.io, "paxos-0000000000000002.log");

    const reopened = try openRegistryNode(dir);
    defer reopened.close();
    try testing.expectEqual(@as(u64, 2), reopened.identity.configuration_id);
    try testing.expectEqual(@as(u64, 2), reopened.decidedRegistry().?.configuration_id);
    try testing.expectEqual(@as(i64, 1), try countItems(reopened));
    const pointer = try node_dir.readFileAlloc(io, "REGISTRY", gpa, .limited(64));
    defer gpa.free(pointer);
    try testing.expectEqualStrings("0000000000000002", pointer);
}

test "recovery completes registry rollover after the pointer advances" {
    const gpa = testing.allocator;
    var test_dir = try TestDir.init(gpa);
    defer test_dir.deinit(gpa);
    const dir = try test_dir.nodeDir(gpa);
    defer gpa.free(dir);

    var database_id: u128 = 0;
    {
        const node = try openRegistryNode(dir);
        defer node.close();
        _ = try node.exec("create table items(id integer primary key, v text)");
        _ = try node.exec("insert into items(v) values ('durable')");
        database_id = node.identity.database_id;
        try node.snapshot();
    }

    // The crash window one step later than the previous test: CURRENT and
    // REGISTRY both advanced, the identity file did not. Recovery must use
    // the pointer's configuration, never fall back to the old registry.
    var node_dir = try std.Io.Dir.cwd().openDir(testing.io, dir, .{});
    defer node_dir.close(testing.io);
    var identity_buffer: [256]u8 = undefined;
    const identity = std.fmt.bufPrint(
        &identity_buffer,
        "format=2\nnode_id=1\ndatabase_id={x:0>32}\nconfiguration_id=1\nrole=data-voter\n",
        .{database_id},
    ) catch unreachable;
    {
        const file = try node_dir.createFile(testing.io, "identity", .{
            .read = true,
            .truncate = true,
        });
        try file.writePositionalAll(testing.io, identity, 0);
        try file.sync(testing.io);
        file.close(testing.io);
    }
    try node_dir.deleteFile(testing.io, "paxos-0000000000000002.log");

    const reopened = try openRegistryNode(dir);
    defer reopened.close();
    try testing.expectEqual(@as(u64, 2), reopened.identity.configuration_id);
    try testing.expectEqual(@as(u64, 2), reopened.decidedRegistry().?.configuration_id);
    try testing.expectEqual(@as(i64, 1), try countItems(reopened));
}
