//! Abrupt one-process crash matrix for the durable host ordering contract.
//!
//! Every case starts from a committed baseline, spawns the real CLI with one
//! exact failpoint, observes `_exit` without cleanup, then reopens through the
//! library and checks integrity. Unknown client fate permits either absence or
//! durable completion at the early boundaries; once the accept prefix is synced
//! in a one-voter configuration, recovery must complete the value. The legacy
//! commit-named failpoint now denotes chosen-before-materialized-apply.

const std = @import("std");
const zaxonlite = @import("zaxonlite");

const Case = struct {
    failpoint: []const u8,
    minimum_count: i64,
    maximum_count: i64,
};

const cases = [_]Case{
    .{ .failpoint = "before_payload_sync", .minimum_count = 0, .maximum_count = 0 },
    .{ .failpoint = "after_payload_sync", .minimum_count = 0, .maximum_count = 0 },
    // Process death does not emulate power loss: an unsynced append may still
    // reach disk. Both outcomes are safe because the client saw no success.
    .{ .failpoint = "after_accept_append", .minimum_count = 0, .maximum_count = 1 },
    .{ .failpoint = "after_accept_sync", .minimum_count = 1, .maximum_count = 1 },
    .{
        .failpoint = "after_commit_sync_before_apply",
        .minimum_count = 1,
        .maximum_count = 1,
    },
};

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;
    var arguments = std.process.Args.Iterator.init(init.minimal.args);
    defer arguments.deinit();
    _ = arguments.next();
    const zaxon = arguments.next() orelse {
        std.debug.print("usage: crash-test <zaxon>\n", .{});
        return 2;
    };

    var random_bytes: [8]u8 = undefined;
    io.random(&random_bytes);
    const nonce = std.mem.readInt(u64, &random_bytes, .little);
    const root = try std.fmt.allocPrint(
        gpa,
        ".zig-cache/tmp/zx-crash-{x}",
        .{nonce},
    );
    defer gpa.free(root);
    try std.Io.Dir.cwd().createDirPath(io, root);
    defer std.Io.Dir.cwd().deleteTree(io, root) catch {};

    for (cases, 0..) |case, index| {
        try runCase(gpa, io, zaxon, root, case, index);
        std.debug.print("ok   crash at {s}\n", .{case.failpoint});
    }
    std.debug.print("crash matrix: all {d} cases passed\n", .{cases.len});
    return 0;
}

fn runCase(
    gpa: std.mem.Allocator,
    io: std.Io,
    zaxon: []const u8,
    root: []const u8,
    case: Case,
    index: usize,
) !void {
    const directory = try std.fmt.allocPrint(gpa, "{s}/case-{d}", .{ root, index });
    defer gpa.free(directory);
    {
        const node = try zaxonlite.Node.open(gpa, io, .{ .directory = directory });
        defer node.close();
        _ = try node.exec("create table t(id integer primary key, v text)");
    }

    const assignment = try std.fmt.allocPrint(
        gpa,
        "ZAXON_FAILPOINT={s}",
        .{case.failpoint},
    );
    defer gpa.free(assignment);
    const argv = [_][]const u8{
        "/usr/bin/env",
        assignment,
        zaxon,
        "exec",
        "--data",
        directory,
        "--sql",
        "insert into t(v) values ('crash')",
        // Process-kill recovery is identical under both sync policies.
        "--sync",
        "os",
    };
    var child = try std.process.spawn(io, .{
        .argv = &argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const termination = try child.wait(io);
    const code = switch (termination) {
        .exited => |value| value,
        else => 0,
    };
    if (code != 137) return error.FailpointDidNotCrash;

    const recovered = try zaxonlite.Node.open(gpa, io, .{ .directory = directory });
    defer recovered.close();
    var result = try recovered.query(gpa, "select count(*) from t");
    defer result.deinit();
    const count = try std.fmt.parseInt(i64, result.rows[0][0].?, 10);
    if (count < case.minimum_count or count > case.maximum_count) {
        return error.UnexpectedRecoveredCount;
    }
    const report = try recovered.integrityCheck();
    if (!report.ok()) return error.IntegrityFailure;
}
