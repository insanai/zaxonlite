//! The zaxon CLI contract test.
//!
//! Drives the real binary end to end and asserts the documented contract:
//! exit codes, JSON output shape, session retry semantics, the interactive
//! shell in script mode, directory locking, and offline client-mode
//! failure. Runs against a scratch directory and cleans up after itself.
//!
//! Usage: cli-test <path-to-zaxon>

const std = @import("std");
const Io = std.Io;
const zaxonlite = @import("zaxonlite");

var zaxon_path: []const u8 = undefined;
var scratch_root: []const u8 = undefined;
var failures: usize = 0;

const RunResult = struct {
    code: u8,
    stdout: []u8,
    stderr: []u8,

    fn deinit(self: *RunResult, gpa: std.mem.Allocator) void {
        gpa.free(self.stdout);
        gpa.free(self.stderr);
    }
};

fn runCli(
    gpa: std.mem.Allocator,
    io: Io,
    arguments: []const []const u8,
    stdin_text: ?[]const u8,
) !RunResult {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.append(gpa, zaxon_path);
    try argv.appendSlice(gpa, arguments);

    var child = try std.process.spawn(io, .{
        .argv = argv.items,
        .stdin = if (stdin_text != null) .pipe else .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    if (stdin_text) |text| {
        const stdin = child.stdin.?;
        var write_buffer: [4096]u8 = undefined;
        var writer = stdin.writerStreaming(io, &write_buffer);
        writer.interface.writeAll(text) catch {};
        writer.interface.flush() catch {};
        stdin.close(io);
        child.stdin = null;
    }

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_reader = child.stdout.?.readerStreaming(io, &stdout_buffer);
    const stdout = try stdout_reader.interface.allocRemaining(gpa, .limited(1 << 22));
    errdefer gpa.free(stdout);
    var stderr_buffer: [4096]u8 = undefined;
    var stderr_reader = child.stderr.?.readerStreaming(io, &stderr_buffer);
    const stderr = try stderr_reader.interface.allocRemaining(gpa, .limited(1 << 22));
    errdefer gpa.free(stderr);

    const term = try child.wait(io);
    const code: u8 = switch (term) {
        .exited => |value| value,
        else => 255,
    };
    return .{ .code = code, .stdout = stdout, .stderr = stderr };
}

fn check(
    condition: bool,
    name: []const u8,
    result: *const RunResult,
) void {
    if (condition) {
        std.debug.print("ok   {s}\n", .{name});
    } else {
        failures += 1;
        std.debug.print(
            "FAIL {s}\n  code={d}\n  stdout: {s}\n  stderr: {s}\n",
            .{ name, result.code, result.stdout, result.stderr },
        );
    }
}

fn expect(
    gpa: std.mem.Allocator,
    io: Io,
    name: []const u8,
    arguments: []const []const u8,
    stdin_text: ?[]const u8,
    expected_code: u8,
    stdout_contains: ?[]const u8,
    stderr_contains: ?[]const u8,
) !void {
    var result = try runCli(gpa, io, arguments, stdin_text);
    defer result.deinit(gpa);
    var ok = result.code == expected_code;
    if (stdout_contains) |needle| {
        ok = ok and std.mem.indexOf(u8, result.stdout, needle) != null;
    }
    if (stderr_contains) |needle| {
        ok = ok and std.mem.indexOf(u8, result.stderr, needle) != null;
    }
    check(ok, name, &result);
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;

    var iterator = std.process.Args.Iterator.init(init.minimal.args);
    defer iterator.deinit();
    _ = iterator.next();
    zaxon_path = iterator.next() orelse {
        std.debug.print("usage: cli-test <path-to-zaxon>\n", .{});
        return 2;
    };

    var random_bytes: [8]u8 = undefined;
    io.random(&random_bytes);
    const nonce = std.mem.readInt(u64, &random_bytes, .little);
    const root = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/zx-cli-{x}", .{nonce});
    defer gpa.free(root);
    scratch_root = root;
    try Io.Dir.cwd().createDirPath(io, root);
    defer Io.Dir.cwd().deleteTree(io, root) catch {};

    const data = try std.fmt.allocPrint(gpa, "{s}/node", .{root});
    defer gpa.free(data);
    const backup_path = try std.fmt.allocPrint(gpa, "{s}/backup.db", .{root});
    defer gpa.free(backup_path);
    const config_path = try std.fmt.allocPrint(gpa, "{s}/config.json", .{root});
    defer gpa.free(config_path);
    const config_json = try std.fmt.allocPrint(
        gpa,
        "{{\"data\":\"{s}\"}}",
        .{data},
    );
    defer gpa.free(config_json);
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = config_path,
        .data = config_json,
    });

    // --- usage and version -------------------------------------------
    try expect(gpa, io, "no arguments prints usage, exit 2", &.{}, null, 2, "Usage:", null);
    try expect(gpa, io, "version exits 0", &.{"version"}, null, 0, "zaxon ", null);
    try expect(gpa, io, "help exits 0", &.{"help"}, null, 0, "Commands:", null);
    try expect(
        gpa,
        io,
        "unknown option exits 2",
        &.{ "status", "--data", data, "--bogus" },
        null,
        2,
        null,
        "-- UNKNOWN OPTION --",
    );
    try expect(
        gpa,
        io,
        "exec without sql exits 2",
        &.{ "exec", "--data", data },
        null,
        2,
        null,
        "exec needs --sql",
    );

    // --- embedded write/read path ------------------------------------
    try expect(
        gpa,
        io,
        "create table",
        &.{ "exec", "--data", data, "--sql", "create table t(a integer primary key, b text)" },
        null,
        0,
        "0 row(s) changed",
        null,
    );
    try expect(
        gpa,
        io,
        "config file supplies data directory",
        &.{ "status", "--config", config_path, "--json" },
        null,
        0,
        "\"node_id\":1",
        null,
    );
    try expect(
        gpa,
        io,
        "CLI overrides config file",
        &.{ "status", "--config", config_path, "--data", data, "--json" },
        null,
        0,
        "\"node_id\":1",
        null,
    );
    try expect(
        gpa,
        io,
        "insert rows",
        &.{ "exec", "--data", data, "--sql", "insert into t(b) values ('x'),('y')" },
        null,
        0,
        "2 row(s) changed",
        null,
    );
    try expect(
        gpa,
        io,
        "query json shape",
        &.{ "query", "--data", data, "--sql", "select * from t order by a", "--json" },
        null,
        0,
        "{\"columns\":[\"a\",\"b\"],\"rows\":[[\"1\",\"x\"],[\"2\",\"y\"]]}",
        null,
    );
    try expect(
        gpa,
        io,
        "write statement via query exits 1",
        &.{ "query", "--data", data, "--sql", "insert into t(b) values ('nope')" },
        null,
        1,
        null,
        "not read-only",
    );
    try expect(
        gpa,
        io,
        "sql error exits 1 with message",
        &.{ "exec", "--data", data, "--sql", "insert into missing values (1)" },
        null,
        1,
        null,
        "no such table",
    );

    // --- sessions ------------------------------------------------------
    try expect(
        gpa,
        io,
        "open session",
        &.{ "session", "--data", data },
        null,
        0,
        "session 1",
        null,
    );
    try expect(
        gpa,
        io,
        "idempotent exec",
        &.{
            "exec",      "--data", data,
            "--session", "1",      "--sequence",
            "1",         "--sql",  "insert into t(b) values ('z')",
        },
        null,
        0,
        "1 row(s) changed",
        null,
    );
    try expect(
        gpa,
        io,
        "duplicate sequence replays recorded result",
        &.{
            "exec",      "--data", data,
            "--session", "1",      "--sequence",
            "1",         "--sql",  "insert into t(b) values ('z')",
        },
        null,
        0,
        "replayed",
        null,
    );
    try expect(
        gpa,
        io,
        "sequence gap exits 1",
        &.{
            "exec",      "--data", data,
            "--session", "1",      "--sequence",
            "9",         "--sql",  "insert into t(b) values ('gap')",
        },
        null,
        1,
        null,
        "SequenceGap",
    );
    try expect(
        gpa,
        io,
        "unknown session exits 1",
        &.{
            "exec",      "--data", data,
            "--session", "77",     "--sequence",
            "1",         "--sql",  "insert into t(b) values ('s')",
        },
        null,
        1,
        null,
        "UnknownSession",
    );

    // --- status, snapshot, backup, integrity ---------------------------
    try expect(
        gpa,
        io,
        "status json parses",
        &.{ "status", "--data", data, "--json" },
        null,
        0,
        "\"role\":\"leader\"",
        null,
    );
    try expect(
        gpa,
        io,
        "snapshot seals the epoch",
        &.{ "snapshot", "--data", data },
        null,
        0,
        "snapshot installed",
        null,
    );
    try expect(
        gpa,
        io,
        "backup writes a file",
        &.{ "backup", "--data", data, "--to", backup_path },
        null,
        0,
        "backup written",
        null,
    );
    {
        Io.Dir.cwd().access(io, backup_path, .{}) catch {
            failures += 1;
            std.debug.print("FAIL backup file exists\n", .{});
        };
    }
    try expect(
        gpa,
        io,
        "integrity-check passes",
        &.{ "integrity-check", "--data", data },
        null,
        0,
        "sqlite: pass",
        null,
    );
    try expect(
        gpa,
        io,
        "recover rebuilds and verifies",
        &.{ "recover", "--data", data },
        null,
        0,
        "recovery rebuild complete",
        null,
    );
    try expect(
        gpa,
        io,
        "members reports static membership",
        &.{ "members", "--data", data, "--json" },
        null,
        0,
        "\"membership\":\"static\"",
        null,
    );
    try expect(
        gpa,
        io,
        "expire-sessions runs",
        &.{ "expire-sessions", "--data", data, "--retain", "1000" },
        null,
        0,
        "session(s) expired",
        null,
    );

    // --- interactive shell in script mode ------------------------------
    try expect(
        gpa,
        io,
        "shell executes scripted statements",
        &.{ "sql", "--data", data },
        "insert into t(b) values ('shell');\nselect count(*) from t;\n.quit\n",
        0,
        "count(*)",
        null,
    );

    // --- locking --------------------------------------------------------
    {
        const node = try zaxonlite.Node.open(gpa, io, .{ .directory = data });
        defer node.close();
        try expect(
            gpa,
            io,
            "locked directory exits 4",
            &.{ "status", "--data", data },
            null,
            4,
            null,
            "-- NODE DIRECTORY LOCKED --",
        );
    }

    // --- offline client mode ---------------------------------------------
    try expect(
        gpa,
        io,
        "client mode with no server exits 4",
        &.{ "status", "--connect", "127.0.0.1:9", "--json" },
        null,
        4,
        null,
        "-- NO REACHABLE LEADER --",
    );

    if (failures == 0) {
        std.debug.print("cli contract test: all checks passed\n", .{});
        return 0;
    }
    std.debug.print("cli contract test: {d} failure(s)\n", .{failures});
    return 1;
}
