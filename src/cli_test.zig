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

/// Creates `<dir>/<name>.key` and `<dir>/<name>.crt` with the given
/// common name; self-signed when `signer` is null, otherwise signed by
/// the previously generated `<dir>/<signer>.{key,crt}`.
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

    // --- unix-domain socket service --------------------------------------
    {
        const unix_data = try std.fmt.allocPrint(gpa, "{s}/unix-node", .{root});
        defer gpa.free(unix_data);
        const socket_path = try std.fmt.allocPrint(gpa, "{s}/zaxon.sock", .{root});
        defer gpa.free(socket_path);
        const unix_endpoint = try std.fmt.allocPrint(gpa, "unix:{s}", .{socket_path});
        defer gpa.free(unix_endpoint);

        try expect(
            gpa,
            io,
            "unix listener refuses peers",
            &.{
                "serve",       "--data", unix_data,
                "--node",      "1",      "--listen",
                unix_endpoint, "--peer", "2@127.0.0.1:9902",
            },
            null,
            2,
            null,
            "single-node",
        );

        var serve_child = try std.process.spawn(io, .{
            .argv = &.{
                zaxon_path, "serve",
                "--data",   unix_data,
                "--node",   "1",
                "--listen", unix_endpoint,
            },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        var socket_ready = false;
        var waited: usize = 0;
        while (waited < 200) : (waited += 1) {
            if (Io.Dir.cwd().access(io, socket_path, .{})) |_| {
                socket_ready = true;
                break;
            } else |_| {}
            io.sleep(.fromMilliseconds(25), .awake) catch {};
        }
        if (!socket_ready) {
            failures += 1;
            std.debug.print("FAIL unix socket never appeared\n", .{});
        }

        // Owner-only permissions are applied before serving.
        if (Io.Dir.cwd().statFile(io, socket_path, .{})) |stat| {
            const mode = @intFromEnum(stat.permissions) & 0o777;
            if (mode != 0o600) {
                failures += 1;
                std.debug.print("FAIL unix socket mode {o} != 600\n", .{mode});
            } else {
                std.debug.print("ok   unix socket is owner-only\n", .{});
            }
        } else |err| {
            failures += 1;
            std.debug.print(
                "FAIL unix socket stat: {s}\n",
                .{@errorName(err)},
            );
        }

        try expect(
            gpa,
            io,
            "status over unix socket",
            &.{ "status", "--connect", unix_endpoint, "--json" },
            null,
            0,
            "\"node_id\":1",
            null,
        );
        try expect(
            gpa,
            io,
            "exec over unix socket",
            &.{
                "exec",  "--connect",                             unix_endpoint,
                "--sql", "create table u(a integer primary key)",
            },
            null,
            0,
            "0 row(s) changed",
            null,
        );

        // A second server must refuse the live socket path instead of
        // silently taking it over.
        const second_data = try std.fmt.allocPrint(gpa, "{s}/unix-node2", .{root});
        defer gpa.free(second_data);
        try expect(
            gpa,
            io,
            "existing socket path is refused",
            &.{
                "serve",       "--data", second_data,
                "--node",      "1",      "--listen",
                unix_endpoint,
            },
            null,
            4,
            null,
            "UNIX SOCKET LISTEN FAILED",
        );

        try expect(
            gpa,
            io,
            "stop over unix socket",
            &.{ "stop", "--connect", unix_endpoint },
            null,
            0,
            null,
            null,
        );
        _ = try serve_child.wait(io);

        // Orderly shutdown removes the socket path.
        if (Io.Dir.cwd().access(io, socket_path, .{})) |_| {
            failures += 1;
            std.debug.print("FAIL unix socket not removed on shutdown\n", .{});
        } else |_| {
            std.debug.print("ok   unix socket removed on shutdown\n", .{});
        }
    }

    // --- mutual TLS service ----------------------------------------------
    {
        const tls_root = try std.fmt.allocPrint(gpa, "{s}/tls", .{root});
        defer gpa.free(tls_root);
        try Io.Dir.cwd().createDirPath(io, tls_root);
        try generateTlsIdentity(gpa, io, tls_root, "ca", null, "zaxon-test-ca");
        try generateTlsIdentity(gpa, io, tls_root, "n1", "ca", "zaxon-node-1");
        try generateTlsIdentity(gpa, io, tls_root, "client", "ca", "zaxon-client");
        // A second CA whose certificates the cluster must refuse.
        try generateTlsIdentity(gpa, io, tls_root, "ca2", null, "other-ca");
        try generateTlsIdentity(gpa, io, tls_root, "rogue", "ca2", "zaxon-node-1");

        const tls_data = try std.fmt.allocPrint(gpa, "{s}/tls-node", .{root});
        defer gpa.free(tls_data);
        const port: u16 = @intCast(20000 + nonce % 20000);
        const listen = try std.fmt.allocPrint(gpa, "127.0.0.1:{d}", .{port});
        defer gpa.free(listen);
        const ca = try std.fmt.allocPrint(gpa, "{s}/ca.crt", .{tls_root});
        defer gpa.free(ca);
        const n1_cert = try std.fmt.allocPrint(gpa, "{s}/n1.crt", .{tls_root});
        defer gpa.free(n1_cert);
        const n1_key = try std.fmt.allocPrint(gpa, "{s}/n1.key", .{tls_root});
        defer gpa.free(n1_key);
        const client_cert = try std.fmt.allocPrint(gpa, "{s}/client.crt", .{tls_root});
        defer gpa.free(client_cert);
        const client_key = try std.fmt.allocPrint(gpa, "{s}/client.key", .{tls_root});
        defer gpa.free(client_key);
        const rogue_cert = try std.fmt.allocPrint(gpa, "{s}/rogue.crt", .{tls_root});
        defer gpa.free(rogue_cert);
        const rogue_key = try std.fmt.allocPrint(gpa, "{s}/rogue.key", .{tls_root});
        defer gpa.free(rogue_key);
        const ca2 = try std.fmt.allocPrint(gpa, "{s}/ca2.crt", .{tls_root});
        defer gpa.free(ca2);

        try expect(
            gpa,
            io,
            "partial tls flags exit 2",
            &.{ "status", "--connect", listen, "--tls-ca", ca },
            null,
            2,
            null,
            "given together",
        );

        var serve_child = try std.process.spawn(io, .{
            .argv = &.{
                zaxon_path,   "serve",
                "--data",     tls_data,
                "--node",     "1",
                "--listen",   listen,
                "--tls-cert", n1_cert,
                "--tls-key",  n1_key,
                "--tls-ca",   ca,
            },
            .stdin = .ignore,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        io.sleep(.fromMilliseconds(300), .awake) catch {};

        try expect(
            gpa,
            io,
            "status over mutual TLS",
            &.{
                "status",     "--connect", listen,
                "--tls-cert", client_cert, "--tls-key",
                client_key,   "--tls-ca",  ca,
                "--json",
            },
            null,
            0,
            "\"node_id\":1",
            null,
        );
        try expect(
            gpa,
            io,
            "exec over mutual TLS",
            &.{
                "exec",       "--connect",                                 listen,
                "--tls-cert", client_cert,                                 "--tls-key",
                client_key,   "--tls-ca",                                  ca,
                "--sql",      "create table tls_t(a integer primary key)",
            },
            null,
            0,
            "0 row(s) changed",
            null,
        );
        // A plaintext client cannot speak to a TLS listener.
        try expect(
            gpa,
            io,
            "plaintext client fails against TLS server",
            &.{ "status", "--connect", listen, "--json" },
            null,
            4,
            null,
            "-- NO REACHABLE LEADER --",
        );
        // A certificate from a foreign CA is refused even with the right name.
        try expect(
            gpa,
            io,
            "foreign-CA certificate is refused",
            &.{
                "status",     "--connect", listen,
                "--tls-cert", rogue_cert,  "--tls-key",
                rogue_key,    "--tls-ca",  ca,
                "--json",
            },
            null,
            4,
            null,
            "-- NO REACHABLE LEADER --",
        );

        try expect(
            gpa,
            io,
            "stop over mutual TLS",
            &.{
                "stop",       "--connect", listen,
                "--tls-cert", client_cert, "--tls-key",
                client_key,   "--tls-ca",  ca,
            },
            null,
            0,
            null,
            null,
        );
        _ = try serve_child.wait(io);
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
