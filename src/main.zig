//! zaxon: the zaxonlite command line.
//!
//! Two modes share one command surface:
//! * embedded (`--data <dir>`): the command opens the node in-process,
//!   exactly as an embedding application would;
//! * client (`--connect host:port[,host:port...]`): the command speaks the
//!   RPC protocol to running `zaxon serve` processes, following leader
//!   redirects.
//!
//! `zaxon serve` hosts one role-aware node behind a TCP endpoint, alone or in
//! a runtime-sized cluster registry.

const std = @import("std");
const zaxonlite = @import("zaxonlite");

const Node = zaxonlite.Node;
const server = zaxonlite.server;
const client = zaxonlite.client;
const gateway = zaxonlite.gateway;
const configuration = zaxonlite.configuration;
const diagnostic = zaxonlite.diagnostic;
const tls = zaxonlite.tls;
const enrollment = zaxonlite.enrollment;
const Role = zaxonlite.Role;

const exit_ok: u8 = 0;
const exit_sql: u8 = 1;
const exit_usage: u8 = 2;
const exit_integrity: u8 = 3;
const exit_unavailable: u8 = 4;

const usage_text =
    \\zaxon — embedded replicated SQLite (zaxonlite)
    \\
    \\Usage:
    \\  zaxon <command> --data <dir> [options]          embedded mode
    \\  zaxon <command> --connect host:port[,...]       client mode
    \\  zaxon serve --data <dir> --node <id> --listen <endpoint>
    \\        [--role <role>] [--peer <id>@host:port[/role] ...]
    \\        [--cluster-id <text>]
    \\        [--auth-file <path>] [--dev-psk] [--enable-failpoints]
    \\
    \\Commands:
    \\  sql               Interactive SQL shell (embedded or client mode).
    \\  exec              Execute SQL; --session/--sequence for idempotent retry.
    \\  query             Read query. --level any|leader|linearizable.
    \\  session           Open a client session and print its ID.
    \\  status            Show node status. --json for automation.
    \\  members           Show cluster membership and node roles.
    \\  leader            Show the current leader (client mode).
    \\  wait              Wait for --applied <slot> and/or --leader (client mode).
    \\  snapshot          Take a snapshot and seal the current journal epoch.
    \\  backup            Stream a consistent logical backup. --to <path>.
    \\  integrity-check   Verify SQLite image, descriptor chain, and payloads.
    \\  recover           Rebuild from authoritative state and verify it.
    \\  expire-sessions   Delete idle sessions; --retain <n> newest activity.
    \\  enroll-token      Create a short-lived token bundle for --node (client mode).
    \\  enroll            Redeem --token-file into an atomic --identity-dir.
    \\  serve             Host this node behind a TCP endpoint.
    \\  stop              Ask a served node to shut down (client mode).
    \\  version           Print the zaxonlite version.
    \\
    \\Options:
    \\  --config <path>     JSON config; or ZAXON_CONFIG.
    \\  --data <dir>        Node data directory (created when missing).
    \\  --connect <list>    Comma-separated endpoints (host:port or unix:<path>).
    \\  --sql <text>        SQL for exec/query.
    \\  --session <id>      Session ID for exec.
    \\  --sequence <n>      Monotonic per-session sequence for exec.
    \\  --level <level>     Read level for query (default linearizable).
    \\  --freshness-ms <n>  Maximum age for a local learner read.
    \\  --to <path>         Backup or enrollment-token destination path.
    \\  --retain <n>        Activity window for expire-sessions.
    \\  --applied <slot>    Slot to wait for (wait).
    \\  --leader            Also wait for a known leader (wait).
    \\  --timeout-ms <n>    Wait deadline in milliseconds.
    \\  --node <id>         This node's ID (serve) or enrollment target.
    \\  --listen <endpoint> host:port, or unix:<path> for owner-only local
    \\                      service over a Unix-domain socket (serve).
    \\  --role <role>       data-voter|witness|standby|read-replica|gateway.
    \\  --peer <spec>       id@host:port[/role] (repeat; serve).
    \\  --cluster-id <text> Extra entropy for the derived database identity.
    \\  --auth-file <path>  PSK provider; or ZAXON_AUTH_FILE. Never a literal key.
    \\  --dev-psk           Loopback-only PSK transport for local development.
    \\  --tls-cert <path>   Node certificate PEM (mutual TLS; needs all three).
    \\  --tls-key <path>    Node private key PEM.
    \\  --tls-ca <path>     Cluster CA PEM that peer certificates chain to.
    \\  --enrollment-ca-key <path>
    \\                      CA private key PEM; enables token/CSR issuance on serve.
    \\  --token-file <path> Opaque owner-only enrollment bundle (enroll).
    \\  --identity-dir <dir> New directory receiving node.key/node.crt/ca.crt.
    \\  --ttl-seconds <n>   Enrollment token lifetime (default 600, maximum 86400).
    \\  --revocation-file <path>
    \\                      Reloaded node-ID denylist (serve).
    \\  --sync <mode>       full (default; F_FULLFSYNC on macOS, survives power
    \\                      loss) or os (plain fsync; faster, development only).
    \\  --enable-failpoints Honor failpoint RPCs (test controllers only).
    \\  --json              Machine-readable output on stdout.
    \\
    \\Exit codes: 0 ok, 1 SQL/session error, 2 usage, 3 integrity failure,
    \\4 node unavailable (locked, corrupt, or no leader).
    \\
;

const Options = struct {
    command: []const u8,
    config: ?[]const u8 = null,
    data: ?[]const u8 = null,
    connect: ?[]const u8 = null,
    sql: ?[:0]const u8 = null,
    session: ?u64 = null,
    sequence: ?u64 = null,
    level: ?[]const u8 = null,
    freshness_ms: ?u64 = null,
    to: ?[]const u8 = null,
    retain: ?u64 = null,
    applied: ?u64 = null,
    wait_leader: bool = false,
    timeout_ms: ?u64 = null,
    node_id: ?u32 = null,
    role: Role = .data_voter,
    role_set: bool = false,
    listen: ?[]const u8 = null,
    peers: std.ArrayList([]const u8) = .empty,
    cluster_id: ?[]const u8 = null,
    auth_file: ?[]const u8 = null,
    tls_cert: ?[]const u8 = null,
    tls_key: ?[]const u8 = null,
    tls_ca: ?[]const u8 = null,
    enrollment_ca_key: ?[]const u8 = null,
    token_file: ?[]const u8 = null,
    identity_dir: ?[]const u8 = null,
    ttl_seconds: ?u64 = null,
    revocation_file: ?[]const u8 = null,
    sync: ?[]const u8 = null,
    enable_failpoints: bool = false,
    dev_psk: bool = false,
    insecure_test_tcp: bool = false,
    json: bool = false,
};

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;

    var stdout_buffer: [16 * 1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writerStreaming(io, &stdout_buffer);
    const out = &stdout_writer.interface;
    var stderr_buffer: [4096]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writerStreaming(io, &stderr_buffer);
    const err_out = &stderr_writer.interface;

    const code = run(
        gpa,
        io,
        init.minimal.args,
        init.environ_map,
        out,
        err_out,
    ) catch |err| blk: {
        diagnostic.write(
            err_out,
            "command failed",
            @errorName(err),
            "Preserve the error and node logs before retrying.",
        ) catch {};
        break :blk exit_unavailable;
    };
    out.flush() catch {};
    err_out.flush() catch {};
    return code;
}

fn run(
    gpa: std.mem.Allocator,
    io: std.Io,
    args: std.process.Args,
    environ: *std.process.Environ.Map,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    var iterator = std.process.Args.Iterator.init(args);
    defer iterator.deinit();
    _ = iterator.next();

    const command = iterator.next() orelse {
        try out.writeAll(usage_text);
        return exit_usage;
    };
    var options = Options{ .command = command };
    defer options.peers.deinit(gpa);

    while (iterator.next()) |arg| {
        if (std.mem.eql(u8, arg, "--config")) {
            options.config = iterator.next() orelse
                return usageError(err_out, "--config needs a value");
        } else if (std.mem.eql(u8, arg, "--data")) {
            options.data = iterator.next() orelse return usageError(err_out, "--data needs a value");
        } else if (std.mem.eql(u8, arg, "--connect")) {
            options.connect = iterator.next() orelse return usageError(err_out, "--connect needs a value");
        } else if (std.mem.eql(u8, arg, "--sql")) {
            options.sql = iterator.next() orelse return usageError(err_out, "--sql needs a value");
        } else if (std.mem.eql(u8, arg, "--session")) {
            const text = iterator.next() orelse return usageError(err_out, "--session needs a value");
            options.session = std.fmt.parseInt(u64, text, 10) catch
                return usageError(err_out, "--session must be an integer");
        } else if (std.mem.eql(u8, arg, "--sequence")) {
            const text = iterator.next() orelse return usageError(err_out, "--sequence needs a value");
            options.sequence = std.fmt.parseInt(u64, text, 10) catch
                return usageError(err_out, "--sequence must be an integer");
        } else if (std.mem.eql(u8, arg, "--level")) {
            options.level = iterator.next() orelse return usageError(err_out, "--level needs a value");
        } else if (std.mem.eql(u8, arg, "--freshness-ms")) {
            const text = iterator.next() orelse
                return usageError(err_out, "--freshness-ms needs a value");
            options.freshness_ms = std.fmt.parseInt(u64, text, 10) catch
                return usageError(err_out, "--freshness-ms must be an integer");
        } else if (std.mem.eql(u8, arg, "--to")) {
            options.to = iterator.next() orelse return usageError(err_out, "--to needs a value");
        } else if (std.mem.eql(u8, arg, "--retain")) {
            const text = iterator.next() orelse return usageError(err_out, "--retain needs a value");
            options.retain = std.fmt.parseInt(u64, text, 10) catch
                return usageError(err_out, "--retain must be an integer");
        } else if (std.mem.eql(u8, arg, "--applied")) {
            const text = iterator.next() orelse return usageError(err_out, "--applied needs a value");
            options.applied = std.fmt.parseInt(u64, text, 10) catch
                return usageError(err_out, "--applied must be an integer");
        } else if (std.mem.eql(u8, arg, "--leader")) {
            options.wait_leader = true;
        } else if (std.mem.eql(u8, arg, "--timeout-ms")) {
            const text = iterator.next() orelse return usageError(err_out, "--timeout-ms needs a value");
            options.timeout_ms = std.fmt.parseInt(u64, text, 10) catch
                return usageError(err_out, "--timeout-ms must be an integer");
        } else if (std.mem.eql(u8, arg, "--node")) {
            const text = iterator.next() orelse return usageError(err_out, "--node needs a value");
            options.node_id = std.fmt.parseInt(u32, text, 10) catch
                return usageError(err_out, "--node must be an integer");
        } else if (std.mem.eql(u8, arg, "--listen")) {
            options.listen = iterator.next() orelse return usageError(err_out, "--listen needs a value");
        } else if (std.mem.eql(u8, arg, "--role")) {
            const text = iterator.next() orelse
                return usageError(err_out, "--role needs a value");
            options.role = Role.parse(text) catch
                return usageError(err_out, "--role is not a known node role");
            options.role_set = true;
        } else if (std.mem.eql(u8, arg, "--peer")) {
            const text = iterator.next() orelse return usageError(err_out, "--peer needs a value");
            try options.peers.append(gpa, text);
        } else if (std.mem.eql(u8, arg, "--cluster-id")) {
            options.cluster_id = iterator.next() orelse return usageError(err_out, "--cluster-id needs a value");
        } else if (std.mem.eql(u8, arg, "--auth-file")) {
            options.auth_file = iterator.next() orelse
                return usageError(err_out, "--auth-file needs a value");
        } else if (std.mem.eql(u8, arg, "--tls-cert")) {
            options.tls_cert = iterator.next() orelse
                return usageError(err_out, "--tls-cert needs a value");
        } else if (std.mem.eql(u8, arg, "--tls-key")) {
            options.tls_key = iterator.next() orelse
                return usageError(err_out, "--tls-key needs a value");
        } else if (std.mem.eql(u8, arg, "--tls-ca")) {
            options.tls_ca = iterator.next() orelse
                return usageError(err_out, "--tls-ca needs a value");
        } else if (std.mem.eql(u8, arg, "--enrollment-ca-key")) {
            options.enrollment_ca_key = iterator.next() orelse
                return usageError(err_out, "--enrollment-ca-key needs a value");
        } else if (std.mem.eql(u8, arg, "--token-file")) {
            options.token_file = iterator.next() orelse
                return usageError(err_out, "--token-file needs a value");
        } else if (std.mem.eql(u8, arg, "--identity-dir")) {
            options.identity_dir = iterator.next() orelse
                return usageError(err_out, "--identity-dir needs a value");
        } else if (std.mem.eql(u8, arg, "--ttl-seconds")) {
            const text = iterator.next() orelse
                return usageError(err_out, "--ttl-seconds needs a value");
            options.ttl_seconds = std.fmt.parseInt(u64, text, 10) catch
                return usageError(err_out, "--ttl-seconds must be an integer");
        } else if (std.mem.eql(u8, arg, "--revocation-file")) {
            options.revocation_file = iterator.next() orelse
                return usageError(err_out, "--revocation-file needs a value");
        } else if (std.mem.eql(u8, arg, "--sync")) {
            options.sync = iterator.next() orelse
                return usageError(err_out, "--sync needs a value");
        } else if (std.mem.eql(u8, arg, "--enable-failpoints")) {
            options.enable_failpoints = true;
        } else if (std.mem.eql(u8, arg, "--dev-psk")) {
            options.dev_psk = true;
        } else if (std.mem.eql(u8, arg, "--insecure-test-tcp")) {
            options.insecure_test_tcp = true;
        } else if (std.mem.eql(u8, arg, "--json")) {
            options.json = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try out.writeAll(usage_text);
            return exit_ok;
        } else {
            try diagnostic.write(
                err_out,
                "unknown option",
                arg,
                "Run 'zaxon help' and remove or correct this option.",
            );
            return exit_usage;
        }
    }

    if (std.mem.eql(u8, command, "version")) {
        try out.print("zaxon {s}\n", .{zaxonlite.version});
        return exit_ok;
    }
    if (std.mem.eql(u8, command, "help")) {
        try out.writeAll(usage_text);
        return exit_ok;
    }
    const config_path = options.config orelse environ.get("ZAXON_CONFIG");
    var loaded_config: ?configuration.Loaded = if (config_path) |path|
        configuration.loadFile(gpa, io, path) catch |err| {
            try diagnostic.write(
                err_out,
                "configuration unreadable",
                @errorName(err),
                "Check the provider path, permissions, and JSON fields.",
            );
            return exit_usage;
        }
    else
        null;
    defer if (loaded_config) |*loaded| loaded.deinit();
    const file_config = if (loaded_config) |*loaded| loaded.value() else null;
    applyConfiguration(gpa, environ, file_config, &options, err_out) catch
        return exit_usage;
    if (options.sync) |sync_text| {
        const mode = std.meta.stringToEnum(
            zaxonlite.durability.SyncMode,
            sync_text,
        ) orelse return usageError(err_out, "--sync must be os or full");
        zaxonlite.durability.setSyncMode(mode);
    }
    if (std.mem.eql(u8, command, "enroll")) {
        return enrollCommand(gpa, io, &options, out, err_out);
    }
    var secret: ?configuration.Secret = if (options.auth_file) |path|
        configuration.loadSecret(gpa, io, path) catch |err| {
            try diagnostic.write(
                err_out,
                "authentication provider unreadable",
                @errorName(err),
                "Use a readable provider file containing at least 32 bytes.",
            );
            return exit_usage;
        }
    else
        null;
    defer if (secret) |*value| value.deinit(gpa);
    const secret_bytes: ?[]const u8 = if (secret) |*value| value.bytes else null;
    const tls_config: ?tls.Config = blk: {
        const any = options.tls_cert != null or options.tls_key != null or
            options.tls_ca != null;
        if (!any) break :blk null;
        if (options.tls_cert == null or options.tls_key == null or
            options.tls_ca == null)
        {
            return usageError(
                err_out,
                "--tls-cert, --tls-key, and --tls-ca must be given together",
            );
        }
        break :blk .{
            .cert_path = options.tls_cert.?,
            .key_path = options.tls_key.?,
            .ca_path = options.tls_ca.?,
        };
    };
    if (std.mem.eql(u8, command, "serve")) {
        return serveCommand(gpa, io, &options, secret_bytes, tls_config, err_out);
    }
    if (options.connect != null) {
        // One client TLS identity serves every connection this command
        // makes, including redirect follow-ups.
        var tls_context: ?tls.Context = null;
        defer if (tls_context) |*context| context.deinit();
        if (tls_config) |config| {
            configuration.validatePrivateFile(io, config.key_path) catch |err| {
                try diagnostic.write(
                    err_out,
                    "unsafe TLS private key",
                    @errorName(err),
                    "Use a regular, non-symlink key file with mode 0600.",
                );
                return exit_usage;
            };
            tls_context = tls.Context.initClient(config) catch |err| {
                try diagnostic.write(
                    err_out,
                    "tls identity failed",
                    @errorName(err),
                    "Check that --tls-cert, --tls-key, and --tls-ca name " ++
                        "readable PEM files.",
                );
                return exit_usage;
            };
        }
        const transport = client.Transport{
            .secret = secret_bytes,
            .tls = if (tls_context) |*context| context else null,
        };
        return remote(gpa, io, &options, transport, out, err_out);
    }

    const data = options.data orelse
        return usageError(err_out, "--data <dir> or --connect is required");

    const node = Node.open(gpa, io, .{ .directory = data }) catch |err| switch (err) {
        error.NodeLocked => {
            try diagnostic.write(
                err_out,
                "node directory locked",
                "Another process owns this data directory.",
                "Stop that process or choose a different --data directory.",
            );
            return exit_unavailable;
        },
        else => {
            try diagnostic.write(
                err_out,
                "node open failed",
                @errorName(err),
                "Inspect identity, journal, payload, and filesystem diagnostics.",
            );
            return exit_unavailable;
        },
    };
    defer node.close();

    if (std.mem.eql(u8, command, "sql")) {
        return shell(gpa, io, node, out, err_out);
    } else if (std.mem.eql(u8, command, "exec")) {
        const sql = options.sql orelse return usageError(err_out, "exec needs --sql");
        return execCommand(node, sql, options, out, err_out);
    } else if (std.mem.eql(u8, command, "query")) {
        const sql = options.sql orelse return usageError(err_out, "query needs --sql");
        return queryCommand(gpa, node, sql, options.json, out, err_out);
    } else if (std.mem.eql(u8, command, "session")) {
        const session = try node.openSession();
        if (options.json) {
            try out.print("{{\"session_id\":{d}}}\n", .{session});
        } else {
            try out.print("session {d}\n", .{session});
        }
        return exit_ok;
    } else if (std.mem.eql(u8, command, "status")) {
        try printStatus(node, options.json, out);
        return exit_ok;
    } else if (std.mem.eql(u8, command, "members")) {
        const status = node.status();
        if (options.json) try out.writeAll("{\"membership\":\"static\",\"members\":[");
        for (node.memberIds(), 0..) |member, index| {
            if (options.json) {
                if (index > 0) try out.writeAll(",");
                try out.print("{d}", .{member});
            } else {
                try out.print("node {d}{s}\n", .{
                    member,
                    if (member == status.node_id) " (self)" else "",
                });
            }
        }
        if (options.json) try out.writeAll("]}\n");
        return exit_ok;
    } else if (std.mem.eql(u8, command, "snapshot")) {
        try node.snapshot();
        const status = node.status();
        if (options.json) {
            try out.print(
                "{{\"configuration_id\":{d},\"snapshot\":\"{s}\"}}\n",
                .{ status.configuration_id, if (status.snapshot) |name| &name else "" },
            );
        } else {
            try out.print(
                "snapshot installed; epoch sealed, now at configuration {d}\n",
                .{status.configuration_id},
            );
        }
        return exit_ok;
    } else if (std.mem.eql(u8, command, "backup")) {
        const destination = options.to orelse return usageError(err_out, "backup needs --to");
        node.backup(destination) catch |err| switch (err) {
            error.SqliteError => {
                try diagnostic.write(
                    err_out,
                    "backup failed",
                    node.lastSqliteMessage(),
                    "Choose a new path and verify its parent directory.",
                );
                return exit_sql;
            },
            else => return err,
        };
        try out.print("backup written to {s}\n", .{destination});
        return exit_ok;
    } else if (std.mem.eql(u8, command, "integrity-check") or
        std.mem.eql(u8, command, "recover"))
    {
        const report = try node.integrityCheck();
        if (options.json) {
            try out.print(
                "{{\"sqlite_ok\":{},\"chain_ok\":{},\"payloads_ok\":{}}}\n",
                .{ report.sqlite_ok, report.chain_ok, report.payloads_ok },
            );
        } else {
            try out.print(
                "sqlite: {s}\nchain: {s}\npayloads: {s}\n",
                .{ passFail(report.sqlite_ok), passFail(report.chain_ok), passFail(report.payloads_ok) },
            );
            if (std.mem.eql(u8, command, "recover")) {
                try out.writeAll("recovery rebuild complete\n");
            }
        }
        return if (report.ok()) exit_ok else exit_integrity;
    } else if (std.mem.eql(u8, command, "expire-sessions")) {
        const retain = options.retain orelse
            return usageError(err_out, "expire-sessions needs --retain");
        const result = try node.expireSessions(retain);
        try out.print("{d} session(s) expired\n", .{result.changes});
        return exit_ok;
    }

    try diagnostic.write(
        err_out,
        "unknown command",
        command,
        "Run 'zaxon help' to list the supported commands.",
    );
    try out.writeAll(usage_text);
    return exit_usage;
}

/// Applies the public precedence contract: explicit CLI values are already in
/// `options`; environment values then override file values.
fn applyConfiguration(
    gpa: std.mem.Allocator,
    environ: *std.process.Environ.Map,
    file: ?*const configuration.File,
    options: *Options,
    err_out: *std.Io.Writer,
) !void {
    if (options.data == null) {
        options.data = environ.get("ZAXON_DATA") orelse
            if (file) |value| value.data else null;
    }
    if (options.connect == null) {
        options.connect = environ.get("ZAXON_CONNECT") orelse
            if (file) |value| value.connect else null;
    }
    if (options.listen == null) {
        options.listen = environ.get("ZAXON_LISTEN") orelse
            if (file) |value| value.listen else null;
    }
    if (options.cluster_id == null) {
        options.cluster_id = environ.get("ZAXON_CLUSTER_ID") orelse
            if (file) |value| value.cluster_id else null;
    }
    if (options.auth_file == null) {
        options.auth_file = environ.get("ZAXON_AUTH_FILE") orelse
            if (file) |value| value.auth_file else null;
    }
    if (options.tls_cert == null) {
        options.tls_cert = environ.get("ZAXON_TLS_CERT") orelse
            if (file) |value| value.tls_cert else null;
    }
    if (options.tls_key == null) {
        options.tls_key = environ.get("ZAXON_TLS_KEY") orelse
            if (file) |value| value.tls_key else null;
    }
    if (options.tls_ca == null) {
        options.tls_ca = environ.get("ZAXON_TLS_CA") orelse
            if (file) |value| value.tls_ca else null;
    }
    if (options.enrollment_ca_key == null) {
        options.enrollment_ca_key = environ.get("ZAXON_ENROLLMENT_CA_KEY") orelse
            if (file) |value| value.enrollment_ca_key else null;
    }
    if (options.revocation_file == null) {
        options.revocation_file = environ.get("ZAXON_REVOCATION_FILE") orelse
            if (file) |value| value.revocation_file else null;
    }
    if (options.sync == null) {
        options.sync = environ.get("ZAXON_SYNC") orelse
            if (file) |value| value.sync else null;
    }
    if (options.node_id == null) {
        if (environ.get("ZAXON_NODE")) |text| {
            options.node_id = std.fmt.parseInt(u32, text, 10) catch {
                _ = try usageError(err_out, "ZAXON_NODE must be an integer");
                return error.InvalidEnvironment;
            };
        } else if (file) |value| {
            options.node_id = value.node;
        }
    }
    if (!options.role_set) {
        const role_text = environ.get("ZAXON_ROLE") orelse
            if (file) |value| value.role else null;
        if (role_text) |text| {
            options.role = Role.parse(text) catch {
                _ = try usageError(err_out, "ZAXON_ROLE/config role is unknown");
                return error.InvalidEnvironment;
            };
        }
    }
    if (options.peers.items.len == 0) {
        if (environ.get("ZAXON_PEERS")) |text| {
            var peers = std.mem.tokenizeScalar(u8, text, ',');
            while (peers.next()) |peer| try options.peers.append(gpa, peer);
        } else if (file) |value| {
            try options.peers.appendSlice(gpa, value.peers);
        }
    }
}

fn usageError(err_out: *std.Io.Writer, message: []const u8) !u8 {
    try diagnostic.write(
        err_out,
        "invalid command",
        message,
        "Run 'zaxon help' to see commands and required options.",
    );
    return exit_usage;
}

fn noLeaderDiagnostic(err_out: *std.Io.Writer) !void {
    try diagnostic.write(
        err_out,
        "no reachable leader",
        "No seed endpoint or authenticated leader redirect could complete " ++
            "this leader-only request.",
        "Restore a voter quorum and verify credentials. With --dev-psk, " ++
            "include every cluster member in --connect.",
    );
}

fn malformedResponseDiagnostic(err_out: *std.Io.Writer) !void {
    try diagnostic.write(
        err_out,
        "malformed response",
        "The peer returned a body outside the Zaxonlite JSON contract.",
        "Check protocol versions and preserve the peer log for diagnosis.",
    );
}

fn remoteHint(code: []const u8) []const u8 {
    if (std.mem.eql(u8, code, "not_leader")) {
        return "Retry the advertised leader or restore a voter quorum.";
    }
    if (std.mem.eql(u8, code, "stale")) {
        return "Wait for learner catch-up, relax freshness, or query the leader.";
    }
    if (std.mem.eql(u8, code, "sql")) {
        return "Correct the SQL statement; use exec for statements that write.";
    }
    if (std.mem.eql(u8, code, "session")) {
        return "Retry only the latest sequence in the same unexpired session.";
    }
    return "Inspect node status and retry only when the reported condition is resolved.";
}

fn passFail(ok: bool) []const u8 {
    return if (ok) "pass" else "FAIL";
}

// ----------------------------------------------------------------------
// serve
// ----------------------------------------------------------------------

fn serveCommand(
    gpa: std.mem.Allocator,
    io: std.Io,
    options: *Options,
    auth_secret: ?[]const u8,
    tls_config: ?tls.Config,
    err_out: *std.Io.Writer,
) !u8 {
    if (tls_config) |config| {
        configuration.validatePrivateFile(io, config.key_path) catch |err| {
            try diagnostic.write(
                err_out,
                "unsafe TLS private key",
                @errorName(err),
                "Use a regular, non-symlink key file with mode 0600.",
            );
            return exit_usage;
        };
    }
    const data = options.data orelse
        return usageError(err_out, "serve needs --data");
    const node_id = options.node_id orelse
        return usageError(err_out, "serve needs --node");
    const listen_text = options.listen orelse
        return usageError(err_out, "serve needs --listen");
    const listen = client.Endpoint.parse(listen_text) catch
        return usageError(err_out, "--listen must be host:port or unix:<path>");
    if (listen.unix_path != null) {
        if (options.role == .gateway) {
            return usageError(err_out, "gateway mode listens on TCP");
        }
        if (options.peers.items.len > 0) {
            return usageError(
                err_out,
                "unix socket service is single-node; peers need host:port",
            );
        }
    }

    var members: std.ArrayList(server.PeerAddress) = .empty;
    defer members.deinit(gpa);
    try members.append(gpa, .{
        .id = node_id,
        .host = listen.host,
        .port = listen.port,
        .role = options.role,
    });
    for (options.peers.items) |peer_text| {
        const at = std.mem.indexOfScalar(u8, peer_text, '@') orelse
            return usageError(err_out, "--peer must be id@host:port");
        const id = std.fmt.parseInt(u32, peer_text[0..at], 10) catch
            return usageError(err_out, "--peer must be id@host:port");
        if (id == node_id) continue;
        const address_and_role = peer_text[at + 1 ..];
        const slash = std.mem.lastIndexOfScalar(u8, address_and_role, '/');
        const address = if (slash) |index| address_and_role[0..index] else address_and_role;
        const role = if (slash) |index|
            Role.parse(address_and_role[index + 1 ..]) catch
                return usageError(err_out, "--peer has an unknown role")
        else
            Role.data_voter;
        const endpoint = client.Endpoint.parse(address) catch
            return usageError(err_out, "--peer must be id@host:port[/role]");
        try members.append(gpa, .{
            .id = id,
            .host = endpoint.host,
            .port = endpoint.port,
            .role = role,
        });
    }

    const database_id: ?u128 = if (members.items.len > 1)
        server.deriveDatabaseId(members.items, options.cluster_id)
    else
        null;

    if (options.role == .gateway) {
        if (options.dev_psk) {
            return usageError(err_out, "gateway mode does not terminate --dev-psk");
        }
        if (tls_config != null) {
            return usageError(
                err_out,
                "gateway mode passes TLS through; put --tls-* on clients " ++
                    "and storage nodes, not the gateway",
            );
        }
        if (options.enrollment_ca_key != null) {
            return usageError(
                err_out,
                "gateway mode cannot issue enrollment certificates",
            );
        }
        var backends: std.ArrayList(client.Endpoint) = .empty;
        defer backends.deinit(gpa);
        for (members.items) |member| {
            const capabilities = member.role.capabilities();
            if (member.id == node_id or
                (!capabilities.serves_reads and !capabilities.serves_writes))
            {
                continue;
            }
            try backends.append(gpa, .{ .host = member.host, .port = member.port });
        }
        return gateway.serve(gpa, io, .{
            .listen_host = listen.host,
            .listen_port = listen.port,
            .backends = backends.items,
        }, err_out);
    }

    return server.serve(gpa, io, .{
        .directory = data,
        .node_id = node_id,
        .listen_host = listen.host,
        .listen_port = listen.port,
        .listen_unix = listen.unix_path,
        .members = members.items,
        .database_id = database_id,
        .auth_secret = auth_secret,
        .allow_psk_only_loopback = options.dev_psk,
        .tls = tls_config,
        .enrollment_ca_key = options.enrollment_ca_key,
        .revocation_file = options.revocation_file,
        .enable_failpoints = options.enable_failpoints,
        .allow_insecure_test_tcp = options.insecure_test_tcp,
    }, err_out);
}

// ----------------------------------------------------------------------
// Client mode
// ----------------------------------------------------------------------

fn parseEndpoints(
    gpa: std.mem.Allocator,
    text: []const u8,
) !std.ArrayList(client.Endpoint) {
    var list: std.ArrayList(client.Endpoint) = .empty;
    errdefer list.deinit(gpa);
    var parts = std.mem.tokenizeScalar(u8, text, ',');
    while (parts.next()) |part| {
        try list.append(gpa, try client.Endpoint.parse(part));
    }
    if (list.items.len == 0) return error.InvalidEndpoint;
    return list;
}

fn remote(
    gpa: std.mem.Allocator,
    io: std.Io,
    options: *Options,
    transport: client.Transport,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    var endpoints = parseEndpoints(gpa, options.connect.?) catch
        return usageError(err_out, "--connect must be host:port[,host:port...]");
    defer endpoints.deinit(gpa);

    const command = options.command;
    if (std.mem.eql(u8, command, "sql")) {
        return remoteShell(gpa, io, endpoints.items, transport, out, err_out);
    }
    if (std.mem.eql(u8, command, "backup")) {
        const destination = options.to orelse
            return usageError(err_out, "backup needs --to");
        var probe = client.callClusterWithTransport(
            gpa,
            io,
            endpoints.items,
            "{\"op\":\"query\",\"sql\":\"select 1\"}",
            true,
            transport,
        ) catch {
            try noLeaderDiagnostic(err_out);
            return exit_unavailable;
        };
        defer probe.deinit(gpa);
        const connection = client.Connection.openWithTransport(
            gpa,
            io,
            probe.endpoint,
            transport,
        ) catch {
            try diagnostic.write(
                err_out,
                "backup interrupted",
                "The selected leader became unavailable.",
                "Retry against the endpoint list; the destination was not installed.",
            );
            return exit_unavailable;
        };
        defer connection.close();
        connection.backupTo(destination) catch |err| {
            try diagnostic.write(
                err_out,
                "remote backup failed",
                @errorName(err),
                "Check the destination, cluster health, and transport logs.",
            );
            return exit_unavailable;
        };
        if (options.json) {
            try out.writeAll("{\"ok\":true}\n");
        } else {
            try out.print("backup written to {s}\n", .{destination});
        }
        return exit_ok;
    }

    var request: std.Io.Writer.Allocating = .init(gpa);
    defer request.deinit();
    const writer = &request.writer;
    var require_leader = true;

    if (std.mem.eql(u8, command, "exec")) {
        const sql = options.sql orelse return usageError(err_out, "exec needs --sql");
        if ((options.session == null) != (options.sequence == null)) {
            return usageError(err_out, "--session and --sequence go together");
        }
        try writer.writeAll("{\"op\":\"exec\",\"sql\":");
        try writeJsonString(writer, sql);
        if (options.session) |session| {
            try writer.print(
                ",\"session\":{d},\"sequence\":{d}",
                .{ session, options.sequence.? },
            );
        }
        try writer.writeAll("}");
    } else if (std.mem.eql(u8, command, "query")) {
        const sql = options.sql orelse return usageError(err_out, "query needs --sql");
        const level = options.level orelse "linearizable";
        require_leader = !std.mem.eql(u8, level, "any");
        try writer.writeAll("{\"op\":\"query\",\"sql\":");
        try writeJsonString(writer, sql);
        try writer.print(",\"level\":\"{s}\"", .{level});
        if (options.freshness_ms) |freshness| {
            try writer.print(",\"freshness_ms\":{d}", .{freshness});
        }
        try writer.writeAll("}");
    } else if (std.mem.eql(u8, command, "status")) {
        require_leader = false;
        try writer.writeAll("{\"op\":\"status\"}");
    } else if (std.mem.eql(u8, command, "members")) {
        require_leader = false;
        try writer.writeAll("{\"op\":\"members\"}");
    } else if (std.mem.eql(u8, command, "leader")) {
        require_leader = false;
        try writer.writeAll("{\"op\":\"leader\"}");
    } else if (std.mem.eql(u8, command, "session")) {
        try writer.writeAll("{\"op\":\"session\"}");
    } else if (std.mem.eql(u8, command, "wait")) {
        require_leader = false;
        try writer.print(
            "{{\"op\":\"wait\",\"applied\":{d},\"leader\":{},\"timeout_ms\":{d}}}",
            .{
                options.applied orelse 0,
                options.wait_leader,
                options.timeout_ms orelse 10_000,
            },
        );
    } else if (std.mem.eql(u8, command, "snapshot")) {
        try writer.writeAll("{\"op\":\"snapshot\"}");
    } else if (std.mem.eql(u8, command, "integrity-check")) {
        require_leader = false;
        try writer.writeAll("{\"op\":\"integrity\"}");
    } else if (std.mem.eql(u8, command, "expire-sessions")) {
        const retain = options.retain orelse
            return usageError(err_out, "expire-sessions needs --retain");
        try writer.print("{{\"op\":\"expire-sessions\",\"retain\":{d}}}", .{retain});
    } else if (std.mem.eql(u8, command, "enroll-token")) {
        require_leader = false;
        const node_id = options.node_id orelse
            return usageError(err_out, "enroll-token needs --node");
        const ttl_seconds = options.ttl_seconds orelse enrollment.default_ttl_seconds;
        if (ttl_seconds == 0 or ttl_seconds > enrollment.maximum_ttl_seconds) {
            return usageError(err_out, "--ttl-seconds must be between 1 and 86400");
        }
        if (options.to == null) {
            return usageError(err_out, "enroll-token needs --to");
        }
        if (options.tls_ca == null) {
            return usageError(err_out, "enroll-token requires --tls-ca");
        }
        try writer.print(
            "{{\"op\":\"issue-enrollment-token\",\"node_id\":{d}," ++
                "\"ttl_seconds\":{d}}}",
            .{ node_id, ttl_seconds },
        );
    } else if (std.mem.eql(u8, command, "stop")) {
        require_leader = false;
        try writer.writeAll("{\"op\":\"stop\"}");
    } else {
        try diagnostic.write(
            err_out,
            "unsupported client command",
            command,
            "Use --data for this operation or select a remote-capable command.",
        );
        return exit_usage;
    }

    var result = client.callClusterWithTransport(
        gpa,
        io,
        endpoints.items,
        request.written(),
        require_leader,
        transport,
    ) catch {
        try noLeaderDiagnostic(err_out);
        return exit_unavailable;
    };
    defer {
        if (std.mem.eql(u8, command, "enroll-token")) @memset(result.body, 0);
        result.deinit(gpa);
    }
    if (std.mem.eql(u8, command, "enroll-token")) {
        return saveEnrollmentBundle(
            gpa,
            io,
            options,
            result,
            out,
            err_out,
        );
    }
    return renderRemote(gpa, options, result.body, out, err_out);
}

fn saveEnrollmentBundle(
    gpa: std.mem.Allocator,
    io: std.Io,
    options: *const Options,
    result: client.CallResult,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    const Response = struct {
        ok: bool = false,
        node_id: u32 = 0,
        issuer_node_id: u32 = 0,
        database_id: []const u8 = "",
        expires_unix_seconds: u64 = 0,
        token: []const u8 = "",
        @"error": ?[]const u8 = null,
        message: ?[]const u8 = null,
    };
    const parsed = std.json.parseFromSlice(Response, gpa, result.body, .{
        .ignore_unknown_fields = true,
    }) catch {
        try malformedResponseDiagnostic(err_out);
        return exit_unavailable;
    };
    defer parsed.deinit();
    const response = parsed.value;
    if (!response.ok) {
        try diagnostic.write(
            err_out,
            response.@"error" orelse "enrollment_unavailable",
            response.message orelse "token issuance failed",
            "Connect with an existing mTLS identity to a configured issuer node.",
        );
        return exit_unavailable;
    }
    if (response.node_id == 0 or response.issuer_node_id == 0 or
        response.database_id.len != 32 or response.token.len != 64 or
        response.expires_unix_seconds == 0 or result.endpoint.unix_path != null)
    {
        try malformedResponseDiagnostic(err_out);
        return exit_unavailable;
    }
    var secret: [enrollment.token_bytes]u8 = undefined;
    _ = std.fmt.hexToBytes(&secret, response.token) catch {
        try malformedResponseDiagnostic(err_out);
        return exit_unavailable;
    };
    const database_id = std.fmt.parseInt(u128, response.database_id, 16) catch {
        try malformedResponseDiagnostic(err_out);
        return exit_unavailable;
    };
    const ca_pem = std.Io.Dir.cwd().readFileAlloc(
        io,
        options.tls_ca.?,
        gpa,
        .limited(enrollment.maximum_ca_bytes + 1),
    ) catch |err| {
        try diagnostic.write(
            err_out,
            "cluster CA unreadable",
            @errorName(err),
            "Keep the CA certificate used by the authenticated issuer available.",
        );
        return exit_usage;
    };
    defer gpa.free(ca_pem);
    const endpoint = try std.fmt.allocPrint(
        gpa,
        "{s}:{d}",
        .{ result.endpoint.host, result.endpoint.port },
    );
    defer gpa.free(endpoint);
    const bundle = enrollment.Bundle{
        .node_id = response.node_id,
        .issuer_node_id = response.issuer_node_id,
        .database_id = database_id,
        .expires_unix_seconds = response.expires_unix_seconds,
        .secret = secret,
        .endpoint = endpoint,
        .ca_pem = ca_pem,
    };
    const encoded = bundle.encodeAlloc(gpa) catch |err| {
        try diagnostic.write(
            err_out,
            "invalid enrollment response",
            @errorName(err),
            "Preserve the issuer log and retry with a new token.",
        );
        return exit_unavailable;
    };
    defer {
        @memset(encoded, 0);
        gpa.free(encoded);
    }
    enrollment.writeBundleFile(io, options.to.?, encoded) catch |err| {
        try diagnostic.write(
            err_out,
            "token bundle not written",
            @errorName(err),
            "Choose a new path whose parent exists; existing files are never overwritten.",
        );
        return exit_unavailable;
    };
    if (options.json) {
        try out.print(
            "{{\"ok\":true,\"path\":\"{s}\",\"node_id\":{d}," ++
                "\"expires_unix_seconds\":{d}}}\n",
            .{ options.to.?, response.node_id, response.expires_unix_seconds },
        );
    } else {
        try out.print(
            "enrollment token for node {d} written to {s}; expires at Unix second {d}\n",
            .{ response.node_id, options.to.?, response.expires_unix_seconds },
        );
    }
    return exit_ok;
}

fn enrollCommand(
    gpa: std.mem.Allocator,
    io: std.Io,
    options: *const Options,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    const token_path = options.token_file orelse
        return usageError(err_out, "enroll needs --token-file");
    const identity_dir = options.identity_dir orelse
        return usageError(err_out, "enroll needs --identity-dir");
    const bundle_bytes = enrollment.readBundleFile(gpa, io, token_path) catch |err| {
        try diagnostic.write(
            err_out,
            "enrollment token unreadable",
            @errorName(err),
            "Use the owner-only opaque bundle produced by enroll-token.",
        );
        return exit_usage;
    };
    defer {
        @memset(bundle_bytes, 0);
        gpa.free(bundle_bytes);
    }
    const bundle = enrollment.Bundle.decode(bundle_bytes) catch |err| {
        try diagnostic.write(
            err_out,
            "enrollment token invalid",
            @errorName(err),
            "Request a new enrollment token from a configured issuer.",
        );
        return exit_usage;
    };
    var identity = enrollment.requestCertificate(gpa, io, bundle) catch |err| {
        try diagnostic.write(
            err_out,
            "enrollment refused",
            @errorName(err),
            "Check expiry, target node ID, issuer reachability, and request a new token after any ambiguous failure.",
        );
        return exit_unavailable;
    };
    defer identity.deinit(gpa);
    enrollment.installIdentity(io, identity_dir, &identity, bundle.ca_pem) catch |err| {
        try diagnostic.write(
            err_out,
            "identity installation failed",
            @errorName(err),
            "The token is already consumed. Preserve the error, remove no existing identity, and issue a replacement token.",
        );
        return exit_unavailable;
    };
    enrollment.removeBundleFile(io, token_path) catch {};
    if (options.json) {
        try out.print(
            "{{\"ok\":true,\"node_id\":{d},\"identity_dir\":\"{s}\"}}\n",
            .{ bundle.node_id, identity_dir },
        );
    } else {
        try out.print(
            "node {d} enrolled; identity installed in {s}\n",
            .{ bundle.node_id, identity_dir },
        );
    }
    return exit_ok;
}

/// Prints a response body. `--json` passes the raw response through;
/// otherwise a human summary is rendered per command.
fn renderRemote(
    gpa: std.mem.Allocator,
    options: *Options,
    body: []const u8,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    const parsed = std.json.parseFromSlice(std.json.Value, gpa, body, .{}) catch {
        try malformedResponseDiagnostic(err_out);
        return exit_unavailable;
    };
    defer parsed.deinit();
    const object = switch (parsed.value) {
        .object => |*obj| obj,
        else => {
            try malformedResponseDiagnostic(err_out);
            return exit_unavailable;
        },
    };

    const ok = blk: {
        const value = object.get("ok") orelse break :blk false;
        break :blk value == .bool and value.bool;
    };
    if (!ok) {
        const code = blk: {
            const value = object.get("error") orelse break :blk "unknown";
            break :blk if (value == .string) value.string else "unknown";
        };
        const message = blk: {
            const value = object.get("message") orelse break :blk "";
            break :blk if (value == .string) value.string else "";
        };
        // Integrity reports carry ok=false with detail fields.
        if (std.mem.eql(u8, options.command, "integrity-check") and
            object.get("sqlite_ok") != null)
        {
            if (options.json) {
                try out.print("{s}\n", .{body});
            } else {
                try out.writeAll("integrity: FAIL\n");
            }
            return exit_integrity;
        }
        if (options.json) {
            try out.print("{s}\n", .{body});
        } else {
            try diagnostic.write(err_out, code, message, remoteHint(code));
        }
        if (std.mem.eql(u8, code, "sql") or std.mem.eql(u8, code, "session")) {
            return exit_sql;
        }
        if (std.mem.eql(u8, code, "bad_request")) return exit_usage;
        return exit_unavailable;
    }

    if (options.json) {
        try out.print("{s}\n", .{body});
        return exit_ok;
    }

    const command = options.command;
    if (std.mem.eql(u8, command, "exec")) {
        const changes = jsonInt(object.get("changes")) orelse 0;
        const replayed = blk: {
            const value = object.get("replayed") orelse break :blk false;
            break :blk value == .bool and value.bool;
        };
        if (replayed) {
            try out.print("replayed: {d} row(s) changed (recorded result)\n", .{changes});
        } else {
            try out.print("{d} row(s) changed\n", .{changes});
        }
    } else if (std.mem.eql(u8, command, "query")) {
        try renderRemoteTable(object, out);
    } else if (std.mem.eql(u8, command, "session")) {
        try out.print("session {d}\n", .{jsonInt(object.get("session_id")) orelse 0});
    } else if (std.mem.eql(u8, command, "leader")) {
        if (object.get("leader")) |leader| switch (leader) {
            .object => |leader_object| {
                const id = jsonInt(leader_object.get("id")) orelse 0;
                if (leader_object.get("host")) |host| {
                    if (host == .string) {
                        try out.print("leader: node {d} at {s}:{d}\n", .{
                            id,
                            host.string,
                            jsonInt(leader_object.get("port")) orelse 0,
                        });
                        return exit_ok;
                    }
                }
                try out.print("leader: node {d}\n", .{id});
            },
            else => try out.writeAll("leader: none\n"),
        };
    } else if (std.mem.eql(u8, command, "wait")) {
        try out.print("applied {d}, leader {?d}\n", .{
            jsonInt(object.get("applied_slot")) orelse 0,
            jsonInt(object.get("leader")),
        });
    } else if (std.mem.eql(u8, command, "snapshot")) {
        try out.print(
            "snapshot installed; now at configuration {d}\n",
            .{jsonInt(object.get("configuration_id")) orelse 0},
        );
    } else if (std.mem.eql(u8, command, "integrity-check")) {
        try out.writeAll("integrity: pass\n");
    } else if (std.mem.eql(u8, command, "expire-sessions")) {
        try out.print("{d} session(s) expired\n", .{jsonInt(object.get("expired")) orelse 0});
    } else if (std.mem.eql(u8, command, "status")) {
        try out.print("{s}\n", .{body});
    } else if (std.mem.eql(u8, command, "members")) {
        try out.print("{s}\n", .{body});
    } else {
        try out.print("{s}\n", .{body});
    }
    return exit_ok;
}

fn jsonInt(value: ?std.json.Value) ?i64 {
    const v = value orelse return null;
    return switch (v) {
        .integer => |n| n,
        else => null,
    };
}

fn renderRemoteTable(
    object: *const std.json.ObjectMap,
    out: *std.Io.Writer,
) !void {
    const columns = object.get("columns") orelse return;
    const rows = object.get("rows") orelse return;
    if (columns != .array or rows != .array) return;
    for (columns.array.items, 0..) |column, index| {
        if (index > 0) try out.writeAll(" | ");
        if (column == .string) try out.writeAll(column.string);
    }
    try out.writeAll("\n");
    for (columns.array.items, 0..) |column, index| {
        if (index > 0) try out.writeAll("-+-");
        const len = if (column == .string) column.string.len else 4;
        for (0..len) |_| try out.writeAll("-");
    }
    try out.writeAll("\n");
    for (rows.array.items) |row| {
        if (row != .array) continue;
        for (row.array.items, 0..) |cell, index| {
            if (index > 0) try out.writeAll(" | ");
            switch (cell) {
                .string => |text| try out.writeAll(text),
                .null => try out.writeAll("NULL"),
                .integer => |n| try out.print("{d}", .{n}),
                .float => |f| try out.print("{d}", .{f}),
                else => try out.writeAll("?"),
            }
        }
        try out.writeAll("\n");
    }
}

fn remoteShell(
    gpa: std.mem.Allocator,
    io: std.Io,
    endpoints: []const client.Endpoint,
    transport: client.Transport,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    try out.print(
        "zaxonlite {s} — connected shell\n" ++
            "SQL statements end my line; dot commands: .status .quit\n",
        .{zaxonlite.version},
    );
    var stdin_buffer: [64 * 1024]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().readerStreaming(io, &stdin_buffer);
    const in = &stdin_reader.interface;
    var cluster = client.ClusterConnection.init(gpa, io, endpoints, transport);
    defer cluster.deinit();

    while (true) {
        try out.writeAll("zaxon> ");
        try out.flush();
        const raw_line = in.takeDelimiter('\n') catch |err| switch (err) {
            error.StreamTooLong => {
                try diagnostic.write(
                    err_out,
                    "input line too long",
                    "The shell statement exceeds its bounded input buffer.",
                    "Split the statement or run a smaller --sql request.",
                );
                try err_out.flush();
                continue;
            },
            else => return err,
        };
        const line_bytes = raw_line orelse break;
        const line = std.mem.trim(u8, line_bytes, " \t\r");
        if (line.len == 0) continue;

        var request: std.Io.Writer.Allocating = .init(gpa);
        defer request.deinit();
        var pseudo = Options{ .command = "query" };
        if (line[0] == '.') {
            if (std.mem.eql(u8, line, ".quit") or std.mem.eql(u8, line, ".exit")) break;
            if (std.mem.eql(u8, line, ".status")) {
                try request.writer.writeAll("{\"op\":\"status\"}");
                pseudo.command = "status";
                pseudo.json = true;
            } else {
                try diagnostic.write(
                    err_out,
                    "unknown shell command",
                    line,
                    "Use .status or .quit, or enter a SQL statement.",
                );
                try err_out.flush();
                continue;
            }
        } else if (isReadStatement(line)) {
            try request.writer.writeAll("{\"op\":\"query\",\"sql\":");
            try writeJsonString(&request.writer, line);
            try request.writer.writeAll(",\"level\":\"linearizable\"}");
        } else {
            pseudo.command = "exec";
            try request.writer.writeAll("{\"op\":\"exec\",\"sql\":");
            try writeJsonString(&request.writer, line);
            try request.writer.writeAll("}");
        }

        var result = cluster.call(request.written(), true) catch {
            try noLeaderDiagnostic(err_out);
            try err_out.flush();
            continue;
        };
        defer result.deinit(gpa);
        _ = try renderRemote(gpa, &pseudo, result.body, out, err_out);
        try out.flush();
        try err_out.flush();
    }
    return exit_ok;
}

// ----------------------------------------------------------------------
// exec / query (embedded)
// ----------------------------------------------------------------------

fn execCommand(
    node: *Node,
    sql: [:0]const u8,
    options: Options,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    if ((options.session == null) != (options.sequence == null)) {
        return usageError(err_out, "--session and --sequence go together");
    }
    const result = blk: {
        if (options.session) |session| {
            break :blk node.execIdempotent(session, options.sequence.?, sql);
        }
        break :blk node.exec(sql);
    } catch |err| switch (err) {
        error.SqliteError, error.SqliteBusy => {
            try diagnostic.write(
                err_out,
                "sql error",
                node.lastSqliteMessage(),
                "Correct the statement and retry it as a new request.",
            );
            return exit_sql;
        },
        error.UnknownSession, error.SequenceGap, error.ResultExpired => {
            try diagnostic.write(
                err_out,
                "session error",
                @errorName(err),
                "Use the same live session and its next monotonic sequence.",
            );
            return exit_sql;
        },
        else => return err,
    };
    if (options.json) {
        try out.print(
            "{{\"changes\":{d},\"slot\":{d},\"replayed\":{}}}\n",
            .{ result.changes, result.slot, result.replayed },
        );
    } else if (result.replayed) {
        try out.print("replayed: {d} row(s) changed (recorded result)\n", .{result.changes});
    } else {
        try out.print("{d} row(s) changed\n", .{result.changes});
    }
    return exit_ok;
}

fn queryCommand(
    gpa: std.mem.Allocator,
    node: *Node,
    sql: []const u8,
    json: bool,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    var result = node.query(gpa, sql) catch |err| switch (err) {
        error.SqliteError, error.SqliteBusy, error.WriteInReadQuery => {
            const message = if (err == error.WriteInReadQuery)
                "statement is not read-only; use exec"
            else
                node.lastSqliteMessage();
            try diagnostic.write(
                err_out,
                "query error",
                message,
                "Use query only for read-only SQL; use exec for writes.",
            );
            return exit_sql;
        },
        else => return err,
    };
    defer result.deinit();

    if (json) {
        try writeJsonResult(&result, out);
    } else {
        try writeTable(&result, out);
    }
    return exit_ok;
}

fn writeTable(result: *const zaxonlite.QueryResult, out: *std.Io.Writer) !void {
    for (result.columns, 0..) |column, index| {
        if (index > 0) try out.writeAll(" | ");
        try out.writeAll(column);
    }
    try out.writeAll("\n");
    for (result.columns, 0..) |column, index| {
        if (index > 0) try out.writeAll("-+-");
        for (0..column.len) |_| try out.writeAll("-");
    }
    try out.writeAll("\n");
    for (result.rows) |row| {
        for (row, 0..) |cell, index| {
            if (index > 0) try out.writeAll(" | ");
            try out.writeAll(cell orelse "NULL");
        }
        try out.writeAll("\n");
    }
}

fn writeJsonResult(result: *const zaxonlite.QueryResult, out: *std.Io.Writer) !void {
    try out.writeAll("{\"columns\":[");
    for (result.columns, 0..) |column, index| {
        if (index > 0) try out.writeAll(",");
        try writeJsonString(out, column);
    }
    try out.writeAll("],\"rows\":[");
    for (result.rows, 0..) |row, row_index| {
        if (row_index > 0) try out.writeAll(",");
        try out.writeAll("[");
        for (row, 0..) |cell, index| {
            if (index > 0) try out.writeAll(",");
            if (cell) |text| {
                try writeJsonString(out, text);
            } else {
                try out.writeAll("null");
            }
        }
        try out.writeAll("]");
    }
    try out.writeAll("]}\n");
}

fn writeJsonString(out: *std.Io.Writer, text: []const u8) !void {
    try out.writeAll("\"");
    for (text) |byte| {
        switch (byte) {
            '"' => try out.writeAll("\\\""),
            '\\' => try out.writeAll("\\\\"),
            '\n' => try out.writeAll("\\n"),
            '\r' => try out.writeAll("\\r"),
            '\t' => try out.writeAll("\\t"),
            else => {
                if (byte < 0x20) {
                    try out.print("\\u{x:0>4}", .{byte});
                } else {
                    try out.writeAll(&.{byte});
                }
            },
        }
    }
    try out.writeAll("\"");
}

fn printStatus(node: *Node, json: bool, out: *std.Io.Writer) !void {
    const status = node.status();
    const chain_hex = std.fmt.bytesToHex(status.chain, .lower);
    if (json) {
        try out.print(
            "{{\"node_id\":{d},\"database_id\":\"{x:0>32}\"," ++
                "\"configuration_id\":{d},\"role\":\"{s}\"," ++
                "\"node_type\":\"{s}\"," ++
                "\"leader\":{?d}," ++
                "\"decided_slot\":{d},\"applied_slot\":{d}," ++
                "\"journal_records\":{d},\"epoch_capacity\":{d}," ++
                "\"chain\":\"{s}\",\"page_size\":{d},\"snapshot\":",
            .{
                status.node_id,          status.database_id,
                status.configuration_id, status.role,
                status.node_type,        status.leader,
                status.decided_slot,     status.applied_slot,
                status.journal_records,  status.epoch_capacity,
                &chain_hex,              status.page_size,
            },
        );
        if (status.snapshot) |name| {
            try out.print("\"{s}\"}}\n", .{&name});
        } else {
            try out.writeAll("null}\n");
        }
    } else {
        try out.print(
            \\node id:          {d}
            \\database id:      {x:0>32}
            \\configuration id: {d}
            \\role:             {s}
            \\node type:        {s}
            \\decided slot:     {d}
            \\applied slot:     {d}
            \\journal records:  {d}
            \\epoch capacity:   {d}
            \\chain:            {s}
            \\page size:        {d}
            \\snapshot:         {s}
            \\
        , .{
            status.node_id,
            status.database_id,
            status.configuration_id,
            status.role,
            status.node_type,
            status.decided_slot,
            status.applied_slot,
            status.journal_records,
            status.epoch_capacity,
            &chain_hex,
            status.page_size,
            if (status.snapshot) |name| &name else "(none)",
        });
    }
}

// ----------------------------------------------------------------------
// Interactive shell (embedded)
// ----------------------------------------------------------------------

fn shell(
    gpa: std.mem.Allocator,
    io: std.Io,
    node: *Node,
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    try out.print(
        "zaxonlite {s} — one durable node, journal-replicated SQLite\n" ++
            "SQL statements end my line; dot commands: .status .tables .quit\n",
        .{zaxonlite.version},
    );
    var stdin_buffer: [64 * 1024]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().readerStreaming(io, &stdin_buffer);
    const in = &stdin_reader.interface;

    while (true) {
        try out.writeAll("zaxon> ");
        try out.flush();
        const raw_line = in.takeDelimiter('\n') catch |err| switch (err) {
            error.StreamTooLong => {
                try diagnostic.write(
                    err_out,
                    "input line too long",
                    "The shell statement exceeds its bounded input buffer.",
                    "Split the statement or run a smaller --sql request.",
                );
                try err_out.flush();
                continue;
            },
            else => return err,
        };
        const line_bytes = raw_line orelse break;
        const line = std.mem.trim(u8, line_bytes, " \t\r");
        if (line.len == 0) continue;

        if (line[0] == '.') {
            if (std.mem.eql(u8, line, ".quit") or std.mem.eql(u8, line, ".exit")) break;
            if (std.mem.eql(u8, line, ".status")) {
                try printStatus(node, false, out);
                continue;
            }
            if (std.mem.eql(u8, line, ".tables")) {
                _ = try queryCommand(
                    gpa,
                    node,
                    "select name from sqlite_master where type = 'table' " ++
                        "and name not like '\\_\\_zaxon\\_%' escape '\\' order by name",
                    false,
                    out,
                    err_out,
                );
                continue;
            }
            try diagnostic.write(
                err_out,
                "unknown shell command",
                line,
                "Use .status, .tables, or .quit, or enter SQL.",
            );
            try err_out.flush();
            continue;
        }

        if (isReadStatement(line)) {
            _ = try queryCommand(gpa, node, line, false, out, err_out);
        } else {
            const sql = try gpa.dupeZ(u8, line);
            defer gpa.free(sql);
            _ = try execCommand(node, sql, .{ .command = "exec" }, out, err_out);
        }
        try err_out.flush();
    }
    return exit_ok;
}

fn isReadStatement(sql: []const u8) bool {
    var iterator = std.mem.tokenizeAny(u8, sql, " \t(");
    const first = iterator.next() orelse return false;
    const keywords = [_][]const u8{ "select", "with", "values", "explain" };
    for (keywords) |keyword| {
        if (std.ascii.eqlIgnoreCase(first, keyword)) return true;
    }
    return false;
}
