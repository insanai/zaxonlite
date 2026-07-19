//! zaxon: the zaxonlite command line.
//!
//! Two modes share one command surface:
//! * embedded (`--data <dir>`): the command opens the node in-process,
//!   exactly as an embedding application would;
//! * client (`--connect host:port[,host:port...]`): the command speaks the
//!   RPC protocol to running `zaxon serve` processes, following leader
//!   redirects.
//!
//! `zaxon serve` hosts one node behind a TCP endpoint, alone or as one of
//! three voters.

const std = @import("std");
const zaxonlite = @import("zaxonlite");

const Node = zaxonlite.Node;
const server = zaxonlite.server;
const client = zaxonlite.client;

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
    \\  zaxon serve --data <dir> --node <id> --listen host:port
    \\        [--peer <id>@host:port ...] [--cluster-id <text>]
    \\        [--enable-failpoints]
    \\
    \\Commands:
    \\  sql               Interactive SQL shell (embedded or client mode).
    \\  exec              Execute SQL; --session/--sequence for idempotent retry.
    \\  query             Read-only query. --json; --level any|leader|linearizable.
    \\  session           Open a client session and print its ID.
    \\  status            Show node status. --json for automation.
    \\  leader            Show the current leader (client mode).
    \\  wait              Wait for --applied <slot> and/or --leader (client mode).
    \\  snapshot          Take a snapshot and seal the current journal epoch.
    \\  backup            Stream a consistent logical backup. --to <path>.
    \\  integrity-check   Verify SQLite image, descriptor chain, and payloads.
    \\  expire-sessions   Delete idle sessions; --retain <n> newest activity.
    \\  serve             Host this node behind a TCP endpoint.
    \\  stop              Ask a served node to shut down (client mode).
    \\  version           Print the zaxonlite version.
    \\
    \\Options:
    \\  --data <dir>        Node data directory (created when missing).
    \\  --connect <list>    Comma-separated server endpoints for client mode.
    \\  --sql <text>        SQL for exec/query.
    \\  --session <id>      Session ID for exec.
    \\  --sequence <n>      Monotonic per-session sequence for exec.
    \\  --level <level>     Read level for query (default leader).
    \\  --to <path>         Backup destination path.
    \\  --retain <n>        Activity window for expire-sessions.
    \\  --applied <slot>    Slot to wait for (wait).
    \\  --leader            Also wait for a known leader (wait).
    \\  --timeout-ms <n>    Wait deadline in milliseconds.
    \\  --node <id>         This node's ID (serve).
    \\  --listen host:port  Listen endpoint (serve).
    \\  --peer id@host:port Voting peer (repeat; serve).
    \\  --cluster-id <text> Extra entropy for the derived database identity.
    \\  --enable-failpoints Honor failpoint RPCs (test controllers only).
    \\  --json              Machine-readable output on stdout.
    \\
    \\Exit codes: 0 ok, 1 SQL/session error, 2 usage, 3 integrity failure,
    \\4 node unavailable (locked, corrupt, or no leader).
    \\
;

const Options = struct {
    command: []const u8,
    data: ?[]const u8 = null,
    connect: ?[]const u8 = null,
    sql: ?[:0]const u8 = null,
    session: ?u64 = null,
    sequence: ?u64 = null,
    level: ?[]const u8 = null,
    to: ?[]const u8 = null,
    retain: ?u64 = null,
    applied: ?u64 = null,
    wait_leader: bool = false,
    timeout_ms: ?u64 = null,
    node_id: ?u32 = null,
    listen: ?[]const u8 = null,
    peers: std.ArrayList([]const u8) = .empty,
    cluster_id: ?[]const u8 = null,
    enable_failpoints: bool = false,
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

    const code = run(gpa, io, init.minimal.args, out, err_out) catch |err| blk: {
        err_out.print("zaxon: {s}\n", .{@errorName(err)}) catch {};
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
        if (std.mem.eql(u8, arg, "--data")) {
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
        } else if (std.mem.eql(u8, arg, "--peer")) {
            const text = iterator.next() orelse return usageError(err_out, "--peer needs a value");
            try options.peers.append(gpa, text);
        } else if (std.mem.eql(u8, arg, "--cluster-id")) {
            options.cluster_id = iterator.next() orelse return usageError(err_out, "--cluster-id needs a value");
        } else if (std.mem.eql(u8, arg, "--enable-failpoints")) {
            options.enable_failpoints = true;
        } else if (std.mem.eql(u8, arg, "--json")) {
            options.json = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try out.writeAll(usage_text);
            return exit_ok;
        } else {
            try err_out.print("zaxon: unknown option '{s}'\n", .{arg});
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
    if (std.mem.eql(u8, command, "serve")) {
        return serveCommand(gpa, io, &options, err_out);
    }
    if (options.connect != null) {
        return remote(gpa, io, &options, out, err_out);
    }

    const data = options.data orelse
        return usageError(err_out, "--data <dir> or --connect is required");

    const node = Node.open(gpa, io, .{ .directory = data }) catch |err| switch (err) {
        error.NodeLocked => {
            try err_out.writeAll("zaxon: node directory is locked by another process\n");
            return exit_unavailable;
        },
        else => {
            try err_out.print("zaxon: cannot open node: {s}\n", .{@errorName(err)});
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
                try err_out.print("zaxon: backup failed: {s}\n", .{node.lastSqliteMessage()});
                return exit_sql;
            },
            else => return err,
        };
        try out.print("backup written to {s}\n", .{destination});
        return exit_ok;
    } else if (std.mem.eql(u8, command, "integrity-check")) {
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
        }
        return if (report.ok()) exit_ok else exit_integrity;
    } else if (std.mem.eql(u8, command, "expire-sessions")) {
        const retain = options.retain orelse
            return usageError(err_out, "expire-sessions needs --retain");
        const result = try node.expireSessions(retain);
        try out.print("{d} session(s) expired\n", .{result.changes});
        return exit_ok;
    }

    try err_out.print("zaxon: unknown command '{s}'\n", .{command});
    try out.writeAll(usage_text);
    return exit_usage;
}

fn usageError(err_out: *std.Io.Writer, message: []const u8) !u8 {
    try err_out.print("zaxon: {s}\n", .{message});
    return exit_usage;
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
    err_out: *std.Io.Writer,
) !u8 {
    const data = options.data orelse
        return usageError(err_out, "serve needs --data");
    const node_id = options.node_id orelse
        return usageError(err_out, "serve needs --node");
    const listen_text = options.listen orelse
        return usageError(err_out, "serve needs --listen");
    const listen = client.Endpoint.parse(listen_text) catch
        return usageError(err_out, "--listen must be host:port");

    var members: std.ArrayList(server.PeerAddress) = .empty;
    defer members.deinit(gpa);
    try members.append(gpa, .{
        .id = node_id,
        .host = listen.host,
        .port = listen.port,
    });
    for (options.peers.items) |peer_text| {
        const at = std.mem.indexOfScalar(u8, peer_text, '@') orelse
            return usageError(err_out, "--peer must be id@host:port");
        const id = std.fmt.parseInt(u32, peer_text[0..at], 10) catch
            return usageError(err_out, "--peer must be id@host:port");
        if (id == node_id) continue;
        const endpoint = client.Endpoint.parse(peer_text[at + 1 ..]) catch
            return usageError(err_out, "--peer must be id@host:port");
        try members.append(gpa, .{
            .id = id,
            .host = endpoint.host,
            .port = endpoint.port,
        });
    }

    const database_id: ?u128 = if (members.items.len > 1)
        server.deriveDatabaseId(members.items, options.cluster_id)
    else
        null;

    return server.serve(gpa, io, .{
        .directory = data,
        .node_id = node_id,
        .listen_host = listen.host,
        .listen_port = listen.port,
        .members = members.items,
        .database_id = database_id,
        .enable_failpoints = options.enable_failpoints,
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
    out: *std.Io.Writer,
    err_out: *std.Io.Writer,
) !u8 {
    var endpoints = parseEndpoints(gpa, options.connect.?) catch
        return usageError(err_out, "--connect must be host:port[,host:port...]");
    defer endpoints.deinit(gpa);

    const command = options.command;
    if (std.mem.eql(u8, command, "sql")) {
        return remoteShell(gpa, io, endpoints.items, out, err_out);
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
        const level = options.level orelse "leader";
        require_leader = !std.mem.eql(u8, level, "any");
        try writer.writeAll("{\"op\":\"query\",\"sql\":");
        try writeJsonString(writer, sql);
        try writer.print(",\"level\":\"{s}\"}}", .{level});
    } else if (std.mem.eql(u8, command, "status")) {
        require_leader = false;
        try writer.writeAll("{\"op\":\"status\"}");
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
    } else if (std.mem.eql(u8, command, "stop")) {
        require_leader = false;
        try writer.writeAll("{\"op\":\"stop\"}");
    } else {
        try err_out.print("zaxon: command '{s}' is not available in client mode\n", .{command});
        return exit_usage;
    }

    const result = client.callCluster(
        gpa,
        io,
        endpoints.items,
        request.written(),
        require_leader,
    ) catch {
        try err_out.writeAll("zaxon: no reachable leader\n");
        return exit_unavailable;
    };
    defer gpa.free(result.body);
    return renderRemote(gpa, options, result.body, out, err_out);
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
        try err_out.print("zaxon: malformed response: {s}\n", .{body});
        return exit_unavailable;
    };
    defer parsed.deinit();
    const object = switch (parsed.value) {
        .object => |*obj| obj,
        else => {
            try err_out.print("zaxon: malformed response: {s}\n", .{body});
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
            try err_out.print("zaxon: {s}: {s}\n", .{ code, message });
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

    while (true) {
        try out.writeAll("zaxon> ");
        try out.flush();
        const raw_line = in.takeDelimiter('\n') catch |err| switch (err) {
            error.StreamTooLong => {
                try err_out.writeAll("zaxon: input line too long\n");
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
                try err_out.print("zaxon: unknown dot command '{s}'\n", .{line});
                try err_out.flush();
                continue;
            }
        } else if (isReadStatement(line)) {
            try request.writer.writeAll("{\"op\":\"query\",\"sql\":");
            try writeJsonString(&request.writer, line);
            try request.writer.writeAll(",\"level\":\"leader\"}");
        } else {
            pseudo.command = "exec";
            try request.writer.writeAll("{\"op\":\"exec\",\"sql\":");
            try writeJsonString(&request.writer, line);
            try request.writer.writeAll("}");
        }

        const result = client.callCluster(
            gpa,
            io,
            endpoints,
            request.written(),
            true,
        ) catch {
            try err_out.writeAll("zaxon: no reachable leader\n");
            try err_out.flush();
            continue;
        };
        defer gpa.free(result.body);
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
            try err_out.print("zaxon: sql error: {s}\n", .{node.lastSqliteMessage()});
            return exit_sql;
        },
        error.UnknownSession, error.SequenceGap, error.ResultExpired => {
            try err_out.print("zaxon: session error: {s}\n", .{@errorName(err)});
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
            try err_out.print("zaxon: query error: {s}\n", .{message});
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
                "\"leader\":{?d}," ++
                "\"decided_slot\":{d},\"applied_slot\":{d}," ++
                "\"journal_records\":{d},\"epoch_capacity\":{d}," ++
                "\"chain\":\"{s}\",\"page_size\":{d},\"snapshot\":",
            .{
                status.node_id,          status.database_id,
                status.configuration_id, status.role,
                status.leader,           status.decided_slot,
                status.applied_slot,     status.journal_records,
                status.epoch_capacity,   &chain_hex,
                status.page_size,
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
                try err_out.writeAll("zaxon: input line too long\n");
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
            try err_out.print("zaxon: unknown dot command '{s}'\n", .{line});
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
