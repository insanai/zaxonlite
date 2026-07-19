//! The zaxonlite C ABI: an embeddable replicated SQLite node behind a
//! small, stable C surface (see `include/zaxonlite.h`).
//!
//! Every handle owns its own `std.Io.Threaded` instance and node; handles
//! are independent and must be used from one thread at a time (or under
//! the caller's lock), matching SQLite's own connection discipline.
//!
//! Return codes mirror the CLI contract:
//!   0 ok, 1 SQL/session error, 2 misuse, 3 integrity failure,
//!   4 unavailable (locked, corrupt, or I/O failure).

const std = @import("std");
const zaxonlite = @import("zaxonlite");

const Node = zaxonlite.Node;

const ok_code: c_int = 0;
const sql_code: c_int = 1;
const misuse_code: c_int = 2;
const integrity_code: c_int = 3;
const unavailable_code: c_int = 4;

const Handle = struct {
    threaded: std.Io.Threaded,
    node: *Node,
    error_buffer: [512:0]u8 = undefined,

    fn setError(self: *Handle, text: []const u8) void {
        const len = @min(text.len, self.error_buffer.len - 1);
        @memcpy(self.error_buffer[0..len], text[0..len]);
        self.error_buffer[len] = 0;
    }
};

const gpa = std.heap.c_allocator;

fn handleOf(pointer: ?*anyopaque) ?*Handle {
    return @ptrCast(@alignCast(pointer orelse return null));
}

fn mapError(handle: *Handle, err: anyerror) c_int {
    switch (err) {
        error.SqliteError, error.SqliteBusy => {
            handle.setError(handle.node.lastSqliteMessage());
            return sql_code;
        },
        error.UnknownSession, error.SequenceGap, error.ResultExpired => {
            handle.setError(@errorName(err));
            return sql_code;
        },
        error.WriteInReadQuery => {
            handle.setError("statement is not read-only");
            return misuse_code;
        },
        else => {
            handle.setError(@errorName(err));
            return unavailable_code;
        },
    }
}

export fn zaxonlite_version() [*:0]const u8 {
    return zaxonlite.version;
}

/// Opens (or creates) a node data directory. On success stores the handle
/// in `out_handle`.
export fn zaxonlite_open(
    directory: ?[*:0]const u8,
    out_handle: ?*?*anyopaque,
) c_int {
    const dir = directory orelse return misuse_code;
    const out = out_handle orelse return misuse_code;
    out.* = null;

    const handle = gpa.create(Handle) catch return unavailable_code;
    handle.* = .{
        .threaded = std.Io.Threaded.init(gpa, .{}),
        .node = undefined,
    };
    handle.error_buffer[0] = 0;
    const io = handle.threaded.io();

    handle.node = Node.open(gpa, io, .{
        .directory = std.mem.span(dir),
    }) catch |err| {
        handle.threaded.deinit();
        gpa.destroy(handle);
        return switch (err) {
            error.NodeLocked => unavailable_code,
            else => unavailable_code,
        };
    };
    out.* = handle;
    return ok_code;
}

export fn zaxonlite_close(pointer: ?*anyopaque) void {
    const handle = handleOf(pointer) orelse return;
    handle.node.close();
    handle.threaded.deinit();
    gpa.destroy(handle);
}

/// Executes one replicated write transaction.
export fn zaxonlite_exec(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    changes_out: ?*i64,
) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const result = handle.node.exec(std.mem.span(statement)) catch |err|
        return mapError(handle, err);
    if (changes_out) |out| out.* = result.changes;
    return ok_code;
}

/// Opens a replicated client session for idempotent retry.
export fn zaxonlite_session_open(
    pointer: ?*anyopaque,
    session_out: ?*u64,
) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    const out = session_out orelse return misuse_code;
    out.* = handle.node.openSession() catch |err| return mapError(handle, err);
    return ok_code;
}

/// Executes `sequence` for `session` exactly once; a repeat of the last
/// sequence sets `replayed_out` and returns the recorded change count.
export fn zaxonlite_exec_idempotent(
    pointer: ?*anyopaque,
    session: u64,
    sequence: u64,
    sql: ?[*:0]const u8,
    changes_out: ?*i64,
    replayed_out: ?*bool,
) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const result = handle.node.execIdempotent(
        session,
        sequence,
        std.mem.span(statement),
    ) catch |err| return mapError(handle, err);
    if (changes_out) |out| out.* = result.changes;
    if (replayed_out) |out| out.* = result.replayed;
    return ok_code;
}

/// Runs a read-only query and returns one JSON object
/// `{"columns":[...],"rows":[[...]]}` in `json_out`, released with
/// `zaxonlite_free`.
export fn zaxonlite_query_json(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    json_out: ?*?[*:0]u8,
) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const out = json_out orelse return misuse_code;
    out.* = null;

    var result = handle.node.query(gpa, std.mem.span(statement)) catch |err|
        return mapError(handle, err);
    defer result.deinit();

    var buffer: std.Io.Writer.Allocating = .init(gpa);
    defer buffer.deinit();
    const writer = &buffer.writer;
    writeJson(writer, &result) catch return unavailable_code;
    writer.writeByte(0) catch return unavailable_code;
    const owned = buffer.toOwnedSlice() catch return unavailable_code;
    out.* = @ptrCast(owned.ptr);
    return ok_code;
}

fn writeJson(writer: *std.Io.Writer, result: *const zaxonlite.QueryResult) !void {
    try writer.writeAll("{\"columns\":[");
    for (result.columns, 0..) |column, index| {
        if (index > 0) try writer.writeAll(",");
        try zaxonlite.server.writeJsonString(writer, column);
    }
    try writer.writeAll("],\"rows\":[");
    for (result.rows, 0..) |row, row_index| {
        if (row_index > 0) try writer.writeAll(",");
        try writer.writeAll("[");
        for (row, 0..) |cell, index| {
            if (index > 0) try writer.writeAll(",");
            if (cell) |text| {
                try zaxonlite.server.writeJsonString(writer, text);
            } else {
                try writer.writeAll("null");
            }
        }
        try writer.writeAll("]");
    }
    try writer.writeAll("]}");
}

/// Releases a buffer returned by `zaxonlite_query_json`.
export fn zaxonlite_free(pointer: ?[*:0]u8) void {
    const raw = pointer orelse return;
    gpa.free(std.mem.span(raw));
}

/// Takes an online snapshot and seals the current journal epoch.
export fn zaxonlite_snapshot(pointer: ?*anyopaque) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    handle.node.snapshot() catch |err| return mapError(handle, err);
    return ok_code;
}

/// Streams a consistent logical backup to `path`.
export fn zaxonlite_backup(pointer: ?*anyopaque, path: ?[*:0]const u8) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    const destination = path orelse return misuse_code;
    handle.node.backup(std.mem.span(destination)) catch |err|
        return mapError(handle, err);
    return ok_code;
}

/// Verifies the SQLite image, the descriptor chain, and payload
/// availability. Returns 0 when everything passes, 3 otherwise.
export fn zaxonlite_integrity_check(pointer: ?*anyopaque) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    const report = handle.node.integrityCheck() catch |err|
        return mapError(handle, err);
    return if (report.ok()) ok_code else integrity_code;
}

/// Deletes sessions idle for more than `retain` recent session writes.
export fn zaxonlite_expire_sessions(
    pointer: ?*anyopaque,
    retain: u64,
    expired_out: ?*i64,
) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    const result = handle.node.expireSessions(retain) catch |err|
        return mapError(handle, err);
    if (expired_out) |out| out.* = result.changes;
    return ok_code;
}

/// The most recent error message for this handle.
export fn zaxonlite_last_error(pointer: ?*anyopaque) [*:0]const u8 {
    const handle = handleOf(pointer) orelse return "invalid handle";
    return &handle.error_buffer;
}
