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
const Value = zaxonlite.Value;
const Embedded = zaxonlite.Embedded;

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

const TransactionHandle = struct {
    owner: *Handle,
    transaction: zaxonlite.Transaction,
};

const ClusterHandle = struct {
    threaded: std.Io.Threaded,
    embedded: *Embedded,
    error_buffer: [512:0]u8 = undefined,

    fn setError(self: *ClusterHandle, text: []const u8) void {
        const len = @min(text.len, self.error_buffer.len - 1);
        @memcpy(self.error_buffer[0..len], text[0..len]);
        self.error_buffer[len] = 0;
    }
};

const CMember = extern struct {
    id: u32,
    address: ?[*:0]const u8,
    role: c_int,
};

const CClusterOptions = extern struct {
    directory: ?[*:0]const u8,
    node_id: u32,
    members: ?[*]const CMember,
    member_count: usize,
    cluster_id: ?[*:0]const u8,
    auth_secret: ?*const anyopaque,
    auth_secret_length: usize,
    tls_cert_path: ?[*:0]const u8,
    tls_key_path: ?[*:0]const u8,
    tls_ca_path: ?[*:0]const u8,
    startup_timeout_ms: u64,
    allow_insecure_test_tcp: bool,
};

const CValue = extern struct {
    value_type: c_int,
    integer: i64,
    real: f64,
    bytes: ?*const anyopaque,
    length: usize,
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
        error.WriteInReadQuery, error.ParameterCountMismatch => {
            handle.setError("statement is not read-only");
            return misuse_code;
        },
        error.TransactionFinished,
        error.EmptyTransaction,
        error.TooManyStatements,
        error.TransactionInputTooLarge,
        => {
            handle.setError(@errorName(err));
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

/// Opens a transport-owning embedded cluster member.
export fn zaxonlite_cluster_open(
    raw_options: ?*const CClusterOptions,
    out_handle: ?*?*anyopaque,
) c_int {
    const options = raw_options orelse return misuse_code;
    const out = out_handle orelse return misuse_code;
    out.* = null;
    const directory = options.directory orelse return misuse_code;
    const raw_members = options.members orelse return misuse_code;
    // Every declared count is reduced to the product limit before any
    // slice is formed or allocation sized from it.
    if (options.member_count == 0 or
        options.member_count > zaxonlite.embedded.max_registry_members)
    {
        return misuse_code;
    }
    const secret = parseAuthSecret(options) catch return misuse_code;

    const members = parseClusterMembers(options) catch |err| switch (err) {
        error.Misuse => return misuse_code,
        error.Unavailable => return unavailable_code,
        else => return unavailable_code,
    };
    defer gpa.free(members);

    const handle = gpa.create(ClusterHandle) catch return unavailable_code;
    handle.* = .{
        .threaded = std.Io.Threaded.init(gpa, .{}),
        .embedded = undefined,
    };
    handle.error_buffer[0] = 0;
    const timeout = if (options.startup_timeout_ms == 0) 10_000 else options.startup_timeout_ms;
    const any_tls = options.tls_cert_path != null or
        options.tls_key_path != null or options.tls_ca_path != null;
    if (any_tls and (options.tls_cert_path == null or
        options.tls_key_path == null or options.tls_ca_path == null))
    {
        handle.threaded.deinit();
        gpa.destroy(handle);
        return misuse_code;
    }
    handle.embedded = Embedded.open(gpa, handle.threaded.io(), .{
        .directory = std.mem.span(directory),
        .node_id = options.node_id,
        .members = members,
        .cluster_id = if (options.cluster_id) |text| std.mem.span(text) else null,
        .auth_secret = secret,
        .tls = if (any_tls) .{
            .cert_path = std.mem.span(options.tls_cert_path.?),
            .key_path = std.mem.span(options.tls_key_path.?),
            .ca_path = std.mem.span(options.tls_ca_path.?),
        } else null,
        .startup_timeout_ms = timeout,
        .allow_insecure_test_tcp = options.allow_insecure_test_tcp,
    }) catch {
        handle.threaded.deinit();
        gpa.destroy(handle);
        return unavailable_code;
    };
    out.* = handle;
    return ok_code;
}

fn parseAuthSecret(options: *const CClusterOptions) !?[]const u8 {
    if (options.auth_secret) |pointer| {
        if (options.auth_secret_length == 0 or
            options.auth_secret_length > zaxonlite.configuration.maximum_secret_file_bytes)
        {
            return error.Misuse;
        }
        return @as([*]const u8, @ptrCast(pointer))[0..options.auth_secret_length];
    } else if (options.auth_secret_length == 0) {
        return null;
    }
    return error.Misuse;
}

fn parseClusterMembers(options: *const CClusterOptions) ![]zaxonlite.EmbeddedMember {
    const raw_members = options.members orelse return error.Misuse;
    const members = gpa.alloc(zaxonlite.EmbeddedMember, options.member_count) catch
        return error.Unavailable;
    errdefer gpa.free(members);
    for (raw_members[0..options.member_count], members) |source, *destination| {
        const address = source.address orelse return error.Misuse;
        const role = std.enums.fromInt(zaxonlite.Role, source.role) orelse return error.Misuse;
        destination.* = .{
            .id = source.id,
            .address = std.mem.span(address),
            .role = role,
        };
    }
    return members;
}

export fn zaxonlite_cluster_close(pointer: ?*anyopaque) void {
    const handle: *ClusterHandle = @ptrCast(@alignCast(pointer orelse return));
    handle.embedded.close();
    handle.threaded.deinit();
    gpa.destroy(handle);
}

export fn zaxonlite_cluster_exec(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    changes_out: ?*i64,
) c_int {
    if (changes_out) |out| out.* = 0;
    const handle: *ClusterHandle = @ptrCast(@alignCast(
        pointer orelse return misuse_code,
    ));
    const statement = sql orelse return misuse_code;
    const result = handle.embedded.exec(std.mem.span(statement)) catch |err| {
        handle.setError(@errorName(err));
        return unavailable_code;
    };
    if (changes_out) |out| out.* = result.changes;
    return ok_code;
}

export fn zaxonlite_cluster_query_json(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    json_out: ?*?[*:0]u8,
) c_int {
    const handle: *ClusterHandle = @ptrCast(@alignCast(
        pointer orelse return misuse_code,
    ));
    const statement = sql orelse return misuse_code;
    const out = json_out orelse return misuse_code;
    out.* = null;
    var result = handle.embedded.query(gpa, std.mem.span(statement)) catch |err| {
        handle.setError(@errorName(err));
        return unavailable_code;
    };
    defer result.deinit();
    return resultJson(&result, out);
}

export fn zaxonlite_cluster_call_json(
    pointer: ?*anyopaque,
    request: ?[*:0]const u8,
    require_leader: bool,
    json_out: ?*?[*:0]u8,
) c_int {
    const handle: *ClusterHandle = @ptrCast(@alignCast(
        pointer orelse return misuse_code,
    ));
    const body = request orelse return misuse_code;
    const out = json_out orelse return misuse_code;
    out.* = null;
    const response = handle.embedded.call(
        std.mem.span(body),
        require_leader,
    ) catch |err| {
        handle.setError(@errorName(err));
        return unavailable_code;
    };
    defer gpa.free(response);
    const owned = gpa.alloc(u8, response.len + 1) catch return unavailable_code;
    @memcpy(owned[0..response.len], response);
    owned[response.len] = 0;
    out.* = @ptrCast(owned.ptr);
    return ok_code;
}

export fn zaxonlite_cluster_last_error(pointer: ?*anyopaque) [*:0]const u8 {
    const handle: *ClusterHandle = @ptrCast(@alignCast(
        pointer orelse return "invalid cluster handle",
    ));
    return &handle.error_buffer;
}

/// Executes one replicated write transaction.
export fn zaxonlite_exec(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    changes_out: ?*i64,
) c_int {
    if (changes_out) |out| out.* = 0;
    const handle = handleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const result = handle.node.exec(std.mem.span(statement)) catch |err|
        return mapError(handle, err);
    if (changes_out) |out| out.* = result.changes;
    return ok_code;
}

export fn zaxonlite_exec_prepared(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    raw_values: ?[*]const CValue,
    value_count: usize,
    changes_out: ?*i64,
) c_int {
    if (changes_out) |out| out.* = 0;
    const handle = handleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const values = valuesFromC(raw_values, value_count) catch |err| {
        handle.setError(@errorName(err));
        return misuse_code;
    };
    defer gpa.free(values);
    const result = handle.node.execPrepared(
        std.mem.span(statement),
        values,
    ) catch |err| return mapError(handle, err);
    if (changes_out) |out| out.* = result.changes;
    return ok_code;
}

export fn zaxonlite_transaction_begin(
    pointer: ?*anyopaque,
    out_transaction: ?*?*anyopaque,
) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    const out = out_transaction orelse return misuse_code;
    out.* = null;
    const transaction = gpa.create(TransactionHandle) catch return unavailable_code;
    transaction.* = .{
        .owner = handle,
        .transaction = zaxonlite.Transaction.init(gpa),
    };
    out.* = transaction;
    return ok_code;
}

export fn zaxonlite_transaction_exec(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    raw_values: ?[*]const CValue,
    value_count: usize,
) c_int {
    const transaction: *TransactionHandle = @ptrCast(@alignCast(
        pointer orelse return misuse_code,
    ));
    const statement = sql orelse return misuse_code;
    const values = valuesFromC(raw_values, value_count) catch |err| {
        transaction.owner.setError(@errorName(err));
        return misuse_code;
    };
    defer gpa.free(values);
    transaction.transaction.exec(std.mem.span(statement), values) catch |err| {
        transaction.owner.setError(@errorName(err));
        return misuse_code;
    };
    return ok_code;
}

export fn zaxonlite_transaction_commit(
    pointer: ?*anyopaque,
    changes_out: ?*i64,
) c_int {
    if (changes_out) |out| out.* = 0;
    const transaction: *TransactionHandle = @ptrCast(@alignCast(
        pointer orelse return misuse_code,
    ));
    const result = transaction.owner.node.execTransaction(
        &transaction.transaction,
    ) catch |err| return mapError(transaction.owner, err);
    if (changes_out) |out| out.* = result.changes;
    return ok_code;
}

export fn zaxonlite_transaction_close(pointer: ?*anyopaque) void {
    const transaction: *TransactionHandle = @ptrCast(@alignCast(
        pointer orelse return,
    ));
    transaction.transaction.deinit();
    gpa.destroy(transaction);
}

/// Opens a replicated client session for idempotent retry.
export fn zaxonlite_session_open(
    pointer: ?*anyopaque,
    session_out: ?*u64,
) c_int {
    const out = session_out orelse return misuse_code;
    out.* = 0;
    const handle = handleOf(pointer) orelse return misuse_code;
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
    if (changes_out) |out| out.* = 0;
    if (replayed_out) |out| out.* = false;
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

    return queryPreparedJson(handle, std.mem.span(statement), &.{}, out);
}

export fn zaxonlite_query_prepared_json(
    pointer: ?*anyopaque,
    sql: ?[*:0]const u8,
    raw_values: ?[*]const CValue,
    value_count: usize,
    json_out: ?*?[*:0]u8,
) c_int {
    const handle = handleOf(pointer) orelse return misuse_code;
    const statement = sql orelse return misuse_code;
    const out = json_out orelse return misuse_code;
    out.* = null;
    const values = valuesFromC(raw_values, value_count) catch |err| {
        handle.setError(@errorName(err));
        return misuse_code;
    };
    defer gpa.free(values);
    return queryPreparedJson(handle, std.mem.span(statement), values, out);
}

fn queryPreparedJson(
    handle: *Handle,
    sql: []const u8,
    values: []const Value,
    out: *?[*:0]u8,
) c_int {
    var result = handle.node.queryPrepared(gpa, sql, values) catch |err|
        return mapError(handle, err);
    defer result.deinit();

    return resultJson(&result, out);
}

fn resultJson(result: *const zaxonlite.QueryResult, out: *?[*:0]u8) c_int {
    var buffer: std.Io.Writer.Allocating = .init(gpa);
    defer buffer.deinit();
    const writer = &buffer.writer;
    writeJson(writer, result) catch return unavailable_code;
    writer.writeByte(0) catch return unavailable_code;
    const owned = buffer.toOwnedSlice() catch return unavailable_code;
    out.* = @ptrCast(owned.ptr);
    return ok_code;
}

fn valuesFromC(raw_values: ?[*]const CValue, count: usize) ![]Value {
    if (count == 0) return gpa.alloc(Value, 0);
    const source = raw_values orelse return error.NullValues;
    // Checked before the count sizes an allocation or slices caller memory.
    if (count > zaxonlite.prepared.maximum_statements * 64) {
        return error.TooManyValues;
    }
    const values = try gpa.alloc(Value, count);
    errdefer gpa.free(values);
    for (source[0..count], values) |source_value, *destination| {
        destination.* = switch (source_value.value_type) {
            0 => .null_value,
            1 => .{ .integer = source_value.integer },
            2 => .{ .real = source_value.real },
            3 => .{ .text = try cBytes(source_value) },
            4 => .{ .blob = try cBytes(source_value) },
            else => return error.InvalidValueType,
        };
    }
    return values;
}

fn cBytes(value: CValue) ![]const u8 {
    if (value.length == 0) return "";
    // A declared length beyond the transaction input limit can never be
    // valid, so it is rejected before the caller's memory is sliced.
    if (value.length > zaxonlite.prepared.maximum_input_bytes) {
        return error.ValueTooLarge;
    }
    const pointer = value.bytes orelse return error.NullValueBytes;
    return @as([*]const u8, @ptrCast(pointer))[0..value.length];
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
    const body = std.mem.span(raw);
    gpa.free(raw[0 .. body.len + 1]);
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
    if (expired_out) |out| out.* = 0;
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
