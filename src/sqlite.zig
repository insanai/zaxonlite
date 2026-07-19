//! Narrow SQLite bindings: exactly the C API subset zaxonlite needs.
//!
//! The rest of the product never includes the C header directly. Zaxonlite
//! pins the amalgamation, runs one writer connection per node in WAL mode
//! with automatic checkpoints disabled, and captures committed WAL frames
//! through `sqlite3_wal_hook` plus direct reads of the `-wal` file.

const std = @import("std");
const c = @import("c");

pub const Error = error{
    SqliteError,
    SqliteBusy,
    SqliteMisuse,
};

fn check(db: ?*c.sqlite3, rc: c_int) Error!void {
    switch (rc) {
        c.SQLITE_OK, c.SQLITE_DONE, c.SQLITE_ROW => {},
        c.SQLITE_BUSY, c.SQLITE_LOCKED => return error.SqliteBusy,
        c.SQLITE_MISUSE => return error.SqliteMisuse,
        else => {
            if (db != null and std.debug.runtime_safety) {
                std.log.debug("sqlite error {d}: {s}", .{ rc, c.sqlite3_errmsg(db) });
            }
            return error.SqliteError;
        },
    }
}

pub const WalHook = *const fn (
    context: ?*anyopaque,
    db: ?*c.sqlite3,
    database_name: [*c]const u8,
    frame_count: c_int,
) callconv(.c) c_int;

pub const Db = struct {
    handle: *c.sqlite3,

    pub fn open(path: [:0]const u8) Error!Db {
        var handle: ?*c.sqlite3 = null;
        const flags = c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_CREATE |
            c.SQLITE_OPEN_NOMUTEX | c.SQLITE_OPEN_EXRESCODE;
        const rc = c.sqlite3_open_v2(path.ptr, &handle, flags, null);
        if (rc != c.SQLITE_OK) {
            if (handle) |opened| _ = c.sqlite3_close(opened);
            return error.SqliteError;
        }
        return .{ .handle = handle.? };
    }

    pub fn close(self: *Db) void {
        _ = c.sqlite3_close(self.handle);
        self.* = undefined;
    }

    pub fn errmsg(self: *const Db) []const u8 {
        return std.mem.span(c.sqlite3_errmsg(self.handle));
    }

    /// Executes SQL statements without result rows (or discarding them).
    pub fn exec(self: *Db, sql: [:0]const u8) Error!void {
        try check(self.handle, c.sqlite3_exec(self.handle, sql.ptr, null, null, null));
    }

    pub fn prepare(self: *Db, sql: []const u8) Error!Stmt {
        var stmt: ?*c.sqlite3_stmt = null;
        var tail: [*c]const u8 = null;
        try check(self.handle, c.sqlite3_prepare_v2(
            self.handle,
            sql.ptr,
            @intCast(sql.len),
            &stmt,
            &tail,
        ));
        if (stmt == null) return error.SqliteMisuse;
        return .{ .handle = stmt.?, .db = self.handle };
    }

    pub fn changes(self: *const Db) i64 {
        return c.sqlite3_changes64(self.handle);
    }

    pub fn lastInsertRowId(self: *const Db) i64 {
        return c.sqlite3_last_insert_rowid(self.handle);
    }

    pub fn inTransaction(self: *const Db) bool {
        return c.sqlite3_get_autocommit(self.handle) == 0;
    }

    pub fn setWalHook(self: *Db, hook: WalHook, context: ?*anyopaque) void {
        _ = c.sqlite3_wal_hook(self.handle, hook, context);
    }

    /// Registers a WAL hook that stores the committed frame count after
    /// every commit into `counter`. The counter must outlive the hook.
    pub fn trackCommittedFrames(self: *Db, counter: *u32) void {
        self.setWalHook(frameCounterHook, counter);
    }

    /// Runs a TRUNCATE checkpoint; the WAL is empty afterwards. Requires no
    /// other connections and no open read transaction.
    pub fn checkpointTruncate(self: *Db) Error!void {
        var wal_frames: c_int = 0;
        var checkpointed: c_int = 0;
        try check(self.handle, c.sqlite3_wal_checkpoint_v2(
            self.handle,
            null,
            c.SQLITE_CHECKPOINT_TRUNCATE,
            &wal_frames,
            &checkpointed,
        ));
    }

    /// Returns the database page size via `PRAGMA page_size`.
    pub fn pageSize(self: *Db) Error!u32 {
        var stmt = try self.prepare("pragma page_size");
        defer stmt.finalize();
        if (!try stmt.step()) return error.SqliteError;
        return @intCast(stmt.columnInt64(0));
    }

    /// Runs `PRAGMA integrity_check` and returns true when it reports "ok".
    pub fn integrityCheckOk(self: *Db) Error!bool {
        var stmt = try self.prepare("pragma integrity_check");
        defer stmt.finalize();
        if (!try stmt.step()) return error.SqliteError;
        return std.mem.eql(u8, stmt.columnText(0), "ok");
    }
};

fn frameCounterHook(
    context: ?*anyopaque,
    db: ?*c.sqlite3,
    database_name: [*c]const u8,
    frame_count: c_int,
) callconv(.c) c_int {
    _ = db;
    _ = database_name;
    const counter: *u32 = @ptrCast(@alignCast(context.?));
    counter.* = @intCast(frame_count);
    return c.SQLITE_OK;
}

pub const Stmt = struct {
    handle: *c.sqlite3_stmt,
    db: *c.sqlite3,

    pub fn finalize(self: *Stmt) void {
        _ = c.sqlite3_finalize(self.handle);
        self.* = undefined;
    }

    pub fn reset(self: *Stmt) Error!void {
        try check(self.db, c.sqlite3_reset(self.handle));
    }

    pub fn isReadOnly(self: *const Stmt) bool {
        return c.sqlite3_stmt_readonly(self.handle) != 0;
    }

    /// Returns true when a result row is available.
    pub fn step(self: *Stmt) Error!bool {
        const rc = c.sqlite3_step(self.handle);
        if (rc == c.SQLITE_ROW) return true;
        if (rc == c.SQLITE_DONE) return false;
        try check(self.db, rc);
        return false;
    }

    /// Binds text without copying: `text` must stay alive until the
    /// statement finishes stepping or is reset. (The amalgamation's
    /// SQLITE_TRANSIENT macro is a -1 function pointer that Zig cannot
    /// represent, so the no-copy contract is explicit here instead.)
    pub fn bindText(self: *Stmt, index: u32, text: []const u8) Error!void {
        try check(self.db, c.sqlite3_bind_text(
            self.handle,
            @intCast(index),
            text.ptr,
            @intCast(text.len),
            null,
        ));
    }

    pub fn bindInt64(self: *Stmt, index: u32, value: i64) Error!void {
        try check(self.db, c.sqlite3_bind_int64(self.handle, @intCast(index), value));
    }

    pub fn bindNull(self: *Stmt, index: u32) Error!void {
        try check(self.db, c.sqlite3_bind_null(self.handle, @intCast(index)));
    }

    pub fn columnCount(self: *const Stmt) u32 {
        return @intCast(c.sqlite3_column_count(self.handle));
    }

    pub fn columnName(self: *const Stmt, index: u32) []const u8 {
        const name = c.sqlite3_column_name(self.handle, @intCast(index));
        if (name == null) return "";
        return std.mem.span(name);
    }

    pub fn columnType(self: *const Stmt, index: u32) c_int {
        return c.sqlite3_column_type(self.handle, @intCast(index));
    }

    pub fn columnInt64(self: *const Stmt, index: u32) i64 {
        return c.sqlite3_column_int64(self.handle, @intCast(index));
    }

    pub fn columnText(self: *const Stmt, index: u32) []const u8 {
        const len: usize = @intCast(c.sqlite3_column_bytes(self.handle, @intCast(index)));
        const ptr = c.sqlite3_column_text(self.handle, @intCast(index));
        if (ptr == null) return "";
        return @as([*]const u8, @ptrCast(ptr))[0..len];
    }

    pub fn isColumnNull(self: *const Stmt, index: u32) bool {
        return self.columnType(index) == c.SQLITE_NULL;
    }
};

const testing = std.testing;

test "narrow bindings execute and query" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const dir_path = try tmp.dir.realPath(testing.io, &path_buffer);
    var path_z_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const db_path = try std.fmt.bufPrintZ(
        &path_z_buffer,
        "{s}/t.db",
        .{path_buffer[0..dir_path]},
    );

    var db = try Db.open(db_path);
    defer db.close();
    try db.exec("create table t(a integer, b text)");
    try db.exec("insert into t values (1, 'one'), (2, 'two')");
    try testing.expectEqual(@as(i64, 2), db.changes());

    var stmt = try db.prepare("select b from t where a = ?1");
    defer stmt.finalize();
    try stmt.bindInt64(1, 2);
    try testing.expect(try stmt.step());
    try testing.expectEqualStrings("two", stmt.columnText(0));
    try testing.expect(!try stmt.step());
    try testing.expect(try db.integrityCheckOk());
}
