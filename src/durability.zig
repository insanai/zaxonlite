//! Small POSIX durability helpers shared by the storage components.
//!
//! Syncing file contents does not necessarily persist the directory entry
//! created by link/rename. Callers sync the relevant parent after every
//! authoritative pathname transition.
//!
//! Sync policy: on macOS, `fsync(2)` flushes data to the drive but not
//! the drive's volatile cache to stable media, so acknowledged writes can
//! vanish on power loss. For a consensus journal that is a safety issue,
//! not merely data loss: a voter that forgets an acknowledged promise can
//! vote again and break quorum intersection. The `full` mode therefore
//! issues `fcntl(F_FULLFSYNC)` on Darwin (falling back to `fsync` on
//! filesystems that refuse it), and is the default for real binaries.
//! The `os` mode keeps the platform `fsync`; process-crash recovery is
//! identical under both, only power-loss durability differs. On other
//! supported platforms the modes are equivalent.
//!
//! Group fsync: `F_FULLFSYNC` flushes the drive's entire cache, so one
//! barrier per commit point suffices for every block already handed to
//! the drive. The `...BeforeBarrier` variants therefore issue only the
//! platform `fsync` — moving the bytes from the page cache into the
//! drive — and rely on the caller's next `syncFile`/`syncDirectory`
//! barrier on the same volume to make them power-loss durable. The
//! write path uses this to pay exactly one full flush per replicated
//! write (the journal sync inside `consumeEffects`), which precedes
//! every vote, acknowledgement, and outgoing envelope.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

pub const SyncMode = enum { os, full };

/// Process-wide policy, set once during startup before any storage I/O
/// or thread creation. Test builds default to `os`: the crash campaigns
/// simulate process death, which loses nothing under either mode, and a
/// laptop-development loop should not pay the full-flush latency.
var sync_mode: SyncMode = if (builtin.is_test)
    .os
else if (builtin.os.tag.isDarwin())
    .full
else
    .os;

pub fn setSyncMode(mode: SyncMode) void {
    sync_mode = mode;
}

pub fn syncMode() SyncMode {
    return sync_mode;
}

/// Makes `file`'s written contents durable under the configured policy.
pub fn syncFile(io: Io, file: Io.File) !void {
    if (comptime builtin.os.tag.isDarwin()) {
        if (sync_mode == .full and fullFsync(file.handle)) return;
    }
    try file.sync(io);
}

pub fn syncDirectory(dir: Io.Dir) !void {
    if (comptime builtin.os.tag == .windows) {
        // The threaded Windows backend's atomic replacement has different
        // handle semantics; Windows is not in the current supported matrix.
        return error.UnsupportedDurabilityPlatform;
    }
    if (comptime builtin.os.tag.isDarwin()) {
        if (sync_mode == .full and fullFsync(dir.handle)) return;
    }
    if (std.c.fsync(dir.handle) != 0) return error.DirectorySyncFailed;
}

pub fn syncChildDirectory(io: Io, parent: Io.Dir, path: []const u8) !void {
    var child = try parent.openDir(io, path, .{});
    defer child.close(io);
    try syncDirectory(child);
}

/// Flushes `file` to the drive without forcing the drive's cache to
/// stable media. The bytes become power-loss durable at the caller's
/// next barrier (`syncFile`/`syncDirectory`) on the same volume, which
/// must happen before anything acknowledges or announces them.
pub fn syncFileBeforeBarrier(io: Io, file: Io.File) !void {
    try file.sync(io);
}

/// Directory-entry counterpart of `syncFileBeforeBarrier`.
pub fn syncDirectoryBeforeBarrier(dir: Io.Dir) !void {
    if (comptime builtin.os.tag == .windows) {
        return error.UnsupportedDurabilityPlatform;
    }
    if (std.c.fsync(dir.handle) != 0) return error.DirectorySyncFailed;
}

pub fn syncChildDirectoryBeforeBarrier(
    io: Io,
    parent: Io.Dir,
    path: []const u8,
) !void {
    var child = try parent.openDir(io, path, .{});
    defer child.close(io);
    try syncDirectoryBeforeBarrier(child);
}

/// True when the full flush succeeded; false directs the caller to fall
/// back to plain `fsync` (some filesystems refuse `F_FULLFSYNC`).
fn fullFsync(handle: std.posix.fd_t) bool {
    if (comptime !builtin.os.tag.isDarwin()) return false;
    while (true) {
        const rc = std.c.fcntl(handle, std.c.F.FULLFSYNC, @as(c_int, 0));
        if (rc != -1) return true;
        if (std.posix.errno(rc) == .INTR) continue;
        return false;
    }
}

test "sync mode is settable and file sync succeeds in every mode" {
    const previous = syncMode();
    defer setSyncMode(previous);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    var file = try tmp.dir.createFile(io, "synced", .{});
    defer file.close(io);
    try file.writeStreamingAll(io, "payload");

    for ([_]SyncMode{ .os, .full }) |mode| {
        setSyncMode(mode);
        try std.testing.expectEqual(mode, syncMode());
        try syncFile(io, file);
        try syncDirectory(tmp.dir);
    }
}
