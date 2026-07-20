//! Small POSIX durability helpers shared by the storage components.
//!
//! Syncing file contents does not necessarily persist the directory entry
//! created by link/rename. Callers sync the relevant parent after every
//! authoritative pathname transition.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

pub fn syncDirectory(dir: Io.Dir) !void {
    if (comptime builtin.os.tag == .windows) {
        // The threaded Windows backend's atomic replacement has different
        // handle semantics; Windows is not in the current supported matrix.
        return error.UnsupportedDurabilityPlatform;
    }
    if (std.c.fsync(dir.handle) != 0) return error.DirectorySyncFailed;
}

pub fn syncChildDirectory(io: Io, parent: Io.Dir, path: []const u8) !void {
    var child = try parent.openDir(io, path, .{});
    defer child.close(io);
    try syncDirectory(child);
}
