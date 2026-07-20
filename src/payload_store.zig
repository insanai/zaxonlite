//! The content-addressed, immutable transaction payload store.
//!
//! A payload is named by the SHA-256 of its bytes and installed with
//! write-temp, sync, atomic-rename. Bytes stored under a hash are never
//! mutated. A descriptor may enter the Paxos core only after its payload
//! is installed here; deletion requires a durable reachability proof
//! owned by the host, never age alone.
//!
//! Durability contract: `put`/`putNamed` flush the object and its
//! directory entries to the drive but deliberately stop before the
//! drive-cache barrier. The host's next journal sync — which precedes
//! every vote, recovered-value message, and client acknowledgement — is
//! the single barrier that makes installed payloads power-loss durable
//! (see `durability.zig`). Epoch installs likewise barrier before the
//! CURRENT pointer moves. So every counted vote and every acknowledged
//! write still implies durable payload bytes at its consumer, at one
//! full flush per commit point instead of three.

const std = @import("std");
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const durability = @import("durability.zig");

pub const Hash = [32]u8;

pub const LoadError = error{
    PayloadMissing,
    PayloadCorrupt,
} || anyerror;

pub const PayloadStore = struct {
    io: Io,
    dir: Io.Dir,

    pub fn init(io: Io, parent: Io.Dir) !PayloadStore {
        const dir = try parent.createDirPathOpen(io, "payloads", .{});
        errdefer dir.close(io);
        try durability.syncDirectory(parent);
        try durability.syncDirectory(dir);
        return .{ .io = io, .dir = dir };
    }

    pub fn deinit(self: *PayloadStore) void {
        self.dir.close(self.io);
        self.* = undefined;
    }

    pub fn hashOf(bytes: []const u8) Hash {
        var digest: Hash = undefined;
        Sha256.hash(bytes, &digest, .{});
        return digest;
    }

    /// Stores `bytes` under their content hash and returns the hash;
    /// power-loss durability follows at the caller's next storage
    /// barrier (see the module comment). Idempotent: an
    /// already-installed payload is left untouched.
    pub fn put(self: *PayloadStore, bytes: []const u8) !Hash {
        const digest = hashOf(bytes);
        try self.putNamed(digest, bytes);
        return digest;
    }

    /// Stores bytes whose hash the caller already knows (e.g. verified
    /// transfer). Asserts the digest matches in safe builds.
    pub fn putNamed(self: *PayloadStore, digest: Hash, bytes: []const u8) !void {
        if (!std.mem.eql(u8, &hashOf(bytes), &digest)) {
            return error.PayloadHashMismatch;
        }
        if (self.verify(digest)) |_| {
            return;
        } else |err| switch (err) {
            error.PayloadMissing => {},
            error.PayloadCorrupt => self.remove(digest) catch |remove_err| switch (remove_err) {
                error.FileNotFound => {},
                else => return remove_err,
            },
            else => return err,
        }

        var path_buffer: [65]u8 = undefined;
        const path = pathOf(&path_buffer, digest);
        var atomic = try self.dir.createFileAtomic(self.io, path, .{
            .make_path = true,
        });
        defer atomic.deinit(self.io);
        try atomic.file.writePositionalAll(self.io, bytes, 0);
        try durability.syncFileBeforeBarrier(self.io, atomic.file);
        atomic.link(self.io) catch |err| switch (err) {
            // Another writer installed identical content first.
            error.PathAlreadyExists => {},
            else => return err,
        };
        try durability.syncChildDirectoryBeforeBarrier(self.io, self.dir, path[0..2]);
        try durability.syncDirectoryBeforeBarrier(self.dir);
    }

    pub fn contains(self: *PayloadStore, digest: Hash) bool {
        self.verify(digest) catch return false;
        return true;
    }

    /// Verifies an installed object without allocating its contents. This is
    /// the predicate used by the Paxos host before a descriptor may enter the
    /// core; mere pathname existence is not sufficient.
    pub fn verify(self: *PayloadStore, digest: Hash) !void {
        var path_buffer: [65]u8 = undefined;
        const path = pathOf(&path_buffer, digest);
        const file = self.dir.openFile(self.io, path, .{}) catch |err| switch (err) {
            error.FileNotFound => return error.PayloadMissing,
            else => return err,
        };
        defer file.close(self.io);

        var hasher = Sha256.init(.{});
        var buffer: [64 * 1024]u8 = undefined;
        var offset: u64 = 0;
        while (true) {
            const read = try file.readPositionalAll(self.io, &buffer, offset);
            if (read == 0) break;
            hasher.update(buffer[0..read]);
            offset += read;
            if (read < buffer.len) break;
        }
        var actual: Hash = undefined;
        hasher.final(&actual);
        if (!std.mem.eql(u8, &actual, &digest)) return error.PayloadCorrupt;
    }

    /// Loads and digest-verifies one payload. Caller owns the returned bytes.
    pub fn load(self: *PayloadStore, gpa: std.mem.Allocator, digest: Hash) ![]u8 {
        var path_buffer: [65]u8 = undefined;
        const path = pathOf(&path_buffer, digest);
        const file = self.dir.openFile(self.io, path, .{}) catch |err| switch (err) {
            error.FileNotFound => return error.PayloadMissing,
            else => return err,
        };
        defer file.close(self.io);

        const len = try file.length(self.io);
        const bytes = try gpa.alloc(u8, @intCast(len));
        errdefer gpa.free(bytes);
        const read_len = try file.readPositionalAll(self.io, bytes, 0);
        if (read_len != bytes.len) return error.PayloadCorrupt;
        if (!std.mem.eql(u8, &hashOf(bytes), &digest)) return error.PayloadCorrupt;
        return bytes;
    }

    /// Removes one payload object. The caller owns the reachability proof.
    pub fn remove(self: *PayloadStore, digest: Hash) !void {
        var path_buffer: [65]u8 = undefined;
        const path = pathOf(&path_buffer, digest);
        try self.dir.deleteFile(self.io, path);
    }

    fn pathOf(buffer: *[65]u8, digest: Hash) []const u8 {
        const hex = std.fmt.bytesToHex(digest, .lower);
        buffer[0] = hex[0];
        buffer[1] = hex[1];
        buffer[2] = '/';
        @memcpy(buffer[3..], hex[2..]);
        return buffer;
    }
};

const testing = std.testing;

test "payload store round trips and is idempotent" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try PayloadStore.init(io, tmp.dir);
    defer store.deinit();

    const payload = "frame bytes for one committed transaction batch";
    const digest = try store.put(payload);
    try testing.expect(store.contains(digest));
    const again = try store.put(payload);
    try testing.expectEqualSlices(u8, &digest, &again);

    const loaded = try store.load(testing.allocator, digest);
    defer testing.allocator.free(loaded);
    try testing.expectEqualStrings(payload, loaded);
}

test "payload store detects corruption and missing objects" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var store = try PayloadStore.init(io, tmp.dir);
    defer store.deinit();

    const digest = try store.put("original bytes");

    var path_buffer: [65]u8 = undefined;
    const path = PayloadStore.pathOf(&path_buffer, digest);
    const file = try store.dir.openFile(io, path, .{ .mode = .read_write });
    try file.writePositionalAll(io, "X", 0);
    file.close(io);

    try testing.expectError(
        error.PayloadCorrupt,
        store.load(testing.allocator, digest),
    );
    try testing.expectError(error.PayloadCorrupt, store.verify(digest));
    try testing.expect(!store.contains(digest));

    // A verified transfer repairs an object whose existing pathname contains
    // corrupt bytes, rather than treating pathname existence as durability.
    try store.putNamed(digest, "original bytes");
    try store.verify(digest);
    try testing.expectError(
        error.PayloadHashMismatch,
        store.putNamed(digest, "different bytes"),
    );

    const absent = PayloadStore.hashOf("never stored");
    try testing.expect(!store.contains(absent));
    try testing.expectError(
        error.PayloadMissing,
        store.load(testing.allocator, absent),
    );
}
