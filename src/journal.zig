//! The framed, checksummed, append-only protocol journal.
//!
//! The journal plus the payload store are the authoritative durable state of
//! one node. Every record carries a magic value, format version, kind, byte
//! length, monotonically increasing sequence, and a CRC over the framed
//! content. Recovery replays the durable prefix into
//! `ReplicatedLog.DurableState`, truncates only an incomplete final record,
//! and rejects interior corruption.

const std = @import("std");
const Io = std.Io;
const Crc32 = std.hash.crc.Crc32;

const types = @import("types.zig");
const durability = @import("durability.zig");

const magic: u32 = 0x315a584a; // "ZXJ1" little-endian.
const format_version: u8 = 1;
const header_size = 4 + 1 + 1 + 2 + 8 + 4 + 4;
const max_record_size = header_size + types.max_write_size;

pub const ReplayError = error{
    CorruptJournal,
    UnsupportedJournalVersion,
} || types.DecodeError || anyerror;

pub const ReplayInfo = struct {
    /// Number of valid records replayed.
    record_count: u64 = 0,
    /// Sequence for the next appended record.
    next_sequence: u64 = 1,
    /// Byte offset one past the last valid record.
    end_offset: u64 = 0,
    /// Bytes removed from an incomplete final record.
    truncated_bytes: u64 = 0,
};

pub fn fileName(buffer: *[26]u8, configuration_id: u64) []const u8 {
    return std.fmt.bufPrint(buffer, "paxos-{x:0>16}.log", .{configuration_id}) catch unreachable;
}

pub const Journal = struct {
    io: Io,
    file: Io.File,
    next_sequence: u64,
    end_offset: u64,

    /// Creates a new empty journal for one configuration epoch. Fails if the
    /// file already exists; an existing epoch must be opened via `open`.
    pub fn create(io: Io, dir: Io.Dir, configuration_id: u64) !Journal {
        var name_buffer: [26]u8 = undefined;
        const name = fileName(&name_buffer, configuration_id);
        const file = try dir.createFile(io, name, .{ .exclusive = true, .read = true });
        errdefer file.close(io);
        try durability.syncPathnameTransition(io, dir, name);
        return .{ .io = io, .file = file, .next_sequence = 1, .end_offset = 0 };
    }

    /// Opens an existing journal, replaying every valid record into
    /// `durable` and truncating a torn final record.
    pub fn open(
        io: Io,
        gpa: std.mem.Allocator,
        dir: Io.Dir,
        configuration_id: u64,
        durable: *types.Log.DurableState,
        info: *ReplayInfo,
    ) !Journal {
        var name_buffer: [26]u8 = undefined;
        const name = fileName(&name_buffer, configuration_id);
        const file = try dir.openFile(io, name, .{ .mode = .read_write });
        errdefer file.close(io);

        info.* = try replay(io, gpa, file, durable);
        if (info.truncated_bytes > 0) {
            try file.setLength(io, info.end_offset);
            try durability.syncFile(io, file);
        }
        return .{
            .io = io,
            .file = file,
            .next_sequence = info.next_sequence,
            .end_offset = info.end_offset,
        };
    }

    pub fn close(self: *Journal) void {
        self.file.close(self.io);
        self.* = undefined;
    }

    /// Appends every write from one protocol transition. The records are not
    /// durable until `sync` succeeds; callers must not release dependent
    /// messages before that.
    pub fn appendWrites(self: *Journal, writes: []const types.Write) !void {
        var buffer: [max_record_size]u8 = undefined;
        for (writes) |write| {
            const record = encodeRecord(&buffer, self.next_sequence, write);
            try self.file.writePositionalAll(self.io, record, self.end_offset);
            self.end_offset += record.len;
            self.next_sequence += 1;
        }
    }

    /// Makes every appended record durable.
    pub fn sync(self: *Journal) !void {
        try durability.syncFile(self.io, self.file);
    }
};

fn encodeRecord(
    buffer: *[max_record_size]u8,
    sequence: u64,
    write: types.Write,
) []const u8 {
    var payload_cursor = types.Cursor{ .buffer = buffer[header_size..] };
    types.encodeWrite(write, &payload_cursor);
    const payload_len: u32 = @intCast(payload_cursor.offset);

    var cursor = types.Cursor{ .buffer = buffer };
    cursor.int(u32, magic);
    cursor.byte(format_version);
    cursor.byte(@intFromEnum(write));
    cursor.int(u16, 0);
    cursor.int(u64, sequence);
    cursor.int(u32, payload_len);
    const crc_offset = cursor.offset;
    cursor.int(u32, 0);
    std.debug.assert(crc_offset + 4 == header_size);

    const crc = recordCrc(buffer[0..header_size], buffer[header_size..][0..payload_len]);
    std.mem.writeInt(u32, buffer[crc_offset..][0..4], crc, .little);
    return buffer[0 .. header_size + payload_len];
}

fn recordCrc(header: []const u8, payload: []const u8) u32 {
    var crc = Crc32.init();
    crc.update(header[0 .. header.len - 4]);
    crc.update(payload);
    return crc.final();
}

/// Replays one journal file into `durable`. A record that fails validation
/// and touches the end of the file is a torn tail; anything else is
/// corruption of the durable prefix and the node must refuse to vote.
fn replay(
    io: Io,
    gpa: std.mem.Allocator,
    file: Io.File,
    durable: *types.Log.DurableState,
) !ReplayInfo {
    const file_len = try file.length(io);
    const contents = try gpa.alloc(u8, @intCast(file_len));
    defer gpa.free(contents);
    const read_len = try file.readPositionalAll(io, contents, 0);
    if (read_len != contents.len) return error.CorruptJournal;

    var info = ReplayInfo{};
    var offset: u64 = 0;
    while (offset < contents.len) {
        const remaining = contents[@intCast(offset)..];
        const parsed = parseRecord(remaining, info.next_sequence) catch |err| {
            if (recordTouchesEof(remaining)) {
                info.truncated_bytes = contents.len - offset;
                info.end_offset = offset;
                return info;
            }
            return err;
        };
        durable.apply(parsed.write) catch return error.CorruptJournal;
        info.record_count += 1;
        info.next_sequence += 1;
        offset += parsed.size;
        info.end_offset = offset;
    }
    return info;
}

const ParsedRecord = struct {
    write: types.Write,
    size: u64,
};

fn parseRecord(buffer: []const u8, expected_sequence: u64) !ParsedRecord {
    if (buffer.len < header_size) return error.CorruptJournal;
    var reader = types.ReadCursor{ .buffer = buffer };
    const found_magic = try reader.int(u32);
    if (found_magic != magic) return error.CorruptJournal;
    const version = try reader.byte();
    if (version != format_version) return error.UnsupportedJournalVersion;
    const kind = try reader.byte();
    const reserved = try reader.int(u16);
    if (reserved != 0) return error.CorruptJournal;
    const sequence = try reader.int(u64);
    if (sequence != expected_sequence) return error.CorruptJournal;
    const payload_len = try reader.int(u32);
    if (payload_len > types.max_write_size) return error.CorruptJournal;
    const stored_crc = try reader.int(u32);
    if (buffer.len < header_size + payload_len) return error.CorruptJournal;

    const payload = buffer[header_size..][0..payload_len];
    if (recordCrc(buffer[0..header_size], payload) != stored_crc) {
        return error.CorruptJournal;
    }
    const write = try types.decodeWrite(payload);
    if (@intFromEnum(write) != kind) return error.CorruptJournal;
    return .{ .write = write, .size = header_size + payload_len };
}

/// True when a failed record parse could be explained by a torn append: the
/// claimed extent of the record (or the header itself) runs past end of file.
fn recordTouchesEof(buffer: []const u8) bool {
    if (buffer.len < header_size) return true;
    const payload_len = std.mem.readInt(u32, buffer[16..20], .little);
    if (payload_len > types.max_write_size) {
        // A garbage length cannot prove interior corruption; only treat it
        // as a torn tail when nothing valid follows the claimed header.
        return buffer.len <= max_record_size;
    }
    return buffer.len < header_size + @as(u64, payload_len);
}

const testing = std.testing;
const paxos = @import("paxos");

fn testWrites() [3]types.Write {
    const ballot = paxos.Ballot{ .round = 1, .node = 1 };
    return .{
        .{ .promise = ballot },
        .{ .accept = .{ .ballot = ballot, .slot = 1, .value = .{ .command = .noop } } },
        .{ .commit = .{ .slot = 1, .value = .{ .command = .noop } } },
    };
}

test "journal appends, syncs, and replays" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var journal = try Journal.create(io, tmp.dir, 1);
    const writes = testWrites();
    try journal.appendWrites(&writes);
    try journal.sync();
    journal.close();

    const durable = try testing.allocator.create(types.Log.DurableState);
    defer testing.allocator.destroy(durable);
    durable.* = .{};
    var info: ReplayInfo = undefined;
    var reopened = try Journal.open(io, testing.allocator, tmp.dir, 1, durable, &info);
    defer reopened.close();

    try testing.expectEqual(@as(u64, 3), info.record_count);
    try testing.expectEqual(@as(u64, 0), info.truncated_bytes);
    try testing.expectEqual(@as(u64, 4), reopened.next_sequence);
    try testing.expect(durable.acceptedAt(1) != null);
    try testing.expect(durable.committedAt(1) != null);
}

test "journal truncates a torn tail but keeps the durable prefix" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var journal = try Journal.create(io, tmp.dir, 1);
    const writes = testWrites();
    try journal.appendWrites(&writes);
    try journal.sync();
    const good_end = journal.end_offset;

    // Simulate a torn append: a partial header at the end of the file.
    try journal.file.writePositionalAll(io, &.{ 0x4a, 0x58 }, journal.end_offset);
    journal.close();

    const durable = try testing.allocator.create(types.Log.DurableState);
    defer testing.allocator.destroy(durable);
    durable.* = .{};
    var info: ReplayInfo = undefined;
    var reopened = try Journal.open(io, testing.allocator, tmp.dir, 1, durable, &info);
    defer reopened.close();

    try testing.expectEqual(@as(u64, 3), info.record_count);
    try testing.expectEqual(@as(u64, 2), info.truncated_bytes);
    try testing.expectEqual(good_end, info.end_offset);
    try testing.expectEqual(good_end, try reopened.file.length(io));
}

test "journal rejects interior corruption" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var journal = try Journal.create(io, tmp.dir, 1);
    const writes = testWrites();
    try journal.appendWrites(&writes);
    try journal.sync();

    // Flip one payload byte in the first record.
    var byte: [1]u8 = undefined;
    _ = try journal.file.readPositionalAll(io, &byte, header_size);
    byte[0] ^= 0xff;
    try journal.file.writePositionalAll(io, &byte, header_size);
    journal.close();

    const durable = try testing.allocator.create(types.Log.DurableState);
    defer testing.allocator.destroy(durable);
    durable.* = .{};
    var info: ReplayInfo = undefined;
    try testing.expectError(
        error.CorruptJournal,
        Journal.open(io, testing.allocator, tmp.dir, 1, durable, &info),
    );
}
