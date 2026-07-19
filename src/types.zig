//! The single concrete ReplicatedLog instantiation shared by every
//! zaxonlite module, plus wire encodings for its entry and write types.

const std = @import("std");
const paxos = @import("paxos");
const command = @import("command.zig");

pub const Command = command.Command;

/// Compile-time bounds for the replicated command log. `max_entries` is the
/// hard epoch capacity; the host must checkpoint before it is reached.
pub const log_options = paxos.ReplicatedLogOptions{
    .max_members = 3,
    .max_entries = 256,
    .max_batch = 16,
    .max_metadata_bytes = 256,
};

pub const Log = paxos.ReplicatedLog(Command, log_options);

pub const Entry = Log.Entry;
pub const StopSign = Log.StopSign;
pub const Write = Log.Write;

/// Maximum canonical encoded size of one `Entry`.
pub const max_entry_size = blk: {
    const stop_size = 8 + 2 + log_options.max_members * @sizeOf(paxos.NodeId) +
        2 + log_options.max_metadata_bytes;
    break :blk 1 + @max(command.encoded_size, stop_size);
};

pub const ballot_size = 8 + 4 + 4;

/// Maximum canonical encoded size of one `Write` payload.
pub const max_write_size = 1 + ballot_size + 4 + max_entry_size;

pub const DecodeError = command.DecodeError || error{
    InvalidEntryTag,
    InvalidWriteTag,
    TruncatedRecord,
    InvalidStopSign,
};

pub fn encodeBallot(ballot: paxos.Ballot, writer: *Cursor) void {
    writer.int(u64, ballot.round);
    writer.int(u32, ballot.priority);
    writer.int(u32, ballot.node);
}

pub fn decodeBallot(reader: *ReadCursor) DecodeError!paxos.Ballot {
    return .{
        .round = try reader.int(u64),
        .priority = try reader.int(u32),
        .node = try reader.int(u32),
    };
}

pub fn encodeEntry(entry: Entry, writer: *Cursor) void {
    switch (entry) {
        .command => |cmd| {
            writer.byte(0);
            var buffer: [command.encoded_size]u8 = undefined;
            command.encode(cmd, &buffer);
            writer.bytes(&buffer);
        },
        .stop => |stop| {
            writer.byte(1);
            writer.int(u64, stop.configuration_id);
            const members = stop.membersSlice();
            writer.int(u16, @intCast(members.len));
            for (members) |member| writer.int(u32, member);
            const metadata = stop.metadataSlice();
            writer.int(u16, @intCast(metadata.len));
            writer.bytes(metadata);
        },
    }
}

pub fn decodeEntry(reader: *ReadCursor) DecodeError!Entry {
    const tag = try reader.byte();
    switch (tag) {
        0 => {
            const raw = try reader.take(command.encoded_size);
            return .{ .command = try command.decode(raw) };
        },
        1 => {
            const configuration_id = try reader.int(u64);
            const member_count = try reader.int(u16);
            if (member_count == 0 or member_count > log_options.max_members) {
                return error.InvalidStopSign;
            }
            var members: [log_options.max_members]paxos.NodeId = undefined;
            for (members[0..member_count]) |*member| {
                member.* = try reader.int(u32);
            }
            const metadata_count = try reader.int(u16);
            if (metadata_count > log_options.max_metadata_bytes) {
                return error.InvalidStopSign;
            }
            const metadata = try reader.take(metadata_count);

            var stop = StopSign{
                .configuration_id = configuration_id,
                .members = [_]paxos.NodeId{0} ** log_options.max_members,
                .member_count = member_count,
                .metadata = [_]u8{0} ** log_options.max_metadata_bytes,
                .metadata_count = metadata_count,
            };
            @memcpy(stop.members[0..member_count], members[0..member_count]);
            @memcpy(stop.metadata[0..metadata_count], metadata);
            if (configuration_id == 0) return error.InvalidStopSign;
            return .{ .stop = stop };
        },
        else => return error.InvalidEntryTag,
    }
}

pub fn encodeWrite(write: Write, writer: *Cursor) void {
    switch (write) {
        .promise => |ballot| {
            writer.byte(0);
            encodeBallot(ballot, writer);
        },
        .accept => |accept| {
            writer.byte(1);
            encodeBallot(accept.ballot, writer);
            writer.int(u32, accept.slot);
            encodeEntry(accept.value, writer);
        },
        .commit => |commit| {
            writer.byte(2);
            writer.int(u32, commit.slot);
            encodeEntry(commit.value, writer);
        },
    }
}

pub fn decodeWrite(buffer: []const u8) DecodeError!Write {
    var reader = ReadCursor{ .buffer = buffer };
    const tag = try reader.byte();
    const write: Write = switch (tag) {
        0 => .{ .promise = try decodeBallot(&reader) },
        1 => .{ .accept = .{
            .ballot = try decodeBallot(&reader),
            .slot = try reader.int(u32),
            .value = try decodeEntry(&reader),
        } },
        2 => .{ .commit = .{
            .slot = try reader.int(u32),
            .value = try decodeEntry(&reader),
        } },
        else => return error.InvalidWriteTag,
    };
    if (reader.offset != buffer.len) return error.TruncatedRecord;
    return write;
}

pub const Cursor = struct {
    buffer: []u8,
    offset: usize = 0,

    pub fn byte(self: *Cursor, value: u8) void {
        self.buffer[self.offset] = value;
        self.offset += 1;
    }

    pub fn int(self: *Cursor, comptime T: type, value: T) void {
        std.mem.writeInt(T, self.buffer[self.offset..][0..@sizeOf(T)], value, .little);
        self.offset += @sizeOf(T);
    }

    pub fn bytes(self: *Cursor, value: []const u8) void {
        @memcpy(self.buffer[self.offset..][0..value.len], value);
        self.offset += value.len;
    }
};

pub const ReadCursor = struct {
    buffer: []const u8,
    offset: usize = 0,

    pub fn byte(self: *ReadCursor) DecodeError!u8 {
        if (self.offset + 1 > self.buffer.len) return error.TruncatedRecord;
        const value = self.buffer[self.offset];
        self.offset += 1;
        return value;
    }

    pub fn int(self: *ReadCursor, comptime T: type) DecodeError!T {
        if (self.offset + @sizeOf(T) > self.buffer.len) return error.TruncatedRecord;
        const value = std.mem.readInt(
            T,
            self.buffer[self.offset..][0..@sizeOf(T)],
            .little,
        );
        self.offset += @sizeOf(T);
        return value;
    }

    pub fn take(self: *ReadCursor, count: usize) DecodeError![]const u8 {
        if (self.offset + count > self.buffer.len) return error.TruncatedRecord;
        const slice = self.buffer[self.offset..][0..count];
        self.offset += count;
        return slice;
    }
};

test "write records round trip" {
    const ballot = paxos.Ballot{ .round = 9, .priority = 2, .node = 1 };
    const noop_cmd = Command.noop;
    var stop_members = [_]paxos.NodeId{ 1, 2, 3 };
    const stop = try makeStop(7, &stop_members, "manifest");

    const cases = [_]Write{
        .{ .promise = ballot },
        .{ .accept = .{ .ballot = ballot, .slot = 3, .value = .{ .command = noop_cmd } } },
        .{ .commit = .{ .slot = 3, .value = .{ .stop = stop } } },
    };
    for (cases) |case| {
        var buffer: [max_write_size]u8 = undefined;
        var cursor = Cursor{ .buffer = &buffer };
        encodeWrite(case, &cursor);
        const decoded = try decodeWrite(buffer[0..cursor.offset]);
        try std.testing.expectEqualDeep(case, decoded);
    }
}

fn makeStop(
    configuration_id: u64,
    members: []const paxos.NodeId,
    metadata: []const u8,
) !StopSign {
    var stop = StopSign{
        .configuration_id = configuration_id,
        .members = [_]paxos.NodeId{0} ** log_options.max_members,
        .member_count = @intCast(members.len),
        .metadata = [_]u8{0} ** log_options.max_metadata_bytes,
        .metadata_count = @intCast(metadata.len),
    };
    @memcpy(stop.members[0..members.len], members);
    @memcpy(stop.metadata[0..metadata.len], metadata);
    return stop;
}
