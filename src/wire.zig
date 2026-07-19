//! The zaxonlite peer and client wire protocol.
//!
//! Every connection speaks length-prefixed frames: a little-endian `u32`
//! body length, one `kind` byte, then the body. The first frame on any
//! connection must be a `hello`; it names the protocol version and whether
//! the connection is a cluster peer or a client. Peer frames carry encoded
//! Paxos envelopes, content-addressed payload bytes, host-level read-fence
//! probes, and snapshot transfer streams. Client frames carry one JSON
//! request/response pair per round trip.
//!
//! Ordering rule: a leader pushes `payload_data` on the same ordered stream
//! *before* any accept or commit that references the payload hash, so a
//! follower always stores payload bytes durably before it votes.

const std = @import("std");
const Io = std.Io;
const paxos = @import("paxos");
const types = @import("types.zig");
const command = @import("command.zig");

pub const protocol_version: u16 = 1;

/// Upper bound for one frame body; larger frames are a protocol error.
pub const max_frame_bytes: u32 = 64 * 1024 * 1024;

/// Generous fixed bound for one encoded envelope frame body.
pub const max_envelope_size: usize = 16 + types.max_entry_size + 64;

pub const FrameKind = enum(u8) {
    hello = 1,
    envelope = 2,
    payload_data = 3,
    payload_request = 4,
    fence_request = 5,
    fence_ack = 6,
    snapshot_request = 7,
    snapshot_begin = 8,
    snapshot_chunk = 9,
    snapshot_end = 10,
    rpc_request = 11,
    rpc_response = 12,
};

pub const WireError = error{
    InvalidFrame,
    FrameTooLarge,
    InvalidHello,
    UnsupportedProtocolVersion,
} || types.DecodeError;

pub const ConnectionKind = enum(u8) { peer = 0, client = 1 };

pub const Hello = struct {
    version: u16,
    kind: ConnectionKind,
    node_id: paxos.NodeId,
    database_id: u128,
    configuration_id: u64,

    pub const encoded_size = 2 + 1 + 4 + 16 + 8;

    pub fn encode(self: Hello, buffer: *[encoded_size]u8) []const u8 {
        var cursor = types.Cursor{ .buffer = buffer };
        cursor.int(u16, self.version);
        cursor.byte(@intFromEnum(self.kind));
        cursor.int(u32, self.node_id);
        cursor.int(u128, self.database_id);
        cursor.int(u64, self.configuration_id);
        return buffer[0..cursor.offset];
    }

    pub fn decode(body: []const u8) WireError!Hello {
        if (body.len != encoded_size) return error.InvalidHello;
        var reader = types.ReadCursor{ .buffer = body };
        const version = reader.int(u16) catch return error.InvalidHello;
        if (version != protocol_version) return error.UnsupportedProtocolVersion;
        const kind_raw = reader.byte() catch return error.InvalidHello;
        const kind = std.enums.fromInt(ConnectionKind, kind_raw) orelse
            return error.InvalidHello;
        return .{
            .version = version,
            .kind = kind,
            .node_id = reader.int(u32) catch return error.InvalidHello,
            .database_id = reader.int(u128) catch return error.InvalidHello,
            .configuration_id = reader.int(u64) catch return error.InvalidHello,
        };
    }
};

// ----------------------------------------------------------------------
// Paxos envelope codec
// ----------------------------------------------------------------------

const MessageTag = enum(u8) {
    prepare = 0,
    promise = 1,
    promise_done = 2,
    accept = 3,
    accepted = 4,
    commit = 5,
    learn = 6,
    nack = 7,
    heartbeat = 8,
};

pub fn encodeEnvelope(
    envelope: types.Log.Envelope,
    buffer: *[max_envelope_size]u8,
) []const u8 {
    var cursor = types.Cursor{ .buffer = buffer };
    cursor.int(u32, envelope.from);
    cursor.int(u32, envelope.to);
    switch (envelope.message) {
        .prepare => |m| {
            cursor.byte(@intFromEnum(MessageTag.prepare));
            types.encodeBallot(m.ballot, &cursor);
            cursor.int(u32, m.decided_through);
        },
        .promise => |m| {
            cursor.byte(@intFromEnum(MessageTag.promise));
            types.encodeBallot(m.ballot, &cursor);
            cursor.int(u32, m.slot);
            types.encodeBallot(m.accepted.ballot, &cursor);
            types.encodeEntry(m.accepted.value, &cursor);
        },
        .promise_done => |m| {
            cursor.byte(@intFromEnum(MessageTag.promise_done));
            types.encodeBallot(m.ballot, &cursor);
            cursor.int(u32, m.accepted_count);
            cursor.int(u32, m.decided_through);
        },
        .accept => |m| {
            cursor.byte(@intFromEnum(MessageTag.accept));
            types.encodeBallot(m.ballot, &cursor);
            cursor.int(u32, m.slot);
            types.encodeEntry(m.value, &cursor);
        },
        .accepted => |m| {
            cursor.byte(@intFromEnum(MessageTag.accepted));
            types.encodeBallot(m.ballot, &cursor);
            cursor.int(u32, m.slot);
            cursor.int(u32, m.decided_through);
        },
        .commit => |m| {
            cursor.byte(@intFromEnum(MessageTag.commit));
            cursor.int(u32, m.slot);
            types.encodeEntry(m.value, &cursor);
        },
        .learn => |m| {
            cursor.byte(@intFromEnum(MessageTag.learn));
            cursor.int(u32, m.from_slot);
        },
        .nack => |m| {
            cursor.byte(@intFromEnum(MessageTag.nack));
            types.encodeBallot(m.rejected, &cursor);
            types.encodeBallot(m.promised, &cursor);
            cursor.int(u32, m.decided_through);
        },
        .heartbeat => |m| {
            cursor.byte(@intFromEnum(MessageTag.heartbeat));
            types.encodeBallot(m.ballot, &cursor);
            cursor.int(u32, m.decided_through);
        },
    }
    return buffer[0..cursor.offset];
}

pub fn decodeEnvelope(body: []const u8) WireError!types.Log.Envelope {
    var reader = types.ReadCursor{ .buffer = body };
    const from = try reader.int(u32);
    const to = try reader.int(u32);
    const tag_raw = try reader.byte();
    const tag = std.enums.fromInt(MessageTag, tag_raw) orelse
        return error.InvalidFrame;
    const message: types.Log.Message = switch (tag) {
        .prepare => .{ .prepare = .{
            .ballot = try types.decodeBallot(&reader),
            .decided_through = try reader.int(u32),
        } },
        .promise => .{ .promise = .{
            .ballot = try types.decodeBallot(&reader),
            .slot = try reader.int(u32),
            .accepted = .{
                .ballot = try types.decodeBallot(&reader),
                .value = try types.decodeEntry(&reader),
            },
        } },
        .promise_done => .{ .promise_done = .{
            .ballot = try types.decodeBallot(&reader),
            .accepted_count = try reader.int(u32),
            .decided_through = try reader.int(u32),
        } },
        .accept => .{ .accept = .{
            .ballot = try types.decodeBallot(&reader),
            .slot = try reader.int(u32),
            .value = try types.decodeEntry(&reader),
        } },
        .accepted => .{ .accepted = .{
            .ballot = try types.decodeBallot(&reader),
            .slot = try reader.int(u32),
            .decided_through = try reader.int(u32),
        } },
        .commit => .{ .commit = .{
            .slot = try reader.int(u32),
            .value = try types.decodeEntry(&reader),
        } },
        .learn => .{ .learn = .{
            .from_slot = try reader.int(u32),
        } },
        .nack => .{ .nack = .{
            .rejected = try types.decodeBallot(&reader),
            .promised = try types.decodeBallot(&reader),
            .decided_through = try reader.int(u32),
        } },
        .heartbeat => .{ .heartbeat = .{
            .ballot = try types.decodeBallot(&reader),
            .decided_through = try reader.int(u32),
        } },
    };
    if (reader.offset != body.len) return error.InvalidFrame;
    return .{ .from = from, .to = to, .message = message };
}

/// Returns the transaction-batch payload hash carried by an accept or
/// commit envelope, if any. A follower must have the payload durably in
/// its store before it processes such an envelope.
pub fn envelopePayloadHash(envelope: types.Log.Envelope) ?command.HashBytes {
    const entry: types.Entry = switch (envelope.message) {
        .accept => |m| m.value,
        .commit => |m| m.value,
        else => return null,
    };
    switch (entry) {
        .command => |cmd| switch (cmd) {
            .transaction_batch => |batch| return batch.payload_hash,
            else => return null,
        },
        .stop => return null,
    }
}

// ----------------------------------------------------------------------
// Fence probes
// ----------------------------------------------------------------------

pub const FenceRequest = struct {
    ballot: paxos.Ballot,
    fence_id: u64,

    pub const encoded_size = types.ballot_size + 8;

    pub fn encode(self: FenceRequest, buffer: *[encoded_size]u8) []const u8 {
        var cursor = types.Cursor{ .buffer = buffer };
        types.encodeBallot(self.ballot, &cursor);
        cursor.int(u64, self.fence_id);
        return buffer[0..cursor.offset];
    }

    pub fn decode(body: []const u8) WireError!FenceRequest {
        if (body.len != encoded_size) return error.InvalidFrame;
        var reader = types.ReadCursor{ .buffer = body };
        return .{
            .ballot = try types.decodeBallot(&reader),
            .fence_id = try reader.int(u64),
        };
    }
};

pub const FenceAck = struct {
    fence_id: u64,
    ok: bool,
    promised: paxos.Ballot,

    pub const encoded_size = 8 + 1 + types.ballot_size;

    pub fn encode(self: FenceAck, buffer: *[encoded_size]u8) []const u8 {
        var cursor = types.Cursor{ .buffer = buffer };
        cursor.int(u64, self.fence_id);
        cursor.byte(@intFromBool(self.ok));
        types.encodeBallot(self.promised, &cursor);
        return buffer[0..cursor.offset];
    }

    pub fn decode(body: []const u8) WireError!FenceAck {
        if (body.len != encoded_size) return error.InvalidFrame;
        var reader = types.ReadCursor{ .buffer = body };
        const fence_id = try reader.int(u64);
        const ok_raw = try reader.byte();
        if (ok_raw > 1) return error.InvalidFrame;
        return .{
            .fence_id = fence_id,
            .ok = ok_raw == 1,
            .promised = try types.decodeBallot(&reader),
        };
    }
};

// ----------------------------------------------------------------------
// Snapshot transfer
// ----------------------------------------------------------------------

pub const SnapshotBegin = struct {
    configuration_id: u64,
    name: [16]u8,
    db_size: u64,
    manifest: []const u8,

    pub const max_manifest_bytes = 4096;
    pub const max_encoded_size = 8 + 16 + 8 + 4 + max_manifest_bytes;

    pub fn encode(self: SnapshotBegin, buffer: *[max_encoded_size]u8) []const u8 {
        std.debug.assert(self.manifest.len <= max_manifest_bytes);
        var cursor = types.Cursor{ .buffer = buffer };
        cursor.int(u64, self.configuration_id);
        cursor.bytes(&self.name);
        cursor.int(u64, self.db_size);
        cursor.int(u32, @intCast(self.manifest.len));
        cursor.bytes(self.manifest);
        return buffer[0..cursor.offset];
    }

    /// The returned manifest slice aliases `body`.
    pub fn decode(body: []const u8) WireError!SnapshotBegin {
        var reader = types.ReadCursor{ .buffer = body };
        const configuration_id = try reader.int(u64);
        const name = try reader.take(16);
        const db_size = try reader.int(u64);
        const manifest_len = try reader.int(u32);
        if (manifest_len > max_manifest_bytes) return error.InvalidFrame;
        const manifest = try reader.take(manifest_len);
        if (reader.offset != body.len) return error.InvalidFrame;
        return .{
            .configuration_id = configuration_id,
            .name = name[0..16].*,
            .db_size = db_size,
            .manifest = manifest,
        };
    }
};

pub const SnapshotChunk = struct {
    offset: u64,
    bytes: []const u8,

    pub fn decode(body: []const u8) WireError!SnapshotChunk {
        if (body.len < 8) return error.InvalidFrame;
        return .{
            .offset = std.mem.readInt(u64, body[0..8], .little),
            .bytes = body[8..],
        };
    }
};

// ----------------------------------------------------------------------
// Frame reading and writing
// ----------------------------------------------------------------------

pub const FrameHeader = struct {
    kind: FrameKind,
    body_len: u32,
};

pub const header_size = 4 + 1;

/// Reads one frame header. Returns `error.EndOfStream` on clean close.
pub fn readFrameHeader(reader: *Io.Reader) !FrameHeader {
    const total = try reader.takeInt(u32, .little);
    if (total == 0) return error.InvalidFrame;
    if (total > max_frame_bytes) return error.FrameTooLarge;
    const kind_raw = try reader.takeByte();
    const kind = std.enums.fromInt(FrameKind, kind_raw) orelse
        return error.InvalidFrame;
    return .{ .kind = kind, .body_len = total - 1 };
}

/// Reads one frame body into a freshly allocated buffer.
pub fn readFrameBody(
    gpa: std.mem.Allocator,
    reader: *Io.Reader,
    header: FrameHeader,
) ![]u8 {
    const body = try gpa.alloc(u8, header.body_len);
    errdefer gpa.free(body);
    try reader.readSliceAll(body);
    return body;
}

pub fn writeFrame(writer: *Io.Writer, kind: FrameKind, body: []const u8) !void {
    std.debug.assert(body.len + 1 <= max_frame_bytes);
    var header: [header_size]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], @intCast(body.len + 1), .little);
    header[4] = @intFromEnum(kind);
    try writer.writeAll(&header);
    try writer.writeAll(body);
}

/// Serializes one frame into an owned buffer (header plus body), ready to
/// be handed to a sender queue.
pub fn frameAlloc(
    gpa: std.mem.Allocator,
    kind: FrameKind,
    parts: []const []const u8,
) ![]u8 {
    var body_len: usize = 0;
    for (parts) |part| body_len += part.len;
    std.debug.assert(body_len + 1 <= max_frame_bytes);
    const buffer = try gpa.alloc(u8, header_size + body_len);
    std.mem.writeInt(u32, buffer[0..4], @intCast(body_len + 1), .little);
    buffer[4] = @intFromEnum(kind);
    var offset: usize = header_size;
    for (parts) |part| {
        @memcpy(buffer[offset..][0..part.len], part);
        offset += part.len;
    }
    return buffer;
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

const testing = std.testing;

test "hello round trip" {
    const hello = Hello{
        .version = protocol_version,
        .kind = .peer,
        .node_id = 3,
        .database_id = 0xfeed_beef,
        .configuration_id = 17,
    };
    var buffer: [Hello.encoded_size]u8 = undefined;
    const encoded = hello.encode(&buffer);
    const decoded = try Hello.decode(encoded);
    try testing.expectEqualDeep(hello, decoded);
}

test "hello rejects a future protocol version" {
    var buffer: [Hello.encoded_size]u8 = undefined;
    var hello = Hello{
        .version = protocol_version,
        .kind = .client,
        .node_id = 0,
        .database_id = 0,
        .configuration_id = 0,
    };
    _ = hello.encode(&buffer);
    std.mem.writeInt(u16, buffer[0..2], protocol_version + 1, .little);
    try testing.expectError(
        error.UnsupportedProtocolVersion,
        Hello.decode(&buffer),
    );
    hello.version = protocol_version;
}

test "every envelope kind round trips" {
    const ballot = paxos.Ballot{ .round = 5, .priority = 2, .node = 3 };
    const batch = command.TransactionBatch{
        .database_id = 77,
        .batch_id = 99,
        .base_data_slot = 4,
        .base_chain_hash = [_]u8{1} ** 32,
        .result_chain_hash = [_]u8{2} ** 32,
        .payload_hash = [_]u8{3} ** 32,
        .payload_bytes = 4096,
        .transaction_count = 1,
        .frame_count = 2,
    };
    const entry = types.Entry{ .command = .{ .transaction_batch = batch } };
    const cases = [_]types.Log.Message{
        .{ .prepare = .{ .ballot = ballot, .decided_through = 7 } },
        .{ .promise = .{
            .ballot = ballot,
            .slot = 2,
            .accepted = .{ .ballot = ballot, .value = entry },
        } },
        .{ .promise_done = .{
            .ballot = ballot,
            .accepted_count = 3,
            .decided_through = 1,
        } },
        .{ .accept = .{ .ballot = ballot, .slot = 9, .value = entry } },
        .{ .accepted = .{ .ballot = ballot, .slot = 9, .decided_through = 8 } },
        .{ .commit = .{ .slot = 9, .value = entry } },
        .{ .learn = .{ .from_slot = 3 } },
        .{ .nack = .{
            .rejected = ballot,
            .promised = ballot,
            .decided_through = 2,
        } },
        .{ .heartbeat = .{ .ballot = ballot, .decided_through = 11 } },
    };
    for (cases) |message| {
        const envelope = types.Log.Envelope{ .from = 1, .to = 2, .message = message };
        var buffer: [max_envelope_size]u8 = undefined;
        const encoded = encodeEnvelope(envelope, &buffer);
        const decoded = try decodeEnvelope(encoded);
        try testing.expectEqualDeep(envelope, decoded);
    }
}

test "envelope payload hash extraction" {
    const batch = command.TransactionBatch{
        .database_id = 1,
        .batch_id = 2,
        .base_data_slot = 0,
        .base_chain_hash = [_]u8{0} ** 32,
        .result_chain_hash = [_]u8{0} ** 32,
        .payload_hash = [_]u8{9} ** 32,
        .payload_bytes = 64,
        .transaction_count = 1,
        .frame_count = 1,
    };
    const with_batch = types.Log.Envelope{
        .from = 1,
        .to = 2,
        .message = .{ .accept = .{
            .ballot = .{ .round = 1, .node = 1 },
            .slot = 1,
            .value = .{ .command = .{ .transaction_batch = batch } },
        } },
    };
    try testing.expectEqualSlices(
        u8,
        &batch.payload_hash,
        &envelopePayloadHash(with_batch).?,
    );
    const noop = types.Log.Envelope{
        .from = 1,
        .to = 2,
        .message = .{ .commit = .{ .slot = 1, .value = .{ .command = .noop } } },
    };
    try testing.expect(envelopePayloadHash(noop) == null);
}

test "decode rejects malformed envelopes" {
    try testing.expectError(error.TruncatedRecord, decodeEnvelope(&.{ 1, 2, 3 }));
    var buffer: [max_envelope_size]u8 = undefined;
    const envelope = types.Log.Envelope{
        .from = 1,
        .to = 2,
        .message = .{ .learn = .{ .from_slot = 3 } },
    };
    const encoded = encodeEnvelope(envelope, &buffer);
    // Trailing garbage is rejected.
    var extended: [max_envelope_size + 1]u8 = undefined;
    @memcpy(extended[0..encoded.len], encoded);
    extended[encoded.len] = 0xaa;
    try testing.expectError(
        error.InvalidFrame,
        decodeEnvelope(extended[0 .. encoded.len + 1]),
    );
    // An unknown message tag is rejected.
    var bad_tag: [16]u8 = undefined;
    @memcpy(bad_tag[0..encoded.len], encoded);
    bad_tag[8] = 0xff;
    try testing.expectError(error.InvalidFrame, decodeEnvelope(bad_tag[0..encoded.len]));
}

test "fence frames round trip" {
    const request = FenceRequest{
        .ballot = .{ .round = 3, .priority = 1, .node = 2 },
        .fence_id = 41,
    };
    var request_buffer: [FenceRequest.encoded_size]u8 = undefined;
    try testing.expectEqualDeep(
        request,
        try FenceRequest.decode(request.encode(&request_buffer)),
    );

    const ack = FenceAck{
        .fence_id = 41,
        .ok = true,
        .promised = .{ .round = 3, .priority = 1, .node = 2 },
    };
    var ack_buffer: [FenceAck.encoded_size]u8 = undefined;
    try testing.expectEqualDeep(ack, try FenceAck.decode(ack.encode(&ack_buffer)));
}

test "snapshot begin round trips and bounds the manifest" {
    const begin = SnapshotBegin{
        .configuration_id = 6,
        .name = "0000000000000006".*,
        .db_size = 8192,
        .manifest = "format=1\nchain=00\n",
    };
    var buffer: [SnapshotBegin.max_encoded_size]u8 = undefined;
    const encoded = begin.encode(&buffer);
    const decoded = try SnapshotBegin.decode(encoded);
    try testing.expectEqual(begin.configuration_id, decoded.configuration_id);
    try testing.expectEqualStrings(begin.manifest, decoded.manifest);
}

test "frame alloc produces a parseable frame" {
    const frame = try frameAlloc(testing.allocator, .payload_request, &.{
        &[_]u8{0xab} ** 32,
    });
    defer testing.allocator.free(frame);
    try testing.expectEqual(@as(usize, header_size + 32), frame.len);
    const len = std.mem.readInt(u32, frame[0..4], .little);
    try testing.expectEqual(@as(u32, 33), len);
    try testing.expectEqual(
        @intFromEnum(FrameKind.payload_request),
        frame[4],
    );
}
