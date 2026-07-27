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
//! Ordering rule: a sender queues `payload_data` immediately before every
//! dependent promise, accept, or commit on the same ordered TCP/TLS stream.
//! The receiver installs and drive-flushes the object before reading the next
//! frame; an independent bounded gate holds a reordered envelope whose object
//! is absent. `payload_stored` records readiness for later sends, but is not a
//! round-trip prerequisite for the adjacent envelope. The receiver's journal
//! barrier then makes its vote or recovered value power-loss durable.

const std = @import("std");
const Io = std.Io;
const paxos = @import("paxos");
const types = @import("types.zig");
const command = @import("command.zig");

/// Version 8 adds an explicit durable-installation announcement for a
/// replacement voter. A TCP connection alone never implies readiness.
/// Version 7 added decided-registry membership: checkpoint proof v2 with
/// sealed and next voter sets, the next-registry digest, and the voter
/// replacement operation surface.
/// Version 6 added the bounded one-time-token/CSR enrollment exchange.
/// Version 5 added voter quorum confirmation for transferred checkpoint
/// proofs. Older peers are deliberately rejected:
/// silently falling back would turn a configuration error into a security
/// downgrade.
pub const protocol_version: u16 = 8;

/// Upper bound for one frame body; larger frames are a protocol error.
pub const max_frame_bytes: u32 = 64 * 1024 * 1024;

/// Default upper bound for one declared snapshot or backup transfer.
/// Sized for the intended small embedded database profile, not for the
/// theoretical SQLite maximum; deployments with larger images raise the
/// server's `max_transfer_bytes` explicitly.
pub const max_transfer_bytes: u64 = 4 * 1024 * 1024 * 1024;

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
    payload_stored = 13,
    auth_challenge = 14,
    auth_response = 15,
    backup_begin = 16,
    backup_chunk = 17,
    backup_end = 18,
    learner_commit = 19,
    learner_heartbeat = 20,
    checkpoint_proof_request = 21,
    checkpoint_proof_reply = 22,
    enrollment_request = 23,
    enrollment_response = 24,
    registry_request = 25,
    registry_data = 26,
    installation_ready = 27,
};

/// A replacement sends this only after its snapshot and decided registry
/// are durable and the matching transport generation is active.
pub const InstallationReady = struct {
    configuration_id: u64,
    registry_digest: [32]u8,

    pub const encoded_size = 8 + 32;

    pub fn encode(self: InstallationReady, buffer: *[encoded_size]u8) []const u8 {
        std.mem.writeInt(u64, buffer[0..8], self.configuration_id, .little);
        @memcpy(buffer[8..40], &self.registry_digest);
        return buffer;
    }

    pub fn decode(body: []const u8) WireError!InstallationReady {
        if (body.len != encoded_size) return error.InvalidFrame;
        const configuration_id = std.mem.readInt(u64, body[0..8], .little);
        if (configuration_id == 0) return error.InvalidFrame;
        return .{
            .configuration_id = configuration_id,
            .registry_digest = body[8..40].*,
        };
    }
};

pub const EnrollmentRequest = struct {
    secret: [32]u8,
    node_id: paxos.NodeId,
    database_id: u128,
    csr: []const u8,

    pub const max_csr_bytes: usize = 16 * 1024;
    pub const fixed_size: usize = 32 + 4 + 16 + 4;
    pub const max_encoded_size: usize = fixed_size + max_csr_bytes;

    pub fn encode(
        self: EnrollmentRequest,
        buffer: *[max_encoded_size]u8,
    ) WireError![]const u8 {
        if (self.node_id == 0 or self.database_id == 0 or self.csr.len == 0 or
            self.csr.len > max_csr_bytes)
        {
            return error.InvalidFrame;
        }
        @memcpy(buffer[0..32], &self.secret);
        std.mem.writeInt(u32, buffer[32..36], self.node_id, .little);
        std.mem.writeInt(u128, buffer[36..52], self.database_id, .little);
        std.mem.writeInt(u32, buffer[52..56], @intCast(self.csr.len), .little);
        @memcpy(buffer[56..][0..self.csr.len], self.csr);
        std.debug.assert(fixed_size + self.csr.len <= max_encoded_size);
        const encoded = buffer[0 .. fixed_size + self.csr.len];
        std.debug.assert(encoded.len <= max_encoded_size);
        return encoded;
    }

    pub fn decode(body: []const u8) WireError!EnrollmentRequest {
        if (body.len < fixed_size) return error.InvalidFrame;
        const csr_len = std.mem.readInt(u32, body[52..56], .little);
        if (csr_len == 0 or csr_len > max_csr_bytes or
            body.len != fixed_size + csr_len)
        {
            return error.InvalidFrame;
        }
        const node_id = std.mem.readInt(u32, body[32..36], .little);
        const database_id = std.mem.readInt(u128, body[36..52], .little);
        if (node_id == 0 or database_id == 0) return error.InvalidFrame;
        return .{
            .secret = body[0..32].*,
            .node_id = node_id,
            .database_id = database_id,
            .csr = body[56..],
        };
    }
};

/// The enrollment reply binds the issued certificate to the identity it
/// authorizes: database, node ID, the decided configuration, and the
/// decided registry digest a joining replacement later verifies its
/// fetched registry against.
pub const EnrollmentResponse = struct {
    status: Status,
    node_id: paxos.NodeId = 0,
    database_id: u128 = 0,
    configuration_id: u64 = 0,
    registry_digest: [32]u8 = [_]u8{0} ** 32,
    certificate: []const u8 = &.{},

    pub const Status = enum(u8) {
        ok = 0,
        refused = 1,
    };
    const binding_size = 1 + 4 + 16 + 8 + 32;
    pub const max_certificate_bytes: usize = 64 * 1024;
    pub const max_encoded_size: usize = binding_size + max_certificate_bytes;

    pub fn encode(
        self: EnrollmentResponse,
        buffer: *[max_encoded_size]u8,
    ) WireError![]const u8 {
        if (self.status == .refused) {
            if (self.certificate.len != 0) return error.InvalidFrame;
            buffer[0] = @intFromEnum(self.status);
            return buffer[0..1];
        }
        if (self.certificate.len == 0 or
            self.certificate.len > max_certificate_bytes or
            self.node_id == 0 or self.database_id == 0 or
            self.configuration_id == 0)
        {
            return error.InvalidFrame;
        }
        var cursor = types.Cursor{ .buffer = buffer };
        cursor.byte(@intFromEnum(self.status));
        cursor.int(u32, self.node_id);
        cursor.int(u128, self.database_id);
        cursor.int(u64, self.configuration_id);
        cursor.bytes(&self.registry_digest);
        cursor.bytes(self.certificate);
        std.debug.assert(cursor.offset <= max_encoded_size);
        return buffer[0..cursor.offset];
    }

    pub fn decode(body: []const u8) WireError!EnrollmentResponse {
        if (body.len == 0 or body.len > max_encoded_size) return error.InvalidFrame;
        const status = std.enums.fromInt(Status, body[0]) orelse
            return error.InvalidFrame;
        if (status == .refused) {
            if (body.len != 1) return error.InvalidFrame;
            return .{ .status = status };
        }
        if (body.len <= binding_size) return error.InvalidFrame;
        var reader = types.ReadCursor{ .buffer = body };
        _ = reader.byte() catch unreachable;
        const response = EnrollmentResponse{
            .status = status,
            .node_id = reader.int(u32) catch return error.InvalidFrame,
            .database_id = reader.int(u128) catch return error.InvalidFrame,
            .configuration_id = reader.int(u64) catch return error.InvalidFrame,
            .registry_digest = ((reader.take(32) catch
                return error.InvalidFrame)[0..32]).*,
            .certificate = body[binding_size..],
        };
        if (response.node_id == 0 or response.database_id == 0 or
            response.configuration_id == 0)
        {
            return error.InvalidFrame;
        }
        return response;
    }
};

/// Asks a current member for the canonical decided-registry blob of one
/// configuration. Sent by a joining replacement during snapshot install.
pub const RegistryRequest = struct {
    configuration_id: u64,

    pub const encoded_size = 8;

    pub fn encode(self: RegistryRequest, buffer: *[encoded_size]u8) []const u8 {
        std.mem.writeInt(u64, buffer[0..8], self.configuration_id, .little);
        return buffer;
    }

    pub fn decode(body: []const u8) WireError!RegistryRequest {
        if (body.len != encoded_size) return error.InvalidFrame;
        const configuration_id = std.mem.readInt(u64, body[0..8], .little);
        if (configuration_id == 0) return error.InvalidFrame;
        return .{ .configuration_id = configuration_id };
    }
};

/// One stored decided-registry blob (canonical bytes plus its digest
/// trailer). The receiver verifies it against the digest the chosen stop
/// sign bound before trusting a single byte.
pub const RegistryData = struct {
    configuration_id: u64,
    blob: []const u8,

    pub const max_blob_bytes: usize = 8 * 1024;
    pub const max_encoded_size: usize = 8 + max_blob_bytes;

    pub fn encode(self: RegistryData, buffer: *[max_encoded_size]u8) WireError![]const u8 {
        if (self.blob.len == 0 or self.blob.len > max_blob_bytes) {
            return error.InvalidFrame;
        }
        var cursor = types.Cursor{ .buffer = buffer };
        cursor.int(u64, self.configuration_id);
        cursor.bytes(self.blob);
        return buffer[0..cursor.offset];
    }

    pub fn decode(body: []const u8) WireError!RegistryData {
        if (body.len <= 8 or body.len > max_encoded_size) return error.InvalidFrame;
        const configuration_id = std.mem.readInt(u64, body[0..8], .little);
        if (configuration_id == 0) return error.InvalidFrame;
        return .{ .configuration_id = configuration_id, .blob = body[8..] };
    }
};

pub const LearnerHeartbeat = struct {
    configuration_id: u64,
    decided_through: paxos.Slot,

    pub const encoded_size = 8 + 4;

    pub fn encode(self: LearnerHeartbeat, buffer: *[encoded_size]u8) []const u8 {
        std.mem.writeInt(u64, buffer[0..8], self.configuration_id, .little);
        std.mem.writeInt(u32, buffer[8..12], self.decided_through, .little);
        return buffer;
    }

    pub fn decode(body: []const u8) WireError!LearnerHeartbeat {
        if (body.len != encoded_size) return error.InvalidFrame;
        const configuration_id = std.mem.readInt(u64, body[0..8], .little);
        if (configuration_id == 0) return error.InvalidFrame;
        return .{
            .configuration_id = configuration_id,
            .decided_through = std.mem.readInt(u32, body[8..12], .little),
        };
    }
};

pub const LearnerCommit = struct {
    configuration_id: u64,
    slot: paxos.Slot,
    entry: types.Entry,

    pub fn encode(self: LearnerCommit, buffer: *[encoded_max]u8) []const u8 {
        var cursor = types.Cursor{ .buffer = buffer };
        cursor.int(u64, self.configuration_id);
        cursor.int(u32, self.slot);
        types.encodeEntry(self.entry, &cursor);
        return buffer[0..cursor.offset];
    }

    pub fn decode(body: []const u8) WireError!LearnerCommit {
        var reader = types.ReadCursor{ .buffer = body };
        const configuration_id = try reader.int(u64);
        const slot = try reader.int(u32);
        const entry = try types.decodeEntry(&reader);
        if (configuration_id == 0 or slot == 0 or reader.offset != body.len) {
            return error.InvalidFrame;
        }
        return .{
            .configuration_id = configuration_id,
            .slot = slot,
            .entry = entry,
        };
    }

    pub const encoded_max = 8 + 4 + types.max_entry_size;
};

pub const BackupBegin = struct {
    size: u64,
    sha256: [32]u8,

    pub const encoded_size = 8 + 32;

    pub fn encode(self: BackupBegin, buffer: *[encoded_size]u8) []const u8 {
        std.mem.writeInt(u64, buffer[0..8], self.size, .little);
        @memcpy(buffer[8..40], &self.sha256);
        return buffer;
    }

    pub fn decode(body: []const u8) WireError!BackupBegin {
        if (body.len != encoded_size) return error.InvalidFrame;
        return .{
            .size = std.mem.readInt(u64, body[0..8], .little),
            .sha256 = body[8..40].*,
        };
    }
};

pub const WireError = error{
    InvalidFrame,
    FrameTooLarge,
    InvalidHello,
    UnsupportedProtocolVersion,
} || types.DecodeError;

pub const ConnectionKind = enum(u8) { peer = 0, client = 1, enrollment = 2 };

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

/// Returns the transaction-batch payload hash carried by a value-bearing
/// promise, accept, or commit envelope, if any. Gating promises is essential:
/// completing Phase 1 can emit recovery accepts in the same core transition.
pub fn envelopePayloadHash(envelope: types.Log.Envelope) ?command.HashBytes {
    const entry: types.Entry = switch (envelope.message) {
        .promise => |m| m.accepted.value,
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
    fence_slot: paxos.Slot,

    pub const encoded_size = types.ballot_size + 8 + 4;

    pub fn encode(self: FenceRequest, buffer: *[encoded_size]u8) []const u8 {
        var cursor = types.Cursor{ .buffer = buffer };
        types.encodeBallot(self.ballot, &cursor);
        cursor.int(u64, self.fence_id);
        cursor.int(u32, self.fence_slot);
        return buffer[0..cursor.offset];
    }

    pub fn decode(body: []const u8) WireError!FenceRequest {
        if (body.len != encoded_size) return error.InvalidFrame;
        var reader = types.ReadCursor{ .buffer = body };
        return .{
            .ballot = try types.decodeBallot(&reader),
            .fence_id = try reader.int(u64),
            .fence_slot = try reader.int(u32),
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
    proof: []const u8,

    pub const max_manifest_bytes = 4096;
    pub const max_proof_bytes = 768;
    pub const max_encoded_size = 8 + 16 + 8 + 4 + max_manifest_bytes +
        2 + max_proof_bytes;

    pub fn encode(self: SnapshotBegin, buffer: *[max_encoded_size]u8) []const u8 {
        std.debug.assert(self.manifest.len <= max_manifest_bytes);
        std.debug.assert(self.proof.len <= max_proof_bytes);
        var cursor = types.Cursor{ .buffer = buffer };
        cursor.int(u64, self.configuration_id);
        cursor.bytes(&self.name);
        cursor.int(u64, self.db_size);
        cursor.int(u32, @intCast(self.manifest.len));
        cursor.bytes(self.manifest);
        cursor.int(u16, @intCast(self.proof.len));
        cursor.bytes(self.proof);
        return buffer[0..cursor.offset];
    }

    /// The returned manifest and proof slices alias `body`.
    pub fn decode(body: []const u8) WireError!SnapshotBegin {
        var reader = types.ReadCursor{ .buffer = body };
        const configuration_id = try reader.int(u64);
        const name = try reader.take(16);
        const db_size = try reader.int(u64);
        const manifest_len = try reader.int(u32);
        if (manifest_len > max_manifest_bytes) return error.InvalidFrame;
        const manifest = try reader.take(manifest_len);
        const proof_len = try reader.int(u16);
        if (proof_len == 0 or proof_len > max_proof_bytes) {
            return error.InvalidFrame;
        }
        const proof = try reader.take(proof_len);
        if (reader.offset != body.len) return error.InvalidFrame;
        return .{
            .configuration_id = configuration_id,
            .name = name[0..16].*,
            .db_size = db_size,
            .manifest = manifest,
            .proof = proof,
        };
    }
};

/// A receiver asks configured voters whether they retain the same proof for
/// the sealed epoch. Matching replies are read-quorum evidence about a stop
/// sign Paxos already chose; they do not constitute a new consensus phase.
pub const CheckpointProofProbe = struct {
    nonce: u64,
    sealed_configuration_id: u64,
    digest: [32]u8,

    pub const encoded_size = 8 + 8 + 32;

    pub fn encode(
        self: CheckpointProofProbe,
        buffer: *[encoded_size]u8,
    ) []const u8 {
        std.mem.writeInt(u64, buffer[0..8], self.nonce, .little);
        std.mem.writeInt(
            u64,
            buffer[8..16],
            self.sealed_configuration_id,
            .little,
        );
        @memcpy(buffer[16..48], &self.digest);
        return buffer;
    }

    pub fn decode(body: []const u8) WireError!CheckpointProofProbe {
        if (body.len != encoded_size) return error.InvalidFrame;
        const nonce = std.mem.readInt(u64, body[0..8], .little);
        const sealed = std.mem.readInt(u64, body[8..16], .little);
        if (nonce == 0 or sealed == 0) return error.InvalidFrame;
        return .{
            .nonce = nonce,
            .sealed_configuration_id = sealed,
            .digest = body[16..48].*,
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
    if (body.len >= max_frame_bytes) return error.FrameTooLarge;
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
    for (parts) |part| {
        body_len = std.math.add(usize, body_len, part.len) catch
            return error.FrameTooLarge;
    }
    if (body_len >= max_frame_bytes) return error.FrameTooLarge;
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
    const promise = types.Log.Envelope{
        .from = 2,
        .to = 1,
        .message = .{ .promise = .{
            .ballot = .{ .round = 2, .priority = 1, .node = 1 },
            .slot = 7,
            .accepted = .{
                .ballot = .{ .round = 1, .priority = 2, .node = 2 },
                .value = .{ .command = .{ .transaction_batch = batch } },
            },
        } },
    };
    try testing.expectEqualSlices(
        u8,
        &batch.payload_hash,
        &envelopePayloadHash(promise).?,
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
        .fence_slot = 19,
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

test "learner commit round trips and rejects invalid certificates" {
    const commit = LearnerCommit{
        .configuration_id = 7,
        .slot = 19,
        .entry = .{ .command = .{ .read_barrier = .{ .nonce = 41 } } },
    };
    var buffer: [LearnerCommit.encoded_max]u8 = undefined;
    const encoded = commit.encode(&buffer);
    try testing.expectEqualDeep(commit, try LearnerCommit.decode(encoded));

    var invalid = buffer;
    std.mem.writeInt(u64, invalid[0..8], 0, .little);
    try testing.expectError(
        error.InvalidFrame,
        LearnerCommit.decode(invalid[0..encoded.len]),
    );
    try testing.expectError(
        error.TruncatedRecord,
        LearnerCommit.decode(buffer[0 .. encoded.len - 1]),
    );
}

test "learner heartbeat round trips" {
    const heartbeat = LearnerHeartbeat{
        .configuration_id = 8,
        .decided_through = 144,
    };
    var buffer: [LearnerHeartbeat.encoded_size]u8 = undefined;
    try testing.expectEqualDeep(
        heartbeat,
        try LearnerHeartbeat.decode(heartbeat.encode(&buffer)),
    );
}

test "snapshot begin round trips and bounds the manifest" {
    const begin = SnapshotBegin{
        .configuration_id = 6,
        .name = "0000000000000006".*,
        .db_size = 8192,
        .manifest = "format=1\nchain=00\n",
        .proof = "proof",
    };
    var buffer: [SnapshotBegin.max_encoded_size]u8 = undefined;
    const encoded = begin.encode(&buffer);
    const decoded = try SnapshotBegin.decode(encoded);
    try testing.expectEqual(begin.configuration_id, decoded.configuration_id);
    try testing.expectEqualStrings(begin.manifest, decoded.manifest);
    try testing.expectEqualStrings(begin.proof, decoded.proof);
}

test "checkpoint proof probe round trips" {
    const probe = CheckpointProofProbe{
        .nonce = 19,
        .sealed_configuration_id = 6,
        .digest = [_]u8{0xab} ** 32,
    };
    var buffer: [CheckpointProofProbe.encoded_size]u8 = undefined;
    try testing.expectEqualDeep(
        probe,
        try CheckpointProofProbe.decode(probe.encode(&buffer)),
    );
}

test "installation readiness binds configuration and registry" {
    const ready = InstallationReady{
        .configuration_id = 8,
        .registry_digest = [_]u8{0x7a} ** 32,
    };
    var buffer: [InstallationReady.encoded_size]u8 = undefined;
    try testing.expectEqualDeep(
        ready,
        try InstallationReady.decode(ready.encode(&buffer)),
    );
    buffer[0] = 0;
    @memset(buffer[1..8], 0);
    try testing.expectError(error.InvalidFrame, InstallationReady.decode(&buffer));
}

test "enrollment request and response are bounded" {
    const request = EnrollmentRequest{
        .secret = [_]u8{0xa5} ** 32,
        .node_id = 3,
        .database_id = 91,
        .csr = "-----BEGIN CERTIFICATE REQUEST-----\ncsr\n",
    };
    var request_buffer: [EnrollmentRequest.max_encoded_size]u8 = undefined;
    const decoded = try EnrollmentRequest.decode(try request.encode(&request_buffer));
    try testing.expectEqual(request.secret, decoded.secret);
    try testing.expectEqual(request.node_id, decoded.node_id);
    try testing.expectEqual(request.database_id, decoded.database_id);
    try testing.expectEqualStrings(request.csr, decoded.csr);

    var response_buffer: [EnrollmentResponse.max_encoded_size]u8 = undefined;
    const response = EnrollmentResponse{
        .status = .ok,
        .node_id = 3,
        .database_id = 91,
        .configuration_id = 7,
        .registry_digest = [_]u8{0x5c} ** 32,
        .certificate = "cert",
    };
    const decoded_response = try EnrollmentResponse.decode(
        try response.encode(&response_buffer),
    );
    try testing.expectEqual(EnrollmentResponse.Status.ok, decoded_response.status);
    try testing.expectEqual(@as(u32, 3), decoded_response.node_id);
    try testing.expectEqual(@as(u128, 91), decoded_response.database_id);
    try testing.expectEqual(@as(u64, 7), decoded_response.configuration_id);
    try testing.expectEqual([_]u8{0x5c} ** 32, decoded_response.registry_digest);
    try testing.expectEqualStrings("cert", decoded_response.certificate);
    try testing.expectError(
        error.InvalidFrame,
        EnrollmentResponse.decode(&.{@intFromEnum(EnrollmentResponse.Status.ok)}),
    );

    var registry_buffer: [RegistryData.max_encoded_size]u8 = undefined;
    const registry_data = RegistryData{ .configuration_id = 7, .blob = "blob" };
    const decoded_registry = try RegistryData.decode(
        try registry_data.encode(&registry_buffer),
    );
    try testing.expectEqual(@as(u64, 7), decoded_registry.configuration_id);
    try testing.expectEqualStrings("blob", decoded_registry.blob);
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

test "frame allocation rejects oversized bodies" {
    const too_large = try testing.allocator.alloc(u8, max_frame_bytes);
    defer testing.allocator.free(too_large);
    try testing.expectError(
        error.FrameTooLarge,
        frameAlloc(testing.allocator, .payload_data, &.{too_large}),
    );
}
