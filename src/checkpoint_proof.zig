//! Canonical proof retained beside each transferable checkpoint.
//!
//! The proof is not a signature and does not create a second consensus
//! phase. It serializes the stop sign that Paxos already chose: the sealed
//! and next configuration, stop slot, static voter set, exact stop metadata,
//! manifest digest, applied slot, and chain hash. A receiver accepts the
//! snapshot only after a read quorum of configured voters reports the same
//! proof digest over authenticated transport.

const std = @import("std");
const paxos = @import("paxos");
const types = @import("types.zig");

const magic = "ZXP1";
pub const max_encoded_bytes: usize = 512;

pub const Proof = struct {
    database_id: u128,
    sealed_configuration_id: u64,
    next_configuration_id: u64,
    stop_slot: paxos.Slot,
    applied_slot: paxos.Slot,
    chain: [32]u8,
    manifest_sha256: [32]u8,
    members: [types.log_options.max_members]paxos.NodeId,
    member_count: u8,
    metadata: [types.log_options.max_metadata_bytes]u8,
    metadata_count: u16,

    pub fn membersSlice(self: *const Proof) []const paxos.NodeId {
        return self.members[0..self.member_count];
    }

    pub fn metadataSlice(self: *const Proof) []const u8 {
        return self.metadata[0..self.metadata_count];
    }
};

pub const Encoded = struct {
    bytes: [max_encoded_bytes]u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const Encoded) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub fn create(
    database_id: u128,
    sealed_configuration_id: u64,
    next_configuration_id: u64,
    stop_slot: paxos.Slot,
    applied_slot: paxos.Slot,
    chain: [32]u8,
    manifest_sha256: [32]u8,
    members: []const paxos.NodeId,
    metadata: []const u8,
) !Encoded {
    if (database_id == 0 or sealed_configuration_id == 0 or
        sealed_configuration_id == std.math.maxInt(u64) or
        next_configuration_id != sealed_configuration_id + 1 or
        stop_slot == 0 or applied_slot == std.math.maxInt(paxos.Slot) or
        applied_slot + 1 != stop_slot)
    {
        return error.InvalidCheckpointProof;
    }
    if (members.len == 0 or members.len > types.log_options.max_members or
        metadata.len > types.log_options.max_metadata_bytes)
    {
        return error.InvalidCheckpointProof;
    }
    for (members, 0..) |member, index| {
        if (member == 0) return error.InvalidCheckpointProof;
        for (members[0..index]) |previous| {
            if (previous == member) return error.InvalidCheckpointProof;
        }
    }

    var encoded = Encoded{};
    var cursor = types.Cursor{ .buffer = &encoded.bytes };
    cursor.bytes(magic);
    cursor.int(u128, database_id);
    cursor.int(u64, sealed_configuration_id);
    cursor.int(u64, next_configuration_id);
    cursor.int(u32, stop_slot);
    cursor.int(u32, applied_slot);
    cursor.bytes(&chain);
    cursor.bytes(&manifest_sha256);
    cursor.byte(@intCast(members.len));
    cursor.int(u16, @intCast(metadata.len));
    for (members) |member| cursor.int(u32, member);
    cursor.bytes(metadata);
    encoded.len = cursor.offset;
    std.debug.assert(encoded.len <= encoded.bytes.len);
    return encoded;
}

pub fn decode(bytes: []const u8) !Proof {
    if (bytes.len > max_encoded_bytes) return error.InvalidCheckpointProof;
    var reader = types.ReadCursor{ .buffer = bytes };
    const found_magic = reader.take(magic.len) catch
        return error.InvalidCheckpointProof;
    if (!std.mem.eql(u8, found_magic, magic)) return error.InvalidCheckpointProof;

    var proof = Proof{
        .database_id = reader.int(u128) catch return error.InvalidCheckpointProof,
        .sealed_configuration_id = reader.int(u64) catch
            return error.InvalidCheckpointProof,
        .next_configuration_id = reader.int(u64) catch
            return error.InvalidCheckpointProof,
        .stop_slot = reader.int(u32) catch return error.InvalidCheckpointProof,
        .applied_slot = reader.int(u32) catch return error.InvalidCheckpointProof,
        .chain = undefined,
        .manifest_sha256 = undefined,
        .members = [_]paxos.NodeId{0} ** types.log_options.max_members,
        .member_count = 0,
        .metadata = [_]u8{0} ** types.log_options.max_metadata_bytes,
        .metadata_count = 0,
    };
    // The fixed hashes precede the counts on the wire. Read them before
    // interpreting the count fields initialized above.
    reader.offset = magic.len + @sizeOf(u128) + @sizeOf(u64) * 2 +
        @sizeOf(u32) * 2;
    const chain = reader.take(32) catch return error.InvalidCheckpointProof;
    const manifest = reader.take(32) catch return error.InvalidCheckpointProof;
    @memcpy(&proof.chain, chain);
    @memcpy(&proof.manifest_sha256, manifest);
    proof.member_count = reader.byte() catch return error.InvalidCheckpointProof;
    proof.metadata_count = reader.int(u16) catch return error.InvalidCheckpointProof;

    if (proof.database_id == 0 or proof.sealed_configuration_id == 0 or
        proof.sealed_configuration_id == std.math.maxInt(u64) or
        proof.next_configuration_id != proof.sealed_configuration_id + 1 or
        proof.stop_slot == 0 or
        proof.applied_slot == std.math.maxInt(paxos.Slot) or
        proof.applied_slot + 1 != proof.stop_slot or
        proof.member_count == 0 or
        proof.member_count > types.log_options.max_members or
        proof.metadata_count > types.log_options.max_metadata_bytes)
    {
        return error.InvalidCheckpointProof;
    }
    for (proof.members[0..proof.member_count], 0..) |*member, index| {
        member.* = reader.int(u32) catch return error.InvalidCheckpointProof;
        if (member.* == 0) return error.InvalidCheckpointProof;
        for (proof.members[0..index]) |previous| {
            if (previous == member.*) return error.InvalidCheckpointProof;
        }
    }
    const metadata = reader.take(proof.metadata_count) catch
        return error.InvalidCheckpointProof;
    @memcpy(proof.metadata[0..proof.metadata_count], metadata);
    if (reader.offset != bytes.len) return error.InvalidCheckpointProof;
    return proof;
}

pub fn digest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

test "checkpoint proof is canonical and rejects truncation" {
    const members = [_]paxos.NodeId{ 1, 2, 3 };
    const encoded = try create(
        9,
        4,
        5,
        8,
        7,
        [_]u8{1} ** 32,
        [_]u8{2} ** 32,
        &members,
        "zx1 0000000000000004 digest",
    );
    const proof = try decode(encoded.slice());
    try std.testing.expectEqual(@as(u64, 4), proof.sealed_configuration_id);
    try std.testing.expectEqualSlices(paxos.NodeId, &members, proof.membersSlice());
    try std.testing.expectEqualStrings(
        "zx1 0000000000000004 digest",
        proof.metadataSlice(),
    );
    try std.testing.expectError(
        error.InvalidCheckpointProof,
        decode(encoded.slice()[0 .. encoded.len - 1]),
    );
}
