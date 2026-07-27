//! Canonical proof retained beside each transferable checkpoint.
//!
//! The proof is not a signature and does not create a second consensus
//! phase. It serializes the stop sign that Paxos already chose, binding
//! both sides of the transition: the sealed configuration and its voter
//! set, the next configuration and its voter set, the stop slot, the exact
//! stop metadata, the manifest digest, the next-registry digest, the
//! applied slot, and the chain hash. A receiver accepts the snapshot only
//! after a read quorum of the *sealed* voter set reports the same proof
//! digest over authenticated transport; the proposed next voter never
//! counts toward that quorum.

const std = @import("std");
const paxos = @import("paxos");
const types = @import("types.zig");

const magic = "ZXP2";
pub const max_encoded_bytes: usize = 768;

/// All-zero digest written by registry-less embedded and local hosts.
pub const no_registry_digest = [_]u8{0} ** 32;

comptime {
    const fixed = magic.len + @sizeOf(u128) + 2 * @sizeOf(u64) +
        2 * @sizeOf(u32) + 3 * 32 + 3 * @sizeOf(u16);
    const worst = fixed +
        2 * types.log_options.max_members * @sizeOf(paxos.NodeId) +
        types.log_options.max_metadata_bytes;
    if (worst > max_encoded_bytes) {
        @compileError("checkpoint proof bound is smaller than its worst case");
    }
}

pub const Proof = struct {
    database_id: u128,
    sealed_configuration_id: u64,
    next_configuration_id: u64,
    stop_slot: paxos.Slot,
    applied_slot: paxos.Slot,
    chain: [32]u8,
    manifest_sha256: [32]u8,
    /// Digest of the canonical decided registry for the next
    /// configuration; all zero on registry-less hosts.
    next_registry_digest: [32]u8,
    sealed_members: [types.log_options.max_members]paxos.NodeId,
    sealed_count: u16,
    next_members: [types.log_options.max_members]paxos.NodeId,
    next_count: u16,
    metadata: [types.log_options.max_metadata_bytes]u8,
    metadata_count: u16,

    /// Voters of the configuration that chose the stop sign. Quorum
    /// confirmation counts distinct IDs from exactly this set.
    pub fn sealedMembersSlice(self: *const Proof) []const paxos.NodeId {
        return self.sealed_members[0..self.sealed_count];
    }

    /// Voters of the configuration the stop sign starts.
    pub fn nextMembersSlice(self: *const Proof) []const paxos.NodeId {
        return self.next_members[0..self.next_count];
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

fn validateMembers(members: []const paxos.NodeId) !void {
    if (members.len == 0 or members.len > types.log_options.max_members) {
        return error.InvalidCheckpointProof;
    }
    for (members, 0..) |member, index| {
        if (member == 0) return error.InvalidCheckpointProof;
        if (index > 0 and members[index - 1] >= member) {
            return error.InvalidCheckpointProof;
        }
    }
}

pub fn create(
    database_id: u128,
    sealed_configuration_id: u64,
    next_configuration_id: u64,
    stop_slot: paxos.Slot,
    applied_slot: paxos.Slot,
    chain: [32]u8,
    manifest_sha256: [32]u8,
    next_registry_digest: [32]u8,
    sealed_members: []const paxos.NodeId,
    next_members: []const paxos.NodeId,
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
    if (metadata.len > types.log_options.max_metadata_bytes) {
        return error.InvalidCheckpointProof;
    }
    try validateMembers(sealed_members);
    try validateMembers(next_members);
    // Replacement never changes the voter count; a same-member checkpoint
    // carries identical sets.
    if (sealed_members.len != next_members.len) {
        return error.InvalidCheckpointProof;
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
    cursor.bytes(&next_registry_digest);
    cursor.int(u16, @intCast(sealed_members.len));
    cursor.int(u16, @intCast(next_members.len));
    cursor.int(u16, @intCast(metadata.len));
    for (sealed_members) |member| cursor.int(u32, member);
    for (next_members) |member| cursor.int(u32, member);
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
        .next_registry_digest = undefined,
        .sealed_members = [_]paxos.NodeId{0} ** types.log_options.max_members,
        .sealed_count = 0,
        .next_members = [_]paxos.NodeId{0} ** types.log_options.max_members,
        .next_count = 0,
        .metadata = [_]u8{0} ** types.log_options.max_metadata_bytes,
        .metadata_count = 0,
    };
    @memcpy(&proof.chain, reader.take(32) catch
        return error.InvalidCheckpointProof);
    @memcpy(&proof.manifest_sha256, reader.take(32) catch
        return error.InvalidCheckpointProof);
    @memcpy(&proof.next_registry_digest, reader.take(32) catch
        return error.InvalidCheckpointProof);
    proof.sealed_count = reader.int(u16) catch
        return error.InvalidCheckpointProof;
    proof.next_count = reader.int(u16) catch return error.InvalidCheckpointProof;
    proof.metadata_count = reader.int(u16) catch
        return error.InvalidCheckpointProof;

    if (proof.database_id == 0 or proof.sealed_configuration_id == 0 or
        proof.sealed_configuration_id == std.math.maxInt(u64) or
        proof.next_configuration_id != proof.sealed_configuration_id + 1 or
        proof.stop_slot == 0 or
        proof.applied_slot == std.math.maxInt(paxos.Slot) or
        proof.applied_slot + 1 != proof.stop_slot or
        proof.sealed_count == 0 or
        proof.sealed_count > types.log_options.max_members or
        proof.next_count != proof.sealed_count or
        proof.metadata_count > types.log_options.max_metadata_bytes)
    {
        return error.InvalidCheckpointProof;
    }
    for (proof.sealed_members[0..proof.sealed_count]) |*member| {
        member.* = reader.int(u32) catch return error.InvalidCheckpointProof;
    }
    for (proof.next_members[0..proof.next_count]) |*member| {
        member.* = reader.int(u32) catch return error.InvalidCheckpointProof;
    }
    validateMembers(proof.sealedMembersSlice()) catch
        return error.InvalidCheckpointProof;
    validateMembers(proof.nextMembersSlice()) catch
        return error.InvalidCheckpointProof;
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

test "checkpoint proof binds both voter sets and rejects truncation" {
    const sealed = [_]paxos.NodeId{ 1, 2, 3 };
    const next = [_]paxos.NodeId{ 1, 2, 4 };
    const encoded = try create(
        9,
        4,
        5,
        8,
        7,
        [_]u8{1} ** 32,
        [_]u8{2} ** 32,
        [_]u8{3} ** 32,
        &sealed,
        &next,
        "zx2 0000000000000004 digest registry",
    );
    const proof = try decode(encoded.slice());
    try std.testing.expectEqual(@as(u64, 4), proof.sealed_configuration_id);
    try std.testing.expectEqualSlices(
        paxos.NodeId,
        &sealed,
        proof.sealedMembersSlice(),
    );
    try std.testing.expectEqualSlices(
        paxos.NodeId,
        &next,
        proof.nextMembersSlice(),
    );
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{3} ** 32),
        &proof.next_registry_digest,
    );
    try std.testing.expectEqualStrings(
        "zx2 0000000000000004 digest registry",
        proof.metadataSlice(),
    );
    try std.testing.expectError(
        error.InvalidCheckpointProof,
        decode(encoded.slice()[0 .. encoded.len - 1]),
    );
}

test "checkpoint proof rejects a changed voter count" {
    const sealed = [_]paxos.NodeId{ 1, 2, 3 };
    const grown = [_]paxos.NodeId{ 1, 2, 3, 4 };
    try std.testing.expectError(error.InvalidCheckpointProof, create(
        9,
        4,
        5,
        8,
        7,
        [_]u8{1} ** 32,
        [_]u8{2} ** 32,
        no_registry_digest,
        &sealed,
        &grown,
        "zx1 0000000000000004 digest",
    ));
}

test "checkpoint proof decoder rejects unsorted voter ids" {
    const members = [_]paxos.NodeId{ 1, 2, 3 };
    var encoded = try create(
        9,
        4,
        5,
        8,
        7,
        [_]u8{1} ** 32,
        [_]u8{2} ** 32,
        no_registry_digest,
        &members,
        &members,
        "zx1 0000000000000004 digest",
    );
    const first_member_offset = 146;
    const first = std.mem.readInt(
        u32,
        encoded.bytes[first_member_offset..][0..4],
        .little,
    );
    const second = std.mem.readInt(
        u32,
        encoded.bytes[first_member_offset + 4 ..][0..4],
        .little,
    );
    std.mem.writeInt(
        u32,
        encoded.bytes[first_member_offset..][0..4],
        second,
        .little,
    );
    std.mem.writeInt(
        u32,
        encoded.bytes[first_member_offset + 4 ..][0..4],
        first,
        .little,
    );
    try std.testing.expectError(
        error.InvalidCheckpointProof,
        decode(encoded.slice()),
    );
}
