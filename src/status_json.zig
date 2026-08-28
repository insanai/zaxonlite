//! Serializes the fixed head of the server's status JSON: every field
//! before the membership-operation section. Split from the server so the
//! request surface stays within the file's code-size pin.

const std = @import("std");
const Io = std.Io;
const node_mod = @import("node.zig");

pub fn writeHead(
    out: *Io.Writer,
    status: node_mod.Status,
    leader: ?u32,
    phase: []const u8,
    quorum_available: bool,
    installation_state: []const u8,
) !void {
    const chain_hex = std.fmt.bytesToHex(status.chain, .lower);
    try out.print(
        "{{\"ok\":true,\"node_id\":{d},\"database_id\":\"{x:0>32}\"," ++
            "\"configuration_id\":{d},\"role\":\"{s}\"," ++
            "\"node_type\":\"{s}\",\"leader\":{?d}," ++
            "\"phase\":\"{s}\",\"quorum_available\":{}," ++
            "\"installation_state\":\"{s}\"," ++
            "\"ballot\":{{\"round\":{d},\"priority\":{d},\"node\":{d}}}," ++
            "\"decided_slot\":{d},\"applied_slot\":{d}," ++
            "\"durable_state_slot\":{d},\"memory_floor\":{d}," ++
            "\"chosen_trim_slot\":{d},\"retained_first_slot\":{d}," ++
            "\"journal_records\":{d},\"journal_segment_count\":{d}," ++
            "\"journal_bytes\":{d}," ++
            "\"chain\":\"{s}\",\"page_size\":{d}," ++
            "\"fts5_enabled\":{}," ++
            "\"sqlite_vec_version\":\"{s}\"," ++
            "\"search_feature_version\":{d}," ++
            "\"simd_backend\":\"{s}\"," ++
            "\"mmap_size\":{d}," ++
            "\"candidate_hard_limit\":{d}," ++
            "\"write_gate\":\"fifo-v1\"," ++
            "\"typed_v1\":true,",
        .{
            status.node_id,              status.database_id,
            status.configuration_id,     status.role,
            status.node_type,            leader,
            phase,                       quorum_available,
            installation_state,          status.ballot.round,
            status.ballot.priority,      status.ballot.node,
            status.decided_slot,         status.applied_slot,
            status.durable_state_slot,   status.memory_floor,
            status.chosen_trim_slot,     status.retained_first_slot,
            status.journal_records,      status.journal_segment_count,
            status.journal_bytes,        &chain_hex,
            status.page_size,            status.fts5_enabled,
            status.sqlite_vec_version,   status.search_feature_version,
            status.simd_backend,         status.mmap_size,
            status.candidate_hard_limit,
        },
    );
}
