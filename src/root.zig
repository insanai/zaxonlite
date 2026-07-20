//! Zaxonlite: an embedded SQLite service replicated by the paxos-zig
//! Multi-Paxos library.
//!
//! The Paxos journal plus content-addressed payload store are the
//! authoritative durable state. The SQLite database image is a materialized
//! state machine rebuildable from a snapshot plus the committed journal
//! suffix.

const std = @import("std");

pub const version = "unreleased";

pub const command = @import("command.zig");
pub const Command = command.Command;
pub const types = @import("types.zig");
pub const journal = @import("journal.zig");
pub const payload_store = @import("payload_store.zig");
pub const PayloadStore = payload_store.PayloadStore;
pub const wal = @import("wal.zig");
pub const sqlite = @import("sqlite.zig");
pub const prepared = @import("prepared.zig");
pub const Value = prepared.Value;
pub const Transaction = prepared.Transaction;
pub const wire = @import("wire.zig");
pub const transport_auth = @import("transport_auth.zig");
pub const configuration = @import("configuration.zig");
pub const diagnostic = @import("diagnostic.zig");
pub const node = @import("node.zig");
pub const roles = @import("roles.zig");
pub const Node = node.Node;
pub const OpenOptions = node.OpenOptions;
pub const Role = roles.Role;
pub const ExecResult = node.ExecResult;
pub const QueryResult = node.QueryResult;
pub const server = @import("server.zig");
pub const client = @import("client.zig");
pub const gateway = @import("gateway.zig");
pub const embedded = @import("embedded.zig");
pub const Embedded = embedded.Embedded;
pub const EmbeddedMember = embedded.Member;
pub const EmbeddedOpenOptions = embedded.OpenOptions;

test {
    _ = @import("command.zig");
    _ = @import("types.zig");
    _ = @import("journal.zig");
    _ = @import("payload_store.zig");
    _ = @import("sqlite.zig");
    _ = @import("prepared.zig");
    _ = @import("wal.zig");
    _ = @import("wire.zig");
    _ = @import("transport_auth.zig");
    _ = @import("configuration.zig");
    _ = @import("node.zig");
    _ = @import("roles.zig");
    _ = @import("server.zig");
    _ = @import("client.zig");
    _ = @import("gateway.zig");
    _ = @import("embedded.zig");
}

test "sqlite is linked and recent" {
    const c = @import("c");
    try std.testing.expect(c.sqlite3_libversion_number() >= 3050000);
}
