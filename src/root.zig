//! Zaxonlite: an embedded SQLite service replicated by the paxos-zig
//! Multi-Paxos library.
//!
//! The Paxos journal plus content-addressed payload store are the
//! authoritative durable state. The SQLite database image is a materialized
//! state machine rebuildable from a snapshot plus the committed journal
//! suffix.

const std = @import("std");

pub const version = "0.1.0";

pub const command = @import("command.zig");
pub const Command = command.Command;
pub const types = @import("types.zig");
pub const journal = @import("journal.zig");
pub const payload_store = @import("payload_store.zig");
pub const PayloadStore = payload_store.PayloadStore;
pub const wal = @import("wal.zig");
pub const sqlite = @import("sqlite.zig");
pub const wire = @import("wire.zig");
pub const node = @import("node.zig");
pub const Node = node.Node;
pub const OpenOptions = node.OpenOptions;
pub const ExecResult = node.ExecResult;
pub const QueryResult = node.QueryResult;
pub const server = @import("server.zig");
pub const client = @import("client.zig");

test {
    _ = @import("command.zig");
    _ = @import("types.zig");
    _ = @import("journal.zig");
    _ = @import("payload_store.zig");
    _ = @import("sqlite.zig");
    _ = @import("wal.zig");
    _ = @import("wire.zig");
    _ = @import("node.zig");
    _ = @import("server.zig");
    _ = @import("client.zig");
}

test "sqlite is linked and recent" {
    const c = @import("c");
    try std.testing.expect(c.sqlite3_libversion_number() >= 3050000);
}
