//! Zaxonlite: an embedded SQLite service replicated by the paxos-zig
//! Multi-Paxos library.
//!
//! The Paxos journal plus content-addressed payload store are the
//! authoritative durable state. The SQLite database image is a materialized
//! state machine rebuildable from a snapshot plus the committed journal
//! suffix.

const std = @import("std");

/// Human-readable library version; replaced by the release tag when one exists.
pub const version = "unreleased";

/// Fixed-size replicated command descriptor and its canonical wire codec.
pub const command = @import("command.zig");
/// The command value carried in every Paxos slot; names payloads by content hash.
pub const Command = command.Command;
/// The one concrete ReplicatedLog instantiation and its entry/write encodings.
pub const types = @import("types.zig");
/// Framed, checksummed, append-only protocol journal: the authoritative state.
pub const journal = @import("journal.zig");
/// Content-addressed, immutable transaction payload store (SHA-256 named).
pub const payload_store = @import("payload_store.zig");
/// Store for transaction payload bytes, installed with write-temp/sync/rename.
pub const PayloadStore = payload_store.PayloadStore;
/// SQLite WAL frame capture and deterministic page-level apply.
pub const wal = @import("wal.zig");
/// Narrow SQLite C API bindings; the only module that touches the C header.
pub const sqlite = @import("sqlite.zig");
/// Prepared parameter values and the copied, bounded transaction builder.
pub const prepared = @import("prepared.zig");
/// One bound SQL parameter: null, integer, real, text, or blob.
pub const Value = prepared.Value;
/// Multi-statement builder committed as one replicated SQLite transaction.
pub const Transaction = prepared.Transaction;
/// Length-prefixed peer and client wire protocol frames.
pub const wire = @import("wire.zig");
/// Mutual PSK authentication and per-frame HMAC integrity for TCP streams.
pub const transport_auth = @import("transport_auth.zig");
/// Configuration loading with CLI > environment > file precedence.
pub const configuration = @import("configuration.zig");
/// Elm-style operator diagnostics: boundary header, explanation, and hint.
pub const diagnostic = @import("diagnostic.zig");
/// The embedded node host: one data directory, journal, payloads, SQLite image.
pub const node = @import("node.zig");
/// Product node roles and their consensus/storage capabilities.
pub const roles = @import("roles.zig");
/// One in-process zaxonlite node bound to one data directory.
pub const Node = node.Node;
/// Options for `Node.open`: data directory, identity, membership, and role.
pub const OpenOptions = node.OpenOptions;
/// Node type: data-voter, witness, standby, read-replica, or gateway.
pub const Role = roles.Role;
/// Result of a committed write: change count, decided slot, replay marker.
pub const ExecResult = node.ExecResult;
/// Arena-owned query rows; the caller must call `deinit` to free them.
pub const QueryResult = node.QueryResult;
/// The `zaxon serve` transport host: one node behind a TCP endpoint.
pub const server = @import("server.zig");
/// JSON RPC client with leader-redirect following; used by the CLI and tests.
pub const client = @import("client.zig");
/// Stateless TCP gateway that routes clients to serving cluster backends.
pub const gateway = @import("gateway.zig");
/// Transport-owning embedded facade: an in-process cluster member with TCP.
pub const embedded = @import("embedded.zig");
/// In-process cluster member owning its listener, peers, and tick loop.
pub const Embedded = embedded.Embedded;
/// Static cluster membership entry for the embedded facade.
pub const EmbeddedMember = embedded.Member;
/// Options for `Embedded.open`: directory, identity, membership, and auth.
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
