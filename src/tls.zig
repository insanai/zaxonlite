//! Mutual TLS 1.3 transport built on the system OpenSSL 3 library.
//!
//! This is the optional second transport authentication mode, beside the
//! shared-secret PSK handshake in `transport_auth.zig`. Where the PSK
//! proves possession of one cluster-wide secret, mTLS gives every node a
//! per-node certificate: connections verify the peer's chain against the
//! cluster CA, require a certificate in both directions, and bind a peer
//! connection's certificate common name to the node id it claims in its
//! hello. TLS also provides the confidentiality the PSK mode lacks.
//!
//! Interop shape: a small set of hand-declared OpenSSL externs (no header
//! translation), one `Context` per process per direction, and a `Stream`
//! that exposes the same `std.Io.Reader`/`std.Io.Writer` interfaces the
//! framing layer already consumes, so wire.zig and transport_auth.zig
//! run unchanged above it. Handshakes and I/O use the blocking socket;
//! shutting the socket down unblocks them, which is how the server's
//! existing watchdog and shutdown paths cancel TLS connections too.

const std = @import("std");
const Io = std.Io;

// ----------------------------------------------------------------------
// OpenSSL 3 externs (libssl / libcrypto)
// ----------------------------------------------------------------------

const SSL_CTX = opaque {};
const SSL = opaque {};
const SSL_METHOD = opaque {};
const X509 = opaque {};
const X509_NAME = opaque {};

const SSL_FILETYPE_PEM: c_int = 1;
const SSL_VERIFY_PEER: c_int = 0x01;
const SSL_VERIFY_FAIL_IF_NO_PEER_CERT: c_int = 0x02;
const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
const TLS1_3_VERSION: c_long = 0x0304;
const X509_V_OK: c_long = 0;
const NID_commonName: c_int = 13;
const SSL_ERROR_ZERO_RETURN: c_int = 6;

extern "c" fn TLS_server_method() *const SSL_METHOD;
extern "c" fn TLS_client_method() *const SSL_METHOD;
extern "c" fn SSL_CTX_new(method: *const SSL_METHOD) ?*SSL_CTX;
extern "c" fn SSL_CTX_free(ctx: *SSL_CTX) void;
extern "c" fn SSL_CTX_use_certificate_chain_file(
    ctx: *SSL_CTX,
    file: [*:0]const u8,
) c_int;
extern "c" fn SSL_CTX_use_PrivateKey_file(
    ctx: *SSL_CTX,
    file: [*:0]const u8,
    file_type: c_int,
) c_int;
extern "c" fn SSL_CTX_check_private_key(ctx: *const SSL_CTX) c_int;
extern "c" fn SSL_CTX_load_verify_locations(
    ctx: *SSL_CTX,
    ca_file: ?[*:0]const u8,
    ca_path: ?[*:0]const u8,
) c_int;
extern "c" fn SSL_CTX_set_verify(
    ctx: *SSL_CTX,
    mode: c_int,
    callback: ?*const anyopaque,
) void;
extern "c" fn SSL_CTX_ctrl(
    ctx: *SSL_CTX,
    cmd: c_int,
    larg: c_long,
    parg: ?*anyopaque,
) c_long;
extern "c" fn SSL_new(ctx: *SSL_CTX) ?*SSL;
extern "c" fn SSL_free(ssl: *SSL) void;
extern "c" fn SSL_set_fd(ssl: *SSL, fd: c_int) c_int;
extern "c" fn SSL_accept(ssl: *SSL) c_int;
extern "c" fn SSL_connect(ssl: *SSL) c_int;
extern "c" fn SSL_read(ssl: *SSL, buf: *anyopaque, num: c_int) c_int;
extern "c" fn SSL_write(ssl: *SSL, buf: *const anyopaque, num: c_int) c_int;
extern "c" fn SSL_shutdown(ssl: *SSL) c_int;
extern "c" fn SSL_get_error(ssl: *const SSL, ret: c_int) c_int;
extern "c" fn SSL_get_verify_result(ssl: *const SSL) c_long;
extern "c" fn SSL_get1_peer_certificate(ssl: *const SSL) ?*X509;
extern "c" fn X509_free(x: *X509) void;
extern "c" fn X509_get_subject_name(x: *const X509) ?*X509_NAME;
extern "c" fn X509_NAME_get_text_by_NID(
    name: *X509_NAME,
    nid: c_int,
    buf: [*]u8,
    len: c_int,
) c_int;
extern "c" fn ERR_clear_error() void;

// ----------------------------------------------------------------------
// Configuration and identity
// ----------------------------------------------------------------------

pub const Error = error{
    TlsInit,
    TlsCredentials,
    TlsHandshakeFailed,
    TlsPeerUnverified,
    NameTooLong,
};

/// PEM file paths for one node's transport identity. All three are
/// required together: the node certificate, its private key, and the
/// cluster CA every peer certificate must chain to.
pub const Config = struct {
    cert_path: []const u8,
    key_path: []const u8,
    ca_path: []const u8,
};

/// Longest certificate common name this module reads; longer names fail
/// verification rather than truncating an identity comparison.
pub const max_common_name = 64;

/// Renders the certificate common name a configured node must present:
/// `zaxon-node-<id>`. Enrollment (P1.1) issues certificates with exactly
/// this name; the transport refuses a peer whose certificate and hello
/// disagree.
pub fn nodeCommonName(buffer: *[max_common_name]u8, node_id: u32) []const u8 {
    return std.fmt.bufPrint(buffer, "zaxon-node-{d}", .{node_id}) catch
        unreachable;
}

fn pathZ(buffer: *[std.Io.Dir.max_path_bytes]u8, path: []const u8) Error![:0]const u8 {
    return std.fmt.bufPrintZ(buffer, "{s}", .{path}) catch
        return error.NameTooLong;
}

// ----------------------------------------------------------------------
// Context: one per process per direction
// ----------------------------------------------------------------------

pub const Context = struct {
    handle: *SSL_CTX,

    pub fn initServer(config: Config) Error!Context {
        return initCommon(TLS_server_method(), config);
    }

    pub fn initClient(config: Config) Error!Context {
        return initCommon(TLS_client_method(), config);
    }

    /// Both directions verify the peer chain against the cluster CA and
    /// require a certificate from the peer — that is the mutual part —
    /// and refuse anything below TLS 1.3.
    fn initCommon(method: *const SSL_METHOD, config: Config) Error!Context {
        const ctx = SSL_CTX_new(method) orelse return error.TlsInit;
        errdefer SSL_CTX_free(ctx);
        if (SSL_CTX_ctrl(
            ctx,
            SSL_CTRL_SET_MIN_PROTO_VERSION,
            TLS1_3_VERSION,
            null,
        ) != 1) {
            return error.TlsInit;
        }

        var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        if (SSL_CTX_use_certificate_chain_file(
            ctx,
            (try pathZ(&path_buffer, config.cert_path)).ptr,
        ) != 1) {
            return error.TlsCredentials;
        }
        if (SSL_CTX_use_PrivateKey_file(
            ctx,
            (try pathZ(&path_buffer, config.key_path)).ptr,
            SSL_FILETYPE_PEM,
        ) != 1) {
            return error.TlsCredentials;
        }
        if (SSL_CTX_check_private_key(ctx) != 1) return error.TlsCredentials;
        if (SSL_CTX_load_verify_locations(
            ctx,
            (try pathZ(&path_buffer, config.ca_path)).ptr,
            null,
        ) != 1) {
            return error.TlsCredentials;
        }
        SSL_CTX_set_verify(
            ctx,
            SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
            null,
        );
        return .{ .handle = ctx };
    }

    pub fn deinit(self: *Context) void {
        SSL_CTX_free(self.handle);
        self.* = undefined;
    }
};

// ----------------------------------------------------------------------
// Stream: one TLS connection over an accepted or dialed socket
// ----------------------------------------------------------------------

pub const Stream = struct {
    ssl: *SSL,
    /// Certificate common name of the verified peer; the transport binds
    /// this to the peer's claimed hello identity.
    common_name_buffer: [max_common_name]u8,
    common_name_len: usize,
    reader: Io.Reader,
    writer: Io.Writer,

    /// Responder half: runs the TLS handshake over the accepted socket.
    /// `read_buffer`/`write_buffer` back the exposed interfaces and must
    /// outlive the stream. The socket stays owned by the caller; closing
    /// or shutting it down unblocks any in-flight TLS call.
    pub fn accept(
        context: *const Context,
        socket: std.Io.net.Stream,
        read_buffer: []u8,
        write_buffer: []u8,
    ) Error!Stream {
        return handshake(context, socket, read_buffer, write_buffer, SSL_accept);
    }

    /// Initiator half; see `accept`.
    pub fn connect(
        context: *const Context,
        socket: std.Io.net.Stream,
        read_buffer: []u8,
        write_buffer: []u8,
    ) Error!Stream {
        return handshake(context, socket, read_buffer, write_buffer, SSL_connect);
    }

    fn handshake(
        context: *const Context,
        socket: std.Io.net.Stream,
        read_buffer: []u8,
        write_buffer: []u8,
        step: *const fn (ssl: *SSL) callconv(.c) c_int,
    ) Error!Stream {
        disableSigpipe(socket.socket.handle);
        ERR_clear_error();
        const ssl = SSL_new(context.handle) orelse return error.TlsInit;
        errdefer SSL_free(ssl);
        if (SSL_set_fd(ssl, @intCast(socket.socket.handle)) != 1) {
            return error.TlsInit;
        }
        if (step(ssl) != 1) return error.TlsHandshakeFailed;
        if (SSL_get_verify_result(ssl) != X509_V_OK) {
            return error.TlsPeerUnverified;
        }

        var self = Stream{
            .ssl = ssl,
            .common_name_buffer = undefined,
            .common_name_len = 0,
            .reader = .{
                .vtable = &.{ .stream = streamImpl },
                .buffer = read_buffer,
                .seek = 0,
                .end = 0,
            },
            .writer = .{
                .vtable = &.{ .drain = drainImpl },
                .buffer = write_buffer,
            },
        };
        try self.readPeerCommonName();
        return self;
    }

    /// SIGPIPE would kill the process when OpenSSL writes to a peer that
    /// already closed; connection errors must surface as write failures.
    fn disableSigpipe(handle: anytype) void {
        if (@hasDecl(std.posix.SO, "NOSIGPIPE")) {
            const one: c_int = 1;
            std.posix.setsockopt(
                handle,
                std.posix.SOL.SOCKET,
                std.posix.SO.NOSIGPIPE,
                std.mem.asBytes(&one),
            ) catch {};
        }
    }

    fn readPeerCommonName(self: *Stream) Error!void {
        // Verification already required a certificate; a missing one or
        // an over-long name is a refused identity, not a truncated one.
        const certificate = SSL_get1_peer_certificate(self.ssl) orelse
            return error.TlsPeerUnverified;
        defer X509_free(certificate);
        const subject = X509_get_subject_name(certificate) orelse
            return error.TlsPeerUnverified;
        const written = X509_NAME_get_text_by_NID(
            subject,
            NID_commonName,
            &self.common_name_buffer,
            @intCast(self.common_name_buffer.len),
        );
        if (written <= 0 or written >= self.common_name_buffer.len) {
            return error.TlsPeerUnverified;
        }
        self.common_name_len = @intCast(written);
    }

    /// The verified peer certificate's common name.
    pub fn peerCommonName(self: *const Stream) []const u8 {
        return self.common_name_buffer[0..self.common_name_len];
    }

    /// Sends a best-effort close_notify and releases the TLS state. The
    /// underlying socket remains the caller's to close.
    pub fn deinit(self: *Stream) void {
        _ = SSL_shutdown(self.ssl);
        SSL_free(self.ssl);
        self.* = undefined;
    }

    fn readSsl(self: *Stream, destination: []u8) Io.Reader.StreamError!usize {
        ERR_clear_error();
        const len: c_int = @intCast(@min(
            destination.len,
            std.math.maxInt(c_int),
        ));
        const n = SSL_read(self.ssl, destination.ptr, len);
        if (n > 0) return @intCast(n);
        if (SSL_get_error(self.ssl, n) == SSL_ERROR_ZERO_RETURN) {
            return error.EndOfStream;
        }
        return error.ReadFailed;
    }

    /// Blocking-mode SSL_write completes the whole buffer or fails, so
    /// one call per slice suffices (chunked to the C int limit).
    fn writeSsl(self: *Stream, source: []const u8) Io.Writer.Error!usize {
        var offset: usize = 0;
        while (offset < source.len) {
            ERR_clear_error();
            const len: c_int = @intCast(@min(
                source.len - offset,
                std.math.maxInt(c_int),
            ));
            const n = SSL_write(self.ssl, source.ptr + offset, len);
            if (n <= 0) return error.WriteFailed;
            offset += @intCast(n);
        }
        return source.len;
    }

    fn streamImpl(
        io_reader: *Io.Reader,
        io_writer: *Io.Writer,
        limit: Io.Limit,
    ) Io.Reader.StreamError!usize {
        const self: *Stream = @alignCast(@fieldParentPtr("reader", io_reader));
        const destination = limit.slice(try io_writer.writableSliceGreedy(1));
        const n = try self.readSsl(destination);
        io_writer.advance(n);
        return n;
    }

    fn drainImpl(
        io_writer: *Io.Writer,
        data: []const []const u8,
        splat: usize,
    ) Io.Writer.Error!usize {
        const self: *Stream = @alignCast(@fieldParentPtr("writer", io_writer));
        var written: usize = 0;
        written += try self.writeSsl(io_writer.buffered());
        for (data, 0..) |slice, index| {
            const repeat = if (index == data.len - 1) splat else 1;
            for (0..repeat) |_| written += try self.writeSsl(slice);
        }
        return io_writer.consume(written);
    }
};

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

const testing = std.testing;

test "node common name is deterministic and bounded" {
    var buffer: [max_common_name]u8 = undefined;
    try testing.expectEqualStrings("zaxon-node-3", nodeCommonName(&buffer, 3));
    try testing.expectEqualStrings(
        "zaxon-node-4294967295",
        nodeCommonName(&buffer, std.math.maxInt(u32)),
    );
}

test "context refuses missing credential files" {
    try testing.expectError(error.TlsCredentials, Context.initServer(.{
        .cert_path = ".zig-cache/definitely-missing-cert.pem",
        .key_path = ".zig-cache/definitely-missing-key.pem",
        .ca_path = ".zig-cache/definitely-missing-ca.pem",
    }));
}
