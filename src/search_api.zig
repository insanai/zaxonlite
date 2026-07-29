//! Typed hybrid search (ZDS 0009): the enforced path for the vector
//! candidate cap. Raw application SQL cannot be bounded at the vec0 `k`
//! constraint, so this module validates a typed request — identifiers,
//! `k`, `candidate_count`, weights, and the embedding shape — and builds
//! the canonical hybrid CTE the record documents. Results carry item IDs
//! and scores, never embedding BLOBs.
//!
//! Table contract: the vector table is a vec0 virtual table with columns
//! `item_id` (integer primary key), `embedding` (float32), and
//! `embedding_coarse` (bit). The lexical table is any FTS5 table whose
//! rowid is the item ID.

const std = @import("std");
const prepared = @import("prepared.zig");

/// Hard ceiling for vector KNN candidate counts (ZDS 0009).
pub const candidate_hard_limit: u32 = 4096;

pub const Fusion = enum { rrf, dbsf };

pub const Request = struct {
    /// FTS5 table for the lexical branch; requires `text`.
    fts_table: ?[]const u8 = null,
    /// vec0 table for the vector branch; requires `embedding`.
    vec_table: ?[]const u8 = null,
    /// FTS5 MATCH query text.
    text: ?[]const u8 = null,
    /// Raw little-endian float32 query embedding. The dimension must be
    /// divisible by eight so the coarse bit quantization is defined.
    embedding: ?[]const u8 = null,
    /// Final result count.
    k: u32 = 10,
    /// Coarse candidates retained before exact rerank; defaults to
    /// `min(max(8k, 64), 4096)` and is capped at `candidate_hard_limit`.
    candidate_count: ?u32 = null,
    fusion: Fusion = .rrf,
    text_weight: f64 = 1.0,
    vector_weight: f64 = 1.0,
};

pub const RequestError = error{
    NoRetriever,
    MissingText,
    MissingEmbedding,
    InvalidIdentifier,
    InvalidK,
    InvalidCandidateCount,
    InvalidEmbedding,
    InvalidWeight,
};

/// The ZDS 0009 default oversampling rule.
pub fn defaultCandidateCount(k: u32) u32 {
    return @min(@max(8 *| k, 64), candidate_hard_limit);
}

/// SQL identifier validation for the two table names: ASCII identifier
/// characters only, and never the reserved `__zaxon_` or `sqlite_`
/// namespaces. Everything else in the statement is bound, not spliced.
pub fn validateIdentifier(name: []const u8) RequestError!void {
    if (name.len == 0 or name.len > 128) return error.InvalidIdentifier;
    if (!std.ascii.isAlphabetic(name[0]) and name[0] != '_') {
        return error.InvalidIdentifier;
    }
    for (name) |char| {
        if (!std.ascii.isAlphanumeric(char) and char != '_') {
            return error.InvalidIdentifier;
        }
    }
    if (std.ascii.startsWithIgnoreCase(name, "__zaxon_")) {
        return error.InvalidIdentifier;
    }
    if (std.ascii.startsWithIgnoreCase(name, "sqlite_")) {
        return error.InvalidIdentifier;
    }
}

/// A validated, bindable search statement. The value slices reference the
/// request's text and embedding, which must outlive the query.
pub const Plan = struct {
    sql: []u8,
    values_buffer: [6]prepared.Value = undefined,
    value_count: usize = 0,

    pub fn values(self: *const Plan) []const prepared.Value {
        return self.values_buffer[0..self.value_count];
    }

    pub fn deinit(self: *const Plan, gpa: std.mem.Allocator) void {
        gpa.free(self.sql);
    }
};

fn validate(request: Request) RequestError!u32 {
    if (request.k < 1 or request.k > candidate_hard_limit) {
        return error.InvalidK;
    }
    const candidates = request.candidate_count orelse
        defaultCandidateCount(request.k);
    if (candidates < 1 or candidates > candidate_hard_limit) {
        return error.InvalidCandidateCount;
    }
    if (!std.math.isFinite(request.text_weight) or request.text_weight < 0 or
        !std.math.isFinite(request.vector_weight) or request.vector_weight < 0)
    {
        return error.InvalidWeight;
    }
    const lexical = request.fts_table != null;
    const semantic = request.vec_table != null;
    if (!lexical and !semantic) return error.NoRetriever;
    if (lexical) {
        try validateIdentifier(request.fts_table.?);
        if (request.text == null or request.text.?.len == 0) {
            return error.MissingText;
        }
    }
    if (semantic) {
        try validateIdentifier(request.vec_table.?);
        const embedding = request.embedding orelse
            return error.MissingEmbedding;
        // float32 elements, dimension divisible by eight for the coarse
        // bit quantization: byte length divisible by 32, nonzero.
        if (embedding.len == 0 or embedding.len % 32 != 0) {
            return error.InvalidEmbedding;
        }
    }
    return candidates;
}

/// Builds the canonical statement for the request: lexical-only,
/// vector-only (coarse scan plus exact rerank), or the fused hybrid in
/// the requested fusion. One present branch skips fusion entirely
/// (ZDS 0009 fusion-selection flow).
pub fn plan(gpa: std.mem.Allocator, request: Request) (RequestError ||
    std.mem.Allocator.Error)!Plan {
    const candidates = try validate(request);
    const lexical = request.fts_table != null;
    const semantic = request.vec_table != null;

    if (lexical and !semantic) {
        const fts = request.fts_table.?;
        var result = Plan{ .sql = try std.fmt.allocPrint(
            gpa,
            "select rowid as item_id, -bm25({s}) as score " ++
                "from {s} where {s} match ?1 " ++
                "order by bm25({s}), rowid limit ?2",
            .{ fts, fts, fts, fts },
        ) };
        result.values_buffer[0] = .{ .text = request.text.? };
        result.values_buffer[1] = .{ .integer = request.k };
        result.value_count = 2;
        return result;
    }

    if (semantic and !lexical) {
        const vec = request.vec_table.?;
        var result = Plan{ .sql = try std.fmt.allocPrint(
            gpa,
            "with coarse as (" ++
                "select item_id, embedding from {s} " ++
                "where embedding_coarse match vec_quantize_binary(?1) " ++
                "and k = ?2) " ++
                "select item_id, " ++
                "zaxon_vec_distance_cosine(embedding, ?1) as exact_distance " ++
                "from coarse order by exact_distance, item_id limit ?3",
            .{vec},
        ) };
        result.values_buffer[0] = .{ .blob = request.embedding.? };
        result.values_buffer[1] = .{ .integer = candidates };
        result.values_buffer[2] = .{ .integer = request.k };
        result.value_count = 3;
        return result;
    }

    const fts = request.fts_table.?;
    const vec = request.vec_table.?;
    const sql = switch (request.fusion) {
        .rrf => try std.fmt.allocPrint(
            gpa,
            "with lexical as (" ++
                "select rowid as item_id, " ++
                "row_number() over (order by bm25({s}), rowid) as rank " ++
                "from {s} where {s} match ?1 " ++
                "order by bm25({s}), rowid limit ?2), " ++
                "coarse as (" ++
                "select item_id, embedding from {s} " ++
                "where embedding_coarse match vec_quantize_binary(?3) " ++
                "and k = ?2), " ++
                "reranked as (" ++
                "select item_id, " ++
                "zaxon_vec_distance_cosine(embedding, ?3) as exact_distance " ++
                "from coarse order by exact_distance, item_id limit ?4), " ++
                "semantic as (" ++
                "select item_id, " ++
                "row_number() over (order by exact_distance, item_id) as rank " ++
                "from reranked), " ++
                "contributions as (" ++
                "select item_id, rrf(rank, 60, ?5) as score from lexical " ++
                "union all " ++
                "select item_id, rrf(rank, 60, ?6) as score from semantic) " ++
                "select item_id, sum(score) as fused_score " ++
                "from contributions group by item_id " ++
                "order by fused_score desc, item_id limit ?4",
            .{ fts, fts, fts, fts, vec },
        ),
        .dbsf => try std.fmt.allocPrint(
            gpa,
            "with lexical_raw as (" ++
                "select rowid as item_id, -bm25({s}) as score " ++
                "from {s} where {s} match ?1 " ++
                "order by bm25({s}), rowid limit ?2), " ++
                "lexical as (" ++
                "select item_id, dbsf(score, avg(score) over (), " ++
                "stddev_samp(score) over (), ?5) as score from lexical_raw), " ++
                "coarse as (" ++
                "select item_id, embedding from {s} " ++
                "where embedding_coarse match vec_quantize_binary(?3) " ++
                "and k = ?2), " ++
                "reranked as (" ++
                "select item_id, " ++
                "zaxon_vec_distance_cosine(embedding, ?3) as exact_distance " ++
                "from coarse order by exact_distance, item_id limit ?4), " ++
                "semantic_raw as (" ++
                "select item_id, -exact_distance as score from reranked), " ++
                "semantic as (" ++
                "select item_id, dbsf(score, avg(score) over (), " ++
                "stddev_samp(score) over (), ?6) as score from semantic_raw), " ++
                "contributions as (" ++
                "select item_id, score from lexical " ++
                "union all " ++
                "select item_id, score from semantic) " ++
                "select item_id, sum(score) as fused_score " ++
                "from contributions group by item_id " ++
                "order by fused_score desc, item_id limit ?4",
            .{ fts, fts, fts, fts, vec },
        ),
    };
    var result = Plan{ .sql = sql };
    result.values_buffer[0] = .{ .text = request.text.? };
    result.values_buffer[1] = .{ .integer = candidates };
    result.values_buffer[2] = .{ .blob = request.embedding.? };
    result.values_buffer[3] = .{ .integer = request.k };
    result.values_buffer[4] = .{ .real = request.text_weight };
    result.values_buffer[5] = .{ .real = request.vector_weight };
    result.value_count = 6;
    return result;
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

const testing = std.testing;

test "default candidate count follows the zds rule" {
    try testing.expectEqual(@as(u32, 64), defaultCandidateCount(1));
    try testing.expectEqual(@as(u32, 64), defaultCandidateCount(8));
    try testing.expectEqual(@as(u32, 80), defaultCandidateCount(10));
    try testing.expectEqual(@as(u32, 800), defaultCandidateCount(100));
    try testing.expectEqual(@as(u32, 4096), defaultCandidateCount(1000));
}

test "identifier validation rejects injection and reserved names" {
    try validateIdentifier("media_vec");
    try validateIdentifier("_hidden");
    try validateIdentifier("Table9");
    const bad = [_][]const u8{
        "",
        "9lead",
        "a-b",
        "a b",
        "a;drop table t",
        "a\"b",
        "a'b",
        "__zaxon_meta",
        "__ZAXON_meta",
        "sqlite_master",
        "SQLITE_temp_master",
    };
    for (bad) |name| {
        try testing.expectError(error.InvalidIdentifier, validateIdentifier(name));
    }
}

test "request validation enforces the candidate cap" {
    const embedding = [_]u8{0} ** 32;
    var request = Request{
        .vec_table = "media_vec",
        .embedding = &embedding,
        .k = 10,
    };
    request.candidate_count = candidate_hard_limit + 1;
    try testing.expectError(error.InvalidCandidateCount, plan(testing.allocator, request));
    request.candidate_count = 0;
    try testing.expectError(error.InvalidCandidateCount, plan(testing.allocator, request));
    request.candidate_count = candidate_hard_limit;
    const ok = try plan(testing.allocator, request);
    ok.deinit(testing.allocator);

    request.candidate_count = null;
    request.k = 0;
    try testing.expectError(error.InvalidK, plan(testing.allocator, request));
    request.k = candidate_hard_limit + 1;
    try testing.expectError(error.InvalidK, plan(testing.allocator, request));
}

test "request validation rejects malformed branches" {
    try testing.expectError(error.NoRetriever, plan(testing.allocator, .{}));
    try testing.expectError(
        error.MissingText,
        plan(testing.allocator, .{ .fts_table = "media_fts" }),
    );
    try testing.expectError(
        error.MissingEmbedding,
        plan(testing.allocator, .{ .vec_table = "media_vec" }),
    );
    // 31 bytes: not a float32 vector with dimension divisible by 8.
    const stub = [_]u8{0} ** 31;
    try testing.expectError(
        error.InvalidEmbedding,
        plan(testing.allocator, .{ .vec_table = "media_vec", .embedding = &stub }),
    );
    const embedding = [_]u8{0} ** 32;
    try testing.expectError(
        error.InvalidWeight,
        plan(testing.allocator, .{
            .vec_table = "media_vec",
            .embedding = &embedding,
            .vector_weight = -1,
        }),
    );
    try testing.expectError(
        error.InvalidIdentifier,
        plan(testing.allocator, .{
            .vec_table = "media_vec; drop table t",
            .embedding = &embedding,
        }),
    );
}

test "plans bind every parameter and never splice values" {
    const embedding = [_]u8{0} ** 32;
    const hybrid = try plan(testing.allocator, .{
        .fts_table = "media_fts",
        .vec_table = "media_vec",
        .text = "sqlite",
        .embedding = &embedding,
        .k = 5,
    });
    defer hybrid.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 6), hybrid.values().len);
    // The query text never appears in the SQL; it is bound.
    try testing.expect(std.mem.indexOf(u8, hybrid.sql, "sqlite'") == null);
    try testing.expect(std.mem.indexOf(u8, hybrid.sql, "rrf(rank, 60, ?5)") != null);

    const dbsf_plan = try plan(testing.allocator, .{
        .fts_table = "media_fts",
        .vec_table = "media_vec",
        .text = "sqlite",
        .embedding = &embedding,
        .fusion = .dbsf,
        .k = 5,
    });
    defer dbsf_plan.deinit(testing.allocator);
    try testing.expect(std.mem.indexOf(u8, dbsf_plan.sql, "stddev_samp") != null);
}
