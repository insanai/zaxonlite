//! Pure series statistics behind the write benchmark's periodicity
//! instrument, split out so the estimators carry deterministic unit
//! tests: a timing-instrument regression must fail `zig build test`,
//! not wait for a human to read benchmark output.

const std = @import("std");

/// Lag autocorrelation of a time-ordered series; zero for a constant
/// series or an out-of-range lag.
pub fn autocorrelation(samples: []const u64, lag: usize) f64 {
    if (lag == 0 or lag >= samples.len) return 0;
    var mean: f64 = 0;
    for (samples) |sample| mean += @floatFromInt(sample);
    mean /= @floatFromInt(samples.len);
    var denominator: f64 = 0;
    for (samples) |sample| {
        const centered = @as(f64, @floatFromInt(sample)) - mean;
        denominator += centered * centered;
    }
    if (denominator == 0) return 0;
    var numerator: f64 = 0;
    for (samples[0 .. samples.len - lag], samples[lag..]) |early, late| {
        numerator += (@as(f64, @floatFromInt(early)) - mean) *
            (@as(f64, @floatFromInt(late)) - mean);
    }
    return numerator / denominator;
}

/// Median of the per-anchor paired deltas: each anchor-bearing
/// iteration minus the nearest preceding iteration that carried no
/// anchor at all (walking back a bounded distance, so a natural anchor
/// in the adjacent slot cannot poison the pair). The metric is a
/// deliberately nonnegative, zero-censored "added cost": each delta
/// saturates at zero, so a noisy pair where the plain iteration was
/// slower contributes zero rather than a negative cost.
pub fn pairedAnchorShift(
    intervals: []const u64,
    anchored: []const bool,
) u64 {
    std.debug.assert(intervals.len == anchored.len);
    var deltas: [64]u64 = undefined;
    var count: usize = 0;
    for (anchored, 0..) |is_anchor, index| {
        if (!is_anchor or index == 0) continue;
        if (count == deltas.len) break;
        const pair = pairIndex(anchored, index) orelse continue;
        deltas[count] = intervals[index] -| intervals[pair];
        count += 1;
    }
    if (count == 0) return 0;
    std.mem.sort(u64, deltas[0..count], {}, std.sort.asc(u64));
    return deltas[count / 2];
}

/// The nearest preceding non-anchored iteration within a short window,
/// or null when anchors crowd out every candidate.
fn pairIndex(anchored: []const bool, index: usize) ?usize {
    var back: usize = 1;
    while (back <= 8 and back <= index) : (back += 1) {
        if (!anchored[index - back]) return index - back;
    }
    return null;
}

test "paired shift is the median of adjacent anchor deltas" {
    const intervals = [_]u64{ 100, 100, 900, 100, 100, 400, 100, 100, 250 };
    const anchored = [_]bool{
        false, false, true, false, false, true, false, false, true,
    };
    // Deltas: 800, 300, 150; the median is 300.
    try std.testing.expectEqual(
        @as(u64, 300),
        pairedAnchorShift(&intervals, &anchored),
    );
}

test "a slower plain neighbor censors that pair at zero" {
    const intervals = [_]u64{ 500, 100, 500, 90 };
    const anchored = [_]bool{ false, true, false, true };
    // Deltas censor to 0 and 0; the metric never goes negative.
    try std.testing.expectEqual(
        @as(u64, 0),
        pairedAnchorShift(&intervals, &anchored),
    );
}

test "an even number of anchors takes the upper median" {
    const intervals = [_]u64{ 100, 300, 100, 700 };
    const anchored = [_]bool{ false, true, false, true };
    // Deltas: 200 and 600; count/2 selects the upper median, 600.
    try std.testing.expectEqual(
        @as(u64, 600),
        pairedAnchorShift(&intervals, &anchored),
    );
}

test "a natural anchor in the adjacent slot is skipped when pairing" {
    const intervals = [_]u64{ 100, 800, 900, 100 };
    const anchored = [_]bool{ false, true, true, false };
    // The second anchor pairs with index 0, not the anchored index 1.
    try std.testing.expectEqual(
        @as(u64, 800),
        pairedAnchorShift(&intervals, &anchored),
    );
}

test "empty and anchorless series report zero shift" {
    try std.testing.expectEqual(@as(u64, 0), pairedAnchorShift(&.{}, &.{}));
    const intervals = [_]u64{ 100, 200 };
    const anchored = [_]bool{ false, false };
    try std.testing.expectEqual(
        @as(u64, 0),
        pairedAnchorShift(&intervals, &anchored),
    );
}

test "autocorrelation sees a periodic signal and ignores a constant one" {
    var series: [64]u64 = undefined;
    for (&series, 0..) |*value, index| {
        value.* = if (index % 8 == 0) 1000 else 100;
    }
    try std.testing.expect(autocorrelation(&series, 8) > 0.9);
    try std.testing.expect(autocorrelation(&series, 5) < 0.2);
    const flat = [_]u64{7} ** 16;
    try std.testing.expectEqual(@as(f64, 0), autocorrelation(&flat, 4));
}
