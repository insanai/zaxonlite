const std = @import("std");

fn addSqliteLibrary(
    b: *std.Build,
    sqlite_dep: *std.Build.Dependency,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Step.Compile {
    const sqlite_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    sqlite_mod.addIncludePath(sqlite_dep.path(""));
    sqlite_mod.addCSourceFile(.{
        .file = sqlite_dep.path("sqlite3.c"),
        .flags = &.{
            "-DSQLITE_THREADSAFE=1",
            "-DSQLITE_OMIT_LOAD_EXTENSION",
            "-DSQLITE_OMIT_DEPRECATED",
            "-DSQLITE_DQS=0",
            "-DSQLITE_DEFAULT_WAL_SYNCHRONOUS=1",
            "-DHAVE_USLEEP=1",
        },
    });
    return b.addLibrary(.{
        .name = "sqlite3",
        .root_module = sqlite_mod,
    });
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const paxos = b.dependency("paxos", .{
        .target = target,
        .optimize = optimize,
    }).module("paxos");

    const sqlite_dep = b.dependency("sqlite", .{});
    const sqlite_lib = addSqliteLibrary(b, sqlite_dep, target, optimize);

    const translate_c = b.addTranslateC(.{
        .root_source_file = sqlite_dep.path("sqlite3.h"),
        .target = target,
        .optimize = optimize,
    });
    const c_mod = translate_c.createModule();

    const zaxonlite = b.addModule("zaxonlite", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "paxos", .module = paxos },
            .{ .name = "c", .module = c_mod },
        },
    });
    zaxonlite.linkLibrary(sqlite_lib);

    const zaxon = b.addExecutable(.{
        .name = "zaxon",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zaxonlite", .module = zaxonlite }},
        }),
    });
    b.installArtifact(zaxon);

    const run_cli = b.addRunArtifact(zaxon);
    if (b.args) |args| run_cli.addArgs(args);
    const run_step = b.step("run", "Run the zaxon CLI");
    run_step.dependOn(&run_cli.step);

    const unit_tests = b.addTest(.{ .root_module = zaxonlite });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run the zaxonlite test suite");
    test_step.dependOn(&run_unit_tests.step);

    const integration_mod = b.createModule(.{
        .root_source_file = b.path("src/integration_test.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "zaxonlite", .module = zaxonlite }},
    });
    const integration_tests = b.addTest(.{ .root_module = integration_mod });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    const integration_step = b.step(
        "test-single",
        "Run the single-process durability integration tests",
    );
    integration_step.dependOn(&run_integration_tests.step);
    test_step.dependOn(&run_integration_tests.step);

    // Three-process cluster scenario: a controller spawns three `zaxon
    // serve` processes and drives them over the client RPC protocol.
    const cluster_runs = b.option(
        u32,
        "cluster-runs",
        "Consecutive cluster scenario runs (default 1)",
    ) orelse 1;
    const cluster_test = b.addExecutable(.{
        .name = "zaxon-cluster-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cluster_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zaxonlite", .module = zaxonlite }},
        }),
    });
    const run_cluster_test = b.addRunArtifact(cluster_test);
    run_cluster_test.addArtifactArg(zaxon);
    run_cluster_test.addArg(b.fmt("{d}", .{cluster_runs}));
    const cluster_step = b.step(
        "test-cluster",
        "Run the three-process cluster integration scenario",
    );
    cluster_step.dependOn(&run_cluster_test.step);

    // CLI contract test: drives the installed zaxon binary end to end.
    const cli_test = b.addExecutable(.{
        .name = "zaxon-cli-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zaxonlite", .module = zaxonlite }},
        }),
    });
    const run_cli_test = b.addRunArtifact(cli_test);
    run_cli_test.addArtifactArg(zaxon);
    const cli_step = b.step(
        "test-cli",
        "Run the zaxon CLI contract test",
    );
    cli_step.dependOn(&run_cli_test.step);

    // Seeded property fuzzing.
    const fuzz_iterations = b.option(
        u32,
        "fuzz-iterations",
        "Fuzz iterations per layer (default 300)",
    ) orelse 300;
    const fuzz_seed = b.option(u64, "fuzz-seed", "Fixed fuzz seed");
    const fuzz_exe = b.addExecutable(.{
        .name = "zaxon-fuzz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fuzz.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zaxonlite", .module = zaxonlite },
                .{ .name = "paxos", .module = paxos },
            },
        }),
    });
    const run_fuzz = b.addRunArtifact(fuzz_exe);
    run_fuzz.addArg(b.fmt("{d}", .{fuzz_iterations}));
    if (fuzz_seed) |seed| run_fuzz.addArg(b.fmt("{d}", .{seed}));
    const fuzz_step = b.step("fuzz", "Run seeded property fuzzing");
    fuzz_step.dependOn(&run_fuzz.step);

    // Soak: sustained mixed load with invariants.
    const soak_seconds = b.option(
        u32,
        "soak-seconds",
        "Soak duration in seconds (default 15)",
    ) orelse 15;
    const soak_exe = b.addExecutable(.{
        .name = "zaxon-soak",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/soak.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zaxonlite", .module = zaxonlite }},
        }),
    });
    const run_soak = b.addRunArtifact(soak_exe);
    run_soak.addArg(b.fmt("{d}", .{soak_seconds}));
    const soak_step = b.step("soak", "Run the sustained mixed-load soak");
    soak_step.dependOn(&run_soak.step);

    // Benchmarks always build ReleaseFast regardless of -Doptimize.
    const bench_paxos = b.dependency("paxos", .{
        .target = target,
        .optimize = std.builtin.OptimizeMode.ReleaseFast,
    }).module("paxos");
    const bench_sqlite = addSqliteLibrary(b, sqlite_dep, target, .ReleaseFast);
    const bench_zaxonlite = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseFast,
        .imports = &.{
            .{ .name = "paxos", .module = bench_paxos },
            .{ .name = "c", .module = c_mod },
        },
    });
    bench_zaxonlite.linkLibrary(bench_sqlite);
    const bench_exe = b.addExecutable(.{
        .name = "zaxon-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{.{ .name = "zaxonlite", .module = bench_zaxonlite }},
        }),
    });
    const run_bench = b.addRunArtifact(bench_exe);
    if (b.args) |args| run_bench.addArgs(args);
    const bench_step = b.step(
        "benchmark",
        "Run write/read/recovery benchmarks (ReleaseFast)",
    );
    bench_step.dependOn(&run_bench.step);

    // C ABI: libzaxonlite static library plus installed header.
    const capi_lib = b.addLibrary(.{
        .name = "zaxonlite",
        .linkage = .static,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/capi.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zaxonlite", .module = zaxonlite }},
        }),
    });
    capi_lib.installHeader(b.path("include/zaxonlite.h"), "zaxonlite.h");
    b.installArtifact(capi_lib);

    const capi_smoke = b.addExecutable(.{
        .name = "zaxon-capi-smoke",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    capi_smoke.root_module.addCSourceFile(.{
        .file = b.path("test/capi_smoke.c"),
        .flags = &.{"-std=c11"},
    });
    capi_smoke.root_module.addIncludePath(b.path("include"));
    capi_smoke.root_module.linkLibrary(capi_lib);
    const run_capi_smoke = b.addRunArtifact(capi_smoke);
    run_capi_smoke.addArg(b.fmt(
        "{s}/zx-capi-smoke/data",
        .{b.cache_root.path orelse ".zig-cache"},
    ));
    const capi_step = b.step("test-cabi", "Run the C ABI smoke test");
    capi_step.dependOn(&run_capi_smoke.step);
}
