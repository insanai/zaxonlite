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

/// Links the system OpenSSL 3 (libssl/libcrypto) that backs the optional
/// mTLS transport in `src/tls.zig`.
fn linkOpenSsl(
    b: *std.Build,
    module: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    prefix: []const u8,
) void {
    if (prefix.len > 0) {
        module.addLibraryPath(.{ .cwd_relative = b.fmt("{s}/lib", .{prefix}) });
    }
    const windows = target.result.os.tag == .windows;
    module.linkSystemLibrary(if (windows) "libssl" else "ssl", .{
        .use_pkg_config = .no,
    });
    module.linkSystemLibrary(if (windows) "libcrypto" else "crypto", .{
        .use_pkg_config = .no,
    });
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    // Embedded-only consumers (`Node`, no transport) can drop the OpenSSL
    // link entirely: `node.zig` never imports `tls.zig`, and Zig's lazy
    // analysis emits no OpenSSL externs unless the TLS transport is
    // referenced. With `-Dtls=false` nothing in the build graph links
    // libssl/libcrypto, so the consumer's binary carries no OpenSSL
    // dependency. The `zaxon` executable and the transport hosts require
    // TLS and are only built with the default `-Dtls=true`.
    const tls_enabled = b.option(
        bool,
        "tls",
        "Link OpenSSL 3 for the mTLS transport (false: embedded Node only)",
    ) orelse true;
    const openssl_prefix = b.option(
        []const u8,
        "openssl-prefix",
        "Target OpenSSL 3 SDK prefix (default: Homebrew openssl@3 on macOS)",
    ) orelse if (target.result.os.tag == .macos)
        "/opt/homebrew/opt/openssl@3"
    else
        "";

    const paxos = b.dependency("paxos", .{
        .target = target,
        .optimize = optimize,
    }).module("paxos");

    const sqlite_dep = b.dependency("sqlite", .{});
    const sqlite_lib = addSqliteLibrary(b, sqlite_dep, target, optimize);

    // Terminal layer for the interactive shell (ZDS 0005). Confined to the
    // CLI: the zaxonlite library module never imports it.
    const vaxis = b.dependency("vaxis", .{
        .target = target,
        .optimize = optimize,
    }).module("vaxis");

    // The shared, domain-neutral terminal UI (ZDS 0005; Kynetica KDS
    // 0016): editor, history, highlighter, renderers, line reader, pager.
    // Public so downstream consumers (Kynetica) can import it; it never
    // imports zaxonlite, so `-Dtls=false` embedded builds stay clean.
    const cli_ui = b.addModule("zaxon_cli_ui", .{
        .root_source_file = b.path("src/cli_ui/ui.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "vaxis", .module = vaxis },
        },
    });

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
    if (tls_enabled) linkOpenSsl(b, zaxonlite, target, openssl_prefix);

    const zaxon = b.addExecutable(.{
        .name = "zaxon",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zaxonlite", .module = zaxonlite },
                .{ .name = "zaxon_cli_ui", .module = cli_ui },
            },
        }),
    });
    b.installArtifact(zaxon);

    const run_cli = b.addRunArtifact(zaxon);
    if (b.args) |args| run_cli.addArgs(args);
    const run_step = b.step("run", "Run the zaxon CLI");
    run_step.dependOn(&run_cli.step);

    addApiDocs(b, zaxonlite);

    const unit_tests = b.addTest(.{ .root_module = zaxonlite });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run the zaxonlite test suite");
    test_step.dependOn(&run_unit_tests.step);

    // Pure state machines of the shared terminal UI: editor, history,
    // highlighter, renderers. No TTY or node is spawned.
    const cli_ui_tests = b.addTest(.{ .root_module = cli_ui });
    const run_cli_ui_tests = b.addRunArtifact(cli_ui_tests);
    const cli_ui_step = b.step(
        "test-cli-ui",
        "Run the shared terminal UI unit tests",
    );
    cli_ui_step.dependOn(&run_cli_ui_tests.step);
    test_step.dependOn(&run_cli_ui_tests.step);

    // What stayed zaxon-specific: statement routing, the dot-command
    // registry, and remote result conversion.
    const cli_unit_mod = b.createModule(.{
        .root_source_file = b.path("src/cli/tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zaxonlite", .module = zaxonlite },
            .{ .name = "zaxon_cli_ui", .module = cli_ui },
        },
    });
    const cli_unit_tests = b.addTest(.{ .root_module = cli_unit_mod });
    const run_cli_unit_tests = b.addRunArtifact(cli_unit_tests);
    const cli_unit_step = b.step(
        "test-shell",
        "Run the interactive-shell unit tests",
    );
    cli_unit_step.dependOn(&run_cli_unit_tests.step);
    test_step.dependOn(&run_cli_unit_tests.step);

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

    const crash_test = b.addExecutable(.{
        .name = "zaxon-crash-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/crash_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zaxonlite", .module = zaxonlite }},
        }),
    });
    const run_crash_test = b.addRunArtifact(crash_test);
    run_crash_test.addArtifactArg(zaxon);
    const crash_step = b.step(
        "test-crash",
        "Run real-process one-node crash-point recovery tests",
    );
    crash_step.dependOn(&run_crash_test.step);
    test_step.dependOn(&run_crash_test.step);

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

    const role_cluster_test = b.addExecutable(.{
        .name = "zaxon-role-cluster-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/role_cluster_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zaxonlite", .module = zaxonlite }},
        }),
    });
    const run_role_cluster_test = b.addRunArtifact(role_cluster_test);
    const role_cluster_step = b.step(
        "test-roles",
        "Run voter, witness, standby, and read-replica integration",
    );
    role_cluster_step.dependOn(&run_role_cluster_test.step);

    const gateway_test = b.addExecutable(.{
        .name = "zaxon-gateway-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/gateway_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zaxonlite", .module = zaxonlite }},
        }),
    });
    const run_gateway_test = b.addRunArtifact(gateway_test);
    run_gateway_test.addArtifactArg(zaxon);
    const gateway_step = b.step("test-gateway", "Run stateless gateway integration");
    gateway_step.dependOn(&run_gateway_test.step);

    const fault_cluster_test = b.addExecutable(.{
        .name = "zaxon-fault-cluster-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fault_cluster_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zaxonlite", .module = zaxonlite }},
        }),
    });
    const run_fault_cluster_test = b.addRunArtifact(fault_cluster_test);
    const fault_cluster_step = b.step(
        "test-fault-network",
        "Run packet loss, duplication, reordering, fragmentation, and slow sync",
    );
    fault_cluster_step.dependOn(&run_fault_cluster_test.step);

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
    if (tls_enabled) linkOpenSsl(b, bench_zaxonlite, target, openssl_prefix);
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

    // Three-node cluster benchmark: ReleaseFast server binary driven by a
    // ReleaseFast controller, in plaintext, PSK, or mTLS transport mode.
    const vaxis_fast = b.dependency("vaxis", .{
        .target = target,
        .optimize = std.builtin.OptimizeMode.ReleaseFast,
    }).module("vaxis");
    const cli_ui_fast = b.createModule(.{
        .root_source_file = b.path("src/cli_ui/ui.zig"),
        .target = target,
        .optimize = .ReleaseFast,
        .imports = &.{
            .{ .name = "vaxis", .module = vaxis_fast },
        },
    });
    const zaxon_fast = b.addExecutable(.{
        .name = "zaxon-fast",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "zaxonlite", .module = bench_zaxonlite },
                .{ .name = "zaxon_cli_ui", .module = cli_ui_fast },
            },
        }),
    });
    const cluster_bench_exe = b.addExecutable(.{
        .name = "zaxon-cluster-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cluster_bench.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{.{ .name = "zaxonlite", .module = bench_zaxonlite }},
        }),
    });
    // Compile-only gate: the ReleaseFast binaries otherwise build only
    // inside the benchmark run steps.
    const check_step = b.step("check", "Compile every binary without running");
    check_step.dependOn(&zaxon.step);
    check_step.dependOn(&zaxon_fast.step);
    check_step.dependOn(&cluster_bench_exe.step);
    check_step.dependOn(&bench_exe.step);

    const run_cluster_bench = b.addRunArtifact(cluster_bench_exe);
    run_cluster_bench.addArtifactArg(zaxon_fast);
    // Recorded runs update the JSON table the Zaxonlite book compiles in.
    run_cluster_bench.addArgs(&.{
        "--record",
        "benchmarks/results/transport-latest.json",
    });
    if (b.args) |args| run_cluster_bench.addArgs(args);
    const cluster_bench_step = b.step(
        "bench-cluster",
        "Run the three-node cluster benchmark " ++
            "(args: [--sync os|full] mode writes reads)",
    );
    cluster_bench_step.dependOn(&run_cluster_bench.step);

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

fn addApiDocs(b: *std.Build, zaxonlite: *std.Build.Module) void {
    const docs_object = b.addObject(.{
        .name = "zaxonlite-api-docs",
        .root_module = zaxonlite,
    });
    const install_docs = b.addInstallDirectory(.{
        .source_dir = docs_object.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs/api",
    });
    const docs_step = b.step("docs", "Generate the Zig API documentation");
    docs_step.dependOn(&install_docs.step);

    // The autodoc output is a WASM application; browsers refuse to load it
    // from file://, so serve the installed directory over local HTTP.
    const serve_docs = b.addSystemCommand(&.{
        "python3", "-m", "http.server", "8000", "-d",
    });
    serve_docs.addArg(b.getInstallPath(.prefix, "docs/api"));
    serve_docs.step.dependOn(&install_docs.step);
    const serve_step = b.step(
        "docs-serve",
        "Serve the API documentation at http://localhost:8000",
    );
    serve_step.dependOn(&serve_docs.step);
}
