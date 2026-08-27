const std = @import("std");

const ProductGraph = struct {
    sqlite_lib: *std.Build.Step.Compile,
    c_mod: *std.Build.Module,
    search: *std.Build.Module,
    zaxonlite: *std.Build.Module,
};

/// One optimization mode's full product graph: the static SQLite library
/// (FTS5 plus the pinned sqlite-vec compiled in), the translated C import,
/// the pure `zaxon_search` module, and the zaxonlite module itself. The
/// normal and benchmark builds share this helper so extension and SIMD
/// flags can never diverge (ZDS 0009).
fn addProductGraph(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    tls_enabled: bool,
    openssl_prefix: []const u8,
    public_name: ?[]const u8,
) ProductGraph {
    const sqlite_dep = b.dependency("sqlite", .{});
    const vec_dep = b.dependency("sqlite_vec", .{});
    const paxos = b.dependency("paxos", .{
        .target = target,
        .optimize = optimize,
    }).module("paxos");

    const sqlite_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    sqlite_mod.addIncludePath(sqlite_dep.path(""));
    sqlite_mod.addIncludePath(vec_dep.path(""));
    // The compile-time mmap ceiling permits the runtime opt-in profiles on
    // 64-bit targets; the runtime default stays zero everywhere, and
    // 32-bit or wasm targets compile mapped I/O out entirely (ZDS 0009).
    const mmap_flag = if (target.result.ptrBitWidth() >= 64)
        "-DSQLITE_MAX_MMAP_SIZE=1073741824"
    else
        "-DSQLITE_MAX_MMAP_SIZE=0";
    sqlite_mod.addCSourceFile(.{
        .file = sqlite_dep.path("sqlite3.c"),
        .flags = &.{
            "-DSQLITE_THREADSAFE=1",
            "-DSQLITE_OMIT_LOAD_EXTENSION",
            "-DSQLITE_OMIT_DEPRECATED",
            "-DSQLITE_DQS=0",
            "-DSQLITE_DEFAULT_WAL_SYNCHRONOUS=1",
            "-DHAVE_USLEEP=1",
            "-DSQLITE_ENABLE_FTS5",
            mmap_flag,
        },
    });
    // Pinned sqlite-vec, statically registered per connection. The
    // filesystem helpers stay out, and no AVX or NEON flag is set: the
    // portable artifact must never contain instructions the resolved
    // target does not guarantee (ZDS 0009).
    sqlite_mod.addCSourceFile(.{
        .file = vec_dep.path("sqlite-vec.c"),
        .flags = &.{
            "-DSQLITE_CORE",
            "-DSQLITE_VEC_STATIC",
            "-DSQLITE_VEC_OMIT_FS",
            // sqlite-vec 0.1.9 aliases the fixed-width names through BSD
            // u_int* typedefs on every non-Windows target. musl does not
            // expose those legacy names, so map only this compilation unit
            // back to the equivalent <stdint.h> types.
            "-Du_int8_t=uint8_t",
            "-Du_int16_t=uint16_t",
            "-Du_int64_t=uint64_t",
        },
    });
    const sqlite_lib = b.addLibrary(.{
        .name = "sqlite3",
        .root_module = sqlite_mod,
    });

    const translate_c = b.addTranslateC(.{
        .root_source_file = sqlite_dep.path("sqlite3.h"),
        .target = target,
        .optimize = optimize,
    });
    const c_mod = translate_c.createModule();

    // Pure fusion and distance kernels: deliberately created with no
    // imports so a SQLite, Paxos, or network dependency cannot creep in.
    const search = b.createModule(.{
        .root_source_file = b.path("src/search/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const module_options: std.Build.Module.CreateOptions = .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "paxos", .module = paxos },
            .{ .name = "c", .module = c_mod },
            .{ .name = "zaxon_search", .module = search },
        },
    };
    const zaxonlite = if (public_name) |name|
        b.addModule(name, module_options)
    else
        b.createModule(module_options);
    zaxonlite.linkLibrary(sqlite_lib);
    if (tls_enabled) linkOpenSsl(b, zaxonlite, target, openssl_prefix);

    return .{
        .sqlite_lib = sqlite_lib,
        .c_mod = c_mod,
        .search = search,
        .zaxonlite = zaxonlite,
    };
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
    // MSVC import libraries are named libssl.lib/libcrypto.lib; the
    // windows-gnu (mingw-style) static build produces libssl.a, which the
    // posix names resolve. A native Windows target can leave the ABI as
    // `.none`; that uses the MSVC toolchain unless GNU was explicit.
    const msvc = target.result.os.tag == .windows and
        target.result.abi != .gnu;
    module.linkSystemLibrary(if (msvc) "libssl" else "ssl", .{
        .use_pkg_config = .no,
    });
    module.linkSystemLibrary(if (msvc) "libcrypto" else "crypto", .{
        .use_pkg_config = .no,
    });
    if (target.result.os.tag != .windows) return;
    // A static OpenSSL leaves its platform dependencies to the caller:
    // sockets and name lookup, the certificate and CSP stores, and the
    // registry reads behind RAND_poll.
    for ([_][]const u8{ "ws2_32", "crypt32", "advapi32", "user32" }) |name| {
        module.linkSystemLibrary(name, .{ .use_pkg_config = .no });
    }
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

    const graph = addProductGraph(
        b,
        target,
        optimize,
        tls_enabled,
        openssl_prefix,
        "zaxonlite",
    );
    const zaxonlite = graph.zaxonlite;

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

    // The pure search kernels test as their own module: compiling them
    // without any imports proves the SQLite-free boundary (ZDS 0009).
    const search_tests = b.addTest(.{ .root_module = graph.search });
    const run_search_tests = b.addRunArtifact(search_tests);
    const search_test_step = b.step(
        "test-search",
        "Run the pure zaxon_search kernel tests",
    );
    search_test_step.dependOn(&run_search_tests.step);
    test_step.dependOn(&run_search_tests.step);

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

    const replacement_cluster_test = b.addExecutable(.{
        .name = "zaxon-replace-cluster-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/replacement_cluster_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zaxonlite", .module = zaxonlite }},
        }),
    });
    const run_replacement_cluster_test = b.addRunArtifact(replacement_cluster_test);
    run_replacement_cluster_test.addArtifactArg(zaxon);
    const replacement_cluster_step = b.step(
        "test-replace-cluster",
        "Run the decided voter-replacement cluster scenario under mTLS",
    );
    replacement_cluster_step.dependOn(&run_replacement_cluster_test.step);

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

    // Long-run retention gate: rotation, reclamation, anchored restart.
    const longrun_writes = b.option(
        u64,
        "longrun-writes",
        "Long-run write count (default 20000)",
    ) orelse 20_000;
    const longrun_exe = b.addExecutable(.{
        .name = "zaxon-longrun",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/longrun_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zaxonlite", .module = zaxonlite }},
        }),
    });
    const run_longrun = b.addRunArtifact(longrun_exe);
    run_longrun.addArg(b.fmt("{d}", .{longrun_writes}));
    const longrun_step = b.step(
        "test-longrun",
        "Run the long-run retention and anchored-restart gate",
    );
    longrun_step.dependOn(&run_longrun.step);

    // Benchmarks always build ReleaseFast regardless of -Doptimize. The
    // shared helper guarantees the benchmark SQLite carries exactly the
    // same extension and SIMD flags as the product build.
    const bench_graph = addProductGraph(
        b,
        target,
        .ReleaseFast,
        tls_enabled,
        openssl_prefix,
        null,
    );
    const bench_zaxonlite = bench_graph.zaxonlite;
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

    // Search benchmarks (ZDS 0009 performance gates): kernel throughput,
    // storage ratio, heap bounds, mmap profiles, and representative recall.
    const search_bench_exe = b.addExecutable(.{
        .name = "zaxon-search-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/search_bench.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "zaxonlite", .module = bench_zaxonlite },
                .{ .name = "zaxon_search", .module = bench_graph.search },
            },
        }),
    });
    const run_search_bench = b.addRunArtifact(search_bench_exe);
    // Recorded runs update the JSON the Zaxonlite book compiles in.
    run_search_bench.addArgs(&.{
        "--record",
        "benchmarks/results/search-latest.json",
    });
    if (b.args) |args| run_search_bench.addArgs(args);
    const search_bench_step = b.step(
        "bench-search",
        "Run the search kernel, storage, heap, mmap, and recall benchmarks",
    );
    search_bench_step.dependOn(&run_search_bench.step);

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
    check_step.dependOn(&search_bench_exe.step);

    // Cross-target compile gate for the pure search kernels: the module
    // has no dependencies, so it must build for every supported vector
    // target, including the scalar fallbacks (ZDS 0009).
    const KernelTarget = struct {
        name: []const u8,
        triple: []const u8,
        cpu_features: ?[]const u8 = null,
    };
    const kernel_targets = [_]KernelTarget{
        .{ .name = "aarch64-macos", .triple = "aarch64-macos" },
        .{ .name = "aarch64-linux", .triple = "aarch64-linux-gnu" },
        .{ .name = "aarch64-windows", .triple = "aarch64-windows-gnu" },
        .{ .name = "x86_64-linux", .triple = "x86_64-linux-gnu" },
        .{ .name = "x86_64-windows", .triple = "x86_64-windows-gnu" },
        .{ .name = "x86-linux", .triple = "x86-linux-gnu" },
        .{
            .name = "armv7-scalar",
            .triple = "arm-linux-musleabihf",
            .cpu_features = "baseline-neon",
        },
        .{
            .name = "armv7-neon",
            .triple = "arm-linux-musleabihf",
            .cpu_features = "baseline+neon",
        },
        .{
            .name = "wasm32-scalar",
            .triple = "wasm32-wasi",
            .cpu_features = "baseline-simd128",
        },
        .{
            .name = "wasm32-simd128",
            .triple = "wasm32-wasi",
            .cpu_features = "baseline+simd128",
        },
        .{ .name = "riscv64-scalar", .triple = "riscv64-linux-gnu" },
    };
    // Disassembly gate (ZDS 0009): a ReleaseFast object exporting the
    // SIMD cosine kernel; benchmarks/verify-simd.sh greps its
    // disassembly for packed float multiply/add instructions.
    const probe_obj = b.addObject(.{
        .name = "zaxon-search-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/search/disasm_probe.zig"),
            .target = target,
            .optimize = .ReleaseFast,
        }),
    });
    const install_probe = b.addInstallFile(
        probe_obj.getEmittedBin(),
        "disasm/zaxon-search-probe.o",
    );
    const probe_step = b.step(
        "disasm-probe",
        "Emit the SIMD kernel probe object for disassembly verification",
    );
    probe_step.dependOn(&install_probe.step);

    const kernels_step = b.step(
        "check-kernels",
        "Cross-compile the pure search kernels for the vector target matrix",
    );
    for (kernel_targets) |kernel_target| {
        const query = std.Target.Query.parse(
            .{
                .arch_os_abi = kernel_target.triple,
                .cpu_features = kernel_target.cpu_features,
            },
        ) catch unreachable;
        const kernel_mod = b.createModule(.{
            // The exported probe forces semantic analysis and code
            // generation of the distance kernel. Compiling root.zig alone
            // would be a weak lazy-analysis check that could emit no code.
            .root_source_file = b.path("src/search/disasm_probe.zig"),
            .target = b.resolveTargetQuery(query),
            .optimize = optimize,
        });
        const kernel_obj = b.addObject(.{
            .name = b.fmt("zaxon-search-{s}", .{kernel_target.name}),
            .root_module = kernel_mod,
        });
        kernels_step.dependOn(&kernel_obj.step);
    }
    check_step.dependOn(kernels_step);

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

    // C ABI: libzaxonlite, its exact SQLite dependency, and the header.
    // Installing SQLite avoids forcing external hosts (notably the
    // Python wheel build) to guess which target-specific cache archive
    // belongs to this product graph.
    const install_sqlite = b.addInstallArtifact(graph.sqlite_lib, .{});
    b.getInstallStep().dependOn(&install_sqlite.step);
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
    const install_capi = b.addInstallArtifact(capi_lib, .{});
    b.getInstallStep().dependOn(&install_capi.step);
    const install_cabi_step = b.step(
        "install-cabi",
        "Install only the C ABI libraries and header",
    );
    install_cabi_step.dependOn(&install_sqlite.step);
    install_cabi_step.dependOn(&install_capi.step);

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
    if (openssl_prefix.len > 0) {
        capi_smoke.root_module.addLibraryPath(.{
            .cwd_relative = b.fmt("{s}/lib", .{openssl_prefix}),
        });
    }
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
