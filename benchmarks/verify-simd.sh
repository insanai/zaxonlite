#!/bin/sh
# Disassembly gate (ZDS 0009): supported release targets must carry packed
# float multiply/add instructions in the Zig cosine kernel. Run
# `zig build disasm-probe` first; a benchmark alone is not proof of SIMD.
set -eu

object="zig-out/disasm/zaxon-search-probe.o"
if [ ! -f "$object" ]; then
    echo "verify-simd: $object missing; run 'zig build disasm-probe' first" >&2
    exit 1
fi

arch="$(uname -m)"
disasm="$(objdump -d "$object")"

case "$arch" in
arm64 | aarch64)
    # GNU prints "fmul v0.4s, ..." and LLVM prints "fmul.4s v0, ...".
    echo "$disasm" | grep -E 'fmul(\.4s|[[:space:]]+v[0-9]+\.4s)' >/dev/null ||
        { echo "verify-simd: no packed fmul in aarch64 kernel" >&2; exit 1; }
    echo "$disasm" | grep -E 'fadd(\.4s|[[:space:]]+v[0-9]+\.4s)' >/dev/null ||
        { echo "verify-simd: no packed fadd in aarch64 kernel" >&2; exit 1; }
    echo "verify-simd: packed fmul/fadd present (aarch64 NEON 128-bit)"
    ;;
x86_64 | amd64)
    echo "$disasm" | grep -E '(mulps|vmulps)' >/dev/null ||
        { echo "verify-simd: no packed mulps in x86-64 kernel" >&2; exit 1; }
    echo "$disasm" | grep -E '(addps|vaddps)' >/dev/null ||
        { echo "verify-simd: no packed addps in x86-64 kernel" >&2; exit 1; }
    echo "verify-simd: packed mulps/addps present (x86-64 SSE 128-bit)"
    ;;
*)
    echo "verify-simd: no gate for $arch (scalar or unsupported target)"
    ;;
esac
