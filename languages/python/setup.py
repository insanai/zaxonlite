"""Build the zxlite._zxlite extension against the zaxonlite static library.

The custom build_ext locates the zaxonlite source tree (the directory
holding build.zig and src/capi.zig), runs `zig build -Doptimize=ReleaseSafe`
there, and compiles src/native/module.c against zig-out/include and
zig-out/lib/libzaxonlite.a.  The extension targets the Limited API
(3.12) and ships as an abi3 wheel.

Linking uses `zig cc` because the zig-produced archives need zig's
linker driver on macOS (Apple's ld rejects their member alignment) and
because the zaxonlite compilation unit references zig compiler-rt
f128 helpers that the system toolchain does not provide.  The archive
carries undefined sqlite3_* and OpenSSL references that the reference
C consumer resolves through the zig build graph; here they resolve
from the freshly built libsqlite3.a in the zig cache and the host
OpenSSL 3 (the default `zig build` keeps TLS enabled).

TODO(release wheels): cibuildwheel images must provision OpenSSL 3 for
static linking (or build with -Dtls=false once the C ABI gates the
cluster facade); local Gate A development links the host OpenSSL.
"""

import os
import subprocess
import sys
from pathlib import Path

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

PACKAGE_DIR = Path(__file__).resolve().parent

PY_LIMITED_API = "0x030C0000"  # CPython 3.12


def find_zaxonlite_root() -> Path:
    """Locate the zaxonlite source tree from the package directory.

    Walk up from the package directory; at every ancestor, accept the
    ancestor itself or an ancestor/zaxonlite sibling checkout when it
    contains build.zig next to src/capi.zig.  This covers both the
    monorepo layout (zaxonlite/languages/python) and a standalone
    checkout sitting beside the zaxonlite repository.  A build detached
    from the tree (for example a wheel built from the sdist) must point
    ZAXONLITE_ROOT at a zaxonlite checkout instead.
    """
    override = os.environ.get("ZAXONLITE_ROOT")
    if override:
        root = Path(override).resolve()
        if (root / "build.zig").is_file() and (root / "src" / "capi.zig").is_file():
            return root
        raise RuntimeError(
            f"ZAXONLITE_ROOT={override} does not contain build.zig and src/capi.zig"
        )
    for ancestor in (PACKAGE_DIR, *PACKAGE_DIR.parents):
        for candidate in (ancestor, ancestor / "zaxonlite"):
            if (candidate / "build.zig").is_file() and (
                candidate / "src" / "capi.zig"
            ).is_file():
                return candidate
    raise RuntimeError(
        "cannot locate the zaxonlite source tree (build.zig with "
        "src/capi.zig) above " + str(PACKAGE_DIR)
    )


def find_sqlite_archive(root: Path) -> Path:
    """Return the newest libsqlite3.a produced by the zig build.

    The zig build graph links the bundled SQLite (FTS5 plus the pinned
    sqlite-vec) as a separate static library that is not installed to
    zig-out, so the freshest cache entry after `zig build` is the one
    that matches the just-built libzaxonlite.a.
    """
    candidates = sorted(
        (root / ".zig-cache" / "o").glob("*/libsqlite3.a"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        raise RuntimeError(
            f"no libsqlite3.a found under {root}/.zig-cache after zig build"
        )
    return candidates[0]


def openssl_link_args() -> list[str]:
    """Return linker arguments that resolve OpenSSL 3 symbols.

    Prefer the static Homebrew archives on macOS so the extension has
    no runtime dylib dependency; otherwise fall back to -lssl/-lcrypto.
    """
    prefix = os.environ.get("ZXLITE_OPENSSL_PREFIX")
    if prefix is None and sys.platform == "darwin":
        prefix = "/opt/homebrew/opt/openssl@3"
    if prefix:
        lib_dir = Path(prefix) / "lib"
        static = [lib_dir / "libssl.a", lib_dir / "libcrypto.a"]
        if all(archive.is_file() for archive in static):
            return [str(archive) for archive in static]
        if lib_dir.is_dir():
            return [f"-L{lib_dir}", "-lssl", "-lcrypto"]
    return ["-lssl", "-lcrypto"]


class ZigBuildExt(build_ext):
    """build_ext that builds and links the zaxonlite static library."""

    def build_extension(self, ext: Extension) -> None:
        root = find_zaxonlite_root()
        subprocess.run(
            ["zig", "build", "-Doptimize=ReleaseSafe"],
            cwd=root,
            check=True,
            stdout=sys.stderr,
        )
        library = root / "zig-out" / "lib" / "libzaxonlite.a"
        if not library.is_file():
            raise RuntimeError(f"zig build did not produce {library}")
        ext.include_dirs.append(str(root / "zig-out" / "include"))
        ext.extra_objects.append(str(library))
        ext.extra_objects.append(str(find_sqlite_archive(root)))
        ext.extra_link_args.extend(openssl_link_args())
        self._link_with_zig_cc()
        super().build_extension(ext)

    def _link_with_zig_cc(self) -> None:
        """Route the shared-object link through `zig cc`.

        `zig cc` supplies zig compiler-rt symbols and accepts the
        zig-produced archives.  macOS `-bundle` is rewritten to
        `-shared`: zig's Mach-O linker emits a dylib, which CPython
        dlopens exactly like a bundle.
        """
        original = list(self.compiler.linker_so)
        rewritten = ["zig", "cc"]
        for flag in original[1:]:
            rewritten.append("-shared" if flag == "-bundle" else flag)
        if "-shared" not in rewritten:
            rewritten.append("-shared")
        self.compiler.set_executable("linker_so", rewritten)


extension = Extension(
    name="zxlite._zxlite",
    sources=["src/native/module.c"],
    define_macros=[("Py_LIMITED_API", PY_LIMITED_API)],
    py_limited_api=True,
)

setup(
    ext_modules=[extension],
    cmdclass={"build_ext": ZigBuildExt},
    options={"bdist_wheel": {"py_limited_api": "cp312"}},
)
