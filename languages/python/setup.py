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
from the matching installed SQLite archive and the host OpenSSL 3 (the
default `zig build` keeps TLS enabled).  Wheel builders must provision
OpenSSL 3; macOS prefers Homebrew's static archives and Windows uses a
static vcpkg SDK.
"""

import os
import platform
import subprocess
import sys
import sysconfig
from pathlib import Path

from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext

PACKAGE_DIR = Path(__file__).resolve().parent

PY_LIMITED_API = "0x030C0000"  # CPython 3.12

UNSUPPORTED_ZIG_LINKER_FLAGS = frozenset(
    {
        "-Wl,--exclude-libs,ALL",
        "-Wl,-Bsymbolic-functions",
    }
)


def zig_target_args() -> list[str]:
    """Return a Zig target pinned to the release platform's ABI floor."""
    override = os.environ.get("ZXLITE_ZIG_TARGET")
    if override:
        return [f"-Dtarget={override}"]
    if sys.platform == "win32":
        machine = platform.machine().lower()
        if machine not in {"amd64", "x86_64"}:
            raise RuntimeError(
                f"unsupported Windows wheel architecture: {platform.machine()}"
            )
        return ["-Dtarget=x86_64-windows-msvc"]
    if sys.platform != "darwin":
        return []
    machine = platform.machine().lower()
    if machine in {"arm64", "aarch64"}:
        return ["-Dtarget=aarch64-macos.11.0"]
    if machine == "x86_64":
        return ["-Dtarget=x86_64-macos.10.15"]
    raise RuntimeError(f"unsupported macOS wheel architecture: {machine}")


def zig_openssl_args() -> list[str]:
    """Point the Zig build at the same OpenSSL SDK used by the extension."""
    prefix = os.environ.get("ZXLITE_OPENSSL_PREFIX")
    return [f"-Dopenssl-prefix={prefix}"] if prefix else []


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


def openssl_link_args() -> list[str]:
    """Return linker arguments that resolve OpenSSL 3 symbols.

    Prefer static archives on macOS and Windows so the extension has no
    runtime OpenSSL dependency; otherwise fall back to -lssl/-lcrypto.
    """
    prefix = os.environ.get("ZXLITE_OPENSSL_PREFIX")
    if sys.platform == "win32":
        if prefix is None:
            raise RuntimeError(
                "ZXLITE_OPENSSL_PREFIX must point to a static OpenSSL 3 "
                "SDK when building a Windows wheel"
            )
        lib_dir = Path(prefix) / "lib"
        static = [lib_dir / "libssl.lib", lib_dir / "libcrypto.lib"]
        missing = [str(archive) for archive in static if not archive.is_file()]
        if missing:
            raise RuntimeError(
                "Windows OpenSSL SDK is missing static libraries: " + ", ".join(missing)
            )
        return [
            *(str(archive) for archive in static),
            "-lws2_32",
            "-lcrypt32",
            "-ladvapi32",
            "-luser32",
        ]
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


def static_library(root: Path, name: str) -> Path:
    """Return one Zig-installed static library for the host platform."""
    filename = f"{name}.lib" if sys.platform == "win32" else f"lib{name}.a"
    return root / "zig-out" / "lib" / filename


def windows_python_library() -> Path:
    """Locate CPython's Stable ABI import library."""
    roots = {Path(sys.base_prefix), Path(sys.prefix), Path(sys.exec_prefix)}
    candidates = [root / "libs" / "python3.lib" for root in roots]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise RuntimeError(
        "CPython Stable ABI import library python3.lib was not found under "
        + ", ".join(str(root) for root in sorted(roots))
    )


def zig_linker_command(
    original: list[str],
    platform_name: str,
    macos_target: str | None = None,
) -> list[str]:
    """Adapt one setuptools shared-link command for Zig 0.16."""
    rewritten = ["zig", "cc"]
    if platform_name == "darwin":
        if macos_target is None:
            raise RuntimeError("macOS Zig linking requires an explicit target")
        rewritten.extend(["-target", macos_target])
    for flag in original[1:]:
        # Linux CPython builds inject GNU ld symbol-binding flags that
        # Zig 0.16 rejects instead of forwarding. They are optional
        # extension-linking policy, not ABI requirements.
        if platform_name.startswith("linux") and (flag in UNSUPPORTED_ZIG_LINKER_FLAGS):
            continue
        rewritten.append("-shared" if flag == "-bundle" else flag)
    if "-shared" not in rewritten:
        rewritten.append("-shared")
    return rewritten


class ZigBuildExt(build_ext):
    """build_ext that builds and links the zaxonlite static library."""

    def build_extension(self, ext: Extension) -> None:
        root = find_zaxonlite_root()
        subprocess.run(
            [
                "zig",
                "build",
                "-Doptimize=ReleaseSafe",
                *zig_target_args(),
                *zig_openssl_args(),
            ],
            cwd=root,
            check=True,
            stdout=sys.stderr,
        )
        library = static_library(root, "zaxonlite")
        if not library.is_file():
            raise RuntimeError(f"zig build did not produce {library}")
        sqlite = static_library(root, "sqlite3")
        if not sqlite.is_file():
            raise RuntimeError(f"zig build did not produce {sqlite}")
        ext.include_dirs.append(str(root / "zig-out" / "include"))
        ext.extra_objects.append(str(library))
        ext.extra_objects.append(str(sqlite))
        ext.extra_link_args.extend(openssl_link_args())
        if sys.platform == "win32":
            self._build_windows_extension(ext)
            return
        self._link_with_zig_cc()
        # Native target and static dependency changes are outside
        # distutils' source timestamp graph; always relink the wheel.
        self.force = True
        super().build_extension(ext)

    def _build_windows_extension(self, ext: Extension) -> None:
        """Compile and link one Stable ABI `.pyd` with Zig's MSVC target.

        Official Windows CPython uses the MSVC ABI. Keeping compilation
        and linking in one Zig driver invocation avoids mixing MSVC LTCG
        objects with LLD and supplies Zig compiler-rt symbols referenced
        by the zaxonlite archive.
        """
        if len(ext.sources) != 1:
            raise RuntimeError("the Windows zxlite build expects one C source")
        target = zig_target_args()[0].removeprefix("-Dtarget=")
        output = Path(self.get_ext_fullpath(ext.name)).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        include_dirs = {
            *(Path(path) for path in ext.include_dirs),
            Path(sysconfig.get_path("include")),
            Path(sysconfig.get_path("platinclude")),
        }
        command = [
            "zig",
            "cc",
            "-target",
            target,
            "-shared",
            "-O2",
            "-std=c11",
            "-D_CRT_SECURE_NO_WARNINGS",
            *(f"-D{name}={value}" for name, value in ext.define_macros),
            *(f"-I{path}" for path in sorted(include_dirs)),
            str(PACKAGE_DIR / ext.sources[0]),
            *ext.extra_objects,
            str(windows_python_library()),
            *ext.extra_link_args,
            "-o",
            str(output),
        ]
        subprocess.run(command, check=True, stdout=sys.stderr)

    def _link_with_zig_cc(self) -> None:
        """Route the shared-object link through `zig cc`.

        `zig cc` supplies zig compiler-rt symbols and accepts the
        zig-produced archives.  macOS `-bundle` is rewritten to
        `-shared`: zig's Mach-O linker emits a dylib, which CPython
        dlopens exactly like a bundle.
        """
        original = list(self.compiler.linker_so)
        target = (
            zig_target_args()[0].removeprefix("-Dtarget=")
            if sys.platform == "darwin"
            else None
        )
        rewritten = zig_linker_command(original, sys.platform, target)
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
