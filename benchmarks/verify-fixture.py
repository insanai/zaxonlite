#!/usr/bin/env python3
"""Verify the pinned GME fixture hashes (ZDS 0009).

Routine CI runs this instead of any model inference: when the fixture
directory is absent the check is skipped successfully; when present,
every artifact must match the SHA-256 recorded in manifest.json.
"""

import hashlib
import json
import pathlib
import sys

FIXTURE = pathlib.Path(__file__).parent / "data" / "gme-qwen2-vl-2b-1536"


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    manifest_path = FIXTURE / "manifest.json"
    if not manifest_path.exists():
        print(f"verify-fixture: {FIXTURE} absent; skipped "
              "(generate offline with generate-gme-fixture.py)")
        return 0
    manifest = json.loads(manifest_path.read_text())
    failures = 0
    for name, expected in sorted(manifest["artifacts"].items()):
        path = FIXTURE / name
        if not path.exists():
            print(f"verify-fixture: MISSING {name}")
            failures += 1
            continue
        actual = sha256(path)
        if actual != expected:
            print(f"verify-fixture: MISMATCH {name}\n"
                  f"  recorded {expected}\n  actual   {actual}")
            failures += 1
        else:
            print(f"verify-fixture: ok {name}")
    if failures:
        print(f"verify-fixture: {failures} artifact(s) failed")
        return 1
    print("verify-fixture: all artifacts match the manifest")
    return 0


if __name__ == "__main__":
    sys.exit(main())
