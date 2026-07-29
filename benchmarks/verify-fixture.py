#!/usr/bin/env python3
"""Verify the required representative and optional Qwen fixtures (ZDS 0009).

Routine CI requires the small representative bundle and validates its NumPy
shape, normalization, manifest, relevance structure, and SHA-256 hashes using
only the Python standard library. If an offline GME/Qwen 2B qualification
bundle is present, its pinned manifest and hashes are verified as well.
"""

import ast
import hashlib
import json
import math
import pathlib
import struct
import sys

DATA_DIR = pathlib.Path(__file__).parent / "data"
REPRESENTATIVE = DATA_DIR / "representative-v1-512"
QWEN = DATA_DIR / "gme-qwen2-vl-2b-1536"
ARTIFACTS = {
    "corpus.f32.npy",
    "text-queries.f32.npy",
    "image-queries.f32.npy",
    "relevance.json",
}


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_hashes(directory: pathlib.Path, manifest: dict) -> int:
    failures = 0
    artifacts = manifest.get("artifacts", {})
    if set(artifacts) != ARTIFACTS:
        print(f"verify-fixture: INVALID artifact set in {directory.name}")
        failures += 1
    for name, expected in sorted(artifacts.items()):
        path = directory / name
        if not path.exists():
            print(f"verify-fixture: MISSING {directory.name}/{name}")
            failures += 1
            continue
        actual = sha256(path)
        if actual != expected:
            print(
                f"verify-fixture: MISMATCH {directory.name}/{name}\n"
                f"  recorded {expected}\n  actual   {actual}"
            )
            failures += 1
        else:
            print(f"verify-fixture: ok {directory.name}/{name}")
    return failures


def read_npy(path: pathlib.Path) -> tuple[tuple[int, int], tuple[float, ...]]:
    payload = path.read_bytes()
    if len(payload) < 10 or payload[:8] != b"\x93NUMPY\x01\x00":
        raise ValueError("expected a NumPy v1 array")
    header_length = struct.unpack_from("<H", payload, 8)[0]
    header_end = 10 + header_length
    if header_end > len(payload):
        raise ValueError("truncated NumPy header")
    header = ast.literal_eval(payload[10:header_end].decode("ascii").strip())
    shape = header.get("shape")
    if (
        header.get("descr") != "<f4"
        or header.get("fortran_order") is not False
        or not isinstance(shape, tuple)
        or len(shape) != 2
        or any(not isinstance(value, int) or value <= 0 for value in shape)
    ):
        raise ValueError("expected a little-endian float32 C-order matrix")
    count = shape[0] * shape[1]
    if len(payload) - header_end != count * 4:
        raise ValueError("NumPy payload does not match its shape")
    values = struct.unpack_from(f"<{count}f", payload, header_end)
    return shape, values


def verify_matrix(
    path: pathlib.Path,
    expected_shape: tuple[int, int],
) -> int:
    try:
        shape, values = read_npy(path)
    except (OSError, SyntaxError, ValueError, struct.error) as error:
        print(f"verify-fixture: INVALID {path.name}: {error}")
        return 1
    if shape != expected_shape:
        print(
            f"verify-fixture: INVALID {path.name} shape {shape}; "
            f"expected {expected_shape}"
        )
        return 1
    rows, dimensions = shape
    for row in range(rows):
        vector = values[row * dimensions:(row + 1) * dimensions]
        norm = math.sqrt(sum(value * value for value in vector))
        if not math.isfinite(norm) or abs(norm - 1.0) > 1e-5:
            print(
                f"verify-fixture: INVALID {path.name} row {row} "
                f"L2 norm {norm}"
            )
            return 1
    return 0


def verify_representative() -> int:
    manifest_path = REPRESENTATIVE / "manifest.json"
    if not manifest_path.exists():
        print(
            "verify-fixture: MISSING required representative fixture; run "
            "python3 benchmarks/generate-representative-fixture.py"
        )
        return 1
    manifest = json.loads(manifest_path.read_text())
    expected = {
        "format": 1,
        "fixture": "zaxonlite-representative-v1",
        "fixture_role": "mechanical-regression",
        "generator": "generate-representative-fixture.py",
        "seed": "zaxonlite-zds-0009-representative-v1",
        "dimensions": 512,
        "dtype": "float32",
        "normalization": "l2-unit",
        "distance": "cosine",
        "corpus_rows": 96,
        "text_query_rows": 12,
        "image_query_rows": 12,
        "neural_model": None,
        "quality_claim": False,
    }
    failures = 0
    for field, value in expected.items():
        if manifest.get(field) != value:
            print(
                f"verify-fixture: INVALID representative {field}; "
                f"expected {value!r}"
            )
            failures += 1
    if manifest.get("row_ids") != list(range(96)):
        print("verify-fixture: INVALID representative row IDs")
        failures += 1
    actual_files = {
        path.name for path in REPRESENTATIVE.iterdir() if path.is_file()
    }
    if actual_files != ARTIFACTS | {"manifest.json"}:
        print("verify-fixture: INVALID representative file set")
        failures += 1
    bundle_bytes = sum(
        path.stat().st_size for path in REPRESENTATIVE.iterdir()
        if path.is_file()
    )
    if bundle_bytes >= 250 * 1024:
        print(
            f"verify-fixture: INVALID representative size {bundle_bytes}; "
            "must remain under 250 KiB"
        )
        failures += 1
    failures += verify_hashes(REPRESENTATIVE, manifest)
    failures += verify_matrix(
        REPRESENTATIVE / "corpus.f32.npy",
        (96, 512),
    )
    failures += verify_matrix(
        REPRESENTATIVE / "text-queries.f32.npy",
        (12, 512),
    )
    failures += verify_matrix(
        REPRESENTATIVE / "image-queries.f32.npy",
        (12, 512),
    )
    relevance = json.loads(
        (REPRESENTATIVE / "relevance.json").read_text()
    )
    for modality in ("text", "image"):
        expected_queries = {
            f"{modality}-{topic}": list(range(topic * 8, (topic + 1) * 8))
            for topic in range(12)
        }
        if relevance.get(modality) != expected_queries:
            print(
                f"verify-fixture: INVALID representative {modality} "
                "relevance judgments"
            )
            failures += 1
    return failures


def verify_optional_qwen() -> int:
    manifest_path = QWEN / "manifest.json"
    if not manifest_path.exists():
        if QWEN.exists():
            print(
                "verify-fixture: INVALID partial GME/Qwen 2B qualification; "
                "manifest.json is missing"
            )
            return 1
        print("verify-fixture: optional GME/Qwen 2B qualification absent")
        return 0
    manifest = json.loads(manifest_path.read_text())
    failures = 0
    expected = {
        "model": "Alibaba-NLP/gme-Qwen2-VL-2B-Instruct",
        "dimensions": 1536,
        "dtype": "float32",
        "normalization": "l2-unit",
        "distance": "cosine",
    }
    for field, value in expected.items():
        if manifest.get(field) != value:
            print(f"verify-fixture: INVALID Qwen {field}; expected {value!r}")
            failures += 1
    for field in (
        "revision",
        "licenses",
        "prompt_config",
        "preprocessing",
        "row_ids",
    ):
        if not manifest.get(field):
            print(f"verify-fixture: MISSING Qwen manifest field {field}")
            failures += 1
    failures += verify_hashes(QWEN, manifest)
    return failures


def main() -> int:
    failures = verify_representative() + verify_optional_qwen()
    if failures:
        print(f"verify-fixture: {failures} check(s) failed")
        return 1
    print("verify-fixture: all required fixture checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
