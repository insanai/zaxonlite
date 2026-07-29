#!/usr/bin/env python3
"""Generate the small deterministic ZDS 0009 search fixture.

This generator uses only the Python standard library. It creates related
text-query, image-query, and corpus vectors without neural inference, so the
fixture is reproducible on CI and on an 8 GiB Apple M1 development machine.
It validates the complete NumPy -> vec0 coarse search -> exact rerank path;
it is not evidence of any embedding model's retrieval quality.
"""

import hashlib
import json
import math
import pathlib
import struct

DIMS = 512
TOPICS = 12
ROWS_PER_TOPIC = 8
SEED = "zaxonlite-zds-0009-representative-v1"
OUT_DIR = pathlib.Path(__file__).parent / "data" / "representative-v1-512"


def bit(label: str, index: int) -> int:
    payload = f"{SEED}:{label}:{index}".encode()
    return hashlib.sha256(payload).digest()[0] & 1


def vector(topic: int, variant: int, modality: str) -> list[float]:
    values = []
    for dimension in range(DIMS):
        sign = 1.0 if bit(f"topic-{topic}", dimension) else -1.0
        # Nearby rows share almost every sign. Query-specific flips exercise
        # candidate ordering while preserving an obvious relevant cluster.
        flip_period = 97 if modality == "corpus" else 113
        flip_offset = topic * 17 + variant * 29 + len(modality) * 11
        if (dimension + flip_offset) % flip_period == 0:
            sign = -sign
        magnitude_step = (
            dimension * 7 + topic * 5 + variant * 3 + len(modality)
        ) % 9
        magnitude = 0.90 + magnitude_step * 0.025
        values.append(sign * magnitude)
    norm = math.sqrt(sum(value * value for value in values))
    return [value / norm for value in values]


def write_npy(path: pathlib.Path, rows: list[list[float]]) -> None:
    shape = (len(rows), DIMS)
    header = (
        "{'descr': '<f4', 'fortran_order': False, "
        f"'shape': {shape}, }}"
    )
    padding = (64 - ((10 + len(header) + 1) % 64)) % 64
    header_bytes = (header + " " * padding + "\n").encode("ascii")
    if len(header_bytes) > 0xFFFF:
        raise ValueError("NumPy v1 header is too large")
    with path.open("wb") as handle:
        handle.write(b"\x93NUMPY\x01\x00")
        handle.write(struct.pack("<H", len(header_bytes)))
        handle.write(header_bytes)
        for row in rows:
            handle.write(struct.pack(f"<{DIMS}f", *row))


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    corpus = [
        vector(topic, variant, "corpus")
        for topic in range(TOPICS)
        for variant in range(ROWS_PER_TOPIC)
    ]
    text_queries = [
        vector(topic, 0, "text")
        for topic in range(TOPICS)
    ]
    image_queries = [
        vector(topic, 1, "image")
        for topic in range(TOPICS)
    ]
    outputs = {
        "corpus.f32.npy": corpus,
        "text-queries.f32.npy": text_queries,
        "image-queries.f32.npy": image_queries,
    }
    for name, rows in outputs.items():
        write_npy(OUT_DIR / name, rows)

    relevance = {
        modality: {
            f"{modality}-{topic}": list(range(
                topic * ROWS_PER_TOPIC,
                (topic + 1) * ROWS_PER_TOPIC,
            ))
            for topic in range(TOPICS)
        }
        for modality in ("text", "image")
    }
    (OUT_DIR / "relevance.json").write_text(
        json.dumps(relevance, indent=1, sort_keys=True) + "\n"
    )
    manifest = {
        "format": 1,
        "fixture": "zaxonlite-representative-v1",
        "fixture_role": "mechanical-regression",
        "generator": pathlib.Path(__file__).name,
        "seed": SEED,
        "dimensions": DIMS,
        "dtype": "float32",
        "normalization": "l2-unit",
        "distance": "cosine",
        "corpus_rows": len(corpus),
        "text_query_rows": len(text_queries),
        "image_query_rows": len(image_queries),
        "neural_model": None,
        "quality_claim": False,
        "row_ids": list(range(len(corpus))),
        "artifacts": {
            name: sha256(OUT_DIR / name)
            for name in [*outputs, "relevance.json"]
        },
    }
    (OUT_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=1, sort_keys=True) + "\n"
    )
    print(f"representative fixture written to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
