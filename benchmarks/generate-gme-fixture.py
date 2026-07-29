#!/usr/bin/env python3
"""Offline generator for the pinned GME retrieval-quality fixture (ZDS 0009).

Never run in CI. This script loads Alibaba-NLP/gme-Qwen2-VL-2B-Instruct
(2.21B parameters; expect roughly 2.2 to 4 GiB in reduced precision),
embeds a corpus plus text and image queries, and writes the bounded
fixture that routine benchmarks consume:

    benchmarks/data/gme-qwen2-vl-2b-1536/
      manifest.json         model revision, config, hashes, licenses
      corpus.f32.npy        (N, 1536) float32, L2-normalized
      text-queries.f32.npy  (Q, 1536) float32, L2-normalized
      image-queries.f32.npy (P, 1536) float32, L2-normalized
      relevance.json        query id -> list of relevant corpus row ids

Input is a JSONL corpus file: one object per line with fields
  {"id": int, "text": str}            for text items, or
  {"id": int, "image": "path.jpg"}    for image items,
plus query files in the same shape. Relevance judgments are supplied as
JSON mapping query index to relevant corpus indexes.

Usage:
  python3 benchmarks/generate-gme-fixture.py \
    --corpus corpus.jsonl --text-queries tq.jsonl \
    --image-queries iq.jsonl --relevance relevance.json \
    --revision <model-commit-sha> --license-note "<source licenses>"

CI verifies the recorded SHA-256 hashes only (verify-fixture.py); the
model, weights, and source media never enter the repository.
"""

import argparse
import hashlib
import json
import pathlib
import sys

MODEL = "Alibaba-NLP/gme-Qwen2-VL-2B-Instruct"
DIMS = 1536
OUT_DIR = pathlib.Path(__file__).parent / "data" / "gme-qwen2-vl-2b-1536"


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def load_jsonl(path: str):
    with open(path, "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def embed(model, items):
    import numpy as np

    texts = [item["text"] for item in items if "text" in item]
    images = [item["image"] for item in items if "image" in item]
    vectors = []
    if texts:
        vectors.append(model.get_text_embeddings(texts=texts))
    if images:
        vectors.append(model.get_image_embeddings(images=images))
    matrix = np.concatenate(vectors, axis=0).astype(np.float32)
    if matrix.shape[1] != DIMS:
        raise SystemExit(f"expected {DIMS} dimensions, got {matrix.shape[1]}")
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    return matrix / np.maximum(norms, 1e-12)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--text-queries", required=True)
    parser.add_argument("--image-queries", required=True)
    parser.add_argument("--relevance", required=True)
    parser.add_argument("--revision", required=True,
                        help="exact model repository commit")
    parser.add_argument("--license-note", required=True,
                        help="source-dataset license statement")
    args = parser.parse_args()

    import numpy as np
    from transformers import AutoModel

    model = AutoModel.from_pretrained(
        MODEL, revision=args.revision, trust_remote_code=True
    )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    corpus_items = load_jsonl(args.corpus)
    outputs = {
        "corpus.f32.npy": embed(model, corpus_items),
        "text-queries.f32.npy": embed(model, load_jsonl(args.text_queries)),
        "image-queries.f32.npy": embed(model, load_jsonl(args.image_queries)),
    }
    for name, matrix in outputs.items():
        np.save(OUT_DIR / name.removesuffix(".npy"), matrix)
        # np.save appends .npy to the stem; normalize the final name.
        produced = OUT_DIR / (name.removesuffix(".npy") + ".npy")
        produced.rename(OUT_DIR / name)

    with open(args.relevance, "r", encoding="utf-8") as handle:
        relevance = json.load(handle)
    (OUT_DIR / "relevance.json").write_text(
        json.dumps(relevance, indent=1, sort_keys=True) + "\n"
    )

    manifest = {
        "model": MODEL,
        "revision": args.revision,
        "dimensions": DIMS,
        "dtype": "float32",
        "normalization": "l2-unit",
        "distance": "cosine",
        "licenses": args.license_note,
        "row_ids": [item["id"] for item in corpus_items],
        "artifacts": {
            name: sha256(OUT_DIR / name)
            for name in [*outputs, "relevance.json"]
        },
    }
    (OUT_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=1, sort_keys=True) + "\n"
    )
    print(f"fixture written to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
