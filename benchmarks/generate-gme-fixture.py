#!/usr/bin/env python3
"""Optional GME/Qwen 2B retrieval-quality qualification harness (ZDS 0009).

Never run in CI. This script loads Alibaba-NLP/gme-Qwen2-VL-2B-Instruct
(2.21B parameters; expect roughly 2.2 to 4 GiB in reduced precision),
embeds a corpus plus text and image queries, and writes the bounded
qualification fixture used for explicit model-quality runs:

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
    --revision <model-commit-sha> --license-note "<source licenses>" \
    --prompt-config prompts.json \
    --preprocessing-note "<text/image preprocessing>"

This is deliberately separate from the checked representative fixture
created by generate-representative-fixture.py. Routine CI never loads
the model; the model, weights, and source media do not enter the repository.
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


def as_numpy(value):
    """Copy a model result to a CPU NumPy array."""
    if hasattr(value, "detach"):
        value = value.detach()
    if hasattr(value, "cpu"):
        value = value.cpu()
    if hasattr(value, "numpy"):
        value = value.numpy()
    return value


def embed(model, items):
    import numpy as np

    if not items:
        raise SystemExit("embedding input must contain at least one item")
    text_rows = []
    image_rows = []
    for index, item in enumerate(items):
        has_text = "text" in item
        has_image = "image" in item
        if has_text == has_image:
            raise SystemExit(
                f"item {index} must contain exactly one of text or image"
            )
        target = text_rows if has_text else image_rows
        target.append((index, item["text"] if has_text else item["image"]))

    matrix = np.empty((len(items), DIMS), dtype=np.float32)
    if text_rows:
        values = np.asarray(as_numpy(model.get_text_embeddings(
            texts=[value for _, value in text_rows],
        )), dtype=np.float32)
        if values.shape != (len(text_rows), DIMS):
            raise SystemExit(
                f"text embeddings have shape {values.shape}, "
                f"expected {(len(text_rows), DIMS)}"
            )
        matrix[[index for index, _ in text_rows]] = values
    if image_rows:
        values = np.asarray(as_numpy(model.get_image_embeddings(
            images=[value for _, value in image_rows],
        )), dtype=np.float32)
        if values.shape != (len(image_rows), DIMS):
            raise SystemExit(
                f"image embeddings have shape {values.shape}, "
                f"expected {(len(image_rows), DIMS)}"
            )
        matrix[[index for index, _ in image_rows]] = values
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
    parser.add_argument("--prompt-config", required=True,
                        help="JSON file describing query/corpus prompts")
    parser.add_argument("--preprocessing-note", required=True,
                        help="image and text preprocessing configuration")
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
        np.save(OUT_DIR / name, matrix)

    with open(args.relevance, "r", encoding="utf-8") as handle:
        relevance = json.load(handle)
    with open(args.prompt_config, "r", encoding="utf-8") as handle:
        prompt_config = json.load(handle)
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
        "prompt_config": prompt_config,
        "preprocessing": args.preprocessing_note,
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
