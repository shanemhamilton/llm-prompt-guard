#!/usr/bin/env python3
"""Standalone comparison-classifier benchmark for the held-out BIPIA set.

Scores protectai/deberta-v3-base-prompt-injection-v2 on the exact same rows
benchmarks/heldout/run.ts scored (benchmarks/heldout/heldout_rows.filtered.json,
written by run.ts after its overlap check), and writes the results into the
"## Comparison classifier" section of benchmarks/heldout/HELDOUT_RESULTS.md.

meta-llama/Llama-Prompt-Guard-2-86M is preferred (see the module docstring
in run.ts's task description) but is gated on Hugging Face with manual
approval; this machine's cached token does not have access
(HEAD on its files returns 403). Do not attempt to bypass gating. Meta's
published PG2 numbers are cited in the results doc instead, with the
caveat that they're on a different set.

Requirements (install into a scratch venv, never globally):
    pip install torch --index-url https://download.pytorch.org/whl/cpu
    pip install transformers

Usage:
    python3 benchmarks/heldout/compare.py
"""
import json
import platform
import re
import subprocess
import time
from pathlib import Path

HERE = Path(__file__).parent
ROWS_PATH = HERE / "heldout_rows.filtered.json"
RESULTS_PATH = HERE / "HELDOUT_RESULTS.md"
MARKER = "<!-- COMPARISON_PLACEHOLDER -->"
MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"
MAX_CHUNK_CHARS = 2_000
CHUNK_OVERLAP_CHARS = 200


def get_cpu_brand() -> str:
    try:
        return subprocess.check_output(
            ["sysctl", "-n", "machdep.cpu.brand_string"], text=True
        ).strip()
    except Exception:
        return platform.processor() or "unknown"


def percentile(sorted_vals, p):
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, int((p / 100) * len(sorted_vals)))
    return sorted_vals[idx]


def text_chunks(text: str) -> list[str]:
    """Cover a long BIPIA row without dropping an injection appended at its end."""
    step = MAX_CHUNK_CHARS - CHUNK_OVERLAP_CHARS
    return [text[start : start + MAX_CHUNK_CHARS] for start in range(0, len(text), step)]


def main() -> None:
    import torch
    from transformers import __version__ as transformers_version, pipeline

    rows = json.loads(ROWS_PATH.read_text())
    clf = pipeline("text-classification", model=MODEL_ID, truncation=True)
    model_revision = getattr(clf.model.config, "_commit_hash", None) or "unknown"

    # Warmup (matches run.ts's warmup convention).
    for i in range(20):
        clf(f"warmup {i}")

    tp = fp = tn = fn = 0
    latencies_us = []
    chunk_count = 0
    max_chunks_per_row = 0

    for row in rows:
        t0 = time.perf_counter()
        chunks = text_chunks(row["text"])
        chunk_count += len(chunks)
        max_chunks_per_row = max(max_chunks_per_row, len(chunks))
        is_injection = False
        for chunk in chunks:
            result = clf(chunk)[0]
            if result["label"].upper() in ("INJECTION", "LABEL_1", "UNSAFE"):
                is_injection = True
        latencies_us.append((time.perf_counter() - t0) * 1_000_000)

        if row["label"] == 1:
            if is_injection:
                tp += 1
            else:
                fn += 1
        else:
            if is_injection:
                fp += 1
            else:
                tn += 1

    precision = 0.0 if tp + fp == 0 else tp / (tp + fp) * 100
    recall = 0.0 if tp + fn == 0 else tp / (tp + fn) * 100
    fpr = 0.0 if fp + tn == 0 else fp / (fp + tn) * 100
    latencies_us.sort()
    median_us = percentile(latencies_us, 50)
    p99_us = percentile(latencies_us, 99)

    section = f"""{MARKER}
Ran on the same {len(rows)} held-out rows as the guard (post overlap-check),
same machine, single-threaded CPU inference (no GPU).

**meta-llama/Llama-Prompt-Guard-2-86M could not be run here**: it is gated
on Hugging Face with manual approval, and this machine's cached token does
not have access (a request for its `config.json` returns HTTP 403). Per
the task's instructions, gating was not bypassed. Meta's published PG2
numbers: see the [model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)
— those numbers are on Meta's own eval set, not this one, so they are not
directly comparable to the row below.

**Ran instead: `{MODEL_ID}`** (ungated).

- **CPU:** `{get_cpu_brand()}`
- **Rows scored:** {len(rows)}
- **Input processing:** full text scored in `{MAX_CHUNK_CHARS}`-character chunks
  with `{CHUNK_OVERLAP_CHARS}` characters of overlap ({chunk_count} chunks;
  maximum {max_chunks_per_row} per row).
- **Model revision:** `{model_revision}`
- **Runtime:** `Python {platform.python_version()} / torch {torch.__version__} /
  transformers {transformers_version}`

| Metric | Value |
| --- | --- |
| True positives | {tp} |
| False positives | {fp} |
| True negatives | {tn} |
| False negatives | {fn} |
| Precision | {precision:.1f}% |
| Recall | {recall:.1f}% |
| FPR (over-defense) | {fpr:.2f}% |
| Latency median | {median_us:.1f} µs |
| Latency p99 | {p99_us:.1f} µs |

A transformer classifier trades latency for higher recall on
natural-language task-drift attacks — the class this library's own results
section documents as a structural miss for regex detection. That
trade-off, not a head-to-head "which is better", is the point of running
both: llm-prompt-guard is a Layer-1 filter meant to sit in front of a
model-based layer like this one, not replace it."""

    md = RESULTS_PATH.read_text()

    # Pull the guard's own median latency out of the file (written above the
    # marker by run.ts) so the multiplier below is measured, not guessed.
    guard_match = re.search(r"\| Latency median \| ([\d.]+) µs \|", md)
    multiplier_line = ""
    if guard_match:
        guard_median_us = float(guard_match.group(1))
        if guard_median_us > 0:
            multiplier = median_us / guard_median_us
            multiplier_line = (
                f"\nMeasured latency multiplier on this run: {multiplier:.0f}x "
                f"the guard's median ({median_us:.1f} µs vs {guard_median_us:.1f} µs).\n"
            )

    section = section.rstrip("\n") + "\n" + multiplier_line

    # Replace everything from the marker to end of file with the new section.
    md = re.sub(re.escape(MARKER) + r".*\Z", section, md, flags=re.DOTALL)
    RESULTS_PATH.write_text(md)
    print(f"wrote comparison section to {RESULTS_PATH}")
    print(
        f"precision {precision:.1f}%  recall {recall:.1f}%  FPR {fpr:.2f}%  "
        f"latency median {median_us:.1f}us p99 {p99_us:.1f}us"
    )


if __name__ == "__main__":
    main()
