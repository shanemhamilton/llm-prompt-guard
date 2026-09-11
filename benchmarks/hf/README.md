---
license: mit
task_categories:
  - text-classification
tags:
  - prompt-injection
  - llm-security
size_categories:
  - 1K<n<10K
---

# llm-prompt-guard tuning corpus

Prompt-injection detection corpus used to tune the
[llm-prompt-guard](https://github.com/shanemhamilton/llm-prompt-guard) pattern
set. Two JSONL files:

- `attacks.jsonl` — 198 rows, `label: 1`. Injection payloads grouped by
  attack category (instruction override, role hijacking, jailbreak,
  unicode/homoglyph/tag-block smuggling, encoding bypass, and more).
- `benign.jsonl` — 1,310 rows, `label: 0`. Ordinary user input across
  seven domains, including phrasing that superficially resembles an
  attack ("ignore the warning on the bottle") but isn't one.

## How the corpora were built

- **Attack corpus (`attacks.jsonl`)** is synthetic and curated by hand —
  no scraped or real attacker artifacts. Each entry is a minimal payload
  representative of one bypass technique, not a naturalistic prompt.
- **Benign corpora (`benign.jsonl`)** were written independently per
  domain (skincare product reviews, AI-literate users, developer chat,
  education, SQL assistant, support, pasted transcripts) *without*
  reference to the detector's pattern list — the goal is to catch false
  positives on real usage, not to write text that happens to avoid the
  patterns.

## Label semantics

| Field      | Meaning                                                              |
|------------|-----------------------------------------------------------------------|
| `text`     | The input string.                                                     |
| `label`    | `1` = injection attempt, `0` = benign.                                |
| `category` | (attacks only) Attack technique, e.g. `"instruction-override"`.       |
| `expected` | (attacks only) `"detect"` or `"known-miss"` — see below.              |
| `domain`   | (benign only) Source domain, e.g. `"developer-chat"`, `"support"`.    |

### `known-miss`

A small subset of `attacks.jsonl` is labeled `expected: "known-miss"`.
These document attack shapes the library's normalization/pattern layer
explicitly cannot catch by design — pure semantic paraphrase, leet
substitution, base64/ROT13 encoding, or tag-space-only concatenation
with no matching keyword. They're included for completeness and
transparency, not as a claim of detection. Exclude them from a
detection-rate metric unless you're specifically evaluating that gap.

## Publishing

This dataset is published at
[shanemhamilton/llm-prompt-guard-tuning-corpus](https://huggingface.co/datasets/shanemhamilton/llm-prompt-guard-tuning-corpus).

This directory only stages files locally — a publish or republish step
still requires a maintainer with a Hugging Face account and the `hf`
tool installed and authenticated (`hf auth login`; `huggingface-cli` is
deprecated). After running `npm run bench:export-hf`, republish the
staged files with:

```bash
hf upload shanemhamilton/llm-prompt-guard-tuning-corpus \
  benchmarks/hf/out/attacks.jsonl attacks.jsonl \
  --repo-type dataset

hf upload shanemhamilton/llm-prompt-guard-tuning-corpus \
  benchmarks/hf/out/benign.jsonl benign.jsonl \
  --repo-type dataset

hf upload shanemhamilton/llm-prompt-guard-tuning-corpus \
  benchmarks/hf/README.md README.md \
  --repo-type dataset
```

## What's not included

This is the **tuning set** — the corpus patterns are allowed to be
tuned against. It does not include the held-out evaluation set
(`benchmarks/heldout/`, see `benchmarks/HELDOUT.md`), which exists
specifically to measure the pattern set without ever being read while
writing it. Publishing the held-out set here would defeat its purpose.
