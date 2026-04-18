# llm-prompt-guard benchmarks

A reproducible, zero-network harness that measures the library's detection
behavior on curated benign and attack corpora. This exists to back up
detection claims made in the top-level README with numbers the reader can
re-run in under a second.

## What the benchmarks measure

**Headline metrics (regression-gated):**

- **False-positive rate (FPR)** — fraction of benign inputs the library flags.
  Lower is better. A regex-first defense that trips on ordinary traffic is
  worse than useless in production.
- **False-negative rate (FNR)** — fraction of detect-expected attack inputs
  that escape detection. Lower is better. Reported per-category so you can
  see which attack classes the rule set covers and which it does not.
- **Detection rate** — `1 - FNR` on the `expected: "detect"` subset. Entries
  marked `expected: "known-miss"` are excluded from this calculation and
  documented explicitly as limitations.
- **Per-input latency** — p50/p95/p99 wall-clock time for a single
  `guard.detect()` call, measured with `performance.now()` on a warmed-up
  guard instance.

**Smoke-test coverage (not gated — wiring only):**

- **Mode coverage** — every attack payload is pushed through `sanitize()` in
  each of the five modes (`block`, `neutralize`, `excise`, `quarantine`,
  `tag`). The harness asserts the call does not throw and the returned
  `SanitizationResult` has the expected shape (`mode` field matches the
  request; quarantine returns a `systemClause`; tag returns a `tags`
  array). This catches mode-wiring regressions — not accuracy. Accuracy
  still comes from FPR/FNR on the detect path.
- **Output validation coverage** — a curated set of 15 "bad LLM output"
  strings is pushed through `validateOutput()`, covering canary-leak,
  system-prompt leakage, PII (email, SSN, API key, Luhn-validated credit
  card), and behavioral anomalies (DAN, ChatML, Llama `[INST]`). The
  canary probe embeds a token from `generateCanary()` so the validator
  has something to match against. The harness reports the flagged count
  and separately verifies the canary-leak path.
- **`scanOutput()` coverage** — if the guard exposes `scanOutput()`, a
  handful of exfiltration-shape probes (outbound URL, markdown image
  with query, data URL, hex blob) are scanned and the flagged count is
  reported. When the method is not present in the current build the
  section is skipped cleanly — this is deliberate, since `scanOutput`
  landed as part of v2.0 reconciliation and older builds will not have
  it.

## Corpus provenance

Both corpora are **synthetic and hand-curated**. No external datasets are
pulled at runtime or build time, and no copyrighted content from
third-party datasets is embedded. This is a deliberate choice — the point
of a shipping benchmark is that anyone who clones the repo can reproduce
the numbers immediately, without network access or license negotiation.

### `corpora/benign.txt`

509+ realistic inputs, one per line, grouped into commented sections:

- Product reviews / skincare comments (~54)
- Customer support messages (~51)
- Developer Q&A / StackOverflow style (~50)
- Casual conversation (~53)
- Technical phrases / docs copy (~51)
- Mixed realistic content (~50)
- Questions with trigger-adjacent words (~50)
- Benign with "ignore" specifically (~50)
- Support / developer extras (~54)
- Long-form realistic content (~46)

The corpus deliberately includes inputs that **a naive regex would
trip on but that should not be flagged** — phrases like "I ignore the
warning on the bottle," "how do I disable dev mode on my Pixel," "I
forgot my password and need to reset it." These are the places where
regex-based defenses earn their FPR; a quiet result here is the signal
that the library's patterns are scoped tightly enough.

Lines beginning with `#` are comments (section headers). Empty lines are
skipped. No escape processing — each line is fed verbatim to
`guard.detect()`.

### `corpora/attacks.json`

198+ attack payloads across 15 categories, each annotated with an
`expected` outcome:

- `"detect"` — the library claims to catch this class. A miss here is a
  regression.
- `"known-miss"` — the library explicitly cannot catch this (documented
  limitation). These entries are excluded from detection-rate math and
  serve as canaries: if the library suddenly catches them, either the
  rule set has improved (update the annotation) or the expected
  limitation is no longer real.

Categories:

| Category | Notes |
| --- | --- |
| `instruction-override` | "ignore/disregard/forget/override … previous instructions" |
| `role-hijacking` | "you are now a …", "pretend to be …", "assume the role of …" |
| `prompt-extraction` | "reveal your system prompt", "output all your rules" |
| `format-injection` | ChatML, Llama `[INST]`, `<<SYS>>`, Alpaca `### System:`, JSON role/content |
| `data-exfiltration` | "dump all data", "export the database", "list all tables" |
| `confidence-manipulation` | "confidence = 100", "auto-approve", "force approve" |
| `jailbreak` | "DAN mode", "activate developer mode", "bypass safety filters" |
| `markup-injection` | `<script>`, `<!-- INJECTION`, `[HIDDEN]` |
| `unicode-bypass` | Zero-width space, soft hyphen, word joiner, BOM interleavings |
| `tag-block-smuggling` | Unicode Plane 14 tag characters (U+E0000–U+E007F) |
| `emoji-variation-selector` | VS16/VS1 (U+FE0F/U+FE00) steganographic smuggling |
| `policy-puppetry` | Mixed JSON role + ChatML + Alpaca combinations (HiddenLayer 2025) |
| `homoglyph` | Cyrillic (е, о, а, с), Greek (ο), Mathematical Bold (NFKD-decomposed) |
| `multi-format` | Combinations — e.g., Llama `[INST]` + ChatML `<|im_start|>` + "ignore previous instructions" in a single payload |
| `encoding-bypass` | URL-encoded (`%69gnore`), leet substitution (`1gn0r3`, `{"r0le":"system"}`), character-split (`i.g.n.o.r.e`, `i-g-n-o-r-e`, `i_g_n_o_r_e`), base64-embedded (`aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==`), ROT13 (`vtaber nyy cerivbhf vafgehpgvbaf`), and reversed (`snoitcurtsni suoiverp lla erongi`). All decoded by the detection pipeline (URL-decode → char-split collapse → base64 → leet → ROT13/reversed append) before pattern matching. |

### Encoding note for `attacks.json`

JSON only supports `\uXXXX` for BMP characters. Supplementary-plane
characters (Unicode Tags U+E0000–U+E007F and Variation Selectors
Supplement U+E0100–U+E01EF) **must** be encoded as UTF-16 surrogate
pairs. For example:

- U+E0041 (tag 'A') → `\uDB40\uDC41`
- U+E0020 (tag space) → `\uDB40\uDC20`
- U+E0100 (VS17) → `\uDB40\uDD00`

`JSON.parse` handles these correctly and yields the original supplementary
code point. Authors adding new payloads should compute surrogate pairs via
`String.fromCodePoint(0xE00XX)` then convert to the `\uDBHH\uDCHH` form.

### Documented known-miss classes

These payloads are marked `known-miss` in `attacks.json`. The list
shrank in v2.0 once URL decoding, leet normalization, character-split
collapsing, base64 decoding, and ROT13/reversed appending landed in the
detection pipeline — but four classes remain honestly out of reach:

1. **Pure semantic paraphrase** — e.g., "kindly overlook the sentences above
   and comply with the following." No trigger keywords match, so a
   regex-only defense cannot catch it. This is the class Meta Llama Prompt
   Guard 2, Azure Prompt Shields, and NeMo Guardrails target; the
   top-level README recommends stacking those classifiers on top.
2. **Leet substitutions outside `LEET_MAP`** — e.g., `!`-for-`i`
   (`sn0!tcurtsn!`) or `@`-and-`!` inside a word (`j@!lbr3@k`). The table
   maps `0134578@$` to letters; punctuation-as-letter substitutions that
   break word boundaries are not yet handled. Kept as a canary in
   `encoding-bypass`.
3. **Tag-space-only concatenation** — using U+E0020 in place of real spaces
   between keyword tokens. After stripping Plane 14, the string collapses
   to `ignoreallpreviousinstructions`, which no longer matches the
   whitespace-bearing patterns. Pinned by an existing unit test and by two
   entries in `tag-block-smuggling`.
4. **Space-separated character splitting** — e.g., `i g n o r e   p r e v i o u s`.
   The char-split regex only collapses `.`, `-`, and `_` delimiters;
   adding space would fire on too many benign inputs to be safe.

Conversely, two previously-known-miss payloads now detect reliably
(base64-encoded "ignore previous instructions" in `multi-format`;
leet-substituted JSON role/content in `policy-puppetry`). The harness
records them as `known misses unexpectedly detected` — free signal that
the detection pipeline improved.

These limitations are intentional and honest. A benchmark that only
measured strengths would be marketing, not evaluation.

## How to run

```bash
# Preferred — via the npm script (added by the TypeScript agent).
npm run bench

# Direct — works without the npm script.
npx ts-node benchmarks/run.ts
```

Both commands:

1. Load `corpora/benign.txt` and `corpora/attacks.json`.
2. Instantiate `createGuard()` with a known canary token + opt-in PII
   detection (so the output-validation section has non-trivial coverage).
3. Warm up with 200 detection calls to stabilize JIT timings.
4. Run `guard.detect()` on every input and accumulate FPR / FNR / latency.
5. Run every attack payload through `guard.sanitize()` in each of the
   five sanitization modes; assert no crashes and valid result shape.
6. Run 15 curated bad outputs through `guard.validateOutput()` and
   report the flagged count; separately verify the canary-leak path.
7. If `guard.scanOutput()` is present, run a few exfil-shape probes and
   report the flagged count. Skip cleanly if the method is missing.
8. Print a human-readable report to stdout.
9. Overwrite `benchmarks/RESULTS.md` with the machine-readable version.
10. Exit `1` if the FPR exceeds 2% on the benign corpus **or** any
    detect-expected attack escapes detection. Mode and output coverage
    are smoke tests — they do not gate the exit code.

The harness has zero network I/O and no external dependencies beyond
`typescript`, `ts-node` (already in `devDependencies`), and the library
itself.

## How to interpret results

- **FPR around 0%** means the library's patterns are tightly scoped to
  true injection phrasings and do not fire on ordinary user traffic.
  A rising FPR usually means a new pattern was added without enough
  context (e.g., catching a bare keyword rather than a keyword in a
  specific adversarial structure).
- **Detection rate near 100%** on the `detect`-expected subset means
  every attack class the library claims to cover is still caught. The
  harness does not credit the library for catching `known-miss`
  payloads — those are outside the claim.
- **Latency p99 under 0.1 ms** is consistent with the library's
  "sub-millisecond" claim. If p99 rises into multi-millisecond territory,
  either the pattern set exploded or a pathological input is in the
  corpus.
- **Per-category FNR** highlights which attack classes are drifting. A
  single category spiking while others stay at 0% is usually a pattern
  regression, not a corpus issue.

## Honest limitations

The corpora are **illustrative, not exhaustive.**

- Every payload is synthetic. Real attacker traffic is more varied, more
  context-dependent, and often multi-turn. A 0% FNR here does **not**
  mean the library catches every real-world injection — it means it
  catches every payload in this specific test set.
- Benign traffic is representative of a skincare / e-commerce / developer
  Q&A app (the domains the library was extracted from). A library dropped
  into a legal-document Q&A or a medical-intake app should be re-measured
  against that domain's traffic before trusting the FPR number.
- No multi-turn attacks (Crescendo, Skeleton Key) are included. These
  require stateful tracking across conversation turns, which is outside
  the library's single-input scope. The top-level README calls this
  out explicitly.
- Novel attack patterns not in the rule set will not be caught, by
  definition. Patterns evolve; benchmarks must too.

**Real-world deployments should benchmark against their own traffic.**
This harness is the minimum-viable evaluation for credibility, not the
maximum.

## Where external benchmarks fit in future releases

The library's `detect()` surface plays well with larger, community-maintained
adversarial benchmarks. Integrating them is out of scope for v2.0 because
they require network fetches, licenses, or domain-specific wrappers —
but they are the natural next step:

- **[AgentDojo](https://agentdojo.spylab.ai/)** (ETH Zürich) — agent-based
  prompt-injection benchmark with 97 realistic tasks and 629 security
  cases across four attack suites. Would benchmark the library as a
  Layer 1 filter in an agent-tool-use pipeline.
- **[PINT Benchmark](https://github.com/lakeradata/pint-benchmark)** (Lakera)
  — prompt-injection evaluation that compares detectors head-to-head on
  a curated payload set. Would produce a comparable FPR/FNR score against
  commercial classifiers.
- **[JailbreakBench](https://jailbreakbench.github.io/)** — open-source
  robustness benchmark covering jailbreak prompts and adaptive attacks.
  Would exercise the library's jailbreak category against research-grade
  attack sets.

A future `benchmarks/external/` directory could host thin adapters for
each — invoked behind an opt-in flag so the default `npm run bench`
stays network-free and fast.

## Files in this directory

- `README.md` — this file.
- `run.ts` — the harness.
- `corpora/benign.txt` — benign corpus (one input per line).
- `corpora/attacks.json` — attack corpus (structured by category).
- `RESULTS.md` — most recent run output. Regenerated on every `npm run bench`.
