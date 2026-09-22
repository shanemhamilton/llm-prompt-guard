/**
 * Held-out benchmark: BIPIA (microsoft/BIPIA), never used to write or widen
 * a pattern. See ../HELDOUT.md for the no-tuning rule this file enforces
 * (checkOverlap below is part of that enforcement).
 *
 * This is a REPORT, not a gate: it intentionally never calls process.exit(1)
 * on a metric. Gating a Layer-1 regex triage filter on a held-out recall
 * number would create pressure to tune to it, which defeats the point of
 * holding it out. benchmarks/public.ts already gates the in-domain
 * regression floors; this script only measures and writes results.
 *
 * Usage: `npm run bench:heldout` or `npx ts-node benchmarks/heldout/run.ts`.
 */
import { detect, assess } from "../../src/index";
import { readFileSync, writeFileSync } from "fs";
import { resolve } from "path";
import { performance } from "perf_hooks";

// ── Types ────────────────────────────────────────────────────────────

interface DatasetRow {
  text: string;
  /** 1 = injected attack, 0 = benign. */
  label: 0 | 1;
  /** "<task>" for benign rows, "<task>/<attack-category>" for injected rows. */
  source: string;
}

interface DatasetFile {
  _meta: Record<string, unknown>;
  rows: DatasetRow[];
}

// ── Config ───────────────────────────────────────────────────────────

const BENCH_DIR = __dirname;
const DATASET_PATH = resolve(BENCH_DIR, "bipia.json");
const ATTACKS_CORPUS_PATH = resolve(BENCH_DIR, "../corpora/attacks.json");
const DEEPSET_PATH = resolve(BENCH_DIR, "../corpora/deepset-prompt-injections.json");
const RESULTS_PATH = resolve(BENCH_DIR, "HELDOUT_RESULTS.md");
const FILTERED_ROWS_PATH = resolve(BENCH_DIR, "heldout_rows.filtered.json");
const COMPARISON_MARKER = "<!-- COMPARISON_PLACEHOLDER -->";
const WARMUP_ITERATIONS = 200;
const SAMPLE_LIMIT = 10;

// ── Overlap check (no-tuning enforcement) ───────────────────────────

const normalize = (s: string): string => s.trim().toLowerCase().replace(/\s+/g, " ");

/** Every attack payload from corpora/attacks.json, and every text from the
 * deepset public benchmark — the two corpora patterns are allowed to be
 * tuned against. Any held-out row whose normalized text exact-matches one
 * of these is dropped: it would no longer be measuring something unseen. */
function loadUsedTexts(): Set<string> {
  const used = new Set<string>();

  const attacksCorpus = JSON.parse(readFileSync(ATTACKS_CORPUS_PATH, "utf-8")) as {
    categories: Record<string, { payload: string }[]>;
  };
  for (const entries of Object.values(attacksCorpus.categories)) {
    for (const entry of entries) used.add(normalize(entry.payload));
  }

  const deepset = JSON.parse(readFileSync(DEEPSET_PATH, "utf-8")) as { text: string }[];
  for (const row of deepset) used.add(normalize(row.text));

  return used;
}

function checkOverlap(rows: DatasetRow[]): { kept: DatasetRow[]; removedCount: number } {
  const used = loadUsedTexts();
  const kept: DatasetRow[] = [];
  let removedCount = 0;
  for (const row of rows) {
    if (used.has(normalize(row.text))) removedCount++;
    else kept.push(row);
  }
  return { kept, removedCount };
}

// ── Metrics ──────────────────────────────────────────────────────────

interface Result {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
  fprPercent: number;
  latencyMedianUs: number;
  latencyP99Us: number;
  fpSamples: string[];
  fnSamples: string[];
  recallBySource: { source: string; total: number; detected: number; recallPercent: number }[];
}

const percentile = (sorted: number[], p: number): number =>
  sorted.length === 0
    ? 0
    : sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];

const fmt = (n: number, digits = 1): string => n.toFixed(digits);

function score(rows: DatasetRow[]): Result {
  for (let i = 0; i < WARMUP_ITERATIONS; i++) detect("warmup " + i);

  let tp = 0,
    fp = 0,
    tn = 0,
    fn = 0;
  const fpSamples: string[] = [];
  const fnSamples: string[] = [];
  const latenciesUs: number[] = [];
  const bySource = new Map<string, { total: number; detected: number }>();

  for (const row of rows) {
    const t0 = performance.now();
    const detected = detect(row.text);
    // assess() is the fuller scoring path a real deployment calls; exercise
    // it too so latency/behavior claims cover both public one-shot APIs.
    assess(row.text);
    latenciesUs.push((performance.now() - t0) * 1000);

    if (row.label === 1) {
      if (detected) tp++;
      else {
        fn++;
        if (fnSamples.length < SAMPLE_LIMIT) fnSamples.push(row.text.substring(0, 100));
      }
      const bucket = bySource.get(row.source) ?? { total: 0, detected: 0 };
      bucket.total++;
      if (detected) bucket.detected++;
      bySource.set(row.source, bucket);
    } else {
      if (detected) {
        fp++;
        if (fpSamples.length < SAMPLE_LIMIT) fpSamples.push(row.text.substring(0, 100));
      } else tn++;
    }
  }

  const precision = tp + fp === 0 ? 0 : (tp / (tp + fp)) * 100;
  const recall = tp + fn === 0 ? 0 : (tp / (tp + fn)) * 100;
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  const fprPercent = fp + tn === 0 ? 0 : (fp / (fp + tn)) * 100;
  const sorted = [...latenciesUs].sort((a, b) => a - b);

  const recallBySource = [...bySource.entries()]
    .map(([source, { total, detected }]) => ({
      source,
      total,
      detected,
      recallPercent: total === 0 ? 0 : (detected / total) * 100,
    }))
    .sort((a, b) => a.source.localeCompare(b.source));

  return {
    tp,
    fp,
    tn,
    fn,
    precision,
    recall,
    f1,
    fprPercent,
    latencyMedianUs: percentile(sorted, 50),
    latencyP99Us: percentile(sorted, 99),
    fpSamples,
    fnSamples,
    recallBySource,
  };
}

function getPackageVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(resolve(BENCH_DIR, "../../package.json"), "utf-8"));
    return pkg.version ?? "unknown";
  } catch {
    return "unknown";
  }
}

// ── Main ─────────────────────────────────────────────────────────────

function main(): void {
  const dataset = JSON.parse(readFileSync(DATASET_PATH, "utf-8")) as DatasetFile;
  const { kept: rows, removedCount } = checkOverlap(dataset.rows);
  writeFileSync(FILTERED_ROWS_PATH, JSON.stringify(rows, null, 2), "utf-8");

  const injectionCount = rows.filter((r) => r.label === 1).length;
  const r = score(rows);

  const p = (s = ""): void => console.log(s);
  p(`=== llm-prompt-guard held-out benchmark (BIPIA) ===`);
  p();
  p(`Overlap check: ${removedCount} row(s) removed (matched corpora/attacks.json or deepset).`);
  p(
    `Dataset: ${rows.length} rows scored (${injectionCount} injected / ${
      rows.length - injectionCount
    } benign)`
  );
  p();
  p(
    `precision ${fmt(r.precision)}%  recall ${fmt(r.recall)}%  F1 ${fmt(r.f1)}  FPR ${fmt(
      r.fprPercent,
      2
    )}%`
  );
  p(
    `TP ${r.tp}  FP ${r.fp}  TN ${r.tn}  FN ${r.fn}  latency median ${fmt(
      r.latencyMedianUs,
      1
    )}us  p99 ${fmt(r.latencyP99Us, 1)}us`
  );
  p();
  p("This is a report — it never exits non-zero on a metric (see file header).");

  const md = `# Held-out benchmark: BIPIA

Generated by \`benchmarks/heldout/run.ts\`. Regenerated on every run — do not
edit by hand. This is a report, not a gate: see the no-tuning rule in
\`benchmarks/HELDOUT.md\`.

- **Library version:** \`${getPackageVersion()}\`
- **Timestamp:** ${new Date().toISOString()}
- **Node:** \`${process.version}\`
- **Dataset:** [BIPIA](https://github.com/microsoft/BIPIA) (MIT, vendored at
  \`benchmarks/heldout/bipia.json\`, upstream commit \`${dataset._meta.upstream_commit}\`) —
  benign contexts from \`benchmark/{email,table,code}/test.jsonl\`, attacks
  from \`benchmark/text_attack_test.json\`, inserted via \`insert_end\`
  (seed ${dataset._meta.seed}). ${dataset._meta.row_count} rows built,
  ${removedCount} removed by the overlap check below, ${rows.length} scored.

## Overlap check

\`checkOverlap()\` exact-matches normalized (trimmed, lowercased,
whitespace-collapsed) row text against every payload in
\`corpora/attacks.json\` and every text in \`corpora/deepset-prompt-injections.json\`
— the two corpora this library's patterns are allowed to be tuned against.
**${removedCount} row(s) removed.**

## Results

| Metric | Value |
| --- | --- |
| True positives | ${r.tp} |
| False positives | ${r.fp} |
| True negatives | ${r.tn} |
| False negatives | ${r.fn} |
| Precision | ${fmt(r.precision)}% |
| Recall | ${fmt(r.recall)}% |
| F1 | ${fmt(r.f1)} |
| FPR (over-defense) | ${fmt(r.fprPercent, 2)}% |
| Latency median | ${fmt(r.latencyMedianUs, 1)} µs |
| Latency p99 | ${fmt(r.latencyP99Us, 1)} µs |

This library is a regex-based Layer-1 triage filter: recall on task-drift
attacks with no injection vocabulary (which is most of what BIPIA's
\`insert_end\` attacks are — full natural-language task hijacks with no
keyword signature) is expected to be low, structurally. The recall/latency
trade-off is the point: this filter is meant to sit in front of a
model-based layer, not replace it.

### Recall by source (attack rows only)

| Source | Detected / Total | Recall |
| --- | --- | --- |
${r.recallBySource
  .map((s) => `| ${s.source} | ${s.detected} / ${s.total} | ${fmt(s.recallPercent)}% |`)
  .join("\n")}

### Sample false negatives (first ${SAMPLE_LIMIT})

${r.fnSamples.map((s) => `- \`${s.replace(/`/g, "'")}\``).join("\n") || "_None._"}

### Sample false positives (first ${SAMPLE_LIMIT})

${r.fpSamples.length > 0 ? r.fpSamples.map((s) => `- \`${s.replace(/`/g, "'")}\``).join("\n") : "_None._"}

## Comparison classifier

${COMPARISON_MARKER}
_Not yet run. See \`benchmarks/heldout/compare.py\` for the command._
`;
  writeFileSync(RESULTS_PATH, md, "utf-8");
}

main();
