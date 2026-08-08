/**
 * Public-dataset benchmark: deepset/prompt-injections.
 *
 * Unlike `run.ts` (curated in-house corpora), this harness scores
 * `detect()` against a third-party labeled dataset the library was NOT
 * tuned on, and reports standard precision / recall / F1. The dataset is
 * vendored (Apache-2.0, see benchmarks/README.md) so the run stays
 * zero-network and CI-stable.
 *
 * Dataset: 662 rows (263 injection / 399 benign), mixed English + German.
 * Two configurations are scored — core built-ins only, and core plus the
 * opt-in multilingual packs — because the German rows are exactly what
 * the multilingual packs exist for.
 *
 * Usage: `npm run bench:public` or `npx ts-node benchmarks/public.ts`.
 * Exits 1 when any REGRESSION_FLOORS entry is violated. Floors are set
 * below measured values with headroom — they catch regressions, they are
 * not aspirational targets.
 */
import { createGuard } from "../src";
import {
  spanish,
  french,
  german,
  portuguese,
} from "../src/patterns/multilingual";
import { readFileSync, writeFileSync } from "fs";
import { resolve } from "path";
import { performance } from "perf_hooks";

// ── Types ────────────────────────────────────────────────────────────

interface DatasetRow {
  text: string;
  /** 1 = injection, 0 = legitimate (deepset labeling). */
  label: 0 | 1;
  split: "train" | "test";
}

interface ConfigResult {
  name: string;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
  fprPercent: number;
  latencyP50Ms: number;
  latencyP95Ms: number;
  fpSamples: string[];
  fnSamples: string[];
}

// ── Config ───────────────────────────────────────────────────────────

const BENCH_DIR = __dirname;
const DATASET_PATH = resolve(
  BENCH_DIR,
  "corpora/deepset-prompt-injections.json"
);
const RESULTS_PATH = resolve(BENCH_DIR, "PUBLIC_RESULTS.md");
const WARMUP_ITERATIONS = 200;
const SAMPLE_LIMIT = 10;

/**
 * Regression floors for the core+multilingual configuration (the
 * recommended deployment for mixed-language traffic). Measured on
 * v2.0.2 + widened patterns: precision 100%, recall 11.0%, FPR 0.00%.
 * Floors sit below measured values with headroom so noise doesn't fail
 * CI but a real detection regression does.
 */
const REGRESSION_FLOORS = {
  minPrecisionPercent: 95,
  minRecallPercent: 8,
  maxFprPercent: 1,
};

// ── Helpers ──────────────────────────────────────────────────────────

const loadDataset = (): DatasetRow[] =>
  JSON.parse(readFileSync(DATASET_PATH, "utf-8")) as DatasetRow[];

const percentile = (sorted: number[], p: number): number =>
  sorted.length === 0
    ? 0
    : sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];

const fmt = (n: number, digits = 1): string => n.toFixed(digits);

function scoreConfig(
  name: string,
  guard: ReturnType<typeof createGuard>,
  rows: DatasetRow[]
): ConfigResult {
  for (let i = 0; i < WARMUP_ITERATIONS; i++) guard.detect("warmup " + i);

  let tp = 0,
    fp = 0,
    tn = 0,
    fn = 0;
  const fpSamples: string[] = [];
  const fnSamples: string[] = [];
  const latencies: number[] = [];

  for (const row of rows) {
    const t0 = performance.now();
    const detected = guard.detect(row.text);
    latencies.push(performance.now() - t0);

    if (row.label === 1) {
      if (detected) tp++;
      else {
        fn++;
        if (fnSamples.length < SAMPLE_LIMIT)
          fnSamples.push(row.text.substring(0, 100));
      }
    } else {
      if (detected) {
        fp++;
        if (fpSamples.length < SAMPLE_LIMIT)
          fpSamples.push(row.text.substring(0, 100));
      } else tn++;
    }
  }

  const precision = tp + fp === 0 ? 0 : (tp / (tp + fp)) * 100;
  const recall = tp + fn === 0 ? 0 : (tp / (tp + fn)) * 100;
  const f1 =
    precision + recall === 0
      ? 0
      : (2 * precision * recall) / (precision + recall);
  const fprPercent = fp + tn === 0 ? 0 : (fp / (fp + tn)) * 100;
  const sorted = [...latencies].sort((a, b) => a - b);

  return {
    name,
    tp,
    fp,
    tn,
    fn,
    precision,
    recall,
    f1,
    fprPercent,
    latencyP50Ms: percentile(sorted, 50),
    latencyP95Ms: percentile(sorted, 95),
    fpSamples,
    fnSamples,
  };
}

function resultTable(r: ConfigResult): string {
  return [
    `| Metric | Value |`,
    `| --- | --- |`,
    `| True positives | ${r.tp} |`,
    `| False positives | ${r.fp} |`,
    `| True negatives | ${r.tn} |`,
    `| False negatives | ${r.fn} |`,
    `| Precision | ${fmt(r.precision)}% |`,
    `| Recall | ${fmt(r.recall)}% |`,
    `| F1 | ${fmt(r.f1)} |`,
    `| FPR (over-defense) | ${fmt(r.fprPercent, 2)}% |`,
    `| Latency p50 | ${fmt(r.latencyP50Ms, 3)} ms |`,
    `| Latency p95 | ${fmt(r.latencyP95Ms, 3)} ms |`,
  ].join("\n");
}

function getPackageVersion(): string {
  try {
    const pkg = JSON.parse(
      readFileSync(resolve(BENCH_DIR, "../package.json"), "utf-8")
    );
    return pkg.version ?? "unknown";
  } catch {
    return "unknown";
  }
}

// ── Main ─────────────────────────────────────────────────────────────

function main(): number {
  const rows = loadDataset();
  const injectionCount = rows.filter((r) => r.label === 1).length;

  const core = scoreConfig("core", createGuard(), rows);
  const multilingual = scoreConfig(
    "core+multilingual",
    createGuard({
      extraPatterns: [...spanish, ...french, ...german, ...portuguese],
    }),
    rows
  );

  const p = (s = ""): void => console.log(s);
  p(`=== llm-prompt-guard public benchmark (deepset/prompt-injections) ===`);
  p();
  p(
    `Dataset: ${rows.length} rows (${injectionCount} injection / ${
      rows.length - injectionCount
    } benign), EN+DE`
  );
  for (const r of [core, multilingual]) {
    p();
    p(`[${r.name}]`);
    p(
      `  precision ${fmt(r.precision)}%  recall ${fmt(r.recall)}%  F1 ${fmt(
        r.f1
      )}  FPR ${fmt(r.fprPercent, 2)}%`
    );
    p(
      `  TP ${r.tp}  FP ${r.fp}  TN ${r.tn}  FN ${r.fn}  latency p50 ${fmt(
        r.latencyP50Ms,
        3
      )}ms p95 ${fmt(r.latencyP95Ms, 3)}ms`
    );
  }

  // Regression gate on the recommended configuration.
  const gated = multilingual;
  const failures: string[] = [];
  if (gated.precision < REGRESSION_FLOORS.minPrecisionPercent)
    failures.push(
      `precision ${fmt(gated.precision)}% < floor ${REGRESSION_FLOORS.minPrecisionPercent}%`
    );
  if (gated.recall < REGRESSION_FLOORS.minRecallPercent)
    failures.push(
      `recall ${fmt(gated.recall)}% < floor ${REGRESSION_FLOORS.minRecallPercent}%`
    );
  if (gated.fprPercent > REGRESSION_FLOORS.maxFprPercent)
    failures.push(
      `FPR ${fmt(gated.fprPercent, 2)}% > ceiling ${REGRESSION_FLOORS.maxFprPercent}%`
    );

  p();
  if (failures.length > 0) {
    p(`FAIL (core+multilingual): ${failures.join("; ")}`);
  } else {
    p("PASS: all regression floors met (core+multilingual).");
  }

  const md = `# Public benchmark: deepset/prompt-injections

Generated by \`benchmarks/public.ts\`. Regenerated on every run — do not edit by hand.

- **Library version:** \`${getPackageVersion()}\`
- **Timestamp:** ${new Date().toISOString()}
- **Node:** \`${process.version}\`
- **Dataset:** [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections)
  (Apache-2.0, vendored at \`corpora/deepset-prompt-injections.json\`) —
  ${rows.length} rows: ${injectionCount} injection / ${
    rows.length - injectionCount
  } benign, mixed English + German.

The pattern set was originally developed without this dataset; after the
first scored run, a small number of patterns were widened based on its
misses (article slots, synonym lists, German noun/word-order variants),
so treat these numbers as in-domain, not held-out. They are published
as-is, including the low recall: this corpus is dominated by task-drift
attacks with no injection vocabulary, which regex-based detection
structurally cannot catch. That residual is the documented job of
model-based layers above this one — a Layer-1 triage filter is scored
on precision and latency, not total recall.

## Configuration: core built-ins

${resultTable(core)}

## Configuration: core + multilingual packs (recommended for mixed-language traffic)

${resultTable(multilingual)}

### Sample false negatives (first ${SAMPLE_LIMIT}, core+multilingual)

${multilingual.fnSamples.map((s) => `- \`${s.replace(/`/g, "'")}\``).join("\n")}

### Sample false positives (first ${SAMPLE_LIMIT}, core+multilingual)

${
  multilingual.fpSamples.length > 0
    ? multilingual.fpSamples.map((s) => `- \`${s.replace(/`/g, "'")}\``).join("\n")
    : "_None._"
}

## Regression floors (gated on core+multilingual)

- Precision ≥ ${REGRESSION_FLOORS.minPrecisionPercent}%
- Recall ≥ ${REGRESSION_FLOORS.minRecallPercent}%
- FPR ≤ ${REGRESSION_FLOORS.maxFprPercent}%

Floors sit below measured values with headroom; they catch regressions,
they are not targets.
`;
  writeFileSync(RESULTS_PATH, md, "utf-8");

  return failures.length > 0 ? 1 : 0;
}

process.exit(main());
