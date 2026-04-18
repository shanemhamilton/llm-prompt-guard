/**
 * llm-prompt-guard benchmark harness
 *
 * Measures false-positive rate (FPR) on benign inputs, false-negative rate
 * (FNR) on attack inputs, and per-input detection latency.
 *
 * Usage: `npm run bench` or `npx ts-node benchmarks/run.ts`.
 *
 * Exits 1 when FPR > 2% on the benign corpus OR any detect-expected attack
 * escapes detection (known-miss entries are excluded from this gate).
 *
 * Writes a machine-readable report to benchmarks/RESULTS.md.
 */
import { createGuard } from "../src";
import { readFileSync, writeFileSync } from "fs";
import { resolve } from "path";
import { performance } from "perf_hooks";

// ── Types ────────────────────────────────────────────────────────────

interface AttackEntry {
  payload: string;
  expected: "detect" | "known-miss";
}

interface AttackCorpus {
  version: number;
  description: string;
  categories: Record<string, AttackEntry[]>;
}

interface CategoryStats {
  detectExpected: number;
  truePositives: number;
  falseNegatives: number;
  knownMiss: number;
  knownMissUnexpectedlyDetected: number;
}

// ── Config ───────────────────────────────────────────────────────────

const BENCH_DIR = __dirname;
const BENIGN_PATH = resolve(BENCH_DIR, "corpora/benign.txt");
const ATTACKS_PATH = resolve(BENCH_DIR, "corpora/attacks.json");
const RESULTS_PATH = resolve(BENCH_DIR, "RESULTS.md");

const FPR_THRESHOLD_PERCENT = 2.0;

// ── Helpers ──────────────────────────────────────────────────────────

function loadBenign(): string[] {
  return readFileSync(BENIGN_PATH, "utf-8")
    .split("\n")
    .map((l) => l.trimEnd())
    .filter((l) => l.length > 0 && !l.startsWith("#"));
}

function loadAttacks(): AttackCorpus {
  return JSON.parse(readFileSync(ATTACKS_PATH, "utf-8")) as AttackCorpus;
}

function getPackageVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(resolve(BENCH_DIR, "../package.json"), "utf-8"));
    return pkg.version ?? "unknown";
  } catch {
    return "unknown";
  }
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
}

function fmt(n: number, digits = 3): string {
  return n.toFixed(digits);
}

function pct(num: number, denom: number): number {
  return denom === 0 ? 0 : (num / denom) * 100;
}

// ── Main ─────────────────────────────────────────────────────────────

function main(): number {
  const version = getPackageVersion();
  const benign = loadBenign();
  const attacks = loadAttacks();
  const guard = createGuard();

  // Warm-up so JIT cost doesn't skew latency.
  for (let i = 0; i < 200; i++) guard.detect("warmup " + i);

  // Benign pass
  const benignLatencies: number[] = [];
  let falsePositives = 0;
  const fpSamples: string[] = [];
  for (const line of benign) {
    const t0 = performance.now();
    const detected = guard.detect(line);
    benignLatencies.push(performance.now() - t0);
    if (detected) {
      falsePositives++;
      if (fpSamples.length < 10) fpSamples.push(line.substring(0, 100));
    }
  }

  // Attack pass
  const attackLatencies: number[] = [];
  const categoryStats: Record<string, CategoryStats> = {};
  const fnSamples: { category: string; payload: string }[] = [];
  let totalAttacks = 0;
  let totalDetectExpected = 0;
  let totalTP = 0;
  let totalFN = 0;
  let totalKnownMiss = 0;
  let totalKnownMissDetected = 0;

  for (const [category, entries] of Object.entries(attacks.categories)) {
    const s: CategoryStats = {
      detectExpected: 0,
      truePositives: 0,
      falseNegatives: 0,
      knownMiss: 0,
      knownMissUnexpectedlyDetected: 0,
    };
    for (const entry of entries) {
      totalAttacks++;
      const t0 = performance.now();
      const detected = guard.detect(entry.payload);
      attackLatencies.push(performance.now() - t0);
      if (entry.expected === "detect") {
        s.detectExpected++;
        totalDetectExpected++;
        if (detected) { s.truePositives++; totalTP++; }
        else {
          s.falseNegatives++;
          totalFN++;
          if (fnSamples.length < 20) fnSamples.push({ category, payload: entry.payload.substring(0, 120) });
        }
      } else {
        s.knownMiss++;
        totalKnownMiss++;
        if (detected) { s.knownMissUnexpectedlyDetected++; totalKnownMissDetected++; }
      }
    }
    categoryStats[category] = s;
  }

  const bSorted = [...benignLatencies].sort((a, b) => a - b);
  const aSorted = [...attackLatencies].sort((a, b) => a - b);
  const bP50 = percentile(bSorted, 50), bP95 = percentile(bSorted, 95), bP99 = percentile(bSorted, 99);
  const aP50 = percentile(aSorted, 50), aP95 = percentile(aSorted, 95), aP99 = percentile(aSorted, 99);
  const fprPercent = pct(falsePositives, benign.length);
  const detectionRate = totalDetectExpected === 0 ? 100 : pct(totalTP, totalDetectExpected);

  // Console report
  const out: string[] = [];
  const p = (s = ""): void => { out.push(s); console.log(s); };

  p(`=== llm-prompt-guard benchmark v${version} ===`);
  p();
  p(`Benign corpus: ${benign.length} inputs`);
  p(`- False positives: ${falsePositives} (${fmt(fprPercent, 2)}%)`);
  p(`- Latency p50/p95/p99: ${fmt(bP50)}ms / ${fmt(bP95)}ms / ${fmt(bP99)}ms`);
  p();
  p(`Attack corpus: ${totalAttacks} inputs (${totalKnownMiss} marked as known-miss)`);
  p(`- True positives: ${totalTP} / ${totalDetectExpected} (${fmt(detectionRate, 2)}%)`);
  p(`- False negatives: ${totalFN}  (excluding known-miss)`);
  p(`- Known misses:  ${totalKnownMiss} (documented limitations) — ${totalKnownMissDetected} unexpectedly detected`);
  p(`- Latency p50/p95/p99: ${fmt(aP50)}ms / ${fmt(aP95)}ms / ${fmt(aP99)}ms`);
  p();
  p("Per-category FNR:");
  for (const [cat, s] of Object.entries(categoryStats)) {
    const catFnr = pct(s.falseNegatives, s.detectExpected);
    p(`  ${cat.padEnd(26, " ")} ${s.falseNegatives}/${s.detectExpected} (${fmt(catFnr, 1)}%)`);
  }

  if (fnSamples.length > 0) {
    p();
    p("Unexpected false negatives:");
    for (const f of fnSamples) p(`  [${f.category}] ${f.payload}`);
  }
  if (fpSamples.length > 0) {
    p();
    p("Sample false positives:");
    for (const f of fpSamples) p(`  ${f}`);
  }

  // Write RESULTS.md
  const rows = Object.entries(categoryStats).map(([cat, s]) => {
    const catFnr = pct(s.falseNegatives, s.detectExpected);
    return `| ${cat} | ${s.truePositives} | ${s.detectExpected} | ${s.falseNegatives} | ${fmt(catFnr, 1)}% | ${s.knownMiss} |`;
  });
  const md = [
    `# llm-prompt-guard benchmark results`,
    ``,
    `Generated by \`benchmarks/run.ts\`. Regenerated on every run — do not edit by hand.`,
    ``,
    `- **Library version:** \`${version}\``,
    `- **Timestamp:** ${new Date().toISOString()}`,
    `- **Node:** \`${process.version}\``,
    `- **Platform:** \`${process.platform}/${process.arch}\``,
    ``,
    `## Benign corpus`,
    ``,
    `| Metric | Value |`,
    `| --- | --- |`,
    `| Inputs | ${benign.length} |`,
    `| False positives | ${falsePositives} |`,
    `| FPR | ${fmt(fprPercent, 2)}% |`,
    `| Latency p50 | ${fmt(bP50)} ms |`,
    `| Latency p95 | ${fmt(bP95)} ms |`,
    `| Latency p99 | ${fmt(bP99)} ms |`,
    ``,
    `## Attack corpus`,
    ``,
    `| Metric | Value |`,
    `| --- | --- |`,
    `| Total inputs | ${totalAttacks} |`,
    `| Detect-expected | ${totalDetectExpected} |`,
    `| True positives | ${totalTP} |`,
    `| False negatives | ${totalFN} |`,
    `| Detection rate | ${fmt(detectionRate, 2)}% |`,
    `| Known misses (documented) | ${totalKnownMiss} |`,
    `| Known misses unexpectedly detected | ${totalKnownMissDetected} |`,
    `| Latency p50 | ${fmt(aP50)} ms |`,
    `| Latency p95 | ${fmt(aP95)} ms |`,
    `| Latency p99 | ${fmt(aP99)} ms |`,
    ``,
    `## Per-category detection`,
    ``,
    `| Category | TP | detect-expected | FN | FNR | known-miss |`,
    `| --- | ---: | ---: | ---: | ---: | ---: |`,
    ...rows,
    ``,
    `## Thresholds`,
    ``,
    `- FPR > ${FPR_THRESHOLD_PERCENT}% → regression (exit 1)`,
    `- Any detect-expected attack escapes → regression (exit 1)`,
    ``,
    `## Interpretation`,
    ``,
    `- **FPR** measures how often benign traffic is flagged. Lower is better.`,
    `- **Detection rate** measures how many known attacks are caught. Higher is better.`,
    `- **Known-miss** entries document classes of attack the library explicitly`,
    `  cannot catch (pure semantic paraphrase, leet substitution, base64/ROT13`,
    `  encoding, tag-space-only concatenation). They are excluded from the`,
    `  detection-rate calculation and documented in \`benchmarks/README.md\`.`,
    ``,
  ].join("\n");
  writeFileSync(RESULTS_PATH, md, "utf-8");

  // Regression gate
  let exit = 0;
  if (fprPercent > FPR_THRESHOLD_PERCENT) {
    p();
    p(`FAIL: FPR ${fmt(fprPercent, 2)}% exceeds threshold ${FPR_THRESHOLD_PERCENT}%.`);
    exit = 1;
  }
  if (totalFN > 0) {
    p();
    p(`FAIL: ${totalFN} detect-expected attacks escaped detection. See list above.`);
    exit = 1;
  }
  if (exit === 0) {
    p();
    p("PASS: all thresholds met.");
  }
  return exit;
}

process.exit(main());
