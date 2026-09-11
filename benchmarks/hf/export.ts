/**
 * Exports llm-prompt-guard's tuning corpora to Hugging Face
 * `datasets`-compatible JSONL, staged under `benchmarks/hf/out/` for
 * manual review. Writes files only — never touches the network, never
 * runs `huggingface-cli`. See `benchmarks/hf/README.md` for the
 * publishing command.
 *
 * Usage: `npm run bench:export-hf` or `npx ts-node benchmarks/hf/export.ts`.
 */
import { readFileSync, writeFileSync, mkdirSync, readdirSync } from "fs";
import { resolve } from "path";

const CORPORA_DIR = resolve(__dirname, "../corpora");
const OUT_DIR = resolve(__dirname, "out");

interface AttackEntry {
  payload: string;
  expected: "detect" | "known-miss";
}
interface AttackCorpus {
  categories: Record<string, AttackEntry[]>;
}

interface AttackRow {
  text: string;
  label: 1;
  category: string;
  expected: "detect" | "known-miss";
}
interface BenignRow {
  text: string;
  label: 0;
  domain: string;
}

/** Lines in these plain-text corpora use a literal two-char `\n` to
 * represent an embedded newline (stack traces, config snippets, chat
 * logs flattened to one line). Unescape it to a real newline so the
 * exported JSONL carries the original multi-line text. */
function unescapeLiteralNewlines(line: string): string {
  return line.replace(/\\n/g, "\n");
}

function parseBenignFile(path: string, domain: string): BenignRow[] {
  const raw = readFileSync(path, "utf8");
  return raw
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0 && !l.startsWith("#"))
    .map((l) => ({ text: unescapeLiteralNewlines(l), label: 0, domain }));
}

function buildAttackRows(): AttackRow[] {
  const corpus: AttackCorpus = JSON.parse(readFileSync(resolve(CORPORA_DIR, "attacks.json"), "utf8"));
  const rows: AttackRow[] = [];
  for (const [category, entries] of Object.entries(corpus.categories)) {
    for (const entry of entries) {
      rows.push({ text: entry.payload, label: 1, category, expected: entry.expected });
    }
  }
  return rows;
}

function buildBenignRows(): BenignRow[] {
  const rows = parseBenignFile(resolve(CORPORA_DIR, "benign.txt"), "general");
  const benignDir = resolve(CORPORA_DIR, "benign");
  for (const file of readdirSync(benignDir).sort()) {
    if (!file.endsWith(".txt")) continue;
    const domain = file.replace(/\.txt$/, "");
    rows.push(...parseBenignFile(resolve(benignDir, file), domain));
  }
  return rows;
}

function writeJsonl(path: string, rows: unknown[]): void {
  const body = rows.map((r) => JSON.stringify(r)).join("\n") + "\n";
  writeFileSync(path, body, "utf8");
}

function main(): void {
  mkdirSync(OUT_DIR, { recursive: true });

  const attackRows = buildAttackRows();
  const benignRows = buildBenignRows();

  writeJsonl(resolve(OUT_DIR, "attacks.jsonl"), attackRows);
  writeJsonl(resolve(OUT_DIR, "benign.jsonl"), benignRows);

  console.log(`Wrote ${attackRows.length} attack rows -> benchmarks/hf/out/attacks.jsonl`);
  console.log(`Wrote ${benignRows.length} benign rows -> benchmarks/hf/out/benign.jsonl`);
}

main();
