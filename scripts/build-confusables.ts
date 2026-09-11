/**
 * Generator: downloads Unicode's confusables.txt and emits
 * src/data/confusables.ts — a vendored, generated confusable → ASCII map.
 *
 * Run with: npm run build:confusables (ts-node)
 *
 * Keeps an entry only when:
 *  - the source is a single code point (confusables.txt always is, but we
 *    guard anyway in case a future revision adds multi-codepoint sources)
 *  - the source is non-ASCII
 *  - the target, after NFKD + stripping combining marks, is exactly one
 *    ASCII alphanumeric character
 *  - the source does NOT already fold to that same ASCII char via NFKD +
 *    strip-marks (that case is redundant with guard.ts's existing NFKD step)
 */
import { writeFileSync } from "node:fs";
import { join } from "node:path";

const CONFUSABLES_URL = "https://www.unicode.org/Public/security/latest/confusables.txt";
const LICENSE_URL = "https://www.unicode.org/license.txt";
const OUTPUT_PATH = join(__dirname, "..", "src", "data", "confusables.ts");
const MAX_FILE_BYTES = 80 * 1024;
const MATH_ALPHANUMERIC_START = 0x1d400;
const MATH_ALPHANUMERIC_END = 0x1d7ff;

const ASCII_ALNUM = /^[A-Za-z0-9]$/;
const COMBINING_MARKS = /\p{M}/gu;

function stripToBase(ch: string): string {
  return ch.normalize("NFKD").replace(COMBINING_MARKS, "");
}

function parseConfusables(text: string): Map<number, string> {
  const entries = new Map<number, string>();
  for (const line of text.split("\n")) {
    const withoutComment = line.split("#")[0];
    if (!withoutComment.includes(";")) continue;
    const [sourceField, targetField] = withoutComment.split(";");
    const sourceHex = sourceField.trim().split(/\s+/).filter(Boolean);
    const targetHex = targetField.trim().split(/\s+/).filter(Boolean);
    if (sourceHex.length !== 1) continue; // source must be a single code point

    const sourceCp = parseInt(sourceHex[0], 16);
    if (sourceCp <= 0x7f) continue; // source must be non-ASCII

    const targetChar = targetHex.map((h) => String.fromCodePoint(parseInt(h, 16))).join("");
    const targetBase = stripToBase(targetChar);
    if (![...targetBase].length || [...targetBase].length !== 1 || !ASCII_ALNUM.test(targetBase)) {
      continue;
    }

    const sourceChar = String.fromCodePoint(sourceCp);
    if (stripToBase(sourceChar) === targetBase) continue; // redundant with NFKD alone

    if (!entries.has(sourceCp)) entries.set(sourceCp, targetBase);
  }
  return entries;
}

function buildRanges(codePoints: number[]): [number, number][] {
  const sorted = [...codePoints].sort((a, b) => a - b);
  const ranges: [number, number][] = [];
  for (const cp of sorted) {
    const last = ranges[ranges.length - 1];
    if (last && cp === last[1] + 1) {
      last[1] = cp;
    } else {
      ranges.push([cp, cp]);
    }
  }
  return ranges;
}

function hexEscape(cp: number): string {
  return cp > 0xffff
    ? `\\u{${cp.toString(16)}}`
    : `\\u${cp.toString(16).padStart(4, "0")}`;
}

function buildCharClassSource(codePoints: number[]): string {
  const ranges = buildRanges(codePoints);
  return ranges
    .map(([start, end]) => (start === end ? hexEscape(start) : `${hexEscape(start)}-${hexEscape(end)}`))
    .join("");
}

function buildPairsLiteral(entries: Map<number, string>): string {
  // Alternating source/target characters. `for...of` over a string walks by
  // code point (handles astral source chars correctly), so the same pairing
  // survives round-tripping through the emitted string literal.
  const sortedKeys = [...entries.keys()].sort((a, b) => a - b);
  let pairs = "";
  for (const cp of sortedKeys) {
    pairs += String.fromCodePoint(cp) + entries.get(cp);
  }
  return pairs;
}

async function main(): Promise<void> {
  let confusablesText: string;
  let licenseText: string;
  try {
    const [confusablesRes, licenseRes] = await Promise.all([
      fetch(CONFUSABLES_URL),
      fetch(LICENSE_URL),
    ]);
    if (!confusablesRes.ok) throw new Error(`HTTP ${confusablesRes.status}`);
    if (!licenseRes.ok) throw new Error(`HTTP ${licenseRes.status}`);
    confusablesText = await confusablesRes.text();
    licenseText = await licenseRes.text();
  } catch (err) {
    console.error(`Could not reach unicode.org: ${(err as Error).message}`);
    console.error("Refusing to hand-write a confusables table. Aborting.");
    process.exit(1);
  }

  const versionLine =
    confusablesText.split("\n").find((l) => l.startsWith("# Date:")) ?? "# Date: unknown";

  let entries = parseConfusables(confusablesText);
  let droppedMathBlock = false;

  const render = (map: Map<number, string>) => {
    const codePoints = [...map.keys()];
    const charClass = buildCharClassSource(codePoints);
    const pairs = buildPairsLiteral(map);
    return `/* eslint-disable no-misleading-character-class -- CONFUSABLE_CHARS
   intentionally packs spacing combining marks (e.g. Oriya/Telugu/Malayalam
   dependent vowel signs) into a character class as disjoint code points;
   no combination happens, this is table data, not prose. */
/**
 * Generated from Unicode's confusables.txt — DO NOT EDIT BY HAND.
 * Regenerate with: npm run build:confusables
 *
 * Source: ${CONFUSABLES_URL}
 * ${versionLine.replace(/^#\s*/, "")}
 * Generated: ${new Date().toISOString().slice(0, 10)}
 *
 * ---- Unicode License V3 (https://www.unicode.org/license.txt) ----
${licenseText
  .split("\n")
  .map((l) => ` * ${l}`.trimEnd())
  .join("\n")}
 * ---------------------------------------------------------------
 */

// Alternating [confusable char][ASCII target char] pairs, sorted by code
// point. Iterate with \`for...of\` (code-point-aware) to rebuild the map.
const CONFUSABLE_PAIRS =
  ${JSON.stringify(pairs)};

function buildConfusablesMap(pairs: string): ReadonlyMap<string, string> {
  const map = new Map<string, string>();
  const chars = [...pairs];
  for (let i = 0; i < chars.length; i += 2) {
    map.set(chars[i], chars[i + 1]);
  }
  return map;
}

/** Confusable (non-ASCII) character → its single-ASCII-char fold. */
export const CONFUSABLES_TO_ASCII: ReadonlyMap<string, string> =
  buildConfusablesMap(CONFUSABLE_PAIRS);

/** Character class matching every confusable source code point above. */
export const CONFUSABLE_CHARS = /[${charClass}]/gu;
`;
  };

  let output = render(entries);

  if (Buffer.byteLength(output, "utf8") > MAX_FILE_BYTES) {
    droppedMathBlock = true;
    entries = new Map(
      [...entries].filter(
        ([cp]) => cp < MATH_ALPHANUMERIC_START || cp > MATH_ALPHANUMERIC_END
      )
    );
    output = render(entries);
  }

  writeFileSync(OUTPUT_PATH, output, "utf8");

  const sizeKb = (Buffer.byteLength(output, "utf8") / 1024).toFixed(1);
  console.log(`Wrote ${OUTPUT_PATH}`);
  console.log(`Entries: ${entries.size}`);
  console.log(`Size: ${sizeKb} KB`);
  if (droppedMathBlock) {
    console.log(
      "Dropped mathematical alphanumeric block (U+1D400-U+1D7FF) to stay under the 80 KB cap."
    );
  }
  if (Buffer.byteLength(output, "utf8") > MAX_FILE_BYTES) {
    console.error(`Still over the ${MAX_FILE_BYTES / 1024} KB cap after dropping the math block.`);
    process.exit(1);
  }
}

main();
