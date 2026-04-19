/**
 * Amplify the email ReDoS to prove superlinear (catastrophic) scaling.
 *
 * The pattern `/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g` has
 * two runs that can both match `.`: `[a-zA-Z0-9._%+-]+` (before @) and
 * `[a-zA-Z0-9.-]+` (after @), with a required `\.` in between and a
 * `[a-zA-Z]{2,}` at the end. When the input is all dots followed by a
 * non-letter, the engine has to try every way of splitting the run
 * between the two character classes, scanning O(n^2) or worse.
 */
const pattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

for (const n of [1000, 2000, 4000, 8000, 16000, 32000]) {
  const attack = "x".repeat(100) + "@" + ".".repeat(n) + "!";
  pattern.lastIndex = 0;
  const t0 = process.hrtime.bigint();
  pattern.test(attack);
  const t1 = process.hrtime.bigint();
  const ms = Number(t1 - t0) / 1e6;
  console.log(`  dots=${n.toString().padStart(6)}  time=${ms.toFixed(2)}ms`);
}

// Also: variant that tickles both classes (shared dot character)
console.log("\nBoth-runs-overlap payload (a...@...a with trailing !):");
for (const n of [1000, 2000, 4000, 8000]) {
  const attack = "a".repeat(n) + "@" + "a".repeat(n) + "!";
  pattern.lastIndex = 0;
  const t0 = process.hrtime.bigint();
  pattern.test(attack);
  const t1 = process.hrtime.bigint();
  const ms = Number(t1 - t0) / 1e6;
  console.log(`  n=${n.toString().padStart(6)}  time=${ms.toFixed(2)}ms`);
}

// Most-damaging payload: mix of dots and chars to maximize ambiguity
// AFTER @ (where [a-zA-Z0-9.-]+ overlaps with \.). Worst is: many
// dot-letter alternations without a final [a-zA-Z]{2,}.
console.log("\nDot-letter alternation after @ (no valid TLD):");
for (const n of [500, 1000, 2000, 4000, 8000, 16000]) {
  const attack = "user@" + ".x".repeat(n);
  pattern.lastIndex = 0;
  const t0 = process.hrtime.bigint();
  pattern.test(attack);
  const t1 = process.hrtime.bigint();
  const ms = Number(t1 - t0) / 1e6;
  console.log(`  n=${n.toString().padStart(6)}  time=${ms.toFixed(2)}ms`);
}
