/**
 * Probe more patterns with carefully constructed pathological inputs.
 */

// phones — nested optional with overlapping character classes
const phonesPattern = /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
console.log("phones pattern scaling:");
for (const n of [1000, 4000, 16000]) {
  const attack = "1" + "-".repeat(n) + "234";
  phonesPattern.lastIndex = 0;
  const t0 = process.hrtime.bigint();
  phonesPattern.test(attack);
  const t1 = process.hrtime.bigint();
  console.log(`  dashes=${n.toString().padStart(6)}  time=${(Number(t1 - t0) / 1e6).toFixed(2)}ms`);
}

// markdown-image-with-query — three unbounded runs
const mdImgPattern = /!\[.*?\]\(https?:\/\/[^)]+\?[^)]+\)/g;
console.log("\nmarkdown-image pattern scaling:");
for (const n of [1000, 4000, 16000]) {
  // Unclosed — forces full backtrack through the lazy match
  const attack = "![" + "a".repeat(n) + "](http://" + "a".repeat(n) + "?" + "b".repeat(n);
  mdImgPattern.lastIndex = 0;
  const t0 = process.hrtime.bigint();
  mdImgPattern.test(attack);
  const t1 = process.hrtime.bigint();
  console.log(`  n=${n.toString().padStart(6)}  time=${(Number(t1 - t0) / 1e6).toFixed(2)}ms`);
}

// base64-blob — 120+ char run with potential overlap
const base64Pattern = /[A-Za-z0-9+/]{120,}={0,2}/g;
console.log("\nbase64-blob pattern scaling:");
for (const n of [1000, 10000, 100000]) {
  const attack = "A".repeat(n);
  base64Pattern.lastIndex = 0;
  const t0 = process.hrtime.bigint();
  base64Pattern.test(attack);
  const t1 = process.hrtime.bigint();
  console.log(`  n=${n.toString().padStart(7)}  time=${(Number(t1 - t0) / 1e6).toFixed(2)}ms`);
}

// Separator collapse in preprocess: (A-Za-z0-9)([.-_])(A-Za-z0-9)(?:\2[A-Za-z0-9]){2,}
const sepPattern = /([A-Za-z0-9])([.\-_])([A-Za-z0-9])(?:\2[A-Za-z0-9]){2,}/g;
console.log("\nseparator-collapse pattern scaling:");
for (const n of [1000, 10000, 100000]) {
  const attack = "a.".repeat(n) + "a";
  sepPattern.lastIndex = 0;
  const t0 = process.hrtime.bigint();
  sepPattern.test(attack);
  const t1 = process.hrtime.bigint();
  console.log(`  n=${n.toString().padStart(7)}  time=${(Number(t1 - t0) / 1e6).toFixed(2)}ms`);
}

// outbound-url: https?://[^\s)"'<>]+
const urlPattern = /https?:\/\/[^\s)"'<>]+/g;
console.log("\noutbound-url pattern scaling:");
for (const n of [1000, 100000, 1000000]) {
  const attack = "https://" + "a".repeat(n);
  urlPattern.lastIndex = 0;
  const t0 = process.hrtime.bigint();
  urlPattern.test(attack);
  const t1 = process.hrtime.bigint();
  console.log(`  n=${n.toString().padStart(8)}  time=${(Number(t1 - t0) / 1e6).toFixed(2)}ms`);
}
