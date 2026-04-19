/**
 * ReDoS probe — times how long each suspect regex takes against a
 * pathological input. Runs before and after fixes as a regression guard.
 *
 * Methodology:
 *   - Build an input that maximizes backtracking on the pattern.
 *   - Measure with process.hrtime.bigint for nanosecond precision.
 *   - Flag anything > 50ms as suspicious (benign patterns are <<1ms).
 */
import { BUILTIN_PATTERNS } from "../../src/patterns";
import * as multi from "../../src/patterns/multilingual";

const THRESHOLD_MS = 50;

type Suite = { name: string; pattern: RegExp; attack: string };

const suites: Suite[] = [];

// Classic nested-quantifier payloads.
function spacesPayload(word: string, reps = 4000): string {
  return word + " ".repeat(reps) + "X";
}

suites.push({
  name: "ignore-instructions",
  pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?/i,
  attack: spacesPayload("ignore", 5000),
});
suites.push({
  name: "ignore-instructions-allreps",
  pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?/i,
  attack: "ignore " + "all ".repeat(2000) + "X",
});
suites.push({
  name: "disregard",
  pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier)/i,
  attack: "disregard " + "all ".repeat(2000) + "X",
});
suites.push({
  name: "do-not-follow",
  pattern: /do\s+not\s+follow\s+(the\s+)?(previous|above|earlier)/i,
  attack: "do not follow " + "the ".repeat(2000) + "X",
});

suites.push({
  name: "output.here-is-my",
  pattern: /here\s+(is|are)\s+my\s+(system\s+)?(prompt|instructions|rules)/i,
  attack: "here is my " + "system ".repeat(2000) + "X",
});
suites.push({
  name: "output.as-per-my",
  pattern: /as\s+per\s+my\s+(system\s+)?(instructions|prompt|guidelines)/i,
  attack: "as per my " + "system ".repeat(2000) + "X",
});
suites.push({
  name: "output.my-instructions-are",
  pattern: /my\s+(instructions|rules)\s+(are|say|tell)/i,
  attack: "my instructions " + "are ".repeat(2000) + "X",
});
suites.push({
  name: "output.sure-ill-ignore",
  pattern:
    /sure[!,.]?\s+i('ll|\s+will)\s+(ignore|bypass|override)\s+(my\s+)?(safety|guidelines|rules|restrictions)/i,
  attack: "sure i'll ignore " + "my ".repeat(2000) + "X",
});

suites.push({
  name: "pii.emails",
  pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  attack: "a".repeat(5000) + "@" + "a".repeat(5000) + "!",
});
suites.push({
  name: "pii.emails-dotruns",
  pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  attack: "x".repeat(100) + "@" + ".".repeat(5000) + "!",
});
suites.push({
  name: "pii.phones",
  pattern: /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
  attack: "1" + "-".repeat(5000) + "234",
});

suites.push({
  name: "exfil.markdown-img",
  pattern: /!\[.*?\]\(https?:\/\/[^)]+\?[^)]+\)/g,
  attack: "![" + "a".repeat(5000) + "](http://" + "a".repeat(5000) + "?" + "b".repeat(5000) + "X",
});
suites.push({
  name: "exfil.base64-blob",
  pattern: /[A-Za-z0-9+/]{120,}={0,2}/g,
  attack: "A".repeat(200) + "=".repeat(3) + "A".repeat(200),
});
suites.push({
  name: "exfil.outbound-url",
  pattern: /https?:\/\/[^\s)"'<>]+/g,
  attack: "https://" + "a".repeat(10000),
});

suites.push({
  name: "preprocess.base64-16",
  pattern: /[A-Za-z0-9+/]{16,}={0,2}/g,
  attack: "A".repeat(50000) + "=".repeat(3),
});
suites.push({
  name: "preprocess.separator-collapse",
  pattern: /([A-Za-z0-9])([.\-_])([A-Za-z0-9])(?:\2[A-Za-z0-9]){2,}/g,
  attack: "a.".repeat(5000) + "a",
});
suites.push({
  name: "preprocess.url-decode",
  pattern: /%([0-9A-Fa-f]{2})/g,
  attack: "%AA".repeat(5000),
});

suites.push({
  name: "tag-decode",
  pattern: /[\u{E0020}-\u{E007E}]+/gu,
  attack: "\u{E0041}".repeat(10000),
});

suites.push({
  name: "nonce-tag",
  pattern: /^(.*?)([>\])}]+)$/,
  attack: "a".repeat(10000) + "]",
});

suites.push({
  name: "multi.es-prompt-extract",
  pattern:
    /\b(revela\s+(el|tu|tus)\s+(prompt|instrucciones|sistema)|muestrame\s+(el|tu)\s+prompt|cual\s+es\s+tu\s+prompt)/ui,
  attack: "revela " + "el ".repeat(2000) + "X",
});
suites.push({
  name: "multi.fr-prompt-extract",
  pattern:
    /\b(revele\s+(ton|le)\s+prompt|montre[-\s]+moi\s+(ton|le)\s+prompt|quel\s+est\s+ton\s+prompt)/ui,
  attack: "revele " + "ton ".repeat(2000) + "X",
});
suites.push({
  name: "multi.es-filter-bypass",
  pattern:
    /\b(evita|elude|saltate|salta)\s+(los|las)\s+(filtros|restricciones|controles)\s+(de\s+seguridad)?/ui,
  attack: "evita " + "los ".repeat(2000) + "X",
});
suites.push({
  name: "multi.de-filter-bypass",
  pattern:
    /\bumgehe\s+(die\s+)?(sicherheits[-\s]?)?(filter|richtlinien|beschrankungen|einschrankungen)/ui,
  attack: "umgehe " + "die ".repeat(2000) + "X",
});

// Also run every BUILTIN_PATTERN against a whitespace-heavy decoy.
const decoy = " ".repeat(1000) + "ignore" + " ".repeat(1000) + "the" + " ".repeat(1000) + "zzz";
for (const { pattern, category } of BUILTIN_PATTERNS) {
  suites.push({ name: `builtin.${category}`, pattern, attack: decoy });
}
for (const group of ["spanish", "french", "german", "portuguese"] as const) {
  for (const p of (multi as any)[group]) {
    suites.push({ name: `multi.${group}.${p.category}`, pattern: p.pattern, attack: decoy });
  }
}

let slowCount = 0;
for (const { name, pattern, attack } of suites) {
  const t0 = process.hrtime.bigint();
  try {
    if (pattern.global) pattern.lastIndex = 0;
    pattern.test(attack);
  } catch (e) {
    console.log(`  [ERR] ${name}: ${(e as Error).message}`);
    continue;
  }
  const t1 = process.hrtime.bigint();
  const ms = Number(t1 - t0) / 1e6;
  const flag = ms > THRESHOLD_MS ? "!! SLOW" : "ok";
  if (ms > THRESHOLD_MS) slowCount++;
  console.log(
    `  ${flag.padStart(7)} ${name.padEnd(40)} ${ms.toFixed(2)}ms  len=${attack.length}`
  );
}

console.log(`\n${slowCount} suspect patterns (>${THRESHOLD_MS}ms).`);
process.exit(slowCount > 0 ? 1 : 0);
