import spec from "./data/builtin-patterns.json";
import { BUILTIN_PATTERNS } from "./patterns";
import { detect } from "./guard";
import type { Severity } from "./types";

interface SpecPattern {
  id: string;
  category: string;
  severity: Severity;
  pattern: string;
  flags: string;
  description: string;
  positive: string[];
  negative: string[];
  redosExempt?: string;
}

const patterns = spec.patterns as SpecPattern[];

// Portability ceiling (§6): number of patterns using JS-only regex syntax
// (lookbehind, named groups, \p{...}, \u{...}, or the s/y flags) that a
// straight Python `re` port can't express as-is. Lower this only by
// migrating a pattern away from that syntax — never raise it.
const PORTABILITY_CEILING = 0;

describe("patterns spec (src/data/builtin-patterns.json)", () => {
  // ── 1. Schema ─────────────────────────────────────────────────────
  describe("schema", () => {
    test("has schemaVersion 1", () => {
      expect(spec.schemaVersion).toBe(1);
    });

    test("ids are unique", () => {
      const ids = patterns.map((p) => p.id);
      expect(new Set(ids).size).toBe(ids.length);
    });

    test.each(patterns.map((p): [string, SpecPattern] => [p.id, p]))(
      "%s has required fields with correct types",
      (_id, p) => {
        expect(typeof p.id).toBe("string");
        expect(p.id.length).toBeGreaterThan(0);
        expect(typeof p.category).toBe("string");
        expect(["high", "medium", "low"]).toContain(p.severity);
        expect(typeof p.pattern).toBe("string");
        expect(typeof p.flags).toBe("string");
        expect([...p.flags].every((f) => "gimsuy".includes(f))).toBe(true);
        expect(typeof p.description).toBe("string");
        expect(p.description.length).toBeGreaterThan(0);
        expect(Array.isArray(p.positive)).toBe(true);
        expect(p.positive.length).toBeGreaterThanOrEqual(2);
        expect(Array.isArray(p.negative)).toBe(true);
        expect(p.negative.length).toBeGreaterThanOrEqual(1);
      }
    );
  });

  // ── 2. Round trip ─────────────────────────────────────────────────
  describe("round trip", () => {
    test("BUILTIN_PATTERNS.length matches spec.patterns.length", () => {
      expect(BUILTIN_PATTERNS.length).toBe(patterns.length);
    });

    test.each(patterns.map((p): [string, SpecPattern] => [p.id, p]))(
      "%s: new RegExp(pattern, flags).source === pattern",
      (_id, p) => {
        expect(new RegExp(p.pattern, p.flags).source).toBe(p.pattern);
      }
    );
  });

  // ── 3. Positive/negative matching ────────────────────────────────
  describe("positive and negative examples", () => {
    for (const p of patterns) {
      describe(p.id, () => {
        test.each(p.positive)("positive matches raw regex: %s", (example) => {
          const re = new RegExp(p.pattern, p.flags);
          expect(re.test(example)).toBe(true);
        });

        if (p.severity === "high" || p.severity === "medium") {
          test.each(p.positive)("positive makes detect() true: %s", (example) => {
            expect(detect(example)).toBe(true);
          });
        }

        test.each(p.negative)("negative does not match raw regex: %s", (example) => {
          const re = new RegExp(p.pattern, p.flags);
          expect(re.test(example)).toBe(false);
        });
      });
    }
  });

  // ── 4. ReDoS structural lint ─────────────────────────────────────
  describe("ReDoS structural lint", () => {
    /**
     * Flags a quantified group whose body itself contains a quantifier
     * — the classic nested-quantifier shape, e.g. `(a+)+` or
     * `(foo\s+)*`. This is a syntactic heuristic, not a proof of
     * catastrophic backtracking: it doesn't check whether the group's
     * alternatives actually overlap (the condition that causes real
     * exponential blowup), so its ceiling is false positives on a
     * quantified group whose alternatives have disjoint prefixes.
     * `redosExempt` documents a verified false positive rather than
     * weakening the check.
     */
    function findNestedQuantifiers(source: string): string[] {
      const findings: string[] = [];
      const stack: number[] = [];
      const groups: Array<{ start: number; end: number }> = [];
      for (let i = 0; i < source.length; i++) {
        const ch = source[i];
        if (ch === "\\") {
          i++;
          continue;
        }
        if (ch === "[") {
          let j = i + 1;
          if (source[j] === "^") j++;
          if (source[j] === "]") j++;
          while (j < source.length && source[j] !== "]") {
            if (source[j] === "\\") j++;
            j++;
          }
          i = j;
          continue;
        }
        if (ch === "(") {
          stack.push(i);
        } else if (ch === ")") {
          const start = stack.pop();
          if (start !== undefined) groups.push({ start, end: i });
        }
      }
      for (const g of groups) {
        const body = source.slice(g.start + 1, g.end);
        const after = source[g.end + 1];
        if (after !== "+" && after !== "*" && after !== "{") continue;
        let bodyHasQuantifier = false;
        for (let k = 0; k < body.length; k++) {
          const c = body[k];
          if (c === "\\") {
            k++;
            continue;
          }
          if (c === "+" || c === "*" || c === "{") {
            bodyHasQuantifier = true;
            break;
          }
        }
        if (bodyHasQuantifier) {
          findings.push(`group ${JSON.stringify(body)} followed by "${after}"`);
        }
      }
      return findings;
    }

    test("redosExempt entries are logged and carry timing evidence", () => {
      const exempted = patterns.filter((p) => p.redosExempt);
      if (exempted.length > 0) {
        console.info(
          "ReDoS-exempted patterns:",
          exempted.map((p) => p.id)
        );
      }
      for (const p of exempted) {
        // A justification is only useful if it documents the measurement
        // that backs the exemption, not just an assertion of safety.
        expect(p.redosExempt).toMatch(/\d+(\.\d+)?\s*(ms|milliseconds)/i);
      }
    });

    test.each(patterns.map((p): [string, SpecPattern] => [p.id, p]))(
      "%s has no un-exempted nested-quantifier shape",
      (_id, p) => {
        const findings = findNestedQuantifiers(p.pattern);
        if (p.redosExempt) return; // documented, verified false positive
        expect(findings).toEqual([]);
      }
    );
  });

  // ── 5. ReDoS timing ───────────────────────────────────────────────
  describe("ReDoS timing (100 KB adversarial inputs)", () => {
    const CHUNK_TARGET_BYTES = 100_000;
    const TIME_BUDGET_MS = 100;

    function repeatTo(chunk: string, bytes: number): string {
      let out = "";
      while (Buffer.byteLength(out, "utf8") < bytes) out += chunk;
      return out;
    }

    const adversarialInputs: Array<[string, string]> = [
      ["a-repeat", repeatTo("a", CHUNK_TARGET_BYTES)],
      ["space-repeat", repeatTo(" ", CHUNK_TARGET_BYTES)],
      ["ignore-repeat", repeatTo("ignore ", CHUNK_TARGET_BYTES)],
      ["comment-repeat", repeatTo("<!-- ", CHUNK_TARGET_BYTES)],
      ["a-b-repeat", repeatTo("a b ", CHUNK_TARGET_BYTES)],
    ];

    test.each(patterns.map((p): [string, SpecPattern] => [p.id, p]))(
      "%s stays under budget on all adversarial inputs",
      (_id, p) => {
        const re = new RegExp(p.pattern, p.flags);
        let maxMs = 0;
        for (const [, input] of adversarialInputs) {
          const start = process.hrtime.bigint();
          re.test(input);
          const ms = Number(process.hrtime.bigint() - start) / 1e6;
          maxMs = Math.max(maxMs, ms);
        }
        console.info(`${p.id}: max ${maxMs.toFixed(3)}ms across adversarial inputs`);
        expect(maxMs).toBeLessThan(TIME_BUDGET_MS);
      }
    );
  });

  // ── 6. Portability lint (Python-port readiness) ──────────────────
  describe("portability lint", () => {
    function usesJsOnlySyntax(p: SpecPattern): boolean {
      const src = p.pattern;
      if (/\(\?<[=!]/.test(src)) return true; // lookbehind
      if (/\(\?<[A-Za-z_][A-Za-z0-9_]*>/.test(src)) return true; // named group
      if (/\\p\{/i.test(src)) return true; // unicode property escape
      if (/\\u\{/.test(src)) return true; // unicode code point escape
      if (p.flags.includes("s") || p.flags.includes("y")) return true;
      return false;
    }

    test("JS-only-syntax count does not exceed the portability ceiling", () => {
      const offenders = patterns.filter(usesJsOnlySyntax).map((p) => p.id);
      if (offenders.length > 0) {
        console.warn("Patterns using JS-only regex syntax:", offenders);
      }
      expect(offenders.length).toBeLessThanOrEqual(PORTABILITY_CEILING);
      if (PORTABILITY_CEILING === 0) {
        expect(offenders.length).toBe(0);
      }
    });
  });
});
