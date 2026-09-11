import type { InjectionPattern } from "./types";
import spec from "./data/builtin-patterns.json";

/**
 * Built-in injection detection patterns.
 *
 * Organized by attack category. Each pattern targets a specific prompt
 * injection technique documented in the OWASP LLM Top 10 (LLM01).
 *
 * The pattern data itself lives in `src/data/builtin-patterns.json` —
 * a versioned spec with positive/negative test cases per pattern,
 * validated and ReDoS-checked in `src/patterns-spec.test.ts`. This file
 * just compiles the spec's `pattern`/`flags` strings into `RegExp`
 * instances. See CONTRIBUTING.md to add a pattern.
 *
 * `tool-poisoning.ts` and `multilingual.ts` (in `src/patterns/`) are a
 * separate, still-TypeScript pattern pack — not yet migrated.
 *
 * IMPORTANT: Do not expose pattern details in error messages returned
 * to users — this would help attackers refine bypasses.
 */
export const BUILTIN_PATTERNS: InjectionPattern[] = spec.patterns.map(
  (p): InjectionPattern => ({
    id: p.id,
    category: p.category,
    severity: p.severity as InjectionPattern["severity"],
    pattern: new RegExp(p.pattern, p.flags),
  })
);

/**
 * Leetspeak-to-ASCII mapping for normalization.
 * Maps common digit/symbol substitutions back to their letter equivalents.
 */
export const LEET_MAP: Record<string, string> = {
  "0": "o",
  "1": "i",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "@": "a",
  $: "s",
};

/**
 * Cyrillic / Greek homoglyph → Latin mapping, shared by detection-time
 * normalization, output-safe normalization, and the canary-leak check.
 *
 * All three must agree: detection sees the same Latin form the caller
 * receives on the clean path, and a canary echoed with Cyrillic
 * substitutes still has to compare equal to the ASCII original.
 */
export const HOMOGLYPH_MAP: Record<string, string> = {
  "\u0430": "a", // Cyrillic а
  "\u0435": "e", // Cyrillic е
  "\u043E": "o", // Cyrillic о
  "\u0440": "p", // Cyrillic р
  "\u0441": "c", // Cyrillic с
  "\u0443": "y", // Cyrillic у
  "\u0445": "x", // Cyrillic х
  "\u0456": "i", // Cyrillic і (Ukrainian)
  "\u0458": "j", // Cyrillic ј
  "\u04BB": "h", // Cyrillic һ
  "\u0410": "A", // Cyrillic А
  "\u0412": "B", // Cyrillic В
  "\u0415": "E", // Cyrillic Е
  "\u041A": "K", // Cyrillic К
  "\u041C": "M", // Cyrillic М
  "\u041D": "H", // Cyrillic Н
  "\u041E": "O", // Cyrillic О
  "\u0420": "P", // Cyrillic Р
  "\u0421": "C", // Cyrillic С
  "\u0422": "T", // Cyrillic Т
  "\u0425": "X", // Cyrillic Х
  "\u03BF": "o", // Greek omicron ο
  "\u03B1": "a", // Greek alpha α (when combined with NFKD)
};

/** Matches any character with an entry in {@link HOMOGLYPH_MAP}. */
export const HOMOGLYPH_RANGE = /[\u0410-\u04BB\u03B1\u03BF]/g;

/** Combining diacritical marks, stripped after NFKD decomposition. */
export const DIACRITICAL_MARKS = /[\u0300-\u036F]/g;

/**
 * Return a copy of `regex` with the global (`g`) flag set.
 * If already global, returns the original instance.
 */
export function ensureGlobalFlag(regex: RegExp): RegExp {
  if (regex.global) return regex;
  return new RegExp(regex.source, regex.flags + "g");
}

/**
 * Return a copy of `regex` with the stateful flags (`g`, `y`) removed.
 *
 * Both flags make a regex carry `lastIndex` across calls, and the
 * detection paths call `.test()` on the same pattern object on every
 * request. A global pattern therefore reports true, then false, then
 * true for identical input; a sticky one anchors at `lastIndex` and
 * never matches text that does not begin with it.
 *
 * Every built-in pattern is non-global already, so this only ever
 * rewrites caller-supplied `extraPatterns`. Normalizing once, where
 * patterns enter the guard, is what keeps the invariant true at every
 * `.test()` site — including sites added later, which is how `assess()`
 * acquired the bug after the original report. `excise()` and
 * `generateTags()` re-add `g` via {@link ensureGlobalFlag}, which
 * returns a fresh instance, so match-all behavior is unaffected.
 */
export function stripStatefulFlags(regex: RegExp): RegExp {
  if (!regex.global && !regex.sticky) return regex;
  return new RegExp(regex.source, regex.flags.replace(/[gy]/g, ""));
}

/**
 * Keyword neutralization map used in "neutralize" mode.
 *
 * @deprecated Modern LLMs read through underscore mangling trivially.
 * Prefer `mode: "excise"`, `"quarantine"`, or `"tag"` instead.
 *
 * Replaces injection keywords with mangled equivalents that break BPE
 * tokenization. The replacements intentionally break at non-standard
 * positions to maximize disruption of the LLM's pattern recognition.
 */
export const NEUTRALIZATION_MAP: Array<[RegExp, string]> = [
  // ── Instruction override keywords ──
  [/ignore/gi, "i_g_n_o_r_e"],
  [/disregard/gi, "d_i_s_r_e_g_a_r_d"],
  [/forget/gi, "f_o_r_g_e_t"],
  [/override/gi, "o_v_e_r_r_i_d_e"],

  // ── Role hijacking keywords ──
  [/pretend/gi, "p_r_e_t_e_n_d"],
  [/roleplay/gi, "r_o_l_e_p_l_a_y"],

  // ── Prompt extraction keywords ──
  [/system\s+prompt/gi, "s_y_s_t_e_m p_r_o_m_p_t"],
  [/instructions?/gi, "i_n_s_t_r_u_c_t_i_o_n_s"],
  [/\bprompt\b/gi, "p_r_o_m_p_t"],

  // ── Confidence manipulation keywords ──
  [/confidence/gi, "c_o_n_f_i_d_e_n_c_e"],
  [/auto[_-]?approv/gi, "a_u_t_o_a_p_p_r_o_v"],

  // ── Jailbreak keywords ──
  [/jailbreak/gi, "j_a_i_l_b_r_e_a_k"],
  [/bypass/gi, "b_y_p_a_s_s"],
  // Case-insensitive like every other entry here: "dan mode" and "Dan
  // Mode" are the same jailbreak as "DAN mode", and the `DAN\s+mode`
  // detection pattern already matches case-insensitively. The cost is
  // that the name "Dan" gets mangled too — acceptable in a mode that
  // already mangles "prompt" and "bypass" in ordinary prose.
  [/\bDAN\b/gi, "D_A_N"],

  // ── Format injection tokens ──
  [/<\|/g, "< |"],
  [/\|>/g, "| >"],
  [/\[\s*\/?INST\s*\]/gi, "[ I_N_S_T ]"],
  [/<<\/?SYS>>/gi, "< < S_Y_S > >"],
];

/**
 * Regex matching dangerous control characters (ASCII C0 set minus
 * tab, newline, and carriage return which are legitimate).
 *
 * Internal — not part of the public API.
 */
export const CONTROL_CHARS = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

/**
 * Regex matching invisible Unicode characters that attackers insert
 * between keyword letters to bypass regex detection. LLMs typically
 * ignore these during tokenization, so the injection still works.
 *
 * Covers: zero-width space (U+200B), zero-width non-joiner (U+200C),
 * zero-width joiner (U+200D), word joiner (U+2060), zero-width
 * no-break space / BOM (U+FEFF), soft hyphen (U+00AD), and other
 * format/control characters from Unicode categories Cf and Zs from
 * the Basic Multilingual Plane (Plane 0).
 */
export const INVISIBLE_CHARS =
  /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\uFE00-\uFE0F\uFEFF\uFFF9-\uFFFB]/g;

/**
 * Supplementary invisible / zero-width code points that live above the
 * Basic Multilingual Plane and therefore need the `u` flag to strip via
 * a single regex pass.
 *
 * Two ranges matter for prompt-injection defense:
 *
 * 1. **Tag block — U+E0000–U+E007F (Plane 14).** The Unicode Tag block
 *    encodes a parallel ASCII range (space → "~") using invisible,
 *    zero-width code points. LLMs tokenize these as ordinary text, so
 *    an attacker can steganographically smuggle `ignore previous
 *    instructions` through a visible decoy like `Hello there!` while
 *    evading every ASCII regex. AWS Bedrock and Cisco both published
 *    mitigations for this in 2025.
 *
 * 2. **Variation Selector Supplement — U+E0100–U+E01EF.** These 240
 *    code points are variation selectors (VS17–VS256) used legitimately
 *    only for CJK glyph variants. In injection payloads they are
 *    interleaved between ASCII characters to disrupt byte-level regex
 *    while remaining invisible.
 *
 * The `u` flag is required because both ranges are outside the BMP and
 * would otherwise match as surrogate halves.
 */
export const INVISIBLE_CHARS_SUPPLEMENTARY =
  /[\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu;

/**
 * An invisible character sandwiched between ASCII letters — the
 * keyword-interleave evasion shape
 * (`i\u200Bg\u200Bn\u200Bo\u200Br\u200Be`). Deliberately scoped to
 * letter-adjacent positions so legitimate uses of the same code points
 * (emoji variation selectors, Persian ZWNJ between Arabic letters, RTL
 * marks, soft hyphens at line-break points) do not count as evidence.
 *
 * Internal — feeds `NormalizationSignals.interleavedInvisibles`.
 */
export const INTERLEAVED_INVISIBLE =
  /[A-Za-z][\u00AD\u200B-\u200F\u2060-\u2064\uFEFF]+[A-Za-z]/g;

/**
 * Any Cyrillic or Greek letter (full blocks — wider than the confusable
 * subset in the homoglyph map). Used to distinguish genuine
 * Cyrillic/Greek text from Latin text salted with look-alikes.
 *
 * Internal — feeds `NormalizationSignals.suspiciousHomoglyphs`.
 */
export const CYRILLIC_GREEK = /[\u0370-\u03FF\u0400-\u04FF\u0500-\u052F]/g;

/**
 * Non-lossy output normalization — safe for returning to callers.
 *
 * Only strips invisible characters (BMP + Plane 14 tag block + VS
 * Supplement) and maps homoglyphs / NFKD-decomposed forms back to
 * their ASCII / Latin equivalents. Does NOT apply leetspeak, URL
 * decoding, separator collapse, or reversal — those are aggressive,
 * lossy transforms that are correct for detection but would corrupt
 * legitimate content containing numbers, URLs, or dots.
 *
 * Used by `sanitize()`'s clean path when `normalizeOutput !== false`,
 * and by the canary-leak check so a canary echoed with homoglyph or
 * fullwidth substitutes still compares equal to the ASCII original.
 */
export function normalizeForOutput(input: string): string {
  // Strip BMP invisibles, then Plane 14 Tag block + Variation Selector Supplement.
  let result = input.replace(INVISIBLE_CHARS, "").replace(INVISIBLE_CHARS_SUPPLEMENTARY, "");
  // NFKD decomposition (fullwidth → ASCII, ﬁ → fi, accented base separate).
  result = result.normalize("NFKD");
  // Strip combining diacritical marks after NFKD.
  result = result.replace(DIACRITICAL_MARKS, "");
  // Map Cyrillic / Greek homoglyphs to Latin — same table as detection.
  return result.replace(HOMOGLYPH_RANGE, (ch) => HOMOGLYPH_MAP[ch] ?? ch);
}
