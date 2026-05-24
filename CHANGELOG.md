# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0](https://github.com/shanemhamilton/llm-prompt-guard/compare/llm-prompt-guard-v2.0.2...llm-prompt-guard-v2.1.0) (2026-05-24)


### Features

* add encoding attack resistance and output validation ([e06d337](https://github.com/shanemhamilton/llm-prompt-guard/commit/e06d337211434800533f5e0ba4c9e9987b35624d))
* add excise, quarantine, and tag sanitization modes ([25233a0](https://github.com/shanemhamilton/llm-prompt-guard/commit/25233a04efd2e2d6a988b3836a0e4314a61497ec))
* initial release — regex-based prompt injection firewall for TypeScript ([51591ef](https://github.com/shanemhamilton/llm-prompt-guard/commit/51591efc25be2ae5a7bf774c812dc26245ee895f))
* v2.0.0 reconciliation — Plane 14, scanOutput, quarantine randomize, multilingual, benchmarks, hygiene ([05ca6ab](https://github.com/shanemhamilton/llm-prompt-guard/commit/05ca6ab75a676f94a3a0315f52f8f5d190e8997a))


### Bug Fixes

* add prepare script for git-based installs ([bdf3eb7](https://github.com/shanemhamilton/llm-prompt-guard/commit/bdf3eb7bb5fcf9a730b1b73c14dcc416a4b9083e))
* **release:** Trusted Publishers OIDC — upgrade npm, drop NODE_AUTH_TOKEN ([95fb863](https://github.com/shanemhamilton/llm-prompt-guard/commit/95fb863ef25164f62f5aff2abb86a0b5d517efdc))
* review gate — allowedOrigins dot-prefix, pin pattern counts, trim LEET regex ([31b468b](https://github.com/shanemhamilton/llm-prompt-guard/commit/31b468baa2039174dbf0e0d5cacd5e21e7988a89))
* **security:** v2.0.1 — email ReDoS, canary fallback, canary bypass + simplification ([9038581](https://github.com/shanemhamilton/llm-prompt-guard/commit/90385818a23fa3a76e9389005c5df92fbe767303))

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [2.0.1] - 2026-04-18

### Security

- **Email PII regex ReDoS.** The v2.0 email regex
  `/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g` caused catastrophic
  backtracking on pathological inputs (5–18s lockup on ~500 KB inputs of
  the form `"a"*N + "@" + "b"*N + ".1"`). An attacker who enabled
  `pii.emails: true` on untrusted LLM output had a DoS vector. Fixed with
  a length-gated RFC 5321-aligned pattern (`{1,64}@{1,253}\.{2,24}`) that
  completes in ~30–80 ms on the same adversarial input. All real-world
  email shapes still match.
- **`generateCanary()` silent fallback to `Math.random()`.** When Web
  Crypto was unavailable, the canary token was generated from a
  predictable PRNG — a third party observing a handful of canaries could
  reconstruct state and defeat the mechanism. Web Crypto is available in
  every runtime this library claims compatibility with (Node 20+, Bun,
  Deno, Cloudflare Workers, modern browsers), so the fallback was dead
  code with a footgun attached. `generateCanary()` now throws a clear
  error on runtimes that lack `globalThis.crypto.getRandomValues`.
- **Canary detection bypass via zero-width / tag characters.** The v2.0
  `validateOutput` canary check used `output.includes(canary)` on raw
  UTF-16. An attacker who could induce the LLM to emit the canary with
  U+200B (or any Plane-14 tag char) interleaved between letters would
  leak the canary without being flagged. Fix: strip `INVISIBLE_CHARS`
  and `INVISIBLE_CHARS_SUPPLEMENTARY` from the LLM output before
  `includes()`. Canary tokens are plain ASCII hex so the strip cannot
  clobber legitimate matches.

### Changed

- **Internal refactor (no behavior change).** Deduplicated the two
  identical `HOMOGLYPH_MAP` tables in `src/guard.ts`, extracted shared
  `logDetection` / `truncateWithLog` helpers in `src/guard.ts`, extracted
  `collectFirstMatchFlags` helper in `src/output.ts`, and reused the
  existing public `ensureGlobalFlag` export instead of reimplementing it
  inline. Net −58 lines.

### Added

- **Benchmark corpus:** 6 legitimate base64/hex strings (JWT header,
  Lorem-ipsum base64, Stripe transaction id, 40-char hex commit hash,
  64-char GPG fingerprint) to exercise the base64-decode and hex-blob
  paths. Benign corpus: 509 → 515 inputs. FPR remains 0.00%.
- **Regression tests** for each security finding (email ReDoS gate,
  real-world email shapes, canary zero-width bypass, canary Plane 14
  bypass, `generateCanary` error on runtimes without Web Crypto). Test
  count: 418 → 423.

### Known limitations (flagged, not patched)

- `validateOutput`'s `SYSTEM_PROMPT_PATTERNS` over-match on benign LLM
  phrasings like "here are my instructions for the recipe" or "as per my
  instructions, I've updated the file." This is inherent to a regex-only
  semantic validator. Whether to tighten with context anchors, downgrade
  severity, or leave as advisory-only is a design choice deferred to
  v2.1.

## [2.0.0] - 2026-04-18

### Changed (BREAKING)

- Node 20+ required (was 16+).
- `GuardConfig.normalizeOutput` default is now `true` (was `false`). The clean path
  in `sanitize()` now strips invisible characters (BMP + Plane 14 Tag block + VS
  Supplement) and maps homoglyphs / NFKD-decomposed forms back to their ASCII
  equivalents. Opt out with `normalizeOutput: false` for byte-exact output.

### Added

- Sanitization modes: `excise`, `quarantine`, `tag` (in addition to existing `block` / `neutralize`).
- `QuarantineOptions.randomizeDelimiters` — per-call 12-hex nonce defeats delimiter-forging attacks.
- `validateOutput(output)` — semantic LLM-response validation (canary leaks, system-prompt leakage, PII, behavioral anomalies).
- `scanOutput(text)` — syntactic exfiltration-shape scanner (base64 blobs, markdown-image URLs with query strings, outbound URLs, data URLs, hex blobs).
- `GuardConfig.allowedOrigins` — skip outbound-url flagging for trusted hosts (case-insensitive hostname suffix).
- `generateCanary()` — unique canary tokens for prompt embedding.
- Unicode Plane 14 Tag block (U+E0000–U+E007F) + Variation Selector Supplement (U+E0100–U+E01EF) — stripped and decoded back to ASCII for detection.
- Encoding attack resistance: URL-decode, leetspeak normalization, character-split collapse, base64 decode (ASCII-printable only), ROT13, reversed text.
- Multilingual opt-in patterns at `llm-prompt-guard/patterns/multilingual` (Spanish, French, German, Portuguese; 5 patterns each).
- `benchmarks/` directory with FPR/FNR harness and hard regression gate.
- `.github/` with CI (Node 20/22 matrix), release workflow with Sigstore provenance via OIDC, CodeQL security-extended, OpenSSF Scorecard, Dependabot, issue + PR templates.

### Deprecated

- `NEUTRALIZATION_MAP` and `mode: "neutralize"` — modern LLMs read through underscore mangling trivially; use `excise`, `quarantine`, or `tag` instead.
- `FieldConfig.blockOnDetection` — still works; use `mode` instead. Will be removed in v3.

### Security

- First npm publish with Sigstore provenance attestation.

### Fixed

- Pattern-count test that tautologically compared a value to itself.
- SECURITY.md and CONTRIBUTING.md now use the same disclosure email.
- README format-injection count (was 11, actual 10).

### References

- OWASP LLM Top 10 for LLM Applications 2025 — LLM01 Prompt Injection.
- OWASP Top 10 for Agentic Applications 2026 — ASI01, ASI02, ASI06.
- Microsoft Spotlighting (CEUR Vol 3920 Paper 3).
- Berkeley StruQ / SecAlign (USENIX Security 2025).
- CVE-2025-32711 EchoLeak; ShadowLeak (ChatGPT Deep Research).
- HiddenLayer Policy Puppetry (novel universal bypass for all major LLMs).

## [1.0.0] - 2026-02-22

### Added

- Initial release extracted from production codebase.
- 44 built-in detection patterns across 8 attack categories:
  - Instruction override (5 patterns)
  - Role hijacking (6 patterns)
  - System prompt extraction (6 patterns)
  - Format injection — ChatML, Llama/Llama 2, Alpaca/Vicuna, Anthropic Claude, JSON (11 patterns)
  - Data exfiltration (4 patterns)
  - Confidence/approval manipulation (5 patterns)
  - Jailbreak (5 patterns)
  - Markup injection (3 patterns)
- **Unicode normalization** before detection:
  - Strip invisible characters (zero-width spaces, soft hyphens, word joiners, BOM)
  - NFKD decomposition for fullwidth/ligature normalization
  - Cyrillic/Greek homoglyph mapping to Latin equivalents
- Two response modes:
  - **Block** — reject input entirely (for structured fields).
  - **Neutralize** — mangle injection keywords with underscores (for freetext fields).
- Per-field configuration via `FieldConfig`.
- Pluggable logger interface (works with console, pino, winston, etc.).
- Custom pattern support via `extraPatterns`.
- Category disabling via `disableCategories`.
- Convenience functions (`sanitize`, `detect`, `count`) for quick usage.
- `createGuard()` factory for production use with logging and custom patterns.
- `FieldConfig.maxLength` validation (rejects NaN, negative, Infinity).
- Safe `toString()` coercion (never crashes on malicious input objects).
- Full TypeScript types with JSDoc documentation.
- Dual CJS/ESM build via tsup.
- 161 tests with 100% code coverage.

### Changed (vs. production original)

- `developer mode` pattern narrowed to require a verb prefix (`enable/enter/activate/switch to/turn on developer mode`) to eliminate false positives on legitimate phrases like "developer mode on my phone."
- `system prompt` pattern now uses word boundaries (`\bsystem\s+prompt\b`) to avoid false positives on "My system prompted me."
- Neutralization strategy changed from syllable-boundary hyphenation to underscore separation (`ignore` → `i_g_n_o_r_e`) for stronger BPE tokenization disruption.
- Neutralization map expanded from 10 to 18 entries, now covering format injection tokens (ChatML, INST, SYS).
- Firebase `logger` dependency replaced with pluggable `Logger` interface.
- `CONTROL_CHARS` regex removed from public API (internal only).
