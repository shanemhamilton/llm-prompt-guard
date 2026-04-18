# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Fixed

### Removed

## [2.0.0] - 2026-04-18

### Changed (BREAKING)

- `FieldConfig.blockOnDetection: boolean` replaced by
  `FieldConfig.mode: "block" | "neutralize"`. `blockOnDetection: true`
  becomes `mode: "block"`; `blockOnDetection: false` becomes
  `mode: "neutralize"`. No alias is provided. See
  [MIGRATION.md](./MIGRATION.md).
- `GuardConfig.normalizeOutput` default flipped from `false` to `true`.
  Callers who need byte-exact output on the clean path (no injection
  detected) must opt out with `createGuard({ normalizeOutput: false })`.
- Node **20+** required. Dropped Node 16 and Node 18.

### Added

- `guard.spotlight(input, fieldConfig?)` — wraps sanitized input in a
  randomized delimiter `<USER_INPUT_{nonce}>...</USER_INPUT_{nonce}>`
  (12-char hex nonce from `crypto.getRandomValues()`). Defeats
  delimiter-forging attacks per the Microsoft Spotlighting and Berkeley
  StruQ/SecAlign conventions.
- `guard.scanOutput(text)` — scans LLM **responses** for
  exfiltration-shape patterns: `base64-blob`,
  `markdown-image-with-query`, `outbound-url`, `data-url`, `hex-blob`.
  Motivated by EchoLeak (CVE-2025-32711) and ShadowLeak, where inbound
  filtering alone was insufficient.
- Multilingual opt-in patterns at `llm-prompt-guard/patterns/multilingual`
  exporting `spanish`, `french`, `german`, `portuguese` arrays — 5
  patterns each covering the highest-value injection verbs.
- Plane 14 Unicode Tag block (U+E0000–U+E007F) and Variation Selector
  Supplement (U+E0100–U+E01EF) stripped during normalization.
- Shared preprocess pipeline unifies `sanitize` / `detect` / `count` —
  control-char-injected payloads that bypassed `detect()` in 1.x are
  now caught.
- Homoglyph gate regex is generated from map keys — cannot drift.
- Pinned pattern-count tests (total + per-category) replace the
  tautological 1.x test.
- Neutralize idempotency test.
- `benchmarks/` directory with FPR/FNR harness and `npm run bench`.
- `.github/` with CI (Node 20 / 22 matrix), release workflow with
  Sigstore `--provenance` via OIDC, CodeQL security-extended, OpenSSF
  Scorecard, Dependabot, and issue + PR templates.

### Security

- First npm publish with Sigstore provenance attestation.

### Fixed

- Tautological pattern-count test in 1.x that never validated anything.
- Disclosure email mismatch between `SECURITY.md` and `CONTRIBUTING.md`.
- `CONTRIBUTING.md` described hyphen-neutralization that has not been
  used since before 1.0.
- README pattern count discrepancy (format-injection was listed as 11,
  actual is 10).

### References

- [OWASP LLM Top 10 for LLM Applications 2025 — LLM01 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP Top 10 for Agentic Applications 2026 — ASI01/ASI02/ASI06](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Microsoft Spotlighting (CEUR Vol 3920, Paper 3)](https://ceur-ws.org/Vol-3920/paper03.pdf)
- [Berkeley StruQ / SecAlign (USENIX Security 2025)](https://bair.berkeley.edu/blog/2025/04/11/prompt-injection-defense/)
- CVE-2025-32711 (EchoLeak); ShadowLeak (ChatGPT Deep Research)

## [1.0.0] - 2026-02-22

### Added

- Initial release extracted from production codebase.
- 44 built-in detection patterns across 8 attack categories:
  - Instruction override (5 patterns)
  - Role hijacking (6 patterns)
  - System prompt extraction (6 patterns)
  - Format injection — ChatML, Llama/Llama 2, Alpaca/Vicuna, Anthropic Claude, JSON (10 patterns)
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
