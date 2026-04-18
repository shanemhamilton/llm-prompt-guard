# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

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
