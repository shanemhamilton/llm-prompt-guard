# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
