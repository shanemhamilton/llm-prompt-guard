# Contributing to llm-prompt-guard

Thanks for your interest in improving LLM prompt security!

## Reporting Security Issues

If you discover a bypass for an existing pattern, **please do not open a public issue.** Instead, email security@myskiniq.shop so we can add a fix before the bypass is widely known.

## Adding a Detection Pattern

Built-in patterns are data, not code — they live in `src/data/builtin-patterns.json`,
not `src/patterns.ts`. Adding one is a JSON edit, not a TypeScript change:

1. Add an entry to the `patterns` array: `id` (stable, kebab-case, e.g.
   `"category.short-name"` — this is a public API other configs reference, so
   don't rename an existing one), `category`, `severity` (`"high" | "medium" | "low"`),
   `pattern` (the regex source, as a JSON string — escape backslashes), `flags`,
   a one-sentence `description`, and at least 2 `positive` and 1 `negative` example.
2. Positives must match the raw regex; `high`/`medium` positives must also make
   `detect()` return `true`. Negatives must not match the raw regex — prefer a real
   near-miss line from `benchmarks/corpora/benign/*.txt` over an invented one.
3. Run `npm test` — `src/patterns-spec.test.ts` gates schema validity, the
   round trip, positive/negative matching, a ReDoS structural lint (no nested
   quantifiers — flag a verified false positive with `redosExempt` rather than
   arguing with the lint; the string must include the timing measurement that
   justifies it, e.g. "measured <0.5 ms on 100 KB adversarial inputs...", not
   just an assertion of safety), a 100 KB adversarial-input timing check, and a
   portability lint tracking patterns that use JS-only regex syntax (lookbehind,
   named groups, `\p{...}`, `\u{...}`, or the `s`/`y` flags) — a future Python
   port can't express those as-is, so that count must never go up.
4. `id` is stable API: `GuardProfile`s reference pattern ids to demote severity,
   so don't repurpose or delete an existing id — add a new one instead.

`src/patterns/tool-poisoning.ts` and `src/patterns/multilingual.ts` are a
separate pattern pack still in TypeScript, not yet migrated to this format.

## Adding Neutralization Rules

If you add a new detection pattern with high-severity keywords, consider also adding a neutralization entry in `NEUTRALIZATION_MAP` (`src/patterns.ts`). The neutralization should:

- Break the keyword with a hyphen (e.g., "execute" → "exe-cute")
- Preserve enough readability that a human can still understand the original intent
- Use the `gi` flags (global, case-insensitive)

## Development Setup

```bash
git clone https://github.com/shanehamilton/llm-prompt-guard.git
cd llm-prompt-guard
npm install
npm test
```

## Code Style

- TypeScript strict mode
- No external runtime dependencies (dev dependencies are fine)
- Keep the API surface small and obvious

## Pull Request Process

1. Fork the repo and create a branch from `main`.
2. Add tests for any new functionality.
3. Run `npm test` and ensure all tests pass.
4. Run `npm run typecheck` to verify type safety.
5. Open a PR with a clear description of what the change does and why.
