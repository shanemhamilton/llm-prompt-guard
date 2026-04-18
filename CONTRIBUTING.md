# Contributing to llm-prompt-guard

Thanks for your interest in improving LLM prompt security!

## Reporting Security Issues

If you discover a bypass for an existing pattern, **please do not open a public issue.** Instead, email llm-prompt-guard@proton.me so we can add a fix before the bypass is widely known.

## Adding New Patterns

New detection patterns are the most valuable contribution. When submitting a PR:

1. **Provide a real-world example** of the attack your pattern detects.
2. **Include false-positive test cases** — show that your pattern does not trigger on legitimate input.
3. **Assign the correct severity:**
   - `"high"` — Unambiguous injection attempt. Would never appear in legitimate user input.
   - `"medium"` — Suspicious but context-dependent. Might appear in normal text.
4. **Assign a category** — Use an existing category from `src/patterns.ts` or propose a new one.
5. **Add tests** — Both detection tests and false-positive resistance tests in `src/guard.test.ts`.

## Adding Neutralization Rules

If you add a new detection pattern with high-severity keywords, consider also adding a neutralization entry in `NEUTRALIZATION_MAP` (`src/patterns.ts`). The neutralization should:

- **Use the per-letter underscore convention** — insert an underscore between every letter (e.g., `ignore` → `i_g_n_o_r_e`, `jailbreak` → `j_a_i_l_b_r_e_a_k`). This is the canonical replacement style used throughout `NEUTRALIZATION_MAP`.
- **Optimize for BPE-tokenization disruption.** Modern LLMs tokenize common words like `ignore` or `instructions` as a single subword token; the model has learned strong command-like priors on those exact token IDs. Inserting underscores between every letter forces the tokenizer to split the keyword into many unfamiliar sub-tokens, so the LLM no longer recognizes it as an instruction verb while a human reader can still make it out. Hyphenation or syllable splits (e.g., `exe-cute`) fall back onto other whole-word tokens and are measurably weaker at disrupting the attack.
- **Mirror the existing entries in `NEUTRALIZATION_MAP`** — see `src/patterns.ts` for the canonical examples, including how format-injection tokens like `<|im_start|>`, `[INST]`, and `<<SYS>>` are handled.
- **Use the `gi` flags** (global, case-insensitive) on every entry.

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
