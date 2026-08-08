# Security Policy

## Reporting a Vulnerability

If you discover a way to bypass the detection patterns in llm-prompt-guard, **please report it privately** rather than opening a public issue. This gives us time to ship a fix before the bypass technique is widely known.

**Email:** llm-prompt-guard@proton.me

Please include:
- The input string that bypasses detection
- Which attack category it falls under
- Any context about the technique (e.g., Unicode tricks, encoding, obfuscation)

We aim to acknowledge reports within 48 hours and ship fixes within 7 days.

## Scope

This project is a **Layer-1 defense-in-depth filter**, not a complete security solution. It uses regex-based pattern matching over a normalization/decoding pipeline (Unicode invisibles, Plane-14 tag block, homoglyphs, NFKD, URL-encoding, character-split, leetspeak, base64, ROT13, reversed text — see the README "How It Works" section), which has known limitations:

- Novel attack patterns not in the ruleset will not be detected.
- Semantic paraphrases and task-drift attacks with no injection vocabulary bypass detection — measured recall on the public deepset/prompt-injections corpus is published in [`benchmarks/PUBLIC_RESULTS.md`](benchmarks/PUBLIC_RESULTS.md).
- Encoding passes are heuristic: base64 decoding only accepts ASCII-printable results, character-split collapse only handles `.`/`-`/`_` separators, and leetspeak substitutions outside the 8-character map are not caught.
- Detection is single-turn — multi-turn escalation (Crescendo-style) requires stateful tracking in your application layer.
- The deprecated `neutralize` mode preserves some user intent, so partial attack content may still reach the LLM.

We recommend combining llm-prompt-guard with other security measures:
- A model-based detection layer for semantic paraphrase (see README "Where this fits")
- Output validation (`validateOutput` / `scanOutput`, plus your own checks)
- Principle of least privilege (limit what the LLM can access)
- Rate limiting on your API endpoints
- Monitoring and alerting on detection events

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| 1.x     | No — upgrade via [MIGRATION.md](MIGRATION.md) |
