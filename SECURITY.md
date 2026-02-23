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

This project is a **defense-in-depth layer**, not a complete security solution. It uses regex-based pattern matching with Unicode normalization, which has known limitations:

- Novel attack patterns not in the ruleset will not be detected.
- Obfuscated attacks (Base64, ROT13, URL encoding) are not decoded before matching.
- Semantic equivalents of injection phrases may bypass detection.
- The neutralization mode preserves some user intent, which means partial information from the attack may still reach the LLM.

We recommend combining llm-prompt-guard with other security measures:
- Output validation (check LLM responses for data leakage)
- Principle of least privilege (limit what the LLM can access)
- Rate limiting on your API endpoints
- Monitoring and alerting on detection events

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |
