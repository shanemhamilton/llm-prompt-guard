import type {
  ExfilFinding,
  OutputFlag,
  OutputScanResult,
  OutputValidationResult,
  OutputValidator,
  OutputValidatorConfig,
  PiiConfig,
} from "./types";
import {
  ensureGlobalFlag,
  INVISIBLE_CHARS,
  INVISIBLE_CHARS_SUPPLEMENTARY,
} from "./patterns";

// ── Canary token generation ──────────────────────────────────────────

/**
 * Generate a unique canary token for embedding in system prompts.
 * If the canary appears in LLM output, an injection succeeded.
 *
 * Format: `CANARY_` + 25 random hex characters.
 */
export function generateCanary(): string {
  const hex = randomHex(25);
  return `CANARY_${hex}`;
}

function randomHex(length: number): string {
  // A canary is only useful if it's unguessable to a third party, so we
  // refuse to generate one on a runtime without a real CSPRNG. Every
  // runtime we claim compatibility with (Node 20+, Bun, Deno, Cloudflare
  // Workers, modern browsers) exposes Web Crypto. A `Math.random()`
  // fallback would silently weaken callers who rely on this to detect
  // injection — better to fail loudly than to ship a low-entropy canary.
  if (typeof globalThis.crypto?.getRandomValues !== "function") {
    throw new Error(
      "generateCanary requires Web Crypto (globalThis.crypto.getRandomValues). " +
        "This runtime does not provide it — upgrade to Node 20+, Bun, Deno, " +
        "or a modern browser."
    );
  }
  const bytes = new Uint8Array(Math.ceil(length / 2));
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, length);
}

// ── System prompt leakage patterns ───────────────────────────────────

const SYSTEM_PROMPT_PATTERNS: Array<{ pattern: RegExp; detail: string }> = [
  {
    pattern: /my\s+system\s+prompt\s+is/i,
    detail: 'Output contains "my system prompt is"',
  },
  {
    pattern: /i\s+was\s+(told|instructed)\s+to/i,
    detail: 'Output contains "I was told/instructed to"',
  },
  {
    pattern: /my\s+(instructions|rules)\s+(are|say|tell)/i,
    detail: 'Output contains "my instructions/rules are/say/tell"',
  },
  {
    pattern: /here\s+(is|are)\s+my\s+(system\s+)?(prompt|instructions|rules)/i,
    detail: "Output reveals system prompt/instructions/rules",
  },
  {
    pattern: /the\s+system\s+prompt\s+(says|reads|is|tells)/i,
    detail: 'Output contains "the system prompt says/reads/is"',
  },
  {
    pattern: /as\s+per\s+my\s+(system\s+)?(instructions|prompt|guidelines)/i,
    detail: 'Output contains "as per my instructions/prompt"',
  },
];

// ── Behavioral anomaly patterns ──────────────────────────────────────

const BEHAVIORAL_ANOMALY_PATTERNS: Array<{
  pattern: RegExp;
  detail: string;
}> = [
  {
    pattern: /\bas\s+DAN\b/i,
    detail: 'Output contains "as DAN" jailbreak marker',
  },
  {
    pattern: /\[DAN\]/i,
    detail: "Output contains [DAN] role-play marker",
  },
  {
    pattern: /\bDAN\s+mode\s+(enabled|activated|on)\b/i,
    detail: "Output indicates DAN mode is active",
  },
  {
    pattern: /i('m|\s+am)\s+now\s+(in\s+)?(developer|DAN|unrestricted|jailbreak)\s+mode/i,
    detail: "Output claims to be in a jailbreak mode",
  },
  {
    pattern: /sure[!,.]?\s+i('ll|\s+will)\s+(ignore|bypass|override)\s+(my\s+)?(safety|guidelines|rules|restrictions)/i,
    detail: "Output acknowledges overriding safety restrictions",
  },
  {
    pattern: /<\|im_start\|>/i,
    detail: "Output contains ChatML format token <|im_start|>",
  },
  {
    pattern: /<\|im_end\|>/i,
    detail: "Output contains ChatML format token <|im_end|>",
  },
  {
    pattern: /<\|(system|endoftext)\|>/i,
    detail: "Output contains ChatML control token",
  },
  {
    pattern: /\[\s*\/?INST\s*\]/i,
    detail: "Output contains Llama instruction format token",
  },
  {
    pattern: /<<\/?SYS>>/i,
    detail: "Output contains Llama system delimiter",
  },
];

// ── PII patterns ─────────────────────────────────────────────────────

const PII_PATTERNS: Record<
  keyof Omit<PiiConfig, "custom">,
  { pattern: RegExp; detail: string }
> = {
  emails: {
    // Length-gated to prevent ReDoS. The domain char-class `[a-zA-Z0-9.-]`
    // overlaps with the trailing `\.` on dot, and when the TLD match fails
    // the engine backtracks through every possible split of a long run —
    // ~18s on 200KB pathological inputs without the gate. RFC 5321 caps
    // the local part at 64 chars, domain at 253, and real-world TLDs top
    // out around 24 chars (`.photography` is the practical ceiling), so
    // the gates are RFC-correct, not arbitrary.
    pattern: /[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,253}\.[a-zA-Z]{2,24}/g,
    detail: "Email address detected in output",
  },
  phones: {
    pattern:
      /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    detail: "Phone number detected in output",
  },
  ssns: {
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    detail: "SSN detected in output",
  },
  apiKeys: {
    pattern: /\b(?:sk-[a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{16}|ghp_[a-zA-Z0-9]{36})\b/g,
    detail: "API key detected in output",
  },
  creditCards: {
    pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,
    detail: "Credit card number detected in output",
  },
};

/**
 * Luhn algorithm to validate credit card numbers.
 */
function luhnCheck(digits: string): boolean {
  const nums = digits.replace(/\D/g, "");
  if (nums.length < 13 || nums.length > 19) return false;
  let sum = 0;
  let alternate = false;
  for (let i = nums.length - 1; i >= 0; i--) {
    let n = parseInt(nums[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

/**
 * For each `{pattern, detail}` entry, run a single non-global match and
 * push a flag of the given `type` / `severity` on hit. Used by the
 * system-prompt-leak and behavioral-anomaly passes (both emit at most
 * one flag per pattern, unlike the multi-match PII pass).
 */
function collectFirstMatchFlags(
  entries: ReadonlyArray<{ pattern: RegExp; detail: string }>,
  output: string,
  type: OutputFlag["type"],
  severity: OutputFlag["severity"],
  flags: OutputFlag[]
): void {
  for (const { pattern, detail } of entries) {
    const match = pattern.exec(output);
    if (match) {
      flags.push({ type, severity, detail, matchedText: match[0] });
    }
  }
}

// ── Output validator factory ─────────────────────────────────────────

/**
 * Create an output validator that checks LLM responses for signs of
 * successful injection attacks.
 *
 * @example
 * ```ts
 * import { createOutputValidator, generateCanary } from "llm-prompt-guard";
 *
 * const canary = generateCanary();
 * const validator = createOutputValidator({
 *   canaryTokens: [canary],
 *   pii: { emails: true, apiKeys: true },
 * });
 *
 * const result = validator.validate(llmResponse);
 * if (!result.safe) {
 *   console.warn("Output flags:", result.flags);
 * }
 * ```
 */
export function createOutputValidator(
  config: OutputValidatorConfig = {}
): OutputValidator {
  const {
    canaryTokens = [],
    pii,
    systemPromptLeakage = true,
    behavioralAnomalies = true,
  } = config;

  return {
    validate(output: string): OutputValidationResult {
      const flags: OutputFlag[] = [];

      if (!output) {
        return { safe: true, flags: [] };
      }

      // 1. Canary token detection. We strip invisibles (BMP + Plane 14 +
      // VS Supplement) before the `.includes()` check so an attacker who
      // induces the LLM to emit the canary with zero-width characters
      // interleaved between letters still gets flagged. The canary itself
      // is plain ASCII hex, so the strip cannot disturb legitimate hits.
      if (canaryTokens.length > 0) {
        const stripped = output
          .replace(INVISIBLE_CHARS, "")
          .replace(INVISIBLE_CHARS_SUPPLEMENTARY, "");
        for (const canary of canaryTokens) {
          if (stripped.includes(canary)) {
            flags.push({
              type: "canary_leak",
              severity: "high",
              detail: "Canary token found in output — injection likely succeeded",
              matchedText: canary,
            });
          }
        }
      }

      // 2. System prompt leakage
      if (systemPromptLeakage) {
        collectFirstMatchFlags(SYSTEM_PROMPT_PATTERNS, output, "system_prompt_leak", "high", flags);
      }

      // 3. PII detection (opt-in)
      if (pii) {
        for (const [key, enabled] of Object.entries(pii)) {
          if (key === "custom") continue;
          if (!enabled) continue;
          const piiKey = key as keyof Omit<PiiConfig, "custom">;
          const piiDef = PII_PATTERNS[piiKey];
          if (!piiDef) continue;
          const { pattern, detail } = piiDef;
          // Reset lastIndex for global regex
          pattern.lastIndex = 0;
          let match: RegExpExecArray | null;
          while ((match = pattern.exec(output)) !== null) {
            // Extra validation for credit cards (Luhn)
            if (piiKey === "creditCards") {
              if (!luhnCheck(match[0])) continue;
            }
            flags.push({
              type: "pii_detected",
              severity: "medium",
              detail,
              matchedText: match[0],
            });
          }
        }
        // Custom regex patterns
        if (pii.custom) {
          for (const regex of pii.custom) {
            const global = ensureGlobalFlag(regex);
            global.lastIndex = 0;
            let match: RegExpExecArray | null;
            while ((match = global.exec(output)) !== null) {
              flags.push({
                type: "pii_detected",
                severity: "medium",
                detail: "Custom PII pattern matched",
                matchedText: match[0],
              });
              if (match[0].length === 0) {
                global.lastIndex++;
              }
            }
          }
        }
      }

      // 4. Behavioral anomalies
      if (behavioralAnomalies) {
        collectFirstMatchFlags(BEHAVIORAL_ANOMALY_PATTERNS, output, "behavioral_anomaly", "high", flags);
      }

      return {
        safe: flags.length === 0,
        flags,
      };
    },
  };
}

// ── Output scanning (exfiltration-shape detection) ───────────────────

/**
 * Syntactic exfil-shape patterns. Unlike output *validation* (which
 * looks at semantics — canary leaks, system prompt leakage, PII,
 * behavioral anomalies), these patterns match on shape alone.
 *
 * - `base64-blob` — 120+ char run of base64 alphabet. Raised length
 *   gate (over the detection pipeline's 16-char threshold) keeps the
 *   false-positive rate low for genuine code/data payloads.
 * - `markdown-image-with-query` — `![alt](https://foo.com/bar?qs)` —
 *   a classic LLM-exfil vector where the attacker's URL fires a GET
 *   request carrying stolen data the moment the rendered output hits
 *   a browser.
 * - `outbound-url` — any `http(s)://...` URL, minus hosts on the
 *   caller's allowlist.
 * - `data-url` — `data:...;base64,` embedded blobs.
 * - `hex-blob` — 64+ hex characters (likely hash or long token).
 */
const EXFIL_PATTERNS: Array<{
  type: ExfilFinding["type"];
  pattern: RegExp;
}> = [
  { type: "base64-blob", pattern: /[A-Za-z0-9+/]{120,}={0,2}/g },
  {
    type: "markdown-image-with-query",
    pattern: /!\[.*?\]\(https?:\/\/[^)]+\?[^)]+\)/g,
  },
  { type: "data-url", pattern: /data:[^;,]+;base64,/gi },
  { type: "hex-blob", pattern: /[0-9a-fA-F]{64,}/g },
  // Outbound URL last so more-specific patterns (markdown image, data URL)
  // get first pick on their substrings.
  { type: "outbound-url", pattern: /https?:\/\/[^\s)"'<>]+/g },
];

/**
 * Case-insensitive hostname match against an allowlist.
 *
 * - Bare entry `"example.com"` matches the apex and every subdomain
 *   (`example.com`, `api.example.com`, `www.example.com`), but NOT
 *   `notexample.com` — the dot guard prevents suffix-only matches.
 * - Cookie-style entry `".example.com"` matches subdomains only
 *   (`api.example.com`, `www.example.com`), NOT the apex
 *   `example.com`. Use this when you want the apex to remain flagged.
 */
function hostMatchesAllowlist(host: string, allowlist: string[]): boolean {
  const lowerHost = host.toLowerCase();
  for (const entry of allowlist) {
    const lowerEntryRaw = entry.toLowerCase();
    const subdomainOnly = lowerEntryRaw.startsWith(".");
    const lowerEntry = subdomainOnly ? lowerEntryRaw.slice(1) : lowerEntryRaw;
    if (!subdomainOnly && lowerHost === lowerEntry) return true;
    if (lowerHost.endsWith("." + lowerEntry)) return true;
  }
  return false;
}

/**
 * Extract the hostname from an outbound URL match. Returns null if the
 * URL is unparseable — the caller should then treat it as a finding
 * (the conservative choice for a defense-in-depth tool).
 */
function extractHost(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/**
 * Scan LLM output for syntactic exfiltration-shape patterns.
 *
 * Complements `validateOutput` (semantic signals) with a syntactic
 * sweep: if the response text *looks* like a base64 blob, a markdown
 * image with querystring, an outbound URL, a data URL, or a long hex
 * run, a finding is surfaced. Callers decide whether to block, strip,
 * or log — `scanOutput` reports; it does not mutate.
 *
 * @param text - The LLM's raw response text.
 * @param config - Optional config. Only `allowedOrigins` is honored here —
 *   hosts on the allowlist bypass the `outbound-url` finding type.
 */
export function scanOutputImpl(
  text: string,
  allowedOrigins: string[]
): OutputScanResult {
  const findings: ExfilFinding[] = [];
  if (!text) return { safe: true, findings };

  for (const { type, pattern } of EXFIL_PATTERNS) {
    // Fresh regex per scan — we mutate lastIndex and callers may retain
    // references, so we always clone. Non-global patterns get `g` added.
    const flags = pattern.global ? pattern.flags : pattern.flags + "g";
    const global = new RegExp(pattern.source, flags);
    let match: RegExpExecArray | null;
    while ((match = global.exec(text)) !== null) {
      const matched = match[0];

      // Skip outbound URLs on the caller's allowlist.
      if (type === "outbound-url") {
        const host = extractHost(matched);
        if (host !== null && hostMatchesAllowlist(host, allowedOrigins)) {
          if (matched.length === 0) global.lastIndex++;
          continue;
        }
      }

      findings.push({
        type,
        preview: matched.slice(0, 60),
        offset: match.index,
      });

      if (matched.length === 0) global.lastIndex++;
    }
  }

  return { safe: findings.length === 0, findings };
}

/**
 * Scan LLM output for syntactic exfiltration-shape patterns using
 * default configuration (no allowlist). For per-host allowlisting, use
 * `createGuard({ allowedOrigins }).scanOutput()`.
 */
export function scanOutput(text: string): OutputScanResult {
  return scanOutputImpl(text, []);
}
