import type {
  OutputFlag,
  OutputValidationResult,
  OutputValidator,
  OutputValidatorConfig,
  PiiConfig,
} from "./types";

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
  try {
    // Browser / modern Node
    if (typeof globalThis.crypto?.getRandomValues === "function") {
      const bytes = new Uint8Array(Math.ceil(length / 2));
      globalThis.crypto.getRandomValues(bytes);
      return Array.from(bytes, (b) => b.toString(16).padStart(2, "0"))
        .join("")
        .slice(0, length);
    }
  } catch {
    // Fall through to Math.random
  }
  // Fallback
  let result = "";
  for (let i = 0; i < length; i++) {
    result += Math.floor(Math.random() * 16).toString(16);
  }
  return result;
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
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
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

      // 1. Canary token detection
      for (const canary of canaryTokens) {
        if (output.includes(canary)) {
          flags.push({
            type: "canary_leak",
            severity: "high",
            detail: "Canary token found in output — injection likely succeeded",
            matchedText: canary,
          });
        }
      }

      // 2. System prompt leakage
      if (systemPromptLeakage) {
        for (const { pattern, detail } of SYSTEM_PROMPT_PATTERNS) {
          const match = pattern.exec(output);
          if (match) {
            flags.push({
              type: "system_prompt_leak",
              severity: "high",
              detail,
              matchedText: match[0],
            });
          }
        }
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
            const global = regex.global
              ? regex
              : new RegExp(regex.source, regex.flags + "g");
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
        for (const { pattern, detail } of BEHAVIORAL_ANOMALY_PATTERNS) {
          const match = pattern.exec(output);
          if (match) {
            flags.push({
              type: "behavioral_anomaly",
              severity: "high",
              detail,
              matchedText: match[0],
            });
          }
        }
      }

      return {
        safe: flags.length === 0,
        flags,
      };
    },
  };
}
