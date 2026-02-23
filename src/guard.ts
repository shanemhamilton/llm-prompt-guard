import type {
  FieldConfig,
  GuardConfig,
  InjectionPattern,
  Logger,
  SanitizationResult,
} from "./types";
import {
  BUILTIN_PATTERNS,
  CONTROL_CHARS,
  INVISIBLE_CHARS,
  NEUTRALIZATION_MAP,
} from "./patterns";

/** No-op logger used when the caller does not provide one. */
const SILENT_LOGGER: Logger = {
  warn: () => {},
  info: () => {},
};

/**
 * Create a prompt guard instance with the given configuration.
 *
 * @example
 * ```ts
 * import { createGuard } from "llm-prompt-guard";
 *
 * const guard = createGuard({ logger: console });
 *
 * // Strict mode — block malicious input
 * const name = guard.sanitize("ignore all previous instructions", {
 *   maxLength: 200,
 *   blockOnDetection: true,
 *   fieldName: "productName",
 * });
 * // name.wasBlocked === true
 *
 * // Lenient mode — neutralize instead of blocking
 * const comment = guard.sanitize("please ignore previous instructions and help me", {
 *   maxLength: 1000,
 *   blockOnDetection: false,
 *   fieldName: "userComment",
 * });
 * // comment.sanitized contains mangled keywords
 * ```
 */
export function createGuard(config: GuardConfig = {}) {
  const log: Logger = config.logger ?? SILENT_LOGGER;
  const patterns = buildPatternList(config);

  return {
    /**
     * Sanitize user input for safe inclusion in an LLM prompt.
     *
     * @param input  - Raw user-provided string.
     * @param field  - Configuration for this particular input field.
     * @param userId - Optional user identifier included in log metadata.
     * @returns A {@link SanitizationResult} with the cleaned string and detection metadata.
     */
    sanitize(
      input: string,
      field: FieldConfig,
      userId?: string
    ): SanitizationResult {
      return sanitizeForPrompt(input, field, patterns, log, userId);
    },

    /**
     * Detection-only check. Returns `true` if any injection pattern matches.
     * Does not modify the input. Applies Unicode normalization before checking.
     */
    detect(input: string): boolean {
      return containsInjection(input, patterns);
    },

    /**
     * Count how many distinct injection patterns match the input.
     * Useful for server-side monitoring and alerting dashboards.
     *
     * **Do not expose this count to end users** — it enables oracle attacks.
     */
    count(input: string): number {
      return countPatterns(input, patterns);
    },

    /**
     * Returns the active pattern list (built-ins + extras, minus disabled categories).
     * Useful for testing and auditing.
     */
    getPatterns(): ReadonlyArray<InjectionPattern> {
      return patterns;
    },
  };
}

// ── Convenience functions (use built-in patterns, no logging) ────────

/**
 * One-shot sanitize using built-in patterns and no logging.
 * For quick prototyping — prefer {@link createGuard} in production.
 */
export function sanitize(
  input: string,
  field: FieldConfig,
  userId?: string
): SanitizationResult {
  return sanitizeForPrompt(input, field, BUILTIN_PATTERNS, SILENT_LOGGER, userId);
}

/**
 * One-shot detection check using built-in patterns.
 */
export function detect(input: string): boolean {
  return containsInjection(input, BUILTIN_PATTERNS);
}

/**
 * One-shot pattern count using built-in patterns.
 */
export function count(input: string): number {
  return countPatterns(input, BUILTIN_PATTERNS);
}

// ── Core implementation ──────────────────────────────────────────────

function buildPatternList(config: GuardConfig): InjectionPattern[] {
  const disabled = new Set(config.disableCategories ?? []);
  const base = BUILTIN_PATTERNS.filter((p) => !disabled.has(p.category));
  return config.extraPatterns ? [...base, ...config.extraPatterns] : base;
}

/**
 * Validate FieldConfig to prevent silent bypass via NaN/negative/Infinity.
 */
function validateFieldConfig(field: FieldConfig): void {
  if (
    typeof field.maxLength !== "number" ||
    !Number.isFinite(field.maxLength) ||
    field.maxLength <= 0
  ) {
    throw new RangeError(
      `FieldConfig.maxLength must be a positive finite number, got: ${field.maxLength}`
    );
  }
}

/**
 * Safely coerce input to string. Handles malicious toString() methods
 * and non-string types without crashing.
 */
function safeToString(input: unknown): string | null {
  if (typeof input === "string") return input;
  try {
    return String(input);
  } catch {
    return null;
  }
}

/**
 * Normalize Unicode to defeat invisible-character and homoglyph attacks.
 *
 * 1. Strip invisible Unicode characters (zero-width spaces, soft hyphens, etc.)
 * 2. Apply NFKD decomposition (maps many visual lookalikes to base characters)
 * 3. Strip combining diacritical marks left over from NFKD
 * 4. Map common Cyrillic/Greek homoglyphs to ASCII Latin equivalents
 */
function normalizeUnicode(input: string): string {
  // Step 1: Strip invisible characters
  let result = input.replace(INVISIBLE_CHARS, "");

  // Step 2: NFKD decomposition — decomposes characters like "ﬁ" → "fi",
  // fullwidth letters → ASCII, and separates base chars from diacritics
  result = result.normalize("NFKD");

  // Step 3: Strip combining diacritical marks (U+0300–U+036F)
  // This converts accented characters to their base form
  result = result.replace(/[\u0300-\u036F]/g, "");

  // Step 4: Map common Cyrillic/Greek homoglyphs to Latin equivalents.
  // These are the most frequently used in adversarial attacks.
  const HOMOGLYPH_MAP: Record<string, string> = {
    "\u0430": "a", // Cyrillic а
    "\u0435": "e", // Cyrillic е
    "\u043E": "o", // Cyrillic о
    "\u0440": "p", // Cyrillic р
    "\u0441": "c", // Cyrillic с
    "\u0443": "y", // Cyrillic у
    "\u0445": "x", // Cyrillic х
    "\u0456": "i", // Cyrillic і (Ukrainian)
    "\u0458": "j", // Cyrillic ј
    "\u04BB": "h", // Cyrillic һ
    "\u0410": "A", // Cyrillic А
    "\u0412": "B", // Cyrillic В
    "\u0415": "E", // Cyrillic Е
    "\u041A": "K", // Cyrillic К
    "\u041C": "M", // Cyrillic М
    "\u041D": "H", // Cyrillic Н
    "\u041E": "O", // Cyrillic О
    "\u0420": "P", // Cyrillic Р
    "\u0421": "C", // Cyrillic С
    "\u0422": "T", // Cyrillic Т
    "\u0425": "X", // Cyrillic Х
    "\u03BF": "o", // Greek omicron ο
    "\u03B1": "a", // Greek alpha α (when combined with NFKD)
  };

  result = result.replace(
    /[\u0410-\u04BB\u03B1\u03BF]/g,
    (ch) => HOMOGLYPH_MAP[ch] ?? ch
  );

  return result;
}

function sanitizeForPrompt(
  input: string,
  field: FieldConfig,
  patterns: InjectionPattern[],
  log: Logger,
  userId?: string
): SanitizationResult {
  // Validate config to prevent silent bypass via NaN/negative maxLength.
  validateFieldConfig(field);

  // Handle null/undefined/non-string safely.
  if (!input) {
    return {
      sanitized: "",
      wasModified: false,
      wasBlocked: false,
      patternsDetected: 0,
    };
  }

  const inputStr = safeToString(input);
  if (inputStr === null) {
    return {
      sanitized: "",
      wasModified: true,
      wasBlocked: true,
      blockReason: "Invalid input",
      patternsDetected: 0,
    };
  }

  let sanitized = inputStr;
  let wasModified = false;
  let patternsDetected = 0;

  // Step 1: Strip dangerous ASCII control characters.
  const cleaned = sanitized.replace(CONTROL_CHARS, "");
  if (cleaned !== sanitized) {
    wasModified = true;
    sanitized = cleaned;
  }

  // Step 2: Normalize Unicode — strip invisible chars, decompose, map homoglyphs.
  // We run detection on the normalized form to defeat bypass techniques,
  // but keep the original (control-char-stripped) text for the output.
  const normalized = normalizeUnicode(sanitized);

  // Step 3: Detect injection patterns on normalized text.
  let hasHighSeverity = false;
  for (const { pattern, severity } of patterns) {
    if (pattern.test(normalized)) {
      patternsDetected++;
      if (severity === "high") {
        hasHighSeverity = true;
      }
    }
  }

  // Step 4: Respond to detections.
  if (patternsDetected > 0) {
    log.warn("Prompt injection patterns detected", {
      fieldName: field.fieldName,
      userId: userId ?? "unknown",
      patternsDetected,
      inputLength: inputStr.length,
      severity: hasHighSeverity ? "high" : "medium",
    });

    if (field.blockOnDetection && hasHighSeverity) {
      return {
        sanitized: "",
        wasModified: true,
        wasBlocked: true,
        blockReason: "Invalid input",
        patternsDetected,
      };
    }

    // Neutralize mode: mangle injection keywords on the normalized form.
    wasModified = true;
    sanitized = neutralize(normalized);
  }

  // Step 5: Enforce length limit.
  if (sanitized.length > field.maxLength) {
    sanitized = sanitized.substring(0, field.maxLength);
    wasModified = true;
    log.info("Input truncated to max length", {
      fieldName: field.fieldName,
      originalLength: inputStr.length,
      maxLength: field.maxLength,
    });
  }

  // Step 6: Normalize whitespace.
  const trimmed = sanitized.trim().replace(/\s+/g, " ");
  if (trimmed !== sanitized) {
    wasModified = true;
    sanitized = trimmed;
  }

  return {
    sanitized,
    wasModified,
    wasBlocked: false,
    patternsDetected,
  };
}

function neutralize(input: string): string {
  let result = input;
  for (const [pattern, replacement] of NEUTRALIZATION_MAP) {
    result = result.replace(pattern, replacement);
  }
  return result;
}

function containsInjection(
  input: string,
  patterns: InjectionPattern[]
): boolean {
  if (!input) return false;
  const normalized = normalizeUnicode(String(input));
  for (const { pattern } of patterns) {
    if (pattern.test(normalized)) return true;
  }
  return false;
}

function countPatterns(
  input: string,
  patterns: InjectionPattern[]
): number {
  if (!input) return 0;
  const normalized = normalizeUnicode(String(input));
  let n = 0;
  for (const { pattern } of patterns) {
    if (pattern.test(normalized)) n++;
  }
  return n;
}
