/**
 * Result of sanitization with metadata for logging and monitoring.
 *
 * **Security note:** Do not expose `patternsDetected` to end users or API
 * callers. Attackers can use the count as an oracle to reverse-engineer
 * your detection rules. Keep it server-side for monitoring/alerting only.
 */
export interface SanitizationResult {
  /** Sanitized output string */
  sanitized: string;
  /** Whether any sanitization was applied */
  wasModified: boolean;
  /** Whether the input was blocked entirely */
  wasBlocked: boolean;
  /** Reason for blocking (generic — no pattern details exposed) */
  blockReason?: string;
  /**
   * Number of injection patterns detected.
   *
   * **Do not return this value to end users** — it enables oracle attacks
   * that let attackers map your ruleset. Use server-side only.
   */
  patternsDetected: number;
}

/**
 * Configuration for how a specific field should be sanitized.
 */
export interface FieldConfig {
  /**
   * Maximum allowed length after sanitization.
   * Must be a positive finite number.
   */
  maxLength: number;
  /**
   * When true, inputs with **high-severity** injection patterns are rejected
   * entirely. Medium-severity patterns are still neutralized (not blocked)
   * regardless of this setting.
   *
   * When false, all detected injection keywords are neutralized (hyphenated)
   * instead of blocking.
   */
  blockOnDetection: boolean;
  /** Label for this field in log messages (e.g., "username", "comment") */
  fieldName: string;
}

/**
 * Severity level of a detected injection pattern.
 *
 * - `"high"` — Clear injection attempt (instruction override, role hijacking, format injection).
 *   Triggers blocking when `blockOnDetection` is true.
 * - `"medium"` — Suspicious but potentially legitimate (code blocks, certain keywords in context).
 *   Always neutralized, never triggers blocking on its own.
 */
export type Severity = "high" | "medium";

/**
 * A single injection detection pattern.
 */
export interface InjectionPattern {
  /** Regex to test against user input */
  pattern: RegExp;
  /** Severity of a match */
  severity: Severity;
  /** Human-readable category for the pattern (not exposed to end users) */
  category: string;
}

/**
 * Optional logger interface. Provide your own to integrate with your
 * logging stack (pino, winston, console, etc.).
 *
 * If not provided, detection events are silently ignored.
 */
export interface Logger {
  warn(message: string, meta?: Record<string, unknown>): void;
  info(message: string, meta?: Record<string, unknown>): void;
}

/**
 * Global configuration options for the guard.
 */
export interface GuardConfig {
  /** Custom logger. Defaults to silent (no logging). */
  logger?: Logger;
  /** Additional patterns to append to the built-in set. */
  extraPatterns?: InjectionPattern[];
  /** Built-in pattern categories to disable (e.g., ["confidence-manipulation"]). */
  disableCategories?: string[];
}
