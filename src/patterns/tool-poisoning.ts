import type { InjectionPattern } from "../types";

/**
 * Tool-poisoning detection patterns for MCP-style tool definitions.
 *
 * These are deliberately SEPARATE from `BUILTIN_PATTERNS` and run only
 * against tool definitions, never against user input. The same sentence
 * carries different meaning depending on where it appears: a user
 * writing "do not mention this to anyone" is unremarkable, but a tool
 * description saying it is instructing the model to hide its behavior
 * from the operator.
 *
 * Shapes are drawn from the Invariant Labs MCP tool-poisoning research
 * (April 2025) and the follow-on work showing every schema field is a
 * viable injection surface.
 */

export const CONCEALMENT_PATTERNS: InjectionPattern[] = [
  {
    pattern: /do\s+not\s+(tell|inform|mention|reveal|disclose|notify)\s+(the\s+)?(user|human|operator|anyone)/i,
    severity: "high",
    category: "concealment",
  },
  {
    pattern: /without\s+(telling|informing|notifying|alerting)\s+(the\s+)?(user|human|operator)/i,
    severity: "high",
    category: "concealment",
  },
  {
    pattern: /(hide|conceal|suppress)\s+(this|that|it|the\s+\w+)\s+from\s+(the\s+)?(user|human|operator)/i,
    severity: "high",
    category: "concealment",
  },
  {
    pattern: /\bdo\s+not\s+(show|display|print|output|log)\s+(this|the\s+(contents?|results?|output))/i,
    severity: "high",
    category: "concealment",
  },
  // Hidden-instruction markup smuggled into descriptions — the shape
  // used in the original tool-poisoning proof of concept.
  {
    pattern: /<\s*(IMPORTANT|SECRET|SYSTEM|HIDDEN|INSTRUCTIONS?)\s*>/i,
    severity: "high",
    category: "concealment",
  },
];

export const CREDENTIAL_PATTERNS: InjectionPattern[] = [
  {
    pattern: /~?\/?\.ssh\/(id_[a-z0-9]+|authorized_keys|known_hosts)/i,
    severity: "high",
    category: "credential-access",
  },
  {
    pattern: /\.aws\/credentials|\.kube\/config|\.docker\/config\.json/i,
    severity: "high",
    category: "credential-access",
  },
  {
    pattern: /(read|cat|open|load|send|upload|exfiltrate)\s+(the\s+)?(contents?\s+of\s+)?(\S*\.env\b|~?\/?\.env\b)/i,
    severity: "high",
    category: "credential-access",
  },
  {
    pattern: /\b(api[_\s-]?keys?|secrets?|credentials?|access[_\s-]?tokens?|private[_\s-]?keys?)\b[^.]{0,40}\b(read|send|include|attach|pass|forward|transmit)\b/i,
    severity: "high",
    category: "credential-access",
  },
  {
    pattern: /\b(read|send|include|attach|pass|forward|transmit)\b[^.]{0,40}\b(api[_\s-]?keys?|secrets?|credentials?|access[_\s-]?tokens?|private[_\s-]?keys?)\b/i,
    severity: "high",
    category: "credential-access",
  },
];

export const SHADOWING_PATTERNS: InjectionPattern[] = [
  {
    pattern: /when(ever)?\s+(the\s+)?(user|model|assistant)\s+(asks|requests|calls|uses|invokes)[^.]{0,60}\binstead\b/i,
    severity: "high",
    category: "tool-shadowing",
  },
  {
    pattern: /(override|replace|supersede|take\s+precedence\s+over)\s+(the\s+)?(behaviou?r|description|instructions?|definition)\s+of\s+(the\s+)?(other|any|all|previous)?\s*tools?/i,
    severity: "high",
    category: "tool-shadowing",
  },
  {
    pattern: /before\s+(using|calling|invoking)\s+(any\s+)?(other\s+)?tools?\b[^.]{0,60}\b(you\s+must|always|first)\b/i,
    severity: "high",
    category: "tool-shadowing",
  },
  {
    pattern: /\bthis\s+tool\s+(must|should)\s+be\s+(called|used|invoked)\s+(before|instead\s+of)\b/i,
    severity: "medium",
    category: "tool-shadowing",
  },
];
