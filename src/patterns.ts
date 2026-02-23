import type { InjectionPattern } from "./types";

/**
 * Built-in injection detection patterns.
 *
 * Organized by attack category. Each pattern targets a specific prompt
 * injection technique documented in the OWASP LLM Top 10 (LLM01).
 *
 * IMPORTANT: Do not expose pattern details in error messages returned
 * to users — this would help attackers refine bypasses.
 */
export const BUILTIN_PATTERNS: InjectionPattern[] = [
  // ── Instruction override ──────────────────────────────────────────
  {
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?/i,
    severity: "high",
    category: "instruction-override",
  },
  {
    pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier)/i,
    severity: "high",
    category: "instruction-override",
  },
  {
    pattern: /forget\s+(all\s+)?(previous|prior|above|earlier)/i,
    severity: "high",
    category: "instruction-override",
  },
  {
    pattern: /override\s+(all\s+)?(previous|prior|above|earlier)/i,
    severity: "high",
    category: "instruction-override",
  },
  {
    pattern: /do\s+not\s+follow\s+(the\s+)?(previous|above|earlier)/i,
    severity: "high",
    category: "instruction-override",
  },

  // ── Role hijacking ────────────────────────────────────────────────
  {
    pattern: /you\s+are\s+now\s+(a|an|the)/i,
    severity: "high",
    category: "role-hijacking",
  },
  {
    pattern: /pretend\s+(to\s+be|you('re|\s+are)?)/i,
    severity: "high",
    category: "role-hijacking",
  },
  {
    pattern: /act\s+as\s+(if\s+)?(you('re|\s+are)?|a|an)/i,
    severity: "high",
    category: "role-hijacking",
  },
  {
    pattern: /assume\s+the\s+role\s+of/i,
    severity: "high",
    category: "role-hijacking",
  },
  {
    pattern: /roleplay\s+as/i,
    severity: "high",
    category: "role-hijacking",
  },
  {
    pattern: /you\s+must\s+now/i,
    severity: "high",
    category: "role-hijacking",
  },

  // ── System prompt extraction ──────────────────────────────────────
  {
    pattern: /\bsystem\s+prompt\b/i,
    severity: "high",
    category: "prompt-extraction",
  },
  {
    pattern: /output\s+(all|the|your)\s+(system|instructions|prompts?|rules)/i,
    severity: "high",
    category: "prompt-extraction",
  },
  {
    pattern: /reveal\s+(your|the)\s+(instructions|prompt|rules)/i,
    severity: "high",
    category: "prompt-extraction",
  },
  {
    pattern: /show\s+(me\s+)?(your|the)\s+(system|instructions|prompt)/i,
    severity: "high",
    category: "prompt-extraction",
  },
  {
    pattern: /what\s+(are|is)\s+your\s+(system|initial)\s+(prompt|instructions)/i,
    severity: "high",
    category: "prompt-extraction",
  },
  {
    pattern: /print\s+(your|the)\s+(system|initial)\s+(prompt|instructions)/i,
    severity: "high",
    category: "prompt-extraction",
  },

  // ── Format injection (ChatML / Llama / Alpaca / Claude / JSON) ───
  {
    pattern: /\{\s*"role"\s*:/i,
    severity: "high",
    category: "format-injection",
  },
  {
    pattern: /\{\s*"content"\s*:/i,
    severity: "high",
    category: "format-injection",
  },
  {
    pattern: /```\s*(json|javascript|python|typescript|bash|sh)\s*\n\s*\{/i,
    severity: "medium",
    category: "format-injection",
  },
  // ChatML tokens
  {
    pattern: /<\|im_start\|>/i,
    severity: "high",
    category: "format-injection",
  },
  {
    pattern: /<\|im_end\|>/i,
    severity: "high",
    category: "format-injection",
  },
  // Generic ChatML-style role/control tokens
  {
    pattern: /<\|(system|user|assistant|endoftext)\|>/i,
    severity: "high",
    category: "format-injection",
  },
  // Llama instruction format
  {
    pattern: /\[\s*\/?INST\s*\]/i,
    severity: "high",
    category: "format-injection",
  },
  // Llama 2 system delimiters
  {
    pattern: /<<\/?SYS>>/i,
    severity: "high",
    category: "format-injection",
  },
  // Alpaca / Vicuna format
  {
    pattern: /###\s*(System|Human|Assistant|User)\s*:/i,
    severity: "high",
    category: "format-injection",
  },
  // Anthropic Claude format (line-start anchored)
  {
    pattern: /^\s*(Human|Assistant)\s*:/im,
    severity: "medium",
    category: "format-injection",
  },

  // ── Data exfiltration ─────────────────────────────────────────────
  {
    pattern: /list\s+(all\s+)?(the\s+)?(database|collection|table|schema)/i,
    severity: "high",
    category: "data-exfiltration",
  },
  {
    pattern: /dump\s+(all\s+)?(the\s+)?(data|database|collection)/i,
    severity: "high",
    category: "data-exfiltration",
  },
  {
    pattern: /export\s+(all\s+)?(the\s+)?(data|database)/i,
    severity: "high",
    category: "data-exfiltration",
  },
  {
    pattern: /what\s+(other\s+)?(data|information)\s+(do\s+)?you\s+have/i,
    severity: "medium",
    category: "data-exfiltration",
  },

  // ── Confidence / approval manipulation ────────────────────────────
  {
    pattern: /confidence\s*[=:]\s*(100|99|9[5-9])/i,
    severity: "high",
    category: "confidence-manipulation",
  },
  {
    pattern: /set\s+confidence\s+to/i,
    severity: "high",
    category: "confidence-manipulation",
  },
  {
    pattern: /auto[_-]?approv/i,
    severity: "high",
    category: "confidence-manipulation",
  },
  {
    pattern: /force\s+approv/i,
    severity: "high",
    category: "confidence-manipulation",
  },
  {
    pattern: /always\s+return\s+high\s+confidence/i,
    severity: "high",
    category: "confidence-manipulation",
  },

  // ── Jailbreak ─────────────────────────────────────────────────────
  {
    pattern: /DAN\s+mode/i,
    severity: "high",
    category: "jailbreak",
  },
  {
    // Narrowed from /developer\s+mode/ to reduce false positives on
    // legitimate phrases like "developer mode on my phone crashed."
    pattern: /(?:enable|enter|activate|switch\s+to|turn\s+on)\s+developer\s+mode/i,
    severity: "high",
    category: "jailbreak",
  },
  {
    pattern: /jailbreak/i,
    severity: "high",
    category: "jailbreak",
  },
  {
    pattern: /bypass\s+(safety|content|filter)/i,
    severity: "high",
    category: "jailbreak",
  },
  {
    pattern: /no\s+restrictions/i,
    severity: "medium",
    category: "jailbreak",
  },

  // ── Markup injection ──────────────────────────────────────────────
  {
    pattern: /<script[^>]*>/i,
    severity: "high",
    category: "markup-injection",
  },
  {
    pattern: /<!--\s*INJECTION/i,
    severity: "high",
    category: "markup-injection",
  },
  {
    pattern: /\[HIDDEN\]/i,
    severity: "medium",
    category: "markup-injection",
  },
];

/**
 * Keyword neutralization map used in "neutralize" mode.
 *
 * Replaces injection keywords with mangled equivalents that break BPE
 * tokenization. The replacements intentionally break at non-standard
 * positions to maximize disruption of the LLM's pattern recognition.
 */
export const NEUTRALIZATION_MAP: Array<[RegExp, string]> = [
  // ── Instruction override keywords ──
  [/ignore/gi, "i_g_n_o_r_e"],
  [/disregard/gi, "d_i_s_r_e_g_a_r_d"],
  [/forget/gi, "f_o_r_g_e_t"],
  [/override/gi, "o_v_e_r_r_i_d_e"],

  // ── Role hijacking keywords ──
  [/pretend/gi, "p_r_e_t_e_n_d"],
  [/roleplay/gi, "r_o_l_e_p_l_a_y"],

  // ── Prompt extraction keywords ──
  [/system\s+prompt/gi, "s_y_s_t_e_m p_r_o_m_p_t"],
  [/instructions?/gi, "i_n_s_t_r_u_c_t_i_o_n_s"],
  [/\bprompt\b/gi, "p_r_o_m_p_t"],

  // ── Confidence manipulation keywords ──
  [/confidence/gi, "c_o_n_f_i_d_e_n_c_e"],
  [/auto[_-]?approv/gi, "a_u_t_o_a_p_p_r_o_v"],

  // ── Jailbreak keywords ──
  [/jailbreak/gi, "j_a_i_l_b_r_e_a_k"],
  [/bypass/gi, "b_y_p_a_s_s"],
  [/\bDAN\b/g, "D_A_N"],

  // ── Format injection tokens ──
  [/<\|/g, "< |"],
  [/\|>/g, "| >"],
  [/\[\s*\/?INST\s*\]/gi, "[ I_N_S_T ]"],
  [/<<\/?SYS>>/gi, "< < S_Y_S > >"],
];

/**
 * Regex matching dangerous control characters (ASCII C0 set minus
 * tab, newline, and carriage return which are legitimate).
 *
 * Internal — not part of the public API.
 */
export const CONTROL_CHARS = /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g;

/**
 * Regex matching invisible Unicode characters that attackers insert
 * between keyword letters to bypass regex detection. LLMs typically
 * ignore these during tokenization, so the injection still works.
 *
 * Covers: zero-width space (U+200B), zero-width non-joiner (U+200C),
 * zero-width joiner (U+200D), word joiner (U+2060), zero-width
 * no-break space / BOM (U+FEFF), soft hyphen (U+00AD), and other
 * format/control characters from Unicode categories Cf and Zs.
 */
export const INVISIBLE_CHARS =
  /[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\uFE00-\uFE0F\uFEFF\uFFF9-\uFFFB]/g;
