/**
 * Multilingual injection-detection patterns (opt-in).
 *
 * The built-in pattern set covers English only. Most public prompt
 * injection jailbreaks are authored in English, but attackers do pivot
 * to other common languages once a model provider rolls out
 * English-only filters. These arrays provide the five most dangerous
 * categories (instruction override, role hijack, prompt extraction,
 * jailbreak, filter bypass) in Spanish, French, German, and Portuguese.
 *
 * @example
 * ```ts
 * import { createGuard } from "llm-prompt-guard";
 * import { spanish, french } from "llm-prompt-guard/patterns/multilingual";
 *
 * const guard = createGuard({
 *   extraPatterns: [...spanish, ...french],
 * });
 * ```
 *
 * **Design note.** The guard's preprocess pipeline applies NFKD
 * decomposition and strips combining diacritical marks (U+0300–U+036F)
 * before running detection. That means accented input like `"así"` is
 * normalized to `"asi"` before matching. The patterns below are
 * therefore written on the UNACCENTED form — so, for example, the
 * Spanish "actúa como" regex matches `actua\s+como`, not the accented
 * original. Patterns still carry the `ui` flags for correctness on
 * runtimes that feed the patterns un-normalized (tests, direct use
 * without the guard) and for Unicode-safe character-class semantics.
 */
import type { InjectionPattern } from "../types";

// ── Spanish ──────────────────────────────────────────────────────────
//
// All forms listed below are real Spanish constructions from observed
// jailbreak corpora. Accented variants (e.g., "actúa") normalize to
// their unaccented form before match time, so we only regex the latter.
//
// prettier-ignore
export const spanish: InjectionPattern[] = [
  {
    // "ignora (todas) las instrucciones (anteriores|previas)"
    // "olvida (todas) las instrucciones (anteriores|previas)"
    // "desecha las instrucciones anteriores"
    pattern: /\b(ignora|olvida|desecha)\s+(todas\s+)?(las\s+)?instrucciones\s+(anteriores|previas|anteriormente)/ui,
    severity: "high",
    category: "instruction-override-es",
  },
  {
    // "ahora eres (un|una)"  —  role hijack
    // "actua como (un|una)" (normalized from "actúa como")
    // "haz (el papel|el rol) de"
    pattern: /\b(ahora\s+eres|actua\s+como|haz\s+el\s+(papel|rol)\s+de)\b/ui,
    severity: "high",
    category: "role-hijacking-es",
  },
  {
    // "revela (el|tu|tus) (prompt|instrucciones|sistema)"
    // "muestra(me)? el prompt del sistema"  (normalized "muéstrame")
    // "cual es tu prompt del sistema"       (normalized "cuál")
    pattern: /\b(revela\s+(el|tu|tus)\s+(prompt|instrucciones|sistema)|muestrame\s+(el|tu)\s+prompt|cual\s+es\s+tu\s+prompt)/ui,
    severity: "high",
    category: "prompt-extraction-es",
  },
  {
    // "modo DAN" — loanword jailbreak name, same in Spanish corpora.
    // "modo desarrollador" — "developer mode" calque.
    pattern: /\bmodo\s+(DAN|desarrollador)\b/ui,
    severity: "high",
    category: "jailbreak-es",
  },
  {
    // "evita los filtros"
    // "elude (los|las) restricciones"
    // "salta(te)? los filtros de seguridad"   (normalized "sáltate")
    pattern: /\b(evita|elude|saltate|salta)\s+(los|las)\s+(filtros|restricciones|controles)\s+(de\s+seguridad)?/ui,
    severity: "high",
    category: "filter-bypass-es",
  },
];

// ── French ───────────────────────────────────────────────────────────
//
// French accents (é, è, ê, à, ô, etc.) are stripped by NFKD before
// matching. The patterns are written on the resulting ASCII forms, so
// e.g. "précédentes" → "precedentes" and "révèle" → "revele".
//
// prettier-ignore
export const french: InjectionPattern[] = [
  {
    // "ignore(z) toutes les instructions precedentes"  ("précédentes")
    // "oublie(z) les instructions precedentes"
    pattern: /\b(ignore|ignorez|oublie|oubliez)\s+(toutes\s+)?(les\s+)?instructions?\s+(precedente|precedentes|anterieure|anterieures)/ui,
    severity: "high",
    category: "instruction-override-fr",
  },
  {
    // "tu es (maintenant)? (un|une)"
    // "agis comme (un|une)"       role hijack
    // "fais semblant d'etre"      (normalized "d'être")
    pattern: /\b(tu\s+es\s+maintenant|agis\s+comme|fais\s+semblant\s+d['"]?etre)\b/ui,
    severity: "high",
    category: "role-hijacking-fr",
  },
  {
    // "revele (ton|le) prompt (systeme)?"     ("révèle", "système")
    // "montre(-| )moi (ton|le) prompt"
    // "quel est ton prompt (systeme)?"
    pattern: /\b(revele\s+(ton|le)\s+prompt|montre[-\s]+moi\s+(ton|le)\s+prompt|quel\s+est\s+ton\s+prompt)/ui,
    severity: "high",
    category: "prompt-extraction-fr",
  },
  {
    // "mode DAN" — same loanword.
    // "mode developpeur"                       (normalized "développeur")
    pattern: /\bmode\s+(DAN|developpeur)\b/ui,
    severity: "high",
    category: "jailbreak-fr",
  },
  {
    // "contourne les filtres"
    // "ignore les restrictions (de securite)?" ("sécurité")
    // "desactive les filtres"                  ("désactive")
    pattern: /\b(contourne|desactive)\s+(les\s+)?(filtres|restrictions|securites?|protections?)\b/ui,
    severity: "high",
    category: "filter-bypass-fr",
  },
];

// ── German ───────────────────────────────────────────────────────────
//
// German NFKD strips umlauts (ä→a, ö→o, ü→u) and decomposes ß (which
// NFKD leaves as ß — but note some German corpora already substitute
// "ss", and attackers swap both forms). Patterns below match both
// "beschrankungen" (normalized) and the less-common post-hand-ascii form.
// The compiled regex runs on the normalized input, so stripped-umlaut
// forms are what we target.
//
// prettier-ignore
export const german: InjectionPattern[] = [
  {
    // "ignoriere (alle) (vorherigen|vorigen) (anweisungen|anleitungen)"
    // "vergiss (alle)? (vorherigen|vorigen) anweisungen"
    pattern: /\b(ignoriere|vergiss)\s+(alle\s+)?(vorherigen|vorigen|fruheren)\s+(anweisungen|anleitungen|befehle)/ui,
    severity: "high",
    category: "instruction-override-de",
  },
  {
    // "du bist jetzt (ein|eine)"
    // "verhalte dich wie (ein|eine)"
    // "spiele (die rolle von|einen|eine)"
    pattern: /\b(du\s+bist\s+jetzt|verhalte\s+dich\s+wie|spiele\s+(die\s+rolle\s+von|einen|eine))\b/ui,
    severity: "high",
    category: "role-hijacking-de",
  },
  {
    // "zeige (mir)? (deinen|den) system(-|\s)?prompt"
    // "offenbare (deine|die) (anweisungen|systemanweisungen)"
    // "was ist dein system prompt"
    pattern: /\b(zeige\s+(mir\s+)?(deinen|den)\s+system[-\s]?prompt|offenbare\s+(deine|die)\s+anweisungen|was\s+ist\s+dein\s+system[-\s]?prompt)/ui,
    severity: "high",
    category: "prompt-extraction-de",
  },
  {
    // "DAN modus" / "entwicklermodus"           ("developer mode" calque)
    pattern: /\b(DAN\s+modus|entwicklermodus|DAN[-\s]?modus)\b/ui,
    severity: "high",
    category: "jailbreak-de",
  },
  {
    // "umgehe (die)? (sicherheits-?)?(filter|richtlinien|beschrankungen)"
    //    (umlaut on "beschränkungen" → "beschrankungen" after NFKD)
    pattern: /\bumgehe\s+(die\s+)?(sicherheits[-\s]?)?(filter|richtlinien|beschrankungen|einschrankungen)/ui,
    severity: "high",
    category: "filter-bypass-de",
  },
];

// ── Portuguese ───────────────────────────────────────────────────────
//
// Portuguese NFKD strips ã→a, ç→c, ó→o, etc. So "instruções" → "instrucoes",
// "você" → "voce", "segurança" → "seguranca".
//
// prettier-ignore
export const portuguese: InjectionPattern[] = [
  {
    // "ignore/ignora (todas) as instrucoes (anteriores|previas)"
    // "esqueca (todas)? as instrucoes"          ("esqueça")
    pattern: /\b(ignore|ignora|esqueca)\s+(todas\s+)?(as\s+)?instrucoes\s+(anteriores|previas)/ui,
    severity: "high",
    category: "instruction-override-pt",
  },
  {
    // "voce e agora (um|uma)"                   ("você é")
    // "aja como (um|uma)"
    // "finja ser"
    pattern: /\b(voce\s+e\s+agora|aja\s+como|finja\s+ser|faca\s+o\s+papel\s+de)\b/ui,
    severity: "high",
    category: "role-hijacking-pt",
  },
  {
    // "revele (o|seu|o seu) prompt"            — accept "o seu" together
    // "mostre(-| )me (o|seu|o seu) prompt"
    // "qual e (o|seu|o seu) prompt (do sistema)?"
    pattern: /\b(revele\s+(o\s+)?(seu\s+)?prompt|mostre[-\s]+me\s+(o\s+)?(seu\s+)?prompt|qual\s+e\s+(o\s+)?(seu\s+)?prompt)/ui,
    severity: "high",
    category: "prompt-extraction-pt",
  },
  {
    // "modo DAN"
    // "modo desenvolvedor"
    pattern: /\bmodo\s+(DAN|desenvolvedor)\b/ui,
    severity: "high",
    category: "jailbreak-pt",
  },
  {
    // "ignore os filtros de seguranca"         ("segurança")
    // "contorne as (restricoes|protecoes)"     ("restrições", "proteções")
    pattern: /\b(ignore\s+os\s+filtros|contorne\s+(as|os)\s+(restricoes|protecoes|filtros))/ui,
    severity: "high",
    category: "filter-bypass-pt",
  },
];
