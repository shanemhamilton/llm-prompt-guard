import type { InjectionPattern } from "./types";

/**
 * A named deployment context that pre-tunes the built-in pattern set for
 * a specific kind of application. General-purpose chat assistants should
 * use `"default"` (or omit `profile` entirely); an app that is
 * *structurally* a developer tool, a data assistant, or an education
 * tool can pick the matching profile to drop categories and patterns
 * that are false-positive-prone for that domain but still meaningful
 * elsewhere.
 */
export type GuardProfile =
  | "default"
  | "developer-tool"
  | "data-assistant"
  | "education";

/** Category and pattern-id overrides applied for one {@link GuardProfile}. */
export interface ProfileRules {
  /** Built-in categories to disable entirely, unioned with `GuardConfig.disableCategories`. */
  disableCategories: string[];
  /** Built-in pattern `id`s whose severity is rewritten to `"low"`. */
  demoteToLow: string[];
}

/**
 * All role-hijacking pattern ids. `education` demotes every one of them
 * to low: a tutoring tool routinely asks a model to assume a persona
 * ("roleplay as Abraham Lincoln", "pretend to be Napoleon"), including
 * personas an admin/security-flavored regex might otherwise flag.
 */
const ROLE_HIJACKING_IDS = [
  "role.you-are-now",
  "role.pretend-to-be",
  "role.act-as",
  "role.roleplay-as",
  "role.assume-role-of",
  "role.you-must-now",
  "role.privileged-persona",
  "role.act-as-first-person-directive",
  "role.act-as-execute-command",
  "role.pretend-capability-claim",
];

export const PROFILES: Record<GuardProfile, ProfileRules> = {
  default: {
    disableCategories: [],
    demoteToLow: [],
  },
  "developer-tool": {
    // Developers legitimately paste ChatML/JSON/`<script>` snippets while
    // discussing prompt formats or debugging front-end code.
    disableCategories: ["markup-injection", "format-injection"],
    demoteToLow: [],
  },
  "data-assistant": {
    // A SQL/data assistant is *asked* to list, dump, and export the
    // user's own tables all day — that is the product, not an attack.
    disableCategories: ["data-exfiltration"],
    demoteToLow: [],
  },
  education: {
    disableCategories: [],
    demoteToLow: ROLE_HIJACKING_IDS,
  },
};

/** Look up a profile's rules, defaulting to `"default"` when omitted. */
export function getProfileRules(profile: GuardProfile | undefined): ProfileRules {
  return PROFILES[profile ?? "default"];
}

/**
 * Rewrite the severity of every pattern whose `id` is in the profile's
 * `demoteToLow` list to `"low"`. Patterns without a matching id (or
 * user-supplied `extraPatterns`, which never carry a builtin id) pass
 * through unchanged.
 */
export function applyProfileDemotions(
  patterns: InjectionPattern[],
  profile: GuardProfile | undefined
): InjectionPattern[] {
  const demoteIds = getProfileRules(profile).demoteToLow;
  if (demoteIds.length === 0) return patterns;
  const demote = new Set(demoteIds);
  return patterns.map((p) =>
    p.id && demote.has(p.id) ? { ...p, severity: "low" as const } : p
  );
}
