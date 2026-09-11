/**
 * Subpath entry: `llm-prompt-guard/normalize` — just the normalization
 * primitives (Unicode de-smuggling + HTML visible/hidden text split),
 * for teams that only want the "make this text safe to look at" piece
 * without the pattern-matching guard.
 */
export { normalizeInput } from "./guard";
export { normalizeHtml } from "./html";
export type { HtmlNormalizeResult, HtmlSignals } from "./html";
