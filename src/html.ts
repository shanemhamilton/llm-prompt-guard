/**
 * Dependency-free HTML normalizer: separates visible text from HIDDEN
 * text and reports hidden-text signals — the dominant indirect
 * prompt-injection vector in RAG/web ingestion (`display:none` divs,
 * zero-font spans, white-on-white text, HTML comments, `aria-hidden`,
 * off-screen positioning: invisible to a human, read verbatim by a
 * model once the raw HTML lands in its context).
 *
 * Regex/stack scanner, not a DOM parser — no `document.body` in a
 * zero-dependency Node/edge-runtime library. One tokenizer regex pass
 * plus an explicit nesting stack handles same-tag nesting correctly,
 * unlike a naive non-greedy `.*?</tag>`.
 *
 * ponytail: not a spec HTML5 tokenizer — `<script>`/`<style>` content
 * is scanned by the same regex as everything else, so a literal
 * `</script` or `<!--` inside a script string can confuse the boundary
 * (browsers treat these as raw-text elements). Upgrade path: a
 * dedicated raw-text scan if this ever proves exploitable.
 */

export interface HtmlSignals {
  hiddenElements: number; // elements judged hidden (style/attribute/class rules)
  comments: number; // HTML comments containing non-whitespace text
  hiddenChars: number; // hidden text length after whitespace collapse
  visibleChars: number; // visible text length after whitespace collapse
  hasHiddenText: boolean; // hiddenChars > 0
}

export interface HtmlNormalizeResult {
  /** Text a human would see: tags stripped, entities decoded, whitespace collapsed. */
  visible: string;
  /** All hidden text concatenated with `"\n"`, same normalization. */
  hidden: string;
  /** `visible + "\n" + hidden` — what callers should pass to `assess()`. */
  text: string;
  signals: HtmlSignals;
}

/** Code, not content — dropped entirely, never visible or hidden. */
const DROP_TAGS = new Set(["script", "style", "template", "noscript"]);
/** Produce a line break in `visible` so adjacent sentences don't glue together. */
const BLOCK_TAGS = new Set([
  "p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6",
  "section", "article", "td", "th",
]);
/** No closing tag; never pushed onto the nesting stack. */
const VOID_ELEMENTS = new Set([
  "area", "base", "br", "col", "embed", "hr", "img",
  "input", "link", "meta", "source", "track", "wbr",
]);

const HIDDEN_CLASS_RE = /\b(sr-only|visually-hidden|screen-reader-only|hidden|d-none)\b/i;
/** CSS px offset beyond which an absolutely/text-indented element is off-screen. */
const OFFSCREEN_THRESHOLD_PX = 1000;

// ── Style-attribute hidden rules ─────────────────────────────────────

const RE_DISPLAY_NONE = /display\s*:\s*none\b/i;
const RE_VISIBILITY_HIDDEN = /visibility\s*:\s*hidden\b/i;
// "Exactly 0": 0 / 0.0 / 0.00 match, 0.5 / 0.25 do not.
const RE_OPACITY_ZERO = /opacity\s*:\s*0(?!\.[0-9]*[1-9])\b/i;
const RE_FONT_SIZE_ZERO = /font-size\s*:\s*0(?!\.[0-9])(?:px|em|pt|%)?\b/i;
// White-on-white approximation: literal white values only, not every CSS
// color syntax (hsl(), currentColor tricks). Ceiling accepted per spec.
// (?=[^\w]|$) not \b: \b treats "...255,255)<end>" as a non-boundary
// (")" and end-of-string are both "non-word"), silently rejecting
// rgb(...) as the last declaration in a style attribute.
const RE_COLOR_WHITE =
  /(?<![\w-])color\s*:\s*(#fff(?:fff)?|white|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))(?=[^\w]|$)/i;
const RE_POSITION_ABSOLUTE = /position\s*:\s*absolute\b/i;
const RE_LEFT_PX = /(?:^|[\s;])left\s*:\s*(-?[0-9]+(?:\.[0-9]+)?)px/i;
const RE_TOP_PX = /(?:^|[\s;])top\s*:\s*(-?[0-9]+(?:\.[0-9]+)?)px/i;
const RE_TEXT_INDENT_PX = /text-indent\s*:\s*(-?[0-9]+(?:\.[0-9]+)?)px/i;
const RE_CLIP_RECT_ZERO = /clip\s*:\s*rect\(\s*0[\s,]+0[\s,]+0[\s,]+0\s*\)/i;
const RE_WIDTH_ZERO = /(?<![\w-])width\s*:\s*0(?:px)?\b/i;
const RE_HEIGHT_ZERO = /(?<![\w-])height\s*:\s*0(?:px)?\b/i;
const RE_OVERFLOW_HIDDEN = /overflow\s*:\s*hidden\b/i;

function isOffscreen(style: string): boolean {
  const indent = Number(RE_TEXT_INDENT_PX.exec(style)?.[1]);
  if (indent <= -OFFSCREEN_THRESHOLD_PX) return true;
  if (!RE_POSITION_ABSOLUTE.test(style)) return false;
  const left = Number(RE_LEFT_PX.exec(style)?.[1]);
  const top = Number(RE_TOP_PX.exec(style)?.[1]);
  return left <= -OFFSCREEN_THRESHOLD_PX || top <= -OFFSCREEN_THRESHOLD_PX;
}

function isHiddenByStyle(style: string): boolean {
  if (RE_DISPLAY_NONE.test(style)) return true;
  if (RE_VISIBILITY_HIDDEN.test(style)) return true;
  if (RE_OPACITY_ZERO.test(style)) return true;
  if (RE_FONT_SIZE_ZERO.test(style)) return true;
  if (RE_COLOR_WHITE.test(style)) return true;
  if (isOffscreen(style)) return true;
  if (RE_CLIP_RECT_ZERO.test(style)) return true;
  const widthZero = RE_WIDTH_ZERO.test(style);
  const heightZero = RE_HEIGHT_ZERO.test(style);
  if (widthZero && heightZero) return true;
  return heightZero && RE_OVERFLOW_HIDDEN.test(style);
}

// Fixed, precompiled attribute regexes — a 1MB doc can carry thousands of tags.
const ATTR_VALUE_GROUP = `("([^"]*)"|'([^']*)'|([^\\s"'>]+))`;
const ATTR_STYLE = new RegExp(`(?:^|\\s)style\\s*=\\s*${ATTR_VALUE_GROUP}`, "i");
const ATTR_CLASS = new RegExp(`(?:^|\\s)class\\s*=\\s*${ATTR_VALUE_GROUP}`, "i");
const ATTR_ARIA_HIDDEN = new RegExp(`(?:^|\\s)aria-hidden\\s*=\\s*${ATTR_VALUE_GROUP}`, "i");
const ATTR_TYPE = new RegExp(`(?:^|\\s)type\\s*=\\s*${ATTR_VALUE_GROUP}`, "i");
const ATTR_VALUE = new RegExp(`(?:^|\\s)value\\s*=\\s*${ATTR_VALUE_GROUP}`, "i");
const ATTR_HIDDEN_BOOL = /(?:^|\s)hidden(?:\s|=|\/|$)/i;

function extractAttr(re: RegExp, attrsStr: string): string | undefined {
  const m = re.exec(attrsStr);
  return m ? m[2] ?? m[3] ?? m[4] ?? "" : undefined;
}

function isElementHidden(attrsStr: string): boolean {
  if (ATTR_HIDDEN_BOOL.test(attrsStr)) return true;
  if (extractAttr(ATTR_ARIA_HIDDEN, attrsStr)?.toLowerCase() === "true") return true;
  const className = extractAttr(ATTR_CLASS, attrsStr);
  if (className && HIDDEN_CLASS_RE.test(className)) return true;
  const style = extractAttr(ATTR_STYLE, attrsStr);
  return !!style && isHiddenByStyle(style);
}

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: "\u00A0",
};
const ENTITY_RE = /&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z]+);/g;

function decodeEntities(text: string): string {
  return text.replace(ENTITY_RE, (whole, body: string) => {
    try {
      if (body[0] !== "#") return NAMED_ENTITIES[body.toLowerCase()] ?? whole;
      const isHex = body[1] === "x" || body[1] === "X";
      const codePoint = parseInt(isHex ? body.slice(2) : body.slice(1), isHex ? 16 : 10);
      return String.fromCodePoint(codePoint);
    } catch {
      return whole; // malformed numeric entity (bad code point) — leave as-is
    }
  });
}

function normalizeWhitespace(raw: string): string {
  const collapsedHorizontal = raw.replace(/[ \t\f\v\r\u00A0]+/g, " ");
  const collapsedAroundNewlines = collapsedHorizontal.replace(/ ?\n ?/g, "\n");
  return collapsedAroundNewlines.replace(/\n+/g, "\n").trim();
}

const COMMENT_OPEN = "<!--";
const COMMENT_CLOSE = "-->";
// Comment and tag alternatives match only the opener/name — the terminator
// ("-->" or the next ">") is then found with a linear indexOf scan (below)
// instead of a lazy [\s\S]*? quantifier or adjacent \s*/[^<>]* quantifiers
// that can both consume the same whitespace, either of which is quadratic
// on pathological input (CodeQL js/polynomial-redos).
const TOKEN_RE =
  /<!--|<\/(?<closeName>[A-Za-z][A-Za-z0-9:-]*)|<(?<openName>[A-Za-z][A-Za-z0-9:-]*)|[^<]+|</g;

interface Frame {
  name: string;
  isHidden: boolean;
  isSkip: boolean;
}

/** Mutable scan accumulator threaded through the token loop (keeps helpers to ≤3 params). */
interface ScanState {
  stack: Frame[];
  /** Count of frames on `stack` with isSkip / isHidden — kept in sync on
   * push and pop so context checks are O(1) instead of a stack scan per
   * token (which made deeply nested documents quadratic). */
  skipDepth: number;
  hiddenDepth: number;
  /** Open-frame count per tag name, so an unmatched closing tag is rejected
   * in O(1) instead of scanning the whole stack. */
  openCounts: Map<string, number>;
  visible: string[];
  hidden: string[];
  comments: number;
  hiddenElements: number;
}

const isSkipped = (s: ScanState): boolean => s.skipDepth > 0;
const isHiddenCtx = (s: ScanState): boolean => s.hiddenDepth > 0;
function findFrameIndex(state: ScanState, name: string): number {
  if (!state.openCounts.get(name)) return -1;
  const { stack } = state;
  for (let i = stack.length - 1; i >= 0; i--) {
    if (stack[i].name === name) return i;
  }
  return -1;
}

function pushBlockNewline(state: ScanState, name: string, extraHidden: boolean): void {
  if (!BLOCK_TAGS.has(name) || isSkipped(state)) return;
  (extraHidden || isHiddenCtx(state) ? state.hidden : state.visible).push("\n");
}

function handleHiddenInput(state: ScanState, attrsStr: string): void {
  const isHiddenType = extractAttr(ATTR_TYPE, attrsStr)?.toLowerCase() === "hidden";
  if (isHiddenType) state.hiddenElements++;
  if (isSkipped(state)) return;
  const value = decodeEntities(extractAttr(ATTR_VALUE, attrsStr) ?? "");
  if (isHiddenType || isHiddenCtx(state)) {
    state.hidden.push(value);
    return;
  }
  // A prefilled value is text the user sees; dropping it let an injection
  // in an ordinary <input value> bypass the scanner entirely.
  if (value) state.visible.push(value);
}

interface OpenTag {
  name: string;
  attrsStr: string;
  isSelfClosing: boolean;
}

function handleOpenTag(state: ScanState, tag: OpenTag): void {
  if (tag.name === "input") return handleHiddenInput(state, tag.attrsStr);

  const isDrop = DROP_TAGS.has(tag.name);
  const isVoid = tag.isSelfClosing || VOID_ELEMENTS.has(tag.name);
  const elementHidden = !isDrop && isElementHidden(tag.attrsStr);
  if (elementHidden) state.hiddenElements++;

  pushBlockNewline(state, tag.name, elementHidden);

  if (isVoid) return; // no matching close tag — nothing to push
  state.stack.push({ name: tag.name, isHidden: elementHidden, isSkip: isDrop });
  if (isDrop) state.skipDepth++;
  if (elementHidden) state.hiddenDepth++;
  state.openCounts.set(tag.name, (state.openCounts.get(tag.name) ?? 0) + 1);
}

function handleCloseTag(state: ScanState, name: string): void {
  const idx = findFrameIndex(state, name);
  if (idx === -1) return; // mismatched closing tag — tolerate malformed HTML

  pushBlockNewline(state, name, false);
  for (let i = state.stack.length - 1; i >= idx; i--) {
    const frame = state.stack[i];
    if (frame.isSkip) state.skipDepth--;
    if (frame.isHidden) state.hiddenDepth--;
    state.openCounts.set(frame.name, (state.openCounts.get(frame.name) ?? 1) - 1);
  }
  state.stack.length = idx; // pop this frame and any unbalanced descendants above it
}

function handleComment(state: ScanState, rawContent: string): void {
  if (isSkipped(state)) return;
  const content = decodeEntities(rawContent);
  if (content.trim() === "") return;
  state.comments++;
  state.hidden.push(content);
}

function handleText(state: ScanState, token: string): void {
  if (isSkipped(state)) return;
  (isHiddenCtx(state) ? state.hidden : state.visible).push(decodeEntities(token));
}

/**
 * Normalize HTML into visible text, hidden text, and hidden-text signals.
 * Covers CSS-hidden / `hidden` / `aria-hidden="true"` / screen-reader-only
 * classes / `<input type="hidden">` / HTML comments. `<script>`/`<style>`/
 * `<template>`/`<noscript>` contents are dropped — code, not content.
 * Never throws on malformed HTML.
 *
 * @example
 * ```ts
 * const { text, signals } = normalizeHtml(fetchedPageHtml);
 * if (signals.hasHiddenText) flagForReview(signals);
 * const result = assess(text); // hidden instructions are now visible to the scanner
 * ```
 */
export function normalizeHtml(html: string): HtmlNormalizeResult {
  if (!html.includes("<")) {
    return {
      visible: html,
      hidden: "",
      text: `${html}\n`,
      signals: {
        hiddenElements: 0,
        comments: 0,
        hiddenChars: 0,
        visibleChars: html.length,
        hasHiddenText: false,
      },
    };
  }

  const state: ScanState = {
    stack: [],
    skipDepth: 0,
    hiddenDepth: 0,
    openCounts: new Map(),
    visible: [],
    hidden: [],
    comments: 0,
    hiddenElements: 0,
  };

  TOKEN_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = TOKEN_RE.exec(html)) !== null) {
    const token = match[0];
    if (token === COMMENT_OPEN) {
      // Linear scan for the terminator instead of a lazy-quantifier regex
      // (see TOKEN_RE comment). Absent terminator: rest of document is the
      // comment.
      const closeIdx = html.indexOf(COMMENT_CLOSE, TOKEN_RE.lastIndex);
      const contentEnd = closeIdx === -1 ? html.length : closeIdx;
      handleComment(state, html.slice(TOKEN_RE.lastIndex, contentEnd));
      TOKEN_RE.lastIndex = closeIdx === -1 ? html.length : closeIdx + COMMENT_CLOSE.length;
    } else if (match.groups?.closeName !== undefined) {
      // No attrs to capture — just resume past the next ">" (or EOF).
      const gtIdx = html.indexOf(">", TOKEN_RE.lastIndex);
      TOKEN_RE.lastIndex = gtIdx === -1 ? html.length : gtIdx + 1;
      handleCloseTag(state, match.groups.closeName.toLowerCase());
    } else if (match.groups?.openName !== undefined) {
      const gtIdx = html.indexOf(">", TOKEN_RE.lastIndex);
      const attrsEnd = gtIdx === -1 ? html.length : gtIdx;
      const attrsStr = html.slice(TOKEN_RE.lastIndex, attrsEnd);
      TOKEN_RE.lastIndex = gtIdx === -1 ? html.length : gtIdx + 1;
      handleOpenTag(state, {
        name: match.groups.openName.toLowerCase(),
        attrsStr,
        isSelfClosing: /\/\s*$/.test(attrsStr),
      });
    } else {
      handleText(state, token); // plain text, or a stray "<"
    }
  }

  const visible = normalizeWhitespace(state.visible.join(""));
  const hidden = normalizeWhitespace(state.hidden.join(""));

  return {
    visible,
    hidden,
    text: `${visible}\n${hidden}`,
    signals: {
      hiddenElements: state.hiddenElements,
      comments: state.comments,
      hiddenChars: hidden.length,
      visibleChars: visible.length,
      hasHiddenText: hidden.length > 0,
    },
  };
}
