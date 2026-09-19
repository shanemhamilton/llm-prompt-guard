"use strict";

// LLMPromptGuard is the IIFE global from dist/playground.global.js (built
// from src/index.ts via `npm run build:playground`). The root export now
// covers normalizeHtml and PROFILES too, so a single bundle/global serves
// the whole page.
const Guard = window.LLMPromptGuard;

// Fallback only — used if an older bundle without PROFILES is loaded.
const FALLBACK_PROFILES = ["default", "developer-tool", "data-assistant", "education"];

const els = {
  input: document.getElementById("input"),
  profileSelect: document.getElementById("profile-select"),
  htmlToggle: document.getElementById("html-toggle"),
  htmlSplitSection: document.getElementById("html-split-section"),
  htmlVisible: document.getElementById("html-visible"),
  htmlHidden: document.getElementById("html-hidden"),
  normalizeOutput: document.getElementById("normalize-output"),
  normalizeSignals: document.getElementById("normalize-signals"),
  scoreBarFill: document.getElementById("score-bar-fill"),
  scoreLabel: document.getElementById("score-label"),
  reasons: document.getElementById("reasons"),
  assessSignals: document.getElementById("assess-signals"),
  sanitizeOutput: document.getElementById("sanitize-output"),
  sanitizeMeta: document.getElementById("sanitize-meta"),
  copyBtn: document.getElementById("copy-report-btn"),
};

function populateProfiles() {
  const names = Guard.PROFILES ? Object.keys(Guard.PROFILES) : FALLBACK_PROFILES;
  for (const name of names) {
    const opt = document.createElement("option");
    opt.value = name;
    opt.textContent = name;
    els.profileSelect.appendChild(opt);
  }
}

// All innerHTML writes below go through escapeHtml first — the only raw
// markup inserted is the literal <mark> wrapper this file controls.
function escapeHtml(s) {
  return s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
}

/**
 * Minimal LCS-based diff so normalizeInput()'s changed characters can be
 * highlighted. O(n*m) DP — fine at interactive textarea sizes; skipped
 * above INPUT_DIFF_CAP so a large paste can't stall the 100ms debounce.
 */
const INPUT_DIFF_CAP = 4000;

function diffHighlight(before, after) {
  if (before.length > INPUT_DIFF_CAP || after.length > INPUT_DIFF_CAP) {
    return escapeHtml(after);
  }
  const n = before.length;
  const m = after.length;
  const dp = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = before[i] === after[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  let i = 0, j = 0;
  let out = "";
  let markBuf = "";
  const flushMark = () => {
    if (markBuf) {
      out += `<mark>${escapeHtml(markBuf)}</mark>`;
      markBuf = "";
    }
  };
  while (i < n && j < m) {
    if (before[i] === after[j]) {
      flushMark();
      out += escapeHtml(after[j]);
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      i++; // deletion from `before`, nothing to render
    } else {
      markBuf += after[j];
      j++;
    }
  }
  while (j < m) {
    markBuf += after[j];
    j++;
  }
  flushMark();
  return out;
}

function signalChips(container, signals) {
  container.innerHTML = "";
  const entries = [
    ["tagBlockPayload", signals.tagBlockPayload],
    ["interleavedInvisibles", signals.interleavedInvisibles > 0],
    ["suspiciousHomoglyphs", signals.suspiciousHomoglyphs],
    ["base64DecodedText", signals.base64DecodedText],
    ["truncatedForAnalysis", signals.truncatedForAnalysis],
  ];
  for (const [label, active] of entries) {
    const chip = document.createElement("span");
    chip.className = "chip" + (active ? " active" : "");
    chip.textContent = label;
    container.appendChild(chip);
  }
}

function scoreColor(score) {
  if (score >= 0.7) return "var(--bar-fill-high)";
  if (score >= 0.3) return "var(--bar-fill-mid)";
  return "var(--bar-fill-low)";
}

let lastReport = null;

function render() {
  const raw = els.input.value;
  const isHtml = els.htmlToggle.checked;
  let text = raw;

  els.htmlSplitSection.hidden = !isHtml;
  if (isHtml) {
    const html = Guard.normalizeHtml ? Guard.normalizeHtml(raw) : null;
    if (html) {
      els.htmlVisible.textContent = html.visible;
      els.htmlHidden.textContent = html.hidden;
      text = html.text;
    } else {
      els.htmlVisible.textContent = "(normalizeHtml not available in this build)";
      els.htmlHidden.textContent = "";
    }
  }

  // The profile select only takes effect through createGuard({ profile });
  // the standalone assess()/sanitize() exports always use the default profile.
  const profile = els.profileSelect.value;
  const guard = Guard.createGuard && profile ? Guard.createGuard({ profile }) : Guard;

  const normalized = Guard.normalizeInput(text);
  els.normalizeOutput.innerHTML = diffHighlight(text, normalized.text) || "&nbsp;";
  signalChips(els.normalizeSignals, normalized.signals);

  const assessed = guard.assess(text);
  const pct = Math.round(Math.min(1, assessed.score) * 100);
  els.scoreBarFill.style.width = pct + "%";
  els.scoreBarFill.style.background = scoreColor(assessed.score);
  els.scoreLabel.textContent = `score: ${assessed.score.toFixed(2)} · patternsDetected: ${assessed.patternsDetected} · hasHighSeverity: ${assessed.hasHighSeverity}`;
  els.reasons.innerHTML = assessed.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("");
  signalChips(els.assessSignals, assessed.signals);

  const sanitized = guard.sanitize(text, { maxLength: 5000, mode: "neutralize" });
  els.sanitizeOutput.textContent = sanitized.sanitized;
  els.sanitizeMeta.innerHTML = "";
  for (const [label, value] of [
    ["wasModified", sanitized.wasModified],
    ["wasBlocked", sanitized.wasBlocked],
    [`patternsDetected: ${sanitized.patternsDetected}`, sanitized.patternsDetected > 0],
  ]) {
    const chip = document.createElement("span");
    chip.className = "chip" + (value ? " active" : "");
    chip.textContent = typeof label === "string" && label.includes(":") ? label : `${label}: ${value}`;
    els.sanitizeMeta.appendChild(chip);
  }

  lastReport = { input: raw, normalized: normalized.text, assessed, sanitized };
}

let debounceTimer = null;
function scheduleRender() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(render, 100);
}

els.input.addEventListener("input", scheduleRender);
els.htmlToggle.addEventListener("change", render);
els.profileSelect.addEventListener("change", render);

els.copyBtn.addEventListener("click", async () => {
  if (!lastReport) return;
  const { input, normalized, assessed, sanitized } = lastReport;
  const md = [
    "## Bypass report — llm-prompt-guard",
    "",
    "**Input:**",
    "```",
    input,
    "```",
    "",
    "**Normalized:**",
    "```",
    normalized,
    "```",
    "",
    `**Verdict:** score=${assessed.score.toFixed(2)} hasHighSeverity=${assessed.hasHighSeverity} patternsDetected=${assessed.patternsDetected}`,
    `**Reasons:** ${assessed.reasons.join(", ") || "(none)"}`,
    `**sanitize() output:** \`${sanitized.sanitized}\` (wasModified=${sanitized.wasModified}, wasBlocked=${sanitized.wasBlocked})`,
  ].join("\n");
  try {
    await navigator.clipboard.writeText(md);
    els.copyBtn.textContent = "Copied!";
  } catch {
    els.copyBtn.textContent = "Copy failed — select text manually";
  }
  setTimeout(() => (els.copyBtn.textContent = "Copy bypass report"), 1500);
});

populateProfiles();
render();
