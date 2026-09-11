import type {
  AssessResult,
  ExternalTurnScore,
  NormalizationSignals,
  SessionAssessment,
  SessionConfig,
  SessionGuard,
  SessionState,
} from "./types";

/**
 * Multi-turn risk accumulation.
 *
 * Per-message scanning is structurally blind to attacks that distribute
 * intent across turns: Crescendo (arXiv 2404.01833) escalates gradually,
 * with every individual message scoring below any sane blocking
 * threshold. Accumulating risk across a conversation catches the shape
 * that no single turn reveals.
 *
 * This is deliberately counters-and-thresholds, not a model. It is
 * explainable, costs microseconds, and has no state beyond a handful of
 * numbers the caller can serialize alongside their own session storage.
 */

/** Per-turn score at or above which a turn counts as suspicious. */
const DEFAULT_SUSPICION_THRESHOLD = 0.3;
/** Cumulative score at or above which a session reads as escalating. */
const DEFAULT_ESCALATION_THRESHOLD = 1.5;

/** No detection signals fired — used to fill in the unscanned fields of an external turn. */
const EMPTY_SIGNALS: NormalizationSignals = {
  tagBlockPayload: false,
  interleavedInvisibles: 0,
  suspiciousHomoglyphs: false,
  base64DecodedText: false,
  truncatedForAnalysis: false,
};

function emptyState(): SessionState {
  return {
    turns: 0,
    cumulativeScore: 0,
    peakScore: 0,
    flaggedTurns: 0,
    escalating: false,
  };
}

/** Clamp an external score into [0, 1]; NaN and negative values read as 0. */
function clampScore(score: number): number {
  if (!Number.isFinite(score) || score < 0) return 0;
  return Math.min(score, 1);
}

/**
 * Session factory — takes the assessment function as a parameter so a
 * guard-scoped session picks up the caller's `extraPatterns` and
 * `disableCategories`, while the standalone `createSession` (exported
 * from the package root) binds it to the built-in patterns.
 *
 * Injecting the function also keeps this module free of any import
 * from `guard.ts`, which would otherwise form an import cycle.
 */
export function createSessionWith(
  assessFn: (input: string) => AssessResult,
  config: SessionConfig = {}
): SessionGuard {
  const suspicionThreshold =
    config.suspicionThreshold ?? DEFAULT_SUSPICION_THRESHOLD;
  const escalationThreshold =
    config.escalationThreshold ?? DEFAULT_ESCALATION_THRESHOLD;

  if (suspicionThreshold < 0 || escalationThreshold <= 0) {
    throw new RangeError(
      "SessionConfig thresholds must be non-negative (escalationThreshold positive)."
    );
  }

  let state = emptyState();

  /**
   * Normalize either input shape into an `AssessResult`. A string runs
   * through `assessFn` as before. An `ExternalTurnScore` skips
   * detection — its score is clamped, and any detection fields it
   * doesn't carry (`patternsDetected`, `hasHighSeverity`, `signals`,
   * `reasons`) default to empty/false. An `AssessResult` passed
   * straight through (it structurally satisfies `ExternalTurnScore`)
   * keeps its own detection fields unchanged, so `record(assess(text))`
   * behaves exactly like `record(text)`.
   */
  function resolveTurn(input: string | ExternalTurnScore): AssessResult {
    if (typeof input === "string") {
      return assessFn(input);
    }
    return {
      score: clampScore(input.score),
      patternsDetected: input.patternsDetected ?? 0,
      hasHighSeverity: input.hasHighSeverity ?? false,
      signals: input.signals ?? EMPTY_SIGNALS,
      reasons: input.reasons ?? [],
    };
  }

  return {
    record(input: string | ExternalTurnScore): SessionAssessment {
      const turn = resolveTurn(input);

      state = {
        turns: state.turns + 1,
        cumulativeScore: state.cumulativeScore + turn.score,
        peakScore: Math.max(state.peakScore, turn.score),
        flaggedTurns:
          state.flaggedTurns + (turn.score >= suspicionThreshold ? 1 : 0),
        escalating: false,
      };
      state.escalating = state.cumulativeScore >= escalationThreshold;

      return {
        turn,
        session: { ...state },
        shouldReview: turn.hasHighSeverity || state.escalating,
      };
    },

    state(): SessionState {
      return { ...state };
    },

    reset(): void {
      state = emptyState();
    },
  };
}

