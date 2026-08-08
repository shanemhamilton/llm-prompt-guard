import type {
  AssessResult,
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

function emptyState(): SessionState {
  return {
    turns: 0,
    cumulativeScore: 0,
    peakScore: 0,
    flaggedTurns: 0,
    escalating: false,
  };
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

  return {
    record(input: string): SessionAssessment {
      const turn = assessFn(input);

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

