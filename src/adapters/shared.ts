/**
 * Common option shape and assess/block logic shared by every framework
 * adapter. Adapters never re-implement detection — they all resolve to
 * the guard's own `assess()` (input side) or `scanOutput()` (output side).
 */
import { createGuard } from "../guard";
import type { AssessResult, OutputScanResult, ToolScanResult } from "../types";

export type GuardMode = "block" | "flag";

export interface GuardAdapterOptions<Context = unknown> {
  /** Guard instance to reuse. Defaults to a fresh `createGuard()`. */
  guard?: ReturnType<typeof createGuard>;
  /** `"block"` throws/rejects on detection; `"flag"` passes through and calls `onDetect`. */
  mode?: GuardMode;
  /**
   * Called (in either mode) on detection: an `assess()` pattern match on the
   * input side, an unsafe `scanOutput()` finding on the output side, or an
   * unsafe `scanToolDefinition()` result for the MCP adapter.
   */
  onDetect?: (result: AssessResult | OutputScanResult | ToolScanResult, context: Context) => void;
}

export function resolveGuard(
  guard: ReturnType<typeof createGuard> | undefined
): ReturnType<typeof createGuard> {
  return guard ?? createGuard();
}

/** A pattern matched — the one detection signal every adapter blocks/flags on. */
export function isDetected(result: AssessResult): boolean {
  return result.patternsDetected > 0 || result.hasHighSeverity;
}

/** An exfiltration-shape finding — the output-side counterpart of {@link isDetected}. */
export function isOutputUnsafe(result: OutputScanResult): boolean {
  return !result.safe;
}

/** Thrown by every adapter's `"block"` mode. Carries the triggering assess/scan result. */
export class GuardBlockedError extends Error {
  readonly result: AssessResult | OutputScanResult;

  constructor(
    result: AssessResult | OutputScanResult,
    message = "llm-prompt-guard: blocked a prompt-injection detection"
  ) {
    super(message);
    this.name = "GuardBlockedError";
    this.result = result;
  }
}
