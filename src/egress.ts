/**
 * Subpath entry: `llm-prompt-guard/egress` — output-side scanning only
 * (LLM response text + agent tool-call arguments), for teams that only
 * want to guard what leaves the model, not what goes in.
 */
export { scanOutput } from "./output";
export type { OutputScanResult, ExfilFinding, ExfilFindingType } from "./types";
export { scanToolCall } from "./tool-call";
export type {
  ToolCallScanOptions,
  ToolCallFindingType,
  ToolCallFinding,
  ToolCallScanResult,
} from "./tool-call";
