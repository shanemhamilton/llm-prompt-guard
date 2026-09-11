/**
 * LangChain adapter — wraps any object with an `invoke(input, config?)`
 * method (LangChain's `Tool`/`StructuredTool`/`Runnable` shape) so its
 * input is assessed before the call and its string output is quarantined
 * after. Structural typing only — no `import("@langchain/*")`.
 */
import {
  resolveGuard,
  isDetected,
  isOutputUnsafe,
  GuardBlockedError,
  type GuardAdapterOptions,
} from "./shared";
import { scanOutput } from "../output";
import { wrapToolResult } from "../agentic";

export interface InvokableTool {
  name?: string;
  description?: string;
  schema?: unknown;
  invoke(input: unknown, config?: unknown): Promise<unknown>;
  [key: string]: unknown;
}

export interface LangChainGuardOptions extends GuardAdapterOptions<{ input: unknown }> {
  /** Assess the stringified input before calling `invoke`. Default `true`. */
  scanInput?: boolean;
  /** Quarantine a string result through `wrapToolResult` after `invoke`. Default `true`. */
  wrapOutput?: boolean;
}

function toText(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value ?? "");
}

/**
 * Wrap a LangChain tool/runnable with input assessment and output
 * quarantine, both backed by the guard's own `assess()`/`wrapToolResult()`.
 *
 * @example
 * ```ts
 * import { guardTool } from "llm-prompt-guard/adapters/langchain";
 *
 * const safeSearchTool = guardTool(searchTool, { mode: "block" });
 * await agentExecutor.invoke({ tools: [safeSearchTool] });
 * ```
 */
export function guardTool<T extends InvokableTool>(
  tool: T,
  options: LangChainGuardOptions = {}
): T {
  const guard = resolveGuard(options.guard);
  const mode = options.mode ?? "block";
  const scanInput = options.scanInput !== false;
  const wrapOutput = options.wrapOutput !== false;

  return {
    ...tool,
    async invoke(input: unknown, config?: unknown) {
      if (scanInput) {
        const result = guard.assess(toText(input));
        if (isDetected(result)) {
          options.onDetect?.(result, { input });
          if (mode === "block") throw new GuardBlockedError(result);
        }
      }

      const output = await tool.invoke(input, config);
      if (!wrapOutput || typeof output !== "string") return output;

      const scan = scanOutput(output);
      if (isOutputUnsafe(scan)) {
        options.onDetect?.(scan, { input });
        if (mode === "block") throw new GuardBlockedError(scan);
      }
      return wrapToolResult(output, { sourceName: tool.name ?? "langchain_tool" }).wrapped;
    },
  } as T;
}
