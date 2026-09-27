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

export { GuardBlockedError };

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
  /**
   * Wrap a string result through `wrapToolResult` after `invoke`, adding
   * quarantine delimiters. Default `true`. In `mode: "block"`, output is
   * scanned for exfiltration regardless of this option — set to `false`
   * to skip only the delimiter wrapping, not the scan.
   */
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

      // Structured results are scanned via their JSON text so an exfil URL
      // inside an object is still caught. Scanning runs even when
      // wrapOutput is false — that option only controls whether a clean
      // string result also gets quarantine delimiters, not whether block
      // mode is allowed to see exfiltration-shaped output.
      const scan = scanOutput(toText(output));
      if (isOutputUnsafe(scan)) {
        options.onDetect?.(scan, { input });
        if (mode === "block") throw new GuardBlockedError(scan);
      }
      if (!wrapOutput || typeof output !== "string") return output;
      return wrapToolResult(output, { sourceName: tool.name ?? "langchain_tool" }).wrapped;
    },
  } as T;
}
