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
import { quarantineToolResult, withSystemClause } from "../agentic";
import type { OutputScanResult } from "../types";

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
  /**
   * Also treat plain outbound URLs in a tool result as unsafe. Default
   * `false`: a search or fetch tool legitimately returns links, so only
   * the exfiltration shapes (query-string images, data URLs, long
   * base64/hex blobs) block. Set `true` with `GuardConfig.allowedOrigins`
   * to restrict which hosts a result may link to.
   */
  flagOutboundUrls?: boolean;
}

function scanResult(scan: OutputScanResult, flagOutboundUrls: boolean): OutputScanResult {
  if (flagOutboundUrls) return scan;
  const findings = scan.findings.filter((f) => f.type !== "outbound-url");
  return { safe: findings.length === 0, findings };
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
  const flagOutboundUrls = options.flagOutboundUrls === true;

  const invoke = async (input: unknown, config?: unknown) => {
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
    const scan = scanResult(guard.scanOutput(toText(output)), flagOutboundUrls);
    if (isOutputUnsafe(scan)) {
      options.onDetect?.(scan, { input });
      if (mode === "block") throw new GuardBlockedError(scan);
    }
    if (!wrapOutput || typeof output !== "string") return output;
    return withSystemClause(
      quarantineToolResult(guard.sanitize, output, { sourceName: tool.name ?? "langchain_tool" })
    );
  };

  // A Proxy, not `{ ...tool }`: LangChain tools are class instances whose
  // methods live on the prototype and would be lost by spreading.
  return new Proxy(tool, {
    get(target, prop, receiver) {
      if (prop === "invoke") return invoke;
      const value = Reflect.get(target, prop, target);
      // Bound to the proxy, so entry points like `call`/`stream` that
      // reach `this.invoke` internally go through the guarded invoke.
      return typeof value === "function" ? value.bind(receiver) : value;
    },
  });
}
