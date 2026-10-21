/**
 * MCP client adapter — wraps a client's `listTools()` to scan every
 * advertised tool for poisoning and fingerprint it for rug-pull
 * detection (a server silently swapping a tool's description/schema
 * after approval), and wraps `callTool()` (if present) to quarantine
 * results. Structural typing only — no `import("@modelcontextprotocol/*")`.
 */
import { resolveGuard, type GuardAdapterOptions } from "./shared";
import {
  scanToolDefinition,
  fingerprintTool,
  quarantineToolResult,
  withSystemClause,
} from "../agentic";
import type { ToolDefinition } from "../types";

export interface McpToolsResult {
  tools: ToolDefinition[];
  [key: string]: unknown;
}

export interface McpClient {
  listTools(...args: unknown[]): Promise<McpToolsResult>;
  callTool?(...args: unknown[]): Promise<unknown>;
  [key: string]: unknown;
}

export interface McpGuardOptions extends GuardAdapterOptions<{ tool: ToolDefinition }> {
  /** Called when a previously-seen tool's fingerprint changes between `listTools()` calls. */
  onDrift?: (name: string, before: string, after: string) => void;
}

/** A single MCP `CallToolResult` content item — text, image, or embedded resource. Structural only. */
interface McpContentItem {
  type: string;
  text?: string;
  resource?: { text?: string; [key: string]: unknown };
  [key: string]: unknown;
}

/**
 * Quarantine every text-bearing item in a `content` array in place —
 * `text` items and `resource` items carrying `resource.text` — leaving
 * image/blob/other items untouched. Rebuilding `content` as a single
 * joined text item (the previous behavior) silently dropped non-text
 * items and any `resource.text`.
 */
function quarantineContentItems(
  content: unknown[],
  guard: ReturnType<typeof resolveGuard>,
  sourceName: string
): unknown[] {
  return content.map((item) => {
    if (!item || typeof item !== "object") return item;
    const entry = item as McpContentItem;

    if (entry.type === "text" && typeof entry.text === "string") {
      return { ...entry, text: quarantineText(guard, entry.text, sourceName) };
    }
    if (entry.type === "resource" && typeof entry.resource?.text === "string") {
      return {
        ...entry,
        resource: {
          ...entry.resource,
          text: quarantineText(guard, entry.resource.text, sourceName),
        },
      };
    }
    return entry;
  });
}

/** Quarantine a tool result through the caller's guard, so `extraPatterns`/`disableCategories` are honored. */
function quarantineText(guard: ReturnType<typeof resolveGuard>, text: string, sourceName: string): string {
  return withSystemClause(
    quarantineToolResult(guard.sanitize, text, { sourceName })
  );
}

/**
 * Wrap an MCP client so tool definitions are scanned and fingerprinted
 * on every `listTools()` call, and tool results are quarantined.
 *
 * @example
 * ```ts
 * import { guardMcpClient } from "llm-prompt-guard/adapters/mcp";
 *
 * const client = guardMcpClient(rawMcpClient, {
 *   mode: "block",
 *   onDrift: (name) => console.warn(`Tool "${name}" changed after approval`),
 * });
 * const { tools } = await client.listTools(); // poisoned tools already filtered
 * ```
 */
export function guardMcpClient<T extends McpClient>(client: T, options: McpGuardOptions = {}): T {
  // `options.guard` isn't wired into `scanToolDefinition`/`fingerprintTool`:
  // those scan tool *definitions* with the library's built-in pattern set
  // and don't accept a guard instance. It IS honored below for `callTool`
  // result quarantining, so a caller's `extraPatterns`/`disableCategories`
  // apply to tool results.
  const guard = resolveGuard(options.guard);
  const mode = options.mode ?? "block";
  const fingerprints = new Map<string, string>();

  async function guardedListTools(...args: unknown[]): Promise<McpToolsResult> {
    const raw = await client.listTools(...args);
    const kept: ToolDefinition[] = [];

    for (const tool of raw.tools) {
      const scan = scanToolDefinition(tool);
      if (!scan.safe) {
        options.onDetect?.(scan, { tool });
        if (mode === "block") continue; // poisoned — drop from the advertised list
      }

      const { digest } = await fingerprintTool(tool);
      const previous = fingerprints.get(tool.name);
      if (previous !== undefined && previous !== digest) {
        options.onDrift?.(tool.name, previous, digest);
      }
      fingerprints.set(tool.name, digest);

      kept.push(tool);
    }

    return { ...raw, tools: kept };
  }

  const overrides: Partial<McpClient> = { listTools: guardedListTools };

  if (client.callTool) {
    overrides.callTool = async (...args: unknown[]) => {
      const result = await client.callTool!(...args);
      if (typeof result === "string") {
        return quarantineText(guard, result, "mcp_tool");
      }
      if (result && typeof result === "object" && Array.isArray((result as { content?: unknown }).content)) {
        const content = (result as { content: unknown[] }).content;
        return { ...(result as object), content: quarantineContentItems(content, guard, "mcp_tool") };
      }
      return result;
    };
  }

  // A Proxy, not `{ ...client }`: real SDK clients are class instances whose
  // methods (close, connect, …) live on the prototype and would be lost.
  return new Proxy(client, {
    get(target, prop) {
      if (Object.prototype.hasOwnProperty.call(overrides, prop)) return overrides[prop as keyof McpClient];
      const value = Reflect.get(target, prop, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}
