/**
 * Hono adapter — structural middleware `async (c, next) => Response | void`
 * that assesses one field of the JSON request body. Structural typing
 * only — no `import("hono")`.
 */
import { resolveGuard, isDetected, type GuardAdapterOptions } from "./shared";

export interface HonoGuardOptions extends GuardAdapterOptions<{ c: HonoContext }> {
  /** Field to read off the parsed JSON body. Default `"prompt"`. */
  field?: string;
}

export interface HonoContext {
  req: { json(): Promise<Record<string, unknown>> };
  json(body: unknown, status?: number): unknown;
  set(key: string, value: unknown): void;
  [key: string]: unknown;
}

export type HonoNext = () => Promise<void>;

/**
 * Build Hono middleware that guards one field of the JSON request body.
 *
 * @example
 * ```ts
 * import { guardHono } from "llm-prompt-guard/adapters/hono";
 *
 * app.post("/chat", guardHono({ mode: "block" }), handler);
 * ```
 */
export function guardHono(options: HonoGuardOptions = {}) {
  const guard = resolveGuard(options.guard);
  const mode = options.mode ?? "block";
  const field = options.field ?? "prompt";

  return async (c: HonoContext, next: HonoNext) => {
    let body: Record<string, unknown>;
    try {
      body = await c.req.json();
    } catch {
      return next(); // non-JSON body — nothing to guard, let the handler decide
    }

    const value = body[field];
    if (value === undefined || value === null) return next();
    // The body is attacker-controlled JSON: a payload wrapped in an array or
    // object must still be assessed, not waved through. Stringify like the
    // LangChain adapter does for non-string input.
    const text = typeof value === "string" ? value : JSON.stringify(value);

    const result = guard.assess(text);
    if (!isDetected(result)) return next();

    options.onDetect?.(result, { c });
    if (mode === "block") {
      return c.json({ error: "prompt_rejected", reasons: result.reasons }, 400);
    }
    c.set("guard", result);
    await next();
  };
}
