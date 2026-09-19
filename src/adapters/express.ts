/**
 * Express adapter — middleware `(req, res, next)` that assesses one
 * field of `req.body`. Express-only: `res.status(code).json(body)` is
 * Express's response API, not Connect's, so this middleware doesn't run
 * unmodified on a bare Connect app.
 */
import { resolveGuard, isDetected, type GuardAdapterOptions } from "./shared";

export interface ExpressGuardOptions extends GuardAdapterOptions<{ req: ExpressRequest }> {
  /** Field to read off `req.body`. Default `"prompt"`. */
  field?: string;
}

export interface ExpressRequest {
  body?: Record<string, unknown>;
  guard?: unknown;
  [key: string]: unknown;
}

export interface ExpressResponse {
  status(code: number): ExpressResponse;
  json(body: unknown): void;
  [key: string]: unknown;
}

export type ExpressNext = (err?: unknown) => void;

/**
 * Build Express middleware that guards `req.body[field]`.
 *
 * @example
 * ```ts
 * import { guardExpress } from "llm-prompt-guard/adapters/express";
 *
 * app.post("/chat", guardExpress({ mode: "block" }), handler);
 * ```
 */
export function guardExpress(options: ExpressGuardOptions = {}) {
  const guard = resolveGuard(options.guard);
  const mode = options.mode ?? "block";
  const field = options.field ?? "prompt";

  return (req: ExpressRequest, res: ExpressResponse, next: ExpressNext): void => {
    const value = req.body?.[field];
    if (value === undefined || value === null) return next();
    // The body is attacker-controlled JSON: a payload wrapped in an array or
    // object must still be assessed, not waved through. Stringify like the
    // LangChain adapter does for non-string input.
    const text = typeof value === "string" ? value : JSON.stringify(value);

    const result = guard.assess(text);
    if (!isDetected(result)) return next();

    options.onDetect?.(result, { req });
    if (mode === "block") {
      res.status(400).json({ error: "prompt_rejected", reasons: result.reasons });
      return;
    }
    req.guard = result;
    next();
  };
}
