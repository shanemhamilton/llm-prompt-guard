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
  /** Reject (400) when `field` is absent instead of passing through. Default `false`. */
  requireField?: boolean;
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
    if (req.body === undefined) {
      // Almost always a missing body parser; passing through would leave
      // the route unguarded without any sign of it.
      return next(new Error("llm-prompt-guard: req.body is undefined — mount a body parser before guardExpress"));
    }
    const value = req.body[field];
    if (value === undefined || value === null) {
      if (!options.requireField) return next();
      res.status(400).json({ error: "prompt_rejected" });
      return;
    }
    // The body is attacker-controlled JSON: a payload wrapped in an array or
    // object must still be assessed, not waved through. Stringify like the
    // LangChain adapter does for non-string input.
    const text = typeof value === "string" ? value : JSON.stringify(value);

    const result = guard.assess(text);
    if (!isDetected(result)) return next();

    options.onDetect?.(result, { req });
    if (mode === "block") {
      res.status(400).json({ error: "prompt_rejected" });
      return;
    }
    req.guard = result;
    next();
  };
}
