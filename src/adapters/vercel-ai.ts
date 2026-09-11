/**
 * Vercel AI SDK adapter — a `LanguageModelV1Middleware`/`LanguageModelV2Middleware`
 * that assesses the latest user message before it reaches the model.
 *
 * Structural types only (no `import("ai")`): this library stays zero-dependency,
 * and the AI SDK's middleware shape (`transformParams({ params })`) is small
 * enough to declare locally rather than depend on the real package.
 */
import { resolveGuard, isDetected, GuardBlockedError, type GuardAdapterOptions } from "./shared";

export { GuardBlockedError };

// ── Structural types mirroring the Vercel AI SDK ─────────────────────

interface TextPart {
  type: "text";
  text: string;
}

/** A prompt message's content: plain text, or SDK-style parts array. */
type MessageContent = string | ReadonlyArray<TextPart | { type: string; [key: string]: unknown }>;

interface PromptMessage {
  role: string;
  content: MessageContent;
}

interface LanguageModelCallParams {
  prompt: ReadonlyArray<PromptMessage>;
  [key: string]: unknown;
}

export interface GuardMiddleware {
  transformParams(args: { params: LanguageModelCallParams }): Promise<LanguageModelCallParams>;
}

// ── Helpers ───────────────────────────────────────────────────────────

function extractText(content: MessageContent): string {
  if (typeof content === "string") return content;
  return content
    .filter((part): part is TextPart => part.type === "text" && typeof part.text === "string")
    .map((part) => part.text)
    .join("\n");
}

function latestUserText(prompt: ReadonlyArray<PromptMessage>): string {
  for (let i = prompt.length - 1; i >= 0; i--) {
    if (prompt[i].role === "user") return extractText(prompt[i].content);
  }
  return "";
}

// ── Public API ────────────────────────────────────────────────────────

/**
 * Build AI-SDK middleware that guards the latest user message.
 *
 * Stream wrapping (`wrapGenerate`/`wrapStream`) is deliberately not
 * implemented — `transformParams` alone covers input-side guarding.
 *
 * @example
 * ```ts
 * import { wrapLanguageModel } from "ai";
 * import { guardMiddleware } from "llm-prompt-guard/adapters/vercel-ai";
 *
 * const model = wrapLanguageModel({
 *   model: openai("gpt-4o"),
 *   middleware: guardMiddleware({ mode: "block" }),
 * });
 * ```
 */
export function guardMiddleware(
  options: GuardAdapterOptions<{ params: LanguageModelCallParams }> = {}
): GuardMiddleware {
  const guard = resolveGuard(options.guard);
  const mode = options.mode ?? "block";

  return {
    async transformParams({ params }) {
      const text = latestUserText(params.prompt);
      if (!text) return params;

      const result = guard.assess(text);
      if (!isDetected(result)) return params;

      options.onDetect?.(result, { params });
      if (mode === "block") throw new GuardBlockedError(result);
      return params;
    },
  };
}
