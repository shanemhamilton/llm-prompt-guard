import { defineConfig } from "tsup";

export default defineConfig([
  {
    // One bundle per subpath export, each mirrored under dist/ at the same
    // relative path (dist/index.{js,mjs,d.ts}, dist/patterns/multilingual.*,
    // dist/adapters/vercel-ai.*, ...):
    //   - index.ts                    — the main library
    //   - patterns/multilingual.ts    — opt-in ES/FR/DE/PT pattern packs
    //   - normalize.ts                — normalizeInput + normalizeHtml only
    //   - egress.ts                   — scanOutput + scanToolCall only
    //   - agentic.ts                  — MCP tool-poisoning/fingerprint/quarantine
    //   - adapters/*.ts               — per-framework middleware (Vercel AI SDK,
    //                                    LangChain, MCP client, Express, Hono)
    entry: [
      "src/index.ts",
      "src/patterns/multilingual.ts",
      "src/normalize.ts",
      "src/egress.ts",
      "src/agentic.ts",
      "src/adapters/vercel-ai.ts",
      "src/adapters/langchain.ts",
      "src/adapters/mcp.ts",
      "src/adapters/express.ts",
      "src/adapters/hono.ts",
    ],
    format: ["cjs", "esm"],
    dts: true,
    clean: true,
    sourcemap: true,
    minify: false,
    target: "es2020",
  },
  {
    // Browser IIFE bundle for the static playground (playground/index.html).
    // Exposes the whole root export (including normalizeHtml and PROFILES)
    // as `window.LLMPromptGuard`. Not part of the npm package — output
    // lives under playground/dist/, gitignored.
    entry: { playground: "src/index.ts" },
    format: ["iife"],
    globalName: "LLMPromptGuard",
    outDir: "playground/dist",
    minify: true,
    platform: "browser",
    dts: false,
    clean: false,
    sourcemap: false,
    target: "es2020",
  },
]);
