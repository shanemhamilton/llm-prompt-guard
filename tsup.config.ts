import { defineConfig } from "tsup";

export default defineConfig({
  // Two entries produce two bundles:
  //   dist/index.{js,mjs,d.ts}                — the main library
  //   dist/patterns/multilingual.{js,mjs,d.ts}
  //     — opt-in Spanish/French/German/Portuguese pattern packs,
  //       imported via the `llm-prompt-guard/patterns/multilingual`
  //       subpath export.
  entry: ["src/index.ts", "src/patterns/multilingual.ts"],
  format: ["cjs", "esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  minify: false,
  target: "es2020",
});
