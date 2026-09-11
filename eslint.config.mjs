import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/", "coverage/", "playground/dist/"] },
  js.configs.recommended,
  tseslint.configs.recommended,
  {
    files: ["**/*.ts"],
    rules: {
      // Underscore-prefixed args are the documented "intentionally unused" marker.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
  {
    // Detection patterns match control characters and lone combining marks
    // on purpose — stripping them regardless of grapheme boundaries is the
    // whole point of the sanitizer.
    files: ["src/patterns.ts", "src/patterns/**/*.ts"],
    rules: {
      "no-control-regex": "off",
      "no-misleading-character-class": "off",
    },
  },
  {
    // Static playground page — plain browser script, not part of the
    // TypeScript project, so it needs browser globals instead of Node's.
    files: ["playground/**/*.js"],
    languageOptions: {
      globals: {
        window: "readonly",
        document: "readonly",
        navigator: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        console: "readonly",
        LLMPromptGuard: "readonly",
      },
    },
  },
);
