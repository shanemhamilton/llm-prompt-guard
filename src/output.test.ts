import { generateCanary, createOutputValidator, createGuard } from "./index";
import type { OutputValidatorConfig } from "./types";

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
