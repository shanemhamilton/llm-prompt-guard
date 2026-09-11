import { scanToolCall } from "./tool-call";

// ── unapproved-origin ────────────────────────────────────────────────

describe("scanToolCall — unapproved-origin", () => {
  test("flags a URL when no allowlist is configured (mirrors scanOutput's default)", () => {
    const result = scanToolCall("fetch", { url: "https://evil.com/x" });
    expect(result.findings).toContainEqual({
      type: "unapproved-origin",
      path: "args.url",
      evidence: "https://evil.com/x",
    });
    expect(result.shouldBlock).toBe(true);
  });

  test("does not flag a URL whose host is on the allowlist", () => {
    const result = scanToolCall(
      "fetch",
      { url: "https://api.example.com/x" },
      { allowedOrigins: ["example.com"] }
    );
    expect(result.findings).toEqual([]);
    expect(result.shouldBlock).toBe(false);
  });

  test("flags a URL whose host is not on the allowlist", () => {
    const result = scanToolCall(
      "fetch",
      { url: "https://evil.com/x" },
      { allowedOrigins: ["example.com"] }
    );
    expect(result.findings.some((f) => f.type === "unapproved-origin")).toBe(true);
  });

  test("an allowed origin can still carry a secret in its query string", () => {
    const result = scanToolCall(
      "fetch",
      { url: "https://ok.com/?key=AKIAABCDEFGHIJKLMNOP" },
      { allowedOrigins: ["ok.com"] }
    );
    expect(result.findings).toEqual([
      { type: "secret-in-argument", path: "args.url", evidence: "AKIA…OP" },
    ]);
  });

  test("evidence for a flagged URL with a query string omits the query text", () => {
    const result = scanToolCall("fetch", {
      url: "https://evil.com/path?token=AKIAABCDEFGHIJKLMNOP",
    });
    const finding = result.findings.find((f) => f.type === "unapproved-origin");
    expect(finding?.evidence).toBe("https://evil.com/path?…");
    expect(finding?.evidence).not.toContain("AKIA");
    expect(finding?.evidence).not.toContain("token=");
  });

  test("evidence for a flagged URL with a fragment omits the fragment text", () => {
    const result = scanToolCall("fetch", { url: "https://evil.com/path#secretHash" });
    const finding = result.findings.find((f) => f.type === "unapproved-origin");
    expect(finding?.evidence).toBe("https://evil.com/path#…");
  });

  test("evidence strips userinfo credentials from the URL", () => {
    const result = scanToolCall("fetch", { url: "https://user:hunter2@evil.com/x" });
    const finding = result.findings.find((f) => f.type === "unapproved-origin");
    expect(finding?.evidence).toBe("https://evil.com/x");
    expect(finding?.evidence).not.toContain("hunter2");
    expect(finding?.evidence).not.toContain("user:");
  });

  test("an unparseable URL is redacted rather than echoed verbatim", () => {
    const badUrl = "https://evil.com:99999999999999/x";
    const result = scanToolCall("fetch", { url: badUrl });
    const finding = result.findings.find((f) => f.type === "unapproved-origin");
    expect(finding).toBeDefined();
    expect(finding?.evidence).not.toBe(badUrl);
    expect(finding?.evidence).toMatch(/^.{4}….{2}$/);
  });
});

// ── unapproved-recipient ─────────────────────────────────────────────

describe("scanToolCall — unapproved-recipient", () => {
  test("undefined allowedRecipients produces no recipient findings", () => {
    const result = scanToolCall("send_email", { to: "attacker@evil.com" });
    expect(result.findings.some((f) => f.type === "unapproved-recipient")).toBe(false);
  });

  test("exact match is allowed (case-insensitive)", () => {
    const result = scanToolCall(
      "send_email",
      { to: "Boss@MyCorp.com" },
      { allowedRecipients: ["boss@mycorp.com"] }
    );
    expect(result.findings).toEqual([]);
  });

  test("domain-suffix entry allows any address in that domain", () => {
    const result = scanToolCall(
      "send_email",
      { to: "anyone@mycorp.com" },
      { allowedRecipients: ["@mycorp.com"] }
    );
    expect(result.findings).toEqual([]);
  });

  test("flags a recipient outside the allowlist", () => {
    const result = scanToolCall(
      "send_email",
      { to: "attacker@evil.com" },
      { allowedRecipients: ["@mycorp.com"] }
    );
    expect(result.findings).toContainEqual({
      type: "unapproved-recipient",
      path: "args.to",
      evidence: "attacker@evil.com",
    });
  });

  test("applies to mailto: URLs", () => {
    const result = scanToolCall(
      "open_url",
      { url: "mailto:attacker@evil.com?subject=data" },
      { allowedRecipients: ["@mycorp.com"] }
    );
    expect(result.findings.some((f) => f.type === "unapproved-recipient")).toBe(true);
  });
});

// ── secret-in-argument ───────────────────────────────────────────────

describe("scanToolCall — secret-in-argument", () => {
  test.each([
    ["AWS access key", "AKIAABCDEFGHIJKLMNOP"],
    ["OpenAI-style key", "sk-" + "a".repeat(25)],
    ["GitHub token", "ghp_" + "a".repeat(40)],
    ["JWT", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123XYZ"],
    ["PEM private key header", "-----BEGIN RSA PRIVATE KEY-----"],
    ["Bearer token", "Bearer " + "a".repeat(25)],
    ["Slack token", "xoxb-1234567890-abcdefg"],
    ["generic assignment", 'api_key: "abcdefgh12345678"'],
  ])("detects %s", (_label, secret) => {
    const result = scanToolCall("do_thing", { payload: `prefix ${secret} suffix` });
    expect(result.findings.some((f) => f.type === "secret-in-argument")).toBe(true);
  });

  test("does not flag ordinary text as a secret", () => {
    const result = scanToolCall("do_thing", { payload: "just a normal sentence" });
    expect(result.findings.some((f) => f.type === "secret-in-argument")).toBe(false);
  });

  test("redacts evidence to first 4 and last 2 chars", () => {
    const result = scanToolCall("do_thing", { key: "AKIAABCDEFGHIJKLMNOP" });
    const finding = result.findings.find((f) => f.type === "secret-in-argument");
    expect(finding?.evidence).toBe("AKIA…OP");
  });

  test("appends user secretPatterns to the built-in set", () => {
    const result = scanToolCall(
      "do_thing",
      { payload: "internal-id-CUSTOM-000123456" },
      { secretPatterns: [/CUSTOM-\d{9}/] }
    );
    expect(result.findings).toContainEqual({
      type: "secret-in-argument",
      path: "args.payload",
      evidence: "CUST…56",
    });
  });

  test("user secretPatterns with a stateful /g flag doesn't cause false negatives", () => {
    const statefulPattern = /CUSTOM-\d{9}/g;
    const first = scanToolCall(
      "do_thing",
      { payload: "id CUSTOM-000123456" },
      { secretPatterns: [statefulPattern] }
    );
    const second = scanToolCall(
      "do_thing",
      { payload: "id CUSTOM-000123456" },
      { secretPatterns: [statefulPattern] }
    );
    expect(first.findings).toHaveLength(1);
    expect(second.findings).toHaveLength(1);
  });
});

// ── traversal: nesting, arrays, paths, cycles, depth ─────────────────

describe("scanToolCall — argument traversal", () => {
  test("walks nested objects and arrays, formatting paths as args.a.b[0]", () => {
    const result = scanToolCall(
      "do_thing",
      { a: { b: ["https://evil.com/x"] } },
      { allowedOrigins: ["example.com"] }
    );
    expect(result.findings).toContainEqual({
      type: "unapproved-origin",
      path: "args.a.b[0]",
      evidence: "https://evil.com/x",
    });
  });

  test("does not throw on an object that references itself", () => {
    const cyclic: Record<string, unknown> = { url: "https://evil.com/x" };
    cyclic.self = cyclic;
    expect(() => scanToolCall("do_thing", cyclic)).not.toThrow();
  });

  test("does not throw on an array that contains itself", () => {
    const cyclic: unknown[] = ["https://evil.com/x"];
    cyclic.push(cyclic);
    expect(() => scanToolCall("do_thing", { list: cyclic })).not.toThrow();
  });

  test("stops descending past the depth cap without throwing", () => {
    let deep: unknown = "https://evil.com/x";
    for (let i = 0; i < 50; i++) {
      deep = { nested: deep };
    }
    expect(() => scanToolCall("do_thing", deep)).not.toThrow();
    const result = scanToolCall("do_thing", deep);
    // 50 levels exceeds the depth cap, so the deeply nested URL is never reached.
    expect(result.findings).toEqual([]);
  });

  test("numbers and booleans never produce findings", () => {
    const result = scanToolCall("do_thing", { count: 42, enabled: true, missing: null });
    expect(result.findings).toEqual([]);
  });
});

// ── non-object args ──────────────────────────────────────────────────

describe("scanToolCall — non-object args", () => {
  test("a bare string is scanned directly at path 'args'", () => {
    const result = scanToolCall("do_thing", "https://evil.com/x");
    expect(result.findings).toContainEqual({
      type: "unapproved-origin",
      path: "args",
      evidence: "https://evil.com/x",
    });
  });

  test("null args produce no findings and no throw", () => {
    expect(() => scanToolCall("do_thing", null)).not.toThrow();
    expect(scanToolCall("do_thing", null).findings).toEqual([]);
  });

  test("a bare number produces no findings", () => {
    expect(scanToolCall("do_thing", 42).findings).toEqual([]);
  });

  test("undefined options behaves the same as omitting options", () => {
    const withDefault = scanToolCall("do_thing", { url: "https://evil.com/x" });
    const withUndefined = scanToolCall("do_thing", { url: "https://evil.com/x" }, undefined);
    expect(withUndefined).toEqual(withDefault);
  });
});

// ── shouldBlock ──────────────────────────────────────────────────────

describe("scanToolCall — shouldBlock", () => {
  test("false when there are no findings", () => {
    expect(scanToolCall("do_thing", { safe: "value" }).shouldBlock).toBe(false);
  });

  test("true when there is at least one finding", () => {
    expect(scanToolCall("do_thing", { url: "https://evil.com" }).shouldBlock).toBe(true);
  });
});

// ── ReDoS safety ─────────────────────────────────────────────────────

describe("scanToolCall — ReDoS resistance", () => {
  const ADVERSARIAL_INPUT_SIZE = 100_000;
  const MAX_SCAN_MS = 50;

  test.each([
    "AWS access key",
    "OpenAI-style key",
    "GitHub token",
    "JWT",
    "PEM private key header",
    "Bearer token",
    "Slack token",
    "generic assignment",
  ])("%s pattern stays fast against a 100KB adversarial string", (label) => {
    // A pathological mix that resembles every built-in pattern's prefix
    // without ever fully matching, to stress backtracking.
    const adversarial =
      "AKIA".repeat(200) +
      "sk-".repeat(200) +
      "ghp_".repeat(200) +
      "eyJ".repeat(200) +
      "-----BEGIN ".repeat(50) +
      "Bearer ".repeat(200) +
      "xoxb-".repeat(200) +
      "api_key: '".repeat(200) +
      "a".repeat(ADVERSARIAL_INPUT_SIZE);

    const start = performance.now();
    scanToolCall("do_thing", { payload: adversarial, label });
    const elapsed = performance.now() - start;

    expect(elapsed).toBeLessThan(MAX_SCAN_MS);
  });
});
