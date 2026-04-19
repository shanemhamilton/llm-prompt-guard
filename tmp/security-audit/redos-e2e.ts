/**
 * End-to-end ReDoS: call the actual library API with a pathological
 * payload. If a realistic caller's `validateOutput({pii:{emails:true}})`
 * can be blocked for seconds, that's a denial-of-service in production.
 */
import { createOutputValidator } from "../../src/output";

const v = createOutputValidator({ pii: { emails: true } });

console.log("validateOutput (emails enabled) scaling:");
for (const n of [1000, 4000, 16000, 32000]) {
  const payload = "user@" + ".".repeat(n) + "!";
  const t0 = process.hrtime.bigint();
  v.validate(payload);
  const t1 = process.hrtime.bigint();
  console.log(`  chars=${n.toString().padStart(6)}  time=${(Number(t1 - t0) / 1e6).toFixed(2)}ms`);
}

// Verify the library normally completes quickly on real-world input
console.log("\nvalidateOutput on real-world text:");
for (const n of [1000, 10000, 100000]) {
  const payload = "My name is John and my email is john@example.com. ".repeat(n / 50);
  const t0 = process.hrtime.bigint();
  v.validate(payload);
  const t1 = process.hrtime.bigint();
  console.log(`  chars=${payload.length.toString().padStart(7)}  time=${(Number(t1 - t0) / 1e6).toFixed(2)}ms`);
}
