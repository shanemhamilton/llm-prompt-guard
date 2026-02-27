export { createGuard, sanitize, detect, count } from "./guard";
export { BUILTIN_PATTERNS, NEUTRALIZATION_MAP, ensureGlobalFlag } from "./patterns";
export type {
  SanitizationResult,
  SanitizationMode,
  QuarantineOptions,
  InjectionTag,
  FieldConfig,
  GuardConfig,
  InjectionPattern,
  Logger,
  Severity,
} from "./types";
