export { createGuard, sanitize, detect, count } from "./guard";
export { BUILTIN_PATTERNS, NEUTRALIZATION_MAP, LEET_MAP, ensureGlobalFlag } from "./patterns";
export { generateCanary, createOutputValidator } from "./output";
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
  OutputValidationResult,
  OutputFlag,
  OutputValidator,
  OutputValidatorConfig,
  PiiConfig,
} from "./types";
