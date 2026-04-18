export {
  createGuard,
  sanitize,
  detect,
  count,
  spotlight,
  scanOutput,
} from "./guard";
export { BUILTIN_PATTERNS, NEUTRALIZATION_MAP } from "./patterns";
export type {
  SanitizationResult,
  FieldConfig,
  GuardMode,
  GuardConfig,
  InjectionPattern,
  Logger,
  Severity,
  SpotlightResult,
  OutputScanResult,
  ExfilFinding,
  ExfilFindingType,
} from "./types";
