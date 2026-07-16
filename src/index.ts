/**
 * prompt-injection-guard -- Real-time prompt injection detection and prevention.
 *
 * Quick start:
 *   import { isSafe, detect, Shield } from "prompt-injection-guard";
 *
 *   if (!isSafe(userInput)) {
 *     return "I cannot process that request.";
 *   }
 *
 *   const result = detect(userInput);
 *   console.log(result.score, result.threatLevel, result.categories);
 *
 *   const shield = new Shield({ threshold: 0.5, strict: false });
 *   const scanned = shield.scan(userInput);
 */

export const VERSION = "1.0.0";

export { Detector, DetectionResult } from "./detector.js";
export type { DetectorOptions, MatchedRule, ThreatLevel } from "./detector.js";

export { Shield, InjectionDetected, detect, isSafe } from "./shield.js";
export type { ShieldOptions } from "./shield.js";

export { sanitize } from "./sanitizer.js";
export type { SanitizeOptions } from "./sanitizer.js";

export { PATTERNS, PATTERNS_BY_CATEGORY, ALL_CATEGORIES } from "./patterns.js";
export type { Pattern } from "./patterns.js";
