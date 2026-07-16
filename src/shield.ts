/**
 * High-level Shield interface and framework-agnostic helpers.
 */

import { Detector, DetectionResult, type DetectorOptions } from "./detector.js";
import { sanitize as sanitizeText } from "./sanitizer.js";

export class InjectionDetected extends Error {
  result: DetectionResult;

  constructor(result: DetectionResult) {
    super(
      `Prompt injection detected (score=${result.score.toFixed(2)}, ` +
        `threat=${result.threatLevel}, categories=${JSON.stringify(result.categories)})`
    );
    this.name = "InjectionDetected";
    this.result = result;
  }
}

export interface ShieldOptions {
  threshold?: number;
  strict?: boolean;
  sanitize?: boolean;
  log?: boolean;
  onInjection?: (result: DetectionResult) => void;
  detectorOptions?: DetectorOptions;
}

/**
 * High-level shield interface. Instantiate once and reuse across your app.
 *
 * ```ts
 * const shield = new Shield();
 * const result = shield.scan(userInput);
 * if (result.isInjection) return "I cannot process that request.";
 * ```
 */
export class Shield {
  private strict: boolean;
  private doSanitize: boolean;
  private log: boolean;
  private onInjection?: (result: DetectionResult) => void;
  private detector: Detector;

  constructor(options: ShieldOptions = {}) {
    const { threshold = 0.5, strict = false, sanitize = true, log = true, onInjection, detectorOptions } = options;
    this.strict = strict;
    this.doSanitize = sanitize;
    this.log = log;
    this.onInjection = onInjection;
    this.detector = new Detector({ threshold, ...detectorOptions });
  }

  /**
   * Scan text for prompt injection.
   * Returns DetectionResult. If `strict: true`, throws InjectionDetected instead.
   */
  scan(text: string): DetectionResult {
    let result: DetectionResult;
    if (this.doSanitize) {
      const clean = sanitizeText(text);
      result = this.detector.detect(clean);
      result.sanitized = clean;
    } else {
      result = this.detector.detect(text);
    }
    this.handleResult(result);
    return result;
  }

  /**
   * Sanitize text and scan for injections in one step.
   * Returns [sanitizedText, DetectionResult].
   */
  sanitizeAndScan(text: string): [string, DetectionResult] {
    const clean = sanitizeText(text);
    const result = this.detector.detect(clean);
    result.sanitized = clean;
    this.handleResult(result);
    return [clean, result];
  }

  isSafe(text: string): boolean {
    return !this.scan(text).isInjection;
  }

  private handleResult(result: DetectionResult): void {
    if (!result.isInjection) return;
    if (this.log) {
      console.warn(
        `prompt-injection-guard: injection detected | score=${result.score.toFixed(2)} ` +
          `threat=${result.threatLevel} categories=${JSON.stringify(result.categories)} ` +
          `input_len=${result.inputLength}`
      );
    }
    this.onInjection?.(result);
    if (this.strict) {
      throw new InjectionDetected(result);
    }
  }
}

// -- Module-level convenience functions using a default Shield instance ------------

const defaultShield = new Shield({ threshold: 0.5, log: true });

/** Scan text for prompt injection using default settings. */
export function detect(text: string): DetectionResult {
  return defaultShield.scan(text);
}

/** Returns true if text does NOT appear to be a prompt injection attempt. */
export function isSafe(text: string): boolean {
  return defaultShield.isSafe(text);
}
