/**
 * Core detection engine.
 * Combines rule-based pattern matching with heuristic anomaly scoring.
 */

import { PATTERNS, type Pattern } from "./patterns.js";

export type ThreatLevel = "none" | "low" | "medium" | "high" | "critical";

export interface MatchedRule {
  name: string;
  category: string;
  weight: number;
  description: string;
  matchedText: string;
}

export class DetectionResult {
  isInjection: boolean;
  score: number;
  threatLevel: ThreatLevel;
  matchedRules: MatchedRule[];
  heuristicScore: number;
  inputLength: number;
  sanitized: string | null;

  constructor(init: {
    isInjection: boolean;
    score: number;
    threatLevel: ThreatLevel;
    matchedRules?: MatchedRule[];
    heuristicScore?: number;
    inputLength?: number;
    sanitized?: string | null;
  }) {
    this.isInjection = init.isInjection;
    this.score = init.score;
    this.threatLevel = init.threatLevel;
    this.matchedRules = init.matchedRules ?? [];
    this.heuristicScore = init.heuristicScore ?? 0.0;
    this.inputLength = init.inputLength ?? 0;
    this.sanitized = init.sanitized ?? null;
  }

  get categories(): string[] {
    return [...new Set(this.matchedRules.map((r) => r.category))];
  }

  /** Allows: `if (result)` truthiness checks via valueOf */
  valueOf(): boolean {
    return this.isInjection;
  }
}

// -- Heuristic scorers -----------------------------------------------------------

function instructionDensity(text: string): number {
  const matches = text.match(
    /\b(ignore|forget|disregard|override|bypass|pretend|act|roleplay|repeat|print|reveal|show|tell|execute|run|perform|do|say|write|output|display|provide|give|list|explain)\b/gi
  );
  const commandCount = matches ? matches.length : 0;
  const words = Math.max(text.split(/\s+/).filter(Boolean).length, 1);
  const density = commandCount / words;
  return Math.min(density * 5, 1.0); // normalize: 0.2 cmd/word = score 1.0
}

function delimiterDensity(text: string): number {
  const matches = text.match(/(#{3,}|={3,}|-{3,}|_{3,}|\*{3,}|<[a-z]+>|<\/[a-z]+>|\[\/?[A-Z]+\])/g);
  const count = matches ? matches.length : 0;
  return Math.min(count * 0.15, 1.0);
}

function specialCharRatio(text: string): number {
  if (!text) return 0.0;
  let special = 0;
  for (const ch of text) {
    const code = ch.codePointAt(0)!;
    if (code < 32 || isFormatOrControlChar(ch)) special++;
  }
  return Math.min((special / text.length) * 20, 1.0);
}

// Approximates Python's unicodedata.category(c) in ("Cf", "Cc", "Co")
function isFormatOrControlChar(ch: string): boolean {
  return /\p{Cf}|\p{Cc}|\p{Co}/u.test(ch);
}

function entropy(text: string): number {
  if (!text) return 0.0;
  const freq = new Map<string, number>();
  for (const ch of text) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  const n = text.length;
  let h = 0;
  for (const f of freq.values()) {
    const p = f / n;
    h -= p * Math.log2(p);
  }
  // Typical English text: ~4.0 bits/char; base64: ~6.0; random: ~8.0
  const normalized = Math.max(0.0, (h - 4.5) / 3.5); // 0 at 4.5, 1 at 8.0
  return Math.min(normalized, 1.0);
}

function lengthPenalty(text: string): number {
  return Math.min(Math.max(0.0, text.length - 500) / 5000, 0.3);
}

function computeHeuristic(text: string): number {
  const scores = [
    instructionDensity(text) * 0.35,
    delimiterDensity(text) * 0.25,
    specialCharRatio(text) * 0.2,
    entropy(text) * 0.1,
    lengthPenalty(text) * 0.1,
  ];
  return Math.min(
    scores.reduce((a, b) => a + b, 0),
    1.0
  );
}

// -- Threat level mapping ----------------------------------------------------------

function threatLevel(score: number): ThreatLevel {
  if (score >= 0.85) return "critical";
  if (score >= 0.65) return "high";
  if (score >= 0.4) return "medium";
  if (score >= 0.2) return "low";
  return "none";
}

// -- Detector -------------------------------------------------------------------

export interface DetectorOptions {
  threshold?: number;
  heuristicWeight?: number;
  patternWeight?: number;
  disabledCategories?: string[];
  customPatterns?: Pattern[];
}

/**
 * Core detection engine. Instantiate once and reuse.
 * Stateless per call (safe to share across requests).
 */
export class Detector {
  threshold: number;
  heuristicWeight: number;
  patternWeight: number;
  private disabledCategories: Set<string>;
  private patterns: Pattern[];

  constructor(options: DetectorOptions = {}) {
    const {
      threshold = 0.5,
      heuristicWeight = 0.3,
      patternWeight = 0.7,
      disabledCategories = [],
      customPatterns,
    } = options;

    if (Math.abs(heuristicWeight + patternWeight - 1.0) > 0.01) {
      throw new Error("heuristicWeight + patternWeight must equal 1.0");
    }

    this.threshold = threshold;
    this.heuristicWeight = heuristicWeight;
    this.patternWeight = patternWeight;
    this.disabledCategories = new Set(disabledCategories);

    this.patterns = PATTERNS.filter((p) => !this.disabledCategories.has(p.category));
    if (customPatterns) {
      this.patterns = [...this.patterns, ...customPatterns];
    }
  }

  /**
   * Analyze `text` for prompt injection signals.
   * Returns a DetectionResult. Use `result.isInjection` for the verdict.
   */
  detect(text: string): DetectionResult {
    if (!text || !text.trim()) {
      return new DetectionResult({
        isInjection: false,
        score: 0.0,
        threatLevel: "none",
        inputLength: text ? text.length : 0,
      });
    }

    const matchedRules: MatchedRule[] = [];

    for (const pattern of this.patterns) {
      const m = pattern.regex.exec(text);
      if (m) {
        matchedRules.push({
          name: pattern.name,
          category: pattern.category,
          weight: pattern.weight,
          description: pattern.description,
          matchedText: m[0].slice(0, 120),
        });
      }
    }

    let patternScore = 0.0;
    if (matchedRules.length > 0) {
      const weights = matchedRules.map((r) => r.weight).sort((a, b) => b - a);
      // Diminishing returns: each extra hit adds less
      let combined = weights[0];
      for (const w of weights.slice(1)) {
        combined = combined + w * (1.0 - combined) * 0.4;
      }
      patternScore = Math.min(combined, 1.0);
    }

    const heuristicScore = computeHeuristic(text);

    let finalScore = patternScore * this.patternWeight + heuristicScore * this.heuristicWeight;
    finalScore = Math.min(finalScore, 1.0);

    return new DetectionResult({
      isInjection: finalScore >= this.threshold,
      score: Math.round(finalScore * 10000) / 10000,
      threatLevel: threatLevel(finalScore),
      matchedRules,
      heuristicScore: Math.round(heuristicScore * 10000) / 10000,
      inputLength: text.length,
    });
  }

  isSafe(text: string): boolean {
    return !this.detect(text).isInjection;
  }
}
