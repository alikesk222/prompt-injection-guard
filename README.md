# prompt-injection-guard

> Real-time **prompt injection detection and prevention** for LLM applications.
> Zero dependencies. TypeScript-first. One line to integrate.

[![CI](https://github.com/alikesk222/prompt-injection-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/alikesk222/prompt-injection-guard/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/prompt-injection-guard.svg)](https://www.npmjs.com/package/prompt-injection-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-zero-brightgreen?style=flat-square)](#)

**prompt-injection-guard** sits between your users and your LLM. It detects prompt injection attempts in real-time using multi-layer analysis — pattern matching + heuristic anomaly scoring — and blocks them before they reach the model.

This is the TypeScript/npm counterpart of [prompt-shield](https://github.com/alikesk222/prompt-shield) (Python) — same detection engine, same test corpus, ported for the Node.js / Next.js / LangChain.js ecosystem.

---

## Install

```bash
npm install prompt-injection-guard
```

---

## Quick Start

```ts
import { isSafe, detect, Shield } from "prompt-injection-guard";

// One-liner guard
if (!isSafe(userInput)) {
  return "I cannot process that request.";
}

// Detailed result
const result = detect(userInput);
console.log(result.score);        // 0.0 - 1.0
console.log(result.threatLevel);  // 'none' | 'low' | 'medium' | 'high' | 'critical'
console.log(result.categories);   // ['direct_override', 'role_confusion']
console.log(result.isInjection);  // true / false
```

---

## Detection Layers

### 1. Rule-Based Pattern Matching
30+ regex patterns covering 8 attack categories:

| Category | Examples |
|----------|---------|
| `direct_override` | "ignore previous instructions", "disregard all rules" |
| `role_confusion` | DAN jailbreak, "act as", "you are now", evil mode |
| `prompt_extraction` | "repeat your system prompt", "what were your instructions" |
| `delimiter_injection` | `[INST]`, `<\|im_start\|>`, `<system>`, JSON role injection |
| `encoding` | zero-width chars, Cyrillic lookalikes, base64 instructions |
| `indirect_injection` | HTML comment injection, hidden instruction markers |
| `data_exfiltration` | URL parameter exfil, "summarize and send" |
| `goal_hijacking` | Task substitution, "your true purpose is" |

### 2. Heuristic Anomaly Scoring
- **Instruction density** — ratio of command verbs to total words
- **Delimiter density** — suspicious `###`, `===`, XML tag frequency
- **Special character ratio** — control/invisible character abuse
- **Shannon entropy** — detects encoded/obfuscated payloads
- **Length penalty** — unusually long inputs

Final score = `patternScore × 0.7 + heuristicScore × 0.3`

---

## Shield Class

```ts
import { Shield } from "prompt-injection-guard";

const shield = new Shield({
  threshold: 0.5,   // score threshold (default 0.5)
  strict: false,    // if true, throws InjectionDetected instead of returning
  sanitize: true,   // auto-sanitize input before scanning
  log: true,         // console.warn on detections
});

const result = shield.scan(userInput);

// Sanitize + scan in one step
const [clean, scanned] = shield.sanitizeAndScan(userInput);
if (!scanned.isInjection) {
  callLLM(clean);
}

// Strict mode — throws
try {
  const strictShield = new Shield({ strict: true });
  strictShield.scan(userInput);
} catch (e) {
  if (e instanceof InjectionDetected) console.log(e.result.score);
}
```

---

## Express Middleware

```ts
import express from "express";
import { expressMiddleware } from "prompt-injection-guard/express";

const app = express();
app.use(express.json());
app.use(expressMiddleware()); // scans "message", "prompt", "query", "input" fields

app.post("/chat", (req, res) => {
  res.json({ response: callLLM(req.body.message) });
});
```

## Next.js API Route

```ts
import { Shield } from "prompt-injection-guard";

const shield = new Shield();

export async function POST(req: Request) {
  const { message } = await req.json();
  const result = shield.scan(message);
  if (result.isInjection) {
    return Response.json({ error: "Rejected: potential prompt injection" }, { status: 400 });
  }
  return Response.json({ response: await callLLM(message) });
}
```

---

## Input Sanitizer

```ts
import { sanitize } from "prompt-injection-guard";

const clean = sanitize(userInput, {
  removeInvisible: true,   // strip zero-width chars
  removeControl: true,     // strip control characters
  removeDelimiters: true,  // strip [INST], <|im_start|>, etc.
  normalize: true,         // Unicode NFC normalization
  collapseNewlines: true,  // collapse 3+ newlines to 2
  maxLength: 4096,         // hard truncate
});
```

---

## Custom Patterns

```ts
import { Detector } from "prompt-injection-guard";

const detector = new Detector({
  customPatterns: [
    {
      name: "my_secret_keyword",
      regex: /ACME_INTERNAL_BYPASS/i,
      category: "custom",
      weight: 1.0,
      description: "Internal bypass keyword",
    },
  ],
});
```

---

## Detection Result

```ts
const result = detect(text);

result.isInjection;     // boolean
result.score;           // number 0.0-1.0
result.threatLevel;     // 'none' | 'low' | 'medium' | 'high' | 'critical'
result.categories;      // string[] — attack categories found
result.matchedRules;    // MatchedRule[] — detailed rule matches
result.heuristicScore;  // number — anomaly component
result.inputLength;     // number — input character count
result.sanitized;       // string | null — sanitized text (if sanitize=true)
```

---

## vs. prompt-shield (Python)

| | prompt-injection-guard (this) | prompt-shield |
|--|---|---|
| **Runtime** | Node.js / TypeScript | Python |
| **Install** | `npm install prompt-injection-guard` | `pip install prompt-injection-shield` |
| **Frameworks** | Express, Next.js | FastAPI, Flask |
| **Detection engine** | Same patterns + heuristics, ported 1:1 | Original |

Same detection engine, different runtime — pick whichever matches your stack.

---

## License

MIT — See [LICENSE](LICENSE)

---

> Built by [Ali Kesik](https://github.com/alikesk222)
