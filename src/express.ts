/**
 * Express.js middleware integration for prompt-injection-guard.
 *
 * ```ts
 * import express from "express";
 * import { expressMiddleware } from "prompt-injection-guard/express";
 *
 * const app = express();
 * app.use(express.json());
 * app.use(expressMiddleware());
 * ```
 */

import { Shield } from "./shield.js";

export interface ExpressMiddlewareOptions {
  shield?: Shield;
  fields?: string[];
  rejectionStatus?: number;
  rejectionBody?: Record<string, unknown>;
}

// Minimal structural types so this file has no hard dependency on @types/express.
interface MinimalRequest {
  body?: Record<string, unknown>;
}
interface MinimalResponse {
  status(code: number): this;
  json(body: unknown): this;
}
type NextFn = (err?: unknown) => void;

export function expressMiddleware(options: ExpressMiddlewareOptions = {}) {
  const shield = options.shield ?? new Shield();
  const fields = options.fields ?? ["message", "prompt", "query", "input", "content", "text"];
  const rejection = options.rejectionBody ?? {
    error: "Input rejected: potential prompt injection detected.",
  };
  const rejectionStatus = options.rejectionStatus ?? 400;

  return function promptInjectionGuard(req: MinimalRequest, res: MinimalResponse, next: NextFn): void {
    const body = req.body;
    if (body && typeof body === "object") {
      for (const field of fields) {
        const value = body[field];
        if (typeof value === "string") {
          const result = shield.scan(value);
          if (result.isInjection) {
            res.status(rejectionStatus).json({
              ...rejection,
              field,
              score: result.score,
              threatLevel: result.threatLevel,
            });
            return;
          }
        }
      }
    }
    next();
  };
}
