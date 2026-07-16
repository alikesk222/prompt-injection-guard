/**
 * Input sanitizer -- strips/normalizes dangerous characters from user input
 * before it reaches the LLM. Use alongside detection, not as a replacement.
 */

// Zero-width and invisible characters (often used for smuggling)
const INVISIBLE = new RegExp(
  "[\\u200b\\u200c\\u200d\\u2060\\u2061\\u2062\\u2063\\u2064" +
    "\\ufeff\\u00ad\\u034f\\u17b4\\u17b5\\u180b-\\u180d\\ufe00-\\ufe0f]",
  "g"
);

// Control characters (except newline \n, carriage return \r, tab \t)
const CONTROL = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g;

// LLM conversation delimiter tags that should never appear in user input
const DELIMITERS =
  /\[\/?INST\]|<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>|<\/?system>|<\/?prompt>|<\/?instructions?>/gi;

// Excessive whitespace: more than 2 consecutive newlines
const EXCESS_NEWLINES = /\n{3,}/g;

export function stripInvisible(text: string): string {
  return text.replace(INVISIBLE, "");
}

export function stripControlChars(text: string): string {
  return text.replace(CONTROL, "");
}

export function stripDelimiters(text: string): string {
  return text.replace(DELIMITERS, "");
}

export function normalizeUnicode(text: string, form: "NFC" | "NFD" | "NFKC" | "NFKD" = "NFC"): string {
  return text.normalize(form);
}

export function collapseWhitespace(text: string): string {
  return text.replace(EXCESS_NEWLINES, "\n\n");
}

export function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength);
}

export interface SanitizeOptions {
  removeInvisible?: boolean;
  removeControl?: boolean;
  removeDelimiters?: boolean;
  normalize?: boolean;
  collapseNewlines?: boolean;
  maxLength?: number;
}

/**
 * Apply all sanitization steps to user input.
 */
export function sanitize(text: string, options: SanitizeOptions = {}): string {
  const {
    removeInvisible = true,
    removeControl = true,
    removeDelimiters = true,
    normalize = true,
    collapseNewlines = true,
    maxLength = 0,
  } = options;

  if (normalize) text = normalizeUnicode(text);
  if (removeInvisible) text = stripInvisible(text);
  if (removeControl) text = stripControlChars(text);
  if (removeDelimiters) text = stripDelimiters(text);
  if (collapseNewlines) text = collapseWhitespace(text);
  if (maxLength > 0) text = truncate(text, maxLength);
  return text;
}
