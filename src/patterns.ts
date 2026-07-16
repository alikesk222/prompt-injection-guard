/**
 * Regex pattern library for prompt injection detection.
 * Patterns are organized by attack category with associated severity weights.
 */

export interface Pattern {
  name: string;
  regex: RegExp;
  category: string;
  weight: number; // 0.0 - 1.0 contribution to threat score
  description: string;
}

function c(pattern: string, flags = "is"): RegExp {
  return new RegExp(pattern, flags);
}

export const PATTERNS: Pattern[] = [
  // -- Direct Override --------------------------------------------------------
  {
    name: "ignore_instructions",
    regex: c(
      "ignore\\s+(all\\s+)?(previous|prior|above|earlier|your)\\s+(instructions?|prompts?|context|rules?|constraints?|directives?)"
    ),
    category: "direct_override",
    weight: 0.9,
    description: "Classic 'ignore previous instructions' injection",
  },
  {
    name: "forget_instructions",
    regex: c(
      "forget\\s+(everything|all|your|the|any)\\s*(previous|prior|above|earlier|instructions?|prompts?|rules?|training)?"
    ),
    category: "direct_override",
    weight: 0.85,
    description: "Instruction reset attempt",
  },
  {
    name: "disregard_instructions",
    regex: c(
      "(disregard|override|bypass|circumvent|overwrite)\\s+(all\\s+)?(previous|prior|your|the|any)\\s*(instructions?|rules?|guidelines?|constraints?)"
    ),
    category: "direct_override",
    weight: 0.85,
    description: "Instruction disregard attempt",
  },
  {
    name: "new_instructions",
    regex: c("(new|updated?|revised?|actual|real|true)\\s+instructions?\\s*(follow|are|below|:)"),
    category: "direct_override",
    weight: 0.75,
    description: "New instructions injection",
  },
  {
    name: "end_of_prompt",
    regex: c("(end\\s+of\\s+(prompt|system|instructions?|context)|---+\\s*end\\s*---+|\\[END\\s+SYSTEM\\])"),
    category: "direct_override",
    weight: 0.7,
    description: "False end-of-prompt delimiter",
  },
  {
    name: "priority_override",
    regex: c("(highest|top|absolute|maximum|critical)\\s+priority\\s*(instruction|directive|command|order)"),
    category: "direct_override",
    weight: 0.7,
    description: "Priority escalation injection",
  },

  // -- Role Confusion -----------------------------------------------------------
  {
    name: "you_are_now",
    regex: c("you\\s+are\\s+now\\s+(a|an|the|no\\s+longer)?\\s*\\w"),
    category: "role_confusion",
    weight: 0.75,
    description: "Role reassignment attempt",
  },
  {
    name: "act_as",
    regex: c("(act|behave|pretend|roleplay|play)\\s+(as|like)\\s+(a|an|the)?\\s*\\w"),
    category: "role_confusion",
    weight: 0.65,
    description: "Role persona injection",
  },
  {
    name: "dan_jailbreak",
    regex: c("\\bDAN\\b|do\\s+anything\\s+now|jailbreak(ed|ing)?\\b|unrestricted\\s+(AI|mode|version)"),
    category: "role_confusion",
    weight: 0.95,
    description: "DAN jailbreak pattern",
  },
  {
    name: "evil_mode",
    regex: c("(evil|dark|unrestricted|unfiltered|uncensored|dev(eloper)?)\\s+(mode|version|persona|twin|AI)"),
    category: "role_confusion",
    weight: 0.85,
    description: "Evil/developer mode injection",
  },
  {
    name: "no_restrictions",
    regex: c("(without|no|without\\s+any)\\s+(restrictions?|limitations?|filters?|guidelines?|rules?|ethics?|morals?)"),
    category: "role_confusion",
    weight: 0.7,
    description: "Restriction removal request",
  },
  {
    name: "grandma_exploit",
    regex: c(
      "(my\\s+(grand(ma|pa|mother|father)|deceased|dead)|(bedtime\\s+story|childhood\\s+memory).*\\bused\\s+to\\b)"
    ),
    category: "role_confusion",
    weight: 0.6,
    description: "Grandma/emotional context exploit",
  },

  // -- Prompt Extraction ----------------------------------------------------------
  {
    name: "repeat_system_prompt",
    regex: c(
      "(repeat|print|output|show|reveal|tell\\s+me|display|write\\s+out)\\s+(your\\s+)?(system\\s+prompt|instructions?|initial\\s+prompt|original\\s+prompt|prompt\\s+above)"
    ),
    category: "prompt_extraction",
    weight: 0.9,
    description: "System prompt extraction attempt",
  },
  {
    name: "what_were_instructions",
    regex: c(
      "what\\s+(were|are)\\s+(your|the)\\s+(instructions?|system\\s+prompt|initial\\s+(instructions?|prompt)|rules?|guidelines?)"
    ),
    category: "prompt_extraction",
    weight: 0.85,
    description: "Instruction inquiry extraction",
  },
  {
    name: "start_with",
    regex: c("(start|begin|respond)\\s+with\\s+(\"|')?(your\\s+)?(first|opening|initial|exact)\\s*(words?|sentence|instruction|line)"),
    category: "prompt_extraction",
    weight: 0.8,
    description: "First-words extraction technique",
  },
  {
    name: "base64_leak",
    regex: c(
      "(encode|output|print|show)\\s+(your\\s+)?(system\\s+prompt|instructions?)\\s+(in\\s+)?(base64|hex|binary|rot13)"
    ),
    category: "prompt_extraction",
    weight: 0.85,
    description: "Encoded prompt extraction",
  },

  // -- Delimiter Injection --------------------------------------------------------
  {
    name: "human_assistant_tags",
    regex: c(
      "(\\[INST\\]|\\[/INST\\]|<\\|im_start\\|>|<\\|im_end\\|>|\\[SYSTEM\\]|\\[/SYSTEM\\]|<\\|system\\|>|<\\|user\\|>|<\\|assistant\\|>)"
    ),
    category: "delimiter_injection",
    weight: 0.9,
    description: "LLM conversation delimiter injection",
  },
  {
    name: "system_tag_injection",
    regex: c("(<system>|</system>|<prompt>|</prompt>|<instructions?>|</instructions?>|\\{system\\}|\\{prompt\\})"),
    category: "delimiter_injection",
    weight: 0.8,
    description: "System/prompt XML tag injection",
  },
  {
    name: "triple_delimiter",
    regex: c(
      "(###\\s*(system|instruction|prompt|human|assistant)|---\\s*(system|instruction|new\\s+prompt)|===\\s*(system|instruction))"
    ),
    category: "delimiter_injection",
    weight: 0.75,
    description: "Triple-delimiter section injection",
  },
  {
    name: "json_injection",
    regex: c("\\{\\s*\"role\"\\s*:\\s*\"(system|user|assistant)\"\\s*,\\s*\"content\"\\s*:"),
    category: "delimiter_injection",
    weight: 0.85,
    description: "JSON message format injection",
  },

  // -- Encoding / Obfuscation -----------------------------------------------------
  {
    name: "base64_instruction",
    regex: c("(decode|execute|run|follow)\\s+(the\\s+)?(following\\s+)?(base64|encoded)\\s*(instruction|command|prompt|message)"),
    category: "encoding",
    weight: 0.85,
    description: "Base64-encoded instruction execution",
  },
  {
    name: "zero_width_chars",
    regex: c("[\\u200b\\u200c\\u200d\\u2060\\ufeff\\u00ad]"),
    category: "encoding",
    weight: 0.7,
    description: "Zero-width / invisible characters",
  },
  {
    name: "unicode_lookalikes",
    regex: c(
      "[\\u0430\\u0435\\u043e\\u0440\\u0441\\u0445\\u0440\\u04cf\\u0456].*\\b(ignore|system|prompt|instruction)\\b" +
        "|" +
        "\\b(ignore|system|prompt|instruction)\\b.*[\\u0430\\u0435\\u043e\\u0440\\u0441\\u0445\\u0440\\u04cf\\u0456]"
    ),
    category: "encoding",
    weight: 0.75,
    description: "Cyrillic lookalike character substitution",
  },

  // -- Indirect Injection ---------------------------------------------------------
  {
    name: "web_injection_marker",
    regex: c("(<!-- .*injection|injection.*payload|<script>.*prompt|prompt\\s+injection\\s+payload)"),
    category: "indirect_injection",
    weight: 0.9,
    description: "Web content injection marker",
  },
  {
    name: "hidden_instruction_comment",
    regex: c("(<!--|/\\*|#)\\s*(ignore|system\\s+prompt|new\\s+instruction|you\\s+are)"),
    category: "indirect_injection",
    weight: 0.8,
    description: "Hidden instruction in comment syntax",
  },

  // -- Data Exfiltration ------------------------------------------------------------
  {
    name: "exfil_via_url",
    regex: c("(send|fetch|request|http\\s+get|navigate\\s+to|load)\\s+.*\\?\\w+=(system|prompt|secret|key|password|token)"),
    category: "data_exfiltration",
    weight: 0.85,
    description: "Exfiltration via URL parameter",
  },
  {
    name: "summarize_and_send",
    regex: c(
      "(summarize|include|embed|append)\\s+(all\\s+)?(user\\s+data|conversation\\s+history|system\\s+prompt|secrets?)\\s+(in|into|and\\s+send)"
    ),
    category: "data_exfiltration",
    weight: 0.8,
    description: "Data collection and exfiltration",
  },

  // -- Goal Hijacking -----------------------------------------------------------
  {
    name: "task_substitution",
    regex: c(
      "(instead\\s+of|rather\\s+than)\\s+(that|this|your\\s+task|answering)\\s*(,|please|just|actually)?\\s*(do|perform|execute|say|write)"
    ),
    category: "goal_hijacking",
    weight: 0.7,
    description: "Task substitution injection",
  },
  {
    name: "true_purpose",
    regex: c("(your\\s+(true|real|actual|hidden)\\s+(purpose|goal|task|mission|instruction)\\s+(is|was|should\\s+be))"),
    category: "goal_hijacking",
    weight: 0.75,
    description: "Hidden purpose revelation attack",
  },

  // -- Multi-turn Escalation ------------------------------------------------------
  {
    name: "hypothetical_setup",
    regex: c(
      "(hypothetically|in\\s+a\\s+fictional|imagine|let'?s\\s+say|suppose|what\\s+if)\\s.{0,60}(how\\s+would|could\\s+you|would\\s+you|can\\s+you)"
    ),
    category: "multi_turn",
    weight: 0.55,
    description: "Hypothetical framing for escalation",
  },
  {
    name: "opposite_day",
    regex: c("(opposite\\s+day|everything\\s+you\\s+say\\s+means\\s+the\\s+opposite|reverse\\s+(your\\s+)?(logic|answer|response))"),
    category: "multi_turn",
    weight: 0.7,
    description: "Opposite-day logic inversion",
  },
];

export const PATTERNS_BY_CATEGORY: Record<string, Pattern[]> = {};
for (const p of PATTERNS) {
  (PATTERNS_BY_CATEGORY[p.category] ??= []).push(p);
}

export const ALL_CATEGORIES = Object.keys(PATTERNS_BY_CATEGORY);
