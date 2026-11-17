export type EntityCategory =
  | "API_SECRET"
  | "AUTH_TOKEN"
  | "DATABASE_URI"
  | "EMAIL"
  | "PHONE"
  | "GOVERNMENT_ID"
  | "FINANCIAL_ACCOUNT"
  | "WALLET_ADDRESS"
  | "INTERNAL_IP"
  | "PERSON_NAME"
  | "MONETARY_AMOUNT"
  | "CUSTOM_PII";

export interface VaultEntry {
  placeholder: string;
  category: EntityCategory;
  original: string;
  source: "deterministic" | "on_device_ai";
  sensitiveSecret: boolean;
}

export interface RedactionResult {
  sanitizedText: string;
  entries: VaultEntry[];
  countsByCategory: Record<string, number>;
  leakCheckPassed: boolean;
}

interface PatternSpec {
  category: EntityCategory;
  regex: RegExp;
  sensitiveSecret: boolean;
  groupIndex?: number;
}

const PATTERN_SPECS: PatternSpec[] = [
  {
    category: "DATABASE_URI",
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s"'`]+/gi,
    sensitiveSecret: true,
  },
  {
    category: "API_SECRET",
    regex: /\b(?:sk_live_|sk_test_|pk_live_|rk_live_|sk-proj-|AIza|ghp_|gho_|github_pat_|xoxb-|AKIA)[A-Za-z0-9._\-]{10,}\b/g,
    sensitiveSecret: true,
  },
  {
    category: "AUTH_TOKEN",
    regex: /Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+/g,
    sensitiveSecret: true,
  },
  {
    category: "AUTH_TOKEN",
    regex: /\beyJ[A-Za-z0-9\-_]{8,}\.eyJ[A-Za-z0-9\-_]{8,}\.[A-Za-z0-9\-_]{4,}\b/g,
    sensitiveSecret: true,
  },
  {
    category: "EMAIL",
    regex: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
    sensitiveSecret: false,
  },
  {
    category: "PHONE",
    regex: /(?:\+?\d{1,3}[\s\-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s\-]\d{3,4}[\s\-]\d{3,4}\b/g,
    sensitiveSecret: false,
  },
  {
    category: "GOVERNMENT_ID",
    regex: /\b(?:\d{3}-\d{2}-\d{4}|MRN-\d{4,12}|ACCT-\d{4,12}|Routing\s+\d{9})\b/g,
    sensitiveSecret: false,
  },
  {
    category: "FINANCIAL_ACCOUNT",
    regex: /\b\d{4}[-\s](?:\d{4}|x{4})[-\s](?:\d{4}|x{4})[-\s]\d{4}\b/gi,
    sensitiveSecret: false,
  },
  {
    category: "WALLET_ADDRESS",
    regex: /\b0x[a-fA-F0-9]{40}\b/g,
    sensitiveSecret: false,
  },
  {
    category: "WALLET_ADDRESS",
    regex: /\b[1-9A-HJ-NP-Za-km-z]{36,44}\b/g,
    sensitiveSecret: false,
  },
  {
    category: "INTERNAL_IP",
    regex: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g,
    sensitiveSecret: false,
  },
  {
    category: "MONETARY_AMOUNT",
    regex: /\$\d{1,3}(?:,\d{3})*(?:\.\d{1,4})?(?:\s*(?:USD|USDC|USDT))?\b/gi,
    sensitiveSecret: false,
  },
  {
    category: "PERSON_NAME",
    regex:
      /(?:Reported by|Signer|Patient|Customer|Emergency Contact|Attn|Prepared for)\s*:\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})/g,
    sensitiveSecret: false,
    groupIndex: 1,
  },
];

interface RawSpan {
  start: number;
  end: number;
  category: EntityCategory;
  original: string;
  sensitiveSecret: boolean;
  source: "deterministic" | "on_device_ai";
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Redacts PII, API keys, URIs, financial numbers, and optional AI-identified spans locally.
 * Keeps original->placeholder vault strictly inside client memory.
 */
export function redactTextLocally(
  inputText: string,
  extraAiEntities: Array<{ text: string; category?: EntityCategory }> = []
): RedactionResult {
  const source = String(inputText || "");
  if (!source.trim()) {
    return {
      sanitizedText: "",
      entries: [],
      countsByCategory: {},
      leakCheckPassed: true,
    };
  }

  const spans: RawSpan[] = [];

  for (const spec of PATTERN_SPECS) {
    const flags = spec.regex.flags.includes("g") ? spec.regex.flags : `${spec.regex.flags}g`;
    const re = new RegExp(spec.regex.source, flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(source)) !== null) {
      const idx = spec.groupIndex ?? 0;
      const val = m[idx];
      if (!val || val.length < 4) continue;
      // Compute exact character offset for capture group matches
      const start = idx === 0 ? m.index : m.index + m[0].indexOf(val);
      const end = start + val.length;
      if (start >= 0 && end <= source.length) {
        spans.push({
          start,
          end,
          category: spec.category,
          original: val,
          sensitiveSecret: spec.sensitiveSecret,
          source: "deterministic",
        });
      }
    }
  }

  for (const item of extraAiEntities) {
    const target = String(item.text || "").trim();
    if (target.length < 3 || /^\[[A-Z_]+_\d+\]$/.test(target)) continue;
    const cat: EntityCategory = item.category || "CUSTOM_PII";
    const re = new RegExp(escapeRegExp(target), "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(source)) !== null) {
      spans.push({
        start: m.index,
        end: m.index + target.length,
        category: cat,
        original: target,
        sensitiveSecret: false,
        source: "on_device_ai",
      });
    }
  }

  // Sort by earliest start, then longest span, and prefer deterministic rules on exact ties
  spans.sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    if (b.end - b.start !== a.end - a.start) return b.end - b.start - (a.end - a.start);
    return a.source === "deterministic" ? -1 : 1;
  });

  const merged: RawSpan[] = [];
  let cursorEnd = -1;
  for (const sp of spans) {
    if (sp.start >= cursorEnd) {
      merged.push(sp);
      cursorEnd = sp.end;
    }
  }

  const originalToEntry = new Map<string, VaultEntry>();
  const categoryCounter: Record<string, number> = {};
  const parts: string[] = [];
  let pos = 0;

  for (const sp of merged) {
    if (sp.start > pos) {
      parts.push(source.slice(pos, sp.start));
    }
    let entry = originalToEntry.get(sp.original);
    if (!entry) {
      const nextNum = (categoryCounter[sp.category] || 0) + 1;
      categoryCounter[sp.category] = nextNum;
      entry = {
        placeholder: `[${sp.category}_${nextNum}]`,
        category: sp.category,
        original: sp.original,
        source: sp.source,
        sensitiveSecret: sp.sensitiveSecret,
      };
      originalToEntry.set(sp.original, entry);
    }
    parts.push(entry.placeholder);
    pos = sp.end;
  }
  if (pos < source.length) {
    parts.push(source.slice(pos));
  }

  const sanitizedText = parts.join("");
  const entries = Array.from(originalToEntry.values());
  const leakCheckPassed = assertNoUnmaskedSecrets(sanitizedText);

  return {
    sanitizedText,
    entries,
    countsByCategory: categoryCounter,
    leakCheckPassed,
  };
}

/**
 * Verifies that high-risk credentials (API keys, DB URIs, bearer tokens) do not remain unmasked.
 */
export function assertNoUnmaskedSecrets(sanitizedText: string): boolean {
  const highRiskSpecs = PATTERN_SPECS.filter((s) => s.sensitiveSecret);
  for (const spec of highRiskSpecs) {
    const flags = spec.regex.flags.replace("g", "");
    const re = new RegExp(spec.regex.source, flags);
    if (re.test(sanitizedText)) {
      return false;
    }
  }
  return true;
}

/**
 * Restores non-credential entities locally in the user's browser while optionally keeping
 * hard credentials (API keys, DB URIs, JWTs) masked as `[REDACTED_SECRET]`.
 */
export function rehydrateTextLocally(
  modelOutput: string,
  entries: VaultEntry[],
  revealHardSecrets: boolean = false
): string {
  let result = String(modelOutput || "");
  for (const entry of entries) {
    const replacement =
      entry.sensitiveSecret && !revealHardSecrets
        ? `[SECRET_PROTECTED:${entry.category}]`
        : entry.original;
    result = result.split(entry.placeholder).join(replacement);
  }
  return result;
}
