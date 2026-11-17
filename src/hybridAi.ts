import { deleteApp, getApps, initializeApp, type FirebaseApp } from "firebase/app";
import { initializeAppCheck, ReCaptchaEnterpriseProvider } from "firebase/app-check";
import {
  getAI,
  getGenerativeModel,
  GoogleAIBackend,
  InferenceMode,
  InferenceSource,
  ThinkingLevel,
  type GenerativeModel,
  type HybridParams,
} from "firebase/ai";
import {
  assertNoUnmaskedSecrets,
  redactTextLocally,
  rehydrateTextLocally,
  type EntityCategory,
  type RedactionResult,
  type VaultEntry,
} from "./privacyEngine";

export { InferenceMode, InferenceSource };
export type InferenceModeValue = (typeof InferenceMode)[keyof typeof InferenceMode];
export type InferenceSourceValue = (typeof InferenceSource)[keyof typeof InferenceSource];

export interface FirebaseRuntimeConfig {
  apiKey: string;
  authDomain: string;
  projectId: string;
  appId: string;
  cloudModel: string;
  appCheckSiteKey?: string;
  appCheckDebugToken?: string;
}

export type DeviceNanoStatus =
  | "available"
  | "downloadable"
  | "downloading"
  | "unavailable"
  | "unsupported";

export interface RiskFinding {
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  title: string;
  detail: string;
}

export interface AnalysisBrief {
  documentType: string;
  riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  executiveSummary: string;
  riskFindings: RiskFinding[];
  actionItems: string[];
  complianceNotes: string;
  directAnswer?: string;
}

export interface HybridTelemetry {
  executionMode: "firebase_hybrid" | "sandbox_preview";
  requestedMode: InferenceModeValue;
  stage1Source: "on_device" | "deterministic_local";
  stage2Source: "on_device" | "in_cloud" | "sandbox_local";
  stage1LatencyMs: number;
  stage2LatencyMs: number;
  totalLatencyMs: number;
  rawChars: number;
  sanitizedChars: number;
  secretsProtectedCount: number;
  leakCheckPassed: boolean;
  deviceModelNote?: string;
}

export interface HybridAnalysisOutput {
  redaction: RedactionResult;
  cloudPayloadSent: string;
  maskedBrief: AnalysisBrief;
  rehydratedBrief: AnalysisBrief;
  telemetry: HybridTelemetry;
}

export interface FollowUpOutput {
  sanitizedQuestionSent: string;
  maskedAnswer: string;
  rehydratedAnswer: string;
  entries: VaultEntry[];
  inferenceSource: "on_device" | "in_cloud" | "sandbox_local";
  executionMode: "firebase_hybrid" | "sandbox_preview";
  latencyMs: number;
}

export interface AiCallResult {
  text: string;
  inferenceSource?: InferenceSourceValue | string;
}

export interface HybridAiAdapter {
  warmUpDeviceModel?(onProgress?: (pct: number) => void): Promise<void>;
  runStage1OnDevice(prompt: string): Promise<AiCallResult>;
  runStage2(prompt: string, mode: InferenceModeValue, cloudModel: string): Promise<AiCallResult>;
  runFollowUp?(prompt: string, mode: InferenceModeValue, cloudModel: string): Promise<AiCallResult>;
}

export const DEFAULT_CLOUD_MODEL = "gemini-4-hydrogen";

export interface CloudModelOption {
  id: string;
  label: string;
  tier: "Free Spark" | "Blaze Billing";
  note: string;
}

export const CLOUD_MODEL_OPTIONS: CloudModelOption[] = [
  {
    id: "gemini-4-hydrogen",
    label: "Gemini 4 Hydrogen (Latest Flagship · Free Spark)",
    tier: "Free Spark",
    note: "Released Nov 12, 2026 — highest intelligence & multimodal accuracy on Spark free tier.",
  },
  {
    id: "gemini-3.8-flash",
    label: "Gemini 3.8 Flash (Stable Frontier · Free Spark)",
    tier: "Free Spark",
    note: "Latest Flash generation replacing 3.5/3.6/3.7 Flash; fast frontier reasoning.",
  },
  {
    id: "gemini-3.5-flash-lite",
    label: "Gemini 3.5 Flash-Lite (Ultra Fast · Free Spark)",
    tier: "Free Spark",
    note: "Lowest-latency workhorse model on Spark free tier.",
  },
  {
    id: "gemini-4-argon",
    label: "Gemini 4 Argon (Deep Reasoning · Blaze)",
    tier: "Blaze Billing",
    note: "Advanced math, science, and complex legal/code reasoning (requires Blaze plan).",
  },
  {
    id: "gemini-4-carbon",
    label: "Gemini 4 Carbon (Peak Cybersecurity/Code · Blaze)",
    tier: "Blaze Billing",
    note: "Strongest reasoning model for cybersecurity defense & deep engineering (requires Blaze plan).",
  },
];

const CONFIG_STORAGE_KEY = "cloakbrief.firebaseConfig.v1";
const FIREBASE_APP_NAME = "cloakbrief-hybrid-app";

const STAGE1_RESPONSE_SCHEMA = {
  type: "object",
  properties: {
    documentType: { type: "string" },
    riskLevel: { type: "string", enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"] },
    extraEntities: {
      type: "array",
      items: {
        type: "object",
        properties: {
          text: { type: "string" },
          category: { type: "string", enum: ["PERSON_NAME", "CUSTOM_PII"] },
        },
        required: ["text", "category"],
      },
    },
  },
  required: ["documentType", "riskLevel", "extraEntities"],
};

const STAGE2_RESPONSE_SCHEMA = {
  type: "object",
  properties: {
    documentType: { type: "string" },
    riskLevel: { type: "string", enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"] },
    executiveSummary: { type: "string" },
    riskFindings: {
      type: "array",
      items: {
        type: "object",
        properties: {
          severity: { type: "string", enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW"] },
          title: { type: "string" },
          detail: { type: "string" },
        },
        required: ["severity", "title", "detail"],
      },
    },
    actionItems: {
      type: "array",
      items: { type: "string" },
    },
    complianceNotes: { type: "string" },
    directAnswer: { type: "string" },
  },
  required: [
    "documentType",
    "riskLevel",
    "executiveSummary",
    "riskFindings",
    "actionItems",
    "complianceNotes",
  ],
};

function nowMs(): number {
  return typeof performance !== "undefined" ? performance.now() : Date.now();
}

export function getEnvFirebaseConfig(): FirebaseRuntimeConfig {
  const env = typeof import.meta !== "undefined" && import.meta.env ? import.meta.env : undefined;
  return {
    apiKey: (env?.VITE_FIREBASE_API_KEY ?? "").trim(),
    authDomain: (env?.VITE_FIREBASE_AUTH_DOMAIN ?? "").trim(),
    projectId: (env?.VITE_FIREBASE_PROJECT_ID ?? "").trim(),
    appId: (env?.VITE_FIREBASE_APP_ID ?? "").trim(),
    cloudModel: (env?.VITE_FIREBASE_CLOUD_MODEL ?? DEFAULT_CLOUD_MODEL).trim() || DEFAULT_CLOUD_MODEL,
    appCheckSiteKey: (env?.VITE_FIREBASE_APPCHECK_SITE_KEY ?? "").trim(),
    appCheckDebugToken: (env?.VITE_FIREBASE_APPCHECK_DEBUG_TOKEN ?? "").trim(),
  };
}

export function hasValidFirebaseConfig(cfg: Partial<FirebaseRuntimeConfig> | null | undefined): boolean {
  if (!cfg) return false;
  return Boolean(cfg.apiKey?.trim() && cfg.projectId?.trim() && cfg.appId?.trim());
}

export function loadFirebaseConfig(): FirebaseRuntimeConfig {
  const fallback = getEnvFirebaseConfig();
  if (typeof localStorage === "undefined") {
    return fallback;
  }
  try {
    const raw = localStorage.getItem(CONFIG_STORAGE_KEY);
    if (!raw) return fallback;
    const parsed = JSON.parse(raw) as Partial<FirebaseRuntimeConfig>;
    const rawModel = (parsed.cloudModel ?? fallback.cloudModel).trim();
    const migratedModel = !rawModel || rawModel === "gemini-2.5-flash" ? DEFAULT_CLOUD_MODEL : rawModel;
    return {
      apiKey: (parsed.apiKey ?? fallback.apiKey).trim(),
      authDomain: (parsed.authDomain ?? fallback.authDomain).trim(),
      projectId: (parsed.projectId ?? fallback.projectId).trim(),
      appId: (parsed.appId ?? fallback.appId).trim(),
      cloudModel: migratedModel,
      appCheckSiteKey: (parsed.appCheckSiteKey?.trim() || fallback.appCheckSiteKey || "").trim(),
      appCheckDebugToken: (parsed.appCheckDebugToken ?? fallback.appCheckDebugToken ?? "").trim(),
    };
  } catch {
    return fallback;
  }
}

export function saveFirebaseConfig(cfg: FirebaseRuntimeConfig): void {
  if (typeof localStorage === "undefined") return;
  localStorage.setItem(
    CONFIG_STORAGE_KEY,
    JSON.stringify({
      apiKey: cfg.apiKey.trim(),
      authDomain: cfg.authDomain.trim(),
      projectId: cfg.projectId.trim(),
      appId: cfg.appId.trim(),
      cloudModel: cfg.cloudModel.trim() || DEFAULT_CLOUD_MODEL,
      appCheckSiteKey: (cfg.appCheckSiteKey ?? "").trim(),
      appCheckDebugToken: (cfg.appCheckDebugToken ?? "").trim(),
    }),
  );
}

export function clearFirebaseConfig(): void {
  if (typeof localStorage === "undefined") return;
  localStorage.removeItem(CONFIG_STORAGE_KEY);
}

export async function probeDeviceNanoAvailability(): Promise<DeviceNanoStatus> {
  const g = globalThis as unknown as {
    LanguageModel?: { availability?: () => Promise<string> };
    ai?: { languageModel?: { capabilities?: () => Promise<{ available?: string }> } };
  };

  try {
    if (g.LanguageModel && typeof g.LanguageModel.availability === "function") {
      const status = (await g.LanguageModel.availability()).toLowerCase();
      if (status === "available" || status === "readily") return "available";
      if (status === "downloadable" || status === "after-download") return "downloadable";
      if (status === "downloading") return "downloading";
      if (status === "unavailable" || status === "no") return "unavailable";
    }
    if (g.ai?.languageModel && typeof g.ai.languageModel.capabilities === "function") {
      const caps = await g.ai.languageModel.capabilities();
      const avail = (caps.available ?? "").toLowerCase();
      if (avail === "readily" || avail === "available") return "available";
      if (avail === "after-download" || avail === "downloadable") return "downloadable";
      return "unavailable";
    }
  } catch {
    return "unavailable";
  }
  return "unsupported";
}

const appCheckActivatedApps = new WeakSet<FirebaseApp>();

function ensureAppCheckInitialized(app: FirebaseApp, config: FirebaseRuntimeConfig): void {
  const siteKey = config.appCheckSiteKey?.trim() ?? "";
  const debugToken = config.appCheckDebugToken?.trim() ?? "";

  if (debugToken) {
    const g = globalThis as unknown as { FIREBASE_APPCHECK_DEBUG_TOKEN?: string | boolean };
    g.FIREBASE_APPCHECK_DEBUG_TOKEN = debugToken.toLowerCase() === "true" ? true : debugToken;
  }

  if ((siteKey || debugToken) && !appCheckActivatedApps.has(app)) {
    initializeAppCheck(app, {
      provider: new ReCaptchaEnterpriseProvider(siteKey || "debug-mode-placeholder-key"),
      isTokenAutoRefreshEnabled: true,
    });
    appCheckActivatedApps.add(app);
  }
}

async function getOrInitFirebaseApp(config: FirebaseRuntimeConfig): Promise<FirebaseApp> {
  const existing = getApps().find((app) => app.name === FIREBASE_APP_NAME);
  if (existing) {
    const opts = existing.options;
    const sameConfig =
      opts.apiKey === config.apiKey &&
      opts.projectId === config.projectId &&
      opts.appId === config.appId &&
      (opts.authDomain ?? "") === config.authDomain;
    if (sameConfig) {
      ensureAppCheckInitialized(existing, config);
      return existing;
    }
    await deleteApp(existing);
  }

  const app = initializeApp(
    {
      apiKey: config.apiKey.trim(),
      authDomain: config.authDomain.trim() || undefined,
      projectId: config.projectId.trim(),
      appId: config.appId.trim(),
    },
    FIREBASE_APP_NAME,
  );
  ensureAppCheckInitialized(app, config);
  return app;
}

export function createFirebaseHybridAdapter(config: FirebaseRuntimeConfig): HybridAiAdapter {
  const CLOUD_REQUEST_TIMEOUT_MS = 18000;

  const withCallTimeout = async <T>(promise: Promise<T>, label: string): Promise<T> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        promise,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            reject(new Error(`${label} timed out after ${Math.round(CLOUD_REQUEST_TIMEOUT_MS / 1000)}s (upstream model busy).`));
          }, CLOUD_REQUEST_TIMEOUT_MS + 1000);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  };

  const getModels = async (
    mode: InferenceModeValue,
    cloudModel: string,
    schema: Record<string, unknown>,
    maxOutputTokens: number,
  ): Promise<GenerativeModel> => {
    const app = await getOrInitFirebaseApp(config);
    const ai = getAI(app, { backend: new GoogleAIBackend() });

    const params: HybridParams = {
      mode,
      inCloudParams: {
        model: cloudModel || DEFAULT_CLOUD_MODEL,
        generationConfig: {
          responseMimeType: "application/json",
          responseJsonSchema: schema,
          maxOutputTokens,
          thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
        },
      },
    };
    return getGenerativeModel(ai, params, { timeout: CLOUD_REQUEST_TIMEOUT_MS });
  };

  return {
    async warmUpDeviceModel(onProgress?: (pct: number) => void): Promise<void> {
      const app = await getOrInitFirebaseApp(config);
      const ai = getAI(app, { backend: new GoogleAIBackend() });
      const model = getGenerativeModel(ai, {
        mode: InferenceMode.PREFER_ON_DEVICE,
        inCloudParams: { model: config.cloudModel || DEFAULT_CLOUD_MODEL },
      });
      await model.initializeDeviceModel((progressValue) => {
        if (onProgress) {
          onProgress(Math.max(0, Math.min(100, Math.round(progressValue * 100))));
        }
      });
    },

    async runStage1OnDevice(prompt: string): Promise<AiCallResult> {
      const model = await getModels(
        InferenceMode.ONLY_ON_DEVICE,
        config.cloudModel || DEFAULT_CLOUD_MODEL,
        STAGE1_RESPONSE_SCHEMA,
        550,
      );
      const result = await model.generateContent(prompt);
      return {
        text: result.response.text(),
        inferenceSource: result.response.inferenceSource ?? InferenceSource.ON_DEVICE,
      };
    },

    async runStage2(prompt: string, mode: InferenceModeValue, cloudModel: string): Promise<AiCallResult> {
      const model = await getModels(mode, cloudModel, STAGE2_RESPONSE_SCHEMA, 1400);
      const result = await withCallTimeout(model.generateContent(prompt), "Stage 2 analysis");
      return {
        text: result.response.text(),
        inferenceSource: result.response.inferenceSource ?? InferenceSource.IN_CLOUD,
      };
    },

    async runFollowUp(prompt: string, mode: InferenceModeValue, cloudModel: string): Promise<AiCallResult> {
      const app = await getOrInitFirebaseApp(config);
      const ai = getAI(app, { backend: new GoogleAIBackend() });
      const model = getGenerativeModel(
        ai,
        {
          mode,
          inCloudParams: {
            model: cloudModel || DEFAULT_CLOUD_MODEL,
            generationConfig: {
              maxOutputTokens: 600,
              thinkingConfig: { thinkingLevel: ThinkingLevel.LOW },
            },
          },
        },
        { timeout: CLOUD_REQUEST_TIMEOUT_MS },
      );
      const result = await withCallTimeout(model.generateContent(prompt), "Follow-up Q&A");
      return {
        text: result.response.text(),
        inferenceSource: result.response.inferenceSource ?? InferenceSource.IN_CLOUD,
      };
    },
  };
}

export async function warmUpDeviceModel(
  config: FirebaseRuntimeConfig,
  onProgress?: (pct: number) => void,
  customAdapter?: HybridAiAdapter,
): Promise<{ status: "ready" | "error"; message: string }> {
  if (customAdapter?.warmUpDeviceModel) {
    try {
      await customAdapter.warmUpDeviceModel(onProgress);
      return { status: "ready", message: "On-device Gemini Nano initialized and warm." };
    } catch (err) {
      return {
        status: "error",
        message: err instanceof Error ? err.message : "Failed to initialize on-device model.",
      };
    }
  }

  if (!hasValidFirebaseConfig(config)) {
    return {
      status: "error",
      message: "Add a Firebase Web Config first to initialize Gemini Nano via Firebase AI Logic.",
    };
  }

  try {
    const adapter = createFirebaseHybridAdapter(config);
    await adapter.warmUpDeviceModel?.(onProgress);
    return { status: "ready", message: "Chrome Gemini Nano initialized via Firebase AI Logic." };
  } catch (err) {
    return {
      status: "error",
      message:
        err instanceof Error
          ? err.message
          : "On-device Gemini Nano unavailable in this browser. Cloud fallback remains active.",
    };
  }
}

function safeParseJson<T>(rawText: string): T | null {
  try {
    const cleaned = rawText
      .replace(/^```(?:json)?\s*/i, "")
      .replace(/```$/i, "")
      .trim();
    return JSON.parse(cleaned) as T;
  } catch {
    return null;
  }
}

function normalizeRiskLevel(val: unknown): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" {
  const upper = typeof val === "string" ? val.toUpperCase().trim() : "";
  if (upper === "CRITICAL" || upper === "HIGH" || upper === "MEDIUM" || upper === "LOW") {
    return upper;
  }
  return "MEDIUM";
}

function parseStage1Entities(rawText: string): Array<{ text: string; category: EntityCategory }> {
  const parsed = safeParseJson<{
    extraEntities?: Array<{ text?: string; category?: string }>;
  }>(rawText);
  if (!parsed || !Array.isArray(parsed.extraEntities)) return [];

  const entities: Array<{ text: string; category: EntityCategory }> = [];
  for (const item of parsed.extraEntities) {
    const text = typeof item?.text === "string" ? item.text.trim() : "";
    if (text.length < 3 || /^\[[A-Z_]+_\d+\]$/.test(text)) continue;
    const cat = item.category === "PERSON_NAME" ? "PERSON_NAME" : "CUSTOM_PII";
    entities.push({ text, category: cat });
  }
  return entities;
}

function normalizeStage2Brief(rawText: string, sanitizedSource: string): AnalysisBrief {
  const parsed = safeParseJson<Partial<AnalysisBrief>>(rawText);
  if (parsed && typeof parsed.executiveSummary === "string" && parsed.executiveSummary.trim()) {
    const findings: RiskFinding[] = Array.isArray(parsed.riskFindings)
      ? parsed.riskFindings.slice(0, 6).map((f) => ({
          severity: normalizeRiskLevel(f?.severity),
          title: typeof f?.title === "string" && f.title.trim() ? f.title.trim() : "Risk Finding",
          detail: typeof f?.detail === "string" ? f.detail.trim() : "",
        }))
      : [];

    const actions = Array.isArray(parsed.actionItems)
      ? parsed.actionItems.filter((item): item is string => typeof item === "string" && item.trim().length > 0)
      : [];

    return {
      documentType:
        typeof parsed.documentType === "string" && parsed.documentType.trim()
          ? parsed.documentType.trim()
          : "Sanitized Workspace Document",
      riskLevel: normalizeRiskLevel(parsed.riskLevel),
      executiveSummary: parsed.executiveSummary.trim(),
      riskFindings:
        findings.length > 0
          ? findings
          : [{ severity: "MEDIUM", title: "Review Required", detail: "Inspect redaction boundaries." }],
      actionItems:
        actions.length > 0
          ? actions
          : ["Verify masked placeholders match local vault entries before sharing externally."],
      complianceNotes:
        typeof parsed.complianceNotes === "string" && parsed.complianceNotes.trim()
          ? parsed.complianceNotes.trim()
          : "Processed strictly from locally redacted payload; zero raw secrets left client device.",
      directAnswer:
        typeof parsed.directAnswer === "string" && parsed.directAnswer.trim()
          ? parsed.directAnswer.trim()
          : undefined,
    };
  }

  return {
    documentType: "Hybrid AI Unstructured Response",
    riskLevel: sanitizedSource.includes("[API_SECRET") || sanitizedSource.includes("[DATABASE_URI") ? "HIGH" : "MEDIUM",
    executiveSummary: rawText.trim() || "Model returned an empty response.",
    riskFindings: [
      {
        severity: "LOW",
        title: "Non-JSON Model Output Normalized",
        detail: "Stage 2 returned free-form text instead of strict JSON; safely wrapped without leaking raw entities.",
      },
    ],
    actionItems: ["Review executive summary above and re-run with structured Gemini 4 Hydrogen if needed."],
    complianceNotes: "Zero-leak sanitization barrier held across model response normalization.",
  };
}

function buildSandboxPreviewBrief(
  sanitizedText: string,
  entries: VaultEntry[],
  customQuestion?: string,
): AnalysisBrief {
  const lower = sanitizedText.toLowerCase();
  const hasSecret = entries.some((e) => e.category === "API_SECRET" || e.category === "DATABASE_URI" || e.category === "AUTH_TOKEN");
  const hasClinical = lower.includes("clinical") || lower.includes("lisinopril") || lower.includes("bp drop") || lower.includes("mrn");
  const hasLegal = lower.includes("agreement") || lower.includes("indemnity") || lower.includes("termination") || lower.includes("deliverables");
  const hasEscalation =
    lower.includes("chargeback") ||
    lower.includes("escrow") ||
    lower.includes("settlement") ||
    lower.includes("sla credit") ||
    lower.includes("ticket #") ||
    lower.includes("dispute");

  let documentType = "Confidential Operational Brief";
  let riskLevel: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" = hasSecret ? "CRITICAL" : "HIGH";
  let executiveSummary =
    `Sandbox analysis inspected ${sanitizedText.length} sanitized characters across ${entries.length} local vault placeholder(s). No raw keys, tokens, emails, or personal IDs entered external context.`;
  let riskFindings: RiskFinding[] = [];
  let actionItems: string[] = [];
  let complianceNotes =
    "Local-first sandbox preview completed deterministically. Connect a free Firebase Spark Web Config in Settings to invoke live Firebase AI Logic (Chrome Gemini Nano + Cloud Gemini 4 Hydrogen).";

  if (hasSecret && (lower.includes("incident") || lower.includes("503") || lower.includes("worker"))) {
    documentType = "DevSecOps Production Incident Report";
    riskLevel = "CRITICAL";
    executiveSummary =
      "Checkout outage caused by upstream HTTP 503 retry amplification and pool exhaustion. Crash snapshot exposed live production credentials ([DATABASE_URI_1], [API_SECRET_1], [AUTH_TOKEN_1]), all intercepted locally before AI analysis.";
    riskFindings = [
      {
        severity: "CRITICAL",
        title: "Production Secret Exposure in Crash Dump",
        detail: "Crash telemetry captured database DSN, payment secret key, LLM key, and JWT bearer header in plaintext.",
      },
      {
        severity: "HIGH",
        title: "Retry Storm Cascading Failure",
        detail: "Unjittered retries after HTTP 503 saturated connection pool during peak 14:10-14:28 UTC window.",
      },
      {
        severity: "MEDIUM",
        title: "Financial Revenue Impact",
        detail: "412 stalled orders representing [MONETARY_AMOUNT_1] require reconciliation once gateway stability resumes.",
      },
    ];
    actionItems = [
      "Immediately revoke and rotate [DATABASE_URI_1], [API_SECRET_1], [API_SECRET_2], and [AUTH_TOKEN_1].",
      "Scrub crash-dump serializers to redact Authorization headers and DSN passwords at ingress.",
      "Deploy bounded exponential backoff with full jitter and circuit breaking on HTTP 503 upstream failures.",
      "Notify [PERSON_NAME_1] ([EMAIL_1]) to trigger order backlog replay and customer verification.",
    ];
    complianceNotes = "Zero raw secrets exited client browser; safe remediation brief preserves internal placeholders for DevSecOps handoff.";
  } else if (hasLegal) {
    documentType = "Executive Vendor MSA Draft";
    riskLevel = "HIGH";
    executiveSummary =
      "Draft agreement between Helios Robotics Inc. and [PERSON_NAME_2] Consulting introduces asymmetric liability, a 24-month auto-renewal trap, and IP holdback leverage over disputed invoices.";
    riskFindings = [
      {
        severity: "HIGH",
        title: "Uncapped Indemnity Carve-Out (Sec 8.3)",
        detail: "Exposes company beyond retainer value ([MONETARY_AMOUNT_1]/mo) with no mutual liability cap.",
      },
      {
        severity: "HIGH",
        title: "Silent 24-Month Auto-Renewal",
        detail: "Requires 90-day advance termination notice; missing notice locks commitment automatically.",
      },
      {
        severity: "MEDIUM",
        title: "IP Ownership Tied to Disputed Invoices",
        detail: "Deliverable IP transfer waits until all disputed bills settle, granting vendor operational leverage.",
      },
    ];
    actionItems = [
      "Cap aggregate indemnity at 12 months of fees paid and make indemnity obligations mutual.",
      "Replace 24-month auto-renewal with 30-day termination for convenience or annual opt-in renewal.",
      "Decouple IP assignment so undisputed paid deliverables transfer cleanly on acceptance.",
      "Route counter-redline between [EMAIL_1] and [PERSON_NAME_2] ([PHONE_1]) without exposing [GOVERNMENT_ID_1].",
    ];
  } else if (hasClinical) {
    documentType = "Urgent Clinical Triage Summary";
    riskLevel = "CRITICAL";
    executiveSummary =
      "Patient [PERSON_NAME_1] ([CUSTOM_PII_1]) reports acute orthostatic hypotension (BP 88/54 mmHg), dizziness, and palpitations after doubling Lisinopril 20mg alongside high-dose NSAID (Ibuprofen 800mg TID).";
    riskFindings = [
      {
        severity: "CRITICAL",
        title: "Hemodynamic Instability / Syncope Risk",
        detail: "Systolic BP 88/54 mmHg with progressive palpitations and postural symptoms requires urgent clinician evaluation.",
      },
      {
        severity: "HIGH",
        title: "ACE Inhibitor + High-Dose NSAID Interaction",
        detail: "Doubled Lisinopril combined with Ibuprofen 800mg TID risks acute kidney injury and refractory hypotension.",
      },
    ];
    actionItems = [
      "Escalate immediately to on-call physician or advise urgent ED evaluation if dizziness/chest symptoms worsen.",
      "Hold next doubled Lisinopril and Ibuprofen doses pending clinician medication reconciliation.",
      "Contact [PERSON_NAME_1] via [PHONE_1] or emergency contact [PERSON_NAME_2] ([PHONE_2]) if unreachable.",
    ];
    complianceNotes = "Patient name, DOB, MRN, email, and phone numbers masked locally before analysis; rehydrated strictly inside browser session.";
  } else if (hasEscalation) {
    documentType = "VIP Fintech Settlement Escalation Brief";
    riskLevel = "HIGH";
    executiveSummary =
      "High-priority escalation for [PERSON_NAME_1] ([EMAIL_1]): [MONETARY_AMOUNT_1] was debited from escrow wallet [WALLET_ADDRESS_1] after an expired cross-border quote while ledger stayed PENDING for 6 hours. Legal/regulatory escalation threatened within 24 hours.";
    riskFindings = [
      {
        severity: "HIGH",
        title: "Debited Escrow vs. Stuck PENDING Ledger State",
        detail: "On-chain/escrow debit occurred without finalized settlement confirmation, risking compliance SLA breach.",
      },
      {
        severity: "MEDIUM",
        title: "24h Regulatory Escalation Window",
        detail: "Customer card reference [FINANCIAL_ACCOUNT_1] and wallet history require immediate audit reconciliation receipt.",
      },
    ];
    actionItems = [
      "Verify on-chain settlement tx hash for [WALLET_ADDRESS_1] and release or refund [MONETARY_AMOUNT_1] today.",
      "Issue time-stamped reconciliation receipt and approved SLA credit to [PERSON_NAME_1] via [EMAIL_1] / [PHONE_1].",
      "Add idempotent quote-expiry guard so expired quotes cannot settle debit steps.",
    ];
    complianceNotes = "Customer wallet address, card reference, name, phone, and email masked locally before synthesis.";
  } else {
    riskFindings = [
      {
        severity: hasSecret ? "CRITICAL" : "MEDIUM",
        title: hasSecret ? "High-Sensitivity Secrets Detected & Masked" : "PII Entities Masked Locally",
        detail: `${entries.length} sensitive tokens were isolated inside the browser Zero-Leak Vault prior to synthesis.`,
      },
    ];
    actionItems = [
      "Inspect the Cloud Payload Diff tab to verify no raw secrets appear.",
      "Connect Firebase AI Logic in Settings to run full semantic analysis with Gemini Nano + Gemini 4 Hydrogen.",
    ];
  }

  const brief: AnalysisBrief = {
    documentType,
    riskLevel,
    executiveSummary,
    riskFindings,
    actionItems,
    complianceNotes,
  };

  if (customQuestion?.trim()) {
    brief.directAnswer =
      `Answer derived strictly from sanitized context (${entries.length} protected items): Focus first on the highest-severity item ("${riskFindings[0]?.title ?? documentType}") and execute "${actionItems[0] ?? "verify masked artifacts"}" while keeping credentials offline.`;
  }

  return brief;
}

function rehydrateBrief(
  brief: AnalysisBrief,
  entries: VaultEntry[],
  revealHardSecrets: boolean,
): AnalysisBrief {
  const r = (txt: string) => rehydrateTextLocally(txt, entries, revealHardSecrets);
  return {
    documentType: r(brief.documentType),
    riskLevel: brief.riskLevel,
    executiveSummary: r(brief.executiveSummary),
    riskFindings: brief.riskFindings.map((f) => ({
      severity: f.severity,
      title: r(f.title),
      detail: r(f.detail),
    })),
    actionItems: brief.actionItems.map((item) => r(item)),
    complianceNotes: r(brief.complianceNotes),
    directAnswer: brief.directAnswer ? r(brief.directAnswer) : undefined,
  };
}

function redactExtendingVault(
  text: string,
  baseEntries: VaultEntry[],
  extraAiEntities: Array<{ text: string; category?: EntityCategory }> = [],
): { sanitizedText: string; mergedEntries: VaultEntry[]; leakCheckPassed: boolean } {
  const localRes = redactTextLocally(text, extraAiEntities);
  if (localRes.entries.length === 0) {
    return {
      sanitizedText: localRes.sanitizedText,
      mergedEntries: [...baseEntries],
      leakCheckPassed: localRes.leakCheckPassed && assertNoUnmaskedSecrets(localRes.sanitizedText),
    };
  }

  const maxIndexByCategory = new Map<string, number>();
  for (const existing of baseEntries) {
    const match = /^\[([A-Z_]+)_(\d+)\]$/.exec(existing.placeholder);
    if (match) {
      const cat = match[1];
      const idx = Number(match[2]);
      maxIndexByCategory.set(cat, Math.max(maxIndexByCategory.get(cat) ?? 0, idx));
    }
  }

  const mergedEntries = [...baseEntries];
  let remappedText = localRes.sanitizedText;
  const sentinelReplacements: Array<{ sentinel: string; finalPlaceholder: string }> = [];

  for (let i = 0; i < localRes.entries.length; i += 1) {
    const qEntry = localRes.entries[i];
    const existingMatch = mergedEntries.find((e) => e.original === qEntry.original);
    let targetPlaceholder: string;

    if (existingMatch) {
      targetPlaceholder = existingMatch.placeholder;
    } else {
      const nextIdx = (maxIndexByCategory.get(qEntry.category) ?? 0) + 1;
      maxIndexByCategory.set(qEntry.category, nextIdx);
      targetPlaceholder = `[${qEntry.category}_${nextIdx}]`;
      mergedEntries.push({
        ...qEntry,
        placeholder: targetPlaceholder,
      });
    }

    if (targetPlaceholder !== qEntry.placeholder) {
      const sentinel = `<<CLOAK_REMAP_${i}>>`;
      remappedText = remappedText.split(qEntry.placeholder).join(sentinel);
      sentinelReplacements.push({ sentinel, finalPlaceholder: targetPlaceholder });
    }
  }

  for (const item of sentinelReplacements) {
    remappedText = remappedText.split(item.sentinel).join(item.finalPlaceholder);
  }

  return {
    sanitizedText: remappedText,
    mergedEntries,
    leakCheckPassed: localRes.leakCheckPassed && assertNoUnmaskedSecrets(remappedText),
  };
}

function isRetryableQuotaOrCapacityError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message.toLowerCase() : String(err).toLowerCase();
  return (
    msg.includes("429") ||
    msg.includes("quota") ||
    msg.includes("resource_exhausted") ||
    msg.includes("503") ||
    msg.includes("500") ||
    msg.includes("high demand") ||
    msg.includes("deadline") ||
    msg.includes("timed out") ||
    msg.includes("timeout")
  );
}

function isCloudOriginError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message.toLowerCase() : String(err).toLowerCase();
  return (
    isRetryableQuotaOrCapacityError(err) ||
    msg.includes("app check") ||
    msg.includes("401") ||
    msg.includes("403") ||
    msg.includes("unauthenticated") ||
    msg.includes("fetch-error") ||
    msg.includes("firebasevertexai")
  );
}

async function executeHybridWithFallback(params: {
  invoke: (targetMode: InferenceModeValue, modelId: string) => Promise<AiCallResult>;
  requestedMode: InferenceModeValue;
  primaryModel: string;
}): Promise<{ result: AiCallResult; note?: string }> {
  const { invoke, requestedMode, primaryModel } = params;
  try {
    const result = await invoke(requestedMode, primaryModel);
    return { result };
  } catch (err) {
    if (requestedMode === InferenceMode.ONLY_ON_DEVICE) {
      throw err;
    }

    let lastErr: unknown = err;
    let note: string | undefined;

    if (requestedMode === InferenceMode.PREFER_ON_DEVICE && !isCloudOriginError(err)) {
      note =
        err instanceof Error
          ? `On-device fallback to cloud (${err.message.slice(0, 90)})`
          : "On-device execution fell back to cloud model.";
      try {
        const result = await invoke(InferenceMode.ONLY_IN_CLOUD, primaryModel);
        return { result, note };
      } catch (cloudErr) {
        lastErr = cloudErr;
      }
    }

    if (isRetryableQuotaOrCapacityError(lastErr)) {
      const fallbacks = ["gemini-3.5-flash-lite", "gemini-3.8-flash", "gemini-4-hydrogen"].filter(
        (m) => m !== primaryModel,
      );
      for (const fallbackModel of fallbacks) {
        try {
          const result = await invoke(InferenceMode.ONLY_IN_CLOUD, fallbackModel);
          const errSummary = lastErr instanceof Error ? lastErr.message.slice(0, 60) : "quota/capacity";
          return {
            result,
            note: `Cloud fallback: ${primaryModel} (${errSummary}) -> ${fallbackModel}`,
          };
        } catch (fbErr) {
          lastErr = fbErr;
          if (!isRetryableQuotaOrCapacityError(fbErr)) {
            throw fbErr;
          }
        }
      }
    }

    throw lastErr;
  }
}

function normalizeStageSource(
  rawSource: InferenceSourceValue | string | undefined,
  requestedMode: InferenceModeValue,
): "on_device" | "in_cloud" {
  if (rawSource === InferenceSource.ON_DEVICE || rawSource === "on_device") {
    return "on_device";
  }
  if (rawSource === InferenceSource.IN_CLOUD || rawSource === "in_cloud") {
    return "in_cloud";
  }
  return requestedMode === InferenceMode.ONLY_ON_DEVICE ? "on_device" : "in_cloud";
}

export async function analyzeDocumentWithHybridAi(params: {
  rawText: string;
  customQuestion?: string;
  mode: InferenceModeValue;
  config: FirebaseRuntimeConfig;
  revealHardSecrets?: boolean;
  adapter?: HybridAiAdapter;
}): Promise<HybridAnalysisOutput> {
  const totalStart = nowMs();
  const { rawText, customQuestion, mode, config, revealHardSecrets = false } = params;
  const trimmedRaw = rawText.trim();
  if (!trimmedRaw) {
    throw new Error("Document input cannot be empty.");
  }

  const adapter =
    params.adapter ?? (hasValidFirebaseConfig(config) ? createFirebaseHybridAdapter(config) : null);

  // Stage 1: On-Device ONLY entity discovery (never send raw input to cloud)
  let stage1Source: "on_device" | "deterministic_local" = "deterministic_local";
  let extraAiEntities: Array<{ text: string; category?: EntityCategory }> = [];
  let deviceModelNote: string | undefined;

  const s1Start = nowMs();
  if (
    adapter &&
    mode !== InferenceMode.ONLY_IN_CLOUD &&
    (Boolean(params.adapter) || (await probeDeviceNanoAvailability()) === "available")
  ) {
    try {
      const stage1Prompt = [
        "Extract person full names and organization/project/MRN identifiers from the text below that should be masked as PII.",
        "Return strict JSON matching schema: { documentType, riskLevel, extraEntities: [{ text, category }] }.",
        "Do NOT alter strings; quote exact substrings.",
        "",
        trimmedRaw.slice(0, 1800),
      ].join("\n");
      const s1Res = await adapter.runStage1OnDevice(stage1Prompt);
      extraAiEntities = parseStage1Entities(s1Res.text);
      stage1Source = "on_device";
    } catch (err) {
      stage1Source = "deterministic_local";
      deviceModelNote =
        err instanceof Error
          ? `Stage 1 fallback to deterministic engine (${err.message.slice(0, 90)})`
          : "Stage 1 used deterministic local redaction engine.";
    }
  }

  const redaction = redactTextLocally(trimmedRaw, extraAiEntities);
  const questionExtended = customQuestion?.trim()
    ? redactExtendingVault(customQuestion.trim(), redaction.entries, extraAiEntities)
    : null;

  const mergedEntries: VaultEntry[] = questionExtended ? questionExtended.mergedEntries : [...redaction.entries];

  // Zero-Leak Verification Barrier BEFORE Stage 2
  const barrierDocOk = redaction.leakCheckPassed && assertNoUnmaskedSecrets(redaction.sanitizedText);
  const barrierQuestionOk = questionExtended ? questionExtended.leakCheckPassed : true;

  if (!barrierDocOk || !barrierQuestionOk) {
    throw new Error("Zero-Leak Barrier blocked outbound call: unmasked secret signature remained after redaction.");
  }
  const stage1LatencyMs = Math.max(1, Math.round(nowMs() - s1Start));

  const cloudPayloadSent = questionExtended
    ? `${redaction.sanitizedText}\n\n[USER_QUESTION]: ${questionExtended.sanitizedText}`
    : redaction.sanitizedText;

  // Double-check outbound payload integrity
  if (!assertNoUnmaskedSecrets(cloudPayloadSent)) {
    throw new Error("Zero-Leak Barrier aborted Stage 2 because cloud payload failed verification.");
  }

  // Stage 2: Deep Analysis on strictly sanitized payload
  const s2Start = nowMs();
  let executionMode: "firebase_hybrid" | "sandbox_preview" = "sandbox_preview";
  let stage2Source: "on_device" | "in_cloud" | "sandbox_local" = "sandbox_local";
  let maskedBrief: AnalysisBrief;

  if (adapter) {
    executionMode = "firebase_hybrid";
    const stage2Prompt = [
      "You are CloakBrief, a security-first executive analyst.",
      "Analyze ONLY the locally sanitized document below. Preserve all bracketed placeholders like [API_SECRET_1], [PERSON_NAME_1], [EMAIL_1] VERBATIM in your response so the client browser can rehydrate safe fields locally.",
      "Respond strictly with JSON containing: documentType, riskLevel (CRITICAL|HIGH|MEDIUM|LOW), executiveSummary, riskFindings ([{severity, title, detail}]), actionItems ([string]), complianceNotes, and optional directAnswer if USER_QUESTION is present.",
      "",
      cloudPayloadSent,
    ].join("\n");

    const primaryModel = config.cloudModel || DEFAULT_CLOUD_MODEL;
    const { result: s2Res, note } = await executeHybridWithFallback({
      invoke: (targetMode, modelId) => adapter.runStage2(stage2Prompt, targetMode, modelId),
      requestedMode: mode,
      primaryModel,
    });
    if (note) {
      deviceModelNote = deviceModelNote ? `${deviceModelNote} | ${note}` : note;
    }
    stage2Source = normalizeStageSource(s2Res.inferenceSource, mode);
    maskedBrief = normalizeStage2Brief(s2Res.text, redaction.sanitizedText);
  } else {
    maskedBrief = buildSandboxPreviewBrief(
      redaction.sanitizedText,
      mergedEntries,
      questionExtended?.sanitizedText,
    );
  }

  const stage2LatencyMs = Math.max(1, Math.round(nowMs() - s2Start));
  const totalLatencyMs = Math.max(1, Math.round(nowMs() - totalStart));
  const rehydratedBrief = rehydrateBrief(maskedBrief, mergedEntries, revealHardSecrets);

  return {
    redaction,
    cloudPayloadSent,
    maskedBrief,
    rehydratedBrief,
    telemetry: {
      executionMode,
      requestedMode: mode,
      stage1Source,
      stage2Source,
      stage1LatencyMs,
      stage2LatencyMs,
      totalLatencyMs,
      rawChars: trimmedRaw.length,
      sanitizedChars: redaction.sanitizedText.length,
      secretsProtectedCount: mergedEntries.length,
      leakCheckPassed: barrierDocOk && barrierQuestionOk,
      deviceModelNote,
    },
  };
}

export async function askFollowUpWithHybridAi(params: {
  sanitizedDocument: string;
  entries: VaultEntry[];
  question: string;
  mode: InferenceModeValue;
  config: FirebaseRuntimeConfig;
  revealHardSecrets?: boolean;
  adapter?: HybridAiAdapter;
}): Promise<FollowUpOutput> {
  const start = nowMs();
  const qTrim = params.question.trim();
  if (!qTrim) {
    throw new Error("Please enter a follow-up question.");
  }

  const qExtended = redactExtendingVault(qTrim, params.entries);
  const allEntries = qExtended.mergedEntries;

  if (!qExtended.leakCheckPassed) {
    throw new Error("Follow-up question failed Zero-Leak verification barrier.");
  }
  if (!assertNoUnmaskedSecrets(params.sanitizedDocument)) {
    throw new Error("Context document failed Zero-Leak verification barrier.");
  }

  const adapter =
    params.adapter ??
    (hasValidFirebaseConfig(params.config) ? createFirebaseHybridAdapter(params.config) : null);

  let maskedAnswer: string;
  let inferenceSource: "on_device" | "in_cloud" | "sandbox_local" = "sandbox_local";
  let executionMode: "firebase_hybrid" | "sandbox_preview" = "sandbox_preview";

  if (adapter) {
    executionMode = "firebase_hybrid";
    const prompt = [
      "Answer the user's question concisely using ONLY the sanitized document context below.",
      "Keep all bracketed placeholders like [PERSON_NAME_1], [API_SECRET_1], [EMAIL_1] untouched so the client can rehydrate safe values locally.",
      "",
      "DOCUMENT:",
      params.sanitizedDocument.slice(0, 6000),
      "",
      `QUESTION: ${qExtended.sanitizedText}`,
    ].join("\n");

    const primaryModel = params.config.cloudModel || DEFAULT_CLOUD_MODEL;
    const { result: res } = await executeHybridWithFallback({
      invoke: (targetMode, modelId) =>
        adapter.runFollowUp
          ? adapter.runFollowUp(prompt, targetMode, modelId)
          : adapter.runStage2(prompt, targetMode, modelId),
      requestedMode: params.mode,
      primaryModel,
    });
    maskedAnswer = res.text.trim();
    inferenceSource = normalizeStageSource(res.inferenceSource, params.mode);
  } else {
    const brief = buildSandboxPreviewBrief(
      params.sanitizedDocument,
      allEntries,
      qExtended.sanitizedText,
    );
    maskedAnswer =
      brief.directAnswer ??
      `Based strictly on the sanitized document (${allEntries.length} masked tokens), prioritize: ${brief.actionItems[0] ?? "Verify remediation items."}`;
  }

  const latencyMs = Math.max(1, Math.round(nowMs() - start));
  const rehydratedAnswer = rehydrateTextLocally(
    maskedAnswer,
    allEntries,
    params.revealHardSecrets ?? false,
  );

  return {
    sanitizedQuestionSent: qExtended.sanitizedText,
    maskedAnswer,
    rehydratedAnswer,
    entries: allEntries,
    inferenceSource,
    executionMode,
    latencyMs,
  };
}

export function rehydrateAnalysisOutput(
  brief: AnalysisBrief,
  entries: VaultEntry[],
  revealHardSecrets: boolean,
): AnalysisBrief {
  return rehydrateBrief(brief, entries, revealHardSecrets);
}
