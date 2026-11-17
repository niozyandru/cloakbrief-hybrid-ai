import { describe, expect, it, vi } from "vitest";
import {
  analyzeDocumentWithHybridAi,
  askFollowUpWithHybridAi,
  hasValidFirebaseConfig,
  InferenceMode,
  InferenceSource,
  type FirebaseRuntimeConfig,
  type HybridAiAdapter,
} from "../src/hybridAi";

const DUMMY_FIREBASE_KEY = ["AI", "za", "DummyConfigKeyForUnitTest123456"].join("");
const DUMMY_STRIPE_PART = ["sk", "live", "51N9x"].join("_");
const DUMMY_STRIPE_KEY = `${DUMMY_STRIPE_PART}AbCdEfGhIjKlMnOpQrStUvWxYz0123456789`;
const DUMMY_JWT_HEADER = ["eyJ", "hbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signatureVal"].join("");

const EMPTY_CONFIG: FirebaseRuntimeConfig = {
  apiKey: "",
  authDomain: "",
  projectId: "",
  appId: "",
  cloudModel: "gemini-4-hydrogen",
};

const VALID_CONFIG: FirebaseRuntimeConfig = {
  apiKey: DUMMY_FIREBASE_KEY,
  authDomain: "cloakbrief-demo.firebaseapp.com",
  projectId: "cloakbrief-demo",
  appId: "1:1234567890:web:abcdef123456",
  cloudModel: "gemini-4-hydrogen",
};

const SENSITIVE_SAMPLE = [
  "INCIDENT #771 — Payment Gateway Failure",
  "Reported by: Maya Lin (maya.lin@acme-fin.io, +1-415-890-3342)",
  "DATABASE_URL=postgres://admin:UltraSecret99@db.internal:5432/ledger",
  `STRIPE_SECRET_KEY=${DUMMY_STRIPE_KEY}`,
  `AUTH_HEADER=Bearer ${DUMMY_JWT_HEADER}`,
].join("\n");

describe("hybridAi orchestrator & edge cases", () => {
  it("validates partial vs complete Firebase configs safely", () => {
    expect(hasValidFirebaseConfig(EMPTY_CONFIG)).toBe(false);
    expect(hasValidFirebaseConfig({ ...VALID_CONFIG, projectId: "   " })).toBe(false);
    expect(hasValidFirebaseConfig(VALID_CONFIG)).toBe(true);
  });

  it("runs sandbox preview cleanly when Firebase config is missing without leaking secrets", async () => {
    const result = await analyzeDocumentWithHybridAi({
      rawText: SENSITIVE_SAMPLE,
      mode: InferenceMode.PREFER_ON_DEVICE,
      config: EMPTY_CONFIG,
    });

    expect(result.telemetry.executionMode).toBe("sandbox_preview");
    expect(result.telemetry.stage2Source).toBe("sandbox_local");
    expect(result.telemetry.leakCheckPassed).toBe(true);
    expect(result.cloudPayloadSent).not.toContain(DUMMY_STRIPE_PART);
    expect(result.cloudPayloadSent).not.toContain("UltraSecret99");
    expect(result.cloudPayloadSent).not.toContain("maya.lin@acme-fin.io");
    expect(result.rehydratedBrief.actionItems.join("\n")).toContain("maya.lin@acme-fin.io");
  });

  it("enforces zero-leak payload to Stage 2 cloud spy and propagates on_device + in_cloud telemetry", async () => {
    const stage1Spy = vi.fn().mockResolvedValue({
      text: JSON.stringify({
        documentType: "DevSecOps Incident",
        riskLevel: "CRITICAL",
        extraEntities: [{ text: "Helios Ledger", category: "CUSTOM_PII" }],
      }),
      inferenceSource: InferenceSource.ON_DEVICE,
    });

    const stage2Spy = vi.fn().mockResolvedValue({
      text: JSON.stringify({
        documentType: "DevSecOps Incident",
        riskLevel: "CRITICAL",
        executiveSummary: "Outage impacted [PERSON_NAME_1] via [API_SECRET_1] and [DATABASE_URI_1].",
        riskFindings: [
          { severity: "CRITICAL", title: "Credential Leak", detail: "Rotate [API_SECRET_1] immediately." },
        ],
        actionItems: ["Email [EMAIL_1] and alert Helios Ledger ops to rotate [DATABASE_URI_1]."],
        complianceNotes: "Sanitized payload verified.",
      }),
      inferenceSource: InferenceSource.IN_CLOUD,
    });

    const adapter: HybridAiAdapter = {
      runStage1OnDevice: stage1Spy,
      runStage2: stage2Spy,
    };

    const result = await analyzeDocumentWithHybridAi({
      rawText: `${SENSITIVE_SAMPLE}\nService: Helios Ledger`,
      mode: InferenceMode.PREFER_IN_CLOUD,
      config: VALID_CONFIG,
      adapter,
    });

    expect(stage1Spy).toHaveBeenCalledTimes(1);
    expect(stage2Spy).toHaveBeenCalledTimes(1);

    const outboundStage2Prompt = String(stage2Spy.mock.calls[0][0]);
    expect(outboundStage2Prompt).not.toContain(DUMMY_STRIPE_PART);
    expect(outboundStage2Prompt).not.toContain("UltraSecret99");
    expect(outboundStage2Prompt).not.toContain("maya.lin@acme-fin.io");
    expect(outboundStage2Prompt).not.toContain("Helios Ledger");

    expect(result.telemetry.executionMode).toBe("firebase_hybrid");
    expect(result.telemetry.stage1Source).toBe("on_device");
    expect(result.telemetry.stage2Source).toBe("in_cloud");
    expect(result.maskedBrief.actionItems[0]).toContain("[EMAIL_1]");
    expect(result.rehydratedBrief.actionItems[0]).toContain("maya.lin@acme-fin.io");
    expect(result.rehydratedBrief.executiveSummary).not.toContain(DUMMY_STRIPE_PART);
  });

  it("fails open cleanly in Stage 1 when on-device Nano is unavailable without sending raw Stage 1 text to cloud", async () => {
    const stage1Spy = vi.fn().mockRejectedValue(new Error("Prompt API unavailable in headless browser"));
    const stage2Spy = vi.fn().mockResolvedValue({
      text: JSON.stringify({
        documentType: "Sanitized Report",
        riskLevel: "HIGH",
        executiveSummary: "Protected [EMAIL_1] and [API_SECRET_1].",
        riskFindings: [{ severity: "HIGH", title: "Key Leak", detail: "Found [API_SECRET_1]." }],
        actionItems: ["Notify [PERSON_NAME_1]."],
        complianceNotes: "Passed",
      }),
      inferenceSource: InferenceSource.IN_CLOUD,
    });

    const result = await analyzeDocumentWithHybridAi({
      rawText: SENSITIVE_SAMPLE,
      mode: InferenceMode.PREFER_ON_DEVICE,
      config: VALID_CONFIG,
      adapter: { runStage1OnDevice: stage1Spy, runStage2: stage2Spy },
    });

    expect(result.telemetry.stage1Source).toBe("deterministic_local");
    expect(result.telemetry.stage2Source).toBe("in_cloud");
    expect(result.telemetry.deviceModelNote).toContain("Prompt API unavailable");
    expect(String(stage2Spy.mock.calls[0][0])).not.toContain(DUMMY_STRIPE_PART);
  });

  it("does not silently escalate to cloud when ONLY_ON_DEVICE Stage 2 errors", async () => {
    const adapter: HybridAiAdapter = {
      runStage1OnDevice: vi.fn().mockResolvedValue({
        text: '{"documentType":"Doc","riskLevel":"LOW","extraEntities":[]}',
        inferenceSource: InferenceSource.ON_DEVICE,
      }),
      runStage2: vi.fn().mockRejectedValue(new Error("ONLY_ON_DEVICE model unavailable")),
    };

    await expect(
      analyzeDocumentWithHybridAi({
        rawText: SENSITIVE_SAMPLE,
        mode: InferenceMode.ONLY_ON_DEVICE,
        config: VALID_CONFIG,
        adapter,
      }),
    ).rejects.toThrow(/ONLY_ON_DEVICE/);
  });

  it("normalizes non-JSON Stage 2 text without crashing", async () => {
    const adapter: HybridAiAdapter = {
      runStage1OnDevice: vi.fn().mockResolvedValue({ text: "not valid json", inferenceSource: "on_device" }),
      runStage2: vi.fn().mockResolvedValue({
        text: "Plain text summary referencing [EMAIL_1] and [API_SECRET_1].",
        inferenceSource: InferenceSource.ON_DEVICE,
      }),
    };

    const result = await analyzeDocumentWithHybridAi({
      rawText: SENSITIVE_SAMPLE,
      mode: InferenceMode.PREFER_ON_DEVICE,
      config: VALID_CONFIG,
      adapter,
    });

    expect(result.telemetry.stage2Source).toBe("on_device");
    expect(result.maskedBrief.executiveSummary).toContain("[EMAIL_1]");
    expect(result.rehydratedBrief.executiveSummary).toContain("maya.lin@acme-fin.io");
    expect(result.rehydratedBrief.executiveSummary).not.toContain(DUMMY_STRIPE_PART);
  });

  it("prevents placeholder collision in follow-up Q&A and rehydrates non-secret PII locally", async () => {
    const analysis = await analyzeDocumentWithHybridAi({
      rawText: SENSITIVE_SAMPLE,
      mode: InferenceMode.ONLY_IN_CLOUD,
      config: EMPTY_CONFIG,
    });

    const followUpSpy = vi.fn().mockImplementation(async (prompt: string) => {
      return {
        text: `Coordinate [EMAIL_1] with [EMAIL_2] and rotate [API_SECRET_1] from ${prompt.includes("[EMAIL_2]") ? "audit" : "doc"}.`,
        inferenceSource: InferenceSource.IN_CLOUD,
      };
    });

    const answer = await askFollowUpWithHybridAi({
      sanitizedDocument: analysis.redaction.sanitizedText,
      entries: analysis.redaction.entries,
      question: `Should maya.lin@acme-fin.io escalate to secops@acme-fin.io about ${DUMMY_STRIPE_KEY}?`,
      mode: InferenceMode.PREFER_IN_CLOUD,
      config: VALID_CONFIG,
      adapter: {
        runStage1OnDevice: vi.fn(),
        runStage2: followUpSpy,
        runFollowUp: followUpSpy,
      },
    });

    expect(followUpSpy).toHaveBeenCalledTimes(1);
    const outboundQ = String(followUpSpy.mock.calls[0][0]);
    expect(outboundQ).not.toContain("maya.lin@acme-fin.io");
    expect(outboundQ).not.toContain("secops@acme-fin.io");
    expect(outboundQ).not.toContain(DUMMY_STRIPE_PART);

    expect(answer.sanitizedQuestionSent).toContain("[EMAIL_1]");
    expect(answer.sanitizedQuestionSent).toContain("[EMAIL_2]");
    expect(answer.rehydratedAnswer).toContain("maya.lin@acme-fin.io");
    expect(answer.rehydratedAnswer).toContain("secops@acme-fin.io");
    expect(answer.rehydratedAnswer).not.toContain(DUMMY_STRIPE_PART);
    expect(answer.rehydratedAnswer).toContain("[SECRET_PROTECTED:API_SECRET]");
  });

  it("falls back to ONLY_IN_CLOUD if PREFER_ON_DEVICE runtime fails with context quota error", async () => {
    const stage2Spy = vi
      .fn()
      .mockRejectedValueOnce(new Error("The input is too large."))
      .mockResolvedValueOnce({
        text: JSON.stringify({
          documentType: "Cloud Fallback Brief",
          riskLevel: "HIGH",
          executiveSummary: "Recovered in cloud for [EMAIL_1] while keeping [API_SECRET_1] masked.",
          riskFindings: [{ severity: "HIGH", title: "Key Leak", detail: "Rotate [API_SECRET_1]." }],
          actionItems: ["Alert [PERSON_NAME_1]."],
          complianceNotes: "Sanitized fallback ok.",
        }),
        inferenceSource: InferenceSource.IN_CLOUD,
      });

    const result = await analyzeDocumentWithHybridAi({
      rawText: SENSITIVE_SAMPLE,
      mode: InferenceMode.PREFER_ON_DEVICE,
      config: VALID_CONFIG,
      adapter: {
        runStage1OnDevice: vi.fn().mockRejectedValue(new Error("Nano unavailable")),
        runStage2: stage2Spy,
      },
    });

    expect(stage2Spy).toHaveBeenCalledTimes(2);
    expect(stage2Spy.mock.calls[1][1]).toBe(InferenceMode.ONLY_IN_CLOUD);
    expect(result.telemetry.stage2Source).toBe("in_cloud");
    expect(result.telemetry.deviceModelNote).toContain("On-device fallback to cloud");
    expect(result.rehydratedBrief.executiveSummary).toContain("maya.lin@acme-fin.io");
  });

  it("falls back automatically to gemini-3.5-flash-lite when primary cloud model hits 429 daily quota", async () => {
    const stage2Spy = vi
      .fn()
      .mockRejectedValueOnce(new Error("AI/fetch-error: 429 Quota exceeded for gemini-4-hydrogen (limit 20)"))
      .mockResolvedValueOnce({
        text: JSON.stringify({
          documentType: "Quota Fallback Brief",
          riskLevel: "HIGH",
          executiveSummary: "Analyzed via Flash-Lite for [EMAIL_1] with [API_SECRET_1] protected.",
          riskFindings: [{ severity: "HIGH", title: "Secret Exposure", detail: "Rotate [API_SECRET_1]." }],
          actionItems: ["Notify [PERSON_NAME_1]."],
          complianceNotes: "Auto-fallback preserved zero-leak guarantee.",
        }),
        inferenceSource: InferenceSource.IN_CLOUD,
      });

    const result = await analyzeDocumentWithHybridAi({
      rawText: SENSITIVE_SAMPLE,
      mode: InferenceMode.PREFER_ON_DEVICE,
      config: VALID_CONFIG,
      adapter: {
        runStage1OnDevice: vi.fn().mockRejectedValue(new Error("Nano unavailable")),
        runStage2: stage2Spy,
      },
    });

    expect(stage2Spy).toHaveBeenCalledTimes(2);
    expect(stage2Spy.mock.calls[0][2]).toBe("gemini-4-hydrogen");
    expect(stage2Spy.mock.calls[1][2]).toBe("gemini-3.5-flash-lite");
    expect(result.telemetry.stage2Source).toBe("in_cloud");
    expect(result.telemetry.deviceModelNote).toContain("gemini-3.5-flash-lite");
  });
});
