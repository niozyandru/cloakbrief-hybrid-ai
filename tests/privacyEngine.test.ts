import { describe, expect, it } from "vitest";
import {
  assertNoUnmaskedSecrets,
  redactTextLocally,
  rehydrateTextLocally,
} from "../src/privacyEngine";
import { SAMPLE_WORKLOADS } from "../src/samples";

const STRIPE_LIVE_PREFIX = ["sk", "live"].join("_") + "_";
const OPENAI_PROJ_PREFIX = ["sk", "proj"].join("-") + "-";
const DEMO_STRIPE_SECRET = `${STRIPE_LIVE_PREFIX}51N9xAbCdEfGhIjKlMnOpQrStUvWx`;
const DEMO_GH_TOKEN = ["ghp", "1234567890abcdefghijklmnop"].join("_");

describe("privacyEngine local redaction & rehydration", () => {
  it("masks API secrets, database URIs, bearer tokens, emails, phones, and names locally", () => {
    const sample = SAMPLE_WORKLOADS[0].content;
    const res = redactTextLocally(sample);

    expect(res.leakCheckPassed).toBe(true);
    expect(assertNoUnmaskedSecrets(res.sanitizedText)).toBe(true);
    expect(res.sanitizedText).not.toContain(STRIPE_LIVE_PREFIX);
    expect(res.sanitizedText).not.toContain(OPENAI_PROJ_PREFIX);
    expect(res.sanitizedText).not.toContain("Str0ngP@ss!2026");
    expect(res.sanitizedText).not.toContain("maya.lin@acme-fin.io");
    expect(res.sanitizedText).not.toContain("Maya Lin");
    expect(res.sanitizedText).toContain("[DATABASE_URI_1]");
    expect(res.sanitizedText).toContain("[API_SECRET_1]");
    expect(res.sanitizedText).toContain("[EMAIL_1]");
  });

  it("deduplicates identical entity strings to a single consistent placeholder", () => {
    const text = "Customer: Alice Smith emailed alice@example.com and Alice Smith signed.";
    const res = redactTextLocally(text, [{ text: "Alice Smith", category: "PERSON_NAME" }]);

    expect(res.sanitizedText).toBe(
      "Customer: [PERSON_NAME_1] emailed [EMAIL_1] and [PERSON_NAME_1] signed."
    );
    expect(res.entries.filter((e) => e.original === "Alice Smith")).toHaveLength(1);
  });

  it("handles regex special characters in AI-discovered spans safely", () => {
    const text = "Project Atlas (v2.0+alpha) paid $1,250.00 USD.";
    const res = redactTextLocally(text, [{ text: "Atlas (v2.0+alpha)", category: "CUSTOM_PII" }]);

    expect(res.sanitizedText).toContain("[CUSTOM_PII_1]");
    expect(res.sanitizedText).toContain("[MONETARY_AMOUNT_1]");
  });

  it("rehydrates PII locally while keeping hard credentials protected by default", () => {
    const text = `Reported by: Maya Lin (maya@acme.io)\nSTRIPE_SECRET_KEY=${DEMO_STRIPE_SECRET}`;
    const res = redactTextLocally(text);
    const cloudReply = `Rotate ${res.entries.find((e) => e.category === "API_SECRET")?.placeholder} and notify [PERSON_NAME_1] ([EMAIL_1]).`;

    const safeView = rehydrateTextLocally(cloudReply, res.entries, false);
    expect(safeView).toContain("Maya Lin");
    expect(safeView).toContain("maya@acme.io");
    expect(safeView).not.toContain(STRIPE_LIVE_PREFIX);
    expect(safeView).toContain("[SECRET_PROTECTED:API_SECRET]");

    const revealedView = rehydrateTextLocally(cloudReply, res.entries, true);
    expect(revealedView).toContain(DEMO_STRIPE_SECRET);
  });

  it("fails leak check if a raw secret bypasses tokenization", () => {
    expect(assertNoUnmaskedSecrets(`key=${STRIPE_LIVE_PREFIX}51N9xAbCdEfGhIjKlMnOp`)).toBe(false);
    expect(assertNoUnmaskedSecrets(`pat=${DEMO_GH_TOKEN}`)).toBe(false);
    expect(assertNoUnmaskedSecrets("safe=[API_SECRET_1]")).toBe(true);
  });

  it("handles empty and whitespace-only inputs cleanly", () => {
    const empty = redactTextLocally("   \n ");
    expect(empty.sanitizedText).toBe("");
    expect(empty.entries).toHaveLength(0);
    expect(empty.leakCheckPassed).toBe(true);
  });
});
