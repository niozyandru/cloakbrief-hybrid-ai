# CloakBrief — Privacy-First Hybrid AI Workspace

> Built for the **Google `#BuildHybridAI` Hackathon (2026)** using **Firebase AI Logic (`firebase/ai`)** — combining **On-Device Gemini Nano** (Chrome Built-in AI) with **Cloud Gemini 4 Hydrogen / 3.8 Flash** behind a deterministic **Zero-Leak Vault Barrier**.

---

## Why CloakBrief?

Developers, legal teams, clinicians, and support engineers constantly want AI summaries of high-sensitivity text (production crash dumps with `.env` API keys, vendor MSAs with bank routing/SSNs, clinical triage notes, or fraud logs) — **without** streaming raw secrets to cloud servers or blocking offline work.

**CloakBrief guarantees that raw credentials and PII NEVER leave your browser:**

1. **Stage 1 — On-Device Edge Guard (`ONLY_ON_DEVICE`)**:
   - Invokes Chrome's on-device **Gemini Nano** via Firebase AI Logic (`InferenceMode.ONLY_ON_DEVICE`) to detect contextual PII (`PERSON_NAME`, `CUSTOM_PII`) and classify risk locally — raw unmasked text never travels over the network.
   - Runs in lockstep with a deterministic regex + signature **Zero-Leak Redaction Vault** (`src/privacyEngine.ts`) catching Stripe/OpenAI/Gemini/GitHub/AWS keys, database URIs, JWT bearer tokens, emails, phones, SSNs/MRNs, payment accounts, wallet addresses, and internal IPs.
2. **Stage 2 — Zero-Leak Outbound Barrier**:
   - Before any Stage 2 call fires, `assertNoUnmaskedSecrets()` blocks outbound execution if any secret pattern remains unmasked.
   - Users choose exact Firebase Hybrid Inference routing:
     - `PREFER_ON_DEVICE` (Offline-capable Gemini Nano first, automatic cloud Gemini escalation)
     - `ONLY_ON_DEVICE` (Strict browser-only airgap)
     - `PREFER_IN_CLOUD` / `ONLY_IN_CLOUD` (Deep Cloud reasoning strictly over masked tokens `[API_SECRET_1]`, `[EMAIL_1]`)
3. **Stage 3 — Telemetry & Local Rehydration**:
   - Tracks real `response.inferenceSource` (`"on_device"` vs `"in_cloud"`), stage latency, and protected entity counts.
   - Restores non-secret context PII (`[PERSON_NAME_1]`, `[EMAIL_1]`) locally inside the browser while keeping hard secrets (`[SECRET_PROTECTED:API_SECRET]`) locked unless explicitly unlocked.

---

## Architecture Flow

```text
Raw Sensitive Input (local browser memory only)
   │
   ▼
Stage 1: Gemini Nano (ONLY_ON_DEVICE) + Deterministic Zero-Leak Engine
   │  └─ Maps secrets -> [API_SECRET_1], [DATABASE_URI_1], [EMAIL_1] in local Vault
   ▼
Zero-Leak Barrier Gatekeeper (assertNoUnmaskedSecrets === true)
   │
   ▼
Stage 2: Firebase AI Logic (PREFER_ON_DEVICE | ONLY_ON_DEVICE | PREFER_IN_CLOUD | ONLY_IN_CLOUD)
   │  ├─ When On-Device -> Chrome Gemini Nano (offline capable, $0 cloud cost)
   │  └─ When In-Cloud  -> GoogleAIBackend (gemini-4-hydrogen / gemini-3.8-flash) sees ONLY [PLACEHOLDERS]
   ▼
Local Client Rehydration & Export (.MD Report / .JSON Zero-Leak Audit)
```

---

## Tech Stack

- **AI SDK**: `firebase` (`v13.4.0`, `firebase/ai` Hybrid Inference + `GoogleAIBackend`)
- **Frontend**: React 19, TypeScript 5.8, Vite 6, Lucide Icons
- **Tests**: Vitest + JSDOM (`tests/privacyEngine.test.ts`, `tests/hybridAi.test.ts`)

---

## Quick Start (Local Development)

### 1. Install Dependencies & Run Tests

```bash
npm install
npm run typecheck
npm test
npm run dev
```

Open `http://localhost:5173`. CloakBrief launches immediately in **Sandbox Preview Mode** so every privacy inspection panel, payload diff, rehydration toggle, Q&A flow, and export button works right away even before connecting Firebase.

### 2. Connect Free Firebase Spark Plan & Enable AI Logic + App Check

1. Open [Firebase Console](https://console.firebase.google.com/) and create or select a free **Spark** project (no credit card required).
2. Enable **Firebase AI Logic (Gemini Developer API)** — either in the console (**Build → AI Logic → Get started**) or via Firebase CLI:
   ```bash
   npx -y firebase-tools@latest login
   npx -y firebase-tools@latest use <YOUR_PROJECT_ID>
   npx -y firebase-tools@latest init ailogic
   ```
3. *(Recommended)* Enable **Firebase App Check** (reCAPTCHA v3 site key or debug token for hackathon judging) and paste the Web App `firebaseConfig` (plus optional App Check key/token) into **Sandbox Mode · Setup Firebase** in the top bar (or in `.env` from `.env.example`).
4. *(Optional for On-Device Gemini Nano)* Use Chrome 139+ with Prompt API enabled (`chrome://flags/#prompt-api-for-gemini-nano`) and click **Warm Up Nano**.

### 3. Build & Deploy to Standalone Firebase Hosting (`*.web.app`)

```bash
npm run build
npx -y firebase-tools@latest deploy --only hosting
```

Your app will deploy cleanly to `https://<YOUR_PROJECT_ID>.web.app` (configured via `firebase.json` for SPA hosting with HTTPS enabled for Chrome Prompt API).

---

## License

Licensed under the [Apache License 2.0](./LICENSE).

---

## 2.5-Minute YouTube Demo Script (For `#BuildHybridAI` Submission)

- **0:00–0:25 | Hook**: Show pasting a real-looking production crash log containing `sk_live_...`, `postgres://...`, JWT bearer token, and engineer email into AI tools — and the security nightmare of leaking credentials to cloud APIs.
- **0:25–0:55 | Stage 1 On-Device Guard & Zero-Leak Barrier**: Open **CloakBrief**, switch preset tabs (`Prod Incident + .env Leak`, `Executive Vendor Contract`, `Clinical Triage Note`), highlight the **Zero-Leak Outbound Guard -> Cloud Payload** panel showing zero raw keys in outbound payload.
- **0:55–1:40 | Firebase AI Logic Hybrid Inference Live**: Switch inference modes (`Prefer On-Device`, `Only On-Device`, `Prefer In-Cloud`), click **Warm Up Nano** / **Analyze with Hybrid AI**, highlight live `inferenceSource` telemetry badge (`On-Device Nano` vs `Cloud Gemini`) + latency + interactive offline toggle.
- **1:40–2:15 | Local Rehydration & Encrypted Follow-Up Q&A**: Toggle **Rehydrated Local** vs **Masked View** and show how hard keys stay protected (`[SECRET_PROTECTED:API_SECRET]`) while engineer contact context returns locally. Ask a follow-up question mentioning an email and prove outbound Q&A only transmits `[EMAIL_1]`.
- **2:15–2:35 | Wrap-Up**: Export `.MD` Executive Brief + `.JSON` Zero-Leak Audit Trail and recap Firebase AI Logic Hybrid Architecture.
