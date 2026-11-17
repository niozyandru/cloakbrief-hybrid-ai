export interface SampleWorkload {
  id: string;
  label: string;
  category: string;
  description: string;
  content: string;
}

const buildDemoToken = (...parts: string[]) => parts.join("");

export const SAMPLE_WORKLOADS: SampleWorkload[] = [
  {
    id: "prod-env-incident",
    label: "Prod Incident + .env Leak",
    category: "DevSecOps",
    description: "Crash postmortem containing live API keys, bearer tokens, internal DB URI & on-call engineer contact.",
    content: `INCIDENT REPORT #4821 — Checkout Payment Timeout
Reported by: Maya Lin (maya.lin@acme-fin.io, +1-415-890-3342)
Account Ref: ACCT-99812401 | Host IP: 10.42.18.91

Observed exception in worker-eu-west-2:
Upstream gateway returned HTTP 503 after retry storm exhausted pool quota.

Captured config snapshot from crash dump (DO NOT FORWARD):
DATABASE_URL=postgres://svc_checkout:Str0ngP@ss!2026@db.internal.acme:5432/prod_ledger
STRIPE_SECRET_KEY=${buildDemoToken("sk", "_live_", "51N9xAbCdEfGhIjKlMnOpQrStUvWxYz0123456789")}
OPENAI_API_KEY=${buildDemoToken("sk", "-proj-", "99887766554433221100AaBbCcDdEeFfGgHhIiJjKkLlMm")}
AUTH_BEARER=Bearer ${buildDemoToken("eyJ", "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.", "eyJzdWIiOiIxMjM0NTYifQ.", "sigXYZ")}

Customer Impact:
- 412 orders stalled totaling $48,920.50 USD during 14:10-14:28 UTC.
- Immediate remediation needed: rotate leaked keys, add jittered exponential backoff, and decouple webhook retries.`,
  },
  {
    id: "enterprise-nda",
    label: "Executive Vendor Contract",
    category: "Legal / Finance",
    description: "Draft MSA containing executive names, compensation terms, IBAN routing & termination clauses.",
    content: `MASTER SERVICES AGREEMENT (CONFIDENTIAL DRAFT)
Between: Helios Robotics Inc. (Signer: David Kowalski, d.kowalski@helios-robotics.com)
And: Nadia Vance Consulting LLC (Signer: Nadia Vance, SSN-ref 441-88-2910, +1-650-555-0194)

1. Commercial Terms:
- Retainer Fee: $18,500.00 USD / month, payable net-7 via wire to Account 4412-8890-1122-3344 (Routing 021000021).
- Performance Milestone Bonus: $45,000 USD upon SOC-2 Type II sign-off before Dec 15, 2026.

2. Liability & IP Risk:
- Section 8.3 currently grants Provider an uncapped indemnity carve-out and automatic 24-month renewal unless terminated 90 days prior.
- Client owns deliverables only after final settlement of all disputed invoices, creating holdback leverage risk.`,
  },
  {
    id: "patient-intake",
    label: "Clinical Triage Note",
    category: "Healthcare",
    description: "Telehealth escalation summary with patient identifiers, MRN, phone & medication interactions.",
    content: `CLINICAL ESCALATION NOTE — URGENT TRIAGE
Patient: Elena Rostova | DOB: 1984-07-19 | MRN: MRN-8841209
Contact: elena.rostova@mail-health.org | Phone: +1-312-555-0178
Emergency Contact: Viktor Rostov (+1-312-555-0199)

Chief Complaint:
42yo female presents with 3 days of progressive palpitations, orthostatic dizziness, and systolic BP drop to 88/54 mmHg after doubling prescribed dose of Lisinopril 20mg alongside Ibuprofen 800mg TID.

Triage Request:
Summarize immediate drug-interaction risks, red-flag escalation criteria, and patient-friendly next steps for the attending physician.`,
  },
  {
    id: "support-chargeback",
    label: "VIP Customer Escalation",
    category: "Customer Ops",
    description: "High-value fintech ticket containing user wallet/card tokens, email & SLA breach threat.",
    content: `TICKET #VIP-90412 — URGENT ESCALATION
Customer: Marcus Thorne (m.thorne@meridian-ventures.co, +44-20-7946-0821)
Solana Treasury Wallet: 7xKXtR9mP2nQwV4zL8cB5yN1dG6hJ3kS9uF2aE4rT8wX
Card Last4 Ref: 4532-xxxx-xxxx-9910 | Charge Amount: $12,450.00 USDC

Summary:
Customer attempted cross-border settlement at 09:14 UTC. Quote expired mid-flight; $12,450.00 USDC was debited from escrow wallet while ledger status stayed PENDING for 6 hours. Customer threatens regulatory complaint within 24 hours unless reconciliation receipt and SLA credit are issued today.`,
  },
];
