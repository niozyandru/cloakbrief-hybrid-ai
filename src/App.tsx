import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Cloud,
  Cpu,
  Download,
  Eye,
  EyeOff,
  FileText,
  KeyRound,
  Lock,
  Moon,
  RefreshCw,
  Send,
  Settings,
  ShieldCheck,
  Sparkles,
  Sun,
  Upload,
  Wifi,
  WifiOff,
  X,
} from "lucide-react";
import {
  analyzeDocumentWithHybridAi,
  askFollowUpWithHybridAi,
  clearFirebaseConfig,
  CLOUD_MODEL_OPTIONS,
  DEFAULT_CLOUD_MODEL,
  hasValidFirebaseConfig,
  InferenceMode,
  loadFirebaseConfig,
  probeDeviceNanoAvailability,
  rehydrateAnalysisOutput,
  saveFirebaseConfig,
  warmUpDeviceModel,
  type DeviceNanoStatus,
  type FirebaseRuntimeConfig,
  type FollowUpOutput,
  type HybridAnalysisOutput,
  type InferenceModeValue,
} from "./hybridAi";
import { redactTextLocally, rehydrateTextLocally, type VaultEntry } from "./privacyEngine";
import { SAMPLE_WORKLOADS } from "./samples";

interface QaEntry extends FollowUpOutput {
  id: string;
  rawQuestion: string;
}

function maskPreviewOriginal(original: string, sensitiveSecret: boolean, revealed: boolean): string {
  if (!sensitiveSecret || revealed) {
    return original;
  }
  if (original.length <= 10) return "••••••••";
  return `${original.slice(0, 5)}••••${original.slice(-4)}`;
}

function renderHighlightedPayload(text: string): React.ReactNode {
  const parts = text.split(/(\[[A-Z_]+_\d+\])/g);
  return parts.map((part, idx) => {
    const match = /^\[([A-Z_]+)_\d+\]$/.exec(part);
    if (!match) {
      return <React.Fragment key={idx}>{part}</React.Fragment>;
    }
    const isSecret =
      match[1] === "API_SECRET" || match[1] === "AUTH_TOKEN" || match[1] === "DATABASE_URI";
    return (
      <span key={idx} className={isSecret ? "token-pill secret" : "token-pill"}>
        {part}
      </span>
    );
  });
}

function parsePastedFirebaseSnippet(snippet: string): Partial<FirebaseRuntimeConfig> | null {
  const extract = (key: string): string => {
    const re = new RegExp(`["']?${key}["']?\\s*:\\s*["']([^"']+)["']`, "i");
    return re.exec(snippet)?.[1]?.trim() ?? "";
  };
  const apiKey = extract("apiKey");
  const authDomain = extract("authDomain");
  const projectId = extract("projectId");
  const appId = extract("appId");
  if (!apiKey && !projectId && !appId) return null;
  return { apiKey, authDomain, projectId, appId };
}

function sourceBadgeLabel(source: string): string {
  if (source === "on_device") return "On-Device Nano";
  if (source === "in_cloud") return "Cloud Gemini";
  if (source === "deterministic_local") return "Local Vault";
  return "Sandbox Preview";
}

export default function App() {
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [isOnline, setIsOnline] = useState<boolean>(
    typeof navigator !== "undefined" ? navigator.onLine : true,
  );
  const [nanoStatus, setNanoStatus] = useState<DeviceNanoStatus>("unsupported");
  const [firebaseConfig, setFirebaseConfig] = useState<FirebaseRuntimeConfig>(() =>
    loadFirebaseConfig(),
  );
  const [mode, setMode] = useState<InferenceModeValue>(InferenceMode.PREFER_ON_DEVICE);

  const [selectedSampleId, setSelectedSampleId] = useState<string>(SAMPLE_WORKLOADS[0].id);
  const [rawText, setRawText] = useState<string>(SAMPLE_WORKLOADS[0].content);
  const [customQuestion, setCustomQuestion] = useState<string>("");

  const [analysis, setAnalysis] = useState<HybridAnalysisOutput | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const [centerTab, setCenterTab] = useState<"payload" | "vault" | "diff">("payload");
  const [showRehydrated, setShowRehydrated] = useState<boolean>(true);
  const [revealHardSecrets, setRevealHardSecrets] = useState<boolean>(false);

  const [warmProgress, setWarmProgress] = useState<number | null>(null);
  const [warmMessage, setWarmMessage] = useState<string | null>(null);

  const [followUpInput, setFollowUpInput] = useState<string>("");
  const [isAskingFollowUp, setIsAskingFollowUp] = useState<boolean>(false);
  const [qaHistory, setQaHistory] = useState<QaEntry[]>([]);

  const [isConfigOpen, setIsConfigOpen] = useState<boolean>(false);
  const [draftConfig, setDraftConfig] = useState<FirebaseRuntimeConfig>(firebaseConfig);
  const [snippetPaste, setSnippetPaste] = useState<string>("");
  const [snippetMsg, setSnippetMsg] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const hasFirebase = hasValidFirebaseConfig(firebaseConfig);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  useEffect(() => {
    const onUp = () => setIsOnline(true);
    const onDown = () => setIsOnline(false);
    window.addEventListener("online", onUp);
    window.addEventListener("offline", onDown);
    probeDeviceNanoAvailability().then(setNanoStatus).catch(() => setNanoStatus("unsupported"));
    return () => {
      window.removeEventListener("online", onUp);
      window.removeEventListener("offline", onDown);
    };
  }, []);

  // Live instant local preview redaction before submitting
  const liveLocalRedaction = useMemo(() => redactTextLocally(rawText), [rawText]);

  // Render instant zero-quota Local Sandbox Showcase on initial page open; live Cloud calls fire only on explicit user action
  useEffect(() => {
    let active = true;
    const initialCfg = loadFirebaseConfig();
    analyzeDocumentWithHybridAi({
      rawText: SAMPLE_WORKLOADS[0].content,
      mode: InferenceMode.PREFER_ON_DEVICE,
      config: { ...initialCfg, apiKey: "", projectId: "", appId: "" },
      revealHardSecrets: false,
    })
      .then((res) => {
        if (active) setAnalysis(res);
      })
      .catch(() => {
        // Safe ignore
      });
    return () => {
      active = false;
    };
  }, []);

  const displayedBrief = useMemo(() => {
    if (!analysis) return null;
    if (!showRehydrated) return analysis.maskedBrief;
    return rehydrateAnalysisOutput(analysis.maskedBrief, analysis.redaction.entries, revealHardSecrets);
  }, [analysis, showRehydrated, revealHardSecrets]);

  const activeRedaction = analysis?.redaction ?? liveLocalRedaction;

  const handleSelectSample = (sampleId: string) => {
    const found = SAMPLE_WORKLOADS.find((s) => s.id === sampleId);
    if (!found) return;
    setSelectedSampleId(found.id);
    setRawText(found.content);
    setCustomQuestion("");
    setQaHistory([]);
    setErrorMsg(null);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 250_000) {
      setErrorMsg("File exceeds 250 KB limit for in-browser analysis.");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const content = typeof reader.result === "string" ? reader.result : "";
      setSelectedSampleId("custom");
      setRawText(content);
      setQaHistory([]);
      setErrorMsg(null);
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  const handleRunSandboxFallback = async () => {
    if (!rawText.trim()) return;
    setIsAnalyzing(true);
    try {
      const res = await analyzeDocumentWithHybridAi({
        rawText,
        customQuestion,
        mode,
        config: { ...firebaseConfig, apiKey: "", projectId: "", appId: "" },
        revealHardSecrets,
      });
      setAnalysis(res);
      setQaHistory([]);
      setErrorMsg(null);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleAnalyze = async () => {
    setErrorMsg(null);
    setIsAnalyzing(true);
    try {
      const res = await analyzeDocumentWithHybridAi({
        rawText,
        customQuestion,
        mode,
        config: firebaseConfig,
        revealHardSecrets,
      });
      setAnalysis(res);
      setQaHistory([]);
    } catch (err) {
      const rawMsg = err instanceof Error ? err.message : "Failed to run hybrid analysis.";
      if (rawMsg.toLowerCase().includes("app check") || rawMsg.includes("401")) {
        setErrorMsg(
          "Firebase AI Logic rejected Cloud request (App Check token required/invalid). Add an App Check Site Key / Debug Token in Firebase Setup, or click Run Sandbox Preview.",
        );
      } else {
        setErrorMsg(rawMsg);
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleWarmUpNano = async () => {
    setWarmProgress(0);
    setWarmMessage("Initializing Chrome Gemini Nano model...");
    const res = await warmUpDeviceModel(firebaseConfig, (pct) => setWarmProgress(pct));
    setWarmProgress(null);
    setWarmMessage(res.message);
    probeDeviceNanoAvailability().then(setNanoStatus).catch(() => undefined);
  };

  const handleFollowUp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!followUpInput.trim() || !analysis) return;
    setIsAskingFollowUp(true);
    setErrorMsg(null);
    const question = followUpInput.trim();
    try {
      const res = await askFollowUpWithHybridAi({
        sanitizedDocument: analysis.redaction.sanitizedText,
        entries: analysis.redaction.entries,
        question,
        mode,
        config: firebaseConfig,
        revealHardSecrets,
      });
      setQaHistory((prev) => [
        ...prev,
        {
          id: `${Date.now()}-${prev.length}`,
          rawQuestion: question,
          ...res,
        },
      ]);
      setFollowUpInput("");
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Follow-up query failed.");
    } finally {
      setIsAskingFollowUp(false);
    }
  };

  const handleExportMarkdown = () => {
    if (!analysis || !displayedBrief) return;
    const md = [
      `# CloakBrief Report — ${displayedBrief.documentType}`,
      `- Risk Level: **${displayedBrief.riskLevel}**`,
      `- Execution Mode: \`${analysis.telemetry.executionMode}\``,
      `- Stage 1 Guard: \`${analysis.telemetry.stage1Source}\` (${analysis.telemetry.stage1LatencyMs}ms)`,
      `- Stage 2 Inference: \`${analysis.telemetry.stage2Source}\` (${analysis.telemetry.stage2LatencyMs}ms)`,
      `- Secrets Masked Locally: ${analysis.telemetry.secretsProtectedCount}`,
      `- Zero-Leak Verification: ${analysis.telemetry.leakCheckPassed ? "PASSED" : "FAILED"}`,
      "",
      "## Executive Summary",
      displayedBrief.executiveSummary,
      "",
      "## Key Risk Findings",
      ...displayedBrief.riskFindings.map((f) => `- **[${f.severity}] ${f.title}**: ${f.detail}`),
      "",
      "## Remediation Action Items",
      ...displayedBrief.actionItems.map((item, idx) => `${idx + 1}. ${item}`),
      "",
      "## Compliance Barrier",
      displayedBrief.complianceNotes,
    ].join("\n");

    const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cloakbrief-${displayedBrief.riskLevel.toLowerCase()}-report.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportAuditJson = () => {
    if (!analysis) return;
    const payload = {
      generatedAt: new Date().toISOString(),
      telemetry: analysis.telemetry,
      maskedBrief: analysis.maskedBrief,
      redactionCounts: analysis.redaction.countsByCategory,
      cloudPayloadSent: analysis.cloudPayloadSent,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "cloakbrief-zero-leak-audit.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  const openConfigModal = () => {
    setDraftConfig(firebaseConfig);
    setSnippetPaste("");
    setSnippetMsg(null);
    setIsConfigOpen(true);
  };

  const handleApplySnippet = () => {
    const parsed = parsePastedFirebaseSnippet(snippetPaste);
    if (!parsed) {
      setSnippetMsg("Could not find apiKey / projectId / appId in pasted snippet.");
      return;
    }
    setDraftConfig((prev) => ({
      ...prev,
      apiKey: parsed.apiKey || prev.apiKey,
      authDomain: parsed.authDomain || prev.authDomain,
      projectId: parsed.projectId || prev.projectId,
      appId: parsed.appId || prev.appId,
    }));
    setSnippetMsg("Parsed fields into form below. Click Save Config to activate.");
  };

  const handleSaveConfig = () => {
    const appCheckChanged =
      (draftConfig.appCheckDebugToken ?? "").trim() !== (firebaseConfig.appCheckDebugToken ?? "").trim() ||
      (draftConfig.appCheckSiteKey ?? "").trim() !== (firebaseConfig.appCheckSiteKey ?? "").trim();
    saveFirebaseConfig(draftConfig);
    setFirebaseConfig(draftConfig);
    setIsConfigOpen(false);
    if (appCheckChanged) {
      window.location.reload();
    }
  };

  const handleResetConfig = () => {
    clearFirebaseConfig();
    const empty: FirebaseRuntimeConfig = {
      apiKey: "",
      authDomain: "",
      projectId: "",
      appId: "",
      cloudModel: DEFAULT_CLOUD_MODEL,
      appCheckSiteKey: "",
      appCheckDebugToken: "",
    };
    setFirebaseConfig(empty);
    setDraftConfig(empty);
    setIsConfigOpen(false);
  };

  const renderQaAnswer = (item: QaEntry): string => {
    if (!showRehydrated) return item.maskedAnswer;
    return rehydrateTextLocally(item.maskedAnswer, item.entries as VaultEntry[], revealHardSecrets);
  };

  return (
    <div className="app-shell">
      {/* Header Toolbar */}
      <header className="topbar">
        <div className="brand-group">
          <div className="brand-logo" aria-hidden="true">
            <ShieldCheck size={22} />
          </div>
          <div>
            <h1 className="brand-title">
              CloakBrief
              <span className="pill pill-violet" style={{ fontSize: "11px", padding: "2px 8px" }}>
                #BuildHybridAI
              </span>
            </h1>
            <p className="brand-subtitle">
              On-Device Gemini Nano Zero-Leak Guard + Cloud Gemini via Firebase AI Logic
            </p>
          </div>
        </div>

        <div className="controls-group">
          <button
            type="button"
            onClick={openConfigModal}
            className={`pill pill-btn ${hasFirebase ? "pill-emerald" : "pill-amber"}`}
            title="Configure Firebase AI Logic Web Config"
          >
            <KeyRound size={13} />
            {hasFirebase ? "Firebase AI: Live" : "Sandbox Mode · Setup Firebase"}
          </button>

          <span
            className={`pill ${nanoStatus === "available" ? "pill-emerald" : "pill-amber"}`}
            title="Chrome Built-in Prompt API (Gemini Nano) status"
          >
            <Cpu size={13} />
            Nano: {nanoStatus === "available" ? "Ready" : nanoStatus}
          </span>

          <span className={`pill ${isOnline ? "pill-emerald" : "pill-rose"}`}>
            {isOnline ? <Wifi size={13} /> : <WifiOff size={13} />}
            {isOnline ? "Online" : "Offline"}
          </span>

          <select
            aria-label="Cloud Fallback Model"
            className="select-control"
            value={firebaseConfig.cloudModel || DEFAULT_CLOUD_MODEL}
            onChange={(e) => {
              const next = { ...firebaseConfig, cloudModel: e.target.value };
              setFirebaseConfig(next);
              if (hasValidFirebaseConfig(next)) {
                saveFirebaseConfig(next);
              }
            }}
            title="Select Cloud Gemini model used when Firebase AI Logic routes to cloud"
          >
            {CLOUD_MODEL_OPTIONS.map((opt) => (
              <option key={opt.id} value={opt.id}>
                {opt.label}
              </option>
            ))}
          </select>

          <select
            aria-label="Firebase Inference Mode"
            className="select-control"
            value={mode}
            onChange={(e) => setMode(e.target.value as InferenceModeValue)}
          >
            <option value={InferenceMode.PREFER_ON_DEVICE}>Prefer On-Device (Hybrid)</option>
            <option value={InferenceMode.ONLY_ON_DEVICE}>Only On-Device (Offline Airgap)</option>
            <option value={InferenceMode.PREFER_IN_CLOUD}>Prefer In-Cloud (Deep + Guard)</option>
            <option value={InferenceMode.ONLY_IN_CLOUD}>Only In-Cloud (Guard + Cloud Gemini)</option>
          </select>

          <button type="button" className="btn" onClick={handleWarmUpNano} disabled={warmProgress !== null}>
            <Sparkles size={14} />
            {warmProgress !== null ? `Downloading ${warmProgress}%` : "Warm Up Nano"}
          </button>

          <button type="button" className="btn" onClick={openConfigModal} aria-label="Firebase Settings">
            <Settings size={14} />
          </button>

          <button
            type="button"
            className="btn"
            onClick={() => setTheme((prev) => (prev === "dark" ? "light" : "dark"))}
            aria-label="Toggle Color Theme"
          >
            {theme === "dark" ? <Sun size={14} /> : <Moon size={14} />}
          </button>
        </div>
      </header>

      {/* Pipeline Overview Banner */}
      <section className="pipeline-banner" aria-label="Hybrid Inference Pipeline">
        <div className="pipeline-step active">
          <div className="step-icon">
            <Cpu size={16} />
          </div>
          <div className="step-meta">
            <div className="step-title">1. On-Device Edge Guard</div>
            <div className="step-desc">Gemini Nano + local PII scanner</div>
          </div>
        </div>

        <div className={`pipeline-step ${activeRedaction.leakCheckPassed ? "active" : ""}`}>
          <div className="step-icon">
            <ShieldCheck size={16} />
          </div>
          <div className="step-meta">
            <div className="step-title">2. Zero-Leak Vault Barrier</div>
            <div className="step-desc">
              {activeRedaction.entries.length} entities isolated before egress
            </div>
          </div>
        </div>

        <div className={`pipeline-step ${analysis ? "active" : ""}`}>
          <div className="step-icon">
            <Cloud size={16} />
          </div>
          <div className="step-meta">
            <div className="step-title">3. Hybrid AI Synthesis</div>
            <div className="step-desc">
              {analysis
                ? `Routed to ${sourceBadgeLabel(analysis.telemetry.stage2Source)}`
                : "Awaiting sanitized payload"}
            </div>
          </div>
        </div>

        <div className={`pipeline-step ${analysis ? "active" : ""}`}>
          <div className="step-icon">
            <Lock size={16} />
          </div>
          <div className="step-meta">
            <div className="step-title">4. Local Rehydration</div>
            <div className="step-desc">Safe PII restored · secrets locked</div>
          </div>
        </div>
      </section>

      {/* Banners */}
      {warmMessage && (
        <div className="notice-banner" role="status">
          <span>
            <strong>On-Device Model Status:</strong> {warmMessage}
          </span>
          <button type="button" className="btn btn-sm" onClick={() => setWarmMessage(null)}>
            Dismiss
          </button>
        </div>
      )}

      {!hasFirebase && (
        <div className="notice-banner" role="note">
          <span>
            <strong>Sandbox Preview Active:</strong> Local Zero-Leak Vault redaction &amp; domain preview
            analysis work immediately offline. Add a free{" "}
            <strong>Firebase Spark Web Config</strong> to invoke live Chrome Gemini Nano &amp; Cloud{" "}
            <code>{firebaseConfig.cloudModel || DEFAULT_CLOUD_MODEL}</code> via <code>firebase/ai</code>.
          </span>
          <button type="button" className="btn btn-sm" onClick={openConfigModal}>
            Connect Firebase Config
          </button>
        </div>
      )}

      {errorMsg && (
        <div className="notice-banner error" role="alert">
          <span>
            <strong>Pipeline Notice:</strong> {errorMsg}
          </span>
          <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
            <button type="button" className="btn btn-sm" onClick={handleRunSandboxFallback} disabled={isAnalyzing}>
              Run Sandbox Preview
            </button>
            <button type="button" className="btn btn-sm" onClick={() => setErrorMsg(null)}>
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Main 3-Column Bento Grid */}
      <main className="workspace-grid">
        {/* LEFT COLUMN: Input & Workloads */}
        <section className="panel">
          <div className="panel-header">
            <h2 className="panel-title">
              <FileText size={16} />
              Raw Sensitive Document
            </h2>
            <div style={{ display: "flex", gap: "6px" }}>
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt,.md,.json,.csv,.log"
                hidden
                onChange={handleFileUpload}
              />
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => fileInputRef.current?.click()}
              >
                <Upload size={13} />
                Upload File
              </button>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => {
                  setSelectedSampleId("custom");
                  setRawText("");
                  setQaHistory([]);
                }}
              >
                Clear
              </button>
            </div>
          </div>

          <div className="panel-body">
            <div className="sample-pills" role="tablist" aria-label="Sample Sensitive Workloads">
              {SAMPLE_WORKLOADS.map((sample) => (
                <button
                  key={sample.id}
                  type="button"
                  role="tab"
                  aria-selected={selectedSampleId === sample.id}
                  className={`sample-chip ${selectedSampleId === sample.id ? "active" : ""}`}
                  onClick={() => handleSelectSample(sample.id)}
                  title={sample.description}
                >
                  {sample.label}
                </button>
              ))}
            </div>

            <textarea
              aria-label="Sensitive Document Input"
              className="doc-textarea"
              placeholder="Paste crash logs with .env keys, vendor NDAs, clinical intake notes, or chargeback logs..."
              value={rawText}
              onChange={(e) => {
                setSelectedSampleId("custom");
                setRawText(e.target.value);
              }}
            />

            <div className="field-group">
              <label htmlFor="focus-question" className="field-label">
                Optional Specific Question (also sanitized locally before Stage 2)
              </label>
              <input
                id="focus-question"
                type="text"
                className="text-input"
                placeholder="e.g. Which credentials must rotate first and who is on-call?"
                value={customQuestion}
                onChange={(e) => setCustomQuestion(e.target.value)}
              />
            </div>

            <div className="input-footer">
              <span>
                {rawText.length.toLocaleString()} chars · Live scan found{" "}
                <strong style={{ color: "var(--emerald)" }}>
                  {liveLocalRedaction.entries.length} sensitive tokens
                </strong>
              </span>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleAnalyze}
                disabled={isAnalyzing || !rawText.trim()}
              >
                {isAnalyzing ? <RefreshCw size={15} className="spin" /> : <ShieldCheck size={15} />}
                {isAnalyzing ? "Sanitizing & Analyzing..." : "Analyze with Hybrid AI"}
              </button>
            </div>
          </div>
        </section>

        {/* CENTER COLUMN: Zero-Leak Verification & Vault */}
        <section className="panel">
          <div className="panel-header">
            <h2 className="panel-title">
              <ShieldCheck size={16} color="var(--emerald)" />
              Zero-Leak Outbound Guard
            </h2>
            <div className="tabs" role="tablist">
              <button
                type="button"
                className={`tab-btn ${centerTab === "payload" ? "active" : ""}`}
                onClick={() => setCenterTab("payload")}
              >
                Cloud Payload
              </button>
              <button
                type="button"
                className={`tab-btn ${centerTab === "vault" ? "active" : ""}`}
                onClick={() => setCenterTab("vault")}
              >
                Vault ({activeRedaction.entries.length})
              </button>
              <button
                type="button"
                className={`tab-btn ${centerTab === "diff" ? "active" : ""}`}
                onClick={() => setCenterTab("diff")}
              >
                Diff View
              </button>
            </div>
          </div>

          <div className="panel-body">
            <div
              className={`barrier-status ${activeRedaction.leakCheckPassed ? "pill-emerald" : "pill-rose"}`}
            >
              <span style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}>
                {activeRedaction.leakCheckPassed ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />}
                {activeRedaction.leakCheckPassed
                  ? "Zero-Leak PASSED · 0 raw secrets leave browser"
                  : "Barrier Alert · Unmasked secret detected"}
              </span>
              <span>{activeRedaction.entries.length} protected</span>
            </div>

            {centerTab === "payload" && (
              <div>
                <div className="diff-col-label">
                  Exact Sanitized Payload Sent to Stage 2 AI
                </div>
                <div className="payload-box" data-testid="sanitized-payload">
                  {renderHighlightedPayload(
                    analysis?.cloudPayloadSent ?? liveLocalRedaction.sanitizedText,
                  )}
                </div>
              </div>
            )}

            {centerTab === "vault" && (
              <div className="vault-list">
                {activeRedaction.entries.length === 0 ? (
                  <div style={{ color: "var(--text-muted)", fontSize: "12.5px" }}>
                    No PII or credential patterns detected yet in current input.
                  </div>
                ) : (
                  activeRedaction.entries.map((entry, idx) => (
                    <div key={`${entry.placeholder}-${idx}`} className="vault-row">
                      <span className={entry.sensitiveSecret ? "token-pill secret" : "token-pill"}>
                        {entry.placeholder}
                      </span>
                      <span
                        className="vault-orig"
                        title={entry.sensitiveSecret && !revealHardSecrets ? "Hard secret locked" : entry.original}
                      >
                        {maskPreviewOriginal(entry.original, entry.sensitiveSecret, revealHardSecrets)}
                      </span>
                      <span className="pill" style={{ padding: "2px 7px", fontSize: "10.5px" }}>
                        {entry.sensitiveSecret ? "Hard Lock" : entry.source === "on_device_ai" ? "Nano" : "PII"}
                      </span>
                    </div>
                  ))
                )}
              </div>
            )}

            {centerTab === "diff" && (
              <div className="diff-grid">
                <div>
                  <div className="diff-col-label">Local Raw Memory</div>
                  <div className="payload-box" style={{ maxHeight: "320px" }}>
                    {rawText || "(empty)"}
                  </div>
                </div>
                <div>
                  <div className="diff-col-label">Sanitized Cloud Egress</div>
                  <div className="payload-box" style={{ maxHeight: "320px" }}>
                    {renderHighlightedPayload(
                      analysis?.cloudPayloadSent ?? liveLocalRedaction.sanitizedText,
                    )}
                  </div>
                </div>
              </div>
            )}

            {Object.keys(activeRedaction.countsByCategory).length > 0 && (
              <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                {Object.entries(activeRedaction.countsByCategory).map(([cat, count]) => (
                  <span key={cat} className="pill" style={{ fontSize: "11px", padding: "3px 8px" }}>
                    {cat}: {count}
                  </span>
                ))}
              </div>
            )}
          </div>
        </section>

        {/* RIGHT COLUMN: Hybrid Brief, Telemetry, Q&A & Exports */}
        <section className="panel">
          <div className="panel-header">
            <h2 className="panel-title">
              <Activity size={16} color="var(--accent)" />
              Intelligence Brief
            </h2>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => setShowRehydrated((prev) => !prev)}
                title="Switch between locally rehydrated view and strictly masked cloud response"
              >
                {showRehydrated ? <Eye size={13} /> : <EyeOff size={13} />}
                {showRehydrated ? "Rehydrated Local" : "Masked View"}
              </button>
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => setRevealHardSecrets((prev) => !prev)}
                title="By default hard API/DB secrets remain locked even after local rehydration"
              >
                <Lock size={13} />
                {revealHardSecrets ? "Hide Hard Keys" : "Hard Keys Locked"}
              </button>
              <button
                type="button"
                className="btn btn-sm"
                onClick={handleExportMarkdown}
                disabled={!analysis}
                title="Export Executive Brief Markdown"
              >
                <Download size={13} />
                .MD
              </button>
              <button
                type="button"
                className="btn btn-sm"
                onClick={handleExportAuditJson}
                disabled={!analysis}
                title="Export Zero-Leak Telemetry & Sanitized Audit JSON"
              >
                <Download size={13} />
                .JSON
              </button>
            </div>
          </div>

          <div className="panel-body">
            {analysis && displayedBrief ? (
              <>
                {/* Telemetry KPIs */}
                <div className="telemetry-grid">
                  <div className="metric-card">
                    <div className="metric-label">Stage 1 Guard</div>
                    <div className="metric-val">{sourceBadgeLabel(analysis.telemetry.stage1Source)}</div>
                  </div>
                  <div className="metric-card">
                    <div className="metric-label">Stage 2 Engine</div>
                    <div className="metric-val" style={{ color: "var(--accent)" }}>
                      {sourceBadgeLabel(analysis.telemetry.stage2Source)}
                    </div>
                  </div>
                  <div className="metric-card">
                    <div className="metric-label">Total Latency</div>
                    <div className="metric-val">{analysis.telemetry.totalLatencyMs} ms</div>
                  </div>
                  <div className="metric-card">
                    <div className="metric-label">Protected</div>
                    <div className="metric-val" style={{ color: "var(--emerald)" }}>
                      {analysis.telemetry.secretsProtectedCount} items
                    </div>
                  </div>
                </div>

                {analysis.telemetry.deviceModelNote && (
                  <div className="pill" style={{ borderRadius: "9px", padding: "6px 10px", fontSize: "11.5px", whiteSpace: "normal", width: "100%" }}>
                    <strong>Routing Note:</strong> {analysis.telemetry.deviceModelNote}
                  </div>
                )}

                {/* Executive Brief */}
                <div className="brief-box">
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: "8px",
                      flexWrap: "wrap",
                    }}
                  >
                    <strong style={{ fontSize: "14px" }}>{displayedBrief.documentType}</strong>
                    <span className={`risk-badge sev-${displayedBrief.riskLevel}`}>
                      RISK: {displayedBrief.riskLevel}
                    </span>
                  </div>

                  <p style={{ margin: 0, color: "var(--text-secondary)", fontSize: "13px" }}>
                    {displayedBrief.executiveSummary}
                  </p>

                  {displayedBrief.directAnswer && (
                    <div
                      className="risk-card"
                      style={{ borderColor: "rgba(56, 189, 248, 0.45)", background: "var(--bg-muted)" }}
                    >
                      <div className="risk-card-head">Direct Answer to Your Question</div>
                      <div style={{ fontSize: "12.5px", color: "var(--text-secondary)" }}>
                        {displayedBrief.directAnswer}
                      </div>
                    </div>
                  )}

                  <div style={{ display: "flex", flexDirection: "column", gap: "7px" }}>
                    <div className="diff-col-label" style={{ marginBottom: 0 }}>
                      Risk Findings
                    </div>
                    {displayedBrief.riskFindings.map((finding, idx) => (
                      <div key={idx} className="risk-card">
                        <div className="risk-card-head">
                          <span className={`risk-badge sev-${finding.severity}`}>{finding.severity}</span>
                          <span>{finding.title}</span>
                        </div>
                        <div style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                          {finding.detail}
                        </div>
                      </div>
                    ))}
                  </div>

                  <div>
                    <div className="diff-col-label">Action Items</div>
                    <ol className="action-list">
                      {displayedBrief.actionItems.map((item, idx) => (
                        <li key={idx}>{item}</li>
                      ))}
                    </ol>
                  </div>

                  <div style={{ fontSize: "11.5px", color: "var(--text-muted)", borderTop: "1px solid var(--border)", paddingTop: "8px" }}>
                    <strong>Compliance Note:</strong> {displayedBrief.complianceNotes}
                  </div>
                </div>

                {/* Encrypted-Context Follow-up Q&A */}
                <div className="qa-box">
                  <div className="diff-col-label" style={{ marginBottom: 0 }}>
                    Zero-Leak Follow-Up Q&amp;A
                  </div>
                  <form className="qa-form" onSubmit={handleFollowUp}>
                    <input
                      type="text"
                      className="text-input"
                      placeholder="Ask about next actions (any PII in your question is masked locally)..."
                      value={followUpInput}
                      onChange={(e) => setFollowUpInput(e.target.value)}
                    />
                    <button
                      type="submit"
                      className="btn btn-primary"
                      disabled={isAskingFollowUp || !followUpInput.trim()}
                    >
                      <Send size={14} />
                      {isAskingFollowUp ? "Asking..." : "Ask"}
                    </button>
                  </form>

                  {qaHistory.map((item) => (
                    <div key={item.id} className="qa-item">
                      <div style={{ display: "flex", justifyContent: "space-between", gap: "8px", flexWrap: "wrap" }}>
                        <strong>Q: {item.rawQuestion}</strong>
                        <span className="pill" style={{ padding: "1px 7px", fontSize: "10.5px" }}>
                          {sourceBadgeLabel(item.inferenceSource)} · {item.latencyMs}ms
                        </span>
                      </div>
                      <div style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                        Sent: {item.sanitizedQuestionSent}
                      </div>
                      <div style={{ color: "var(--text-secondary)" }}>{renderQaAnswer(item)}</div>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div style={{ color: "var(--text-muted)", fontSize: "13px" }}>
                Click <strong>Analyze with Hybrid AI</strong> to inspect local sanitization and hybrid inference results.
              </div>
            )}
          </div>
        </section>
      </main>

      {/* Firebase Configuration Modal */}
      {isConfigOpen && (
        <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Firebase AI Logic Settings">
          <div className="modal-card">
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <h2 className="panel-title" style={{ fontSize: "15px" }}>
                <Settings size={17} />
                Connect Firebase AI Logic (Spark Free Tier)
              </h2>
              <button type="button" className="btn btn-sm" onClick={() => setIsConfigOpen(false)} aria-label="Close Settings">
                <X size={15} />
              </button>
            </div>

            <p style={{ margin: 0, fontSize: "12.5px", color: "var(--text-secondary)" }}>
              Create a free Firebase Spark project → <strong>Build → AI Logic → Get started</strong> (enable{" "}
              <em>Gemini Developer API</em>) → copy your Web App config below. Stored locally in your
              browser only (<code>localStorage</code>).
            </p>

            <div className="field-group">
              <label htmlFor="firebase-snippet" className="field-label">
                Quick Paste (paste entire <code>firebaseConfig = &#123;...&#125;</code> object)
              </label>
              <textarea
                id="firebase-snippet"
                rows={4}
                className="doc-textarea"
                style={{ minHeight: "88px" }}
                placeholder='apiKey: "your-firebase-key", authDomain: "...", projectId: "...", appId: "..."'
                value={snippetPaste}
                onChange={(e) => setSnippetPaste(e.target.value)}
              />
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "8px" }}>
                <span style={{ fontSize: "11.5px", color: "var(--accent)" }}>{snippetMsg ?? ""}</span>
                <button type="button" className="btn btn-sm" onClick={handleApplySnippet}>
                  Parse Snippet
                </button>
              </div>
            </div>

            <div className="field-group">
              <label htmlFor="cfg-apikey" className="field-label">apiKey *</label>
              <input
                id="cfg-apikey"
                type="text"
                className="text-input"
                value={draftConfig.apiKey}
                onChange={(e) => setDraftConfig({ ...draftConfig, apiKey: e.target.value })}
              />
            </div>

            <div className="field-group">
              <label htmlFor="cfg-project" className="field-label">projectId *</label>
              <input
                id="cfg-project"
                type="text"
                className="text-input"
                value={draftConfig.projectId}
                onChange={(e) => setDraftConfig({ ...draftConfig, projectId: e.target.value })}
              />
            </div>

            <div className="field-group">
              <label htmlFor="cfg-appid" className="field-label">appId *</label>
              <input
                id="cfg-appid"
                type="text"
                className="text-input"
                value={draftConfig.appId}
                onChange={(e) => setDraftConfig({ ...draftConfig, appId: e.target.value })}
              />
            </div>

            <div className="diff-grid">
              <div className="field-group">
                <label htmlFor="cfg-auth" className="field-label">authDomain</label>
                <input
                  id="cfg-auth"
                  type="text"
                  className="text-input"
                  value={draftConfig.authDomain}
                  onChange={(e) => setDraftConfig({ ...draftConfig, authDomain: e.target.value })}
                />
              </div>

              <div className="field-group">
                <label htmlFor="cfg-model" className="field-label">Cloud Fallback Model</label>
                <select
                  id="cfg-model"
                  className="select-control"
                  value={draftConfig.cloudModel || DEFAULT_CLOUD_MODEL}
                  onChange={(e) => setDraftConfig({ ...draftConfig, cloudModel: e.target.value })}
                >
                  {CLOUD_MODEL_OPTIONS.map((opt) => (
                    <option key={opt.id} value={opt.id}>
                      {opt.id} ({opt.tier})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="diff-grid">
              <div className="field-group">
                <label htmlFor="cfg-appcheck-key" className="field-label">App Check Web Site Key (optional)</label>
                <input
                  id="cfg-appcheck-key"
                  type="text"
                  className="text-input"
                  placeholder="6L... (if App Check enforced)"
                  value={draftConfig.appCheckSiteKey ?? ""}
                  onChange={(e) => setDraftConfig({ ...draftConfig, appCheckSiteKey: e.target.value })}
                />
              </div>

              <div className="field-group">
                <label htmlFor="cfg-appcheck-debug" className="field-label">App Check Debug Token (optional)</label>
                <input
                  id="cfg-appcheck-debug"
                  type="text"
                  className="text-input"
                  placeholder="UUID or true"
                  value={draftConfig.appCheckDebugToken ?? ""}
                  onChange={(e) => setDraftConfig({ ...draftConfig, appCheckDebugToken: e.target.value })}
                />
              </div>
            </div>

            <div style={{ display: "flex", justifyContent: "space-between", gap: "8px", marginTop: "4px" }}>
              <button type="button" className="btn" onClick={handleResetConfig}>
                Reset to Sandbox Mode
              </button>
              <div style={{ display: "flex", gap: "8px" }}>
                <button type="button" className="btn" onClick={() => setIsConfigOpen(false)}>
                  Cancel
                </button>
                <button type="button" className="btn btn-primary" onClick={handleSaveConfig}>
                  Save Firebase Config
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
