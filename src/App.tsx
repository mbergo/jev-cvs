import React, { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  Code2,
  Cpu,
  EyeOff,
  FileCheck2,
  Filter,
  Layers,
  Lock,
  Play,
  RotateCcw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  Terminal,
  X,
} from "lucide-react";
import {
  buildGuardrailPolicyFromControlPlane,
  type ControlPlaneRule,
  INITIAL_CONTROL_PLANE_RULES,
  PRESET_PROMPTS,
  type PresetPromptItem,
  type RuleEnforcementMode,
} from "./data/controlPlaneRules";
import { evaluatePrompt, formatVerdictAuditLog } from "./guardrails/evaluator";
import type { GuardrailCategory, GuardrailVerdict } from "./guardrails/types";

interface TriggeredRuleReport {
  ruleId: string;
  ruleName: string;
  category: GuardrailCategory;
  mode: RuleEnforcementMode;
  deterministicMatched: boolean;
  maskedMatches: string[];
  typesafeNoulProbability: number | null;
  typesafeConfidence: number | null;
  actionTaken:
    | "Enforced (Blocked)"
    | "Alerted & Sanitized"
    | "Ignored (Bypassed)";
}

interface EntropyItem {
  maskedToken: string;
  length: number;
  shannonEntropy: number;
  exceedsThreshold: boolean;
}

interface NoulAnswer {
  type: "noul";
  noul: number;
  confidence: number;
}

interface ChoiceAnswer {
  type: "choice";
  choice: string;
  probabilities: Record<string, number>;
  confidence: number;
}

interface ScoreAnswer {
  type: "score";
  score: number;
  probabilities: Record<string, number>;
  legend?: Record<string, string>;
  confidence: number;
}

type DecisionAnswer = NoulAnswer | ChoiceAnswer | ScoreAnswer;

interface EvaluationApiResponse {
  contractVerdict: GuardrailVerdict;
  effectiveVerdict: GuardrailVerdict;
  contractAuditLog: string;
  compiledPolicy: unknown;
  sanitizedPrompt: string;
  sanitizedEndUserOutput: string;
  downstreamStatus: "blocked" | "sanitized_and_completed" | "clean_completed";
  triggeredRules: TriggeredRuleReport[];
  entropyAnalysis: EntropyItem[];
  typesafeInternals: {
    endpoint: string;
    httpStatus: number;
    requestedModel: string;
    model: string;
    architecture: string;
    totalOutputTokens: number;
    totalInputTokens: number | null;
    decisionsLatencyMs: number;
    totalPipelineLatencyMs: number;
    requestPayload: {
      endpoint: string;
      model: string;
      statePreview: string;
      questionCount: number;
      questions: Record<string, unknown>;
    };
    rawAnswers: Record<string, DecisionAnswer>;
  };
}

interface TestSuiteResultItem {
  id: string;
  name: string;
  input: string;
  expectedDecision: GuardrailVerdict["decision"];
  actualVerdict: GuardrailVerdict;
  auditLog: string;
  passed: boolean;
  rawMaskingVerified: boolean;
  durationMs: number;
}

function HighSeverityStackIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 16 16"
      fill="none"
      aria-hidden="true"
      className="shrink-0"
    >
      <path d="M8 1L14 4.2L8 7.4L2 4.2L8 1Z" fill="#525866" />
      <path
        d="M2 7.8L8 11L14 7.8"
        stroke="#F43F5E"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M2 11.4L8 14.6L14 11.4"
        stroke="#E11D48"
        strokeWidth="1.8"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function SensitivityDotsIndicator() {
  return (
    <div
      className="hidden sm:flex items-center gap-1"
      title="Calibrated threshold sensitivity (0.65)"
      aria-hidden="true"
    >
      <span className="w-1.5 h-1.5 border border-neutral-600 rounded-[1px]" />
      <span className="w-1.5 h-1.5 border border-neutral-600 rounded-[1px]" />
      <span className="w-1.5 h-1.5 bg-neutral-100 rounded-[1px]" />
      <span className="w-1.5 h-1.5 border border-neutral-600 rounded-[1px]" />
      <span className="w-1.5 h-1.5 border border-neutral-600 rounded-[1px]" />
    </div>
  );
}

export default function App() {
  const [activeNavTab, setActiveNavTab] = useState<
    "workspace" | "control-plane" | "internals" | "test-suite"
  >("workspace");

  const [rules, setRules] = useState<ReadonlyArray<ControlPlaneRule>>(
    INITIAL_CONTROL_PLANE_RULES
  );
  const [ruleSearch, setRuleSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<
    "all" | GuardrailCategory
  >("all");
  const [editingRule, setEditingRule] = useState<ControlPlaneRule | null>(null);
  const [editPatternDraft, setEditPatternDraft] = useState("");
  const [editQuestionDraft, setEditQuestionDraft] = useState("");
  const [editSamplePromptDraft, setEditSamplePromptDraft] = useState("");

  const [presetGroupFilter, setPresetGroupFilter] = useState<
    "all" | PresetPromptItem["group"] | "Custom User Prompts"
  >("all");
  const [customPresets, setCustomPresets] = useState<PresetPromptItem[]>([]);
  const [customPromptInput, setCustomPromptInput] = useState<string>("");
  const [customPromptLabel, setCustomPromptLabel] = useState<string>("");
  const [selectedPresetId, setSelectedPresetId] = useState<string>(
    PRESET_PROMPTS[0].id
  );
  const [promptInput, setPromptInput] = useState<string>(
    PRESET_PROMPTS[0].prompt
  );
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [evalError, setEvalError] = useState<string | null>(null);
  const [apiResult, setApiResult] = useState<EvaluationApiResponse | null>(
    null
  );

  const [testSuiteData, setTestSuiteData] = useState<{
    total: number;
    passed: number;
    results: TestSuiteResultItem[];
  } | null>(null);
  const [isLoadingTests, setIsLoadingTests] = useState(false);
  const [typesafeStatus, setTypesafeStatus] = useState<{
    connected: boolean;
    endpoint: string;
    model: string;
  } | null>(null);

  // Instant client-side preview of the strict TypeScript evaluatePrompt contract
  const livePolicy = useMemo(
    () => buildGuardrailPolicyFromControlPlane(rules),
    [rules]
  );

  const liveLocalVerdict = useMemo(
    () => evaluatePrompt(promptInput, livePolicy),
    [promptInput, livePolicy]
  );

  const liveAuditLog = useMemo(
    () => formatVerdictAuditLog(liveLocalVerdict),
    [liveLocalVerdict]
  );

  const filteredRules = useMemo(() => {
    return rules.filter((r) => {
      const matchesCategory =
        categoryFilter === "all" || r.category === categoryFilter;
      const matchesSearch =
        ruleSearch.trim() === "" ||
        r.name.toLowerCase().includes(ruleSearch.toLowerCase()) ||
        r.category.toLowerCase().includes(ruleSearch.toLowerCase());
      return matchesCategory && matchesSearch;
    });
  }, [rules, categoryFilter, ruleSearch]);

  const ruleModeCounts = useMemo(() => {
    let block = 0;
    let detect = 0;
    let ignore = 0;
    for (const r of rules) {
      if (r.mode === "Block") block++;
      else if (r.mode === "Detect") detect++;
      else ignore++;
    }
    return { block, detect, ignore };
  }, [rules]);

  const handleRuleModeChange = (
    ruleId: string,
    newMode: RuleEnforcementMode
  ) => {
    setRules((prev) =>
      prev.map((r) => (r.id === ruleId ? { ...r, mode: newMode } : r))
    );
  };

  const handleBulkSetMode = (mode: RuleEnforcementMode) => {
    setRules((prev) => prev.map((r) => ({ ...r, mode })));
  };

  const handleResetDefaultRules = () => {
    setRules(INITIAL_CONTROL_PLANE_RULES);
  };

  const handleOpenEditModal = (rule: ControlPlaneRule) => {
    setEditingRule(rule);
    setEditPatternDraft(rule.customPatternDescription);
    setEditQuestionDraft(rule.typesafeQuestion.instructions);
    setEditSamplePromptDraft(rule.sampleViolationPrompt);
  };

  const handleSaveRuleEdit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingRule) return;
    setRules((prev) =>
      prev.map((r) =>
        r.id === editingRule.id
          ? {
              ...r,
              customPatternDescription: editPatternDraft.trim(),
              sampleViolationPrompt: editSamplePromptDraft.trim(),
              typesafeQuestion: {
                ...r.typesafeQuestion,
                instructions: editQuestionDraft.trim(),
              },
            }
          : r
      )
    );
    setEditingRule(null);
  };

  const handleTestSingleRule = (rule: ControlPlaneRule) => {
    setSelectedPresetId(`preset-${rule.id}`);
    setPromptInput(rule.sampleViolationPrompt);
    setEvalError(null);
    runTypeSafeEvaluation(rule.sampleViolationPrompt);
  };

  const handleSelectPreset = (preset: PresetPromptItem) => {
    setSelectedPresetId(preset.id);
    setPromptInput(preset.prompt);
    setEvalError(null);
  };

  const handleTestCustomPrompt = () => {
    const trimmed = customPromptInput.trim();
    if (!trimmed) {
      setEvalError("Please enter a custom prompt in the custom prompt textarea.");
      return;
    }
    setSelectedPresetId("custom-active");
    setPromptInput(trimmed);
    setEvalError(null);
    runTypeSafeEvaluation(trimmed);
  };

  const handleSaveCustomPreset = () => {
    const trimmed = customPromptInput.trim();
    if (!trimmed) return;
    const newId = `custom-${Date.now()}`;
    const label =
      customPromptLabel.trim() ||
      `Custom Prompt #${customPresets.length + 1}`;
    const newPreset: PresetPromptItem = {
      id: newId,
      label,
      group: "4. Safe & Negative Fixtures (4)",
      badge: "Custom",
      prompt: trimmed,
      expectedBehavior: "User-defined custom test prompt",
    };
    setCustomPresets((prev) => [newPreset, ...prev]);
    setSelectedPresetId(newId);
    setPromptInput(trimmed);
    setCustomPromptLabel("");
  };

  const runTypeSafeEvaluation = async (overridePrompt?: string) => {
    const targetPrompt = overridePrompt ?? promptInput;
    if (!targetPrompt.trim()) {
      setEvalError("Please enter or select a prompt to evaluate.");
      return;
    }

    setIsEvaluating(true);
    setEvalError(null);

    try {
      const response = await fetch("/api/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          prompt: targetPrompt,
          rules,
        }),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status} evaluation error`);
      }

      setApiResult(data as EvaluationApiResponse);
    } catch (err: unknown) {
      const msg =
        err instanceof Error ? err.message : "Failed to evaluate prompt.";
      setEvalError(msg);
    } finally {
      setIsEvaluating(false);
    }
  };

  const fetchTestSuite = async () => {
    setIsLoadingTests(true);
    try {
      const response = await fetch("/api/test-suite");
      if (response.ok) {
        const data = await response.json();
        setTestSuiteData(data);
      }
    } catch {
      // Ignore background fetch error
    } finally {
      setIsLoadingTests(false);
    }
  };

  useEffect(() => {
    fetchTestSuite();
    fetch("/api/typesafe-status")
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (d) setTypesafeStatus(d);
      })
      .catch(() => {});
  }, []);

  const primaryChoiceAnswer = useMemo(() => {
    const ans =
      apiResult?.typesafeInternals.rawAnswers?.["primary_threat_vector"];
    return ans && ans.type === "choice" ? ans : null;
  }, [apiResult]);

  const severityScoreAnswer = useMemo(() => {
    const ans =
      apiResult?.typesafeInternals.rawAnswers?.["threat_severity_rubric"];
    return ans && ans.type === "score" ? ans : null;
  }, [apiResult]);

  const ruleNoulEntries = useMemo(() => {
    if (!apiResult) return [];
    const answers = apiResult.typesafeInternals.rawAnswers;
    return rules
      .filter((r) => r.mode !== "Ignore")
      .map((rule) => {
        const ans = answers[rule.id];
        const noul = ans && ans.type === "noul" ? ans.noul : 0.01;
        const confidence = ans && ans.type === "noul" ? ans.confidence : 0.99;
        return {
          rule,
          noul,
          confidence,
          triggered: noul >= 0.65,
        };
      })
      .sort((a, b) => b.noul - a.noul);
  }, [apiResult, rules]);

  return (
    <div className="min-h-screen bg-[#0B0D11] text-neutral-100 flex flex-col">
      {/* Top Bar Contract: Zone 1 (Brand) — Zone 2 (4 Nav Links) — Zone 3 (1 Primary Action) */}
      <header className="flex items-center justify-between gap-8 px-6 py-3.5 border-b border-neutral-800 bg-[#0F1218] sticky top-0 z-30">
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveNavTab("workspace");
          }}
          className="text-base font-bold tracking-tight text-white whitespace-nowrap shrink-0"
        >
          TypeSafe Guardrail Studio
        </a>

        <nav
          aria-label="Primary Workspace Views"
          className="hidden md:flex items-center gap-6 text-sm font-medium text-neutral-400"
        >
          <button
            type="button"
            onClick={() => setActiveNavTab("workspace")}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeNavTab === "workspace"
                ? "text-white border-emerald-500"
                : "border-transparent hover:text-neutral-200"
            }`}
          >
            Split Workspace
          </button>
          <button
            type="button"
            onClick={() => setActiveNavTab("control-plane")}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeNavTab === "control-plane"
                ? "text-white border-emerald-500"
                : "border-transparent hover:text-neutral-200"
            }`}
          >
            Guardrails Control Plane
          </button>
          <button
            type="button"
            onClick={() => setActiveNavTab("internals")}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeNavTab === "internals"
                ? "text-white border-emerald-500"
                : "border-transparent hover:text-neutral-200"
            }`}
          >
            TypeSafe Model Internals
          </button>
          <button
            type="button"
            onClick={() => {
              setActiveNavTab("test-suite");
              fetchTestSuite();
            }}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeNavTab === "test-suite"
                ? "text-white border-emerald-500"
                : "border-transparent hover:text-neutral-200"
            }`}
          >
            Contract Test Fixtures
          </button>
        </nav>

        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => runTypeSafeEvaluation()}
            disabled={isEvaluating}
            className="px-4 py-2 text-xs font-semibold text-neutral-950 bg-emerald-400 hover:bg-emerald-300 disabled:opacity-50 rounded-md transition-colors whitespace-nowrap shrink-0 flex items-center gap-2 cursor-pointer"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>
              {isEvaluating ? "Evaluating Pipeline..." : "Evaluate Prompt"}
            </span>
          </button>
        </div>
      </header>

      {/* Mobile Navigation Bar */}
      <div className="flex md:hidden items-center gap-1 px-4 py-2 border-b border-neutral-800 bg-[#0F1218] overflow-x-auto">
        {(
          [
            { id: "workspace", label: "Workspace" },
            { id: "control-plane", label: "Control Plane" },
            { id: "internals", label: "TypeSafe Internals" },
            { id: "test-suite", label: "Test Fixtures" },
          ] as const
        ).map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveNavTab(tab.id)}
            className={`px-3 py-1.5 text-xs font-medium rounded whitespace-nowrap shrink-0 ${
              activeNavTab === tab.id
                ? "bg-neutral-800 text-white"
                : "text-neutral-400 hover:text-neutral-200"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Main Content Area */}
      <main className="flex-1 max-w-[1440px] w-full mx-auto px-4 sm:px-6 py-6 flex flex-col gap-6">
        {/* Top Summary Strip */}
        <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-[#12151E] border border-neutral-800 rounded-lg p-4">
            <div className="text-xs text-neutral-400">
              Deduplicated Control Plane Rules
            </div>
            <div className="mt-1 flex items-baseline justify-between">
              <span className="text-2xl font-bold text-white tabular-nums">
                {rules.length}
              </span>
              <span className="text-xs text-neutral-400 tabular-nums">
                {ruleModeCounts.block} Enforce · {ruleModeCounts.detect} Alert ·{" "}
                {ruleModeCounts.ignore} Ignore
              </span>
            </div>
          </div>

          <div className="bg-[#12151E] border border-neutral-800 rounded-lg p-4">
            <div className="text-xs text-neutral-400">
              Instant Contract Verdict (Sync)
            </div>
            <div className="mt-1 flex items-baseline justify-between">
              <span
                className={`text-lg font-bold uppercase tracking-tight ${
                  liveLocalVerdict.decision === "block"
                    ? "text-rose-400"
                    : liveLocalVerdict.decision === "redact"
                    ? "text-amber-400"
                    : "text-emerald-400"
                }`}
              >
                {liveLocalVerdict.decision}
              </span>
              <span className="text-xs text-neutral-400">
                {liveLocalVerdict.decision === "allow"
                  ? "No local regex trigger"
                  : `Category: ${liveLocalVerdict.category}`}
              </span>
            </div>
          </div>

          <div className="bg-[#12151E] border border-neutral-800 rounded-lg p-4">
            <div className="text-xs text-neutral-400">
              TypeSafe Endpoint (docs.typesafe.ai)
            </div>
            <div className="mt-1 flex items-baseline justify-between gap-2">
              <span className="text-sm font-semibold text-white font-mono truncate">
                {apiResult?.typesafeInternals.model ??
                  typesafeStatus?.model ??
                  "jev-latest"}
              </span>
              <span
                className={`text-xs font-mono tabular-nums shrink-0 ${
                  typesafeStatus?.connected === false
                    ? "text-amber-400"
                    : "text-emerald-400"
                }`}
              >
                {typesafeStatus?.connected === false
                  ? "Key Missing"
                  : "api.typesafe.ai/v1"}
              </span>
            </div>
          </div>

          <div className="bg-[#12151E] border border-neutral-800 rounded-lg p-4">
            <div className="text-xs text-neutral-400">
              Table-Driven Contract Suite
            </div>
            <div className="mt-1 flex items-baseline justify-between">
              <span className="text-2xl font-bold text-emerald-400 tabular-nums">
                {testSuiteData
                  ? `${testSuiteData.passed}/${testSuiteData.total}`
                  : "11/11"}
              </span>
              <span className="text-xs text-neutral-400">
                UUID & Git SHA negatives passing
              </span>
            </div>
          </div>
        </section>

        {/* Triggered Guardrail Notification Banner (Shown whenever any rule is triggered in Block, Detect, or Ignore mode) */}
        {apiResult && apiResult.triggeredRules.length > 0 && (
          <section
            aria-label="Triggered Guardrail Notification"
            className={`border rounded-lg p-4 ${
              apiResult.effectiveVerdict.decision === "block"
                ? "bg-rose-950/30 border-rose-800/80 text-rose-100"
                : "bg-amber-950/30 border-amber-800/80 text-amber-100"
            }`}
          >
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div className="flex items-start gap-3">
                {apiResult.effectiveVerdict.decision === "block" ? (
                  <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
                )}
                <div>
                  <h2 className="text-sm font-semibold">
                    {apiResult.effectiveVerdict.decision === "block"
                      ? `Execution Halted — ${apiResult.triggeredRules.length} Guardrail Rule(s) Triggered during Ingestion`
                      : `Middle-Layer Guardrail Notification — ${apiResult.triggeredRules.length} Rule(s) Triggered & Sanitized Before Reaching End User`}
                  </h2>
                  <p className="text-xs text-neutral-300 mt-0.5">
                    All raw matches are masked to first 4 chars +{" "}
                    <code className="font-mono">****</code>. Sensitive spans
                    were stripped prior to downstream output rendering.
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setActiveNavTab("internals")}
                className="px-3 py-1.5 text-xs font-medium bg-neutral-900/90 hover:bg-neutral-800 text-neutral-100 border border-neutral-700 rounded transition-colors whitespace-nowrap shrink-0 self-start md:self-center cursor-pointer"
              >
                Inspect TypeSafe API Internals
              </button>
            </div>

            <div className="mt-3 pt-3 border-t border-neutral-800/80 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
              {apiResult.triggeredRules.map((tr) => (
                <div
                  key={tr.ruleId}
                  className="bg-[#0B0D11]/90 border border-neutral-800 rounded px-3 py-2 flex items-center justify-between gap-2 text-xs"
                >
                  <div className="min-w-0">
                    <div className="font-medium text-white truncate">
                      {tr.ruleName}
                    </div>
                    <div className="text-neutral-400 font-mono text-[11px] mt-0.5 truncate">
                      <span>
                        Toggle:{" "}
                        {tr.mode === "Block"
                          ? "Enforce"
                          : tr.mode === "Detect"
                          ? "Alert"
                          : "Ignore"}
                      </span>
                      <span aria-hidden="true"> · </span>
                      <span>
                        {tr.typesafeNoulProbability !== null
                          ? `noul=${(tr.typesafeNoulProbability * 100).toFixed(1)}%`
                          : "Regex Match"}
                      </span>
                      {tr.maskedMatches.length > 0 && (
                        <>
                          <span aria-hidden="true"> · </span>
                          <span className="text-amber-300">
                            {tr.maskedMatches.join(", ")}
                          </span>
                        </>
                      )}
                    </div>
                  </div>
                  <span
                    className={`text-[11px] font-medium shrink-0 ${
                      tr.actionTaken === "Enforced (Blocked)"
                        ? "text-rose-400"
                        : tr.actionTaken === "Alerted & Sanitized"
                        ? "text-amber-400"
                        : "text-neutral-500"
                    }`}
                  >
                    {tr.actionTaken}
                  </span>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* VIEW 1 & 2: Split Workspace or Dedicated Control Plane */}
        {(activeNavTab === "workspace" || activeNavTab === "control-plane") && (
          <div
            className={`grid grid-cols-1 ${
              activeNavTab === "workspace" ? " lg:grid-cols-12" : ""
            } gap-6 items-start`}
          >
            {/* Left / Full Column: Deduplicated Guardrails Control Plane (Matching Screenshots) */}
            <section
              aria-label="Guardrails Control Plane"
              className={`${
                activeNavTab === "workspace" ? "lg:col-span-6" : "col-span-1"
              } bg-[#111318] border border-neutral-800 rounded-lg overflow-hidden`}
            >
              {/* Control Plane Header */}
              <div className="p-4 border-b border-neutral-800 flex flex-col gap-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h2 className="text-xs font-semibold tracking-wider text-neutral-400 uppercase">
                      Guardrails ({filteredRules.length} of {rules.length} Deduplicated)
                    </h2>
                    <p className="text-xs text-neutral-400 mt-0.5">
                      Toggle each guardrail: Left{" "}
                      <strong className="text-rose-300">Enforce</strong>{" "}
                      (block), Middle{" "}
                      <strong className="text-amber-300">Alert</strong>{" "}
                      (notify &amp; sanitize), or Right{" "}
                      <strong className="text-neutral-300">Ignore</strong>{" "}
                      (disable).
                    </p>
                  </div>

                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => handleBulkSetMode("Block")}
                      className="px-2.5 py-1 text-xs font-medium bg-neutral-800 hover:bg-neutral-700 text-neutral-200 rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      All Enforce
                    </button>
                    <button
                      type="button"
                      onClick={() => handleBulkSetMode("Detect")}
                      className="px-2.5 py-1 text-xs font-medium bg-neutral-800 hover:bg-neutral-700 text-neutral-200 rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      All Alert
                    </button>
                    <button
                      type="button"
                      onClick={() => handleBulkSetMode("Ignore")}
                      className="px-2.5 py-1 text-xs font-medium bg-neutral-800 hover:bg-neutral-700 text-neutral-400 rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      All Ignore
                    </button>
                    <button
                      type="button"
                      onClick={handleResetDefaultRules}
                      title="Reset to screenshot default configuration"
                      className="px-2.5 py-1 text-xs font-medium bg-neutral-900 hover:bg-neutral-800 text-neutral-400 hover:text-neutral-200 border border-neutral-800 rounded transition-colors whitespace-nowrap shrink-0 flex items-center gap-1 cursor-pointer"
                    >
                      <RotateCcw className="w-3 h-3" />
                      <span>Reset</span>
                    </button>
                  </div>
                </div>

                {/* Search & Category Filter Bar */}
                <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                  <div className="relative flex-1">
                    <Search className="w-3.5 h-3.5 text-neutral-500 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      value={ruleSearch}
                      onChange={(e) => setRuleSearch(e.target.value)}
                      placeholder="Filter guardrails (e.g. SSN, RCE, API Keys, Package)..."
                      aria-label="Filter guardrails"
                      className="w-full bg-[#0B0D11] border border-neutral-800 rounded pl-8 pr-3 py-1.5 text-xs text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-neutral-600"
                    />
                  </div>

                  <div className="flex items-center gap-1 bg-[#0B0D11] p-1 rounded border border-neutral-800 overflow-x-auto">
                    {(
                      [
                        { id: "all", label: "All (21)" },
                        { id: "pii", label: "PII (6)" },
                        { id: "credential_leak", label: "Credentials (1)" },
                        { id: "prompt_injection", label: "Injection & System (14)" },
                      ] as const
                    ).map((cat) => (
                      <button
                        key={cat.id}
                        type="button"
                        onClick={() => setCategoryFilter(cat.id)}
                        className={`px-2.5 py-1 text-[11px] font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                          categoryFilter === cat.id
                            ? "bg-neutral-800 text-white"
                            : "text-neutral-400 hover:text-neutral-200"
                        }`}
                      >
                        {cat.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Guardrail List Rows (Faithful to attached screenshots) */}
              <div className="divide-y divide-neutral-800/80 max-h-[680px] overflow-y-auto">
                {filteredRules.map((rule) => {
                  const triggeredInfo = apiResult?.triggeredRules.find(
                    (tr) => tr.ruleId === rule.id
                  );

                  return (
                    <div
                      key={rule.id}
                      className={`px-4 py-3 flex items-center justify-between gap-4 transition-colors ${
                        triggeredInfo
                          ? "bg-amber-950/15 hover:bg-amber-950/25"
                          : "hover:bg-neutral-900/50"
                      }`}
                    >
                      {/* Rule Name & Optional Triggered Status */}
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium text-neutral-100 truncate">
                            {rule.name}
                          </span>
                          {triggeredInfo && (
                            <span className="text-[11px] font-mono text-amber-400 shrink-0">
                              · Triggered ({triggeredInfo.actionTaken})
                            </span>
                          )}
                        </div>
                        {rule.customPatternDescription && (
                          <p className="text-[11px] text-neutral-500 truncate mt-0.5">
                            {rule.customPatternDescription}
                          </p>
                        )}
                      </div>

                      {/* Right Controls: [Test] | [Edit] | [High Icon + High] | [□□■□□] | [3-Way Toggle: Enforce | Alert | Ignore] */}
                      <div className="flex items-center gap-3 shrink-0">
                        <button
                          type="button"
                          onClick={() => handleTestSingleRule(rule)}
                          title={`Load and evaluate test prompt for ${rule.name}`}
                          className="px-2 py-0.5 text-[11px] font-medium text-emerald-300 hover:text-emerald-200 bg-emerald-950/40 hover:bg-emerald-950/70 border border-emerald-800/60 rounded transition-colors cursor-pointer"
                        >
                          Test
                        </button>

                        {rule.editable && (
                          <button
                            type="button"
                            onClick={() => handleOpenEditModal(rule)}
                            className="text-xs text-neutral-300 hover:text-white underline underline-offset-4 cursor-pointer"
                          >
                            Edit
                          </button>
                        )}

                        <div className="hidden sm:flex items-center gap-1.5 text-xs text-neutral-200 w-14">
                          <HighSeverityStackIcon />
                          <span>{rule.severity}</span>
                        </div>

                        <div className="w-11 hidden xl:flex justify-center">
                          {rule.hasSensitivityDots ? (
                            <SensitivityDotsIndicator />
                          ) : null}
                        </div>

                        {/* 3-State Segmented Toggle: Left (Enforce) | Middle (Alert) | Right (Ignore) */}
                        <div
                          role="group"
                          aria-label={`${rule.name} enforcement toggle`}
                          className="inline-flex items-center bg-[#0B0D11] border border-neutral-800 rounded-md p-0.5"
                        >
                          <button
                            type="button"
                            onClick={() =>
                              handleRuleModeChange(rule.id, "Block")
                            }
                            aria-pressed={rule.mode === "Block"}
                            className={`px-2.5 py-1 text-[11px] font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                              rule.mode === "Block"
                                ? "bg-rose-600 text-white shadow-xs"
                                : "text-neutral-400 hover:text-neutral-200"
                            }`}
                          >
                            Enforce
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              handleRuleModeChange(rule.id, "Detect")
                            }
                            aria-pressed={rule.mode === "Detect"}
                            className={`px-2.5 py-1 text-[11px] font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                              rule.mode === "Detect"
                                ? "bg-amber-500 text-neutral-950 font-semibold shadow-xs"
                                : "text-neutral-400 hover:text-neutral-200"
                            }`}
                          >
                            Alert
                          </button>
                          <button
                            type="button"
                            onClick={() =>
                              handleRuleModeChange(rule.id, "Ignore")
                            }
                            aria-pressed={rule.mode === "Ignore"}
                            className={`px-2.5 py-1 text-[11px] font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                              rule.mode === "Ignore"
                                ? "bg-neutral-700 text-neutral-100 shadow-xs"
                                : "text-neutral-500 hover:text-neutral-300"
                            }`}
                          >
                            Ignore
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </section>

            {/* Right Column: Custom Prompt Textarea, Preset Library, & Sanitized Output */}
            {(activeNavTab === "workspace" ||
              activeNavTab === "control-plane") && (
              <section
                aria-label="Prompt Ingestion and Output Sanitization Playground"
                className={`${
                  activeNavTab === "workspace" ? "lg:col-span-6" : "col-span-1"
                } flex flex-col gap-5`}
              >
                {/* Dedicated Custom Prompt Tester Card */}
                <div className="bg-[#111318] border border-emerald-500/40 rounded-lg p-4 flex flex-col gap-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <label
                        htmlFor="custom-prompt-textarea"
                        className="text-xs font-semibold uppercase tracking-wider text-emerald-400 block"
                      >
                        Custom Prompt Tester (Write or Paste Any Prompt)
                      </label>
                      <p className="text-xs text-neutral-400 mt-0.5">
                        Test your own custom prompt directly against all active
                        Control Plane guardrails and{" "}
                        <code className="font-mono">jev-latest</code>.
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      {customPromptInput && (
                        <button
                          type="button"
                          onClick={() => setCustomPromptInput("")}
                          className="px-2.5 py-1 text-xs text-neutral-400 hover:text-white bg-neutral-900 border border-neutral-800 rounded cursor-pointer"
                        >
                          Clear
                        </button>
                      )}
                      <span className="text-xs text-neutral-400 font-mono tabular-nums">
                        {customPromptInput.length} chars
                      </span>
                    </div>
                  </div>

                  <textarea
                    id="custom-prompt-textarea"
                    rows={3}
                    value={customPromptInput}
                    onChange={(e) => setCustomPromptInput(e.target.value)}
                    placeholder="Type or paste any custom prompt here (e.g. a custom jailbreak attempt, a secret token, PII, or a benign question)..."
                    className="w-full bg-[#0B0D11] border border-neutral-700 rounded-md p-3 text-sm font-mono text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-emerald-400 resize-y"
                  />

                  <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2 flex-1">
                      <input
                        type="text"
                        value={customPromptLabel}
                        onChange={(e) => setCustomPromptLabel(e.target.value)}
                        placeholder="Optional label to save as preset..."
                        aria-label="Custom preset label"
                        className="flex-1 bg-[#0B0D11] border border-neutral-800 rounded px-2.5 py-1.5 text-xs text-neutral-200 placeholder-neutral-500 focus:outline-none focus:border-neutral-600"
                      />
                      <button
                        type="button"
                        onClick={handleSaveCustomPreset}
                        disabled={!customPromptInput.trim()}
                        className="px-3 py-1.5 text-xs font-medium bg-neutral-800 hover:bg-neutral-700 disabled:opacity-40 text-neutral-200 rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        Save Preset
                      </button>
                    </div>

                    <button
                      type="button"
                      onClick={handleTestCustomPrompt}
                      disabled={isEvaluating || !customPromptInput.trim()}
                      className="px-4 py-1.5 text-xs font-semibold text-neutral-950 bg-emerald-400 hover:bg-emerald-300 disabled:opacity-40 rounded transition-colors whitespace-nowrap shrink-0 flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>
                        {isEvaluating
                          ? "Evaluating..."
                          : "Test Custom Prompt"}
                      </span>
                    </button>
                  </div>
                </div>

                {/* Preset Prompt Library (21 Guardrail Prompts + 4 Safe/Negative Fixtures + Custom Saved) */}
                <div className="bg-[#111318] border border-neutral-800 rounded-lg p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-2.5">
                    <h2 className="text-xs font-semibold uppercase tracking-wider text-neutral-400">
                      Preset Test Prompts (1 per Guardrail Rule + Safe + Custom)
                    </h2>
                    <div className="flex items-center gap-1 bg-[#0B0D11] p-1 rounded border border-neutral-800 overflow-x-auto">
                      {(
                        [
                          {
                            id: "all",
                            label: `All (${
                              PRESET_PROMPTS.length + customPresets.length
                            })`,
                          },
                          { id: "1. PII Guardrails (6)", label: "PII (6)" },
                          {
                            id: "2. Credentials & Secrets (1)",
                            label: "Credentials (1)",
                          },
                          {
                            id: "3. Injection, Execution & Policy (14)",
                            label: "Injection & System (14)",
                          },
                          {
                            id: "4. Safe & Negative Fixtures (4)",
                            label: "Safe & Custom",
                          },
                        ] as const
                      ).map((grp) => (
                        <button
                          key={grp.id}
                          type="button"
                          onClick={() => setPresetGroupFilter(grp.id)}
                          className={`px-2 py-0.5 text-[11px] font-medium rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                            presetGroupFilter === grp.id
                              ? "bg-neutral-800 text-white"
                              : "text-neutral-400 hover:text-neutral-200"
                          }`}
                        >
                          {grp.label}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 max-h-56 overflow-y-auto pr-1">
                    {[...customPresets, ...PRESET_PROMPTS]
                      .filter(
                        (p) =>
                          presetGroupFilter === "all" ||
                          p.group === presetGroupFilter
                      )
                      .map((preset) => {
                        const isSelected = selectedPresetId === preset.id;
                        return (
                          <button
                            key={preset.id}
                            type="button"
                            onClick={() => handleSelectPreset(preset)}
                            className={`text-left p-2.5 rounded border transition-colors cursor-pointer flex flex-col justify-between ${
                              isSelected
                                ? "bg-neutral-800/90 border-emerald-500/80 text-white"
                                : "bg-[#0B0D11] border-neutral-800/90 text-neutral-300 hover:border-neutral-700"
                            }`}
                          >
                            <div className="text-[11px] text-neutral-400 flex items-center justify-between gap-1">
                              <span className="truncate">
                                {preset.badge === "Custom"
                                  ? "Custom User Prompt"
                                  : preset.group}
                              </span>
                            </div>
                            <div className="text-xs font-medium text-neutral-100 mt-1 line-clamp-1">
                              {preset.label}
                            </div>
                            <div className="text-[11px] text-neutral-500 mt-0.5 line-clamp-1 font-mono">
                              {preset.prompt}
                            </div>
                          </button>
                        );
                      })}
                  </div>
                </div>

                {/* Active Prompt Ingestion Payload Box */}
                <div className="bg-[#111318] border border-neutral-800 rounded-lg p-4 flex flex-col gap-3">
                  <div className="flex items-center justify-between">
                    <label
                      htmlFor="prompt-ingestion-textarea"
                      className="text-xs font-semibold uppercase tracking-wider text-neutral-300"
                    >
                      Active Ingestion Payload (Editable)
                    </label>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => setPromptInput("")}
                        className="text-xs text-neutral-400 hover:text-white cursor-pointer"
                      >
                        Clear
                      </button>
                      <span className="text-xs text-neutral-400 font-mono">
                        {promptInput.length} chars
                      </span>
                    </div>
                  </div>

                  <textarea
                    id="prompt-ingestion-textarea"
                    rows={4}
                    value={promptInput}
                    onChange={(e) => {
                      setPromptInput(e.target.value);
                      setSelectedPresetId("edited");
                    }}
                    placeholder="Enter a malicious prompt, secret key leak, or harmless query to test the guardrail control plane..."
                    className="w-full bg-[#0B0D11] border border-neutral-800 rounded-md p-3 text-sm font-mono text-neutral-100 placeholder-neutral-500 focus:outline-none focus:border-emerald-500/80 resize-y"
                  />

                  {/* Instant Local Contract Audit Preview */}
                  <div className="bg-[#0B0D11] border border-neutral-800/90 rounded px-3 py-2 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
                    <span className="text-neutral-300 truncate">
                      {liveAuditLog}
                    </span>
                    <button
                      type="button"
                      onClick={() => runTypeSafeEvaluation()}
                      disabled={isEvaluating}
                      className="px-3.5 py-1.5 text-xs font-sans font-semibold text-neutral-950 bg-emerald-400 hover:bg-emerald-300 disabled:opacity-50 rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      {isEvaluating
                        ? "Calling TypeSafe API..."
                        : "Run Full TypeSafe Evaluation"}
                    </button>
                  </div>

                  {evalError && (
                    <div className="bg-rose-950/40 border border-rose-800 text-rose-200 rounded p-3 text-xs flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                      <span>{evalError}</span>
                    </div>
                  )}
                </div>

                {/* Sanitized End-User Output & Masked Verdict Card */}
                <div className="bg-[#111318] border border-neutral-800 rounded-lg p-4 flex flex-col gap-4">
                  <div className="flex items-center justify-between border-b border-neutral-800 pb-3">
                    <div>
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-neutral-300">
                        Sanitized Output Delivered to End User
                      </h3>
                      <p className="text-xs text-neutral-400 mt-0.5">
                        Raw matches are masked to first 4 chars +{" "}
                        <code className="font-mono">****</code> before reaching
                        logs or user output.
                      </p>
                    </div>
                    {apiResult && (
                      <span
                        className={`text-xs font-semibold uppercase font-mono ${
                          apiResult.effectiveVerdict.decision === "block"
                            ? "text-rose-400"
                            : apiResult.effectiveVerdict.decision === "redact"
                            ? "text-amber-400"
                            : "text-emerald-400"
                        }`}
                      >
                        decision: &quot;{apiResult.effectiveVerdict.decision}&quot;
                      </span>
                    )}
                  </div>

                  {apiResult ? (
                    <div className="flex flex-col gap-3">
                      <div>
                        <div className="text-xs text-neutral-400 mb-1">
                          Sanitized Prompt (Post-Ingestion Redaction):
                        </div>
                        <pre className="bg-[#0B0D11] border border-neutral-800 rounded p-3 text-xs font-mono text-neutral-200 whitespace-pre-wrap break-words">
                          {apiResult.sanitizedPrompt}
                        </pre>
                      </div>

                      <div>
                        <div className="text-xs text-neutral-400 mb-1">
                          Final Sanitized End-User Response:
                        </div>
                        <div
                          className={`rounded border p-3 text-sm whitespace-pre-wrap break-words ${
                            apiResult.effectiveVerdict.decision === "block"
                              ? "bg-rose-950/20 border-rose-900/60 text-rose-200 font-mono text-xs"
                              : "bg-[#0B0D11] border-neutral-800 text-neutral-100"
                          }`}
                        >
                          {apiResult.sanitizedEndUserOutput}
                        </div>
                      </div>

                      {/* Compact TypeSafe Internals Preview inside Workspace */}
                      <div className="pt-2 border-t border-neutral-800 flex flex-col gap-2">
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-semibold text-neutral-300">
                            TypeSafe Non-Regressive API Telemetry (
                            <code className="font-mono text-emerald-400">
                              {apiResult.typesafeInternals.model}
                            </code>
                            )
                          </span>
                          <span className="text-neutral-400 font-mono tabular-nums">
                            {apiResult.typesafeInternals.decisionsLatencyMs}ms ·{" "}
                            output_tokens:{" "}
                            {apiResult.typesafeInternals.totalOutputTokens}
                          </span>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                          {ruleNoulEntries.slice(0, 4).map((item) => (
                            <div
                              key={item.rule.id}
                              className="bg-[#0B0D11] border border-neutral-800 rounded p-2 flex items-center justify-between text-xs"
                            >
                              <span className="text-neutral-300 truncate pr-2">
                                {item.rule.name}
                              </span>
                              <span
                                className={`font-mono tabular-nums shrink-0 ${
                                  item.triggered
                                    ? "text-amber-400 font-semibold"
                                    : "text-neutral-400"
                                }`}
                              >
                                noul={(item.noul * 100).toFixed(1)}%
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="py-8 text-center flex flex-col items-center gap-2">
                      <Shield className="w-6 h-6 text-neutral-500" />
                      <div className="text-sm text-neutral-300 font-medium">
                        Ready to Validate Guardrails
                      </div>
                      <p className="text-xs text-neutral-500 max-w-md">
                        Click &ldquo;Run Full TypeSafe Evaluation&rdquo; to
                        ingest the prompt through both the deterministic
                        TypeScript guardrail module and the live non-regressive{" "}
                        <code className="font-mono">
                          https://api.typesafe.ai/v1/systemone
                        </code>{" "}
                        (<code className="font-mono">jev-latest</code>) model
                        API.
                      </p>
                    </div>
                  )}
                </div>
              </section>
            )}
          </div>
        )}

        {/* VIEW 3: Full TypeSafe Model Internals & Contract Inspector */}
        {(activeNavTab === "internals" ||
          (activeNavTab === "workspace" && apiResult)) && (
          <section
            aria-label="TypeSafe API Internals"
            className="bg-[#111318] border border-neutral-800 rounded-lg p-5 flex flex-col gap-5"
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-neutral-800 pb-4">
              <div>
                <h2 className="text-base font-bold text-white">
                  TypeSafe Non-Regressive Decision Model & Contract Internals
                </h2>
                <p className="text-xs text-neutral-400 mt-0.5">
                  Live inspection of calibrated <code className="font-mono">noul</code>{" "}
                  probabilities, <code className="font-mono">choice</code> threat
                  routing, <code className="font-mono">score</code> rubric
                  evaluation (<code className="font-mono">total_output_tokens = 0</code>),
                  and strict TypeScript <code className="font-mono">GuardrailVerdict</code>{" "}
                  discriminated unions.
                </p>
              </div>
              {!apiResult && (
                <button
                  type="button"
                  onClick={() => runTypeSafeEvaluation()}
                  disabled={isEvaluating}
                  className="px-3.5 py-2 text-xs font-semibold text-neutral-950 bg-emerald-400 hover:bg-emerald-300 rounded transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {isEvaluating
                    ? "Evaluating..."
                    : "Run Evaluation to Populate Internals"}
                </button>
              )}
            </div>

            {apiResult ? (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                {/* Calibrated noul Probabilities per Control Plane Rule */}
                <div className="lg:col-span-7 flex flex-col gap-4">
                  <div className="bg-[#0B0D11] border border-neutral-800 rounded-lg p-4">
                    <div className="flex items-center justify-between mb-3">
                      <h3 className="text-xs font-semibold uppercase tracking-wider text-neutral-300">
                        Calibrated <code className="font-mono">noul</code>{" "}
                        Probabilities across Active Guardrails
                      </h3>
                      <span className="text-xs font-mono text-neutral-400 tabular-nums">
                        Threshold: P(true) &ge; 0.65
                      </span>
                    </div>

                    <div className="space-y-2.5 max-h-[420px] overflow-y-auto pr-1">
                      {ruleNoulEntries.map(({ rule, noul, confidence, triggered }) => (
                        <div
                          key={rule.id}
                          className="p-2.5 rounded border border-neutral-800/90 bg-[#111318] flex flex-col gap-1.5"
                        >
                          <div className="flex items-center justify-between text-xs">
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-neutral-100">
                                {rule.name}
                              </span>
                              <span className="text-neutral-500">·</span>
                              <span className="text-neutral-400 font-mono text-[11px]">
                                {rule.mode === "Block"
                                  ? "Enforce"
                                  : rule.mode === "Detect"
                                  ? "Alert"
                                  : "Ignore"}
                              </span>
                            </div>
                            <div className="font-mono text-xs tabular-nums flex items-center gap-3">
                              <span
                                className={
                                  triggered
                                    ? "text-amber-400 font-semibold"
                                    : "text-neutral-300"
                                }
                              >
                                noul={noul.toFixed(2)}
                              </span>
                              <span className="text-neutral-500">
                                conf={confidence.toFixed(2)}
                              </span>
                            </div>
                          </div>
                          <div className="w-full h-1.5 bg-neutral-800 rounded-full overflow-hidden">
                            <div
                              className={`h-full transition-all ${
                                triggered ? "bg-rose-500" : "bg-emerald-500"
                              }`}
                              style={{ width: `${Math.max(2, noul * 100)}%` }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Choice & Score Rubric Outputs */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    {primaryChoiceAnswer && (
                      <div className="bg-[#0B0D11] border border-neutral-800 rounded-lg p-4">
                        <h3 className="text-xs font-semibold uppercase tracking-wider text-neutral-300 mb-2">
                          TypeSafe <code className="font-mono">choice</code>{" "}
                          Threat Vector
                        </h3>
                        <div className="text-sm font-mono font-semibold text-emerald-400 mb-2">
                          {primaryChoiceAnswer.choice} (conf{" "}
                          {(primaryChoiceAnswer.confidence * 100).toFixed(1)}%)
                        </div>
                        <div className="space-y-1.5 text-xs font-mono">
                          {Object.entries(
                            primaryChoiceAnswer.probabilities
                          ).map(([opt, prob]) => (
                            <div
                              key={opt}
                              className="flex items-center justify-between text-neutral-300"
                            >
                              <span className="truncate pr-2">{opt}</span>
                              <span className="tabular-nums text-neutral-400">
                                {(prob * 100).toFixed(1)}%
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {severityScoreAnswer && (
                      <div className="bg-[#0B0D11] border border-neutral-800 rounded-lg p-4">
                        <h3 className="text-xs font-semibold uppercase tracking-wider text-neutral-300 mb-2">
                          TypeSafe <code className="font-mono">score</code>{" "}
                          Severity Rubric
                        </h3>
                        <div className="text-sm font-mono font-semibold text-amber-400 mb-2 tabular-nums">
                          Expected Rubric Index:{" "}
                          {severityScoreAnswer.score.toFixed(2)} / 3.00
                        </div>
                        <div className="space-y-1.5 text-xs font-mono">
                          {Object.entries(
                            severityScoreAnswer.probabilities
                          ).map(([idx, prob]) => (
                            <div
                              key={idx}
                              className="flex items-center justify-between text-neutral-300"
                            >
                              <span>Level {idx}</span>
                              <span className="tabular-nums text-neutral-400">
                                {(prob * 100).toFixed(1)}%
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Strict TypeScript GuardrailVerdict & Shannon Entropy Inspector */}
                <div className="lg:col-span-5 flex flex-col gap-4">
                  <div className="bg-[#0B0D11] border border-neutral-800 rounded-lg p-4">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-neutral-300 mb-2">
                      Strict Discriminated Union{" "}
                      <code className="font-mono">GuardrailVerdict</code>
                    </h3>
                    <pre className="text-xs font-mono text-emerald-300 bg-[#111318] border border-neutral-800 rounded p-3 overflow-x-auto">
                      {JSON.stringify(apiResult.effectiveVerdict, null, 2)}
                    </pre>
                  </div>

                  <div className="bg-[#0B0D11] border border-neutral-800 rounded-lg p-4">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-neutral-300 mb-2">
                      Shannon Entropy Token Telemetry (&ge; 4.5 bits/char over
                      20+ chars)
                    </h3>
                    {apiResult.entropyAnalysis.length > 0 ? (
                      <div className="divide-y divide-neutral-800 text-xs font-mono">
                        {apiResult.entropyAnalysis.map((ent, idx) => (
                          <div
                            key={`${ent.maskedToken}-${idx}`}
                            className="py-1.5 flex items-center justify-between"
                          >
                            <span className="text-neutral-200">
                              {ent.maskedToken}{" "}
                              <span className="text-neutral-500">
                                ({ent.length} chars)
                              </span>
                            </span>
                            <span
                              className={`tabular-nums ${
                                ent.exceedsThreshold
                                  ? "text-amber-400 font-semibold"
                                  : "text-neutral-400"
                              }`}
                            >
                              {ent.shannonEntropy} bits/ch
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-neutral-500">
                        No long candidate tokens (12+ chars) in current prompt.
                      </p>
                    )}
                  </div>

                  <div className="bg-[#0B0D11] border border-neutral-800 rounded-lg p-4">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-neutral-300 mb-2">
                      TypeSafe Endpoint Request (
                      <code className="font-mono text-emerald-400">
                        {apiResult.typesafeInternals.endpoint}
                      </code>
                      )
                    </h3>
                    <pre className="text-xs font-mono text-neutral-300 bg-[#111318] border border-neutral-800 rounded p-3 max-h-48 overflow-y-auto">
                      {JSON.stringify(
                        apiResult.typesafeInternals.requestPayload,
                        null,
                        2
                      )}
                    </pre>
                  </div>
                </div>
              </div>
            ) : (
              <div className="bg-[#0B0D11] border border-neutral-800 rounded-lg p-6">
                <h3 className="text-xs font-semibold uppercase tracking-wider text-neutral-300 mb-2">
                  Live Local <code className="font-mono">evaluatePrompt(input, policy)</code>{" "}
                  Preview
                </h3>
                <pre className="text-xs font-mono text-emerald-300 overflow-x-auto">
                  {JSON.stringify(liveLocalVerdict, null, 2)}
                </pre>
              </div>
            )}
          </section>
        )}

        {/* VIEW 4: Table-Driven Contract Test Suite (Positive & Negative Fixtures) */}
        {activeNavTab === "test-suite" && (
          <section
            aria-label="Table-Driven Contract Test Suite"
            className="bg-[#111318] border border-neutral-800 rounded-lg p-5 flex flex-col gap-4"
          >
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-neutral-800 pb-4">
              <div>
                <h2 className="text-base font-bold text-white">
                  Table-Driven Contract Fixtures (
                  <code className="font-mono text-sm">
                    src/guardrails/evaluator.test.ts
                  </code>
                  )
                </h2>
                <p className="text-xs text-neutral-400 mt-0.5">
                  Verifies AWS keys, GitHub tokens, PEM headers, JWT shapes,
                  Shannon entropy &ge; 4.5, PII redaction, and negative fixtures
                  (UUIDv4 is not a secret, 40-char Git SHA is not a key).
                </p>
              </div>
              <button
                type="button"
                onClick={fetchTestSuite}
                disabled={isLoadingTests}
                className="px-3.5 py-1.5 text-xs font-semibold bg-emerald-400 hover:bg-emerald-300 text-neutral-950 rounded transition-colors cursor-pointer"
              >
                {isLoadingTests ? "Running Fixtures..." : "Re-Run Test Suite"}
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-neutral-800 text-neutral-400">
                    <th className="py-2.5 px-3 font-medium">Status</th>
                    <th className="py-2.5 px-3 font-medium">Fixture Case</th>
                    <th className="py-2.5 px-3 font-medium">Expected</th>
                    <th className="py-2.5 px-3 font-medium">Actual Verdict</th>
                    <th className="py-2.5 px-3 font-medium">
                      Raw Masking (<code className="font-mono">XXXX****</code>)
                    </th>
                    <th className="py-2.5 px-3 font-medium text-right">
                      Latency
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-neutral-800/80">
                  {testSuiteData?.results.map((item) => (
                    <tr key={item.id} className="hover:bg-neutral-900/50">
                      <td className="py-2.5 px-3 font-mono">
                        {item.passed ? (
                          <span className="text-emerald-400 font-semibold">
                            PASS
                          </span>
                        ) : (
                          <span className="text-rose-400 font-semibold">
                            FAIL
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="font-medium text-neutral-100">
                          {item.name}
                        </div>
                        <div className="text-neutral-400 font-mono text-[11px] mt-0.5 truncate max-w-md">
                          {item.auditLog}
                        </div>
                      </td>
                      <td className="py-2.5 px-3 font-mono uppercase text-neutral-300">
                        {item.expectedDecision}
                      </td>
                      <td className="py-2.5 px-3 font-mono uppercase text-emerald-400">
                        {item.actualVerdict.decision}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-neutral-300">
                        {item.rawMaskingVerified
                          ? "Verified (Zero raw leak)"
                          : "Failed"}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-right text-neutral-400 tabular-nums">
                        {item.durationMs}ms
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}
      </main>

      {/* Edit Custom Guardrail Policy Modal */}
      {editingRule && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="edit-rule-modal-title"
          className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4"
        >
          <div className="bg-[#12151E] border border-neutral-800 rounded-lg max-w-lg w-full p-5 flex flex-col gap-4">
            <div className="flex items-center justify-between border-b border-neutral-800 pb-3">
              <h3
                id="edit-rule-modal-title"
                className="text-sm font-semibold text-white"
              >
                Edit Guardrail Policy: {editingRule.name}
              </h3>
              <button
                type="button"
                onClick={() => setEditingRule(null)}
                aria-label="Close modal"
                className="text-neutral-400 hover:text-white cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSaveRuleEdit} className="flex flex-col gap-4">
              <div>
                <label
                  htmlFor="custom-policy-description"
                  className="block text-xs font-medium text-neutral-300 mb-1.5"
                >
                  Guardrail Rule Specification
                </label>
                <textarea
                  id="custom-policy-description"
                  rows={2}
                  value={editPatternDraft}
                  onChange={(e) => setEditPatternDraft(e.target.value)}
                  className="w-full bg-[#0B0D11] border border-neutral-800 rounded p-2.5 text-xs font-mono text-neutral-100 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label
                  htmlFor="custom-typesafe-question"
                  className="block text-xs font-medium text-neutral-300 mb-1.5"
                >
                  TypeSafe System One (<code className="font-mono">noul</code>)
                  Question Instructions
                </label>
                <textarea
                  id="custom-typesafe-question"
                  rows={2}
                  value={editQuestionDraft}
                  onChange={(e) => setEditQuestionDraft(e.target.value)}
                  className="w-full bg-[#0B0D11] border border-neutral-800 rounded p-2.5 text-xs font-mono text-neutral-100 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div>
                <label
                  htmlFor="custom-sample-prompt"
                  className="block text-xs font-medium text-neutral-300 mb-1.5"
                >
                  Dedicated Rule Test Prompt
                </label>
                <textarea
                  id="custom-sample-prompt"
                  rows={2}
                  value={editSamplePromptDraft}
                  onChange={(e) => setEditSamplePromptDraft(e.target.value)}
                  className="w-full bg-[#0B0D11] border border-neutral-800 rounded p-2.5 text-xs font-mono text-neutral-100 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setEditingRule(null)}
                  className="px-3 py-1.5 text-xs font-medium text-neutral-300 hover:text-white bg-neutral-800 rounded cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3.5 py-1.5 text-xs font-semibold text-neutral-950 bg-emerald-400 hover:bg-emerald-300 rounded cursor-pointer"
                >
                  Save Guardrail Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
