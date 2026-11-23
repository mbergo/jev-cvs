import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  X,
  Zap,
} from "lucide-react";
import {
  buildRulePresets,
  type ControlPlaneRule,
  INITIAL_CONTROL_PLANE_RULES,
  HEALTHCARE_NEAR_MISS_PROMPTS,
  NEGATIVE_PRESET_PROMPTS,
  type PresetPromptItem,
  type RuleEnforcementMode,
  type RuleGroup,
} from "./data/controlPlaneRules";
import InsideJev from "./components/InsideJev";
import JevConfig from "./components/JevConfig";
import LiveWire, { type WireEntry } from "./components/LiveWire";
import { TYPESAFE_THRESHOLDS } from "./guardrails/typesafe";

// ─── Types (mirror of /api/evaluate) ──────────────────────────────────────

type Band = "pass" | "review" | "action";

interface TriggeredRule {
  ruleId: string;
  ruleName: string;
  mode: RuleEnforcementMode;
  typesafeNoulProbability: number | null;
  band: Band;
  escalatedBySeverity: boolean;
  actionTaken:
    | "Enforced (Blocked)"
    | "Alerted & Sanitized"
    | "Flagged for Review"
    | "Ignored (Bypassed)";
}

interface NoulAnswer { type: "noul"; noul: number }
interface ChoiceAnswer { type: "choice"; choice: string; probabilities: Record<string, number>; confidence: number }
interface ScoreAnswer { type: "score"; score: number; probabilities: Record<string, number>; legend?: Record<string, string> }
type Answer = NoulAnswer | ChoiceAnswer | ScoreAnswer;

interface EvalResult {
  effectiveVerdict:
    | { decision: "allow" }
    | { decision: "block"; category: string; reason: string }
    | { decision: "redact"; category: string };
  triggeredRules: TriggeredRule[];
  typesafeInternals: {
    endpoint: string;
    httpStatus?: number;
    model: string;
    thresholds: { noulAction: number; noulReview: number; severityBlock: number };
    severityScore: number;
    totalInputTokens: number | null;
    totalOutputTokens: number;
    decisionsLatencyMs: number;
    totalPipelineLatencyMs?: number;
    requestPayload: { model?: string; state: unknown; questions: Record<string, unknown> };
    rawAnswers: Record<string, Answer>;
  };
}

const GROUPS: RuleGroup[] = [
  "PII", "Credentials & Secrets", "Confidential Data", "Injection & Execution", "Harmful Content",
  // CVS Health proposal, listed after the original groups.
  "Healthcare Identifiers", "Healthcare Confidential Data", "Healthcare Conduct",
];

const VERDICT_LABEL: Record<EvalResult["effectiveVerdict"]["decision"], string> = {
  allow: "ALLOW",
  redact: "ALERT",
  block: "BLOCK",
};

const MODE_LABEL: Record<RuleEnforcementMode, string> = { Block: "Enforce", Detect: "Alert", Ignore: "Ignore" };

/** "pii_disclosure" → "PII disclosure": machine keys read as words in the verdict panel. */
function humanize(key: string): string {
  const s = key.replace(/_/g, " ").replace(/\bpii\b/i, "PII");
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// ─── Small components ──────────────────────────────────────────────────────

function NoulBar({ p, thresholds }: { p: number | null; thresholds?: EvalResult["typesafeInternals"]["thresholds"] }) {
  const action = thresholds?.noulAction ?? 0.7;
  const review = thresholds?.noulReview ?? 0.35;
  const band: Band = p === null ? "pass" : p >= action ? "action" : p >= review ? "review" : "pass";
  const color = band === "action" ? "bg-rose-500" : band === "review" ? "bg-sky-400" : "bg-emerald-500";
  const text = band === "action" ? "text-rose-300" : band === "review" ? "text-sky-300" : "text-ink-3";
  return (
    <div className="flex items-center gap-3 flex-1 min-w-[10rem]">
      <div className="relative flex-1 h-1.5 bg-raised rounded-full overflow-hidden" title={`Action threshold ${action}`}>
        {p !== null && <div className={`h-full rounded-full ${color} transition-all duration-500`} style={{ width: `${Math.max(2, p * 100)}%` }} />}
        <div className="absolute -top-0.5 -bottom-0.5 w-0.5 bg-ink-3/70" style={{ left: `${action * 100}%` }} />
      </div>
      <span className={`font-mono text-sm tabular-nums w-10 text-right ${text}`}>{p === null ? "—" : p.toFixed(2)}</span>
    </div>
  );
}

function ModeToggle({ mode, onChange }: { mode: RuleEnforcementMode; onChange: (m: RuleEnforcementMode) => void }) {
  const opts: { m: RuleEnforcementMode; on: string }[] = [
    { m: "Block", on: "bg-rose-600 text-white" },
    { m: "Detect", on: "bg-amber-400 text-black" },
    { m: "Ignore", on: "bg-neutral-600 text-white" },
  ];
  return (
    <div className="flex p-0.5 gap-0.5 rounded-lg bg-canvas border border-line shrink-0">
      {opts.map((o) => (
        <button key={o.m} type="button" onClick={() => onChange(o.m)} aria-pressed={mode === o.m}
          className={`px-2.5 py-1 rounded-md text-[13px] font-medium cursor-pointer transition-colors ${mode === o.m ? o.on : "text-ink-3 hover:text-ink"}`}>
          {MODE_LABEL[o.m]}
        </button>
      ))}
    </div>
  );
}

function Switch({ on, onToggle, label, tone }: { on: boolean; onToggle: () => void; label: string; tone: string }) {
  return (
    <button type="button" role="switch" aria-checked={on} onClick={onToggle} className="flex items-center gap-2.5 text-sm text-ink-2 hover:text-ink cursor-pointer select-none">
      <span className={`relative w-9 h-5 rounded-full transition-colors ${on ? tone : "bg-line-strong"}`}>
        <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${on ? "left-[1.125rem]" : "left-0.5"}`} />
      </span>
      {label}
    </button>
  );
}

function Collapsible({ title, children, defaultOpen = false }: { title: string; children: React.ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="card overflow-hidden">
      <button type="button" onClick={() => setOpen(!open)} aria-expanded={open} className="w-full flex items-center gap-3 px-6 py-4 text-[15px] font-medium text-ink-2 hover:text-ink cursor-pointer">
        {open ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}{title}
      </button>
      {open && <div className="px-6 pb-6">{children}</div>}
    </div>
  );
}

function ProbabilityRows({ title, note, rows }: { title: string; note?: string; rows: { key: string; label: string; v: number; strong: boolean; color: string }[] }) {
  return (
    <div>
      <div className="flex items-baseline justify-between gap-3 mb-3">
        <h3 className="text-sm font-semibold text-ink">{title}</h3>
        {note && <span className="text-xs text-ink-3">{note}</span>}
      </div>
      <div className="space-y-2.5">
        {rows.map((r) => (
          <div key={r.key} className="grid grid-cols-[minmax(0,13rem)_1fr_2.75rem] items-center gap-3 text-sm">
            <span className={`leading-snug ${r.strong ? "text-ink font-medium" : "text-ink-3"}`}>{r.label}</span>
            <div className="h-1.5 bg-canvas/70 rounded-full overflow-hidden"><div className={`h-full rounded-full ${r.color}`} style={{ width: `${r.v * 100}%` }} /></div>
            <span className="text-right font-mono tabular-nums text-ink-2">{(r.v * 100).toFixed(0)}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

const ACTION_TONE: Record<TriggeredRule["actionTaken"], { chip: string; label: string }> = {
  "Enforced (Blocked)": { chip: "bg-rose-500/15 text-rose-300 ring-rose-500/30", label: "Blocked" },
  "Alerted & Sanitized": { chip: "bg-amber-400/15 text-amber-300 ring-amber-400/30", label: "Alert" },
  "Flagged for Review": { chip: "bg-sky-500/15 text-sky-300 ring-sky-500/30", label: "Review" },
  "Ignored (Bypassed)": { chip: "bg-neutral-500/15 text-ink-3 ring-neutral-500/30", label: "Ignored" },
};

// ─── App ───────────────────────────────────────────────────────────────────

export default function App() {
  const [rules, setRules] = useState<ReadonlyArray<ControlPlaneRule>>(INITIAL_CONTROL_PLANE_RULES);
  const [prompt, setPrompt] = useState(INITIAL_CONTROL_PLANE_RULES[0].sampleViolationPrompt);
  const [selectedPreset, setSelectedPreset] = useState(`preset-${INITIAL_CONTROL_PLANE_RULES[0].id}`);
  const [result, setResult] = useState<EvalResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [inside, setInside] = useState<boolean>(() => localStorage.getItem("insideJev") === "1");
  const [runId, setRunId] = useState(0);
  useEffect(() => { localStorage.setItem("insideJev", inside ? "1" : "0"); }, [inside]);
  // Live wire: the latest browser → policy server round-trip, shown as devtools would.
  // On by default. New storage key: the old "liveWire" key holds "0" for every browser that loaded the page before.
  const [wireOn, setWireOn] = useState<boolean>(() => localStorage.getItem("liveWireOn") !== "0");
  useEffect(() => { localStorage.setItem("liveWireOn", wireOn ? "1" : "0"); }, [wireOn]);
  const [wire, setWire] = useState<WireEntry | null>(null);
  const wireSeq = useRef(0);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<{ connected: boolean; model: string; error?: string } | null>(null);
  const [editing, setEditing] = useState<ControlPlaneRule | null>(null);
  const [draft, setDraft] = useState({ ask: "", yes: "", no: "", examples: "", sample: "" });

  // Batch run ("Run all N presets": one per guardrail)
  interface BatchRow { id: string; label: string; expected: "flag" | "allow"; decision?: string; own?: number | null; ms?: number; ok?: boolean }
  const [batch, setBatch] = useState<BatchRow[] | null>(null);
  const [batchBusy, setBatchBusy] = useState(false);

  const presets = useMemo<PresetPromptItem[]>(() => [...buildRulePresets(rules), ...NEGATIVE_PRESET_PROMPTS, ...HEALTHCARE_NEAR_MISS_PROMPTS], [rules]);

  useEffect(() => {
    fetch("/api/typesafe-status").then((r) => r.json()).then(setStatus).catch(() => setStatus({ connected: false, model: "jev-latest", error: "unreachable" }));
  }, []);

  async function evaluate(p: string, r: ReadonlyArray<ControlPlaneRule>): Promise<EvalResult> {
    const body = { prompt: p, rules: r };
    const id = ++wireSeq.current;
    const t0 = performance.now();
    // Log the round-trip as it happens: TX at send time, RX when the reply lands. Every call
    // goes through here, so the batch run streams too. Only the latest is kept.
    setWire({ id, startedAt: Date.now(), method: "POST", url: "/api/evaluate", request: body });
    const patch = (u: Partial<WireEntry>) => setWire((w) => (w && w.id === id ? { ...w, ...u } : w));
    try {
      const res = await fetch("/api/evaluate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const data = await res.json();
      patch({ status: res.status, ms: Math.round(performance.now() - t0), response: data });
      if (!res.ok) throw new Error(data.error ?? `HTTP ${res.status}`);
      return data as EvalResult;
    } catch (e) {
      patch({ ms: Math.round(performance.now() - t0), error: e instanceof Error ? e.message : String(e) });
      throw e;
    }
  }

  async function run(p = prompt, r = rules) {
    if (!p.trim()) return;
    setBusy(true); setError(null);
    try { setResult(await evaluate(p, r)); setRunId((n) => n + 1); } catch (e) { setError(e instanceof Error ? e.message : String(e)); } finally { setBusy(false); }
  }

  function applyRules(next: ReadonlyArray<ControlPlaneRule>) {
    setRules(next);
    if (result) run(prompt, next);
  }

  function testRule(rule: ControlPlaneRule) {
    setSelectedPreset(`preset-${rule.id}`);
    setPrompt(rule.sampleViolationPrompt);
    run(rule.sampleViolationPrompt, rules);
  }

  function pickPreset(p: PresetPromptItem) {
    setSelectedPreset(p.id);
    setPrompt(p.prompt);
    run(p.prompt, rules);
  }

  function openEdit(rule: ControlPlaneRule) {
    setEditing(rule);
    setDraft({
      ask: rule.typesafeQuestion.instructions,
      yes: rule.typesafeQuestion.trueDescription,
      no: rule.typesafeQuestion.falseDescription,
      examples: rule.typesafeQuestion.examples.join("\n"),
      sample: rule.sampleViolationPrompt,
    });
  }

  function saveEdit(e: React.FormEvent) {
    e.preventDefault();
    if (!editing) return;
    const next = rules.map((r) => r.id !== editing.id ? r : {
      ...r,
      sampleViolationPrompt: draft.sample.trim(),
      typesafeQuestion: {
        instructions: draft.ask.trim(),
        trueDescription: draft.yes.trim(),
        falseDescription: draft.no.trim(),
        examples: draft.examples.split("\n").map((s) => s.trim()).filter(Boolean),
      },
    });
    if (selectedPreset === `preset-${editing.id}`) setPrompt(draft.sample.trim());
    setEditing(null);
    applyRules(next);
  }

  async function runAll() {
    const toRun = presets.filter((p) => p.ruleId);
    const rows: BatchRow[] = toRun.map((p) => ({ id: p.id, label: p.label, expected: p.ruleId ? "flag" : "allow" }));
    setBatch(rows); setBatchBusy(true);
    for (let i = 0; i < toRun.length; i++) {
      const p = toRun[i];
      try {
        const r = await evaluate(p.prompt, rules);
        const own = p.ruleId ? r.typesafeInternals.rawAnswers[p.ruleId] : null;
        const ownNoul = own && own.type === "noul" ? own.noul : null;
        const flagged = r.effectiveVerdict.decision !== "allow";
        const ok = p.ruleId ? flagged && (ownNoul ?? 0) >= r.typesafeInternals.thresholds.noulAction : !flagged;
        rows[i] = { ...rows[i], decision: VERDICT_LABEL[r.effectiveVerdict.decision], own: ownNoul, ms: r.typesafeInternals.decisionsLatencyMs, ok };
      } catch (e) {
        rows[i] = { ...rows[i], decision: "ERROR", ok: false };
      }
      setBatch([...rows]);
    }
    setBatchBusy(false);
  }

  // Derived
  const answers = result?.typesafeInternals.rawAnswers ?? {};
  const noulOf = (id: string): number | null => { const a = answers[id]; return a && a.type === "noul" ? a.noul : null; };
  const vector = answers["primary_threat_vector"] as ChoiceAnswer | undefined;
  const severity = answers["threat_severity_rubric"] as ScoreAnswer | undefined;
  const verdict = result?.effectiveVerdict.decision;
  const counts = { block: rules.filter((r) => r.mode === "Block").length, alert: rules.filter((r) => r.mode === "Detect").length, ignore: rules.filter((r) => r.mode === "Ignore").length };
  const batchPassed = batch?.filter((b) => b.ok).length ?? 0;
  const batchDone = batch?.filter((b) => b.decision).length ?? 0;

  const activeCount = rules.filter((r) => r.mode !== "Ignore").length;
  const verdictStyle = verdict === "block"
    ? { box: "border-rose-500/40 bg-gradient-to-br from-rose-950/50 to-surface", icon: <ShieldAlert className="w-9 h-9 text-rose-400" />, word: "text-rose-300" }
    : verdict === "redact"
      ? { box: "border-amber-400/40 bg-gradient-to-br from-amber-950/40 to-surface", icon: <AlertTriangle className="w-9 h-9 text-amber-400" />, word: "text-amber-300" }
      : { box: "border-emerald-500/40 bg-gradient-to-br from-emerald-950/40 to-surface", icon: <ShieldCheck className="w-9 h-9 text-emerald-400" />, word: "text-emerald-300" };

  return (
    <div className="min-h-screen bg-canvas text-ink">
      {/* Header */}
      <header className="sticky top-0 z-10 border-b border-line bg-canvas/85 backdrop-blur-md">
        <div className="mx-auto max-w-[1600px] px-6 lg:px-10 h-[72px] flex items-center justify-between gap-8">
          <div className="flex items-center gap-3.5 min-w-0">
            <div className="w-9 h-9 rounded-xl bg-emerald-500/15 ring-1 ring-emerald-500/30 flex items-center justify-center shrink-0">
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
            </div>
            <div className="min-w-0">
              <div className="text-xs font-semibold tracking-[0.08em] uppercase text-ink-3">TypeSafe Guardrail Studio</div>
              <h1 className="text-[17px] font-semibold tracking-tight truncate">Non-Autoregressive Guardrails for AI Gateways</h1>
            </div>
          </div>
          <div className="hidden lg:flex items-center gap-3 text-sm whitespace-nowrap">
            <span className={`flex items-center gap-2 px-3 py-1.5 rounded-full ring-1 ${status?.connected ? "bg-emerald-500/10 ring-emerald-500/25 text-emerald-300" : status ? "bg-rose-500/10 ring-rose-500/25 text-rose-300" : "bg-raised ring-line text-ink-3"}`}>
              <span className={`w-2 h-2 rounded-full ${status?.connected ? "bg-emerald-400" : status ? "bg-rose-400" : "bg-ink-3 animate-pulse"}`} />
              {status ? (status.connected ? <>api.typesafe.ai <span className="font-mono text-[13px] opacity-80">{result?.typesafeInternals.model ?? status.model}</span></> : `Offline: ${status.error}`) : "Connecting…"}
            </span>
            <span className="px-3 py-1.5 rounded-full bg-raised ring-1 ring-line text-ink-2">
              <span className="text-rose-300">{counts.block}</span> enforce · <span className="text-amber-300">{counts.alert}</span> alert · {counts.ignore} ignore
            </span>
            <button type="button" onClick={() => applyRules(INITIAL_CONTROL_PLANE_RULES)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-ink-3 hover:text-ink hover:bg-raised cursor-pointer"><RotateCcw className="w-3.5 h-3.5" />Reset</button>
          </div>
        </div>
      </header>

      <main className={`mx-auto px-6 lg:px-10 py-10 grid grid-cols-1 gap-8 ${inside ? "max-w-[1800px] xl:grid-cols-2" : "max-w-[1600px] xl:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)]"}`}>
        {/* ── Prompt, verdict, explanation ──────────────────── */}
        <section className="flex flex-col gap-8 min-w-0">
          {/* Intro */}
          <div className="max-w-3xl">
            <p className="text-[1.0625rem] leading-relaxed text-ink-2">
              Every prompt that enters the gateway is checked against <span className="text-ink font-medium">{activeCount} active guardrails</span> in a single call.
              Jev answers one yes/no question per guardrail; plain policy code turns those probabilities into <span className="text-emerald-300">Allow</span>, <span className="text-amber-300">Alert</span> or <span className="text-rose-300">Block</span>. No regex.
            </p>
          </div>

          {/* Prompt */}
          <div className="card p-7 flex flex-col gap-5">
            <div className="flex flex-wrap items-end justify-between gap-4">
              <div>
                <div className="eyebrow mb-1.5">Step 1 · Input</div>
                <h2 className="section-title">Prompt entering the gateway</h2>
              </div>
              <label className="flex flex-col gap-1.5 text-xs font-medium text-ink-3">
                Example prompt
                <select value={selectedPreset} onChange={(e) => { const p = presets.find((x) => x.id === e.target.value); if (p) pickPreset(p); }} className="bg-canvas border border-line-strong rounded-lg text-sm text-ink px-3 py-2 w-[280px] max-w-full cursor-pointer focus:outline-none focus:border-emerald-500">
                  <option value="custom">Custom prompt</option>
                  {GROUPS.map((g) => (
                    <optgroup key={g} label={g}>
                      {rules.filter((r) => r.group === g).map((r) => <option key={r.id} value={`preset-${r.id}`}>{r.name}</option>)}
                    </optgroup>
                  ))}
                  <optgroup label="Safe / negative">
                    {NEGATIVE_PRESET_PROMPTS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
                  </optgroup>
                  <optgroup label="Healthcare near-misses (should allow)">
                    {HEALTHCARE_NEAR_MISS_PROMPTS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
                  </optgroup>
                </select>
              </label>
            </div>
            <textarea value={prompt} onChange={(e) => { setPrompt(e.target.value); setSelectedPreset("custom"); }} rows={4} className="w-full bg-canvas border border-line-strong rounded-xl px-5 py-4 text-[1.0625rem] leading-relaxed text-ink placeholder:text-ink-3 resize-y focus:outline-none focus:border-emerald-500 focus:ring-4 focus:ring-emerald-500/10 transition" placeholder="Paste any prompt…" />
            <div className="flex flex-wrap items-center gap-3">
              <button type="button" onClick={() => run()} disabled={busy || !prompt.trim()} className="btn px-5 py-2.5 bg-emerald-500 hover:bg-emerald-400 text-emerald-950 text-[15px] shadow-lg shadow-emerald-500/10">
                <Play className="w-4 h-4 fill-current" />{busy ? "Evaluating…" : "Evaluate"}
              </button>
              <button type="button" onClick={runAll} disabled={batchBusy} className="btn px-4 py-2.5 border border-line-strong hover:bg-raised text-ink text-[15px]">
                <Zap className="w-4 h-4 text-amber-400" />{batchBusy ? `Running ${batchDone}/${rules.length}…` : `Run all ${rules.length} presets`}
              </button>
              <div className="flex items-center gap-5 pl-4 ml-1 border-l border-line-strong h-8">
                <Switch on={inside} onToggle={() => setInside((v) => !v)} label="Inside Jev" tone="bg-violet-500" />
                <Switch on={wireOn} onToggle={() => setWireOn((v) => !v)} label="Live wire" tone="bg-emerald-500" />
              </div>
            </div>
            {error && <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-300 break-words">{error}</div>}
          </div>

          {/* Verdict */}
          {result && (
            <div className={`rounded-2xl border p-7 ${verdictStyle.box}`}>
              <div className="flex flex-wrap items-start justify-between gap-6">
                <div className="flex items-center gap-4">
                  {verdictStyle.icon}
                  <div>
                    <div className="eyebrow mb-0.5">Step 2 · Decision</div>
                    <div className={`text-4xl font-bold tracking-tight leading-tight ${verdictStyle.word}`}>{VERDICT_LABEL[verdict!]}</div>
                  </div>
                </div>
                <div className="text-right text-sm text-ink-2">
                  <div><span className="font-semibold text-ink text-lg tabular-nums">{result.typesafeInternals.decisionsLatencyMs} ms</span></div>
                  <div className="text-ink-3">{Object.keys(result.typesafeInternals.requestPayload.questions).length} questions · <span className="font-mono text-[13px]">{result.typesafeInternals.model}</span></div>
                </div>
              </div>
              <p className="mt-4 text-[1.0625rem] text-ink-2">
                {verdict === "block" && "Request halted. It was not forwarded to the LLM."}
                {verdict === "redact" && "Forwarded with a notice: guardrails in Alert mode fired."}
                {verdict === "allow" && "Clean. The request was forwarded to the LLM."}
              </p>
              {result.triggeredRules.length > 0 && (
                <div className="mt-5">
                  <div className="text-xs font-medium text-ink-3 mb-2">Guardrails that fired</div>
                  <div className="flex flex-wrap gap-2">
                    {result.triggeredRules.map((t) => (
                      <span key={t.ruleId} className={`inline-flex items-center gap-2 text-sm px-3 py-1 rounded-full ring-1 ${ACTION_TONE[t.actionTaken].chip}`}>
                        <span className="font-medium">{t.ruleName}</span>
                        <span className="font-mono text-[13px] opacity-80">{t.typesafeNoulProbability?.toFixed(2)}</span>
                        {t.escalatedBySeverity && <span className="text-xs opacity-80" title="Escalated by the overall severity score">↑ severity</span>}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Vector + severity */}
              <div className="mt-7 pt-6 border-t border-white/10 grid grid-cols-1 md:grid-cols-2 gap-x-10 gap-y-6">
                {vector && (
                  <ProbabilityRows title="Threat vector" note="Choice question"
                    rows={Object.entries(vector.probabilities).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ key: k, label: humanize(k), v, strong: k === vector.choice, color: k === vector.choice ? "bg-ink" : "bg-ink-3/50" }))} />
                )}
                {severity && (
                  <ProbabilityRows title={`Severity · ${severity.score.toFixed(2)} of 3`} note={`Escalates reviews at ≥ ${result.typesafeInternals.thresholds.severityBlock}`}
                    rows={Object.entries(severity.probabilities).map(([lvl, v]) => ({ key: lvl, label: `${lvl} · ${severity.legend?.[lvl]?.split(":")[0] ?? ""}`, v, strong: Number(lvl) === Math.round(severity.score), color: Number(lvl) >= result.typesafeInternals.thresholds.severityBlock ? "bg-rose-500" : "bg-emerald-500" }))} />
                )}
              </div>
            </div>
          )}

          {/* Inside Jev: only when the toggle is on */}
          {result && inside && (
            <InsideJev key={runId} result={result} ruleNames={Object.fromEntries(rules.map((r) => [r.id, r.name]))} />
          )}

          {/* Live wire: latest request/response on the wire, one side at a time */}
          {wireOn && <LiveWire entry={wire} />}

          {/* Batch results */}
          {batch && (
            <div className="card overflow-hidden">
              <div className="px-6 py-5 border-b border-line flex items-center justify-between gap-4">
                <div>
                  <div className="eyebrow mb-1">Batch run · live</div>
                  <h2 className="section-title">All presets</h2>
                </div>
                <div className="text-right">
                  <div className={`text-2xl font-semibold tabular-nums ${batchDone === batch.length && batchPassed === batch.length ? "text-emerald-300" : "text-ink"}`}>{batchPassed}/{batchDone}</div>
                  <div className="text-xs text-ink-3">{batchBusy ? "running…" : "passed"}</div>
                </div>
              </div>
              <div className="max-h-96 overflow-y-auto">
                <table className="w-full text-sm">
                  <thead className="text-xs text-ink-3 sticky top-0 bg-surface z-[1]">
                    <tr>
                      <th className="text-left px-6 py-2.5 font-medium">Preset</th>
                      <th className="text-left px-3 font-medium">Expected</th>
                      <th className="text-left px-3 font-medium">Verdict</th>
                      <th className="text-right px-3 font-medium">Own P(yes)</th>
                      <th className="text-right px-3 font-medium">ms</th>
                      <th className="px-6 font-medium"><span className="sr-only">Result</span></th>
                    </tr>
                  </thead>
                  <tbody>
                    {GROUPS.map((g) => ({ name: g as string, ids: rules.filter((r) => r.group === g).map((r) => `preset-${r.id}`) })).map(({ name, ids }) => {
                      const rows = ids.map((id) => batch.find((b) => b.id === id)).filter((b): b is BatchRow => !!b);
                      if (rows.length === 0) return null;
                      return (
                        <React.Fragment key={name}>
                          <tr className="border-t border-line bg-raised/60">
                            <td colSpan={6} className="px-6 py-2 text-xs font-semibold uppercase tracking-wider text-ink-3">{name} <span className="ml-1 normal-case tracking-normal font-mono">{rows.filter((b) => b.ok).length}/{rows.length}</span></td>
                          </tr>
                          {rows.map((b) => (
                            <tr key={b.id} className="border-t border-line/60 hover:bg-raised/40">
                              <td className="px-6 py-2.5 text-ink">{b.label}</td>
                              <td className="px-3 text-ink-3">{b.expected}</td>
                              <td className={`px-3 font-semibold text-xs tracking-wide ${b.decision === "BLOCK" ? "text-rose-300" : b.decision === "ALERT" ? "text-amber-300" : b.decision === "ALLOW" ? "text-emerald-300" : "text-ink-3"}`}>{b.decision ?? "…"}</td>
                              <td className="px-3 text-right font-mono tabular-nums">{b.own === undefined ? "" : b.own === null ? "—" : b.own.toFixed(2)}</td>
                              <td className="px-3 text-right font-mono tabular-nums text-ink-3">{b.ms ?? ""}</td>
                              <td className="px-6 text-right">{b.ok === undefined ? "" : b.ok ? <span className="text-emerald-400">✓</span> : <span className="text-rose-400">✗</span>}</td>
                            </tr>
                          ))}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Architecture: where a prompt goes, from start to decision — shown when Inside Jev is off */}
          {!inside && (
            <section className="card p-7">
              <div className="eyebrow mb-2">How it works</div>
              <h2 className="section-title">Architecture</h2>
              <p className="lead mt-1.5">Where a prompt goes, from the application to the decision.</p>
              <ol className="mt-7">
                {[
                  { title: "AI application", body: "A user writes a prompt." },
                  { title: "Policy server", body: "This demo. Receives the prompt and builds one yes/no question per guardrail." },
                  { title: "Jev", body: "TypeSafe API, POST /v1/systemone. Answers every question in one call." },
                  { title: "Policy code", body: `Compares each probability with ${TYPESAFE_THRESHOLDS.noulAction.toFixed(2)} (triggered) and ${TYPESAFE_THRESHOLDS.noulReview.toFixed(2)} (review), then applies the mode of each guardrail.` },
                  { title: "Decision", body: "Allow, Alert or Block." },
                ].map((step, i, all) => (
                  <li key={step.title} className="grid grid-cols-[2rem_minmax(0,1fr)] gap-x-4">
                    <div className="flex flex-col items-center">
                      <span className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold ring-1 ${step.title === "Jev" ? "bg-violet-500/15 text-violet-300 ring-violet-500/40" : "bg-raised text-ink-2 ring-line-strong"}`}>{i + 1}</span>
                      {i < all.length - 1 && <span className="flex-1 w-px bg-line-strong my-1" />}
                    </div>
                    <div className={i < all.length - 1 ? "pb-5" : ""}>
                      <div className="text-[15px] font-semibold text-ink pt-1">{step.title}</div>
                      <p className="text-[15px] leading-relaxed text-ink-2 mt-0.5">{step.body}</p>
                    </div>
                  </li>
                ))}
              </ol>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-7">
                <div className="rounded-xl bg-raised/60 border border-line p-4 text-[15px] leading-relaxed text-ink-2"><div className="text-xs font-semibold uppercase tracking-wider text-ink-3 mb-1">Sent to Jev</div>The prompt and {activeCount} guardrail questions, in a single request.</div>
                <div className="rounded-xl bg-raised/60 border border-line p-4 text-[15px] leading-relaxed text-ink-2"><div className="text-xs font-semibold uppercase tracking-wider text-ink-3 mb-1">Returned by Jev</div>One probability per question. Jev does not make the decision.</div>
              </div>
            </section>
          )}

          {/* What Jev lets you configure — shown here when Inside Jev is off */}
          {!inside && <JevConfig />}

          {/* Raw data */}
          {result && (
            <div className="flex flex-col gap-3">
              <Collapsible title="Request sent to POST /v1/systemone">
                <pre className="text-[13px] leading-relaxed font-mono text-ink-2 overflow-auto max-h-96 bg-canvas p-5 rounded-xl border border-line">{JSON.stringify({ model: result.typesafeInternals.requestPayload.model ?? "jev-latest", state: result.typesafeInternals.requestPayload.state, questions: result.typesafeInternals.requestPayload.questions }, null, 2)}</pre>
              </Collapsible>
              <Collapsible title="Raw answers from Jev">
                <pre className="text-[13px] leading-relaxed font-mono text-ink-2 overflow-auto max-h-96 bg-canvas p-5 rounded-xl border border-line">{JSON.stringify(result.typesafeInternals.rawAnswers, null, 2)}</pre>
              </Collapsible>
            </div>
          )}
        </section>

        {/* ── Guardrails with live probability bars ─────────── */}
        <section className="card overflow-hidden self-start xl:sticky xl:top-[104px] min-w-0">
          <div className="px-6 py-5 border-b border-line">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="eyebrow mb-1">Policy</div>
                <h2 className="section-title">Guardrails</h2>
              </div>
              <div className="flex gap-1.5">
                {(["Block", "Detect", "Ignore"] as RuleEnforcementMode[]).map((m) => (
                  <button key={m} type="button" onClick={() => applyRules(rules.map((r) => ({ ...r, mode: m })))} className="px-3 py-1.5 text-[13px] text-ink-2 border border-line-strong rounded-lg hover:bg-raised hover:text-ink cursor-pointer whitespace-nowrap">
                    All {MODE_LABEL[m]}
                  </button>
                ))}
              </div>
            </div>
            <p className="mt-2 text-sm leading-relaxed text-ink-3">
              {inside
                ? "Probability that the current prompt violates each guardrail, as returned by Jev."
                : <>Each bar is P(yes) from Jev for the current prompt. The tick marks the action threshold ({result?.typesafeInternals.thresholds.noulAction ?? TYPESAFE_THRESHOLDS.noulAction}); <span className="text-sky-300">blue</span> is the review band.</>}
            </p>
          </div>

          {inside ? (
            <div className="overflow-x-auto xl:max-h-[calc(100vh-260px)] xl:overflow-y-auto">
              <table className="w-full border-collapse text-[15px]">
                <thead className="sticky top-0 bg-surface z-[1] text-xs uppercase tracking-wider text-ink-3">
                  <tr>
                    <th className="px-6 py-3 font-semibold text-left w-[30%]">Guardrail</th>
                    <th className="px-3 py-3 font-semibold text-left">Question sent to Jev</th>
                    <th className="px-6 py-3 font-semibold text-right w-28">Probability</th>
                  </tr>
                </thead>
                <tbody>
                  {GROUPS.map((g) => (
                    <React.Fragment key={g}>
                      <tr className="border-t border-line bg-raised/60">
                        <td colSpan={3} className="px-6 py-2 text-xs font-semibold uppercase tracking-wider text-ink-3">{g}</td>
                      </tr>
                      {rules.filter((r) => r.group === g).map((rule) => {
                        const p = rule.mode === "Ignore" ? null : noulOf(rule.id);
                        const th = result?.typesafeInternals.thresholds;
                        const tone = p === null || !th ? "text-ink-3" : p >= th.noulAction ? "text-rose-300" : p >= th.noulReview ? "text-sky-300" : "text-ink-2";
                        return (
                          <tr key={rule.id} className="border-t border-line/60">
                            <td className={`px-6 py-3.5 align-top font-medium ${rule.mode === "Ignore" ? "text-ink-3" : "text-ink"}`}>{rule.name}</td>
                            <td className="px-3 py-3.5 align-top text-ink-2 leading-relaxed">{rule.typesafeQuestion.instructions}</td>
                            <td className={`px-6 py-3.5 align-top text-right font-mono text-lg tabular-nums ${tone}`}>{p === null ? "—" : `${Math.round(p * 100)}%`}</td>
                          </tr>
                        );
                      })}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
          <div className="xl:max-h-[calc(100vh-280px)] xl:overflow-y-auto">
            {GROUPS.map((g) => (
              <div key={g}>
                <div className="sticky top-0 z-[1] px-6 py-2 text-xs font-semibold uppercase tracking-wider text-ink-3 bg-raised/95 backdrop-blur border-y border-line flex justify-between">
                  <span>{g}</span><span className="font-mono normal-case">{rules.filter((r) => r.group === g).length}</span>
                </div>
                {rules.filter((r) => r.group === g).map((rule) => {
                  const hit = result?.triggeredRules.find((t) => t.ruleId === rule.id);
                  const p = rule.mode === "Ignore" ? null : noulOf(rule.id);
                  const rowTint = hit ? (hit.actionTaken === "Enforced (Blocked)" ? "bg-rose-500/[0.07] shadow-[inset_3px_0_0_rgb(244_63_94)]" : hit.actionTaken === "Flagged for Review" ? "bg-sky-500/[0.06] shadow-[inset_3px_0_0_rgb(56_189_248)]" : "bg-amber-400/[0.06] shadow-[inset_3px_0_0_rgb(251_191_36)]") : "";
                  return (
                    <div key={rule.id} className={`px-6 py-4 border-b border-line/60 ${rowTint}`}>
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                            <span className={`text-[15px] font-semibold leading-snug ${rule.mode === "Ignore" ? "text-ink-3" : "text-ink"}`}>{rule.name}</span>
                            {hit && <span className={`text-[11px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full ring-1 ${ACTION_TONE[hit.actionTaken].chip}`}>{ACTION_TONE[hit.actionTaken].label}{hit.escalatedBySeverity ? " ↑ sev" : ""}</span>}
                          </div>
                          <p className="mt-1 text-sm leading-relaxed text-ink-3">{rule.typesafeQuestion.instructions}</p>
                        </div>
                      </div>
                      <div className="mt-3 flex flex-wrap items-center gap-3">
                        <NoulBar p={p} thresholds={result?.typesafeInternals.thresholds} />
                        <button type="button" onClick={() => testRule(rule)} disabled={busy} className="px-2.5 py-1 text-[13px] font-medium rounded-lg text-emerald-300 ring-1 ring-emerald-500/40 hover:bg-emerald-500/10 cursor-pointer disabled:opacity-50 shrink-0">Test</button>
                        <button type="button" onClick={() => openEdit(rule)} className="px-2.5 py-1 text-[13px] font-medium rounded-lg text-ink-2 ring-1 ring-line-strong hover:text-ink hover:bg-raised cursor-pointer shrink-0">Edit</button>
                        <ModeToggle mode={rule.mode} onChange={(m) => applyRules(rules.map((r) => (r.id === rule.id ? { ...r, mode: m } : r)))} />
                      </div>
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
          )}
        </section>

      </main>

      {/* Edit modal */}
      {editing && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-20 p-4" onClick={() => setEditing(null)}>
          <form onSubmit={saveEdit} onClick={(e) => e.stopPropagation()} className="card bg-surface shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto p-7 flex flex-col gap-4">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="eyebrow mb-1">Edit guardrail · the question is the configuration</div>
                <h3 className="section-title">{editing.name}</h3>
              </div>
              <button type="button" onClick={() => setEditing(null)} aria-label="Close" className="p-1 rounded-md text-ink-3 hover:text-ink hover:bg-raised cursor-pointer"><X className="w-5 h-5" /></button>
            </div>
            {([
              ["ask", "Question (one yes/no)", 2],
              ["yes", "criteria.true: what counts as yes", 2],
              ["no", "criteria.false: what counts as no", 2],
              ["examples", "Examples of a yes (one per line)", 3],
              ["sample", "Test prompt", 2],
            ] as const).map(([k, label, rows]) => (
              <label key={k} className="text-sm font-medium text-ink-2 flex flex-col gap-1.5">
                {label}
                <textarea rows={rows} value={draft[k]} onChange={(e) => setDraft({ ...draft, [k]: e.target.value })} className="bg-canvas border border-line-strong rounded-lg px-3.5 py-2.5 text-[15px] font-normal leading-relaxed text-ink focus:outline-none focus:border-emerald-500" />
              </label>
            ))}
            <div className="flex justify-end gap-2 pt-2">
              <button type="button" onClick={() => setEditing(null)} className="btn px-4 py-2 text-sm border border-line-strong hover:bg-raised">Cancel</button>
              <button type="submit" className="btn px-4 py-2 text-sm bg-emerald-500 hover:bg-emerald-400 text-emerald-950">Save & re-evaluate</button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
