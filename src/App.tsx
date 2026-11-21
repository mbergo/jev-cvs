import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
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
  NEGATIVE_PRESET_PROMPTS,
  type PresetPromptItem,
  type RuleEnforcementMode,
  type RuleGroup,
} from "./data/controlPlaneRules";
import InsideJev from "./components/InsideJev";
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
    | "Ignored (Bypassed)"
    | "Guardrail Error (Failed Closed)";
  /** Present when the first answer was uncertain and the rule was re-asked. NaN samples arrive as null. */
  retried?: { first: number; samples: (number | null)[] };
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
  guardrailErrors?: { ruleId: string; ruleName: string; first: number; samples: (number | null)[] }[];
  typesafeInternals: {
    endpoint: string;
    httpStatus?: number;
    model: string;
    thresholds: { noulAction: number; noulReview: number; severityBlock: number };
    severityScore: number;
    totalInputTokens: number | null;
    totalOutputTokens: number;
    decisionsLatencyMs: number;
    retryLatencyMs?: number;
    retries?: { ruleId: string; ruleName: string; first: number; samples: (number | null)[]; resolved: boolean }[];
    totalPipelineLatencyMs?: number;
    requestPayload: { state: unknown; questions: Record<string, unknown> };
    rawAnswers: Record<string, Answer>;
  };
}

const GROUPS: RuleGroup[] = ["PII", "Credentials & Secrets", "Confidential Data", "Injection & Execution", "Harmful Content"];

const GUARDRAIL_ERROR: TriggeredRule["actionTaken"] = "Guardrail Error (Failed Closed)";
const fmtP = (p: number | null | undefined) => (typeof p === "number" && Number.isFinite(p) ? p.toFixed(2) : "error");

const VERDICT_LABEL: Record<EvalResult["effectiveVerdict"]["decision"], string> = {
  allow: "ALLOW",
  redact: "ALERT",
  block: "BLOCK",
};

// ─── Small components ──────────────────────────────────────────────────────

function NoulBar({ p, thresholds }: { p: number | null; thresholds?: EvalResult["typesafeInternals"]["thresholds"] }) {
  const action = thresholds?.noulAction ?? 0.7;
  const review = thresholds?.noulReview ?? 0.35;
  const band: Band = p === null ? "pass" : p >= action ? "action" : p >= review ? "review" : "pass";
  const color = band === "action" ? "bg-rose-500" : band === "review" ? "bg-sky-400" : "bg-emerald-500";
  const text = band === "action" ? "text-rose-300" : band === "review" ? "text-sky-300" : "text-neutral-500";
  return (
    <div className="flex items-center gap-2 w-40 shrink-0">
      <div className="relative flex-1 h-2 bg-neutral-800 rounded-full overflow-hidden">
        {p !== null && <div className={`h-full ${color} transition-all duration-500`} style={{ width: `${Math.max(2, p * 100)}%` }} />}
        <div className="absolute top-0 bottom-0 w-px bg-neutral-500" style={{ left: `${action * 100}%` }} />
      </div>
      <span className={`font-mono text-sm tabular-nums w-10 text-right ${text}`}>{p === null ? "—" : p.toFixed(2)}</span>
    </div>
  );
}

function ModeToggle({ mode, onChange }: { mode: RuleEnforcementMode; onChange: (m: RuleEnforcementMode) => void }) {
  const opts: { m: RuleEnforcementMode; label: string; on: string }[] = [
    { m: "Block", label: "Enforce", on: "bg-rose-600 text-white" },
    { m: "Detect", label: "Alert", on: "bg-amber-500 text-black" },
    { m: "Ignore", label: "Ignore", on: "bg-neutral-600 text-white" },
  ];
  return (
    <div className="flex rounded border border-neutral-800 overflow-hidden shrink-0">
      {opts.map((o) => (
        <button key={o.m} type="button" onClick={() => onChange(o.m)}
          className={`px-2 py-1.5 text-[13px] font-medium cursor-pointer ${mode === o.m ? o.on : "bg-[#0B0D11] text-neutral-400 hover:text-white"}`}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

function Collapsible({ title, children, defaultOpen = false }: { title: string; children: React.ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-neutral-800 rounded-lg bg-[#111318]">
      <button type="button" onClick={() => setOpen(!open)} className="w-full flex items-center gap-2 px-4 py-2.5 text-sm font-semibold text-neutral-300 cursor-pointer">
        {open ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}{title}
      </button>
      {open && <div className="px-4 pb-4">{children}</div>}
    </div>
  );
}

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
  const [wireOn, setWireOn] = useState<boolean>(() => localStorage.getItem("liveWire") === "1");
  useEffect(() => { localStorage.setItem("liveWire", wireOn ? "1" : "0"); }, [wireOn]);
  const [wire, setWire] = useState<WireEntry | null>(null);
  const wireSeq = useRef(0);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<{ connected: boolean; model: string; error?: string } | null>(null);
  const [editing, setEditing] = useState<ControlPlaneRule | null>(null);
  const [draft, setDraft] = useState({ ask: "", yes: "", no: "", examples: "", sample: "" });

  // Batch run ("Run all 25")
  interface BatchRow { id: string; label: string; expected: "flag" | "allow"; decision?: string; own?: number | null; ms?: number; ok?: boolean }
  const [batch, setBatch] = useState<BatchRow[] | null>(null);
  const [batchBusy, setBatchBusy] = useState(false);

  const presets = useMemo<PresetPromptItem[]>(() => [...buildRulePresets(rules), ...NEGATIVE_PRESET_PROMPTS], [rules]);

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

  return (
    <div className="min-h-screen bg-[#0B0D11] text-neutral-100">
      {/* Header */}
      <header className="border-b border-neutral-800 px-6 py-4 flex items-center justify-between gap-8 sticky top-0 bg-[#0B0D11]/95 backdrop-blur z-10">
        <div className="flex items-center gap-3">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
          <div>
            <h1 className="text-base font-bold tracking-tight">Non-Autoregressive Guardrails for AI Gateways</h1>
            <p className="text-[13px] text-neutral-500">TypeSafe Jev · {rules.length} rules · one question per rule · one HTTP call · no regex</p>
          </div>
        </div>
        <div className="hidden lg:flex items-center gap-6 text-[13px] font-mono text-neutral-400 whitespace-nowrap">
          <span className={status?.connected ? "text-emerald-400" : "text-rose-400"}>● {status ? (status.connected ? `api.typesafe.ai · ${result?.typesafeInternals.model ?? status.model}` : `offline: ${status.error}`) : "connecting…"}</span>
          <span className="text-neutral-500">{counts.block} enforce · {counts.alert} alert · {counts.ignore} ignore</span>
          <button type="button" onClick={() => applyRules(INITIAL_CONTROL_PLANE_RULES)} className="flex items-center gap-1 text-neutral-400 hover:text-white cursor-pointer"><RotateCcw className="w-3 h-3" />reset</button>
        </div>
      </header>

      <main className={`p-6 grid grid-cols-1 gap-6 mx-auto ${inside ? "w-full px-8 xl:grid-cols-2" : "xl:grid-cols-[1.4fr_1fr] max-w-[1700px]"}`}>
        {/* ── Prompt, verdict, data ──────────────────────────── */}
        <section className="flex flex-col gap-6">
          {/* Prompt */}
          <div className="border border-neutral-800 rounded-lg bg-[#111318] p-6 flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold ">Prompt entering the gateway</h2>
              <select value={selectedPreset} onChange={(e) => { const p = presets.find((x) => x.id === e.target.value); if (p) pickPreset(p); }} className="bg-[#0B0D11] border border-neutral-700 rounded text-sm px-2 py-1.5 max-w-[260px]">
                <option value="custom">— custom —</option>
                {GROUPS.map((g) => (
                  <optgroup key={g} label={g}>
                    {rules.filter((r) => r.group === g).map((r) => <option key={r.id} value={`preset-${r.id}`}>{r.name}</option>)}
                  </optgroup>
                ))}
                <optgroup label="Safe / negative">
                  {NEGATIVE_PRESET_PROMPTS.map((p) => <option key={p.id} value={p.id}>{p.label}</option>)}
                </optgroup>
              </select>
            </div>
            <textarea value={prompt} onChange={(e) => { setPrompt(e.target.value); setSelectedPreset("custom"); }} rows={4} className="w-full bg-[#0B0D11] border border-neutral-700 rounded p-4 font-mono text-base resize-y focus:outline-none focus:border-emerald-600" placeholder="Paste any prompt…" />
            <div className="flex items-center gap-2">
              <button type="button" onClick={() => run()} disabled={busy || !prompt.trim()} className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-base font-semibold rounded cursor-pointer">
                <Play className="w-4 h-4" />{busy ? "Evaluating…" : "Evaluate"}
              </button>
              <button type="button" onClick={runAll} disabled={batchBusy} className="flex items-center gap-2 px-3 py-2 border border-neutral-700 hover:bg-neutral-800 disabled:opacity-50 text-base rounded cursor-pointer">
                <Zap className="w-4 h-4 text-amber-400" />{batchBusy ? `Running ${batchDone}/${rules.length}…` : `Run all ${rules.length} presets`}
              </button>
              <button type="button" role="switch" aria-checked={inside} onClick={() => setInside((v) => !v)} className="ml-auto flex items-center gap-2 text-sm text-neutral-300 cursor-pointer select-none">
                <span className={`relative w-8 h-4 rounded-full transition-colors ${inside ? "bg-violet-600" : "bg-neutral-700"}`}>
                  <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${inside ? "left-4" : "left-0.5"}`} />
                </span>
                Inside Jev
              </button>
              <button type="button" role="switch" aria-checked={wireOn} onClick={() => setWireOn((v) => !v)} className="flex items-center gap-2 text-sm text-neutral-300 cursor-pointer select-none">
                <span className={`relative w-8 h-4 rounded-full transition-colors ${wireOn ? "bg-emerald-600" : "bg-neutral-700"}`}>
                  <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${wireOn ? "left-4" : "left-0.5"}`} />
                </span>
                Live wire
              </button>
              {error && <span className="text-sm text-rose-400 truncate">{error}</span>}
            </div>
          </div>

          {/* Verdict */}
          {result && (
            <div className={`border rounded-lg p-6 ${verdict === "block" ? "border-rose-700 bg-rose-950/30" : verdict === "redact" ? "border-amber-700 bg-amber-950/25" : "border-emerald-700 bg-emerald-950/25"}`}>
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-center gap-3">
                  {verdict === "block" ? <ShieldAlert className="w-8 h-8 text-rose-400" /> : verdict === "redact" ? <AlertTriangle className="w-8 h-8 text-amber-400" /> : <ShieldCheck className="w-8 h-8 text-emerald-400" />}
                  <div>
                    <div className="text-3xl font-bold tracking-tight">{VERDICT_LABEL[verdict!]}</div>
                    <div className="text-sm text-neutral-300">
                      {verdict === "block" && (result.guardrailErrors?.length
                        ? `Failed closed — guardrail error on "${result.guardrailErrors[0].ruleName}": Jev answered ${fmtP(result.guardrailErrors[0].first)} in the battery and ${result.guardrailErrors[0].samples.map(fmtP).join(" / ")} on retry — no confident, agreeing answer. Not forwarded to the LLM.`
                        : "Request halted — not forwarded to the LLM.")}
                      {verdict === "redact" && "Forwarded with notice — rules in Alert mode fired."}
                      {verdict === "allow" && "Clean — forwarded to the LLM."}
                    </div>
                  </div>
                </div>
                <div className="text-right text-[13px] font-mono text-neutral-400">
                  <div>{result.typesafeInternals.model}</div>
                  <div>{result.typesafeInternals.decisionsLatencyMs} ms for {Object.keys(result.typesafeInternals.requestPayload.questions).length} questions</div>
                  {(result.typesafeInternals.retryLatencyMs ?? 0) > 0 && (
                    <div className="text-amber-300">+{result.typesafeInternals.retryLatencyMs} ms · {result.typesafeInternals.retries?.length} uncertain rule{(result.typesafeInternals.retries?.length ?? 0) === 1 ? "" : "s"} re-asked ×2</div>
                  )}
                </div>
              </div>
              {result.triggeredRules.length > 0 && (
                <div className="mt-3 flex flex-wrap gap-2">
                  {result.triggeredRules.map((t) => (
                    <span key={t.ruleId} className={`text-[13px] font-mono px-2 py-0.5 rounded border ${t.actionTaken === GUARDRAIL_ERROR ? "border-rose-500 bg-rose-900/40 text-rose-200" : t.actionTaken === "Enforced (Blocked)" ? "border-rose-700 text-rose-300" : t.actionTaken === "Flagged for Review" ? "border-sky-700 text-sky-300" : "border-amber-700 text-amber-300"}`}>
                      {t.actionTaken === GUARDRAIL_ERROR ? "ERROR " : ""}{t.ruleName} {t.retried ? `${fmtP(t.retried.first)} ↻ ${t.retried.samples.map(fmtP).join("/")}` : t.typesafeNoulProbability?.toFixed(2)}{t.escalatedBySeverity ? " ↑sev" : ""}
                    </span>
                  ))}
                </div>
              )}

              {/* Vector + severity */}
              <div className="mt-6 grid grid-cols-2 gap-10">
                <div>
                  <div className="text-xs text-neutral-500 mb-1.5">Threat vector (choice)</div>
                  {vector && Object.entries(vector.probabilities).sort((a, b) => b[1] - a[1]).map(([k, v]) => (
                    <div key={k} className="flex items-center gap-2 text-[13px] font-mono mb-1.5">
                      <span className={`w-52 truncate ${k === vector.choice ? "text-white" : "text-neutral-500"}`}>{k}</span>
                      <div className="flex-1 h-2 bg-neutral-800 rounded"><div className={`h-full rounded ${k === vector.choice ? "bg-white" : "bg-neutral-600"}`} style={{ width: `${v * 100}%` }} /></div>
                      <span className="w-10 text-right">{(v * 100).toFixed(0)}%</span>
                    </div>
                  ))}
                </div>
                <div>
                  <div className="text-xs text-neutral-500 mb-1.5">Severity (score 0–3) · {severity?.score.toFixed(2)} · escalates reviews at ≥ {result.typesafeInternals.thresholds.severityBlock}</div>
                  {severity && Object.entries(severity.probabilities).map(([lvl, v]) => (
                    <div key={lvl} className="flex items-center gap-2 text-[13px] font-mono mb-1.5">
                      <span className="w-52 truncate text-neutral-400">{lvl} · {severity.legend?.[lvl]?.split(":")[0]}</span>
                      <div className="flex-1 h-2 bg-neutral-800 rounded"><div className={`h-full rounded ${Number(lvl) >= result.typesafeInternals.thresholds.severityBlock ? "bg-rose-500" : "bg-emerald-500"}`} style={{ width: `${v * 100}%` }} /></div>
                      <span className="w-10 text-right">{(v * 100).toFixed(0)}%</span>
                    </div>
                  ))}
                </div>
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
            <div className="border border-neutral-800 rounded-lg bg-[#111318] overflow-hidden">
              <div className="px-4 py-2.5 border-b border-neutral-800 flex items-center justify-between">
                <h2 className="text-sm font-semibold ">All presets · live</h2>
                <span className={`text-sm font-mono ${batchDone === batch.length && batchPassed === batch.length ? "text-emerald-400" : "text-neutral-300"}`}>{batchPassed}/{batchDone} pass{batchBusy ? "…" : ""}</span>
              </div>
              <div className="max-h-72 overflow-y-auto">
                <table className="w-full text-[13px] font-mono">
                  <thead className="text-neutral-500 sticky top-0 bg-[#111318]"><tr><th className="text-left px-4 py-1.5 font-normal">preset</th><th className="text-left px-2 font-normal">expect</th><th className="text-left px-2 font-normal">verdict</th><th className="text-right px-2 font-normal">own noul</th><th className="text-right px-2 font-normal">ms</th><th className="px-4 font-normal"></th></tr></thead>
                  <tbody>
                    {[...GROUPS.map((g) => ({ name: g as string, ids: rules.filter((r) => r.group === g).map((r) => `preset-${r.id}`) }))].map(({ name, ids }) => {
                      const rows = ids.map((id) => batch.find((b) => b.id === id)).filter((b): b is BatchRow => !!b);
                      if (rows.length === 0) return null;
                      return (
                        <React.Fragment key={name}>
                          <tr className="border-t border-neutral-700 bg-neutral-900/60">
                            <td colSpan={6} className="px-4 py-1.5 text-neutral-300 font-semibold">{name} · {rows.filter((b) => b.ok).length}/{rows.length}</td>
                          </tr>
                          {rows.map((b) => (
                            <tr key={b.id} className="border-t border-neutral-800/50">
                              <td className="px-4 py-1.5 truncate max-w-[220px]">{b.label}</td>
                              <td className="px-2 text-neutral-500">{b.expected}</td>
                              <td className={`px-2 ${b.decision === "BLOCK" ? "text-rose-300" : b.decision === "ALERT" ? "text-amber-300" : b.decision === "ALLOW" ? "text-emerald-300" : "text-neutral-500"}`}>{b.decision ?? "…"}</td>
                              <td className="px-2 text-right">{b.own === undefined ? "" : b.own === null ? "—" : b.own.toFixed(2)}</td>
                              <td className="px-2 text-right text-neutral-400">{b.ms ?? ""}</td>
                              <td className="px-4 text-right">{b.ok === undefined ? "" : b.ok ? <span className="text-emerald-400">✓</span> : <span className="text-rose-400">✗</span>}</td>
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
            <div className="border border-neutral-700 rounded-md bg-neutral-900/60 p-5 text-base text-neutral-300">
              <div className="font-medium text-white mb-1">Architecture</div>
              <p className="text-sm text-neutral-400 mb-4">Where a prompt goes, from the application to the decision.</p>
              <div className="flex items-stretch gap-2">
                {[
                  { title: "AI application", body: "A user writes a prompt." },
                  { title: "Policy server", body: "This demo. Receives the prompt and builds one yes/no question per guardrail." },
                  { title: "Jev", body: "TypeSafe API, POST /v1/systemone. Answers every question in one call." },
                  { title: "Policy code", body: `Compares each probability with ${TYPESAFE_THRESHOLDS.noulAction.toFixed(2)} (triggered) and ${TYPESAFE_THRESHOLDS.noulReview.toFixed(2)} (review), then applies the mode of each guardrail.` },
                  { title: "Decision", body: "Allow, Alert or Block." },
                ].map((step, i, all) => (
                  <React.Fragment key={step.title}>
                    <div className="flex-1 min-w-0 rounded-md border border-neutral-700 bg-[#0B0D11] p-3">
                      <div className="text-sm text-white mb-1">{step.title}</div>
                      <div className="text-sm text-neutral-400 leading-relaxed">{step.body}</div>
                    </div>
                    {i < all.length - 1 && <ArrowRight className="w-4 h-4 self-center shrink-0 text-neutral-500" />}
                  </React.Fragment>
                ))}
              </div>
              <div className="grid grid-cols-2 gap-4 mt-4 text-sm text-neutral-400">
                <div><span className="text-neutral-200">Sent to Jev:</span> the prompt and {rules.filter((r) => r.mode !== "Ignore").length} guardrail questions, in a single request.</div>
                <div><span className="text-neutral-200">Returned by Jev:</span> one probability per question. Jev does not make the decision.</div>
              </div>
            </div>
          )}

          {/* What Jev lets you configure — shown here when Inside Jev is off */}
          {!inside && (
          <div className="border border-neutral-700 rounded-md bg-neutral-900/60 p-5 text-base leading-relaxed text-neutral-300">
            <div className="font-medium text-white mb-3">What can be configured in Jev</div>
            <div className="grid grid-cols-1 2xl:grid-cols-2 gap-x-10 gap-y-4">
              <div>
                <div className="text-neutral-200 mb-1">Per question</div>
                <ul className="list-disc pl-5 space-y-1 text-neutral-400">
                  <li><span className="text-neutral-300">Type:</span> Noul (yes/no, returns a probability), Choice (one of several options), Score (a position on a scale you describe), Box (a location in an image; Jev 1.14 only).</li>
                  <li><span className="text-neutral-300">Instructions:</span> the question, as plain text or as structured fields.</li>
                  <li><span className="text-neutral-300">Criteria:</span> what yes and no mean (Noul), the options (Choice), or the levels (Score).</li>
                </ul>
              </div>
              <div>
                <div className="text-neutral-200 mb-1">Per request</div>
                <ul className="list-disc pl-5 space-y-1 text-neutral-400">
                  <li><span className="text-neutral-300">State:</span> what Jev reads: text, JSON, or PNG and JPEG images.</li>
                  <li><span className="text-neutral-300">Model:</span> jev-latest, jev-preview, or a fixed version such as jev-1.14.0.</li>
                  <li><span className="text-neutral-300">Long context:</span> an optional header raises the limit to 262,000 tokens (default 64,000 per request and 32,000 per question). It is slower and less accurate.</li>
                </ul>
              </div>
              <div>
                <div className="text-neutral-200 mb-1">Per account</div>
                <ul className="list-disc pl-5 space-y-1 text-neutral-400">
                  <li>Rate limits, set in the TypeSafe console.</li>
                </ul>
              </div>
              <div>
                <div className="text-neutral-200 mb-1">Not configurable</div>
                <ul className="list-disc pl-5 space-y-1 text-neutral-400">
                  <li>The model is not trained on customer data: no fine-tuning and no LoRA. Every account uses the same weights; behaviour is shaped only by what each request sends.</li>
                  <li>Thresholds do not exist in Jev. Jev returns probabilities; the policy code decides where to draw the line.</li>
                </ul>
              </div>
            </div>
            <div className="mt-4 text-sm text-neutral-500">Source: docs.typesafe.ai (Models and Primitives pages).</div>
          </div>
          )}

          {/* Raw data */}
          {result && (
            <>
              <Collapsible title="Request sent to POST /v1/systemone">
                <pre className="text-[13px] font-mono text-neutral-300 overflow-auto max-h-80 bg-[#0B0D11] p-4 rounded">{JSON.stringify({ model: "jev-latest", state: result.typesafeInternals.requestPayload.state, questions: result.typesafeInternals.requestPayload.questions }, null, 2)}</pre>
              </Collapsible>
              <Collapsible title="Raw answers from Jev">
                <pre className="text-[13px] font-mono text-neutral-300 overflow-auto max-h-80 bg-[#0B0D11] p-4 rounded">{JSON.stringify(result.typesafeInternals.rawAnswers, null, 2)}</pre>
              </Collapsible>
            </>
          )}
        </section>
        {/* ── Rules with live noul bars ───────────────────────── */}
        <section className="border border-neutral-800 rounded-lg bg-[#111318] overflow-hidden">
          <div className="px-4 py-3 border-b border-neutral-800 flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold ">Guardrails</h2>
              <p className="text-[13px] text-neutral-500">{inside ? "Probability that the current prompt violates each guardrail, as returned by Jev." : `Bar = P(yes) from Jev for the current prompt · tick = action threshold ${result?.typesafeInternals.thresholds.noulAction ?? 0.7} · blue = review band`}</p>
            </div>
            <div className="flex gap-2">
              {(["Block", "Detect", "Ignore"] as RuleEnforcementMode[]).map((m) => (
                <button key={m} type="button" onClick={() => applyRules(rules.map((r) => ({ ...r, mode: m })))} className="px-2 py-1.5 text-[13px] border border-neutral-700 rounded hover:bg-neutral-800 cursor-pointer">
                  All {m === "Block" ? "Enforce" : m === "Detect" ? "Alert" : "Ignore"}
                </button>
              ))}
            </div>
          </div>

          {inside ? (
            <div className="p-4 xl:max-h-[calc(100vh-180px)] xl:overflow-y-auto">
              <table className="w-full border-collapse text-[15px]">
                <thead>
                  <tr>
                    <th className="border border-neutral-600 px-4 py-3 font-medium text-neutral-200 text-center w-56">Guardrail</th>
                    <th className="border border-neutral-600 px-4 py-3 font-medium text-neutral-200 text-center">Question sent to Jev</th>
                    <th className="border border-neutral-600 px-4 py-3 font-medium text-neutral-200 text-center w-32">Probability</th>
                  </tr>
                </thead>
                <tbody>
                  {GROUPS.map((g) => (
                    <React.Fragment key={g}>
                      <tr>
                        <td colSpan={3} className="border border-neutral-600 px-4 py-2 text-sm font-semibold text-neutral-400 bg-[#0B0D11]">{g}</td>
                      </tr>
                      {rules.filter((r) => r.group === g).map((rule) => {
                        const p = rule.mode === "Ignore" ? null : noulOf(rule.id);
                        const th = result?.typesafeInternals.thresholds;
                        const tone = p === null || !th ? "text-neutral-500" : p >= th.noulAction ? "text-rose-300" : p >= th.noulReview ? "text-sky-300" : "text-neutral-300";
                        return (
                          <tr key={rule.id}>
                            <td className={`border border-neutral-600 px-4 py-3 align-top ${rule.mode === "Ignore" ? "text-neutral-500" : "text-neutral-100"}`}>{rule.name}</td>
                            <td className="border border-neutral-600 px-4 py-3 align-top text-neutral-300 leading-relaxed">{rule.typesafeQuestion.instructions}</td>
                            <td className={`border border-neutral-600 px-4 py-3 align-top text-right font-mono text-lg ${tone}`}>{p === null ? "—" : `${Math.round(p * 100)}%`}</td>
                          </tr>
                        );
                      })}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
          <div className="xl:max-h-[calc(100vh-180px)] xl:overflow-y-auto">
            {GROUPS.map((g) => (
              <div key={g}>
                <div className="px-4 py-1.5 text-xs font-semibold text-neutral-500 bg-[#0B0D11] border-y border-neutral-800/70">{g} · {rules.filter((r) => r.group === g).length}</div>
                {rules.filter((r) => r.group === g).map((rule) => {
                  const hit = result?.triggeredRules.find((t) => t.ruleId === rule.id);
                  const p = rule.mode === "Ignore" ? null : noulOf(rule.id);
                  return (
                    <div key={rule.id} className={`px-4 py-2 flex items-center gap-3 border-b border-neutral-800/50 ${hit ? (hit.actionTaken === GUARDRAIL_ERROR ? "bg-rose-950/40" : hit.actionTaken === "Enforced (Blocked)" ? "bg-rose-950/25" : hit.actionTaken === "Flagged for Review" ? "bg-sky-950/20" : "bg-amber-950/20") : ""}`}>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className={`text-base font-medium truncate ${rule.mode === "Ignore" ? "text-neutral-500" : ""}`}>{rule.name}</span>
                          {hit && <span className={`text-xs font-mono px-1.5 py-0.5 rounded ${hit.actionTaken === GUARDRAIL_ERROR ? "bg-rose-600/50 text-rose-100" : hit.actionTaken === "Enforced (Blocked)" ? "bg-rose-600/30 text-rose-300" : hit.actionTaken === "Flagged for Review" ? "bg-sky-600/30 text-sky-300" : "bg-amber-600/30 text-amber-300"}`}>{hit.actionTaken === GUARDRAIL_ERROR ? "ERROR · failed closed" : hit.actionTaken === "Enforced (Blocked)" ? "BLOCKED" : hit.actionTaken === "Flagged for Review" ? "REVIEW" : "ALERT"}{hit.escalatedBySeverity ? " ↑sev" : ""}</span>}
                          {hit?.retried && hit.actionTaken !== GUARDRAIL_ERROR && <span className="text-xs font-mono text-neutral-500" title="re-asked: battery ↻ retries">{fmtP(hit.retried.first)} ↻ {hit.retried.samples.map(fmtP).join("/")}</span>}
                        </div>
                        <p className="text-[13px] text-neutral-500 truncate" title={rule.typesafeQuestion.instructions}>{rule.typesafeQuestion.instructions}</p>
                      </div>
                      <NoulBar p={p} thresholds={result?.typesafeInternals.thresholds} />
                      <button type="button" onClick={() => testRule(rule)} disabled={busy} className="px-2 py-1.5 text-[13px] font-medium border border-emerald-700 text-emerald-300 rounded hover:bg-emerald-900/40 cursor-pointer disabled:opacity-50 shrink-0">Test</button>
                      <button type="button" onClick={() => openEdit(rule)} className="text-[13px] text-neutral-400 hover:text-white underline cursor-pointer shrink-0">Edit</button>
                      <ModeToggle mode={rule.mode} onChange={(m) => applyRules(rules.map((r) => (r.id === rule.id ? { ...r, mode: m } : r)))} />
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
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-20 p-4" onClick={() => setEditing(null)}>
          <form onSubmit={saveEdit} onClick={(e) => e.stopPropagation()} className="bg-[#111318] border border-neutral-700 rounded-lg w-full max-w-2xl p-5 flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold">{editing.name} — the question is the configuration</h3>
              <button type="button" onClick={() => setEditing(null)} className="text-neutral-400 hover:text-white cursor-pointer"><X className="w-4 h-4" /></button>
            </div>
            {([
              ["ask", "Question (one yes/no)", 2],
              ["yes", "criteria.true — what counts as yes", 2],
              ["no", "criteria.false — what counts as no", 2],
              ["examples", "Examples of a yes (one per line)", 3],
              ["sample", "Test prompt", 2],
            ] as const).map(([k, label, rows]) => (
              <label key={k} className="text-[13px] text-neutral-400 flex flex-col gap-1">
                {label}
                <textarea rows={rows} value={draft[k]} onChange={(e) => setDraft({ ...draft, [k]: e.target.value })} className="bg-[#0B0D11] border border-neutral-700 rounded p-2 font-mono text-sm text-neutral-100 focus:outline-none focus:border-emerald-600" />
              </label>
            ))}
            <div className="flex justify-end gap-2 pt-1">
              <button type="button" onClick={() => setEditing(null)} className="px-3 py-1.5 text-sm border border-neutral-700 rounded cursor-pointer">Cancel</button>
              <button type="submit" className="px-3 py-1.5 text-sm bg-emerald-600 hover:bg-emerald-500 rounded font-semibold cursor-pointer">Save & re-evaluate</button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
