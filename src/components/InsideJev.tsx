import React from "react";
import { motion } from "motion/react";
import { ArrowRight, Braces, Cpu, GitBranch, ListChecks } from "lucide-react";
import JevConfig from "./JevConfig";

// ─── Shape of the parts of /api/evaluate this panel reads ─────────────────

type Band = "pass" | "review" | "action";

export interface InsideTriggeredRule {
  ruleId: string;
  ruleName: string;
  mode: "Block" | "Detect" | "Ignore";
  typesafeNoulProbability: number | null;
  band: Band;
  escalatedBySeverity: boolean;
  actionTaken: "Enforced (Blocked)" | "Alerted & Sanitized" | "Flagged for Review" | "Ignored (Bypassed)";
}

export interface InsideResult {
  effectiveVerdict: { decision: "allow" | "block" | "redact" };
  triggeredRules: InsideTriggeredRule[];
  typesafeInternals: {
    model: string;
    endpoint: string;
    decisionsLatencyMs: number;
    totalPipelineLatencyMs?: number;
    thresholds: { noulAction: number; noulReview: number; severityBlock: number };
    requestPayload: { state: unknown; questions: Record<string, unknown> };
    rawAnswers: Record<string, { type: string; noul?: number }>;
  };
}

const VERDICT = { allow: "ALLOW", redact: "ALERT", block: "BLOCK" } as const;
// Copied verbatim from server.ts (per-rule decision) and src/guardrails/typesafe.ts (bands).
// If that code changes, update this text: the panel claims it is the real code.
const POLICY_CODE = `// src/guardrails/typesafe.ts
if (p >= TYPESAFE_THRESHOLDS.noulAction) return "action";   // 0.70
if (p >= TYPESAFE_THRESHOLDS.noulReview) return "review";   // 0.35
return "pass";

// server.ts, for every guardrail
let band = bandForNoul(noulProb);
if (band === "review" && severityEscalates) {
  band = "action";
  escalatedBySeverity = true;
}
if (band === "pass") continue;

if (band === "review") {
  actionTaken = "Flagged for Review";
} else if (rule.mode === "Block") {
  actionTaken = "Enforced (Blocked)";
} else {
  actionTaken = "Alerted & Sanitized";
}`;

function FlowStep({ n, title, explain, last, children }: {
  n: number; title: string; explain: string; last?: boolean; children: React.ReactNode;
}) {
  return (
    <div className="grid grid-cols-[2.25rem_minmax(0,1fr)] gap-x-4">
      <div className="flex flex-col items-center">
        <div className="w-9 h-9 rounded-full bg-ink flex items-center justify-center font-display text-lg text-canvas">{n}</div>
        {!last && <div className="flex-1 w-px bg-line-strong my-1" />}
      </div>
      <div className={last ? "" : "pb-8"}>
        <div className="font-display text-xl font-medium text-ink pt-1">{title}</div>
        <p className="text-base text-ink-2 mt-1 mb-4 max-w-3xl leading-relaxed">{explain}</p>
        {children}
      </div>
    </div>
  );
}

const Code = ({ children }: { children: string }) => (
  <pre className="font-mono text-[15px] leading-relaxed whitespace-pre-wrap break-words rounded-[4px] border border-term-line bg-term p-5 text-term-ink">{children}</pre>
);

const SUMMARY_LABEL: Record<string, string> = { primary_threat_vector: "Threat vector", threat_severity_rubric: "Severity" };
const MODE_LABEL = { Block: "Enforce", Detect: "Alert", Ignore: "Ignore" } as const;
const ACTION_LABEL = {
  "Enforced (Blocked)": "request blocked",
  "Alerted & Sanitized": "request flagged",
  "Flagged for Review": "referred for review",
  "Ignored (Bypassed)": "ignored",
} as const;

// The four stages appear in order, so the sequence of the pipeline is visible.
const stage = (i: number) => ({
  initial: { opacity: 0, y: 8 },
  animate: { opacity: 1, y: 0 },
  transition: { delay: i * 0.35, duration: 0.35 },
});

function StageCard({ i, icon, title, side, children }: {
  i: number; icon: React.ReactNode; title: string; side: "jev" | "code"; children: React.ReactNode;
}) {
  return (
    <motion.div
      {...stage(i)}
      className={`flex-1 min-w-0 rounded-[4px] border p-5 ${side === "jev" ? "border-jev/30 bg-jev/[0.04]" : "border-ink/25 bg-ink/[0.03]"}`}
    >
      <div className="flex items-center gap-2 mb-3">
        <span className="text-xs font-mono font-semibold text-ink-3">0{i + 1}</span>
        {icon}
        <span className="text-base font-semibold text-ink">{title}</span>
      </div>
      <div className="text-[15px] leading-relaxed text-ink-2 space-y-1.5">{children}</div>
    </motion.div>
  );
}

const Arrow = ({ i }: { i: number }) => (
  <motion.div {...stage(i)} className="hidden 2xl:block self-center shrink-0 text-ink-3">
    <ArrowRight className="w-4 h-4" />
  </motion.div>
);

export default function InsideJev({ result, ruleNames }: { result: InsideResult; ruleNames: Record<string, string> }) {
  const ti = result.typesafeInternals;
  const action = ti.thresholds.noulAction;
  const review = ti.thresholds.noulReview;
  const guardrailCount = Object.values(ti.rawAnswers).filter((a) => a.type === "noul").length;
  const state = ti.requestPayload.state as { request?: { prompt?: string } };
  const promptLen = state.request?.prompt?.length ?? 0;
  const verdict = result.effectiveVerdict.decision;

  // Trace: two real spans measured by the server. Bars are proportional to time.
  const total = Math.max(ti.totalPipelineLatencyMs ?? ti.decisionsLatencyMs, ti.decisionsLatencyMs, 1);
  const jevStart = 0;
  const pct = (ms: number) => `${(ms / total) * 100}%`;

  // Inbound: guardrails that reached the review threshold, highest first; the rest are counted.
  const guardrailAnswers = Object.entries(ti.rawAnswers)
    .filter(([, a]) => a.type === "noul" && typeof a.noul === "number")
    .map(([id, a]) => ({ id, p: a.noul as number }))
    .sort((a, b) => b.p - a.p);
  const sent = ti.requestPayload.questions as Record<string, { instructions?: unknown }>;
  const questionText = (id: string): string => {
    const ins = sent[id]?.instructions;
    if (typeof ins === "string") return ins;
    if (ins && typeof ins === "object" && "question" in ins) return String((ins as { question: unknown }).question);
    return "";
  };
  const ruleNameOf = (id: string) => ruleNames[id] ?? id;
  // The two questions that are not guardrails: the threat vector (choice) and the severity (score).
  const summaryIds = Object.keys(sent).filter((id) => ti.rawAnswers[id]?.type !== "noul");
  const top = guardrailAnswers[0];
  const topSent = top ? (sent[top.id] as { type?: string; criteria?: { true?: string; false?: string } }) : undefined;
  const requestExcerpt = top
    ? `POST ${ti.endpoint}
{
  "model": "jev-latest",
  "state": {
    "request": { "prompt": ${JSON.stringify(state.request?.prompt ?? "")} }
  },
  "questions": {
    "${top.id}": {
      "type": "${topSent?.type ?? "noul"}",
      "question": ${JSON.stringify(questionText(top.id))},
      "criteria": {
        "true": ${JSON.stringify(topSent?.criteria?.true ?? "")},
        "false": ${JSON.stringify(topSent?.criteria?.false ?? "")}
      }
    },
    … ${Object.keys(sent).length - 1} more questions in the same request
  }
}`
    : "";
  const responseExcerpt = `{
  "model": "${ti.model}",
  "answers": {
${guardrailAnswers.slice(0, 3).map((g) => `    "${g.id}": { "type": "noul", "noul": ${g.p.toFixed(2)} }`).join(",\n")}
    … ${Object.keys(ti.rawAnswers).length - Math.min(3, guardrailAnswers.length)} more answers
  }
}`;

  const summaryAnswer = (id: string): string => {
    const a = ti.rawAnswers[id] as { type: string; choice?: string; score?: number; probabilities?: Record<string, number> };
    if (a?.type === "choice") return `${a.choice} (${Math.round((a.probabilities?.[a.choice ?? ""] ?? 0) * 100)}%)`;
    if (a?.type === "score") return `${a.score?.toFixed(2)} on a 0–3 scale`;
    return "—";
  };

  return (
    <div className="card p-7 space-y-10">
      <div className="max-w-3xl text-[1.0625rem] leading-relaxed text-ink-2">
        <div className="eyebrow mb-2">Inside Jev</div>
        <h2 className="section-title mb-3">How to read this panel</h2>
        <p>
          Jev does not make the decision. For each guardrail, Jev answers one yes/no question about the
          prompt and returns the probability that the answer is yes. The policy code then compares each
          probability with fixed thresholds and applies the mode configured for that guardrail: Enforce
          blocks the request, Alert lets it through with a notice.
        </p>
        <p className="mt-2 text-ink-3 text-[15px]">Every value below comes from the response to this request.</p>
      </div>

      {/* ── The pipeline, left to right ─────────────────────────────── */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <span className="text-base font-medium text-jev">Evaluation by Jev</span>
          <span className="text-base font-medium text-ink">Decision by policy code</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 2xl:flex items-stretch gap-3">
          <StageCard i={0} side="jev" title="Prompt" icon={<Braces className="w-3.5 h-3.5 text-jev" />}>
            <div><span className="font-display text-2xl text-ink">{promptLen}</span> characters</div>
            <div className="text-ink-3 pt-1">Submitted to the gateway</div>
          </StageCard>
          <Arrow i={1} />
          <StageCard i={1} side="jev" title="Guardrails" icon={<ListChecks className="w-3.5 h-3.5 text-jev" />}>
            <div><span className="font-display text-2xl text-ink">{guardrailCount}</span> guardrails</div>
            <div className="text-ink-3 pt-1">One yes/no question per guardrail</div>
          </StageCard>
          <Arrow i={2} />
          <StageCard i={2} side="jev" title="Jev" icon={<Cpu className="w-3.5 h-3.5 text-jev" />}>
            <div>All guardrails evaluated in a single call</div>
            <div className="text-ink-3 pt-1">Answers are returned as typed probabilities, not free text.</div>
          </StageCard>

          {/* The line between evaluation and decision */}
          <motion.div {...stage(3)} className="hidden 2xl:block self-stretch w-px border-l border-dashed border-line-strong mx-1" />

          <StageCard i={3} side="code" title="Policy" icon={<GitBranch className="w-3.5 h-3.5 text-ink" />}>
            <div>Probability ≥ {action.toFixed(2)} → <span className="text-block">guardrail triggered</span></div>
            <div>{review.toFixed(2)} to {action.toFixed(2)} → <span className="text-review">under review</span>; triggered only if the overall risk score is high</div>
            <div>Enforce: request blocked · Alert: request flagged</div>
            <div className="text-ink-3 pt-1">The most restrictive outcome applies</div>
          </StageCard>
        </div>
      </div>


      {/* ── Trace of this request (APM style) ────────────────────────── */}
      <motion.div {...stage(4)} className="space-y-4">
        <div className="flex items-baseline justify-between">
          <h3 className="font-display text-xl font-medium text-ink">Trace of this request</h3>
          <div className="text-[15px] font-mono text-ink-2">{total} ms total</div>
        </div>

        <div className="rounded-[4px] border border-line bg-canvas p-5 space-y-3 font-mono text-sm">
          {[
            { label: "Policy server", op: "POST /api/evaluate", start: 0, dur: total, color: "bg-ink", indent: false },
            { label: "Jev", op: `POST ${ti.endpoint.replace(/^https?:\/\//, "")}`, start: jevStart, dur: ti.decisionsLatencyMs, color: "bg-jev/80", indent: true },
          ].map((span) => (
            <div key={span.label} className="grid grid-cols-[minmax(0,22rem)_1fr_4.5rem] items-center gap-4">
              <div className={`truncate ${span.indent ? "pl-5 text-ink" : "text-ink"}`}>
                {span.indent && <span className="text-ink-3">└ </span>}
                {span.label} <span className="text-ink-3">{span.op}</span>
              </div>
              <div className="relative h-3 rounded bg-line">
                <motion.div
                  className={`absolute inset-y-0 rounded ${span.color}`}
                  style={{ left: pct(span.start) }}
                  initial={{ width: 0 }}
                  animate={{ width: pct(span.dur) }}
                  transition={{ delay: 1.8, duration: 0.6, ease: "easeOut" }}
                />
              </div>
              <div className="text-right text-ink">{span.dur} ms</div>
            </div>
          ))}
        </div>

        <div className="rounded-[4px] border border-line overflow-hidden">
          <div className="grid grid-cols-[minmax(0,3fr)_minmax(0,1fr)] text-base">
            <div className="px-4 py-2.5 bg-jev/10 text-ink border-r border-line">Outbound · sent to Jev</div>
            <div className="px-4 py-2.5 bg-jev/10 text-ink">Inbound · returned by Jev ({ti.model})</div>
          </div>
          <div className="max-h-[32rem] overflow-y-auto text-[15px]">
            <div className="grid grid-cols-[minmax(0,3fr)_minmax(0,1fr)] border-t border-line">
              <div className="px-4 py-3 border-r border-line">
                <div className="text-ink-3 mb-1">The prompt under evaluation ({promptLen} characters)</div>
                <div className="font-mono text-ink whitespace-pre-wrap break-words">{state.request?.prompt}</div>
              </div>
              <div className="px-4 py-3 text-ink-3">Read once by Jev for every question below</div>
            </div>
            {guardrailAnswers.map((g) => {
              const status = g.p >= action ? "triggered" : g.p >= review ? "under review" : "clear";
              return (
                <div key={g.id} className="grid grid-cols-[minmax(0,3fr)_minmax(0,1fr)] border-t border-line">
                  <div className="px-4 py-2.5 border-r border-line">
                    <span className="text-ink">{ruleNameOf(g.id)}</span>
                    <span className="text-ink-3"> · </span>
                    <span className="text-ink-2">{questionText(g.id)}</span>
                  </div>
                  <div className="px-4 py-2.5 flex items-baseline justify-between gap-3 font-mono">
                    <span className={g.p >= action ? "text-block" : g.p >= review ? "text-review" : "text-ink"}>{g.p.toFixed(2)}</span>
                    <span className={`font-sans ${g.p >= action ? "text-block" : g.p >= review ? "text-review" : "text-ink-3"}`}>{status}</span>
                  </div>
                </div>
              );
            })}
            {summaryIds.map((id) => (
              <div key={id} className="grid grid-cols-[minmax(0,3fr)_minmax(0,1fr)] border-t border-line bg-raised/50">
                <div className="px-4 py-2.5 border-r border-line">
                  <span className="text-ink">{SUMMARY_LABEL[id] ?? id}</span>
                  <span className="text-ink-3"> · </span>
                  <span className="text-ink-2">{questionText(id)}</span>
                </div>
                <div className="px-4 py-2.5 font-mono text-ink">{summaryAnswer(id)}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-[4px] border border-line bg-raised/50 p-5 text-[15px] leading-relaxed text-ink-2 max-w-3xl">
          <div className="font-semibold text-ink mb-1">How to read the trace</div>
          Each bar is a step of this request, measured by the server. Bar length is proportional to time.
          The Jev bar sits inside the policy server bar because the server waits for Jev before it decides.
          The difference between the two is the time spent preparing the questions and applying the policy.
        </div>
      </motion.div>

      {/* ── Request flow: what goes, what comes back, what decides, where it goes ── */}
      <motion.div {...stage(5)} className="pt-2">
        <h3 className="font-display text-xl font-medium text-ink mb-6">Request flow</h3>

        <FlowStep n={1} title="The prompt arrives" explain="The text a user sent to the AI application. Nothing has been checked yet.">
          <Code>{state.request?.prompt ?? ""}</Code>
        </FlowStep>

        <FlowStep n={2} title="Sent to Jev" explain="One HTTP request carries the prompt and every guardrail question. Shown here: the question that received the highest probability, exactly as it was sent.">
          <Code>{requestExcerpt}</Code>
        </FlowStep>

        <FlowStep n={3} title="Returned by Jev" explain="One probability per question, in a single response. Each answer is independent of the others. Shown here: the three highest.">
          <Code>{responseExcerpt}</Code>
        </FlowStep>

        <FlowStep n={4} last title="The policy code decides" explain="The decision is made here, in plain code with fixed thresholds, not inside Jev. Below the code: how it applied to this request.">
          <Code>{POLICY_CODE}</Code>
          <div className="mt-4 space-y-2.5">
            {result.triggeredRules.length === 0 && (
              <div className="text-[15px] font-mono text-ink-2">
                No guardrail reached the review threshold ({review.toFixed(2)}). <span className="text-allow">Request allowed.</span>
              </div>
            )}
            {result.triggeredRules.map((t) => (
              <div key={t.ruleId} className="flex flex-wrap items-center gap-2 text-[15px] font-mono">
                <span className="text-ink">{t.ruleName}</span>
                <span className="text-ink-3">→</span>
                <span>{t.typesafeNoulProbability?.toFixed(2)}</span>
                <span className="text-ink-3">→</span>
                {t.escalatedBySeverity ? (
                  <span className="text-alert">escalated by overall risk</span>
                ) : (
                  <span className={t.band === "action" ? "text-block" : "text-review"}>{t.band === "action" ? "triggered" : "under review"}</span>
                )}
                <span className="text-ink-3">→</span>
                <span className="text-ink-2">{MODE_LABEL[t.mode]} mode</span>
                <span className="text-ink-3">→</span>
                <span className={t.actionTaken === "Enforced (Blocked)" ? "text-block" : t.actionTaken === "Flagged for Review" ? "text-review" : "text-alert"}>
                  {ACTION_LABEL[t.actionTaken]}
                </span>
              </div>
            ))}
            <div className="pt-1 text-[15px] font-mono text-ink-2">
              Final decision, most restrictive outcome:{" "}
              <span className={verdict === "block" ? "text-block font-bold" : verdict === "redact" ? "text-alert font-bold" : "text-allow font-bold"}>
                {VERDICT[verdict]}
              </span>
            </div>
          </div>
        </FlowStep>

      </motion.div>

      {/* ── What Jev lets you configure (from docs.typesafe.ai) ───────── */}
      <motion.div {...stage(6)}>
        <JevConfig className="bg-raised/40" />
      </motion.div>
    </div>
  );
}
