/**
 * Live verification against TypeSafe Jev through /api/evaluate.
 *   1. one-by-one : each rule is sent ALONE with its own sample prompt
 *   2. battery    : all 21 rules sent together for every preset (+4 negatives)
 * Usage: PORT=3100 bun scripts/run-presets.ts
 */
import {
  INITIAL_CONTROL_PLANE_RULES,
  NEGATIVE_PRESET_PROMPTS,
} from "../src/data/controlPlaneRules";
import { TYPESAFE_THRESHOLDS } from "../src/guardrails/typesafe";

const base = `http://localhost:${process.env.PORT ?? 3000}`;
const ACTION = TYPESAFE_THRESHOLDS.noulAction;

async function evaluate(prompt: string, rules: unknown) {
  const res = await fetch(`${base}/api/evaluate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ prompt, rules }),
  });
  const j = (await res.json()) as any;
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${j.error}`);
  return j;
}

let failures = 0;
let model = "?";

// 1) one-by-one ----------------------------------------------------------
const solo: Record<string, unknown>[] = [];
for (const r of INITIAL_CONTROL_PLANE_RULES) {
  const j = await evaluate(r.sampleViolationPrompt, [r]);
  model = j.typesafeInternals.model;
  const noul: number = j.typesafeInternals.rawAnswers[r.id]?.noul ?? 0;
  const ok = noul >= ACTION;
  if (!ok) failures++;
  solo.push({
    group: r.group,
    rule: r.id,
    noul: noul.toFixed(2),
    decision: j.effectiveVerdict.decision,
    ms: j.typesafeInternals.decisionsLatencyMs,
    ok: ok ? "PASS" : "FAIL",
  });
}
console.log("\n== 1) one-by-one: each rule sent alone with its own prompt ==");
console.table(solo);

// 2) full battery --------------------------------------------------------
const battery: Record<string, unknown>[] = [];
const cases = [
  ...INITIAL_CONTROL_PLANE_RULES.map((r) => ({ id: r.id, prompt: r.sampleViolationPrompt, ruleId: r.id as string | null })),
  ...NEGATIVE_PRESET_PROMPTS.map((p) => ({ id: p.id, prompt: p.prompt, ruleId: null as string | null })),
];
for (const c of cases) {
  const j = await evaluate(c.prompt, INITIAL_CONTROL_PLANE_RULES);
  const answers = j.typesafeInternals.rawAnswers as Record<string, any>;
  const own = c.ruleId ? (answers[c.ruleId]?.noul as number) : null;
  const others = Object.entries(answers)
    .filter(([k, a]) => a.type === "noul" && k !== c.ruleId && a.noul >= ACTION)
    .map(([k, a]) => `${k}=${a.noul.toFixed(2)}`);
  const flagged = j.effectiveVerdict.decision !== "allow";
  const ok = c.ruleId ? flagged && (own ?? 0) >= ACTION : !flagged;
  if (!ok) failures++;
  battery.push({
    preset: c.id.replace("preset-", ""),
    decision: j.effectiveVerdict.decision,
    ownNoul: own === null ? "-" : own.toFixed(2),
    alsoFired: others.join(", ") || "-",
    severity: j.typesafeInternals.severityScore,
    vector: answers.primary_threat_vector.choice,
    ms: j.typesafeInternals.decisionsLatencyMs,
    ok: ok ? "PASS" : "FAIL",
  });
}
console.log("\n== 2) full battery: all 21 rules on every preset + 4 negatives ==");
console.table(battery);
console.log(`model: ${model} | action threshold: ${ACTION} | failures: ${failures}`);
process.exit(failures ? 1 : 0);
