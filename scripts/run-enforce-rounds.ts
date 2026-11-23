/**
 * Enforce-mode calibration, one rule at a time.
 *
 * All rules stay loaded. For each rule in turn it is switched to Block and the
 * previously blocked rule is reverted to its original mode, so exactly one rule
 * is enforcing per request. Repeated for N rounds.
 *
 * A rule passes when, in every round:
 *   - its noul is at or above the action threshold,
 *   - the gateway verdict is "block",
 *   - and the rule that caused the block is the rule under test.
 *
 * Usage: PORT=3100 ROUNDS=3 bun scripts/run-enforce-rounds.ts
 */
import { INITIAL_CONTROL_PLANE_RULES } from "../src/data/controlPlaneRules";
import { TYPESAFE_THRESHOLDS } from "../src/guardrails/typesafe";

const base = `http://localhost:${process.env.PORT ?? 3000}`;
const ROUNDS = Number(process.env.ROUNDS ?? 3);
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

// Mutable copy of the control plane; exactly one rule is "Block" at any moment.
const plane = INITIAL_CONTROL_PLANE_RULES.map((r) => ({ ...r }));
const originalMode = new Map(plane.map((r) => [r.id, r.mode]));
// Start from a clean slate: nothing enforcing until a rule is put under test.
for (const r of plane) if (r.mode === "Block") r.mode = "Detect";

const rows: Record<string, unknown>[] = [];
let failures = 0;
let model = "?";
let previouslyBlocked: string | null = null;

for (const target of plane) {
  // unblock the previous one, block this one
  if (previouslyBlocked) {
    const prev = plane.find((r) => r.id === previouslyBlocked)!;
    // Baseline is Detect: a rule that ships as Block (malicious_url_access) would
    // otherwise keep enforcing and make two rules block at once.
    prev.mode = originalMode.get(prev.id) === "Ignore" ? "Ignore" : "Detect";
  }
  target.mode = "Block";
  previouslyBlocked = target.id;

  const blockingNow = plane.filter((r) => r.mode === "Block").map((r) => r.id);
  if (blockingNow.length !== 1 || blockingNow[0] !== target.id) {
    throw new Error(`expected exactly one blocking rule, got ${blockingNow.join(",")}`);
  }

  const nouls: number[] = [];
  let allBlocked = true;
  let culpritOk = true;

  for (let i = 0; i < ROUNDS; i++) {
    const j = await evaluate(target.sampleViolationPrompt, plane);
    model = j.typesafeInternals.model;
    nouls.push(j.typesafeInternals.rawAnswers[target.id]?.noul ?? 0);
    if (j.effectiveVerdict.decision !== "block") allBlocked = false;
    const culprit = (j.triggeredRules ?? []).find(
      (t: any) => t.actionTaken === "Enforced (Blocked)"
    );
    if (!culprit || culprit.ruleId !== target.id) culpritOk = false;
  }

  const min = Math.min(...nouls);
  const ok = min >= ACTION && allBlocked && culpritOk;
  if (!ok) failures++;

  rows.push({
    group: target.group,
    rule: target.id,
    blocking: blockingNow[0],
    r1: nouls[0].toFixed(2),
    r2: (nouls[1] ?? NaN).toFixed(2),
    r3: (nouls[2] ?? NaN).toFixed(2),
    min: min.toFixed(2),
    blocked: allBlocked ? "yes" : "NO",
    culprit: culpritOk ? "self" : "OTHER",
    ok: ok ? "PASS" : "FAIL",
  });
}

// restore
const last = plane.find((r) => r.id === previouslyBlocked)!;
last.mode = originalMode.get(last.id)!;

console.log(`\n== enforce: one rule in Block at a time, all ${plane.length} loaded, ${ROUNDS} rounds ==`);
console.table(rows);
console.log(`model: ${model} | threshold: ${ACTION} | rules: ${rows.length} | failures: ${failures}`);
process.exit(failures ? 1 : 0);
