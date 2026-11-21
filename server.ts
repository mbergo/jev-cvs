import "dotenv/config";
import express from "express";
import http from "http";
import path from "path";
import { fileURLToPath } from "url";
import { createServer as createViteServer } from "vite";
import {
  ALL_PURE_DETECTORS,
  calculateShannonEntropy,
  maskMatch,
  resolveFindingSpan,
  sanitizeWithFindings,
} from "./src/guardrails/detectors";
import {
  evaluatePrompt,
  formatVerdictAuditLog,
} from "./src/guardrails/evaluator";
import type {
  Finding,
  GuardrailCategory,
  GuardrailVerdict,
} from "./src/guardrails/types";
import {
  buildGuardrailPolicyFromControlPlane,
  type ControlPlaneRule,
  INITIAL_CONTROL_PLANE_RULES,
} from "./src/data/controlPlaneRules";
import { GUARDRAIL_TEST_FIXTURES } from "./src/guardrails/evaluator.test";
import {
  bandForNoul,
  buildTypeSafeQuestions,
  buildTypeSafeState,
  type NoulBand,
  SHARED_QUESTION_IDS,
  TYPESAFE_THRESHOLDS,
} from "./src/guardrails/typesafe";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT ?? 3000);
const TYPESAFE_API_BASE = "https://api.typesafe.ai/v1";
const TYPESAFE_MODEL = process.env.TYPESAFE_MODEL?.trim() || "jev-latest";


interface TypeSafeSystemOneResponse {
  model?: string;
  answers?: Record<
    string,
    | {
        type: "noul";
        noul: number; // P(yes) in [0,1]; no separate confidence field per docs
      }
    | {
        type: "choice";
        choice: string;
        probabilities: Record<string, number>;
        confidence: number;
      }
    | {
        type: "score";
        score: number;
        probabilities: Record<string, number>;
        legend?: Record<string, string>;
        confidence: number;
      }
  >;
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
  };
  // 400 -> detail: string | object ; 422 -> detail: [{loc,msg,type}]
  detail?: unknown;
}

function formatTypeSafeError(parsed: TypeSafeSystemOneResponse, rawText: string): string {
  const d = parsed.detail;
  if (typeof d === "string") return d;
  if (Array.isArray(d)) {
    return d
      .map((e) =>
        e && typeof e === "object" && "msg" in e
          ? `${Array.isArray((e as { loc?: unknown }).loc) ? ((e as { loc: unknown[] }).loc as unknown[]).join(".") + ": " : ""}${(e as { msg: string }).msg}`
          : JSON.stringify(e)
      )
      .join("; ");
  }
  if (d && typeof d === "object") return JSON.stringify(d);
  return rawText.slice(0, 240);
}

/**
 * Calls the real TypeSafe System One (Jev) non-regressive model endpoint directly.
 * Zero fallback: if TYPESAFE_API_KEY is missing or the API returns an error, it throws immediately.
 */
async function callTypeSafeSystemOne(
  state: unknown,
  questions: Record<string, unknown>
): Promise<{
  data: TypeSafeSystemOneResponse;
  endpointUsed: string;
  statusCode: number;
}> {
  const typesafeKey = process.env.TYPESAFE_API_KEY?.trim();
  if (!typesafeKey) {
    throw new Error(
      "TYPESAFE_API_KEY is missing from environment secrets. Configure TYPESAFE_API_KEY in Settings > Secrets and restart the server."
    );
  }

  const endpoint = `${TYPESAFE_API_BASE}/systemone`;
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${typesafeKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: TYPESAFE_MODEL,
      state,
      questions,
    }),
  });

  const rawText = await response.text();
  let parsed: TypeSafeSystemOneResponse = {};
  try {
    parsed = JSON.parse(rawText) as TypeSafeSystemOneResponse;
  } catch {
    throw new Error(
      `TypeSafe API (${endpoint}) returned non-JSON HTTP ${response.status}: ${rawText.slice(0, 240)}`
    );
  }

  if (!response.ok) {
    throw new Error(
      `TypeSafe API HTTP ${response.status} (${endpoint}): ${formatTypeSafeError(parsed, rawText)}`
    );
  }

  return {
    data: parsed,
    endpointUsed: endpoint,
    statusCode: response.status,
  };
}

interface TriggeredRuleReport {
  ruleId: string;
  ruleName: string;
  category: GuardrailCategory;
  mode: "Block" | "Detect" | "Ignore";
  deterministicMatched: boolean;
  maskedMatches: string[];
  typesafeNoulProbability: number | null;
  typesafeConfidence: number | null;
  /** pass | review | action, from the noul thresholds in src/guardrails/typesafe.ts */
  band: NoulBand;
  /** true when a review-band rule was escalated by the severity score. */
  escalatedBySeverity: boolean;
  actionTaken:
    | "Enforced (Blocked)"
    | "Alerted & Sanitized"
    | "Flagged for Review"
    | "Ignored (Bypassed)"
    | "Guardrail Error (Failed Closed)";
  /** Present when the first answer was uncertain and the rule was re-asked. */
  retried?: { first: number; samples: number[] };
}

/** One uncertain rule re-asked: the first (battery) noul and one sample per retry. */
interface RetryReport {
  ruleId: string;
  ruleName: string;
  first: number;
  samples: number[];
  resolved: boolean;
}

/** A rule whose retries did not all come back confident and in agreement → fail closed. */
interface GuardrailErrorReport {
  ruleId: string;
  ruleName: string;
  category: GuardrailCategory;
  first: number;
  samples: number[];
}

type JevAnswers = NonNullable<TypeSafeSystemOneResponse["answers"]>;

/**
 * The question sent on retry `attempt` (0-based). Identical to the battery question for now;
 * this is the one place to swap in a different example reference per attempt later.
 */
function retryQuestion(question: unknown, _attempt: number): unknown {
  return question;
}

const fmtNoul = (p: number) => (Number.isFinite(p) ? p.toFixed(2) : "error");

async function startServer() {
  const app = express();
  app.use(express.json({ limit: "2mb" }));

  // Endpoint 0: Live TypeSafe Endpoint Access & Models Check (No fallback)
  app.get("/api/typesafe-status", async (_req, res) => {
    const key = process.env.TYPESAFE_API_KEY?.trim();
    if (!key) {
      res.status(401).json({
        connected: false,
        endpoint: `${TYPESAFE_API_BASE}/systemone`,
        model: TYPESAFE_MODEL,
        error: "TYPESAFE_API_KEY is not set in environment.",
      });
      return;
    }

    try {
      const modelsResp = await fetch(`${TYPESAFE_API_BASE}/models`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${key}`,
        },
      });
      const rawBody = await modelsResp.text();
      if (!modelsResp.ok) {
        res.status(modelsResp.status).json({
          connected: false,
          endpoint: `${TYPESAFE_API_BASE}/systemone`,
          model: TYPESAFE_MODEL,
          error: `GET /v1/models returned HTTP ${modelsResp.status}: ${rawBody.slice(0, 200)}`,
        });
        return;
      }

      let modelsData: unknown = rawBody;
      try {
        modelsData = JSON.parse(rawBody);
      } catch {
        // keep text
      }

      res.json({
        connected: true,
        endpoint: `${TYPESAFE_API_BASE}/systemone`,
        model: TYPESAFE_MODEL,
        modelsData,
      });
    } catch (err: unknown) {
      res.status(502).json({
        connected: false,
        endpoint: `${TYPESAFE_API_BASE}/systemone`,
        model: TYPESAFE_MODEL,
        error:
          err instanceof Error
            ? err.message
            : "Failed to reach api.typesafe.ai",
      });
    }
  });

  // Endpoint 1: Run the Table-Driven Contract Test Suite
  app.get("/api/test-suite", (_req, res) => {
    const results = GUARDRAIL_TEST_FIXTURES.map((fixture) => {
      const start = performance.now();
      const verdict = evaluatePrompt(fixture.input, fixture.policy);
      const durationMs = Number((performance.now() - start).toFixed(3));
      const auditLog = formatVerdictAuditLog(verdict);

      const decisionPassed = verdict.decision === fixture.expectedDecision;
      let categoryPassed = true;
      if (
        fixture.expectedCategory &&
        (verdict.decision === "block" || verdict.decision === "redact")
      ) {
        categoryPassed = verdict.category === fixture.expectedCategory;
      }

      let rawMaskingVerified = true;
      if (fixture.forbiddenRawSubstring) {
        const serialized = JSON.stringify(verdict) + auditLog;
        rawMaskingVerified = !serialized.includes(fixture.forbiddenRawSubstring);
      }

      return {
        id: fixture.id,
        name: fixture.name,
        input: sanitizeWithFindings(
          fixture.input,
          ALL_PURE_DETECTORS.flatMap((d) => d(fixture.input))
        ),
        expectedDecision: fixture.expectedDecision,
        actualVerdict: verdict,
        auditLog,
        passed: decisionPassed && categoryPassed && rawMaskingVerified,
        rawMaskingVerified,
        durationMs,
      };
    });

    res.json({
      total: results.length,
      passed: results.filter((r) => r.passed).length,
      results,
    });
  });

  // Endpoint 2: Pure TypeSafe Non-Regressive Guardrail Evaluation (No fallbacks)
  app.post("/api/evaluate", async (req, res) => {
    const requestStart = performance.now();
    try {
      const rawPrompt: string =
        typeof req.body?.prompt === "string" ? req.body.prompt.trim() : "";
      if (!rawPrompt) {
        res.status(400).json({ error: "Prompt input is required." });
        return;
      }

      const rules: ReadonlyArray<ControlPlaneRule> = Array.isArray(
        req.body?.rules
      )
        ? req.body.rules
        : INITIAL_CONTROL_PLANE_RULES;

      // Policy compiled only for display in the UI (the model is the guardrail; no regex
      // takes part in the decision below).
      const compiledPolicy = buildGuardrailPolicyFromControlPlane(rules);
      const entropyAnalysis: never[] = [];

      // Build TypeSafe System One (`POST https://api.typesafe.ai/v1/systemone`) request.
      // State is nested JSON; questions + thresholds live in src/guardrails/typesafe.ts.
      const activeRules = rules.filter((r) => r.mode !== "Ignore");
      const typesafeState = buildTypeSafeState(rawPrompt, activeRules);
      const questionsPayload = buildTypeSafeQuestions(activeRules);

      // Nothing is rewritten: the gateway either forwards the prompt or halts it.
      const sanitizedPrompt = rawPrompt;

      // Call the live TypeSafe System One API directly (throws on error, no fallback)
      const decisionsStart = performance.now();
      const { data: decisionResult, endpointUsed, statusCode } =
        await callTypeSafeSystemOne(typesafeState, questionsPayload);
      const decisionsLatencyMs = Math.round(performance.now() - decisionsStart);

      const rawAnswers = decisionResult.answers ?? {};
      const normalizedAnswers: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(rawAnswers)) {
        if (val && val.type === "noul") {
          const noulVal = typeof val.noul === "number" ? val.noul : 0;
          // Noul has no confidence field; the value fully describes the yes/no distribution.
          // Derived "confidence" = distance from 0.5, expressed as max(p, 1-p) for the UI.
          const confVal = Math.max(noulVal, 1 - noulVal);
          normalizedAnswers[k] = {
            type: "noul",
            noul: noulVal,
            confidence: confVal,
          };
        } else {
          normalizedAnswers[k] = val;
        }
      }

      // Retry band: a noul answer with confidence max(p, 1-p) below retryConfidence
      // (0.3 < noul < 0.7) is not decided from one sample. The uncertain rules are re-asked
      // `retries` times in parallel — one request per attempt, carrying only those questions —
      // and a rule stands only if every retry is confident and on the same side. Anything
      // else is a guardrail error and the whole request fails closed (block).
      const retryStart = performance.now();
      const isConfident = (p: number) =>
        Number.isFinite(p) &&
        Math.max(p, 1 - p) >= TYPESAFE_THRESHOLDS.retryConfidence;
      const uncertainRules = activeRules.filter((rule) => {
        const a = normalizedAnswers[rule.id] as
          | { type?: string; noul?: number }
          | undefined;
        return (
          a?.type === "noul" && typeof a.noul === "number" && !isConfident(a.noul)
        );
      });
      const retryReports: RetryReport[] = [];
      const guardrailErrors: GuardrailErrorReport[] = [];
      if (uncertainRules.length > 0) {
        const attempts: JevAnswers[] = await Promise.all(
          Array.from({ length: TYPESAFE_THRESHOLDS.retries }, async (_, attempt) => {
            const questions: Record<string, unknown> = {};
            for (const rule of uncertainRules) {
              questions[rule.id] = retryQuestion(questionsPayload[rule.id], attempt);
            }
            try {
              const { data } = await callTypeSafeSystemOne(typesafeState, questions);
              return data.answers ?? {};
            } catch {
              return {}; // a failed retry counts as "could not decide"
            }
          })
        );
        for (const rule of uncertainRules) {
          const first = (normalizedAnswers[rule.id] as { noul: number }).noul;
          const samples = attempts.map((answers) => {
            const a = answers[rule.id];
            return a && a.type === "noul" && typeof a.noul === "number"
              ? Number(a.noul.toFixed(4))
              : NaN;
          });
          const resolved =
            samples.every(isConfident) &&
            samples.every((p) => (p >= 0.5) === (samples[0] >= 0.5));
          retryReports.push({ ruleId: rule.id, ruleName: rule.name, first, samples, resolved });
          if (resolved) {
            const mean = samples.reduce((s, p) => s + p, 0) / samples.length;
            normalizedAnswers[rule.id] = {
              type: "noul",
              noul: Number(mean.toFixed(4)),
              confidence: Math.max(mean, 1 - mean),
              retried: { first, samples },
            };
          } else {
            guardrailErrors.push({
              ruleId: rule.id,
              ruleName: rule.name,
              category: rule.category,
              first,
              samples,
            });
          }
        }
      }
      const retryLatencyMs =
        uncertainRules.length > 0 ? Math.round(performance.now() - retryStart) : 0;

      // Severity score drives escalation of review-band rules (cookbook: score >= 2.0 → block).
      const severityAnswer = normalizedAnswers[SHARED_QUESTION_IDS.severity] as
        | { type: "score"; score: number }
        | undefined;
      const severityScore =
        severityAnswer && typeof severityAnswer.score === "number"
          ? severityAnswer.score
          : 0;
      const severityEscalates =
        severityScore >= TYPESAFE_THRESHOLDS.severityBlock;

      // Evaluate per-rule triggers from the Jev noul bands only.
      // Decision logic is code; Jev only answers yes/no per rule.
      const ruleReports: TriggeredRuleReport[] = [];
      for (const rule of activeRules) {
        const guardrailError = guardrailErrors.find((g) => g.ruleId === rule.id);
        if (guardrailError) {
          // Fail closed: the rule could not be decided, so it is enforced regardless of mode.
          ruleReports.push({
            ruleId: rule.id,
            ruleName: rule.name,
            category: rule.category,
            mode: rule.mode,
            deterministicMatched: false,
            maskedMatches: [],
            typesafeNoulProbability: Number(guardrailError.first.toFixed(4)),
            typesafeConfidence: Number(
              Math.max(guardrailError.first, 1 - guardrailError.first).toFixed(4)
            ),
            band: "action",
            escalatedBySeverity: false,
            actionTaken: "Guardrail Error (Failed Closed)",
            retried: { first: guardrailError.first, samples: guardrailError.samples },
          });
          continue;
        }
        const ans = normalizedAnswers[rule.id] as
          | { type: "noul"; noul: number; confidence: number; retried?: { first: number; samples: number[] } }
          | undefined;
        const noulProb =
          ans && ans.type === "noul" ? Number(ans.noul.toFixed(4)) : null;
        const noulConf =
          ans && ans.type === "noul" ? Number(ans.confidence.toFixed(4)) : null;

        const deterministicMatched = false;
        let band = bandForNoul(noulProb);
        let escalatedBySeverity = false;
        if (band === "review" && severityEscalates) {
          band = "action";
          escalatedBySeverity = true;
        }

        if (band === "pass") continue;

        let actionTaken: TriggeredRuleReport["actionTaken"];
        if (band === "review") {
          actionTaken = "Flagged for Review";
        } else if (rule.mode === "Block") {
          actionTaken = "Enforced (Blocked)";
        } else {
          actionTaken = "Alerted & Sanitized";
        }

        ruleReports.push({
          ruleId: rule.id,
          ruleName: rule.name,
          category: rule.category,
          mode: rule.mode,
          deterministicMatched,
          maskedMatches: [],
          typesafeNoulProbability: noulProb,
          typesafeConfidence: noulConf,
          band,
          escalatedBySeverity,
          actionTaken,
          retried: ans?.retried,
        });
      }

      // Verdict comes from Jev alone.
      let effectiveVerdict: GuardrailVerdict = { decision: "allow" };
      const contractVerdict: GuardrailVerdict = effectiveVerdict;
      const blockingRuleReport = ruleReports.find(
        (r) => r.actionTaken === "Enforced (Blocked)"
      );
      const detectingRuleReports = ruleReports.filter(
        (r) =>
          r.actionTaken === "Alerted & Sanitized" ||
          r.actionTaken === "Flagged for Review"
      );

      // Precedence: guardrail error (fail closed) > block > detect > allow.
      if (guardrailErrors.length > 0) {
        const g = guardrailErrors[0];
        const others = guardrailErrors.length - 1;
        effectiveVerdict = {
          decision: "block",
          category: g.category,
          reason: `Guardrail error on rule "${g.ruleName}": Jev answered ${fmtNoul(g.first)} in the battery and ${g.samples.map(fmtNoul).join(" / ")} on ${TYPESAFE_THRESHOLDS.retries} retries — no confident, agreeing answer, failed closed${others > 0 ? ` (+${others} more rule${others > 1 ? "s" : ""})` : ""}`,
          span: { start: 0, end: rawPrompt.length },
        };
      } else if (blockingRuleReport) {
        effectiveVerdict = {
          decision: "block",
          category: blockingRuleReport.category,
          reason: `Enforced by TypeSafe Jev rule "${blockingRuleReport.ruleName}" (noul=${blockingRuleReport.typesafeNoulProbability}${blockingRuleReport.escalatedBySeverity ? `, escalated by severity=${severityScore.toFixed(2)}` : ""})`,
          span: { start: 0, end: rawPrompt.length },
        };
      } else if (detectingRuleReports.length > 0) {
        const primary = detectingRuleReports[0];
        const syntheticFindings: Finding[] = detectingRuleReports.map((r) => ({
          category: r.category,
          match: `${r.ruleId} noul=${r.typesafeNoulProbability}`,
          confidence: r.typesafeNoulProbability ?? 0,
          detector: r.ruleId,
        }));
        effectiveVerdict = {
          decision: "redact",
          category: primary.category,
          redacted: sanitizedPrompt,
          findings: syntheticFindings,
        };
      }

      // 6. Sanitized output produced directly by the guardrail pipeline (no LLM fallback)
      let sanitizedEndUserOutput = "";
      let downstreamStatus:
        | "blocked"
        | "sanitized_and_completed"
        | "clean_completed" = "clean_completed";

      if (effectiveVerdict.decision === "block") {
        downstreamStatus = "blocked";
        sanitizedEndUserOutput = `[REQUEST ENFORCED & HALTED BY GUARDRAIL CONTROL PLANE]\nCategory: ${effectiveVerdict.category}\nReason: ${effectiveVerdict.reason}\nSpan: [${effectiveVerdict.span.start}, ${effectiveVerdict.span.end}]\n\nSanitized Input Preview:\n${sanitizedPrompt}`;
      } else if (effectiveVerdict.decision === "redact") {
        downstreamStatus = "sanitized_and_completed";
        sanitizedEndUserOutput = effectiveVerdict.redacted;
      } else {
        sanitizedEndUserOutput = sanitizedPrompt;
      }

      const totalLatencyMs = Math.round(performance.now() - requestStart);
      const usage = decisionResult.usage;

      res.json({
        contractVerdict,
        effectiveVerdict,
        contractAuditLog: formatVerdictAuditLog(effectiveVerdict),
        compiledPolicy,
        sanitizedPrompt,
        sanitizedEndUserOutput,
        downstreamStatus,
        triggeredRules: ruleReports,
        guardrailErrors,
        entropyAnalysis,
        typesafeInternals: {
          endpoint: endpointUsed,
          httpStatus: statusCode,
          requestedModel: TYPESAFE_MODEL,
          model: decisionResult.model ?? TYPESAFE_MODEL,
          architecture:
            "TypeSafe System One (Jev Non-Autoregressive Decision Model)",
          noulActionThreshold: TYPESAFE_THRESHOLDS.noulAction,
          thresholds: TYPESAFE_THRESHOLDS,
          severityScore: Number(severityScore.toFixed(2)),
          reviewCount: ruleReports.filter((r) => r.band === "review").length,
          totalOutputTokens: usage?.output_tokens ?? 0,
          totalInputTokens: usage?.input_tokens ?? null,
          decisionsLatencyMs,
          retryLatencyMs,
          retries: retryReports,
          retryPolicy: {
            confidence: TYPESAFE_THRESHOLDS.retryConfidence,
            attempts: TYPESAFE_THRESHOLDS.retries,
            onDisagreement: "fail closed",
          },
          totalPipelineLatencyMs: totalLatencyMs,
          requestPayload: {
            endpoint: endpointUsed,
            model: TYPESAFE_MODEL,
            statePreview: sanitizedPrompt,
            state: {
              ...typesafeState,
              request: { prompt: sanitizedPrompt },
            },
            questionCount: Object.keys(questionsPayload).length,
            questions: questionsPayload,
          },
          rawAnswers: normalizedAnswers,
        },
      });
    } catch (err: unknown) {
      const message =
        err instanceof Error
          ? err.message
          : "Unexpected error during TypeSafe guardrail evaluation.";
      res.status(502).json({ error: message });
    }
  });

  // Create the HTTP server first so Vite's HMR websocket can share it
  // (otherwise Vite binds a separate fixed port 24678, which collides when
  // more than one dev server is running and the browser logs WS errors).
  const httpServer = http.createServer(app);

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true, hmr: { server: httpServer } },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  httpServer.on("error", (err: NodeJS.ErrnoException) => {
    if (err.code === "EADDRINUSE") {
      console.error(
        `Port ${PORT} is already in use. Start with PORT=<free port> bun run dev`
      );
      process.exit(1);
    }
    throw err;
  });

  httpServer.listen(PORT, "0.0.0.0", () => {
    console.log(
      `TypeSafe Guardrail Studio running on http://localhost:${PORT}`
    );
  });
}

startServer();
