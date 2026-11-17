import "dotenv/config";
import express from "express";
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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3000;
const TYPESAFE_API_BASE = "https://api.typesafe.ai/v1";

interface TypeSafeSystemOneResponse {
  model?: string;
  answers?: Record<
    string,
    | {
        type: "noul";
        noul: number;
        confidence?: number;
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
    prompt_tokens?: number;
    input_tokens?: number;
    total_tokens?: number;
    total_input_tokens?: number;
    total_output_tokens?: number;
  };
  error?:
    | {
        message?: string;
        type?: string;
        code?: string;
      }
    | string;
}

/**
 * Calls the real TypeSafe System One (Jev) non-regressive model endpoint directly.
 * Zero fallback: if TYPESAFE_API_KEY is missing or the API returns an error, it throws immediately.
 */
async function callTypeSafeSystemOne(
  stateText: string,
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
      model: "jev-latest",
      state: stateText,
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
    const errDetail =
      typeof parsed.error === "string"
        ? parsed.error
        : parsed.error?.message ?? rawText.slice(0, 240);
    throw new Error(
      `TypeSafe API HTTP ${response.status} (${endpoint}): ${errDetail}`
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
  actionTaken:
    | "Enforced (Blocked)"
    | "Alerted & Sanitized"
    | "Ignored (Bypassed)";
}

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
        model: "jev-latest",
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
          model: "jev-latest",
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
        model: "jev-latest",
        modelsData,
      });
    } catch (err: unknown) {
      res.status(502).json({
        connected: false,
        endpoint: `${TYPESAFE_API_BASE}/systemone`,
        model: "jev-latest",
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

      // 1. Build & validate strict GuardrailPolicy via Zod
      const compiledPolicy = buildGuardrailPolicyFromControlPlane(rules);

      // 2. Run pure deterministic detectors to inspect masked findings
      const allDetectorFindings: Finding[] = [];
      for (const detector of ALL_PURE_DETECTORS) {
        const found = detector(rawPrompt);
        allDetectorFindings.push(...found);
      }

      // Compute token entropy telemetry for the TypeSafe internals panel
      const candidateTokens: string[] = rawPrompt.match(/\S{12,}/g) ?? [];
      const entropyAnalysis = candidateTokens.slice(0, 6).map((rawTok: string) => {
        const tok = rawTok.replace(/^[("'`]+|[.,;!?)"'`]+$/g, "");
        return {
          maskedToken: maskMatch(tok),
          length: tok.length,
          shannonEntropy: Number(calculateShannonEntropy(tok).toFixed(2)),
          exceedsThreshold:
            tok.length >= 20 && calculateShannonEntropy(tok) >= 4.5,
        };
      });

      // 3. Run the strict contract function: evaluatePrompt(input, policy)
      const contractVerdict: GuardrailVerdict = evaluatePrompt(
        rawPrompt,
        compiledPolicy
      );

      // 4. Build TypeSafe System One (`POST https://api.typesafe.ai/v1/systemone`) request
      const activeRules = rules.filter((r) => r.mode !== "Ignore");

      const questionsPayload: Record<string, unknown> = {};
      for (const rule of activeRules) {
        questionsPayload[rule.id] = {
          type: "noul",
          instructions: rule.customPatternDescription
            ? `${rule.typesafeQuestion.instructions} Custom policy scope: ${rule.customPatternDescription}`
            : rule.typesafeQuestion.instructions,
          criteria: {
            true_description: rule.typesafeQuestion.trueDescription,
            false_description: rule.typesafeQuestion.falseDescription,
          },
        };
      }

      questionsPayload["primary_threat_vector"] = {
        type: "choice",
        instructions:
          "Which primary security guardrail category best describes the dominant risk in this input?",
        criteria: {
          benign_input: "Safe, harmless, or standard technical request.",
          credential_or_secret_leak:
            "Contains API keys, cloud tokens, PEM private keys, JWTs, or high-entropy secrets.",
          pii_disclosure:
            "Contains SSN, credit card, bank account, passport, EIN, or TIN numbers.",
          prompt_injection_or_exploit:
            "Contains prompt injection, jailbreak, RCE, system file access, exfiltration, or malicious URLs/packages.",
        },
      };

      const severityCriteria = [
        "Level 0 (Safe): Benign request with zero policy violations.",
        "Level 1 (Low): Minor ambiguity or benign technical discussion of security concepts.",
        "Level 2 (High): Contains sensitive PII or unmasked credentials requiring redaction.",
        "Level 3 (Critical): Active exploit payload, jailbreak override, destructive command, or RCE.",
      ];

      questionsPayload["threat_severity_rubric"] = {
        type: "score",
        instructions:
          "Rate the security risk severity of ingesting this prompt into a production LLM pipeline.",
        criteria: severityCriteria,
      };

      const allActiveFindings = allDetectorFindings.filter((f) => {
        const matchingRule = rules.find(
          (r) =>
            r.detectorKey === f.detector ||
            (r.id === "api_keys_and_secrets" &&
              (f.category === "credential_leak" || f.category === "secret_key"))
        );
        return !matchingRule || matchingRule.mode !== "Ignore";
      });

      const sanitizedPrompt = sanitizeWithFindings(
        rawPrompt,
        allActiveFindings.length > 0 ? allActiveFindings : allDetectorFindings
      );

      // Call the live TypeSafe System One API directly (throws on error, no fallback)
      const decisionsStart = performance.now();
      const { data: decisionResult, endpointUsed, statusCode } =
        await callTypeSafeSystemOne(rawPrompt, questionsPayload);
      const decisionsLatencyMs = Math.round(performance.now() - decisionsStart);

      const rawAnswers = decisionResult.answers ?? {};
      const normalizedAnswers: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(rawAnswers)) {
        if (val && val.type === "noul") {
          const noulVal = typeof val.noul === "number" ? val.noul : 0;
          const confVal =
            typeof val.confidence === "number"
              ? val.confidence
              : Math.max(noulVal, 1 - noulVal);
          normalizedAnswers[k] = {
            type: "noul",
            noul: noulVal,
            confidence: confVal,
          };
        } else {
          normalizedAnswers[k] = val;
        }
      }

      // 5. Evaluate per-rule triggers from TypeSafe `noul` probabilities + deterministic contract
      const ruleReports: TriggeredRuleReport[] = [];
      for (const rule of rules) {
        const matchedFindings = allDetectorFindings.filter((f) => {
          if (rule.id === "api_keys_and_secrets") {
            return (
              f.category === "credential_leak" || f.category === "secret_key"
            );
          }
          return f.detector === rule.detectorKey;
        });

        const ans = normalizedAnswers[rule.id] as
          | { type: "noul"; noul: number; confidence: number }
          | undefined;
        const noulProb =
          ans && ans.type === "noul" ? Number(ans.noul.toFixed(4)) : null;
        const noulConf =
          ans && ans.type === "noul" ? Number(ans.confidence.toFixed(4)) : null;

        const deterministicMatched = matchedFindings.length > 0;
        const modelTriggered = noulProb !== null && noulProb >= 0.65;

        if (deterministicMatched || modelTriggered) {
          let actionTaken: TriggeredRuleReport["actionTaken"] =
            "Alerted & Sanitized";
          if (rule.mode === "Block") {
            actionTaken = "Enforced (Blocked)";
          } else if (rule.mode === "Ignore") {
            actionTaken = "Ignored (Bypassed)";
          }

          ruleReports.push({
            ruleId: rule.id,
            ruleName: rule.name,
            category: rule.category,
            mode: rule.mode,
            deterministicMatched,
            maskedMatches: matchedFindings.map((f) => f.match),
            typesafeNoulProbability: noulProb,
            typesafeConfidence: noulConf,
            actionTaken,
          });
        }
      }

      // Reconcile the effective verdict from TypeSafe Jev & deterministic contract
      let effectiveVerdict: GuardrailVerdict = contractVerdict;
      const blockingRuleReport = ruleReports.find((r) => r.mode === "Block");
      const detectingRuleReports = ruleReports.filter(
        (r) => r.mode === "Detect"
      );

      if (effectiveVerdict.decision === "allow" && blockingRuleReport) {
        const span = resolveFindingSpan(rawPrompt, blockingRuleReport.ruleId);
        effectiveVerdict = {
          decision: "block",
          category: blockingRuleReport.category,
          reason: `Enforced by TypeSafe Jev rule "${blockingRuleReport.ruleName}" (noul=${blockingRuleReport.typesafeNoulProbability ?? 0.95})`,
          span,
        };
      } else if (
        effectiveVerdict.decision === "allow" &&
        detectingRuleReports.length > 0
      ) {
        const primary = detectingRuleReports[0];
        const syntheticFindings: Finding[] = detectingRuleReports.map((r) => ({
          category: r.category,
          match: r.maskedMatches[0] ?? maskMatch(rawPrompt.slice(0, 12)),
          confidence: r.typesafeNoulProbability ?? 0.85,
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
        entropyAnalysis,
        typesafeInternals: {
          endpoint: endpointUsed,
          httpStatus: statusCode,
          requestedModel: "jev-latest",
          model: decisionResult.model ?? "jev-latest",
          architecture:
            "TypeSafe System One (Jev Non-Regressive Decision Model)",
          totalOutputTokens: usage?.total_output_tokens ?? 0,
          totalInputTokens:
            usage?.prompt_tokens ??
            usage?.input_tokens ??
            usage?.total_tokens ??
            usage?.total_input_tokens ??
            null,
          decisionsLatencyMs,
          totalPipelineLatencyMs: totalLatencyMs,
          requestPayload: {
            endpoint: endpointUsed,
            model: "jev-latest",
            statePreview: sanitizedPrompt,
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

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
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

  app.listen(PORT, "0.0.0.0", () => {
    console.log(
      `TypeSafe Guardrail Studio running on http://localhost:${PORT}`
    );
  });
}

startServer();
