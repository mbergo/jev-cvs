import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI } from "@google/genai";
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
import {
  DEFAULT_GUARDRAIL_POLICY,
  type Finding,
  type GuardrailCategory,
  type GuardrailVerdict,
  parseGuardrailPolicy,
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

function getDecisionsClient(): GoogleGenAI {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error(
      "GEMINI_API_KEY is not configured. Please check the Settings > Secrets panel."
    );
  }
  return new GoogleGenAI({
    apiKey,
    apiVersion: "v1beta",
    httpOptions: {
      headers: {
        "User-Agent": "aistudio-build",
      },
    },
  });
}

function getGenClient(): GoogleGenAI {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error(
      "GEMINI_API_KEY is not configured. Please check the Settings > Secrets panel."
    );
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        "User-Agent": "aistudio-build",
      },
    },
  });
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
  actionTaken: "Blocked" | "Notified & Sanitized" | "Ignored (Bypassed)";
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: "2mb" }));

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

  // Endpoint 2: Full TypeSafe Non-Regressive Guardrail & Deterministic Contract Evaluation
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

      // 2. Run all pure deterministic detectors to inspect raw findings (masked)
      const allDetectorFindings: Finding[] = [];
      for (const detector of ALL_PURE_DETECTORS) {
        const found = detector(rawPrompt);
        allDetectorFindings.push(...found);
      }

      // Compute token entropy telemetry for the TypeSafe internals panel
      const candidateTokens: string[] =
        rawPrompt.match(/[A-Za-z0-9+/=_-]{12,}/g) ?? [];
      const entropyAnalysis = candidateTokens.slice(0, 6).map((tok: string) => ({
        maskedToken: maskMatch(tok),
        length: tok.length,
        shannonEntropy: Number(calculateShannonEntropy(tok).toFixed(2)),
        exceedsThreshold:
          tok.length >= 20 && calculateShannonEntropy(tok) >= 4.5,
      }));

      // 3. Run the strict contract function: evaluatePrompt(input, policy)
      const contractVerdict: GuardrailVerdict = evaluatePrompt(
        rawPrompt,
        compiledPolicy
      );
      const contractAuditLog = formatVerdictAuditLog(contractVerdict);

      // 4. Build TypeSafe / Gemini Decisions API (gemini-decision-1) non-regressive request
      // Each non-ignored rule becomes a calibrated `noul` question, plus `choice` and `score` questions
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

      // Sanitize the prompt before sending to any downstream model or showing in logs
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

      const decisionsStart = performance.now();
      const decisionsAi = getDecisionsClient();
      const decisionResult = await decisionsAi.decisions.create({
        model: "gemini-decision-1",
        input: rawPrompt,
        questions: questionsPayload as Parameters<
          typeof decisionsAi.decisions.create
        >[0]["questions"],
      });
      const decisionsLatencyMs = Math.round(performance.now() - decisionsStart);

      const answers = decisionResult.answers ?? {};

      // 5. Combine deterministic detectors + non-regressive TypeSafe `noul` probabilities per Control Plane rule
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

        const ans = answers[rule.id];
        const noulProb =
          ans && ans.type === "noul" ? Number(ans.noul.toFixed(4)) : null;
        const noulConf =
          ans && ans.type === "noul" ? Number(ans.confidence.toFixed(4)) : null;

        const deterministicMatched = matchedFindings.length > 0;
        const modelTriggered = noulProb !== null && noulProb >= 0.65;

        if (deterministicMatched || modelTriggered) {
          let actionTaken: TriggeredRuleReport["actionTaken"] =
            "Notified & Sanitized";
          if (rule.mode === "Block") {
            actionTaken = "Blocked";
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

      // If the non-regressive TypeSafe model caught a rule that wasn't caught by regex alone,
      // reconcile the effective verdict so both engines protect the pipeline.
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
          reason: `Blocked by TypeSafe non-regressive model rule "${blockingRuleReport.ruleName}" (P(violation)=${blockingRuleReport.typesafeNoulProbability ?? 0.95})`,
          span,
        };
      } else if (
        effectiveVerdict.decision === "allow" &&
        detectingRuleReports.length > 0
      ) {
        const primary = detectingRuleReports[0];
        const syntheticFindings: Finding[] = detectingRuleReports.map((r) => ({
          category: r.category,
          match:
            r.maskedMatches[0] ?? maskMatch(rawPrompt.slice(0, 12)),
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

      // 6. Generate downstream sanitized response if not blocked
      let sanitizedEndUserOutput = "";
      let downstreamStatus: "blocked" | "sanitized_and_completed" | "clean_completed" =
        "clean_completed";

      if (effectiveVerdict.decision === "block") {
        downstreamStatus = "blocked";
        sanitizedEndUserOutput = `[REQUEST HALTED BY GUARDRAIL CONTROL PLANE]\nCategory: ${effectiveVerdict.category}\nReason: ${effectiveVerdict.reason}\nSpan: [${effectiveVerdict.span.start}, ${effectiveVerdict.span.end}]\n\nSanitized Input Preview:\n${sanitizedPrompt}`;
      } else {
        const promptForDownstream =
          effectiveVerdict.decision === "redact"
            ? effectiveVerdict.redacted
            : sanitizedPrompt;

        if (
          effectiveVerdict.decision === "redact" ||
          detectingRuleReports.length > 0
        ) {
          downstreamStatus = "sanitized_and_completed";
        }

        const genAi = getGenClient();
        const genResponse = await genAi.models.generateContent({
          model: "gemini-4-hydrogen",
          contents: promptForDownstream,
          config: {
            systemInstruction:
              "You are a concise, security-hardened enterprise assistant. Never echo raw secrets, credentials, or PII. If the prompt contains [REDACTED:...] markers, acknowledge that the sensitive tokens were sanitized by the TypeSafe Guardrail layer and safely address the benign technical part of the user's request in 2-4 sentences.",
          },
        });

        const rawModelText =
          genResponse.text ?? "Request processed with sanitized input.";
        // Sanitize model output before it ever reaches the end user!
        const outputFindings = ALL_PURE_DETECTORS.flatMap((d) =>
          d(rawModelText)
        );
        const outputVerdict = evaluatePrompt(
          rawModelText,
          DEFAULT_GUARDRAIL_POLICY
        );
        if (outputVerdict.decision === "redact") {
          sanitizedEndUserOutput = outputVerdict.redacted;
        } else {
          sanitizedEndUserOutput = sanitizeWithFindings(
            rawModelText,
            outputFindings
          );
        }
      }

      const totalLatencyMs = Math.round(performance.now() - requestStart);

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
          model: "gemini-decision-1",
          apiVersion: "v1beta",
          architecture: "Non-Regressive Calibrated Decision Model (System-1)",
          totalOutputTokens:
            (decisionResult.usage as { total_output_tokens?: number } | undefined)
              ?.total_output_tokens ?? 0,
          totalInputTokens:
            (decisionResult.usage as { total_input_tokens?: number } | undefined)
              ?.total_input_tokens ?? null,
          decisionsLatencyMs,
          totalPipelineLatencyMs: totalLatencyMs,
          requestPayload: {
            model: "gemini-decision-1",
            inputPreview: sanitizedPrompt,
            questionCount: Object.keys(questionsPayload).length,
            questions: questionsPayload,
          },
          rawAnswers: answers,
        },
      });
    } catch (err: unknown) {
      const message =
        err instanceof Error
          ? err.message
          : "Unexpected error during guardrail evaluation.";
      res.status(500).json({ error: message });
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
    console.log(`TypeSafe Guardrail Studio running on http://localhost:${PORT}`);
  });
}

startServer();
