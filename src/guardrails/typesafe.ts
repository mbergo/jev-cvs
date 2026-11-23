/**
 * Every TypeSafe (Jev / System One) question and threshold lives in this one file,
 * as the docs recommend ("keep questions and threshold constants in a single code file").
 *
 * References:
 *   https://docs.typesafe.ai/api/system-one               request/response schema
 *   https://docs.typesafe.ai/primitives/noul              noul = P(yes), thresholds 0.7 / 0.3
 *   https://docs.typesafe.ai/concepts/how-to-build-with-system-one
 *       - state is nested JSON with only the fields the questions need
 *       - code-sourced values go in their own instruction fields, not spliced into prose
 *       - reference state with backticked paths (`request.prompt`)
 *       - use a review band and escalate instead of auto-deciding
 *   https://docs.typesafe.ai/cookbooks/llm_guardrails     review/action thresholds, severity escalation
 */
import type { ControlPlaneRule } from "../data/controlPlaneRules";

// ---------------------------------------------------------------------------
// Thresholds (the "strict" policy from the guardrails cookbook)
// ---------------------------------------------------------------------------

export const TYPESAFE_THRESHOLDS = {
  /** noul >= action → the rule fires and its mode (Block/Detect) is applied. */
  noulAction: 0.7,
  /** review <= noul < action → uncertain band; flagged for review, not auto-decided. */
  noulReview: 0.35,
  /** severity score (0..3) at or above this turns any review into a block. */
  severityBlock: 2.0,
} as const;

export type NoulBand = "pass" | "review" | "action";

export function bandForNoul(p: number | null | undefined): NoulBand {
  if (p === null || p === undefined) return "pass";
  if (p >= TYPESAFE_THRESHOLDS.noulAction) return "action";
  if (p >= TYPESAFE_THRESHOLDS.noulReview) return "review";
  return "pass";
}

// ---------------------------------------------------------------------------
// State: nested JSON, only what the questions need.
// ---------------------------------------------------------------------------

export interface GuardrailState {
  request: {
    /** The untrusted text entering the gateway. */
    prompt: string;
  };
  gateway: {
    /** Where in the pipeline this screen runs. */
    stage: "input";
    /** Names of the rules being evaluated (lets Jev see the policy surface). */
    active_rules: string[];
  };
}

export function buildTypeSafeState(
  prompt: string,
  activeRules: ReadonlyArray<ControlPlaneRule>
): GuardrailState {
  return {
    request: { prompt },
    gateway: {
      stage: "input",
      active_rules: activeRules.map((r) => r.name),
    },
  };
}

// ---------------------------------------------------------------------------
// Questions: one atomic Noul per rule + shared Choice + Score.
// ---------------------------------------------------------------------------

export const THREAT_VECTOR_CRITERIA = {
  benign_input: "Safe, harmless, or ordinary technical request.",
  credential_or_secret_leak:
    "Contains API keys, cloud tokens, PEM private keys, JWTs, or high-entropy secrets.",
  pii_disclosure:
    "Contains SSN, credit card, bank account, passport, EIN, TIN, Medicare/Medicaid ID, health plan member ID, or prescriber DEA numbers.",
  confidential_data_disclosure:
    "Reveals non-public company information or identifiable patient health information: negotiations, M&A, legal, financial, HR, PBM rebate terms, unfiled government submissions.",
  prompt_injection_or_exploit:
    "Contains prompt injection, jailbreak, RCE, system file access, exfiltration, or malicious URLs/packages.",
  harmful_content:
    "Asks for instructions enabling serious physical harm, or promotes discrimination by gender or race.",
  healthcare_misconduct:
    "Asks the assistant to take part in improper healthcare conduct: dispensing without a valid prescription, upcoding, falsifying claims or records, denying coverage without clinician review, bulk patient exports, sharing health data with advertisers, skipping identity verification, or giving individual clinical advice.",
} as const;

/** Ordered: index == score level. */
export const SEVERITY_LEVELS = [
  "Safe: benign request with zero policy violations.",
  "Low: minor ambiguity or benign technical discussion of security concepts.",
  "High: contains sensitive PII or unmasked credentials requiring redaction.",
  "Critical: active exploit payload, jailbreak override, destructive command, or RCE.",
] as const;

export const SHARED_QUESTION_IDS = {
  vector: "primary_threat_vector",
  severity: "threat_severity_rubric",
} as const;

export function buildTypeSafeQuestions(
  activeRules: ReadonlyArray<ControlPlaneRule>
): Record<string, unknown> {
  const questions: Record<string, unknown> = {};

  for (const rule of activeRules) {
    // Short question + yes/no criteria + a couple of "yes" examples. Same shape for
    // every rule in every group; the model only answers yes/no (noul = P(yes)).
    questions[rule.id] = {
      type: "noul",
      instructions: {
        question: rule.typesafeQuestion.instructions,
        examples_of_yes: rule.typesafeQuestion.examples,
      },
      criteria: {
        true: rule.typesafeQuestion.trueDescription,
        false: rule.typesafeQuestion.falseDescription,
      },
    };
  }

  questions[SHARED_QUESTION_IDS.vector] = {
    type: "choice",
    instructions:
      "Which guardrail category best describes the dominant risk in `request.prompt`?",
    criteria: THREAT_VECTOR_CRITERIA,
  };

  questions[SHARED_QUESTION_IDS.severity] = {
    type: "score",
    instructions:
      "Rate the security risk of forwarding `request.prompt` to a production LLM.",
    criteria: [...SEVERITY_LEVELS],
  };

  return questions;
}
