import {
  ALL_PURE_DETECTORS,
  resolveFindingSpan,
  sanitizeWithFindings,
} from "./detectors";
import {
  type Finding,
  type GuardrailPolicy,
  type GuardrailVerdict,
  parseGuardrailPolicy,
} from "./types";

/**
 * Evaluates an input prompt against a validated GuardrailPolicy and returns
 * a strict discriminated-union GuardrailVerdict.
 */
export function evaluatePrompt(
  input: string,
  policy: GuardrailPolicy
): GuardrailVerdict {
  // Validate policy structure (throws ZodError if invalid)
  const validPolicy = parseGuardrailPolicy(policy);

  const rawFindings: Finding[] = [];
  for (const detector of ALL_PURE_DETECTORS) {
    const detected = detector(input);
    for (const finding of detected) {
      const categoryConfig = validPolicy.categories[finding.category];
      const isDetectorDisabled =
        categoryConfig.disabledDetectors?.includes(finding.detector) ?? false;
      if (
        !isDetectorDisabled &&
        categoryConfig.action !== "allow" &&
        finding.confidence >= categoryConfig.minConfidence
      ) {
        rawFindings.push(finding);
      }
    }
  }

  if (rawFindings.length === 0) {
    return { decision: "allow" };
  }

  // First check if any matched finding belongs to a category configured to "block"
  const blockingFinding = rawFindings.find(
    (f) => validPolicy.categories[f.category].action === "block"
  );

  if (blockingFinding) {
    const span = resolveFindingSpan(input, blockingFinding.detector);
    return {
      decision: "block",
      category: blockingFinding.category,
      reason: `Blocked by ${blockingFinding.detector} (${blockingFinding.match}, confidence ${blockingFinding.confidence.toFixed(2)})`,
      span,
    };
  }

  // Otherwise, findings belong to categories configured to "redact"
  const redactFindings = rawFindings.filter(
    (f) => validPolicy.categories[f.category].action === "redact"
  );

  if (redactFindings.length > 0) {
    const primaryCategory = redactFindings[0].category;
    const redacted = sanitizeWithFindings(input, redactFindings);
    return {
      decision: "redact",
      category: primaryCategory,
      redacted,
      findings: redactFindings,
    };
  }

  return { decision: "allow" };
}

/**
 * Exhaustive switch over the GuardrailVerdict discriminated union.
 * Produces a compiler error if any decision branch is unhandled.
 * Ensures raw matches never appear in formatted audit logs.
 */
export function formatVerdictAuditLog(verdict: GuardrailVerdict): string {
  switch (verdict.decision) {
    case "allow":
      return "[GUARDRAIL:ALLOW] Input passed all active policy checks.";
    case "block":
      return `[GUARDRAIL:BLOCK] category=${verdict.category} span=[${verdict.span.start},${verdict.span.end}] reason="${verdict.reason}"`;
    case "redact": {
      const summary = verdict.findings
        .map(
          (f) =>
            `${f.detector}(match=${f.match},conf=${f.confidence.toFixed(2)})`
        )
        .join(", ");
      return `[GUARDRAIL:REDACT] category=${verdict.category} findings=[${summary}]`;
    }
    default: {
      const _exhaustiveCheck: never = verdict;
      return _exhaustiveCheck;
    }
  }
}
