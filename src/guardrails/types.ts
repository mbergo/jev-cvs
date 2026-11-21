import { z } from "zod";

export type GuardrailCategory =
  | "credential_leak"
  | "pii"
  | "secret_key"
  | "prompt_injection"
  | "confidential_data";

export interface Finding {
  category: GuardrailCategory;
  match: string; // masked in logs, never logged raw (first 4 chars + "****")
  confidence: number; // 0–1
  detector: string; // which rule fired
}

export type GuardrailVerdict =
  | { decision: "allow" }
  | {
      decision: "block";
      category: GuardrailCategory;
      reason: string;
      span: { start: number; end: number };
    }
  | {
      decision: "redact";
      category: GuardrailCategory;
      redacted: string;
      findings: Finding[];
    };

export const GuardrailCategorySchema = z.enum([
  "credential_leak",
  "pii",
  "secret_key",
  "prompt_injection",
  "confidential_data",
]);

export const CategoryActionSchema = z.enum(["allow", "block", "redact"]);

export type CategoryAction = z.infer<typeof CategoryActionSchema>;

export const CategoryPolicyConfigSchema = z.object({
  action: CategoryActionSchema,
  minConfidence: z.number().min(0).max(1),
  disabledDetectors: z.array(z.string()).optional(),
  blockDetectors: z.array(z.string()).optional(),
});

export const GuardrailPolicySchema = z.object({
  categories: z.object({
    credential_leak: CategoryPolicyConfigSchema,
    pii: CategoryPolicyConfigSchema,
    secret_key: CategoryPolicyConfigSchema,
    prompt_injection: CategoryPolicyConfigSchema,
    confidential_data: CategoryPolicyConfigSchema,
  }),
});

export type GuardrailPolicy = z.infer<typeof GuardrailPolicySchema>;

/**
 * Parses and validates a GuardrailPolicy at load time.
 * Invalid policy fails fast with a ZodError, never at request time.
 */
export function parseGuardrailPolicy(raw: unknown): GuardrailPolicy {
  return GuardrailPolicySchema.parse(raw);
}

/**
 * Default production policy parsed at module load time.
 */
export const DEFAULT_GUARDRAIL_POLICY: GuardrailPolicy = parseGuardrailPolicy({
  categories: {
    credential_leak: { action: "redact", minConfidence: 0.6 },
    pii: { action: "redact", minConfidence: 0.75 },
    secret_key: { action: "block", minConfidence: 0.8 },
    prompt_injection: { action: "block", minConfidence: 0.75 },
    confidential_data: { action: "block", minConfidence: 0.75 },
  },
});
