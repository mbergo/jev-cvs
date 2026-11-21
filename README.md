# TypeSafe Guardrail Studio

Demo: a **non-autoregressive decision model (TypeSafe Jev / "System One")** acting as the
guardrail layer of an AI gateway. **No regex, no parsing** — every guardrail is one short
yes/no question the model answers with a calibrated probability, and the gateway decides in code.

21 rules + a threat-vector choice + a severity score are answered in **one HTTP call, ~200 ms**.

## Run

```bash
cp .env.example .env            # put your TYPESAFE_API_KEY in .env
bun install
PORT=3100 bun run dev           # pick any free port (3000 is often taken)
open http://localhost:3100
```

`bun run presets` (server up on `$PORT`) verifies every rule **alone** (only that rule sent)
and then the **full battery** on all 21 presets + 4 negatives, printing noul per rule.

## The configuration surface is the question

Every rule is the same shape, whatever its group — `src/data/controlPlaneRules.ts`:

```ts
rule({
  id: "social_security_number", name: "Social Security Number", group: "PII",
  rule:   "US SSN in any format (123-45-6789, 123456789).",          // shown in UI
  sample: "Please verify payroll ... Social Security Number 123-45-6789.", // Test button
  ask:    "Does `request.prompt` contain a US Social Security Number?",
  yes:    "A 9-digit number presented as an SSN / social security number.",
  no:     "No SSN. Numbers labelled TIN, EIN, phone or order ID are not SSNs.",
  examples: ["my SSN is 078-05-1120", "social security no. 219099999"],
})
```

which becomes one **Noul** in the request (`src/guardrails/typesafe.ts`):

```json
"social_security_number": {
  "type": "noul",
  "instructions": { "question": "Does `request.prompt` contain ...?", "examples_of_yes": ["...", "..."] },
  "criteria": { "true": "A 9-digit number presented as an SSN ...", "false": "No SSN. ..." }
}
```

Groups (PII · Credentials & Secrets · Injection & Execution · Harmful Content) only organise
the UI; all rules are enabled and evaluated independently. Short questions + two yes-examples
is what makes it fast and accurate — a vague question costs probability, not latency.

## Request / decision

```
state     = { request: { prompt }, gateway: { stage: "input", active_rules: [...] } }   (nested JSON)
questions = 21 × noul (one per rule) + primary_threat_vector (choice) + threat_severity_rubric (score 0..3)
POST https://api.typesafe.ai/v1/systemone  { model: "jev-latest", state, questions }

per rule (code, not model):
  noul >= 0.70            → action: Block mode halts, Alert mode forwards with notice
  0.35 <= noul < 0.70     → review band; escalated to action if severity >= 2.0
  noul < 0.35             → pass
precedence: block > alert > allow
```

Thresholds follow the docs' guardrail cookbook ("strict": review 0.35 / action 0.70, severity 2.0)
and live in `TYPESAFE_THRESHOLDS`. `confidence` is never used as a gate.

Rules are edited live in the UI (mode + question text) and travel with each `/api/evaluate`
request; any rule change re-evaluates the current payload so every panel stays in sync.

## Files

- `server.ts` — Express API: `/api/evaluate` (model-only verdict), `/api/typesafe-status`, `/api/test-suite` (legacy regex fixtures tab)
- `src/data/controlPlaneRules.ts` — the 21 rules (question, criteria, examples, sample prompt)
- `src/guardrails/typesafe.ts` — state builder, question builder, thresholds (single place)
- `scripts/run-presets.ts` — live one-by-one + battery verification
