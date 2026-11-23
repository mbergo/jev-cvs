# TypeSafe Guardrail Studio

A demo of a **non-autoregressive decision model** — TypeSafe's Jev ("System One") — acting as
the guardrail layer of an AI gateway. **No regex, no parsing.** Every guardrail is one short
yes/no question; Jev answers each with a calibrated probability, and the gateway decides in code.

44 rules + a threat-vector choice + a severity score are answered in **one HTTP call, ~250 ms**.

```
AI application ──prompt──▶ Policy server (this demo) ──one request, 32 questions──▶ Jev
                                    │                                               │
                                    ◀──────────── one probability per question ─────┘
                                    │
                           Policy code: compare each P(yes) with 0.70 / 0.35,
                           apply the rule's mode (Enforce · Alert · Ignore)
                                    │
                                    ▼
                           ALLOW · ALERT · BLOCK
```

## Run

### Docker (port 8080)

```bash
cp .env.example .env        # set TYPESAFE_API_KEY
make build                  # docker build -t jev-cvs .
make run                    # http://localhost:8080
make stop
```

`make logs`, `make restart` and `make status` do what they say. The image runs the server
in the same mode as `./start.sh` (Express + Vite middleware, `vite.config.ts` untouched);
the API key is injected at run time via `--env-file`, never baked into the image.

### Local

```bash
cp .env.example .env        # set TYPESAFE_API_KEY
bun install                 # or npm install
./start.sh                  # http://localhost:3100   (./start.sh 3200 for another port)
```

`./start.sh --test` starts the server, runs the enforce-mode calibration rounds and the
negative checks, then exits. `bun run presets` (server up on `$PORT`) verifies every rule
**alone** and then the **full battery** on all presets + negatives, printing the noul per rule.

## The question is the configuration

Every rule has the same shape, whatever its group — `src/data/controlPlaneRules.ts`:

```ts
rule({
  id: "social_security_number", name: "Social Security Number", group: "PII",
  rule:   "US SSN in any format (123-45-6789, 123456789).",                 // shown in UI
  sample: "Please verify payroll ... Social Security Number 123-45-6789.", // Test button
  ask:    "Does `request.prompt` contain a US Social Security Number?",
  yes:    "A 9-digit number presented as an SSN / social security number.",
  no:     "No SSN. Numbers labelled TIN, EIN, phone or order ID are not SSNs.",
  examples: ["my SSN is 078-05-1120", "social security no. 219099999"],
})
```

which becomes one **Noul** question in the request (`src/guardrails/typesafe.ts`):

```json
"social_security_number": {
  "type": "noul",
  "instructions": { "question": "Does `request.prompt` contain ...?", "examples_of_yes": ["...", "..."] },
  "criteria": { "true": "A 9-digit number presented as an SSN ...", "false": "No SSN. ..." }
}
```

Groups — PII · Credentials & Secrets · Confidential Data · Injection & Execution · Harmful
Content · Healthcare Conduct — only organise the UI; every rule is evaluated independently. Rules are edited live in
the UI (mode, question, criteria, examples, test prompt) and travel with each request, so a
reworded question re-scores the current prompt immediately. Short questions plus two examples of
"yes" is what makes it fast and accurate: a vague question costs probability, not latency.

A new format (a fourth employee-ID scheme, a new vendor's key prefix) is one more string in
`examples`, not a new pattern and a deploy.

## Request and decision

```
state     = { request: { prompt }, gateway: { stage: "input", active_rules: [...] } }
questions = 44 × noul (one per rule) + primary_threat_vector (choice) + threat_severity_rubric (score 0..3)
POST https://api.typesafe.ai/v1/systemone   { model: "jev-latest", state, questions }

per rule (code, not model):
  noul >= 0.70            → action: Enforce mode halts, Alert mode forwards with notice
  0.35 <= noul < 0.70     → review band; escalated to action if severity >= 2.0
  noul < 0.35             → pass
precedence: block > alert > allow
```

Thresholds follow the TypeSafe guardrails cookbook ("strict": review 0.35 / action 0.70,
severity 2.0) and live in one place, `TYPESAFE_THRESHOLDS`. Jev returns probabilities only;
it never makes the decision and `confidence` is never used as a gate.

## The UI

- **Prompt** — type anything, or pick one of the 44 rule presets / safe negatives.
- **Verdict banner** — ALLOW / ALERT / BLOCK, the rules that fired with their P(yes), the threat
  vector and the severity distribution, Jev's latency for the whole battery.
- **Guardrails** — every rule with a live P(yes) bar against the 0.70 tick, a Test button, Edit,
  and the Enforce · Alert · Ignore switch. "All Enforce / Alert / Ignore" at the top.
- **Run all 44 presets** — each rule's sample prompt through the full battery, pass/fail per group.
- **Live wire** (toggle, on by default) — the latest browser → policy-server round-trip exactly as it went over
  the wire: `→ TX` the request body, `← RX` the reply, with status, latency, size and the upstream
  Jev endpoint/model/token usage. Only real traffic; it streams during the batch run.
- **Inside Jev** (toggle) — the same evaluation explained step by step: what was sent, what came
  back, how each probability became a decision.
- **Raw data** — the exact `POST /v1/systemone` body and Jev's raw answers, collapsible.

## Files

| Path | What |
|---|---|
| `server.ts` | Express API — `/api/evaluate` (model-only verdict), `/api/typesafe-status`, `/api/test-suite`; serves the UI through Vite middleware |
| `src/App.tsx` | The studio UI |
| `src/components/LiveWire.tsx` | Live request/response panel |
| `src/components/InsideJev.tsx` | Step-by-step explanation panel |
| `src/data/controlPlaneRules.ts` | The 44 rules — question, criteria, examples, sample prompt, mode |
| `src/guardrails/typesafe.ts` | State builder, question builder, thresholds (single place) |
| `scripts/run-presets.ts` | Live one-by-one + battery verification |
| `scripts/run-enforce-rounds.ts`, `scripts/check-negatives.ts` | Calibration rounds and negative checks used by `./start.sh --test` |
| `start.sh` | Local launcher: frees the port, checks `.env`, runs `tsx server.ts` |
| `Dockerfile`, `Makefile` | Container build/run on 8080 |

## Environment

| Variable | Required | Notes |
|---|---|---|
| `TYPESAFE_API_KEY` | yes | TypeSafe API key; the server refuses to start a request without it, no fallback |
| `TYPESAFE_MODEL` | no | `jev-latest` (default) or `jev-preview` |
| `PORT` | no | 3100 via `start.sh`, 8080 in the container |

Docs: https://docs.typesafe.ai (System One API, Noul/Choice/Score primitives, guardrails cookbook).
