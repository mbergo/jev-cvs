# jev-cvs — TypeSafe Jev as an AI-gateway guardrail

Demo that a **non-autoregressive model** (TypeSafe Jev, "System One") can act as the guardrail layer of
an AI gateway. 21 rules, each one yes/no question. The model returns P(yes); the code decides:

| Rule mode | P(yes) ≥ 0.7 | result |
|---|---|---|
| Enforce | yes | **BLOCK** — stop, later rules not asked, prompt never reaches the LLM |
| Alert | yes | notify, keep going |
| Ignore | — | never asked |

Rules are asked **one API call per rule, in order**. The page shows every call's exact request and response.

## Quick start

```bash
export TYPESAFE_API_KEY=your_key

# Docker
docker build -t jev-guardrail docker
docker run --rm -p 3100:3000 -e TYPESAFE_API_KEY=$TYPESAFE_API_KEY jev-guardrail
# → http://localhost:3100

# Test mode, no Docker (plain node, zero dependencies)
PORT=3100 node docker/server.js

# Live accuracy run against a running server: 21 attack prompts + 5 safe ones, all rules Enforce
node docker/test.mjs http://localhost:3100
```

`docker/` is self-contained: `server.js` (no dependencies), `rules.json` (the 21 rules — edit the
question, the yes/no criteria and the examples; that is the whole configuration), `index.html`.

## Last live run (jev-1.14.0, 2026-11-17)

21/21 attack prompts blocked at the right rule (P(yes) 0.90–0.99), 5/5 safe prompts allowed,
including near-misses `rm -rf ./build` (0.19) and an SSN prompt against the TIN rule (0.23).
~70–200 ms per call.

## API

`POST https://api.typesafe.ai/v1/systemone` — docs: https://docs.typesafe.ai

```json
{"model":"jev-latest","state":"<prompt>","questions":{"<rule>":{"type":"noul",
  "instructions":{"question":"Does the message contain a US Social Security Number?","examples_of_yes":["my SSN is 078-05-1120"]},
  "criteria":{"true":"A 9-digit number presented as an SSN.","false":"No SSN. TIN, EIN, phone or order IDs are not SSNs."}}}}
```
→ `{"model":"jev-1.14.0","answers":{"<rule>":{"type":"noul","noul":0.99}}}`

## Studio (Vite UI in `src/`)

`bun install && PORT=3102 bun run dev` — the original control-plane UI (`server.ts` + `src/`).
