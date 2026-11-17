// Jev guardrail demo — single-file Node server, no dependencies.
//
//   POST /api/run {prompt, rules}  → walks the rules in order, ONE API call per rule
//        Enforce + yes → BLOCK, stop.   Alert + yes → notify, continue.   Ignore → skipped.
//   GET  /api/status                → GET https://api.typesafe.ai/v1/models with the key
//   GET  /api/rules                 → the 21 rules (editable in the page, sent back with each run)
//
// The page gets, for every rule asked: the exact request body sent and the exact response body returned.
import http from "node:http";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT ?? 3000);
const API = (process.env.TYPESAFE_API_BASE ?? "https://api.typesafe.ai/v1").replace(/\/$/, "");
const MODEL = process.env.TYPESAFE_MODEL ?? "jev-latest";
const THRESHOLD = Number(process.env.THRESHOLD ?? 0.7); // noul >= THRESHOLD means "yes"
const KEY = (process.env.TYPESAFE_API_KEY ?? "").trim();

const RULES = JSON.parse(readFileSync(join(__dirname, "rules.json"), "utf8"));
const INDEX = readFileSync(join(__dirname, "index.html"));

function questionFor(rule) {
  // One Noul per rule: short question + yes/no criteria + examples of a yes.
  return {
    type: "noul",
    instructions: { question: rule.ask, examples_of_yes: rule.examples },
    criteria: { true: rule.yes, false: rule.no },
  };
}

async function askJev(prompt, rule) {
  const body = { model: MODEL, state: prompt, questions: { [rule.id]: questionFor(rule) } };
  const t0 = performance.now();
  const res = await fetch(`${API}/systemone`, {
    method: "POST",
    headers: { authorization: `Bearer ${KEY}`, "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  const ms = Math.round(performance.now() - t0);
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = { raw: text }; }
  return { request: body, response: json, httpStatus: res.status, ms, ok: res.ok };
}

async function run(prompt, rules) {
  const steps = [];
  let verdict = "ALLOW";
  let stoppedAt = null;
  const alerts = [];
  for (const rule of rules) {
    if (rule.mode === "Ignore") {
      steps.push({ rule: rule.id, name: rule.name, mode: rule.mode, outcome: "skipped" });
      continue;
    }
    let call;
    try {
      call = await askJev(prompt, rule);
    } catch (e) {
      steps.push({ rule: rule.id, name: rule.name, mode: rule.mode, outcome: "error", error: String(e) });
      verdict = "ERROR"; stoppedAt = rule.id; break;
    }
    const answer = call.response?.answers?.[rule.id];
    const p = answer && typeof answer.noul === "number" ? answer.noul : null;
    if (!call.ok || p === null) {
      steps.push({ rule: rule.id, name: rule.name, mode: rule.mode, outcome: "error", ...call });
      verdict = "ERROR"; stoppedAt = rule.id; break;
    }
    const yes = p >= THRESHOLD;
    let outcome = "no";
    if (yes && rule.mode === "Block") outcome = "BLOCK";
    else if (yes) outcome = "ALERT";
    steps.push({ rule: rule.id, name: rule.name, mode: rule.mode, p, yes, outcome, model: call.response.model, ...call });
    if (outcome === "ALERT") { alerts.push(rule.id); if (verdict === "ALLOW") verdict = "ALERT"; }
    if (outcome === "BLOCK") { verdict = "BLOCK"; stoppedAt = rule.id; break; }
  }
  const asked = steps.filter((s) => s.ms !== undefined);
  return {
    verdict, stoppedAt, alerts, threshold: THRESHOLD, model: asked[0]?.model ?? MODEL,
    calls: asked.length, totalMs: asked.reduce((a, s) => a + s.ms, 0),
    notEvaluated: rules.slice(steps.length).map((r) => r.id),
    steps,
  };
}

const json = (res, status, body) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
async function readJson(req) { const c = []; for await (const x of req) c.push(x); return JSON.parse(Buffer.concat(c).toString("utf8") || "{}"); }

http.createServer(async (req, res) => {
  const path = new URL(req.url, "http://x").pathname;
  try {
    if (req.method === "GET" && path === "/") { res.writeHead(200, { "content-type": "text/html" }); return res.end(INDEX); }
    if (req.method === "GET" && path === "/api/rules") return json(res, 200, { rules: RULES, threshold: THRESHOLD, model: MODEL, endpoint: `${API}/systemone` });
    if (req.method === "GET" && path === "/api/status") {
      if (!KEY) return json(res, 200, { connected: false, error: "TYPESAFE_API_KEY not set" });
      try {
        const r = await fetch(`${API}/models`, { headers: { authorization: `Bearer ${KEY}` }, signal: AbortSignal.timeout(10000) });
        const t = await r.text();
        return json(res, 200, { connected: r.ok, httpStatus: r.status, endpoint: `${API}/models`, body: (() => { try { return JSON.parse(t); } catch { return t; } })() });
      } catch (e) { return json(res, 200, { connected: false, error: String(e) }); }
    }
    if (req.method === "POST" && path === "/api/run") {
      const b = await readJson(req);
      const prompt = typeof b.prompt === "string" ? b.prompt : "";
      if (!prompt.trim()) return json(res, 400, { error: "prompt is required" });
      if (!KEY) return json(res, 400, { error: "TYPESAFE_API_KEY not set — run with -e TYPESAFE_API_KEY=..." });
      const rules = Array.isArray(b.rules) && b.rules.length ? b.rules : RULES;
      return json(res, 200, await run(prompt, rules));
    }
    json(res, 404, { error: "not found" });
  } catch (e) { json(res, 500, { error: String(e) }); }
}).listen(PORT, "0.0.0.0", () => console.log(`Jev guardrail demo on http://localhost:${PORT}  (${API}, model ${MODEL}, threshold ${THRESHOLD}, key ${KEY ? "set" : "MISSING"})`));
