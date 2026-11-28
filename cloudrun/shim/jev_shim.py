"""Local Jev (TypeSafe System One) adapter -> Vertex AI DiffusionGemma (Model Garden vLLM).

Runs on 127.0.0.1 only, on the demo VM. Same API as api.typesafe.ai:
  GET  /v1/models
  POST /v1/systemone   (noul / choice / score; box -> 400, the demo does not use it)

Each question becomes one chat request; all questions of a call go to Vertex as one
batched :predict. Probabilities come from the first answer token's top logprobs over
single-token labels; if logprobs are unavailable the parsed label gets 0.97.

Env:
  VERTEX_PREDICT_URL  https://<dedicated-dns>/v1/projects/P/locations/L/endpoints/E:predict
  JEV_SHIM_KEY_FILE   file holding the Bearer key the demo sends (default ~/.jev-shim-key)
  JEV_MODEL_NAME      name returned by /v1/models (default jev-latest)
"""
from __future__ import annotations

import asyncio
import collections
import datetime as dt
import hashlib
import hmac
import json
import logging
import math
import os
import re
import string
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import google.auth
import google.auth.transport.requests
import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

import schemas as S

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("jev-shim")

PREDICT_URL = os.environ["VERTEX_PREDICT_URL"]
KEY = Path(os.path.expanduser(os.getenv("JEV_SHIM_KEY_FILE", "~/.jev-shim-key"))).read_text().strip()
MODEL_NAME = os.getenv("JEV_MODEL_NAME", "cvs-jv1")
ALIASES = {MODEL_NAME}
BATCH = int(os.getenv("JEV_BATCH", "64"))
MAX_TOKENS = int(os.getenv("JEV_MAX_TOKENS", "24"))
TOP_LOGPROBS = int(os.getenv("JEV_TOP_LOGPROBS", "20"))

CHOICE_LABELS = list(string.ascii_uppercase) + list(string.ascii_lowercase)
SCORE_LABELS = list(string.digits)
SYSTEM = ("You are Jev, a precise classifier. Read the STATE and answer the QUESTION with only the "
          "requested single label. No explanation.")

_creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
_http = httpx.AsyncClient(timeout=httpx.Timeout(180.0, connect=15.0))
app = FastAPI(title="Jev local adapter", version="1.0.0")


def _token() -> str:
    if not _creds.valid:
        _creds.refresh(google.auth.transport.requests.Request())
    return _creds.token


def _auth(authorization: Optional[str]) -> None:
    k = (authorization or "")[7:] if (authorization or "").lower().startswith("bearer ") else ""
    if not k or not hmac.compare_digest(k, KEY):
        raise HTTPException(401, detail="Not authenticated")


# ------------------------------------------------------------------ confidence (docs)
def choice_conf(p: Sequence[float]) -> float:
    n = len(p)
    return 1.0 if n <= 1 else max(0.0, min(1.0, (max(p) - 1 / n) / (1 - 1 / n)))


def score_conf(p: Sequence[float]) -> float:
    n = len(p)
    if n <= 1:
        return 1.0
    m = max(range(n), key=lambda i: p[i])
    mad = sum(pi * abs(i - m) for i, pi in enumerate(p))
    unif = sum(abs(i - m) for i in range(n)) / n
    return 1.0 if unif == 0 else max(0.0, min(1.0, 1 - mad / unif))


# ----------------------------------------------------------------------- prompts
def _prompt(state: str, q) -> Tuple[str, List[str], List[str]]:
    """returns (user_text, labels, keys)"""
    ins = S.render_instructions(q.instructions)
    if isinstance(q, S.NoulQuestion):
        crit = f"\nY means: {q.criteria.true}\nN means: {q.criteria.false}" if q.criteria else ""
        return (f"STATE:\n{state}\n\nQUESTION:\n{ins}{crit}\n\nAnswer Y (yes) or N (no):", ["Y", "N"], ["Y", "N"])
    if isinstance(q, S.ChoiceQuestion):
        keys = list(q.criteria)
        if len(keys) > len(CHOICE_LABELS):
            raise HTTPException(400, detail=f"choice supports at most {len(CHOICE_LABELS)} options here")
        labs = CHOICE_LABELS[: len(keys)]
        opts = "\n".join(f"{l}) {k}: {q.criteria[k]}" for l, k in zip(labs, keys))
        return (f"STATE:\n{state}\n\nQUESTION:\n{ins or 'Which option best applies?'}\n\nOPTIONS:\n{opts}\n\n"
                "Answer with the single option letter:", labs, keys)
    if isinstance(q, S.ScoreQuestion):
        n = len(q.criteria)
        labs = SCORE_LABELS[:n]
        lv = "\n".join(f"{l}: {d}" for l, d in zip(labs, q.criteria))
        return (f"STATE:\n{state}\n\nQUESTION:\n{ins or 'Rate the state.'}\n\nLEVELS (0 lowest, {n-1} highest):\n{lv}\n\n"
                "Answer with the single level number:", labs, [str(i) for i in range(n)])
    raise HTTPException(400, detail="box questions are not supported by this deployment")


def _instance(user: str) -> Dict[str, Any]:
    return {"@requestFormat": "chatCompletions",
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
            "max_tokens": MAX_TOKENS, "temperature": 0.0,
            "logprobs": True, "top_logprobs": TOP_LOGPROBS}


# ---------------------------------------------------------------- answer parsing
_STRIP = re.compile(r"<\|channel\>thought.*?<channel\|>|<[^>]{1,24}>", re.S)


def _label_probs(pred: Any, labels: List[str]) -> Tuple[List[float], int, str]:
    choice = (pred.get("choices") or [{}])[0] if isinstance(pred, dict) else {}
    text = (choice.get("message") or {}).get("content") or (pred if isinstance(pred, str) else "")
    usage = (pred.get("usage") or {}) if isinstance(pred, dict) else {}
    out_tok = int(usage.get("completion_tokens", 0))
    lp = ((choice.get("logprobs") or {}).get("content")) or []
    for step in lp:  # first step whose token is one of the labels
        tok = (step.get("token") or "").strip()
        if tok in labels:
            mass = {l: 0.0 for l in labels}
            for alt in step.get("top_logprobs") or []:
                t = (alt.get("token") or "").strip()
                if t in mass:
                    mass[t] += math.exp(alt.get("logprob", -1e9))
            if tok in mass and mass[tok] == 0.0:
                mass[tok] = math.exp(step.get("logprob", 0.0))
            z = sum(mass.values()) or 1.0
            return [mass[l] / z for l in labels], out_tok, "logprobs"
    clean = _STRIP.sub("", str(text)).strip()
    for l in labels:
        if clean.startswith(l):
            rest = (1 - 0.97) / max(1, len(labels) - 1)
            return [0.97 if x == l else rest for x in labels], out_tok, "text"
    return [1 / len(labels)] * len(labels), out_tok, "none"


# Concurrency 1: on this vLLM build, concurrent requests to the block-diffusion model are batched
# into shared canvases and flip answers (SSN rule: 0.9999 alone -> 0.0 at concurrency 8).
_sem = asyncio.Semaphore(int(os.getenv("JEV_CONCURRENCY", "1")))


async def _post(inst: Dict[str, Any]) -> httpx.Response:
    return await _http.post(PREDICT_URL, json={"instances": [inst]},
                            headers={"Authorization": f"Bearer {_token()}"})


_cache: "collections.OrderedDict[str, Any]" = collections.OrderedDict()
CACHE_MAX = int(os.getenv("JEV_CACHE_MAX", "20000"))
_stats = {"hit": 0, "miss": 0}


async def _predict_one(inst: Dict[str, Any]) -> Any:
    # Exact-match cache: temperature is 0, so an identical prompt gives an identical answer.
    ck = hashlib.sha256(json.dumps(inst, sort_keys=True).encode()).hexdigest()
    if ck in _cache:
        _cache.move_to_end(ck)
        _stats["hit"] += 1
        return _cache[ck]
    _stats["miss"] += 1
    out = await _predict_uncached(inst)
    if out is not None:
        _cache[ck] = out
        if len(_cache) > CACHE_MAX:
            _cache.popitem(last=False)
    return out


async def _predict_uncached(inst: Dict[str, Any]) -> Any:
    # Model Garden's chatCompletions wrapper handles exactly one instance per request and
    # intermittently 500s ("list index out of range"): retry, then retry without logprobs,
    # then give up on this one question only (neutral answer) instead of failing the battery.
    async with _sem:
        last = ""
        for attempt, payload in enumerate([inst, inst, inst,
                                           {k: v for k, v in inst.items() if k not in ("logprobs", "top_logprobs")}]):
            r = await _post(payload)
            if r.status_code == 200:
                p = r.json().get("predictions")
                return p[0] if isinstance(p, list) else p
            last = f"HTTP {r.status_code}: {r.text[:200]}"
            if r.status_code in (401, 403, 404):
                raise HTTPException(502, detail=f"Vertex {last}")
            await asyncio.sleep(0.3 * (attempt + 1))
        log.warning("question failed after retries: %s", last)
        return None


async def _predict(instances: List[Dict[str, Any]]) -> List[Any]:
    _token()  # refresh once before fan-out
    return await asyncio.gather(*(_predict_one(i) for i in instances))


# -------------------------------------------------------------------------- routes
@app.get("/v1/models")
def models(authorization: Optional[str] = Header(default=None)):
    _auth(authorization)
    return S.ModelMetadataList(models=[S.ModelMetadata(
        name=MODEL_NAME, release_date=dt.date(2026, 10, 14),
        description="DiffusionGemma-26B-A4B-it on Vertex AI (Model Garden vLLM) via local Jev adapter")])


@app.post("/v1/systemone", response_model=S.SystemOneResponse)
async def systemone(body: S.SystemOneRequest, authorization: Optional[str] = Header(default=None)):
    _auth(authorization)
    if body.model not in ALIASES:
        raise HTTPException(400, detail=f"unknown model `{body.model}`; see GET /v1/models")
    if body.assets:
        raise HTTPException(400, detail="image assets are not supported by this deployment")
    state = body.state if isinstance(body.state, str) else json.dumps(body.state, indent=2, ensure_ascii=False)
    plan = [(k, q, *_prompt(state, q)) for k, q in body.questions.items()]
    if os.getenv("JEV_DUMP"):
        Path(os.path.expanduser("~/jev-shim/last_instances.json")).write_text(
            json.dumps([{"key": k, "instance": _instance(u)} for k, _, u, _, _ in plan]))
    t0 = time.perf_counter()
    preds = await _predict([_instance(user) for _, _, user, _, _ in plan])
    answers: Dict[str, Any] = {}
    out_total, modes = 0, {}
    for (key, q, user, labels, keys), pred in zip(plan, preds):
        p, out_tok, mode = _label_probs(pred, labels)
        out_total += out_tok
        modes[mode] = modes.get(mode, 0) + 1
        if isinstance(q, S.NoulQuestion):
            answers[key] = S.NoulAnswer(noul=round(p[0], 4))
        elif isinstance(q, S.ChoiceQuestion):
            probs = dict(zip(keys, p))
            answers[key] = S.ChoiceAnswer(choice=max(probs, key=probs.get), confidence=round(choice_conf(p), 4),
                                          probabilities={k: round(v, 4) for k, v in probs.items()})
        else:
            answers[key] = S.ScoreAnswer(score=round(sum(i * x for i, x in enumerate(p)), 4),
                                         confidence=round(score_conf(p), 4),
                                         legend={str(i): d for i, d in enumerate(q.criteria)},
                                         probabilities={k: round(v, 4) for k, v in zip(keys, p)})
    in_tok = sum(len(u) // 4 for _, _, u, _, _ in plan)  # estimate; vLLM usage covers output
    log.info("systemone q=%d %.0fms modes=%s cache=%s", len(plan), (time.perf_counter() - t0) * 1000, modes, _stats)
    return S.SystemOneResponse(model=MODEL_NAME, answers=answers,
                               usage=S.Usage(input_tokens=in_tok, output_tokens=out_total))


@app.exception_handler(HTTPException)
async def _err(_: Request, e: HTTPException):
    return JSONResponse({"detail": e.detail}, status_code=e.status_code)
