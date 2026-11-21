import React, { useEffect, useMemo, useRef, useState } from "react";

/** One round-trip of the browser → policy server call, as a devtools Network row would show it. */
export interface WireEntry {
  id: number;
  startedAt: number;
  method: "POST";
  url: string;
  request: unknown;
  status?: number;
  ms?: number;
  response?: unknown;
  error?: string;
}

type Side = "TX" | "RX";

function sizeOf(v: unknown): string {
  try {
    const b = new TextEncoder().encode(JSON.stringify(v)).length;
    return b < 1024 ? `${b} B` : `${(b / 1024).toFixed(1)} KB`;
  } catch {
    return "?";
  }
}

function clock(t: number): string {
  const d = new Date(t);
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

// JSON syntax colouring without a dependency: strings are consumed whole, so words and
// digits inside them are never re-matched as literals.
const TOKEN = /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

function Json({ value }: { value: unknown }) {
  const nodes = useMemo(() => {
    const text = JSON.stringify(value, null, 2) ?? "";
    const out: React.ReactNode[] = [];
    let last = 0;
    let k = 0;
    for (const m of text.matchAll(TOKEN)) {
      const at = m.index ?? 0;
      if (at > last) out.push(text.slice(last, at));
      if (m[1] !== undefined) {
        if (m[2] !== undefined) {
          out.push(<span key={k++} className="text-sky-300">{m[1]}</span>, m[2]);
        } else {
          out.push(<span key={k++} className="text-amber-200">{m[1]}</span>);
        }
      } else if (m[3] !== undefined) {
        out.push(<span key={k++} className="text-rose-300">{m[3]}</span>);
      } else if (m[4] !== undefined) {
        out.push(<span key={k++} className="text-violet-300">{m[4]}</span>);
      }
      last = at + m[0].length;
    }
    if (last < text.length) out.push(text.slice(last));
    return out;
  }, [value]);
  return (
    <pre className="font-mono text-[12.5px] leading-[1.45] text-neutral-400 whitespace-pre-wrap" style={{ overflowWrap: "anywhere" }}>
      {nodes}
    </pre>
  );
}

const VERDICT: Record<string, { label: string; tone: string }> = {
  allow: { label: "ALLOW", tone: "text-emerald-300" },
  redact: { label: "ALERT", tone: "text-amber-300" },
  block: { label: "BLOCK", tone: "text-rose-300" },
};

/** Live view of the latest round-trip: what left the browser (TX) and what came back (RX). */
export default function LiveWire({ entry }: { entry: WireEntry | null }) {
  const [side, setSide] = useState<Side>("TX");
  const bodyRef = useRef<HTMLDivElement>(null);
  // Start every payload at the top: switching tabs or a new request should not keep the old scroll offset.
  useEffect(() => { bodyRef.current?.scrollTo(0, 0); }, [side, entry?.id]);

  const res = entry?.response as
    | { effectiveVerdict?: { decision?: string }; typesafeInternals?: { endpoint?: string; model?: string; requestPayload?: { questionCount?: number }; totalInputTokens?: number | null; totalOutputTokens?: number; decisionsLatencyMs?: number } }
    | undefined;
  const req = entry?.request as { prompt?: string; rules?: unknown[] } | undefined;
  const verdict = res?.effectiveVerdict?.decision ? VERDICT[res.effectiveVerdict.decision] : undefined;
  const pending = !!entry && entry.status === undefined && !entry.error;
  const origin = typeof window !== "undefined" ? window.location.origin : "";

  return (
    <div className="border border-neutral-700 rounded-md bg-neutral-900/60 overflow-hidden">
      {/* Header: tabs + the one-line summary of the latest round-trip */}
      <div className="px-4 py-2.5 border-b border-neutral-800 flex items-center gap-4">
        <div className="flex rounded border border-neutral-700 overflow-hidden shrink-0">
          {(["TX", "RX"] as Side[]).map((s) => (
            <button key={s} type="button" onClick={() => setSide(s)}
              className={`px-3 py-1 text-[13px] font-mono font-semibold cursor-pointer ${side === s ? (s === "TX" ? "bg-emerald-600 text-white" : "bg-sky-600 text-white") : "bg-[#0B0D11] text-neutral-400 hover:text-white"}`}>
              {s === "TX" ? "→ TX" : "← RX"}
            </button>
          ))}
        </div>
        <div className="min-w-0 flex-1 font-mono text-[13px] text-neutral-400 truncate">
          {!entry && <span className="text-neutral-600">no request yet — press Evaluate or Test</span>}
          {entry && side === "TX" && (
            <>
              <span className="text-neutral-600">#{entry.id} {clock(entry.startedAt)} · </span>
              <span className="text-emerald-400">{entry.method}</span> <span className="text-neutral-200">{origin}{entry.url}</span>
              <span className="text-neutral-600"> · {sizeOf(entry.request)} · prompt + {req?.rules?.length ?? 0} rules</span>
            </>
          )}
          {entry && side === "RX" && (
            <>
              <span className="text-neutral-600">#{entry.id} · </span>
              {pending && <span className="text-neutral-500 animate-pulse">waiting for the policy server…</span>}
              {!pending && (
                <>
                  <span className={entry.error || (entry.status ?? 0) >= 300 ? "text-rose-400" : "text-sky-400"}>{entry.error && !entry.status ? "ERR" : entry.status}</span>
                  <span className="text-neutral-200"> {entry.ms} ms</span>
                  {verdict && <span className={` ${verdict.tone}`}> · {verdict.label}</span>}
                  {res?.typesafeInternals && (
                    <span className="text-neutral-600"> · upstream {res.typesafeInternals.endpoint} · {res.typesafeInternals.model} · {res.typesafeInternals.requestPayload?.questionCount} questions · {res.typesafeInternals.decisionsLatencyMs} ms in Jev · {res.typesafeInternals.totalInputTokens ?? "?"}/{res.typesafeInternals.totalOutputTokens} tokens</span>
                  )}
                  {entry.response !== undefined && <span className="text-neutral-600"> · {sizeOf(entry.response)}</span>}
                </>
              )}
            </>
          )}
        </div>
        <span className={`shrink-0 flex items-center gap-1.5 text-[12px] ${pending ? "text-amber-300" : "text-emerald-400"}`}>
          <span className={`w-2 h-2 rounded-full ${pending ? "bg-amber-400 animate-pulse" : "bg-emerald-400"}`} />
          live
        </span>
      </div>

      {/* Body: the payload, one side at a time */}
      <div ref={bodyRef} className="max-h-[520px] overflow-auto bg-[#0B0D11] p-4">
        {!entry && <div className="text-sm text-neutral-600">The request body and the reply will appear here, exactly as sent on the wire.</div>}
        {entry && side === "TX" && <Json value={entry.request} />}
        {entry && side === "RX" && pending && <div className="text-sm text-neutral-500 animate-pulse">…</div>}
        {entry && side === "RX" && !pending && entry.error && entry.response === undefined && <div className="font-mono text-sm text-rose-300">{entry.error}</div>}
        {entry && side === "RX" && !pending && entry.response !== undefined && <Json value={entry.response} />}
      </div>
    </div>
  );
}
