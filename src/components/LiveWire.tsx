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
          out.push(<span key={k++} className="text-term-key">{m[1]}</span>, m[2]);
        } else {
          out.push(<span key={k++} className="text-term-string">{m[1]}</span>);
        }
      } else if (m[3] !== undefined) {
        out.push(<span key={k++} className="text-term-literal">{m[3]}</span>);
      } else if (m[4] !== undefined) {
        out.push(<span key={k++} className="text-term-number">{m[4]}</span>);
      }
      last = at + m[0].length;
    }
    if (last < text.length) out.push(text.slice(last));
    return out;
  }, [value]);
  return (
    <pre className="font-mono text-[12.5px] leading-[1.45] text-term-ink whitespace-pre-wrap" style={{ overflowWrap: "anywhere" }}>
      {nodes}
    </pre>
  );
}

const VERDICT: Record<string, { label: string; tone: string }> = {
  allow: { label: "ALLOW", tone: "text-allow" },
  redact: { label: "ALERT", tone: "text-alert" },
  block: { label: "BLOCK", tone: "text-block" },
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
    <div className="card overflow-hidden">
      {/* Header: tabs + the one-line summary of the latest round-trip */}
      <div className="px-6 py-4 border-b border-line flex items-center gap-4">
        <div className="flex rounded-[3px] border border-ink overflow-hidden shrink-0">
          {(["TX", "RX"] as Side[]).map((s) => (
            <button key={s} type="button" onClick={() => setSide(s)}
              className={`px-3 py-1 text-[13px] font-mono font-semibold cursor-pointer ${side === s ? (s === "TX" ? "bg-ink text-canvas" : "bg-review text-white") : "bg-surface text-ink-2 hover:text-ink"}`}>
              {s === "TX" ? "→ TX" : "← RX"}
            </button>
          ))}
        </div>
        <div className="min-w-0 flex-1 font-mono text-[13px] text-ink-2 truncate">
          {!entry && <span className="text-ink-3">no request yet — press Evaluate or Test</span>}
          {entry && side === "TX" && (
            <>
              <span className="text-ink-3">#{entry.id} {clock(entry.startedAt)} · </span>
              <span className="text-allow">{entry.method}</span> <span className="text-ink">{origin}{entry.url}</span>
              <span className="text-ink-3"> · {sizeOf(entry.request)} · prompt + {req?.rules?.length ?? 0} rules</span>
            </>
          )}
          {entry && side === "RX" && (
            <>
              <span className="text-ink-3">#{entry.id} · </span>
              {pending && <span className="text-ink-3 animate-pulse">waiting for the policy server…</span>}
              {!pending && (
                <>
                  <span className={entry.error || (entry.status ?? 0) >= 300 ? "text-block" : "text-review"}>{entry.error && !entry.status ? "ERR" : entry.status}</span>
                  <span className="text-ink"> {entry.ms} ms</span>
                  {verdict && <span className={` ${verdict.tone}`}> · {verdict.label}</span>}
                  {res?.typesafeInternals && (
                    <span className="text-ink-3"> · upstream {res.typesafeInternals.endpoint} · {res.typesafeInternals.model} · {res.typesafeInternals.requestPayload?.questionCount} questions · {res.typesafeInternals.decisionsLatencyMs} ms in Jev · {res.typesafeInternals.totalInputTokens ?? "?"}/{res.typesafeInternals.totalOutputTokens} tokens</span>
                  )}
                  {entry.response !== undefined && <span className="text-ink-3"> · {sizeOf(entry.response)}</span>}
                </>
              )}
            </>
          )}
        </div>
        <span className={`shrink-0 flex items-center gap-1.5 text-[12px] ${pending ? "text-alert" : "text-allow"}`}>
          <span className={`w-2 h-2 rounded-full ${pending ? "bg-alert animate-pulse" : "bg-allow"}`} />
          live
        </span>
      </div>

      {/* Body: the payload, one side at a time */}
      <div ref={bodyRef} className="max-h-[520px] overflow-auto bg-term px-6 py-5">
        {!entry && <div className="text-sm text-term-muted">The request body and the reply will appear here, exactly as sent on the wire.</div>}
        {entry && side === "TX" && <Json value={entry.request} />}
        {entry && side === "RX" && pending && <div className="text-sm text-term-muted animate-pulse">…</div>}
        {entry && side === "RX" && !pending && entry.error && entry.response === undefined && <div className="font-mono text-sm text-term-err">{entry.error}</div>}
        {entry && side === "RX" && !pending && entry.response !== undefined && <Json value={entry.response} />}
      </div>
    </div>
  );
}
