import { INITIAL_CONTROL_PLANE_RULES as R, NEGATIVE_PRESET_PROMPTS as N } from "../src/data/controlPlaneRules";
import { TYPESAFE_THRESHOLDS as T } from "../src/guardrails/typesafe";
const base=`http://localhost:3100`;
const rows:any[]=[]; let fail=0;
for (const p of N) {
  const res=await fetch(`${base}/api/evaluate`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({prompt:p.prompt,rules:R})});
  const j:any=await res.json();
  const fired=Object.entries(j.typesafeInternals.rawAnswers as Record<string,any>)
    .filter(([k,a])=>a.type==="noul"&&a.noul>=T.noulAction).map(([k,a])=>`${k}=${a.noul.toFixed(2)}`);
  const ok=j.effectiveVerdict.decision==="allow";
  if(!ok) fail++;
  rows.push({preset:p.id,decision:j.effectiveVerdict.decision,falsePositives:fired.join(", ")||"-",ok:ok?"PASS":"FAIL"});
}
console.table(rows); console.log("falsos positivos:",fail);
process.exit(fail?1:0);
