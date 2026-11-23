import React from "react";

/** What Jev lets you configure, from docs.typesafe.ai. Shared by the main view and Inside Jev. */
const SECTIONS: { title: string; items: React.ReactNode[] }[] = [
  {
    title: "Per question",
    items: [
      <><strong>Type.</strong> Noul (yes/no, returns a probability), Choice (one of several options), Score (a position on a scale you describe), Box (a location in an image; Jev 1.14 only).</>,
      <><strong>Instructions.</strong> The question, as plain text or as structured fields.</>,
      <><strong>Criteria.</strong> What yes and no mean (Noul), the options (Choice), or the levels (Score).</>,
    ],
  },
  {
    title: "Per request",
    items: [
      <><strong>State.</strong> What Jev reads: text, JSON, or PNG and JPEG images.</>,
      <><strong>Model.</strong> jev-latest, jev-preview, or a fixed version such as jev-1.14.0.</>,
      <><strong>Long context.</strong> An optional header raises the limit to 262,000 tokens (default 64,000 per request and 32,000 per question). It is slower and less accurate.</>,
    ],
  },
  {
    title: "Per account",
    items: [<>Rate limits, set in the TypeSafe console.</>],
  },
  {
    title: "Not configurable",
    items: [
      <>The model is not trained on customer data: no fine-tuning and no LoRA. Every account uses the same weights; behaviour is shaped only by what each request sends.</>,
      <>Thresholds do not exist in Jev. Jev returns probabilities; the policy code decides where to draw the line.</>,
    ],
  },
];

export default function JevConfig({ className = "" }: { className?: string }) {
  return (
    <section className={`card p-7 ${className}`}>
      <div className="eyebrow mb-2">Reference</div>
      <h2 className="section-title">What can be configured in Jev</h2>
      <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-x-10 gap-y-7">
        {SECTIONS.map((s) => (
          <div key={s.title}>
            <h3 className="text-[15px] font-semibold text-ink mb-2.5">{s.title}</h3>
            <ul className="space-y-2.5 text-[15px] leading-relaxed text-ink-2 [&_strong]:font-semibold [&_strong]:text-ink">
              {s.items.map((item, i) => (
                <li key={i} className="flex gap-3">
                  <span className="mt-[0.6rem] w-1 h-1 rounded-full bg-ink-3 shrink-0" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <p className="mt-7 pt-5 border-t border-line text-sm text-ink-3">Source: docs.typesafe.ai (Models and Primitives pages).</p>
    </section>
  );
}
