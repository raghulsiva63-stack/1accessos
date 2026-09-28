"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { ArrowRight, BookOpen, ChevronDown, CircleHelp, ExternalLink, LifeBuoy, Mail, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { FAQ, GUIDES, HELP_CATEGORIES, type Guide, type HelpView } from "@/lib/help/guides";

export function HelpCenter({ onNavigate }: { onNavigate: (view: HelpView) => void }) {
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<Guide["category"] | "all">("all");
  const [open, setOpen] = useState<string | null>("choose-plan");

  const results = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return GUIDES.filter((guide) => (category === "all" || guide.category === category)
      && (!needle || [guide.title, guide.summary, ...guide.steps, ...(guide.tips ?? [])].join(" ").toLowerCase().includes(needle)));
  }, [category, query]);

  return <div className="feature-page help-center">
    <div className="help-hero">
      <div><span className="status-pill"><LifeBuoy /> Help &amp; guides</span><h2>How can we help?</h2><p>Short, step-by-step guides for everything in Passkey-X. Each guide can take you straight to the right screen.</p></div>
      <label className="help-search"><Search /><span className="sr-only">Search the guides</span><input type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search, for example “change plan” or “forgot password”" /></label>
    </div>

    <div className="help-chips" role="group" aria-label="Topics">
      <button type="button" className={category === "all" ? "active" : ""} onClick={() => setCategory("all")}>All topics</button>
      {HELP_CATEGORIES.map((entry) => <button key={entry.id} type="button" className={category === entry.id ? "active" : ""} onClick={() => setCategory(entry.id)}>{entry.title}</button>)}
    </div>

    {results.length === 0 && <div className="help-empty"><CircleHelp /><p>No guide matches “{query}”. Try another word, or contact us below.</p></div>}

    <ul className="help-guides">{results.map((guide) => {
      const expanded = open === guide.id;
      const opens = guide.opens;
      return <li key={guide.id} className={expanded ? "open" : ""}>
        <button type="button" className="help-guide-head" aria-expanded={expanded} onClick={() => setOpen(expanded ? null : guide.id)}>
          <BookOpen /><span><strong>{guide.title}</strong><small>{guide.summary}</small></span><ChevronDown />
        </button>
        {expanded && <div className="help-guide-body">
          <ol>{guide.steps.map((step) => <li key={step}>{step}</li>)}</ol>
          {guide.tips && <div className="help-tips">{guide.tips.map((tip) => <p key={tip}><strong>Tip:</strong> {tip}</p>)}</div>}
          {opens && <Button size="sm" onClick={() => onNavigate(opens.view)}>{opens.label} <ArrowRight /></Button>}
        </div>}
      </li>;
    })}</ul>

    <section className="help-faq">
      <h3>Common questions</h3>
      <dl>{FAQ.map(([question, answer]) => <div key={question}><dt>{question}</dt><dd>{answer}</dd></div>)}</dl>
    </section>

    <section className="help-contact">
      <div><h3>Still stuck?</h3><p>Our team answers within one business day. Never send us your vault password or recovery key: we will never ask for them.</p></div>
      <div className="help-contact-actions">
        <Link className="help-link" href="/contact?interest=support" target="_blank"><Mail /> Contact support</Link>
        <Link className="help-link" href="/help" target="_blank"><ExternalLink /> Printable guide</Link>
      </div>
    </section>
  </div>;
}
