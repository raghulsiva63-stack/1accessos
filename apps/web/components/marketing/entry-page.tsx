import Link from "next/link";
import { ArrowRight, Check } from "lucide-react";
import { MarketingIcon } from "@/components/marketing/icon";
import { CtaBand, MarketingPage } from "@/components/marketing/marketing-shell";
import { findProduct, type MarketingEntry } from "@/lib/marketing/catalog";

export function EntryPage({ entry }: { entry: MarketingEntry }) {
  const related = entry.related.map(findProduct).filter((item): item is MarketingEntry => Boolean(item));
  return <MarketingPage className="mk-entry">
    <section className="mk-hero compact mk-entry-hero">
      <div className="mk-hero-copy">
        <span className="public-kicker"><MarketingIcon name={entry.icon} /> {entry.kicker}</span>
        <h1>{entry.title} <em>{entry.titleAccent}</em></h1>
        <p>{entry.intro}</p>
        <div className="public-hero-actions"><Link className="public-primary-link" href={entry.primaryCta.href}>{entry.primaryCta.label} <ArrowRight /></Link><Link className="public-secondary-link" href={entry.secondaryCta.href}>{entry.secondaryCta.label}</Link></div>
        <div className="public-assurance">{entry.proof.map((item) => <span key={item}><Check /> {item}</span>)}</div>
      </div>
    </section>

    <section className="mk-section">
      <div className={`mk-card-grid ${entry.features.length % 3 === 0 ? "three" : ""}`}>{entry.features.map((feature) => <article key={feature.title} className="mk-card"><span className="mk-card-icon"><MarketingIcon name={feature.icon} /></span><h3>{feature.title}</h3><p>{feature.body}</p></article>)}</div>
    </section>

    {entry.highlight && <section className="mk-section mk-dark"><div className="mk-section-heading"><span className="public-kicker">{entry.highlight.kicker}</span><h2>{entry.highlight.title}</h2><p>{entry.highlight.body}</p></div><ul className="mk-checklist dark">{entry.highlight.bullets.map((bullet) => <li key={bullet}><Check /> {bullet}</li>)}</ul></section>}

    {entry.steps && <section className="mk-section"><div className="mk-section-heading"><span className="public-kicker">Get started</span><h2>Up and running in minutes.</h2></div><ol className="mk-steps three">{entry.steps.map((step, index) => <li key={step.title}><span className="mk-step-tag">Step {index + 1}</span><h3>{step.title}</h3><p>{step.body}</p></li>)}</ol></section>}

    <section className="mk-section mk-split">
      <div><span className="public-kicker">Questions</span><h2>Frequently asked</h2></div>
      <div className="mk-faq">{entry.faq.map(([question, answer]) => <details key={question}><summary>{question}</summary><p>{answer}</p></details>)}</div>
    </section>

    {related.length > 0 && <section className="mk-section mk-related"><div className="mk-section-heading"><span className="public-kicker">Works well with</span><h2>More from Passkey-X</h2></div><div className="mk-card-grid three">{related.map((item) => <Link key={item.slug} href={`/products/${item.slug}`} className="mk-card mk-card-link"><span className="mk-card-icon"><MarketingIcon name={item.icon} /></span><h3>{item.name}</h3><p>{item.navBlurb}</p><span className="mk-text-link">Learn more <ArrowRight /></span></Link>)}</div></section>}

    <CtaBand title="See it with your own data." body="Start free in minutes, or book a walkthrough for your team." />
  </MarketingPage>;
}
