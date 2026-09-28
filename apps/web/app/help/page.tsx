import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, BookOpen, LifeBuoy } from "lucide-react";
import { MarketingPage } from "@/components/marketing/marketing-shell";
import { PrintButton } from "@/components/help/print-button";
import { FAQ, HELP_CATEGORIES, guidesByCategory } from "@/lib/help/guides";

export const metadata: Metadata = {
  title: "Help & user guide — Passkey-X",
  description: "Step-by-step guides for Passkey-X: getting started, recovery, sharing, organisations, plans and billing.",
};

export default function HelpPage() {
  return <MarketingPage className="mk-help">
    <section className="mk-hero compact">
      <div className="mk-hero-copy">
        <span className="public-kicker"><LifeBuoy /> Help &amp; user guide</span>
        <h1>Everything you need to use Passkey-X.</h1>
        <p>Short, step-by-step guides for people, families and companies. Inside the app, open <strong>Help &amp; guides</strong> from the menu to jump straight to each screen.</p>
        <div className="public-hero-actions"><Link className="public-primary-link" href="/login">Open Passkey-X <ArrowRight /></Link><PrintButton /></div>
      </div>
    </section>

    <nav className="help-toc mk-section" aria-label="Contents">
      {HELP_CATEGORIES.map((category) => <div key={category.id}>
        <h2>{category.title}</h2>
        <ul>{guidesByCategory(category.id).map((guide) => <li key={guide.id}><a href={`#${guide.id}`}>{guide.title}</a></li>)}</ul>
      </div>)}
    </nav>

    {HELP_CATEGORIES.map((category) => <section key={category.id} className="mk-section help-section">
      <div className="mk-section-heading"><span className="public-kicker"><BookOpen /> {category.title}</span><h2>{category.blurb}</h2></div>
      <div className="help-articles">{guidesByCategory(category.id).map((guide) => <article key={guide.id} id={guide.id} className="help-article">
        <h3>{guide.title}</h3>
        <p className="help-article-summary">{guide.summary}</p>
        <ol>{guide.steps.map((step) => <li key={step}>{step}</li>)}</ol>
        {guide.tips && guide.tips.map((tip) => <p key={tip} className="help-article-tip"><strong>Tip:</strong> {tip}</p>)}
      </article>)}</div>
    </section>)}

    <section className="mk-section help-section">
      <div className="mk-section-heading"><span className="public-kicker"><LifeBuoy /> Questions</span><h2>Common questions</h2></div>
      <dl className="help-public-faq">{FAQ.map(([question, answer]) => <div key={question}><dt>{question}</dt><dd>{answer}</dd></div>)}</dl>
      <p className="help-article-summary">Still stuck? <Link href="/contact?interest=support">Contact support</Link>. We will never ask for your vault password or recovery key.</p>
    </section>
  </MarketingPage>;
}
