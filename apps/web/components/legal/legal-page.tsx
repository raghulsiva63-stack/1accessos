import Link from "next/link";
import { FileText } from "lucide-react";
import { MarketingPage } from "@/components/marketing/marketing-shell";
import { LEGAL_DOCUMENTS, LEGAL_UPDATED, type LegalDocument } from "@/lib/legal/content";

function anchor(heading: string) {
  return heading.toLowerCase().replace(/[^a-z0-9]+/gu, "-").replace(/(^-|-$)/gu, "");
}

export function LegalPage({ document }: { document: LegalDocument }) {
  return <MarketingPage className="mk-legal">
    <section className="mk-hero compact">
      <div className="mk-hero-copy">
        <span className="public-kicker"><FileText /> Legal</span>
        <h1>{document.title}</h1>
        <p>{document.summary}</p>
        <p className="legal-updated">Last updated {LEGAL_UPDATED}</p>
      </div>
    </section>
    <div className="mk-section legal-layout">
      <nav className="legal-nav" aria-label="Legal documents">
        {LEGAL_DOCUMENTS.map((entry) => <Link key={entry.slug} href={`/${entry.slug}`} aria-current={entry.slug === document.slug ? "page" : undefined}>{entry.title}</Link>)}
        <hr />
        <strong>On this page</strong>
        {document.sections.map((section) => <a key={section.heading} href={`#${anchor(section.heading)}`}>{section.heading}</a>)}
      </nav>
      <article className="legal-body">
        {document.sections.map((section) => <section key={section.heading} id={anchor(section.heading)}>
          <h2>{section.heading}</h2>
          {section.paragraphs?.map((paragraph) => <p key={paragraph}>{paragraph}</p>)}
          {section.bullets && <ul>{section.bullets.map((bullet) => <li key={bullet}>{bullet}</li>)}</ul>}
        </section>)}
      </article>
    </div>
  </MarketingPage>;
}
