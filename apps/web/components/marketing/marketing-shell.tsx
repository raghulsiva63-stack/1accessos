import Image from "next/image";
import Link from "next/link";
import type { ReactNode } from "react";
import { ArrowRight, Menu } from "lucide-react";
import { MarketingIcon } from "@/components/marketing/icon";
import { PRODUCTS, SOLUTIONS, type IconName } from "@/lib/marketing/catalog";

type MenuLink = { href: string; label: string; blurb: string; icon: IconName };

const PRODUCT_LINKS: MenuLink[] = PRODUCTS.map((entry) => ({ href: `/products/${entry.slug}`, label: entry.navLabel, blurb: entry.navBlurb, icon: entry.icon }));
const SOLUTION_LINKS: MenuLink[] = [
  ...SOLUTIONS.filter((entry) => entry.slug !== "msp").map((entry) => ({ href: `/solutions/${entry.slug}`, label: entry.navLabel, blurb: entry.navBlurb, icon: entry.icon })),
  { href: "/enterprise", label: "Enterprise", blurb: "Contracts, roadmap commitments and rollout help.", icon: "ShieldCheck" },
  ...SOLUTIONS.filter((entry) => entry.slug === "msp").map((entry) => ({ href: `/solutions/${entry.slug}`, label: entry.navLabel, blurb: entry.navBlurb, icon: entry.icon })),
];
const RESOURCE_LINKS: MenuLink[] = [
  { href: "/help", label: "Help & user guide", blurb: "Step-by-step guides for every feature.", icon: "Users" },
  { href: "/compare", label: "Compare", blurb: "Passkey-X vs spreadsheets and basic managers.", icon: "Sparkles" },
  { href: "/download", label: "Apps & downloads", blurb: "Desktop, mobile and browser extension.", icon: "Laptop" },
  { href: "/api-docs", label: "API documentation", blurb: "REST API and ciphertext-only CLI.", icon: "Code2" },
  { href: "/contact?interest=support", label: "Help & support", blurb: "Questions about your account.", icon: "Users" },
  { href: "/contact?interest=security", label: "Report a vulnerability", blurb: "Responsible disclosure.", icon: "ShieldCheck" },
];

function MenuPanel({ items, footer, wide = false }: { items: MenuLink[]; footer?: { href: string; label: string }; wide?: boolean }) {
  return <div className={`mk-menu ${wide ? "wide" : ""}`} role="menu">
    <div className="mk-menu-grid">{items.map((item) => <Link key={item.href} href={item.href} role="menuitem" className="mk-menu-link"><span className="mk-menu-icon"><MarketingIcon name={item.icon} /></span><span><strong>{item.label}</strong><small>{item.blurb}</small></span></Link>)}</div>
    {footer && <Link className="mk-menu-footer" href={footer.href}>{footer.label} <ArrowRight /></Link>}
  </div>;
}

function Dropdown({ label, children }: { label: string; children: ReactNode }) {
  return <div className="mk-nav-item"><button type="button" className="mk-nav-trigger" aria-haspopup="true">{label}</button>{children}</div>;
}

export function MarketingHeader() {
  return <header className="public-header mk-header">
    <Link className="public-brand" href="/" aria-label="Passkey-X home"><Image src="/brand/passkey-x-horizontal.png" alt="Passkey-X by Vlightsoft" width={230} height={66} priority /></Link>
    <nav aria-label="Main navigation" className="mk-nav">
      <Dropdown label="Products"><MenuPanel items={PRODUCT_LINKS} footer={{ href: "/pricing", label: "Compare plans and pricing" }} wide /></Dropdown>
      <Dropdown label="Solutions"><MenuPanel items={SOLUTION_LINKS} footer={{ href: "/contact?interest=demo", label: "Talk to our team" }} wide /></Dropdown>
      <Link href="/security">Security</Link>
      <Link href="/pricing">Pricing</Link>
      <Dropdown label="Resources"><MenuPanel items={RESOURCE_LINKS} /></Dropdown>
    </nav>
    <div className="public-header-actions"><Link className="public-signin" href="/login">Sign in</Link><Link className="public-signin mk-sales-link" href="/contact?interest=demo">Talk to sales</Link><Link className="public-primary-link compact" href="/login">Start free <ArrowRight /></Link></div>
    <details className="public-mobile-menu mk-mobile-menu"><summary aria-label="Open navigation"><Menu /></summary>
      <nav aria-label="Mobile navigation">
        <span className="mk-mobile-label">Products</span>{PRODUCT_LINKS.map((item) => <Link key={item.href} href={item.href}>{item.label}</Link>)}
        <span className="mk-mobile-label">Solutions</span>{SOLUTION_LINKS.map((item) => <Link key={item.href} href={item.href}>{item.label}</Link>)}
        <span className="mk-mobile-label">Company</span><Link href="/security">Security</Link><Link href="/pricing">Pricing</Link>{RESOURCE_LINKS.slice(0, 3).map((item) => <Link key={item.href} href={item.href}>{item.label}</Link>)}
        <Link href="/contact?interest=demo">Talk to sales</Link><Link href="/login">Sign in</Link>
      </nav>
    </details>
  </header>;
}

export function MarketingFooter() {
  return <footer className="public-footer mk-footer">
    <div><Image src="/brand/passkey-x-horizontal.png" alt="Passkey-X by Vlightsoft" width={190} height={55} /><p>Private access for people, teams, and machines.</p><small>© 2026 Vlightsoft Pvt Ltd. Passkey-X launch catalog v2.2.</small></div>
    <div><strong>Products</strong>{PRODUCT_LINKS.map((item) => <Link key={item.href} href={item.href}>{item.label}</Link>)}</div>
    <div><strong>Solutions</strong>{SOLUTION_LINKS.map((item) => <Link key={item.href} href={item.href}>{item.label}</Link>)}</div>
    <div><strong>Resources</strong><Link href="/pricing">Pricing</Link><Link href="/security">Security &amp; trust</Link>{RESOURCE_LINKS.map((item) => <Link key={item.href} href={item.href}>{item.label}</Link>)}</div>
    <div><strong>Account</strong><Link href="/login">Sign in</Link><Link href="/login">Create a free vault</Link><Link href="/send">Open a Secure Send link</Link><Link href="/contact?interest=demo">Book a demo</Link></div>
    <div><strong>Legal</strong><Link href="/privacy">Privacy Policy</Link><Link href="/terms">Terms of Service</Link><Link href="/refunds">Refunds &amp; cancellation</Link><a href="mailto:support@vlightsoft.com">support@vlightsoft.com</a></div>
  </footer>;
}

export function MarketingPage({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <main className={`public-site mk-page ${className}`}>
    <MarketingHeader />
    {children}
    <MarketingFooter />
  </main>;
}

export function CtaBand({ title, body }: { title: string; body: string }) {
  return <section className="mk-cta">
    <div><h2>{title}</h2><p>{body}</p></div>
    <div className="mk-cta-actions"><Link className="public-primary-link" href="/contact?interest=demo">Book a demo <ArrowRight /></Link><Link className="mk-ghost-link" href="/login">Start free</Link></div>
  </section>;
}
