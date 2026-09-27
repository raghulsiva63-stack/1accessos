import Image from "next/image";
import Link from "next/link";
import type { ReactNode } from "react";
import { ArrowRight, Menu } from "lucide-react";

export const MARKETING_LINKS: { href: string; label: string }[] = [
  { href: "/#product", label: "Product" },
  { href: "/enterprise", label: "Enterprise" },
  { href: "/security", label: "Security" },
  { href: "/#pricing", label: "Pricing" },
  { href: "/compare", label: "Compare" },
  { href: "/download", label: "Apps" },
  { href: "/api-docs", label: "API" },
];

export function MarketingHeader() {
  const links = MARKETING_LINKS.map((link) => <Link key={link.href} href={link.href}>{link.label}</Link>);
  return <header className="public-header">
    <Link className="public-brand" href="/" aria-label="Passkey-X home"><Image src="/brand/passkey-x-horizontal.png" alt="Passkey-X by Vlightsoft" width={230} height={66} priority /></Link>
    <nav aria-label="Main navigation">{links}</nav>
    <div className="public-header-actions"><Link className="public-signin" href="/contact">Talk to sales</Link><Link className="public-primary-link compact" href="/login">Start free <ArrowRight /></Link></div>
    <details className="public-mobile-menu"><summary aria-label="Open navigation"><Menu /></summary><nav>{links}<Link href="/contact">Talk to sales</Link><Link href="/login">Sign in</Link></nav></details>
  </header>;
}

export function MarketingFooter() {
  return <footer className="public-footer mk-footer">
    <div><Image src="/brand/passkey-x-horizontal.png" alt="Passkey-X by Vlightsoft" width={190} height={55} /><p>Private access for people, teams, and machines.</p></div>
    <div><strong>Product</strong><Link href="/#product">Overview</Link><Link href="/#pricing">Pricing</Link><Link href="/compare">Compare</Link><Link href="/download">Apps</Link><Link href="/api-docs">API documentation</Link></div>
    <div><strong>Organizations</strong><Link href="/enterprise">Enterprise</Link><Link href="/security">Security &amp; trust</Link><Link href="/contact?interest=demo">Book a demo</Link><Link href="/contact?interest=security">Report a security issue</Link></div>
    <div><strong>Account</strong><Link href="/login">Sign in</Link><Link href="/login">Create a free vault</Link><Link href="/send">Open a Secure Send link</Link></div>
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
