"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import {
  ArrowRight, Building2, Check, Code2, FileClock, Fingerprint, FolderLock, KeyRound, LayoutDashboard, Link2,
  Send, ShieldCheck, SlidersHorizontal, Sparkles, TimerOff, UserX, Users,
} from "lucide-react";
import { MarketingIcon } from "@/components/marketing/icon";
import { CtaBand, MarketingFooter, MarketingHeader } from "@/components/marketing/marketing-shell";
import { PricingSection } from "@/components/marketing/pricing-section";
import { PRODUCTS } from "@/lib/marketing/catalog";

const ORG_FEATURES = [
  { icon: LayoutDashboard, title: "Admin console", body: "Organization health, members at risk and 2-step coverage at a glance, with a one-click security baseline." },
  { icon: SlidersHorizontal, title: "Enforced policies", body: "Require passkeys or 2-step sign-in, vault password strength, auto-lock, clipboard clearing and export control." },
  { icon: FileClock, title: "Tamper-evident audit", body: "Hash-chained activity log with one-click integrity verification and CSV or JSON evidence export." },
  { icon: FolderLock, title: "Access reviews", body: "Who can open each shared vault, with just-in-time expiry and quarterly certification evidence." },
  { icon: UserX, title: "Offboarding in seconds", body: "Suspend or offboard a member, revoke their keys and flag affected vaults for rotation." },
  { icon: Fingerprint, title: "Phishing-resistant sign-in", body: "Passkeys and authenticator apps protect the account; a separate vault password protects the data." },
];

const AUDIENCES = [
  { href: "/solutions/individuals", icon: KeyRound, title: "Individuals", body: "A private vault for every login." },
  { href: "/solutions/families", icon: Users, title: "Families", body: "Shared vaults for up to six people." },
  { href: "/solutions/teams", icon: Users, title: "Teams", body: "Shared vaults, roles and approvals." },
  { href: "/solutions/business", icon: Building2, title: "Business", body: "Departments, policies and audit." },
];

const HOME_FAQ: [string, string][] = [
  ["Is Passkey-X really zero-knowledge?", "Yes. Your vault is encrypted on your device with a key derived from a vault password we never receive. We store ciphertext only."],
  ["What is the difference between Team and Business?", "Team fits one workgroup sharing vaults with roles. Business adds departments, delegated admins, enforced policies, access reviews, lifecycle controls and the tamper-evident audit trail."],
  ["Can I import from my current password manager?", "Yes. Import from 1Password, Bitwarden, LastPass or any browser CSV in Settings. The file is parsed on your device and each entry is encrypted before upload."],
  ["Which devices are supported?", "Passkey-X runs in any modern browser and has desktop, mobile and browser-extension clients. See the Apps page for downloads."],
  ["What happens if I forget my vault password?", "Use the recovery key you saved at setup. Without it, nobody — including Passkey-X — can decrypt your vault."],
];

export function PublicSite({ children }: { children: ReactNode }) {
  return <main className="public-site">
    <MarketingHeader />

    <section className="public-hero" id="product">
      <div className="public-hero-copy">
        <span className="public-kicker"><ShieldCheck /> Client-side encrypted access</span>
        <h1>Passwords are only the beginning.</h1>
        <p>Passkey-X protects passwords, passkeys, developer secrets, recovery codes, and team access in one zero-knowledge workspace—without giving the service your vault password.</p>
        <div className="public-hero-actions"><a className="public-primary-link" href="#access">Create your vault <ArrowRight /></a><Link className="public-secondary-link" href="/pricing">Compare plans</Link></div>
        <div className="public-assurance"><span><Fingerprint /> Separate vault unlock</span><span><ShieldCheck /> Tamper detection</span><span><KeyRound /> Recovery key</span></div>
      </div>
      <div className="public-access" id="access">{children}<p className="auth-legal">By creating an account you agree to the <Link href="/terms">Terms of Service</Link> and <Link href="/privacy">Privacy Policy</Link>.</p></div>
    </section>

    <section className="public-value-strip" aria-label="Passkey-X capabilities">
      <span><ShieldCheck /><strong>Zero-knowledge boundary</strong><small>Encryption before sync</small></span>
      <span><Users /><strong>Personal to Business</strong><small>Isolated workspace keys</small></span>
      <span><Code2 /><strong>Developer ready</strong><small>API and CLI foundation</small></span>
      <span><Fingerprint /><strong>Passkey ready</strong><small>Domain-bound sign-in</small></span>
    </section>

    <section className="mk-section" id="products">
      <div className="mk-section-heading"><span className="public-kicker"><Sparkles /> Products</span><h2>One platform for every credential.</h2><p>Five products that share one zero-knowledge vault, one sign-in and one admin console.</p></div>
      <div className="mk-product-grid">{PRODUCTS.map((entry) => <Link key={entry.slug} href={`/products/${entry.slug}`} className="mk-card mk-card-link"><span className="mk-card-icon"><MarketingIcon name={entry.icon} /></span><h3>{entry.name}</h3><p>{entry.navBlurb}</p><span className="mk-text-link">Explore <ArrowRight /></span></Link>)}</div>
    </section>

    <section className="mk-section mk-audiences">
      <div className="mk-section-heading"><span className="public-kicker"><Users /> Solutions</span><h2>Built for Teams, Business and everyone in between.</h2></div>
      <div className="mk-audience-grid">{AUDIENCES.map((item) => { const Icon = item.icon; return <Link key={item.href} href={item.href} className="mk-audience"><Icon /><div><strong>{item.title}</strong><span>{item.body}</span></div><ArrowRight /></Link>; })}</div>
    </section>

    <section className="public-security" id="security">
      <div><span className="public-kicker"><ShieldCheck /> Security designed around the breach</span><h2>Your service provider should not become your master key.</h2><Link className="mk-text-link light" href="/security">Visit the trust center <ArrowRight /></Link></div>
      <div className="public-security-grid"><article><span>01</span><h3>Encrypt locally</h3><p>Vault content and workspace keys are encrypted in the trusted client before they reach storage.</p></article><article><span>02</span><h3>Authorize every row</h3><p>Tenant and workspace membership checks protect every accessible object, including negative cross-tenant paths.</p></article><article><span>03</span><h3>Revoke deliberately</h3><p>Device and employee revocation remove key envelopes and force affected workspaces into key rotation.</p></article></div>
    </section>

    <section className="mk-section mk-home-features" id="organizations">
      <div className="mk-section-heading"><span className="public-kicker"><Building2 /> For organizations</span><h2>Govern every credential in your company — without seeing any of them.</h2><p>Admin console, enforced policies, access reviews and a tamper-evident audit trail, on top of client-side encryption.</p></div>
      <div className="mk-card-grid three">{ORG_FEATURES.map((item) => { const Icon = item.icon; return <article key={item.title} className="mk-card"><span className="mk-card-icon"><Icon /></span><h3>{item.title}</h3><p>{item.body}</p></article>; })}</div>
      <Link className="mk-text-link" href="/enterprise">Explore Passkey-X for Enterprise <ArrowRight /></Link>
    </section>

    <section className="mk-section mk-highlight" id="secure-send">
      <div><span className="public-kicker"><Send /> Secure Send</span><h2>Stop pasting passwords into chat.</h2><p>Send a password, note or file to anyone as an end-to-end encrypted link. It opens once — or a few times — then destroys itself.</p>
        <ul className="mk-checklist"><li><Check /> The decryption key lives only in the link, never on our servers</li><li><Check /> Optional passphrase, sent through a different channel</li><li><Check /> Expiry from one hour to 30 days, and revoke any time</li><li><Check /> Recipients do not need a Passkey-X account</li></ul>
        <Link className="mk-text-link" href="/products/secure-send">More about Secure Send <ArrowRight /></Link>
      </div>
      <div className="mk-highlight-visual" aria-hidden><span><Link2 /> passkey-x.com/send#…</span><code>AES-256-GCM · key in URL fragment · 1 view left</code><span><TimerOff /> Burns after reading</span></div>
    </section>

    <PricingSection />

    <section className="mk-section" id="faq">
      <div className="mk-section-heading"><span className="public-kicker"><Sparkles /> Questions</span><h2>Frequently asked questions</h2></div>
      <div className="mk-faq">{HOME_FAQ.map(([question, answer]) => <details key={question}><summary>{question}</summary><p>{answer}</p></details>)}</div>
    </section>

    <CtaBand title="Ready to protect your whole organization?" body="Book a walkthrough, or start free and invite your team when you are ready." />
    <MarketingFooter />
  </main>;
}
