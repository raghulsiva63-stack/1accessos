import type { Metadata } from "next";
import Link from "next/link";
import {
  ArrowRight, BadgeCheck, Database, EyeOff, FileClock, Fingerprint, KeyRound, Link2, LockKeyhole, Server,
  ShieldAlert, ShieldCheck, TriangleAlert, Zap,
} from "lucide-react";
import { CtaBand, MarketingPage } from "@/components/marketing/marketing-shell";

export const metadata: Metadata = {
  title: "Security & trust — Passkey-X",
  description: "How Passkey-X protects your vault: client-side Argon2id and AES-256-GCM encryption, a separate vault password, row-level authorization and a tamper-evident audit chain.",
};

const LAYERS = [
  { title: "Vault password", detail: "Never leaves your device", tone: "you" },
  { title: "Argon2id · 64 MiB · 3 passes", detail: "Derives your master key on-device", tone: "you" },
  { title: "Account root key", detail: "Wrapped by the master key and by your recovery key", tone: "key" },
  { title: "Workspace keys", detail: "One per vault; shared by wrapping to each member", tone: "key" },
  { title: "Items · AES-256-GCM", detail: "Encrypted with context-bound AAD before sync", tone: "data" },
];

const CRYPTO = [
  ["Key derivation", "Argon2id, 64 MiB memory, 3 iterations, per-account random salt. Clients reject weaker or oversized parameters."],
  ["Item encryption", "AES-256-GCM with a fresh 96-bit nonce per write and additional authenticated data binding each item to its workspace."],
  ["Key wrapping", "Account, workspace and device keys are wrapped with AES-256-GCM under domain-separated labels."],
  ["Recovery", "A 256-bit recovery key generated on your device. Passkey-X stores only a verifier; it cannot recover your vault for you."],
  ["Secure Send", "HKDF-SHA256 over a link key kept in the URL fragment (never sent to the server) plus an optional Argon2id passphrase."],
  ["Audit integrity", "Each event is chained with SHA-256 over its content and the previous hash. Append-only for organizations; verifiable on demand."],
];

const VISIBILITY = [
  { item: "Passwords, notes, files and custom fields", us: false, admin: false },
  { item: "Item titles, URLs and usernames", us: false, admin: false },
  { item: "Workspace names", us: false, admin: false },
  { item: "Your vault password or recovery key", us: false, admin: false },
  { item: "That an item exists, its size and revision number", us: true, admin: false },
  { item: "Counts of weak, reused or breached passwords (organizations)", us: false, admin: true },
  { item: "Audit metadata: who shared, revealed or changed what, and when", us: false, admin: true },
];

const CONTROLS = [
  { icon: Database, title: "Row-level authorization", body: "Every table enforces tenant and workspace membership in the database, including negative cross-tenant paths." },
  { icon: Fingerprint, title: "Phishing-resistant sign-in", body: "Domain-bound passkeys and authenticator-app 2-step verification. Account sign-in never unlocks the vault on its own." },
  { icon: Server, title: "Hardened delivery", body: "Strict Content Security Policy, HSTS, no framing, no third-party trackers, and no-store caching on sensitive routes." },
  { icon: Zap, title: "Private breach checks", body: "k-anonymity: only the first five characters of a SHA-1 hash leave your device, padded so response size reveals nothing." },
  { icon: FileClock, title: "Tamper-evident audit", body: "Organization events are hash-chained, append-only and exportable as CSV or JSON evidence." },
  { icon: LockKeyhole, title: "Memory hygiene", body: "Keys are zeroed after use, the vault locks on idle and when the app is hidden, and clipboard copies clear automatically." },
];

const FAQ = [
  ["Can Passkey-X employees read my passwords?", "No. Your vault is encrypted on your device with keys derived from a vault password we never receive. Our servers store ciphertext."],
  ["What happens if Passkey-X is breached?", "An attacker would obtain encrypted data and would still need to guess each user’s vault password against Argon2id with 64 MiB of memory per guess. Use a long, unique vault password."],
  ["Can my company admin open my vault?", "No. Admins can enforce policies, manage access to shared workspaces and see aggregate risk counts, but cannot decrypt anyone’s items."],
  ["What if I forget my vault password?", "Use the recovery key you saved during setup. Without it, nobody — including Passkey-X — can recover the vault."],
  ["Are you SOC 2 or ISO 27001 certified?", "Not yet. Our controls are designed to support those frameworks, and customers receive audit exports and architecture documentation today. We will publish attestations here when they are complete."],
];

export default function SecurityPage() {
  return <MarketingPage className="mk-security">
    <section className="mk-hero compact">
      <div className="mk-hero-copy">
        <span className="public-kicker"><ShieldCheck /> Security &amp; trust center</span>
        <h1>We built Passkey-X assuming <em>we</em> could be breached.</h1>
        <p>Your data is encrypted before it leaves your device, with keys that never reach our servers. This page explains exactly how — and what we can and cannot see.</p>
        <div className="public-hero-actions"><Link className="public-primary-link" href="#architecture">How it works <ArrowRight /></Link><Link className="public-secondary-link" href="/contact?interest=security">Report a vulnerability</Link></div>
      </div>
    </section>

    <section className="mk-section mk-split" id="architecture">
      <div><span className="public-kicker"><KeyRound /> Key hierarchy</span><h2>Five layers between an attacker and your secrets.</h2><p>Every layer is created and used on your device. The server stores only the wrapped, encrypted output of each step.</p><p className="mk-note"><EyeOff /> Your login password and your vault password are separate. Signing in proves who you are; only the vault password decrypts.</p></div>
      <ol className="mk-layers">{LAYERS.map((layer, index) => <li key={layer.title} className={`tone-${layer.tone}`}><span>{index + 1}</span><div><strong>{layer.title}</strong><small>{layer.detail}</small></div></li>)}</ol>
    </section>

    <section className="mk-section mk-dark">
      <div className="mk-section-heading"><span className="public-kicker"><LockKeyhole /> Cryptography</span><h2>Standard, well-reviewed primitives. No homemade crypto.</h2></div>
      <dl className="mk-spec">{CRYPTO.map(([term, detail]) => <div key={term}><dt>{term}</dt><dd>{detail}</dd></div>)}</dl>
    </section>

    <section className="mk-section">
      <div className="mk-section-heading"><span className="public-kicker"><EyeOff /> Visibility</span><h2>What we — and your admins — can see.</h2></div>
      <div className="mk-visibility" role="table" aria-label="Data visibility">
        <div className="mk-visibility-row head" role="row"><span role="columnheader">Data</span><span role="columnheader">Passkey-X</span><span role="columnheader">Your organization admins</span></div>
        {VISIBILITY.map((row) => <div className="mk-visibility-row" role="row" key={row.item}><span role="cell">{row.item}</span><span role="cell" className={row.us ? "yes" : "no"}>{row.us ? "Metadata only" : "Never"}</span><span role="cell" className={row.admin ? "yes" : "no"}>{row.admin ? "Yes" : "Never"}</span></div>)}
      </div>
    </section>

    <section className="mk-section">
      <div className="mk-section-heading"><span className="public-kicker"><ShieldCheck /> Platform controls</span><h2>Defense in depth, from the browser to the database.</h2></div>
      <div className="mk-card-grid three">{CONTROLS.map((item) => { const Icon = item.icon; return <article key={item.title} className="mk-card"><span className="mk-card-icon"><Icon /></span><h3>{item.title}</h3><p>{item.body}</p></article>; })}</div>
    </section>

    <section className="mk-section mk-split">
      <div><span className="public-kicker"><BadgeCheck /> Compliance posture</span><h2>Honest about where we are.</h2><p>Passkey-X is not yet SOC 2 or ISO 27001 certified. Our admin console, policies, access reviews and hash-chained audit trail produce the evidence those frameworks ask for, and Enterprise customers receive architecture and data-flow documentation on request.</p></div>
      <div className="mk-disclosure"><ShieldAlert /><h3>Responsible disclosure</h3><p>Found a vulnerability? Tell us privately and give us a reasonable time to fix it before disclosure. Please do not access other users’ data or degrade the service while testing.</p><Link className="public-primary-link" href="/contact?interest=security">Report a security issue <ArrowRight /></Link><small><TriangleAlert /> Never include real passwords or recovery keys in a report.</small></div>
    </section>

    <section className="mk-section">
      <div className="mk-section-heading"><span className="public-kicker"><Link2 /> Questions</span><h2>Security FAQ</h2></div>
      <div className="mk-faq">{FAQ.map(([question, answer]) => <details key={question}><summary>{question}</summary><p>{answer}</p></details>)}</div>
    </section>

    <CtaBand title="Bring your security team." body="We’ll walk through the architecture, threat model and audit evidence with your reviewers." />
  </MarketingPage>;
}
