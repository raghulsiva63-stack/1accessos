import type { Metadata } from "next";
import Link from "next/link";
import {
  Activity, ArrowRight, BadgeCheck, Building2, CalendarClock, CircleCheck, Clock3, EyeOff, FileClock,
  Fingerprint, FolderLock, Gauge, KeyRound, LayoutDashboard, Link2, Send, ShieldCheck, SlidersHorizontal,
  UserX, Users, Waypoints,
} from "lucide-react";
import { CtaBand, MarketingPage } from "@/components/marketing/marketing-shell";

export const metadata: Metadata = {
  title: "Passkey-X for Enterprise — zero-knowledge password management for organizations",
  description: "Admin console, enforced security policies, tamper-evident audit, access reviews and Secure Send — without your administrators ever seeing a password.",
};

const CAPABILITIES = [
  { icon: LayoutDashboard, title: "Admin console", body: "Organization health, members at risk, 2-step coverage and inactive accounts on one screen, with a one-click recommended security baseline." },
  { icon: SlidersHorizontal, title: "Enforced policies", body: "Require passkeys or 2-step sign-in, set vault password strength, auto-lock, clipboard clearing, breach monitoring, sharing boundaries and export control." },
  { icon: FileClock, title: "Tamper-evident audit", body: "Every admin action, share and secret reveal is written to a SHA-256 hash chain. Verify integrity in one click and export CSV or JSON evidence." },
  { icon: FolderLock, title: "Access reviews", body: "See who can open every shared workspace, set just-in-time expiry, remove stale access, and export certification evidence for your auditors." },
  { icon: UserX, title: "Joiner, mover, leaver", body: "Suspend, reactivate or offboard in seconds. Offboarding revokes key envelopes and flags affected workspaces for key rotation." },
  { icon: Send, title: "Secure Send", body: "Share a credential or file with anyone through an end-to-end encrypted link that burns after reading. Admins decide who may use it." },
  { icon: Gauge, title: "Credential risk insight", body: "Weak, reused and breached password totals from every member’s device — never the passwords, sites or usernames themselves." },
  { icon: Waypoints, title: "Missions and approvals", body: "Time-boxed task access and approval flows give contractors and support staff exactly what they need, for as long as they need it." },
];

const PROMISES = [
  { can: "Enforce who must use passkeys or 2-step sign-in", cannot: "Read any member’s passwords, notes or files" },
  { can: "See how many weak, reused or breached passwords exist", cannot: "See which sites or accounts those passwords belong to" },
  { can: "Remove a leaver’s access and revoke their keys", cannot: "Reset a member’s vault password and open their vault" },
  { can: "Export a verifiable audit trail", cannot: "Edit or delete audit history after the fact" },
];

const ROLLOUT = [
  { icon: Building2, step: "Day 1", title: "Create your organization", body: "Start a Business workspace, invite your admins, and verify your domain users." },
  { icon: BadgeCheck, step: "Day 1", title: "Apply the baseline", body: "Turn on the recommended policies in one click. Members see what they need to fix, inside the app." },
  { icon: Users, step: "Week 1", title: "Roll out to teams", body: "Create shared workspaces per department, import existing passwords, and share with roles and expiry." },
  { icon: CalendarClock, step: "Quarterly", title: "Review and certify", body: "Run an access review, verify the audit chain, and keep the exported evidence for your auditors." },
];

const ROADMAP = [
  { title: "SIEM and webhook audit streaming", status: "Available" },
  { title: "Import from 1Password, Bitwarden and LastPass", status: "Available" },
  { title: "SAML single sign-on (Okta, Entra ID, Google)", status: "Available" },
  { title: "SCIM 2.0 provisioning and instant deprovisioning", status: "Available" },
  { title: "Opt-in organization recovery", status: "Available" },
  { title: "Break-glass and emergency access", status: "Available" },
  { title: "Security alerts and compliance reports", status: "Available" },
  { title: "One-click workspace key rotation", status: "In development" },
  { title: "Device approval workflow", status: "In development" },
  { title: "Native iOS app with AutoFill", status: "Planned" },
];

export default function EnterprisePage() {
  return <MarketingPage className="mk-enterprise">
    <section className="mk-hero">
      <div className="mk-hero-copy">
        <span className="public-kicker"><Building2 /> Passkey-X for organizations</span>
        <h1>Control every credential. <em>See none of them.</em></h1>
        <p>Passkey-X gives security teams real enforcement, evidence and lifecycle control over company passwords, passkeys and secrets — while encryption stays on each member’s device. Your admins manage access; nobody at your company or ours can read the vault.</p>
        <div className="public-hero-actions"><Link className="public-primary-link" href="/contact?interest=demo">Book a demo <ArrowRight /></Link><Link className="public-secondary-link" href="/login">Start a Business trial</Link></div>
        <div className="public-assurance"><span><ShieldCheck /> Zero-knowledge administration</span><span><Link2 /> Hash-chained audit</span><span><Fingerprint /> Passkey and TOTP enforcement</span></div>
      </div>
      <div className="mk-console-preview" aria-hidden>
        <div className="mk-console-bar"><span /><span /><span /><strong>Organization control center</strong></div>
        <div className="mk-console-kpis">
          <div className="good"><small>Organization health</small><strong>86/100</strong></div>
          <div className="warn"><small>Without 2-step</small><strong>3</strong></div>
          <div className="good"><small>Policy baseline</small><strong>100%</strong></div>
        </div>
        <ul className="mk-console-feed">
          <li><Activity /> Policy “Passkey required” enforced <em>2m</em></li>
          <li><FolderLock /> Access to Finance expires in 7 days <em>1h</em></li>
          <li><ShieldCheck /> Audit chain verified · 12,408 events <em>today</em></li>
          <li><UserX /> Contractor offboarded · keys revoked <em>yesterday</em></li>
        </ul>
      </div>
    </section>

    <section className="mk-section">
      <div className="mk-section-heading"><span className="public-kicker"><SlidersHorizontal /> What your security team gets</span><h2>Everything you need to roll out, govern and prove password security.</h2></div>
      <div className="mk-card-grid">{CAPABILITIES.map((item) => { const Icon = item.icon; return <article key={item.title} className="mk-card"><span className="mk-card-icon"><Icon /></span><h3>{item.title}</h3><p>{item.body}</p></article>; })}</div>
    </section>

    <section className="mk-section mk-dark">
      <div className="mk-section-heading"><span className="public-kicker"><EyeOff /> Zero-knowledge administration</span><h2>Admin power without admin access to secrets.</h2><p>Encryption keys are derived and used on members’ devices. The server — and your administrators — only ever handle ciphertext and counts.</p></div>
      <div className="mk-promise-table" role="table" aria-label="What administrators can and cannot do">
        <div className="mk-promise-row head" role="row"><span role="columnheader">Your admins can</span><span role="columnheader">Nobody can</span></div>
        {PROMISES.map((row) => <div className="mk-promise-row" role="row" key={row.can}><span role="cell"><CircleCheck /> {row.can}</span><span role="cell"><KeyRound /> {row.cannot}</span></div>)}
      </div>
    </section>

    <section className="mk-section">
      <div className="mk-section-heading"><span className="public-kicker"><Clock3 /> Rollout</span><h2>Live in a day. Audit-ready every quarter.</h2></div>
      <ol className="mk-steps">{ROLLOUT.map((item) => { const Icon = item.icon; return <li key={item.title}><span className="mk-step-tag">{item.step}</span><Icon /><h3>{item.title}</h3><p>{item.body}</p></li>; })}</ol>
    </section>

    <section className="mk-section mk-split">
      <div><span className="public-kicker"><CalendarClock /> Enterprise roadmap</span><h2>Built in the open.</h2><p>We tell you what ships today and what is coming next. Enterprise contracts can include roadmap commitments and early access.</p><Link className="mk-text-link" href="/security">Read our security architecture <ArrowRight /></Link></div>
      <ul className="mk-roadmap">{ROADMAP.map((item) => <li key={item.title}><strong>{item.title}</strong><span className={item.status === "Planned" ? "planned" : item.status === "Available" ? "available" : "building"}>{item.status}</span></li>)}</ul>
    </section>

    <CtaBand title="See Passkey-X with your own policies." body="A 30-minute walkthrough of the admin console, policies, audit and rollout plan for your organization." />
  </MarketingPage>;
}
