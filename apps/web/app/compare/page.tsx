import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, Check, CircleOff, Sparkles, TriangleAlert } from "lucide-react";
import { CtaBand, MarketingPage } from "@/components/marketing/marketing-shell";

export const metadata: Metadata = {
  title: "Compare — Passkey-X vs spreadsheets, browser passwords and basic password managers",
  description: "See how Passkey-X compares with shared spreadsheets, browser-saved passwords and basic password managers for teams and organizations.",
};

type Mark = "yes" | "partial" | "no";
const COLUMNS = ["Passkey-X", "Basic password manager", "Browser-saved passwords", "Shared spreadsheet or doc"];
const ROWS: { feature: string; marks: [Mark, Mark, Mark, Mark]; note?: string }[] = [
  { feature: "Encrypted on your device before sync", marks: ["yes", "yes", "partial", "no"] },
  { feature: "Separate vault password from account login", marks: ["yes", "partial", "no", "no"] },
  { feature: "Passwords, passkeys, API keys, SSH keys, cards and recovery codes", marks: ["yes", "partial", "partial", "partial"] },
  { feature: "Shared team vaults with roles", marks: ["yes", "yes", "no", "partial"] },
  { feature: "Access expiry and quarterly access reviews", marks: ["yes", "partial", "no", "no"] },
  { feature: "Enforced policies (passkeys, 2-step, auto-lock, export control)", marks: ["yes", "partial", "no", "no"] },
  { feature: "Hash-chained, verifiable audit trail", marks: ["yes", "no", "no", "no"] },
  { feature: "Offboarding that revokes keys and flags rotation", marks: ["yes", "partial", "no", "no"] },
  { feature: "Admins can see risk counts but never secrets", marks: ["yes", "partial", "no", "no"] },
  { feature: "Burn-after-reading links for people outside your company", marks: ["yes", "partial", "no", "no"] },
  { feature: "Time-boxed Missions and approval requests", marks: ["yes", "no", "no", "no"] },
  { feature: "Works on web, desktop, mobile and in the browser", marks: ["yes", "yes", "partial", "yes"] },
];

const LABEL: Record<Mark, string> = { yes: "Included", partial: "Varies or limited", no: "Not available" };

function MarkCell({ mark }: { mark: Mark }) {
  return <span className={`mk-mark ${mark}`} role="cell">{mark === "yes" ? <Check /> : mark === "partial" ? <TriangleAlert /> : <CircleOff />}<span className="sr-only">{LABEL[mark]}</span></span>;
}

export default function ComparePage() {
  return <MarketingPage className="mk-compare">
    <section className="mk-hero compact">
      <div className="mk-hero-copy">
        <span className="public-kicker"><Sparkles /> Compare</span>
        <h1>Still sharing passwords in a spreadsheet?</h1>
        <p>Most breaches start with a reused, shared or leaked credential. Here is how Passkey-X compares with the ways teams usually manage access.</p>
      </div>
    </section>

    <section className="mk-section">
      <div className="mk-compare-table" role="table" aria-label="Feature comparison">
        <div className="mk-compare-row head" role="row"><span role="columnheader">Capability</span>{COLUMNS.map((column, index) => <span role="columnheader" key={column} className={index === 0 ? "ours" : ""}>{column}</span>)}</div>
        {ROWS.map((row) => <div className="mk-compare-row" role="row" key={row.feature}><span role="rowheader">{row.feature}</span>{row.marks.map((mark, index) => <MarkCell key={COLUMNS[index]} mark={mark} />)}</div>)}
      </div>
      <p className="mk-legend"><span><Check /> Included</span><span><TriangleAlert /> Varies by product or plan</span><span><CircleOff /> Not available</span></p>
      <p className="mk-footnote">“Basic password manager” describes typical consumer and small-team products; capabilities vary by vendor and plan. Browser-saved passwords vary by browser and sync settings.</p>
    </section>

    <section className="mk-section mk-split">
      <div><span className="public-kicker"><ArrowRight /> Switching is simple</span><h2>Import in minutes.</h2><p>Export a CSV from your browser or current password manager and import it in Settings. The file is parsed on your device and every entry is encrypted before upload.</p><Link className="mk-text-link" href="/login">Create your free vault <ArrowRight /></Link></div>
      <ol className="mk-mini-steps"><li><strong>Export</strong><span>Download a CSV from your browser or password manager.</span></li><li><strong>Import</strong><span>Settings → Import logins. Parsed locally, encrypted per item.</span></li><li><strong>Delete the CSV</strong><span>Remove the plaintext export from your computer.</span></li></ol>
    </section>

    <CtaBand title="Moving a whole company?" body="We’ll help you plan the migration, policies and rollout for every department." />
  </MarketingPage>;
}
