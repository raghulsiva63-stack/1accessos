import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, BadgeCheck, CreditCard, ShieldCheck } from "lucide-react";
import { CtaBand, MarketingPage } from "@/components/marketing/marketing-shell";
import { PricingSection } from "@/components/marketing/pricing-section";

export const metadata: Metadata = {
  title: "Pricing — Passkey-X",
  description: "Plans for individuals, families, professionals, teams, businesses and enterprises. Start free; upgrade when you need sharing, policies and audit.",
};

const BILLING_FAQ: [string, string][] = [
  ["Can I start free?", "Yes. The Free plan includes the full encrypted vault. Upgrade any time from Plans & billing inside the app."],
  ["How do trials work?", "Paid plans include a trial policy shown on each plan. Your plan activates only after our payment provider confirms it with a signed webhook."],
  ["How are Team and Business billed?", "Per user, with a minimum seat count. You can change the number of seats from the billing portal."],
  ["Who handles my card details?", "Checkout and billing are hosted by Stripe. Passkey-X never receives card numbers or vault contents."],
  ["Do you offer Enterprise contracts?", "Yes — sales-assisted plans with contract controls, rollout help and roadmap commitments."],
];

export default function PricingPage() {
  return <MarketingPage className="mk-pricing-page">
    <section className="mk-hero compact">
      <div className="mk-hero-copy">
        <span className="public-kicker"><CreditCard /> Pricing</span>
        <h1>Simple plans. <em>Serious security.</em></h1>
        <p>Every plan uses the same zero-knowledge encryption. Upgrade for more devices, sharing, policies and audit — never for basic security.</p>
        <div className="public-assurance"><span><ShieldCheck /> Same encryption on every plan</span><span><BadgeCheck /> Cancel any time</span></div>
      </div>
    </section>
    <PricingSection />
    <section className="mk-section mk-split">
      <div><span className="public-kicker">Billing</span><h2>Questions about billing</h2><p>Need something custom? <Link className="mk-text-link" href="/contact?interest=enterprise">Talk to sales <ArrowRight /></Link></p></div>
      <div className="mk-faq">{BILLING_FAQ.map(([question, answer]) => <details key={question}><summary>{question}</summary><p>{answer}</p></details>)}</div>
    </section>
    <CtaBand title="Not sure which plan fits?" body="Tell us about your team and we’ll recommend a plan and rollout." />
  </MarketingPage>;
}
