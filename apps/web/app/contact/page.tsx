import type { Metadata } from "next";
import { Building2, CalendarClock, ShieldCheck, Users } from "lucide-react";
import { MarketingPage } from "@/components/marketing/marketing-shell";
import { ContactForm } from "@/components/marketing/contact-form";

export const metadata: Metadata = {
  title: "Talk to sales — Passkey-X",
  description: "Book a demo of Passkey-X for your organization, ask about Enterprise pricing, or send a security report.",
};

export default function ContactPage() {
  return <MarketingPage className="mk-contact">
    <section className="mk-contact-layout">
      <div className="mk-contact-copy">
        <span className="public-kicker"><CalendarClock /> Talk to us</span>
        <h1>See Passkey-X with your team.</h1>
        <p>Tell us a little about your organization and we’ll set up a walkthrough of the admin console, policies, audit and rollout plan.</p>
        <ul>
          <li><Building2 /><div><strong>Built for organizations</strong><span>Departments, delegated admins, lifecycle and policies.</span></div></li>
          <li><ShieldCheck /><div><strong>Zero-knowledge by design</strong><span>Your admins manage access without seeing secrets.</span></div></li>
          <li><Users /><div><strong>Help with rollout</strong><span>Migration, baseline policies and training for every team.</span></div></li>
        </ul>
      </div>
      <div className="mk-contact-card"><ContactForm /></div>
    </section>
  </MarketingPage>;
}
