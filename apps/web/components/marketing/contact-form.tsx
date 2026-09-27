"use client";

import { useEffect, useState } from "react";
import type { SupabaseClient } from "@supabase/supabase-js";
import { ArrowRight, CircleCheck, LoaderCircle } from "lucide-react";
import { supabase } from "@/lib/supabase/client";

const INTERESTS = [
  { value: "demo", label: "Book a demo" },
  { value: "enterprise", label: "Enterprise pricing and contracts" },
  { value: "security", label: "Security review or vulnerability report" },
  { value: "partnership", label: "Partnership or reseller (MSP)" },
  { value: "support", label: "Help with my account" },
] as const;

const SIZES = ["1-10", "11-50", "51-200", "201-1000", "1000+"] as const;

function inquiryError(reason: unknown) {
  const detail = typeof reason === "object" && reason !== null && "message" in reason ? String(reason.message) : "";
  if (/invalid work email/iu.test(detail)) return "Enter a valid work email address.";
  if (/too many inquiries/iu.test(detail)) return "We already have your request from today. We’ll be in touch soon.";
  if (/rate limited/iu.test(detail)) return "We’re receiving a lot of requests right now. Please try again in a few minutes.";
  if (/invalid inquiry/iu.test(detail)) return "Check your name, company and message, then try again.";
  return "Your request could not be sent. Please try again shortly.";
}

export function ContactForm() {
  const [interest, setInterest] = useState<string>("demo");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [company, setCompany] = useState("");
  const [size, setSize] = useState<string>("11-50");
  const [message, setMessage] = useState("");
  const [website, setWebsite] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    const requested = new URLSearchParams(window.location.search).get("interest");
    if (requested && INTERESTS.some((entry) => entry.value === requested)) void Promise.resolve().then(() => { if (active) setInterest(requested); });
    return () => { active = false; };
  }, []);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!supabase) { setError("The contact service is temporarily unavailable."); return; }
    setBusy(true); setError("");
    try {
      const { error: rpcError } = await (supabase as unknown as SupabaseClient).rpc("submit_sales_inquiry", {
        p_name: name, p_work_email: email, p_company: company, p_company_size: size, p_interest: interest,
        p_message: message || null, p_source_path: `${window.location.pathname}${window.location.search}`.slice(0, 200), p_website: website || null,
      });
      if (rpcError) throw rpcError;
      setSent(true);
    } catch (reason) { setError(inquiryError(reason)); }
    finally { setBusy(false); }
  }

  if (sent) return <div className="mk-form-done" role="status"><CircleCheck /><h2>Thanks, {name.split(" ")[0] || "we got it"}.</h2><p>{interest === "security" ? "Our security team will review your report and reply to your work email. Please don’t share details publicly until we’ve responded." : "We’ll reply to your work email within one business day with times for a walkthrough."}</p></div>;

  return <form className="mk-form" onSubmit={submit}>
    <label>What can we help with?<select value={interest} onChange={(event) => setInterest(event.target.value)}>{INTERESTS.map((entry) => <option key={entry.value} value={entry.value}>{entry.label}</option>)}</select></label>
    <div className="mk-form-row"><label>Full name<input required minLength={2} maxLength={120} autoComplete="name" value={name} onChange={(event) => setName(event.target.value)} /></label><label>Work email<input required type="email" maxLength={254} autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} /></label></div>
    <div className="mk-form-row"><label>Company<input required minLength={2} maxLength={160} autoComplete="organization" value={company} onChange={(event) => setCompany(event.target.value)} /></label><label>Company size<select value={size} onChange={(event) => setSize(event.target.value)}>{SIZES.map((value) => <option key={value} value={value}>{value} people</option>)}</select></label></div>
    <label>{interest === "security" ? "Describe the issue (no real passwords or keys)" : "Anything we should know? (optional)"}<textarea rows={5} maxLength={2000} required={interest === "security"} value={message} onChange={(event) => setMessage(event.target.value)} /></label>
    <label className="mk-hp" aria-hidden>Website<input tabIndex={-1} autoComplete="off" value={website} onChange={(event) => setWebsite(event.target.value)} /></label>
    {error && <p className="form-message" role="alert">{error}</p>}
    <button className="public-primary-link" disabled={busy}>{busy ? <LoaderCircle className="spin" /> : null} {interest === "security" ? "Send report" : "Send request"} <ArrowRight /></button>
    <small className="mk-form-note">We use your details only to reply to this request. Inquiries are deleted after two years.</small>
  </form>;
}
