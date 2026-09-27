"use client";

import { useState } from "react";
import { ArrowRight, CircleCheck, Download, Fingerprint, KeyRound, Plus, ShieldCheck, Upload, Users, X } from "lucide-react";
import { useEnterprise } from "@/components/enterprise/policy-context";

type Stored = { dismissed: boolean; done: string[] };

function storageKey(identityId: string) { return `px-onboarding:${identityId}`; }

function readStored(identityId: string): Stored {
  try {
    const parsed = JSON.parse(window.localStorage.getItem(storageKey(identityId)) ?? "null") as Partial<Stored> | null;
    return { dismissed: parsed?.dismissed === true, done: Array.isArray(parsed?.done) ? parsed.done.filter((value): value is string => typeof value === "string") : [] };
  } catch { return { dismissed: false, done: [] }; }
}

export function OnboardingChecklist({ identityId, itemCount, workspaceCount, onNavigate, onNewItem }: {
  identityId: string;
  itemCount: number;
  workspaceCount: number;
  onNavigate: (view: string) => void;
  onNewItem: () => void;
}) {
  const { compliance } = useEnterprise();
  const [stored, setStored] = useState<Stored>(() => typeof window === "undefined" ? { dismissed: false, done: [] } : readStored(identityId));

  function save(next: Stored) {
    setStored(next);
    try { window.localStorage.setItem(storageKey(identityId), JSON.stringify(next)); } catch { /* storage unavailable */ }
  }
  const mark = (id: string) => { if (!stored.done.includes(id)) save({ ...stored, done: [...stored.done, id] }); };

  const steps = [
    { id: "first-item", icon: Plus, title: "Add your first item", body: "Save a login, card or note. It is encrypted before it leaves this device.", done: itemCount > 0, action: () => onNewItem() },
    { id: "import", icon: Upload, title: "Import your passwords", body: "Bring everything over from 1Password, Bitwarden, LastPass or your browser.", done: itemCount >= 5 || stored.done.includes("import"), action: () => { mark("import"); onNavigate("settings"); } },
    { id: "sign-in", icon: Fingerprint, title: "Protect your sign-in", body: "Add a passkey or an authenticator app for phishing-resistant sign-in.", done: compliance.hasMfa || compliance.hasPasskey === true, action: () => onNavigate("account-security") },
    { id: "security", icon: ShieldCheck, title: "Run a security check", body: "Find weak, reused and breached passwords to fix first.", done: stored.done.includes("security"), action: () => { mark("security"); onNavigate("security"); } },
    { id: "apps", icon: Download, title: "Get the apps and extension", body: "Fill passwords in your browser and use Passkey-X on every device.", done: stored.done.includes("apps"), action: () => { mark("apps"); window.open("/download", "_blank", "noopener,noreferrer"); } },
    { id: "share", icon: Users, title: "Share with your team or family", body: "Create a shared vault with roles, or send a one-time Secure Send link.", done: workspaceCount > 1, action: () => onNavigate("workspaces") },
  ];
  const completed = steps.filter((step) => step.done).length;
  if (stored.dismissed || completed === steps.length) return null;

  return <section className="onboarding" aria-label="Getting started">
    <header>
      <div><span className="status-pill"><KeyRound /> Getting started</span><h2>Set up Passkey-X in a few minutes</h2><p>{completed} of {steps.length} done</p></div>
      <button type="button" className="onboarding-dismiss" aria-label="Hide getting started" onClick={() => save({ ...stored, dismissed: true })}><X /></button>
    </header>
    <div className="onboarding-bar" aria-hidden><i style={{ width: `${Math.round((completed / steps.length) * 100)}%` }} /></div>
    <ol>{steps.map((step) => { const Icon = step.icon; return <li key={step.id} className={step.done ? "done" : ""}>
      <button type="button" onClick={step.action} disabled={step.done}>
        <span className="onboarding-icon">{step.done ? <CircleCheck /> : <Icon />}</span>
        <span><strong>{step.title}</strong><small>{step.body}</small></span>
        {!step.done && <ArrowRight />}
      </button>
    </li>; })}</ol>
  </section>;
}
