"use client";

import { useMemo, useState } from "react";
import {
  CircleCheck, CircleDashed, ClipboardCopy, Download, Fingerprint, LoaderCircle, Printer, Rocket, ShieldCheck,
  UserPlus, Vault,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import type { AdminTab } from "@/components/admin/admin-console";
import { downloadBlob } from "@/lib/browser/download";
import type { MemberOverview } from "@/lib/enterprise/admin";
import type { StoredPolicy } from "@/lib/enterprise/policies";
import { reminderMessage, rolloutCsv, STAGE_LABEL, summarizeRollout, type RolloutStage } from "@/lib/enterprise/rollout";
import type { WorkspaceVault } from "@/lib/vault/items";

const STAGE_TONE: Record<RolloutStage, string> = { not_started: "bad", signed_in: "warn", vault_in_use: "warn", protected: "good" };

/** Team rollout: an admin checklist plus where every person is in getting set up. */
export function RolloutPanel({ vault, members, policies, loading, onNavigate }: {
  vault: WorkspaceVault;
  members: MemberOverview[];
  policies: StoredPolicy[];
  loading: boolean;
  onNavigate: (tab: AdminTab) => void;
}) {
  const [now] = useState(() => Date.now());
  const summary = useMemo(() => summarizeRollout(members, now), [members, now]);
  const [message, setMessage] = useState("");
  const enforced = new Set(policies.filter((policy) => policy.enforced && policy.scope_type === "tenant").map((policy) => policy.policy_type));
  const pending = summary.rows.filter((row) => row.stage !== "protected");

  const checklist = [
    { id: "invite", icon: UserPlus, title: "Invite your people", body: "Add everyone at once from a spreadsheet (CSV) in Directory, or one by one.", done: summary.total > 1, action: "Invite people", onClick: () => onNavigate("directory") },
    { id: "mfa", icon: Fingerprint, title: "Require two-step verification", body: "Everyone must add an authenticator app or a passkey before opening the vault.", done: enforced.has("mfa_required") || enforced.has("passkey_required"), action: "Open policies", onClick: () => onNavigate("policies") },
    { id: "breach", icon: ShieldCheck, title: "Turn on breach checks for everyone", body: "Each person's vault checks for leaked passwords automatically. You see only totals.", done: enforced.has("breach_monitoring"), action: "Open policies", onClick: () => onNavigate("policies") },
    { id: "remind", icon: ClipboardCopy, title: "Nudge people who have not finished", body: `${pending.length} ${pending.length === 1 ? "person has" : "people have"} steps left. Copy a ready-made reminder and send it by email or chat.`, done: summary.total > 0 && pending.length === 0, action: "Copy reminder", onClick: () => void copyReminder() },
  ];

  async function copyReminder() {
    try { await navigator.clipboard.writeText(reminderMessage(vault.name, window.location.origin)); setMessage("Reminder copied. Paste it into an email or chat to the people listed below."); }
    catch { setMessage("Your browser blocked the clipboard. Select the people below and remind them directly."); }
  }

  function downloadCsv() {
    downloadBlob(new Blob([rolloutCsv(summary)], { type: "text/csv;charset=utf-8" }), `passkey-x-rollout-${new Date(now).toISOString().slice(0, 10)}.csv`);
  }

  function printReport() {
    document.documentElement.classList.add("print-rollout");
    const done = () => { document.documentElement.classList.remove("print-rollout"); window.removeEventListener("afterprint", done); };
    window.addEventListener("afterprint", done);
    window.print();
  }

  if (loading) return <div className="rollout-panel"><div className="small-empty"><LoaderCircle className="spin" /><span>Loading your team…</span></div></div>;

  return <div className="rollout-panel">
    <section className="rollout-hero">
      <div>
        <span className="status-pill"><Rocket /> Team rollout</span>
        <h3>{summary.percentComplete === 100 ? "Everyone is set up" : `${summary.counts.protected} of ${summary.total} people fully set up`}</h3>
        <p>Fully set up means signed in, using the vault, and protected with two-step verification or a passkey. You never see anyone&apos;s passwords.</p>
        <div className="rollout-bar" aria-hidden><i style={{ width: `${summary.percentComplete}%` }} /></div>
        <ul className="rollout-counts">{(Object.keys(STAGE_LABEL) as RolloutStage[]).map((stage) => <li key={stage} className={`tone-${STAGE_TONE[stage]}`}><strong>{summary.counts[stage]}</strong> {STAGE_LABEL[stage].toLowerCase()}</li>)}</ul>
      </div>
      <div className="rollout-actions">
        <Button variant="outline" onClick={downloadCsv} disabled={!summary.total}><Download /> Download CSV</Button>
        <Button variant="outline" onClick={printReport} disabled={!summary.total}><Printer /> Print or save as PDF</Button>
      </div>
    </section>

    <section className="rollout-checklist" aria-labelledby="rollout-steps">
      <h3 id="rollout-steps">Your rollout checklist</h3>
      <ol>{checklist.map((step) => { const Icon = step.icon; return <li key={step.id} className={step.done ? "done" : ""}>
        <span className="rollout-check">{step.done ? <CircleCheck /> : <Icon />}</span>
        <div><strong>{step.title}</strong><p>{step.body}</p></div>
        {!step.done && <Button size="sm" variant="outline" onClick={step.onClick}>{step.action}</Button>}
      </li>; })}</ol>
      {message && <p className="form-message" role="status">{message}</p>}
    </section>

    <section className="rollout-people" aria-labelledby="rollout-people-title">
      <h3 id="rollout-people-title">Where everyone is</h3>
      <p className="print-only">{vault.name} · rollout report · {new Date(now).toLocaleDateString()}</p>
      {summary.total === 0 ? <div className="small-empty"><Vault /><strong>No active members yet</strong><span>Invite people from Directory to start your rollout.</span></div> :
        <div className="table-scroll"><table className="rollout-table">
          <thead><tr><th scope="col">Person</th><th scope="col">Status</th><th scope="col">Signed in</th><th scope="col">Using vault</th><th scope="col">Two-step</th><th scope="col">Next step</th></tr></thead>
          <tbody>{summary.rows.map((row) => <tr key={row.identityId}>
            <td><strong>{row.name}</strong>{row.email && row.email !== row.name && <small>{row.email}</small>}</td>
            <td><span className={`rollout-stage tone-${STAGE_TONE[row.stage]}`}>{STAGE_LABEL[row.stage]}</span></td>
            <td>{row.signedIn ? <CircleCheck aria-label="Yes" /> : <CircleDashed aria-label="No" />}</td>
            <td>{row.vaultInUse ? <CircleCheck aria-label="Yes" /> : <CircleDashed aria-label="No" />}</td>
            <td>{row.twoStep ? <CircleCheck aria-label="Yes" /> : <CircleDashed aria-label="No" />}</td>
            <td>{row.nextStep}</td>
          </tr>)}</tbody>
        </table></div>}
    </section>
  </div>;
}
