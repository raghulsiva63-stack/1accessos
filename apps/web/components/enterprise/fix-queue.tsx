"use client";

import { useState } from "react";
import { ExternalLink, KeyRound, ListChecks, SkipForward, Wand2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { FixReason, FixTask } from "@/lib/vault/change-password";

const REASON_LABEL: Record<FixReason, string> = { breached: "Found in a breach", reused: "Reused", weak: "Weak" };

/**
 * Guided "fix my passwords" walkthrough: one item at a time, breached first. Opening the site's
 * change-password page and generating the new password are separate, explicit steps; the new
 * password is saved to the vault only when the person saves the editor.
 */
export function FixQueue({ tasks, onRotate }: { tasks: FixTask[]; onRotate: (itemId: string) => void }) {
  const [skipped, setSkipped] = useState<string[]>([]);
  const remaining = tasks.filter((task) => !skipped.includes(task.itemId));
  const current = remaining[0];
  if (!tasks.length) return null;

  return <section className="fix-queue" aria-labelledby="fix-title">
    <div className="fix-head">
      <span className="coach-icon"><ListChecks /></span>
      <div>
        <h3 id="fix-title">Fix your passwords, one at a time</h3>
        <p>{tasks.length} password{tasks.length === 1 ? "" : "s"} to change — breached first, then reused, then weak. Each takes about a minute.</p>
      </div>
    </div>
    {current ? <div className="fix-current">
      <div className="fix-item">
        <KeyRound />
        <div>
          <small>{tasks.length - remaining.length + 1} of {tasks.length}</small>
          <strong>{current.title}</strong>
          <span className="issue-chips">{current.reasons.map((reason) => <span key={reason} className={`issue-chip tone-${reason === "weak" ? "warning" : "critical"}`}>{REASON_LABEL[reason]}</span>)}</span>
        </div>
      </div>
      <ol className="fix-steps">
        <li>
          <span>Open the site&apos;s change-password page and sign in.</span>
          {current.changeUrl
            ? <a className="help-link" href={current.changeUrl} target="_blank" rel="noopener noreferrer"><ExternalLink /> Open change-password page</a>
            : <small className="field-hint">No website saved for this item — change it in the site&apos;s account settings.</small>}
        </li>
        <li>
          <span>Generate a strong new password, copy it into the site, then save it here.</span>
          <Button onClick={() => onRotate(current.itemId)}><Wand2 /> Generate new password</Button>
        </li>
      </ol>
      <div className="fix-nav">
        <small>Saved the new password? It leaves this list automatically.</small>
        {remaining.length > 1 && <Button variant="ghost" onClick={() => setSkipped([...skipped, current.itemId])}><SkipForward /> Skip for now</Button>}
      </div>
    </div> : <div className="fix-current"><p>You skipped the rest for now. <button type="button" className="coach-privacy" onClick={() => setSkipped([])}>Start again</button></p></div>}
  </section>;
}
