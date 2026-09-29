"use client";

import { useEffect, useEffectEvent, useState } from "react";
import { BellRing, LoaderCircle, RefreshCw, ShieldAlert, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useEnterprise } from "@/components/enterprise/policy-context";
import { checkBreachedPasswords } from "@/lib/enterprise/health";
import {
  acknowledgeBreaches, applyBreachResults, breachCheckDue, breachWatchKey, EMPTY_BREACH_WATCH,
  nextCheckLabel, parseBreachWatch, rememberBreachResults, type BreachWatchState,
} from "@/lib/enterprise/breach-watch";
import type { VaultItem } from "@/lib/vault/items";

function load(key: string): BreachWatchState {
  try { return parseBreachWatch(window.localStorage.getItem(key)); } catch { return { ...EMPTY_BREACH_WATCH }; }
}

/** Home-screen card: weekly on-device breach re-check with alerts for newly breached passwords.
 * Render with key={tenantId} so switching workspace reloads its own state. */
export function BreachWatchCard({ identityId, tenantId, items, onReview }: {
  identityId: string;
  tenantId: string | null;
  items: VaultItem[];
  onReview: () => void;
}) {
  const { policy } = useEnterprise();
  const key = tenantId ? breachWatchKey(identityId, tenantId) : null;
  const [state, setState] = useState<BreachWatchState>(() => (typeof window === "undefined" || !key ? { ...EMPTY_BREACH_WATCH } : load(key)));
  const [checking, setChecking] = useState(false);
  const [message, setMessage] = useState("");
  const required = policy.breachMonitoring === "required";
  const logins = items.filter((item) => !item.deletedAt && item.contentType === "login" && item.payload.secret);
  const effective = required ? { ...state, enabled: true } : state;

  function save(next: BreachWatchState) {
    setState(next);
    if (!key) return;
    try { window.localStorage.setItem(key, JSON.stringify(next)); } catch { /* storage unavailable: works for this session */ }
  }

  async function runCheck(base: BreachWatchState) {
    if (!tenantId || checking) return;
    setChecking(true); setMessage("");
    try {
      const results = await checkBreachedPasswords(logins);
      rememberBreachResults(tenantId, results);
      save(applyBreachResults({ ...base, enabled: true }, results, logins.map((item) => item.id)));
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "The breach check could not complete. It will try again next time.");
    } finally { setChecking(false); }
  }

  const autoCheck = useEffectEvent(() => { void runCheck(effective); });
  const due = breachCheckDue(effective) && logins.length > 0;
  useEffect(() => {
    if (!due || !tenantId) return;
    const timer = window.setTimeout(() => autoCheck(), 1_500);
    return () => window.clearTimeout(timer);
  }, [due, tenantId]);

  if (!tenantId || policy.breachMonitoring === "off") return null;

  if (!effective.enabled) {
    return <section className="watch-card" aria-labelledby="watch-title">
      <span className="watch-icon"><BellRing /></span>
      <div>
        <h3 id="watch-title">Turn on Breach Watch</h3>
        <p>Get an alert here when one of your saved passwords shows up in a new data breach. Passkey-X checks once a week on this device. Only the first 5 characters of each password&apos;s hash are sent to Have I Been Pwned — never your passwords.</p>
      </div>
      <Button onClick={() => void runCheck({ ...state, enabled: true })} disabled={checking || logins.length === 0}>{checking ? <LoaderCircle className="spin" /> : <ShieldCheck />} Turn on</Button>
      {logins.length === 0 && <small className="field-hint">Add a login first.</small>}
      {message && <p className="form-message" role="alert">{message}</p>}
    </section>;
  }

  const fresh = effective.fresh.filter((id) => logins.some((item) => item.id === id));
  if (fresh.length) {
    return <section className="watch-card alert" role="alert" aria-labelledby="watch-title">
      <span className="watch-icon"><ShieldAlert /></span>
      <div>
        <h3 id="watch-title">{fresh.length === 1 ? "1 password was found in a data breach" : `${fresh.length} passwords were found in a data breach`}</h3>
        <p>Change {fresh.length === 1 ? "it" : "them"} now — attackers try breached passwords on other sites. The Security screen walks you through each one.</p>
      </div>
      <Button onClick={() => { save(acknowledgeBreaches(state)); onReview(); }}>Review and fix</Button>
    </section>;
  }

  return <section className="watch-card quiet" aria-labelledby="watch-title">
    <span className="watch-icon"><ShieldCheck /></span>
    <div>
      <h3 id="watch-title">Breach Watch is on</h3>
      <p>{checking ? "Checking your passwords…" : effective.lastCheckedAt
        ? `Last checked ${new Date(effective.lastCheckedAt).toLocaleDateString()}: ${effective.known.length ? `${effective.known.length} breached password${effective.known.length === 1 ? "" : "s"} still to change.` : "no breached passwords."} ${nextCheckLabel(effective)}.`
        : nextCheckLabel(effective)}</p>
    </div>
    <div className="watch-actions">
      {effective.known.length > 0 && <Button variant="outline" onClick={onReview}>Fix now</Button>}
      <Button variant="ghost" onClick={() => void runCheck(effective)} disabled={checking || logins.length === 0}>{checking ? <LoaderCircle className="spin" /> : <RefreshCw />} Check now</Button>
      {!required && <Button variant="ghost" onClick={() => save({ ...state, enabled: false })}>Turn off</Button>}
    </div>
    {message && <p className="form-message" role="alert">{message}</p>}
  </section>;
}
