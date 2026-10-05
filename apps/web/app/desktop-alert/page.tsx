"use client";

import { useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { desktop, isDesktopApp, type GuardAlert } from "@/lib/desktop/bridge";

type Alert = GuardAlert & { at: number };

function valid(value: unknown): value is Alert {
  const alert = value as Partial<Alert> | null;
  return Boolean(alert && typeof alert.title === "string" && alert.title && typeof alert.detail === "string" && typeof alert.site === "string");
}

/**
 * The desktop app's emergency alert window (always on top). The app puts the alert in
 * window.__PX_ALERTS__ before the page loads and sends later ones as "passkey-x:alert" events.
 * Text only; the window can only close itself or open the security check in the main window.
 */
export default function DesktopAlertPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);

  useEffect(() => {
    const queued = (window as unknown as { __PX_ALERTS__?: unknown[] }).__PX_ALERTS__ ?? [];
    const initial = queued.filter(valid).slice(-10).reverse();
    const timer = setTimeout(() => setAlerts(initial), 0);
    const add = (event: Event) => {
      const detail = (event as CustomEvent).detail;
      if (valid(detail)) setAlerts((current) => [detail, ...current].slice(0, 10));
    };
    window.addEventListener("passkey-x:alert", add);
    return () => { clearTimeout(timer); window.removeEventListener("passkey-x:alert", add); };
  }, []);

  const [first, ...rest] = alerts;
  if (!first) return <main className="guard-alert" />;
  const dangerous = first.level === "dangerous";
  return <main className={`guard-alert ${dangerous ? "dangerous" : "suspicious"}`} role="alertdialog" aria-labelledby="guard-alert-title" aria-describedby="guard-alert-detail">
    <div className="guard-alert-icon"><ShieldAlert aria-hidden="true" /></div>
    <p className="guard-alert-kicker">{dangerous ? "Security alert" : "Security warning"} · Passkey-X Guard</p>
    <h1 id="guard-alert-title">{first.title}</h1>
    {first.site && <p className="guard-alert-site">{first.site}</p>}
    <p id="guard-alert-detail">{first.detail}</p>
    {dangerous && first.site && <p className="guard-alert-advice">Don&apos;t enter passwords or payment details there. If you already did, change that password now and tell your IT team.</p>}
    {rest.length > 0 && <details><summary>{rest.length} earlier alert{rest.length === 1 ? "" : "s"}</summary>
      <ul>{rest.map((alert) => <li key={`${alert.at}-${alert.title}`}><strong>{alert.title}</strong>{alert.site ? ` · ${alert.site}` : ""}</li>)}</ul>
    </details>}
    <div className="guard-alert-actions">
      <button type="button" className="primary" autoFocus onClick={() => { if (isDesktopApp()) void desktop.alertWindow.dismiss(); }}>OK</button>
      {!first.site && <button type="button" onClick={() => { if (isDesktopApp()) void desktop.alertWindow.openMain(); }}>Open security check</button>}
    </div>
  </main>;
}
