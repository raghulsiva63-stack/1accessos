"use client";

import { useEffect, useState, useSyncExternalStore } from "react";
import { TriangleAlert, CircleCheck, Globe, HardDrive, RefreshCw, ShieldAlert, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { isDesktopApp } from "@/lib/desktop/bridge";
import { lastScan, runEndpointScan, scanInProgress, startEndpointGuard, subscribeScan } from "@/lib/desktop/endpoint-scan";
import { findingLabel } from "@/lib/security/guard-client";

const serverSnapshot = () => null;
const serverBusy = () => false;

/** Runs the background security checks in the desktop app (mounted once on the home page). */
export function DesktopGuardRunner() {
  useEffect(() => startEndpointGuard(), []);
  return null;
}

const BROWSER_NAMES: Record<string, string> = { chrome: "Google Chrome", edge: "Microsoft Edge", brave: "Brave", chromium: "Chromium" };

/** Settings › This computer › Security check (desktop app only). */
export function SecurityCheckPanel() {
  const result = useSyncExternalStore(subscribeScan, lastScan, serverSnapshot);
  const busy = useSyncExternalStore(subscribeScan, scanInProgress, serverBusy);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!isDesktopApp() || lastScan() || scanInProgress()) return;
    void runEndpointScan({ alert: false }).catch(() => setError("The security check could not run. Try again."));
  }, []);

  async function scan() {
    setError("");
    try { await runEndpointScan({ alert: false }); } catch { setError("The security check could not run. Try again."); }
  }

  const serious = result?.findings.filter((finding) => finding.severity === "critical" || finding.severity === "high").length ?? 0;
  const installedBrowsers = result?.browsers.filter((browser) => browser.installed) ?? [];
  return <section className="desktop-settings" id="security-check" aria-labelledby="security-check-title">
    <h3 id="security-check-title"><ShieldCheck /> Security check</h3>
    <p className="field-hint">Passkey-X checks this computer&apos;s security settings and installed programs every 6 hours. The list of programs never leaves this computer; your organization sees only problems.</p>
    {result && <div className={`guard-summary ${serious ? "bad" : result.findings.length ? "warn" : "good"}`} role="status">
      {serious ? <ShieldAlert /> : result.findings.length ? <TriangleAlert /> : <CircleCheck />}
      <div>
        <strong>{serious ? `${serious} serious problem${serious === 1 ? "" : "s"} need${serious === 1 ? "s" : ""} attention` : result.findings.length ? `${result.findings.length} thing${result.findings.length === 1 ? "" : "s"} to improve` : "No problems found"}</strong>
        <small>{result.support.label}{result.support.status === "unsupported" ? " (no longer updated)" : ""} · {result.programCount} programs checked · {new Date(result.at).toLocaleString()}{result.reported ? "" : " · not yet sent to your organization"}</small>
      </div>
    </div>}
    {result && result.findings.length > 0 && <ul className="si-list">
      {result.findings.map((finding) => <li key={finding.key} className={`si-row ${finding.severity === "critical" || finding.severity === "high" ? "danger" : "warn"}`}>
        {finding.category === "software" ? <HardDrive aria-hidden="true" /> : finding.kind === "browser_unprotected" ? <Globe aria-hidden="true" /> : <ShieldAlert aria-hidden="true" />}
        <div className="si-main">
          <strong>{finding.subject}</strong>
          <small>{findingLabel(finding.kind)} · {String(finding.detail.why ?? "")}</small>
        </div>
        <span className={`si-tag ${finding.severity === "critical" || finding.severity === "high" ? "bad" : "warn"}`}>{finding.severity}</span>
      </li>)}
    </ul>}
    {installedBrowsers.length > 0 && <p className="field-hint">Browser protection: {installedBrowsers.map((browser) => `${BROWSER_NAMES[browser.browser] ?? browser.browser} ${browser.protected ? "protected" : "not protected"}`).join(" · ")}</p>}
    <div className="inline-actions">
      <Button variant="outline" disabled={busy} onClick={() => void scan()}><RefreshCw /> {busy ? "Checking…" : "Check now"}</Button>
    </div>
    {error && <p className="form-message" role="alert">{error}</p>}
  </section>;
}
