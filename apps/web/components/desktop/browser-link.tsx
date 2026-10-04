"use client";

import { useEffect, useState, useSyncExternalStore } from "react";
import { Globe, Link2, ShieldCheck, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  answerPairing, browserLinkVersion, installBrowserLinkHost, listPairings, pendingPairing, removePairing, subscribeBrowserLink, type BrowserPairing,
} from "@/lib/desktop/browser-link";
import { isDesktopApp } from "@/lib/desktop/bridge";

const serverVersion = () => 0;

/** Answers the browser extension and shows pairing requests for approval (desktop app only). */
export function DesktopBrowserLink() {
  useEffect(() => { installBrowserLinkHost(); }, []);
  useSyncExternalStore(subscribeBrowserLink, browserLinkVersion, serverVersion);
  const request = typeof window !== "undefined" && isDesktopApp() ? pendingPairing() : null;
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!request) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [request]);
  if (!request) return null;
  const seconds = Math.max(0, Math.round((request.expiresAt - now) / 1000));
  return <div className="modal-backdrop" role="presentation">
    <Card className="item-editor browser-link-approval" role="alertdialog" aria-modal="true" aria-labelledby="browser-link-title" aria-describedby="browser-link-description">
      <CardHeader>
        <span className="feature-icon"><Link2 /></span>
        <CardTitle id="browser-link-title">Pair the {request.browser} extension?</CardTitle>
        <CardDescription id="browser-link-description">The Passkey-X extension in {request.browser} wants to unlock with this app. Check that it shows the same code, then approve.</CardDescription>
      </CardHeader>
      <CardContent className="form-stack">
        <p className="browser-link-code" aria-label={`Verification code ${request.code.split("").join(" ")}`}>{request.code.slice(0, 3)} {request.code.slice(3)}</p>
        <p className="field-hint">After pairing, the extension unlocks on its own while Passkey-X desktop is unlocked, and locks when this app locks. Only approve if you started this in your browser just now. ({seconds}s)</p>
        <div className="inline-actions">
          <Button onClick={() => void answerPairing(true)}><ShieldCheck /> Codes match — pair</Button>
          <Button variant="outline" onClick={() => void answerPairing(false)}>Deny</Button>
        </div>
      </CardContent>
    </Card>
  </div>;
}

/** Settings › This computer: browsers paired with this app. */
export function BrowserPairingsList() {
  const version = useSyncExternalStore(subscribeBrowserLink, browserLinkVersion, serverVersion);
  const [pairings, setPairings] = useState<BrowserPairing[] | null>(null);
  useEffect(() => {
    let active = true;
    listPairings().then((next) => { if (active) setPairings(next); });
    return () => { active = false; };
  }, [version]);
  if (!pairings) return null;
  if (!pairings.length) return <p className="field-hint">No browser is paired yet. In the extension, choose “Unlock with Passkey-X desktop”.</p>;
  return <ul className="browser-pairings">
    {pairings.map((pairing) => <li key={pairing.id}>
      <Globe aria-hidden="true" />
      <div><strong>{pairing.browser}</strong><small>Paired {new Date(pairing.createdAt).toLocaleDateString()}{pairing.lastUsedAt ? ` · last used ${new Date(pairing.lastUsedAt).toLocaleDateString()}` : ""}</small></div>
      <Button size="sm" variant="ghost" aria-label={`Remove ${pairing.browser}`} onClick={() => void removePairing(pairing.id)}><Trash2 /> Remove</Button>
    </li>)}
  </ul>;
}
