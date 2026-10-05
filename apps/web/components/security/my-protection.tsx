"use client";

import { useEffect, useState } from "react";
import { Globe, Laptop, ShieldAlert, ShieldCheck, Smartphone } from "lucide-react";
import Link from "next/link";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { findingLabel, myGuardOverview, type GuardEndpoint, type GuardFinding } from "@/lib/security/guard-client";

const ICONS = { desktop: Laptop, mobile: Smartphone, extension: Globe } as const;

/** Security Center › My protection: this person's protected devices and recent Guard warnings. */
export function MyProtectionCard() {
  const [data, setData] = useState<{ endpoints: GuardEndpoint[]; findings: GuardFinding[] } | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let active = true;
    myGuardOverview().then((value) => { if (active) setData(value); }, () => { if (active) setFailed(true); });
    return () => { active = false; };
  }, []);
  if (failed || !data) return null;
  const open = data.findings.filter((finding) => finding.status === "open");
  const kinds = new Set(data.endpoints.map((endpoint) => endpoint.kind));
  const missing = (["extension", "desktop", "mobile"] as const).filter((kind) => !kinds.has(kind));
  return <Card>
    <CardHeader>
      <CardTitle>My protection</CardTitle>
      <CardDescription>Passkey-X Guard blocks phishing and dangerous sites and checks your devices. Pages are checked on your device; your browsing is never sent anywhere.</CardDescription>
    </CardHeader>
    <CardContent className="si-stack">
      {data.endpoints.length > 0 && <ul className="si-list">{data.endpoints.map((endpoint) => { const Icon = ICONS[endpoint.kind]; return <li key={endpoint.id} className="si-row">
        <Icon aria-hidden="true" />
        <div className="si-main"><strong>{endpoint.kind === "extension" ? "Browser extension" : endpoint.kind === "mobile" ? "Phone" : "Computer"} · {endpoint.label || endpoint.platform}</strong>
          <small>{endpoint.os_version ?? ""}{endpoint.app_version ? ` · version ${endpoint.app_version}` : ""} · checked {new Date(endpoint.last_seen_at).toLocaleDateString()}</small></div>
        <span className="si-tag good"><ShieldCheck /> Protected</span>
      </li>; })}</ul>}
      {missing.length > 0 && <p className="field-hint">Not protected yet: {missing.map((kind) => kind === "extension" ? "your browser" : kind === "desktop" ? "your computer" : "your phone").join(", ")}. <Link href="/download">Get the Passkey-X apps</Link>.</p>}
      {open.length > 0 && <>
        <h4 className="guard-heading">Recent warnings</h4>
        <ul className="si-list">{open.slice(0, 8).map((finding) => <li key={finding.id} className={`si-row ${finding.severity === "critical" || finding.severity === "high" ? "danger" : "warn"}`}>
          <ShieldAlert aria-hidden="true" />
          <div className="si-main"><strong>{findingLabel(finding.kind)}: {finding.subject}</strong>
            <small>{finding.action}{finding.occurrences > 1 ? ` ${finding.occurrences}×` : ""} · {new Date(finding.last_seen_at).toLocaleString()}{typeof finding.detail.why === "string" ? ` · ${finding.detail.why}` : ""}</small></div>
        </li>)}</ul>
      </>}
      {!open.length && data.endpoints.length > 0 && <p className="field-hint">No open warnings. Nice.</p>}
    </CardContent>
  </Card>;
}
