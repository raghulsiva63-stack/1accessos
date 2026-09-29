"use client";

import { useEffect, useEffectEvent, useMemo, useRef, useState } from "react";
import {
  TriangleAlert, ChevronRight, FileWarning, Fingerprint, KeyRound, Link2Off, LoaderCircle, RefreshCw,
  Repeat2, ShieldAlert, ShieldCheck, Timer, Zap,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useEnterprise } from "@/components/enterprise/policy-context";
import {
  analyzeVaultHealth, checkBreachedPasswords, reportVaultHealth, STRENGTH_LABELS,
  type HealthIssue,
} from "@/lib/enterprise/health";
import type { VaultItem } from "@/lib/vault/items";
import { AiSecurityCoach } from "@/components/app/ai-security-coach";
import { FixQueue } from "@/components/enterprise/fix-queue";
import { recallBreachResults, rememberBreachResults } from "@/lib/enterprise/breach-watch";
import { buildFixQueue } from "@/lib/vault/change-password";
import { upgradeSuggestions } from "@/lib/security/site-directory";
import {
  ExposedSecretsCard, LookalikeCard, MyBreachesCard, RotationTasksCard, UpgradeCard, useSiteDirectory,
} from "@/components/security/security-extras";

const ISSUE_META: Record<HealthIssue, { label: string; tone: "critical" | "warning" | "info"; icon: typeof ShieldAlert }> = {
  breached: { label: "Found in a breach", tone: "critical", icon: Zap },
  reused: { label: "Reused", tone: "critical", icon: Repeat2 },
  weak: { label: "Weak", tone: "warning", icon: KeyRound },
  old: { label: "Due for rotation", tone: "info", icon: Timer },
  insecure_url: { label: "Insecure http:// site", tone: "warning", icon: Link2Off },
  missing_totp: { label: "No 2FA code stored", tone: "info", icon: Fingerprint },
  lookalike: { label: "Look-alike website", tone: "critical", icon: ShieldAlert },
  exposed_secret: { label: "Secret in notes", tone: "warning", icon: FileWarning },
};

export function SecurityCenter({
  tenantId, items, onOpen, onRotate, clientKind = "web",
}: {
  tenantId: string | null;
  items: VaultItem[];
  onOpen: (id: string) => void;
  /** Opens the item editor with a freshly generated password. */
  onRotate?: (id: string) => void;
  clientKind?: string;
}) {
  const { policy, isOrganization, identityId } = useEnterprise();
  const directory = useSiteDirectory();
  const [breaches, setBreaches] = useState<Map<string, number> | undefined>(() => recallBreachResults(tenantId));
  const [checking, setChecking] = useState(false);
  const [message, setMessage] = useState("");
  const [filter, setFilter] = useState<HealthIssue | "all">("all");
  const autoChecked = useRef(false);
  const rotationDays = policy.passwordRotationDays;
  const [now] = useState(() => Date.now());
  const report = useMemo(() => analyzeVaultHealth(items, breaches, now, rotationDays), [items, breaches, now, rotationDays]);
  const breachAllowed = policy.breachMonitoring !== "off";
  const suggestions = useMemo(() => upgradeSuggestions(items, directory), [items, directory]);
  const readiness = useMemo(() => directory ? {
    passkeyReady: suggestions.filter((entry) => entry.passkey).length,
    twoFactorReady: suggestions.filter((entry) => entry.twoStep).length,
  } : undefined, [directory, suggestions]);

  async function runBreachCheck() {
    setChecking(true); setMessage("");
    try {
      const results = await checkBreachedPasswords(items);
      if (tenantId) rememberBreachResults(tenantId, results);
      setBreaches(results);
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "The breach check could not complete.");
    } finally { setChecking(false); }
  }

  const runRequiredCheck = useEffectEvent(() => { void runBreachCheck(); });
  useEffect(() => {
    if (policy.breachMonitoring !== "required" || autoChecked.current || !items.length) return;
    const timer = window.setTimeout(() => { autoChecked.current = true; runRequiredCheck(); }, 0);
    return () => window.clearTimeout(timer);
  }, [items.length, policy.breachMonitoring]);

  useEffect(() => {
    if (!tenantId || !isOrganization) return;
    const timer = window.setTimeout(() => { void reportVaultHealth(tenantId, report, clientKind, readiness).catch(() => undefined); }, 1_500);
    return () => window.clearTimeout(timer);
  }, [clientKind, isOrganization, readiness, report, tenantId]);

  const reusedCount = new Set(report.reused.flat()).size;
  const tiles: { id: HealthIssue; value: number }[] = [
    { id: "breached", value: report.breached.length },
    { id: "reused", value: reusedCount },
    { id: "weak", value: report.weak.length },
    { id: "old", value: report.old.length },
    { id: "insecure_url", value: report.insecureUrl.length },
    { id: "exposed_secret", value: new Set(report.exposedSecrets.map((finding) => finding.itemId)).size },
  ];
  const shown = report.items.filter((entry) => filter === "all" || entry.issues.includes(filter));
  const byId = new Map(items.map((item) => [item.id, item]));
  const scoreTone = report.score >= 80 ? "good" : report.score >= 60 ? "fair" : "poor";

  return <div className="feature-page security-center">
    <section className="score-hero">
      <div className={`score-ring score-${scoreTone}`} style={{ "--score": `${report.score * 3.6}deg` } as React.CSSProperties}><div><strong>{report.score}</strong><span>/ 100</span></div></div>
      <div>
        <span className="status-pill"><ShieldCheck /> Analysed on this device</span>
        <h2>{report.score >= 80 ? "Your vault is in good shape" : report.score >= 60 ? "A few risks worth fixing" : "Your vault needs attention"}</h2>
        <p>Passwords are scored in memory. {isOrganization ? "Your organization sees only these totals — never passwords, sites or usernames." : "Nothing is sent to Vlightsoft."}</p>
        {breachAllowed && <div className="inline-actions">
          <Button onClick={() => void runBreachCheck()} disabled={checking || !report.loginCount}>{checking ? <LoaderCircle className="spin" /> : <RefreshCw />} {report.breachChecked ? "Re-check breaches" : "Check for breaches"}</Button>
          <small className="field-hint">k-anonymity: only the first 5 characters of each password hash are sent to Have I Been Pwned.</small>
        </div>}
        {message && <p className="form-message" role="alert">{message}</p>}
      </div>
    </section>

    <AiSecurityCoach tenantId={tenantId} metrics={{
      score: report.score, logins: report.loginCount, weak: report.weak.length, reused: reusedCount, old: report.old.length,
      breached: report.breachChecked ? report.breached.length : -1, insecure_sites: report.insecureUrl.length,
      missing_two_step: report.missingTotp.length, passkeys: report.passkeyCount,
    }} />

    <LookalikeCard pairs={report.lookalikes} items={items} onOpen={onOpen} />

    {onRotate && <RotationTasksCard identityId={identityId} items={items} onRotate={onRotate} />}

    <MyBreachesCard tenantId={isOrganization ? tenantId : null} identityId={identityId} />

    {onRotate && <FixQueue tasks={buildFixQueue(items, report)} onRotate={onRotate} />}

    <ExposedSecretsCard findings={report.exposedSecrets} onOpen={onOpen} />

    <UpgradeCard suggestions={suggestions} onOpen={onOpen} loading={!directory} />

    <div className="risk-tiles">
      {tiles.map((tile) => { const meta = ISSUE_META[tile.id]; const Icon = meta.icon; const active = filter === tile.id; return <button key={tile.id} className={`risk-tile tone-${tile.value ? meta.tone : "clear"} ${active ? "active" : ""}`} onClick={() => setFilter(active ? "all" : tile.id)} disabled={tile.id === "breached" && !report.breachChecked}>
        <Icon /><strong>{tile.id === "breached" && !report.breachChecked ? "—" : tile.value}</strong><span>{meta.label}</span>
      </button>; })}
    </div>

    <Card>
      <CardHeader><CardTitle>{filter === "all" ? "Items to review" : ISSUE_META[filter].label}</CardTitle><CardDescription>{report.loginCount} login{report.loginCount === 1 ? "" : "s"} checked · fix the most serious first.</CardDescription></CardHeader>
      <CardContent>
        {shown.length === 0 ? <div className="empty-state"><ShieldCheck /><p>{report.loginCount ? "No issues in this category." : "Add logins to see a security analysis."}</p></div> :
          <ul className="health-list">{shown.map((entry) => {
            const item = byId.get(entry.itemId);
            return <li key={entry.itemId}>
              <button onClick={() => onOpen(entry.itemId)}>
                <span className={`strength-dot s${entry.strength}`} aria-hidden />
                <div><strong>{entry.title}</strong><small>{item?.payload.username ?? ""}{item?.payload.username ? " · " : ""}{STRENGTH_LABELS[entry.strength]}{entry.breachCount ? ` · seen ${entry.breachCount.toLocaleString()} times in breaches` : ""}</small></div>
                <span className="issue-chips">{entry.issues.map((issue) => <span key={issue} className={`issue-chip tone-${ISSUE_META[issue].tone}`}>{ISSUE_META[issue].label}</span>)}</span>
                <ChevronRight />
              </button>
            </li>;
          })}</ul>}
      </CardContent>
    </Card>

    {report.missingTotp.length > 0 && <Card className="soft-card"><CardContent className="soft-card-body"><TriangleAlert /><div><strong>{report.missingTotp.length} site{report.missingTotp.length === 1 ? "" : "s"} without a stored 2FA code</strong><p>Turning on two-step verification at the website — and storing its setup key in a custom field named “TOTP” — protects the account even if the password leaks.</p></div></CardContent></Card>}
  </div>;
}
