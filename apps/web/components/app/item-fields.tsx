"use client";

import { useEffect, useMemo, useState } from "react";
import { Clock3, RefreshCw, ShieldAlert } from "lucide-react";
import { PolicyCopyButton } from "@/components/enterprise/vault-guards";
import { findTotpField, parseTotp, secondsRemaining, totpCode, type TotpConfig } from "@/lib/vault/totp";
import { passwordAgeDays } from "@/lib/vault/rotation";
import { useEnterprise } from "@/components/enterprise/policy-context";
import type { VaultItem } from "@/lib/vault/items";

const SENSITIVE_FIELD = /(cvv|cvc|security code|pin|password|passphrase|secret|private|token|key|seed)/iu;

function TotpCode({ config }: { config: TotpConfig }) {
  const [now, setNow] = useState(() => Date.now());
  const [code, setCode] = useState("");
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(timer);
  }, []);
  const step = Math.floor(now / 1000 / config.period);
  useEffect(() => {
    let active = true;
    void totpCode(config, step * config.period * 1000).then((next) => { if (active) setCode(next); }, () => { if (active) setCode(""); });
    return () => { active = false; };
  }, [config, step]);
  const remaining = secondsRemaining(config, now);
  const pretty = code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
  return <div className="detail-field totp-field">
    <span>One-time code{config.issuer ? ` · ${config.issuer}` : ""}</span>
    <div>
      <code aria-live="polite">{pretty || "……"}</code>
      <span className={`totp-timer${remaining <= 5 ? " ending" : ""}`} aria-label={`${remaining} seconds left`}><i style={{ width: `${(remaining / config.period) * 100}%` }} />{remaining}s</span>
      {code && <PolicyCopyButton value={code} label="Copy one-time code" />}
    </div>
  </div>;
}

/**
 * Renders an item's extra fields (imported card details, identity fields, TOTP seeds),
 * a live TOTP code, and the password age with a rotation hint.
 */
export function ItemFields({ item, revealed, onRotate }: { item: VaultItem; revealed: boolean; onRotate?: () => void }) {
  const totpEntry = findTotpField(item.payload.fields);
  const totpSeed = totpEntry?.[1];
  const totp = useMemo(() => parseTotp(totpSeed), [totpSeed]);
  const [now] = useState(() => Date.now());
  const { policy } = useEnterprise();
  const extra = Object.entries(item.payload.fields ?? {}).filter(([name, value]) => value && name !== totpEntry?.[0]);
  const age = item.payload.secret && !item.deletedAt ? passwordAgeDays(item.payload, now) : null;
  const stale = age !== null && age >= policy.passwordRotationDays;

  return <>
    {totp && <TotpCode config={totp} />}
    {extra.map(([name, value]) => {
      const sensitive = SENSITIVE_FIELD.test(name);
      return <div className="detail-field" key={name}>
        <span>{name}</span>
        <div>{sensitive ? <code>{revealed ? value : "••••••"}</code> : <p>{value}</p>}<PolicyCopyButton value={value} audit={sensitive} label={`Copy ${name}`} /></div>
      </div>;
    })}
    {age !== null && <div className={`password-age${stale ? " stale" : ""}`}>
      {stale ? <ShieldAlert /> : <Clock3 />}
      <span>{age === 0 ? "Secret changed today" : `Secret changed ${age} day${age === 1 ? "" : "s"} ago`}{stale ? " — time to rotate it" : ""}</span>
      {stale && onRotate && <button type="button" onClick={onRotate}><RefreshCw /> Rotate</button>}
    </div>}
  </>;
}
