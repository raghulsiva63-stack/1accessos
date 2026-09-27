"use client";

import { useEffect, useEffectEvent, useRef, useState } from "react";
import { Copy, ShieldCheck } from "lucide-react";
import { useEnterprise } from "@/components/enterprise/policy-context";
import { watchVaultLifetime } from "@/lib/browser/vault-lifecycle";

/**
 * Runs the idle/visibility vault lock using the organisation's session timeout and
 * records one metadata-only "vault.unlocked" event per tenant.
 */
export function PolicyLifecycle({ onLock, tenantId }: { onLock: () => void; tenantId: string | null }) {
  const { policy, record, loading } = useEnterprise();
  const lock = useEffectEvent(() => onLock());
  const minutes = policy.sessionTimeoutMinutes;
  useEffect(() => watchVaultLifetime({
    documentObject: document, windowObject: window, onLock: () => lock(), idleMs: minutes * 60_000,
  }), [minutes]);
  const recorded = useRef<string | null>(null);
  const recordUnlock = useEffectEvent(() => record("vault.unlocked", null));
  useEffect(() => {
    if (!tenantId || loading || recorded.current === tenantId) return;
    recorded.current = tenantId;
    recordUnlock();
  }, [loading, tenantId]);
  return null;
}

/** Records a "secret revealed" event when an item's secret becomes visible. */
export function RevealAudit({ revealed, itemId }: { revealed: boolean; itemId: string | null }) {
  const { record } = useEnterprise();
  const recordReveal = useEffectEvent((id: string) => record("item.revealed", id));
  useEffect(() => { if (revealed && itemId) recordReveal(itemId); }, [itemId, revealed]);
  return null;
}

/**
 * Copies a value and clears it from the clipboard after the policy interval (only if
 * the clipboard still holds the same value). Secret copies are audited as metadata.
 */
export function PolicyCopyButton({ value, audit = true }: { value: string; audit?: boolean }) {
  const { policy, record } = useEnterprise();
  const [copied, setCopied] = useState(false);
  return <button type="button" aria-label="Copy" title={`Copied values clear after ${policy.clipboardClearSeconds}s`} onClick={async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    if (audit) record("item.copied");
    window.setTimeout(() => {
      setCopied(false);
      navigator.clipboard.readText().then((current) => { if (current === value) void navigator.clipboard.writeText(""); }).catch(() => undefined);
    }, policy.clipboardClearSeconds * 1_000);
  }}>{copied ? <ShieldCheck /> : <Copy />}</button>;
}
