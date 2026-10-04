"use client";

import { useEffect, useEffectEvent, useRef, useState } from "react";
import { Copy, ShieldCheck } from "lucide-react";
import { useEnterprise } from "@/components/enterprise/policy-context";
import { watchVaultLifetime } from "@/lib/browser/vault-lifecycle";
import { desktop, desktopPolicy, isDesktopApp } from "@/lib/desktop/bridge";

/**
 * Runs the idle/visibility vault lock using the organisation's session timeout and
 * records one metadata-only "vault.unlocked" event per tenant.
 */
export function PolicyLifecycle({ onLock, tenantId }: { onLock: () => void; tenantId: string | null }) {
  const { policy, record, loading } = useEnterprise();
  const lock = useEffectEvent(() => onLock());
  // A managed computer can set a shorter idle limit than the organization's account policy.
  const [computerLimit, setComputerLimit] = useState<number | null>(null);
  useEffect(() => {
    let active = true;
    desktopPolicy().then((managed) => { if (active) setComputerLimit(managed.idleLockMinutes); });
    return () => { active = false; };
  }, []);
  const minutes = computerLimit ? Math.min(policy.sessionTimeoutMinutes, computerLimit) : policy.sessionTimeoutMinutes;
  // Desktop: a hidden window (after a quick copy) stays unlocked until the idle limit,
  // unless the person chose "lock when hidden". Until the setting loads, hidden locks.
  const [lockWhenHidden, setLockWhenHidden] = useState(true);
  useEffect(() => {
    if (!isDesktopApp()) return;
    let active = true;
    desktop.settings().then((settings) => { if (active) setLockWhenHidden(settings.lockOnHide); }).catch(() => undefined);
    return () => { active = false; };
  }, []);
  useEffect(() => watchVaultLifetime({
    documentObject: document, windowObject: window, onLock: () => lock(), idleMs: minutes * 60_000, lockWhenHidden,
  }), [minutes, lockWhenHidden]);
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

const pendingClipboardClears = new Set<string>();

/** Best-effort clipboard wipe. readText is unreliable (focus rules, Firefox), so write "" directly. */
export async function clearClipboard() {
  if (isDesktopApp()) { try { await desktop.clearClipboard(); pendingClipboardClears.clear(); } catch { /* app will clear on its own timer */ } return; }
  try { await navigator.clipboard.writeText(""); pendingClipboardClears.clear(); } catch { /* document not focused; retried on next focus */ }
}

/** Wipes the clipboard only if Passkey-X put a secret there that has not been cleared yet (used on lock). */
export function clearPendingClipboard() {
  if (pendingClipboardClears.size) void clearClipboard();
}

if (typeof window !== "undefined") {
  const retry = () => { if (pendingClipboardClears.size && document.hasFocus()) void clearClipboard(); };
  window.addEventListener("focus", retry);
  document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible") retry(); });
}

/** Copies a secret and schedules a wipe; wipes that fail while unfocused retry when the app regains focus. */
export async function copySecret(value: string, clearSeconds: number) {
  // Desktop: the app copies, hides the value from clipboard history and wipes it even
  // while Passkey-X is in the background.
  if (isDesktopApp()) {
    const settings = await desktop.settings().catch(() => null);
    await desktop.copy(value, Math.min(clearSeconds, settings?.clipboardSeconds ?? clearSeconds));
    return;
  }
  await navigator.clipboard.writeText(value);
  const token = crypto.randomUUID();
  pendingClipboardClears.add(token);
  window.setTimeout(() => { if (pendingClipboardClears.has(token)) void clearClipboard(); }, clearSeconds * 1_000);
}

/**
 * Copies a value and clears it from the clipboard after the policy interval.
 * Secret copies are audited as metadata.
 */
export function PolicyCopyButton({ value, audit = true, label = "Copy" }: { value: string; audit?: boolean; label?: string }) {
  const { policy, record } = useEnterprise();
  const [copied, setCopied] = useState(false);
  return <button type="button" aria-label={label} title={`Copied values clear after ${policy.clipboardClearSeconds}s`} onClick={async () => {
    try { await copySecret(value, policy.clipboardClearSeconds); } catch { return; }
    setCopied(true);
    if (audit) record("item.copied");
    window.setTimeout(() => setCopied(false), 2_000);
  }}>{copied ? <ShieldCheck /> : <Copy />}</button>;
}
