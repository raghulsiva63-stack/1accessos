"use client";

import { Fingerprint, KeyRound, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useEnterprise } from "@/components/enterprise/policy-context";
import { estimateStrength, STRENGTH_LABELS } from "@/lib/enterprise/health";

export type VaultPasswordFacts = { length: number; strength: number } | null;

/** Measures the vault password once at unlock; only the length and score are kept. */
export function vaultPasswordFacts(password: string): VaultPasswordFacts {
  return { length: password.length, strength: estimateStrength(password).score };
}

/**
 * Shows every organisation policy the current member does not yet meet, with a
 * direct path to fix it. Nothing here weakens the vault if dismissed; admins see
 * non-compliance in the admin console.
 */
export function ComplianceBanner({
  passwordFacts, onOpenAccountSecurity, onOpenSettings,
}: {
  passwordFacts: VaultPasswordFacts;
  onOpenAccountSecurity: () => void;
  onOpenSettings: () => void;
}) {
  const { policy, compliance, isOrganization } = useEnterprise();
  if (!isOrganization || !compliance.checked) return null;
  const issues: { id: string; icon: typeof ShieldAlert; title: string; detail: string; action: string; onAction: () => void }[] = [];
  if (policy.passkeyRequired && compliance.hasPasskey === false) {
    issues.push({ id: "passkey", icon: Fingerprint, title: "Register an account passkey", detail: "Your organization requires phishing-resistant sign-in.", action: "Add passkey", onAction: onOpenAccountSecurity });
  }
  if (policy.mfaRequired && !compliance.hasMfa) {
    issues.push({ id: "mfa", icon: ShieldAlert, title: "Turn on two-step verification", detail: "Your organization requires a second sign-in factor.", action: "Set up", onAction: onOpenAccountSecurity });
  }
  if (passwordFacts && (passwordFacts.length < policy.minVaultPasswordLength || passwordFacts.strength < policy.minVaultPasswordStrength)) {
    issues.push({
      id: "vault-password", icon: KeyRound, title: "Update your vault password",
      detail: `Policy requires at least ${policy.minVaultPasswordLength} characters${policy.minVaultPasswordStrength ? ` and ${STRENGTH_LABELS[policy.minVaultPasswordStrength].toLowerCase()} strength` : ""}.`,
      action: "Change", onAction: onOpenSettings,
    });
  }
  if (!issues.length) return null;
  return <div className="compliance-banner" role="alert">
    <div className="compliance-banner-head"><ShieldAlert /><div><strong>Action required by your organization</strong><p>{issues.length} security requirement{issues.length === 1 ? "" : "s"} still need your attention.</p></div></div>
    <ul>{issues.map((issue) => { const Icon = issue.icon; return <li key={issue.id}><Icon /><div><strong>{issue.title}</strong><span>{issue.detail}</span></div><Button size="sm" onClick={issue.onAction}>{issue.action}</Button></li>; })}</ul>
  </div>;
}
