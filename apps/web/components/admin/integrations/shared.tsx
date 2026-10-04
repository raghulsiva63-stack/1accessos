"use client";

import { useState } from "react";
import { Check, Copy, KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { adminErrorMessage } from "@/components/admin/admin-console";
import { copySecret } from "@/components/enterprise/vault-guards";
import { connectorErrorMessage } from "@/lib/enterprise/connectors";

export type Tone = "good" | "warn" | "bad" | "idle";

/** Maps a connector / webhook error to a message that is safe and useful to show. */
export function integrationError(reason: unknown, fallback = "The change could not be saved.") {
  const detail = typeof reason === "object" && reason !== null && "message" in reason ? String(reason.message) : String(reason ?? "");
  if (/at most 5 audit/iu.test(detail)) return "An organization can have up to 5 audit streaming destinations.";
  if (/requires an organization/iu.test(detail)) return "Integrations are available for organizations.";
  const mapped = connectorErrorMessage(reason, "");
  if (mapped) return mapped;
  return adminErrorMessage(reason, fallback);
}

/** Whole-string HTML `pattern` that also compiles under the `v` RegExp flag used by modern browsers. */
export function htmlPattern(pattern: string | undefined) {
  if (!pattern) return undefined;
  return pattern
    .replace(/\\?\//gu, (match) => (match.length === 2 ? match : "\\/"))
    .replace(/\\?-\]/gu, (match) => (match.length === 3 ? match : "\\-]"));
}

export function SecretReveal({ secret, title = "Signing secret — shown once", description = "Store it in your SIEM or receiver. Passkey-X cannot show it again.", onDone }: {
  secret: string; title?: string; description?: string; onDone: () => void;
}) {
  const [copied, setCopied] = useState(false);
  return <div className="webhook-secret" role="status">
    <KeyRound aria-hidden="true" /><div><strong>{title}</strong><p>{description}</p><code>{secret}</code></div>
    <div className="inline-actions">
      <Button size="sm" onClick={async () => { try { await copySecret(secret, 120); setCopied(true); } catch { /* clipboard blocked */ } }}>{copied ? <Check /> : <Copy />} {copied ? "Copied" : "Copy"}</Button>
      <Button size="sm" variant="ghost" onClick={onDone}>I saved it</Button>
    </div>
  </div>;
}

export function StatusMessage({ text, tone = "error" }: { text: string; tone?: "error" | "neutral" }) {
  if (!text) return null;
  return <p className={`form-message${tone === "neutral" ? " neutral-message" : ""}`} role="status">{text}</p>;
}

export function Badge({ tone = "idle", children }: { tone?: Tone; children: React.ReactNode }) {
  return <span className={`cx-badge ${tone}`}>{children}</span>;
}
