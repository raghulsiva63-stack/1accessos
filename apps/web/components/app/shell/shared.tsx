"use client";

import Image from "next/image";
import { PolicyCopyButton } from "@/components/enterprise/vault-guards";
import {
  Bell, Bot, LayoutDashboard, Braces, BriefcaseBusiness, CircleGauge, CreditCard, Database, FileKey,
  FileText, Fingerprint, FolderKanban, IdCard, Inbox, KeyRound, Laptop, Radio, Send, Settings,
  Share2, ShieldAlert, ShieldCheck, Sparkles, UserRound, Users, Vault, WandSparkles, Waypoints, Wifi,
  LifeBuoy, CircleHelp, HardDrive,
} from "lucide-react";
import { fromBase64Url } from "@/lib/crypto/vault";
import type { ItemKind } from "@/lib/vault/items";
import type { TenantEntitlement } from "@/lib/billing/client";

export type CryptoProfile = {
  identity_id: string;
  salt: string;
  kdf_parameters: { memoryKib: number; iterations: number; parallelism: number; hashLength: 32 };
  master_nonce: string;
  master_wrapped_root: string;
  recovery_nonce: string;
  recovery_wrapped_root: string;
  recovery_verifier: string | null;
};

export type View = "home" | "desktop" | "vault" | "workspaces" | "organization" | "admin" | "send" | "saas-ai" | "runtime" | "notifications" | "missions" | "sharing" | "inbox" | "security" | "emergency" | "account-security" | "generator" | "automations" | "devices" | "billing" | "help" | "settings";

export type VaultFilter = ItemKind | "all" | "favorites" | "archive" | "trash";

export type DeviceRow = { id: string; status: "pending" | "trusted" | "revoked"; created_at: string; last_seen_at: string | null; revoked_at: string | null };

export type Entitlement = TenantEntitlement;

export const ITEM_TYPES: Record<ItemKind, { label: string; plural: string; icon: typeof KeyRound; secretLabel?: string; userLabel?: string }> = {
  login: { label: "Login", plural: "Logins", icon: UserRound, secretLabel: "Password" },
  passkey: { label: "Passkey reference", plural: "Passkeys", icon: Fingerprint, secretLabel: "Credential ID", userLabel: "Account" },
  "secure-note": { label: "Secure note", plural: "Secure notes", icon: FileText },
  identity: { label: "Identity", plural: "Identities", icon: IdCard, secretLabel: "Identity number", userLabel: "Full name" },
  "payment-card": { label: "Payment card", plural: "Payment cards", icon: CreditCard, secretLabel: "Card number", userLabel: "Cardholder" },
  "recovery-codes": { label: "Recovery codes", plural: "Recovery codes", icon: ShieldAlert, secretLabel: "Codes", userLabel: "Service" },
  wifi: { label: "Wi-Fi", plural: "Wi-Fi", icon: Wifi, secretLabel: "Password", userLabel: "Network name" },
  "software-license": { label: "Software license", plural: "Licenses", icon: FileKey, secretLabel: "License key", userLabel: "Account" },
  "api-key": { label: "API key", plural: "API keys", icon: KeyRound, secretLabel: "Secret", userLabel: "Service or account" },
  "ssh-key": { label: "SSH key reference", plural: "SSH keys", icon: Radio, secretLabel: "Private key or reference", userLabel: "Host or account" },
  database: { label: "Database credential", plural: "Databases", icon: Database, secretLabel: "Password", userLabel: "Username" },
  certificate: { label: "Certificate / secret file", plural: "Certificates", icon: FileKey, secretLabel: "Private material", userLabel: "Subject" },
  "custom-secret": { label: "Custom secret", plural: "Custom secrets", icon: Braces, secretLabel: "Secret", userLabel: "Account" },
};

export const NAV: { id: View; label: string; icon: typeof Vault }[] = [
  { id: "home", label: "Home", icon: CircleGauge },
  { id: "vault", label: "Vault", icon: Vault },
  { id: "workspaces", label: "Workspaces", icon: Users },
  { id: "admin", label: "Admin console", icon: LayoutDashboard },
  { id: "organization", label: "Organization", icon: BriefcaseBusiness },
  { id: "saas-ai", label: "SaaS & AI", icon: Sparkles },
  { id: "runtime", label: "Runtime & Twin", icon: Waypoints },
  { id: "notifications", label: "Notifications", icon: Bell },
  { id: "missions", label: "Missions", icon: FolderKanban },
  { id: "sharing", label: "Sharing", icon: Share2 },
  { id: "send", label: "Secure Send", icon: Send },
  { id: "inbox", label: "Access inbox", icon: Inbox },
  { id: "security", label: "Security", icon: ShieldCheck },
  { id: "emergency", label: "Emergency access", icon: LifeBuoy },
  { id: "account-security", label: "Account security", icon: Fingerprint },
  { id: "generator", label: "Generator", icon: WandSparkles },
  { id: "automations", label: "Automations", icon: Bot },
  { id: "devices", label: "Devices", icon: Laptop },
  { id: "desktop", label: "This computer", icon: HardDrive },
  { id: "billing", label: "Plans & billing", icon: CreditCard },
  { id: "settings", label: "Settings", icon: Settings },
  { id: "help", label: "Help & guides", icon: CircleHelp },
];

export const NAV_SECTIONS: { label: string; views: View[] }[] = [
  { label: "Workspace", views: ["home", "vault", "workspaces"] },
  { label: "Access", views: ["missions", "sharing", "send", "inbox"] },
  { label: "Protect", views: ["security", "emergency", "account-security", "notifications", "generator", "devices", "desktop"] },
  { label: "Manage", views: ["admin", "saas-ai", "runtime", "automations", "billing", "settings", "help"] },
];

/** Deep links from security emails, e.g. /?view=account-security. Only known views are accepted. */
export function viewFromUrl(): View | null {
  if (typeof window === "undefined") return null;
  const requested = new URLSearchParams(window.location.search).get("view");
  return NAV.some((entry) => entry.id === requested) && requested !== "desktop" ? requested as View : null;
}

export function Brand({ compact = false }: { compact?: boolean }) {
  return <div className={`brand ${compact ? "brand-compact" : ""}`}><Image src={compact ? "/brand/passkey-x-mark.png" : "/brand/passkey-x-horizontal.png"} alt="Passkey-X by Vlightsoft" width={compact ? 48 : 230} height={compact ? 48 : 66} priority /></div>;
}

export function bytea(value: string) {
  return value.startsWith("\\x") ? Uint8Array.from(value.slice(2).match(/.{2}/gu) ?? [], (part) => Number.parseInt(part, 16)) : fromBase64Url(value);
}

export function customerError(reason: unknown, fallback: string) {
  const detail = typeof reason === "object" && reason !== null
    ? `${"code" in reason ? String(reason.code) : ""} ${"message" in reason ? String(reason.message) : ""}`.toLowerCase()
    : String(reason ?? "").toLowerCase();

  if (detail.includes("invalid_credentials") || detail.includes("invalid login credentials")) return "Email or login password is incorrect.";
  if (detail.includes("email_not_confirmed") || detail.includes("email not confirmed")) return "Confirm your email before signing in.";
  if (detail.includes("user_already_exists") || detail.includes("already registered") || detail.includes("already exists")) return "An account already exists for this email.";
  if (detail.includes("weak_password") || detail.includes("password should be")) return "Choose a stronger login password with at least 12 characters.";
  if (detail.includes("signup_disabled") || detail.includes("signups not allowed")) return "New account registration is temporarily unavailable.";
  if (detail.includes("rate") || detail.includes("too many")) return "Too many attempts. Wait a moment and try again.";
  if (detail.includes("captcha")) return "Complete the security check again, then retry.";
  if (detail.includes("mfa_phone_enroll_not_enabled") || detail.includes("phone enroll") || detail.includes("sms provider")) return "SMS verification is not active for this environment yet.";
  if (detail.includes("invalid phone") || detail.includes("phone format")) return "Enter a mobile number in international format, such as +14155550123.";
  if (detail.includes("factor") && detail.includes("already")) return "This mobile verification method is already enrolled.";
  if (detail.includes("challenge") || detail.includes("invalid otp") || detail.includes("otp expired")) return "That security code is invalid or expired. Request a new code.";
  if (detail.includes("notallowederror") || detail.includes("cancel") || detail.includes("webauthn")) return "Passkey verification was cancelled or could not be completed.";
  if (detail.includes("passkey") && (detail.includes("disabled") || detail.includes("not enabled"))) return "Passkey sign-in is temporarily unavailable. Use your login password.";
  if (detail.includes("secure device storage")) return "Secure browser storage is unavailable or blocked. Close other Passkey-X tabs, allow site storage, and try again.";
  if (detail.includes("billing_not_configured")) return "Secure billing is not active yet. Your current plan is unchanged.";
  if (detail.includes("subscription_exists")) return "This workspace already has a subscription. Use Manage billing to make changes.";
  if (detail.includes("customer_missing")) return "No billing profile exists for this workspace yet.";
  if (detail.includes("billing_unavailable")) return "Billing is temporarily unavailable. Your current plan is unchanged.";
  return fallback;
}

export function DetailField({ label, value, copyable = false }: { label: string; value: string; copyable?: boolean }) { return <div className="detail-field"><span>{label}</span><div><p>{value}</p>{copyable && <CopyButton value={value} />}</div></div>; }

export function CopyButton({ value, audit = true }: { value: string; audit?: boolean }) { return <PolicyCopyButton value={value} audit={audit} />; }
