import type { MemberOverview } from "@/lib/enterprise/admin";

/**
 * Team rollout: where each person is in getting set up. Uses only the organisation
 * member overview (sign-in, two-step and aggregate vault-health facts) — never vault contents.
 */
export type RolloutStage = "not_started" | "signed_in" | "vault_in_use" | "protected";

export type RolloutRow = {
  identityId: string;
  name: string;
  email: string | null;
  stage: RolloutStage;
  signedIn: boolean;
  vaultInUse: boolean;
  twoStep: boolean;
  recent: boolean;
  nextStep: string;
};

const DAY = 86_400_000;

export const STAGE_LABEL: Record<RolloutStage, string> = {
  not_started: "Not started",
  signed_in: "Signed in",
  vault_in_use: "Using the vault",
  protected: "Fully set up",
};

export function rolloutRow(member: MemberOverview, now = Date.now()): RolloutRow {
  const signedIn = Boolean(member.last_sign_in_at);
  const vaultInUse = Boolean(member.health_reported_at) || (member.login_count ?? 0) > 0;
  const twoStep = member.mfa_factors > 0 || (member.passkey_count ?? 0) > 0;
  const recent = signedIn && now - Date.parse(member.last_sign_in_at!) <= 30 * DAY;
  const stage: RolloutStage = !signedIn ? "not_started" : !vaultInUse ? "signed_in" : !twoStep ? "vault_in_use" : "protected";
  const nextStep = stage === "not_started" ? "Accept the invitation and sign in"
    : stage === "signed_in" ? "Save or import their passwords"
    : stage === "vault_in_use" ? "Turn on two-step verification or a passkey"
    : recent ? "Nothing — all set" : "Sign in again (inactive for 30+ days)";
  return {
    identityId: member.identity_id,
    name: member.display_name || member.email || "Member",
    email: member.email,
    stage, signedIn, vaultInUse, twoStep, recent, nextStep,
  };
}

export type RolloutSummary = {
  total: number;
  counts: Record<RolloutStage, number>;
  percentComplete: number;
  rows: RolloutRow[];
};

/** Active members only, least-progressed first so admins see who needs a nudge. */
export function summarizeRollout(members: MemberOverview[], now = Date.now()): RolloutSummary {
  const order: RolloutStage[] = ["not_started", "signed_in", "vault_in_use", "protected"];
  const rows = members.filter((member) => member.membership_status === "active")
    .map((member) => rolloutRow(member, now))
    .sort((a, b) => order.indexOf(a.stage) - order.indexOf(b.stage) || a.name.localeCompare(b.name));
  const counts = { not_started: 0, signed_in: 0, vault_in_use: 0, protected: 0 } as Record<RolloutStage, number>;
  for (const row of rows) counts[row.stage] += 1;
  return { total: rows.length, counts, percentComplete: rows.length ? Math.round((counts.protected / rows.length) * 100) : 0, rows };
}

function csvCell(value: unknown) {
  const text = value === null || value === undefined ? "" : String(value);
  const safe = /^[=+\-@\t\r]/u.test(text) ? `'${text}` : text;
  return /[",\n\r]/u.test(safe) ? `"${safe.replaceAll('"', '""')}"` : safe;
}

export function rolloutCsv(summary: RolloutSummary) {
  const header = ["Name", "Email", "Status", "Signed in", "Using the vault", "Two-step on", "Active in last 30 days", "Next step"];
  const lines = summary.rows.map((row) => [row.name, row.email, STAGE_LABEL[row.stage], row.signedIn ? "Yes" : "No", row.vaultInUse ? "Yes" : "No", row.twoStep ? "Yes" : "No", row.recent ? "Yes" : "No", row.nextStep].map(csvCell).join(","));
  return [header.join(","), ...lines].join("\r\n") + "\r\n";
}

/** A friendly message the admin can paste into email or chat for people who have not finished. */
export function reminderMessage(organizationName: string, appUrl = "https://passkey-x.com") {
  return [
    `Hi — a quick reminder to finish setting up Passkey-X for ${organizationName}.`,
    "",
    `1. Sign in at ${appUrl} with your work email (use the invitation link if you have not accepted it yet).`,
    "2. Create your vault password and save your recovery key somewhere safe.",
    "3. Import or add your work passwords (Settings → Import).",
    "4. Turn on two-step verification or add a passkey (Account security).",
    "",
    `It takes about 5 minutes. Step-by-step help: ${appUrl}/help`,
  ].join("\n");
}
