// Mirror of the database rule private.valid_policy_configuration, used to check AI policy
// recommendations before an administrator can apply them. The database still re-checks.

export const POLICY_TYPES = [
  "passkey_required", "device_approval_required", "minimum_vault_password", "sharing_mode",
  "session_timeout_minutes", "export_policy", "mfa_required", "clipboard_clear_seconds",
  "breach_monitoring", "organization_recovery", "password_rotation",
] as const;
export type PolicyTypeName = typeof POLICY_TYPES[number];

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function between(value: unknown, min: number, max: number) {
  return typeof value === "number" && Number.isInteger(value) && value >= min && value <= max;
}

export function validPolicyConfiguration(type: string, config: unknown): boolean {
  if (!isObject(config)) return false;
  const keys = Object.keys(config);
  const only = (...allowed: string[]) => keys.every((key) => allowed.includes(key));
  switch (type) {
    case "passkey_required": case "device_approval_required": case "mfa_required":
      return only("required") && typeof config.required === "boolean";
    case "organization_recovery":
      return only("enabled") && typeof config.enabled === "boolean";
    case "minimum_vault_password":
      return only("min_length", "min_strength") && between(config.min_length, 12, 128)
        && (config.min_strength === undefined || between(config.min_strength, 0, 4));
    case "session_timeout_minutes": return only("minutes") && between(config.minutes, 1, 480);
    case "clipboard_clear_seconds": return only("seconds") && between(config.seconds, 5, 300);
    case "password_rotation": return only("days") && between(config.days, 30, 730);
    case "sharing_mode": return only("mode") && ["open", "internal_only", "disabled"].includes(String(config.mode));
    case "export_policy": return only("mode") && ["allowed", "admins_only", "blocked"].includes(String(config.mode));
    case "breach_monitoring": return only("mode") && ["off", "optional", "required"].includes(String(config.mode));
    default: return false;
  }
}

function stable(value: unknown): string {
  if (!isObject(value)) return JSON.stringify(value);
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
}

export function sameConfiguration(a: unknown, b: unknown) {
  return stable(a) === stable(b);
}

const RANKS: Record<string, Record<string, number>> = {
  sharing_mode: { open: 0, internal_only: 1, disabled: 2 },
  export_policy: { allowed: 0, admins_only: 1, blocked: 2 },
  breach_monitoring: { off: 0, optional: 1, required: 2 },
};

/**
 * True only when `proposed` is stricter than `current` (or than having no policy at all).
 * AI recommendations that would loosen security are never offered.
 */
export function isStricter(type: string, proposed: Record<string, unknown>, current?: Record<string, unknown> | null): boolean {
  switch (type) {
    case "passkey_required": case "device_approval_required": case "mfa_required":
      return proposed.required === true && current?.required !== true;
    case "sharing_mode": case "export_policy": case "breach_monitoring": {
      const rank = RANKS[type];
      const next = rank[String(proposed.mode)] ?? -1;
      const now = current ? rank[String(current.mode)] ?? 0 : 0;
      return next > now;
    }
    case "minimum_vault_password": {
      const length = Number(proposed.min_length); const strength = Number(proposed.min_strength ?? 0);
      const oldLength = Number(current?.min_length ?? 0); const oldStrength = Number(current?.min_strength ?? 0);
      return length >= oldLength && strength >= oldStrength && (length > oldLength || strength > oldStrength);
    }
    case "session_timeout_minutes": return Number(proposed.minutes) <= 60 && (!current || Number(proposed.minutes) < Number(current.minutes));
    case "clipboard_clear_seconds": return Number(proposed.seconds) <= 60 && (!current || Number(proposed.seconds) < Number(current.seconds));
    case "password_rotation": return Number(proposed.days) <= 365 && (!current || Number(proposed.days) < Number(current.days));
    // Organization recovery gives administrators more power; it is a trade-off, not "stricter".
    default: return false;
  }
}
