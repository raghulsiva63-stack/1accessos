// Validation of structured AI answers before they reach an administrator. Anything that does not
// match the known alerts or the policy catalogue is dropped. Pure.

import { isStricter, POLICY_TYPES, validPolicyConfiguration } from "./policy-rules";

export type TriageItem = { kind: string; priority: 1 | 2 | 3 | 4 | 5; why: string; next_step: string };
export type PolicyRecommendation = { policy_type: string; configuration: Record<string, unknown>; reason: string };

function clean(value: unknown, max: number): string {
  return typeof value === "string" ? value.replace(/[\u0000-\u001f\u007f]+/gu, " ").replace(/\s+/gu, " ").trim().slice(0, max) : "";
}

export const TRIAGE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["summary", "items"],
  properties: {
    summary: { type: "string" },
    items: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["kind", "priority", "why", "next_step"],
        properties: {
          kind: { type: "string" },
          priority: { type: "integer", minimum: 1, maximum: 5 },
          why: { type: "string" },
          next_step: { type: "string" },
        },
      },
    },
  },
} as const;

export const POLICY_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["summary", "recommendations"],
  properties: {
    summary: { type: "string" },
    recommendations: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["policy_type", "configuration_json", "reason"],
        properties: {
          policy_type: { type: "string", enum: [...POLICY_TYPES] },
          configuration_json: { type: "string" },
          reason: { type: "string" },
        },
      },
    },
  },
} as const;

export function validateTriage(raw: unknown, knownKinds: Set<string>): { summary: string; items: TriageItem[] } | null {
  if (!raw || typeof raw !== "object") return null;
  const value = raw as { summary?: unknown; items?: unknown };
  if (!Array.isArray(value.items)) return null;
  const seen = new Set<string>();
  const items: TriageItem[] = [];
  for (const entry of value.items.slice(0, 20)) {
    if (!entry || typeof entry !== "object") continue;
    const item = entry as Record<string, unknown>;
    const kind = clean(item.kind, 60);
    const priority = Number(item.priority);
    if (!knownKinds.has(kind) || seen.has(kind) || !Number.isInteger(priority) || priority < 1 || priority > 5) continue;
    const why = clean(item.why, 400); const next = clean(item.next_step, 400);
    if (!why || !next) continue;
    seen.add(kind);
    items.push({ kind, priority: priority as TriageItem["priority"], why, next_step: next });
  }
  items.sort((a, b) => a.priority - b.priority);
  return { summary: clean(value.summary, 600), items };
}

export function validatePolicyAdvice(raw: unknown, enforced: { type: string; configuration: unknown }[]):
  { summary: string; recommendations: PolicyRecommendation[] } | null {
  if (!raw || typeof raw !== "object") return null;
  const value = raw as { summary?: unknown; recommendations?: unknown };
  if (!Array.isArray(value.recommendations)) return null;
  const current = new Map(enforced.map((entry) => [entry.type, entry.configuration]));
  const seen = new Set<string>();
  const recommendations: PolicyRecommendation[] = [];
  for (const entry of value.recommendations.slice(0, 12)) {
    if (!entry || typeof entry !== "object") continue;
    const item = entry as Record<string, unknown>;
    const type = clean(item.policy_type, 60);
    if (seen.has(type)) continue;
    let configuration: unknown;
    try { configuration = JSON.parse(String(item.configuration_json ?? "")); } catch { continue; }
    if (!validPolicyConfiguration(type, configuration)) continue;
    // Only suggestions that tighten the current setting (never loosen it) reach the admin.
    if (!isStricter(type, configuration as Record<string, unknown>, current.get(type) as Record<string, unknown> | undefined)) continue;
    const reason = clean(item.reason, 400);
    if (!reason) continue;
    seen.add(type);
    recommendations.push({ policy_type: type, configuration: configuration as Record<string, unknown>, reason });
  }
  return { summary: clean(value.summary, 600), recommendations };
}
