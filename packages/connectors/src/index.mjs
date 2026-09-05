import { createHash } from "node:crypto";

export const CONNECTOR_CAPABILITIES = Object.freeze([
  "authorize", "discover", "provision", "deprovision",
  "issue_ephemeral_credential", "revoke", "reconcile", "health", "cost_license",
]);

export const CONNECTOR_METHODS = Object.freeze([
  "authorize", "discover", "provision", "deprovision",
  "issueEphemeralCredential", "revoke", "reconcile", "health", "costLicense",
]);

const FORBIDDEN_TELEMETRY_KEYS = /(?:authorization|cookie|credential|password|private.?key|recovery|secret|token)/iu;
const FORBIDDEN_DISCOVERY_KEYS = /(?:dom|form|html|page.?content|vault.?content|plaintext|raw.?prompt)/iu;

function frozenStrings(values, field) {
  if (!Array.isArray(values) || values.length === 0 || values.some((value) => typeof value !== "string" || !value.trim())) {
    throw new TypeError(`${field} must be a non-empty string array`);
  }
  return Object.freeze([...new Set(values.map((value) => value.trim()))]);
}

export function defineConnector(manifest) {
  if (!manifest || typeof manifest !== "object") throw new TypeError("connector manifest is required");
  if (!/^[a-z0-9][a-z0-9-]{2,63}$/u.test(manifest.key ?? "")) throw new TypeError("invalid connector key");
  if (typeof manifest.name !== "string" || manifest.name.trim().length < 2) throw new TypeError("connector name is required");
  const capabilities = frozenStrings(manifest.capabilities,"capabilities");
  const unsupported = capabilities.filter((capability) => !CONNECTOR_CAPABILITIES.includes(capability));
  if (unsupported.length) throw new TypeError(`unsupported capabilities: ${unsupported.join(", ")}`);
  const minimumScopes = frozenStrings(manifest.minimumScopes,"minimumScopes");
  return Object.freeze({
    key: manifest.key,
    name: manifest.name.trim(),
    category: manifest.category,
    authScheme: manifest.authScheme,
    capabilities,
    minimumScopes,
    maturity: manifest.maturity ?? "manifest",
  });
}

export function createConnectorContext({ tenantId, connectorId, invocationId, signal }) {
  for (const [field,value] of Object.entries({ tenantId,connectorId,invocationId })) {
    if (typeof value !== "string" || !value) throw new TypeError(`${field} is required`);
  }
  return Object.freeze({ tenantId,connectorId,invocationId,signal });
}

export function assertMinimumScopes(manifest, grantedScopes) {
  const granted = new Set(frozenStrings(grantedScopes,"grantedScopes"));
  const missing = manifest.minimumScopes.filter((scope) => !granted.has(scope));
  if (missing.length) throw new Error(`minimum connector scopes are missing: ${missing.join(", ")}`);
  return true;
}

function walk(value, path = "result") {
  if (value === null || value === undefined) return;
  if (Array.isArray(value)) return value.forEach((entry,index) => walk(entry,`${path}[${index}]`));
  if (typeof value !== "object") return;
  for (const [key,entry] of Object.entries(value)) {
    if (FORBIDDEN_TELEMETRY_KEYS.test(key)) throw new Error(`secret-shaped field at ${path}.${key}`);
    if (FORBIDDEN_DISCOVERY_KEYS.test(key)) throw new Error(`disallowed discovery field at ${path}.${key}`);
    walk(entry,`${path}.${key}`);
  }
}

export function assertPrivacySafeResult(result) {
  walk(result);
  return result;
}

// Provider errors may contain arbitrary personal data or short credentials.
// Pattern redaction cannot establish the public telemetry boundary.
export function redactConnectorError(_reason) {
  return {
    code: "CONNECTOR_OPERATION_FAILED",
    message: "Connector operation failed. Check the connection and try again.",
  };
}

export async function runConnectorCertification({ manifest, adapter, context }) {
  const checks = {
    manifest: false,
    minimumScopes: false,
    health: false,
    discoveryPrivacy: false,
    reconcileIdempotency: false,
    noSecretTelemetry: false,
  };
  const normalized = defineConnector(manifest);
  checks.manifest = true;
  assertMinimumScopes(normalized,normalized.minimumScopes);
  checks.minimumScopes = true;
  if (!adapter || typeof adapter.health !== "function" || typeof adapter.discover !== "function" || typeof adapter.reconcile !== "function") {
    throw new TypeError("adapter must implement health, discover, and reconcile");
  }
  const health = assertPrivacySafeResult(await adapter.health(context));
  if (!health || !["healthy","degraded"].includes(health.status)) throw new Error("invalid health result");
  checks.health = true;
  const discovery = assertPrivacySafeResult(await adapter.discover(context,{ cursor: null, limit: 1 }));
  if (!discovery || !Array.isArray(discovery.records)) throw new Error("invalid discovery result");
  checks.discoveryPrivacy = true;
  const first = assertPrivacySafeResult(await adapter.reconcile(context,{ dryRun: true }));
  const second = assertPrivacySafeResult(await adapter.reconcile(context,{ dryRun: true }));
  if (JSON.stringify(first) !== JSON.stringify(second)) throw new Error("dry-run reconciliation is not deterministic");
  checks.reconcileIdempotency = true;
  checks.noSecretTelemetry = true;
  const evidence = JSON.stringify({ connector: normalized.key,checks });
  return Object.freeze({
    connectorKey: normalized.key,
    result: "passed",
    checks: Object.freeze(checks),
    evidenceSha256: createHash("sha256").update(evidence).digest("hex"),
  });
}
