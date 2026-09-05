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

// Validate data without invoking provider-controlled getters or serializers.
// Adapters still need explicit per-provider field allowlists and external review.
export function assertPrivacySafeResult(result) {
  const ancestors = new Set();
  let nodes = 0;
  function walk(value, depth = 0) {
    if (++nodes > 10000 || depth > 32) throw new TypeError("connector result exceeds structural limits");
    if (value === null || typeof value === "boolean") return;
    if (typeof value === "string") {
      if (value.length > 65536) throw new TypeError("connector result string exceeds limits");
      return;
    }
    if (typeof value === "number" && Number.isFinite(value)) return;
    if (typeof value !== "object") throw new TypeError("connector result must contain JSON data only");
    if (Array.isArray(value) && (value.length > 10000 || Object.keys(value).length !== value.length
      || Object.keys(value).some((key) => !/^(0|[1-9][0-9]*)$/u.test(key) || Number(key) >= value.length))) {
      throw new TypeError("connector result must contain bounded dense arrays");
    }
    const prototype = Object.getPrototypeOf(value);
    if (!Array.isArray(value) && prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("connector result must contain plain data only");
    }
    if (ancestors.has(value)) throw new TypeError("connector result contains a cycle");
    ancestors.add(value);
    for (const key of Reflect.ownKeys(value)) {
      if (Array.isArray(value) && key === "length") continue;
      if (typeof key !== "string") throw new TypeError("connector result contains a symbol key");
      const descriptor = Object.getOwnPropertyDescriptor(value,key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        throw new TypeError("connector result contains an accessor or hidden field");
      }
      if (FORBIDDEN_TELEMETRY_KEYS.test(key)) throw new Error("secret-shaped field in connector result");
      if (FORBIDDEN_DISCOVERY_KEYS.test(key)) throw new Error("disallowed discovery field in connector result");
      walk(descriptor.value,depth + 1);
    }
    ancestors.delete(value);
  }
  walk(result);
  return result;
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key,canonical(value[key])]));
  }
  return value;
}

// Provider errors may contain arbitrary personal data or short credentials.
// Pattern redaction cannot establish the public telemetry boundary.
export function redactConnectorError(_reason) {
  return {
    code: "CONNECTOR_OPERATION_FAILED",
    message: "Connector operation failed. Check the connection and try again.",
  };
}

export async function runConnectorCertification({ manifest, adapter, context, grantedScopes }) {
  const checks = {
    manifest: false,
    minimumScopes: false,
    health: false,
    discoveryStructure: false,
    dryRunDeterminism: false,
    resultStructure: false,
  };
  const normalized = defineConnector(manifest);
  checks.manifest = true;
  // The server supplies actual grants from its verified connection record.
  const verifiedGrants = frozenStrings(grantedScopes,"grantedScopes");
  assertMinimumScopes(normalized,verifiedGrants);
  const verifiedContext = createConnectorContext(context);
  checks.minimumScopes = true;
  if (!adapter || typeof adapter.health !== "function" || typeof adapter.discover !== "function" || typeof adapter.reconcile !== "function") {
    throw new TypeError("adapter must implement health, discover, and reconcile");
  }
  const health = canonical(assertPrivacySafeResult(await adapter.health(verifiedContext)));
  if (!health || health.status !== "healthy") throw new Error("invalid health result");
  checks.health = true;
  const discovery = canonical(assertPrivacySafeResult(await adapter.discover(verifiedContext,{ cursor: null, limit: 1 })));
  if (!discovery || !Array.isArray(discovery.records)) throw new Error("invalid discovery result");
  checks.discoveryStructure = true;
  const first = canonical(assertPrivacySafeResult(await adapter.reconcile(verifiedContext,{ dryRun: true })));
  const second = canonical(assertPrivacySafeResult(await adapter.reconcile(verifiedContext,{ dryRun: true })));
  for (const result of [first,second]) {
    if (!result || result.dryRun !== true || result.sideEffects !== 0 || !Array.isArray(result.proposals)) {
      throw new Error("reconciliation must acknowledge a dry run with zero side effects");
    }
  }
  if (JSON.stringify(canonical(first)) !== JSON.stringify(canonical(second))) throw new Error("dry-run reconciliation is not deterministic");
  checks.dryRunDeterminism = true;
  checks.resultStructure = true;
  const evidence = JSON.stringify(canonical({
    version: 1,
    manifest: normalized,
    grantedScopes: [...verifiedGrants].sort(),
    context: { tenantId: verifiedContext.tenantId,connectorId: verifiedContext.connectorId,invocationId: verifiedContext.invocationId },
    observations: { health,discovery,reconciliation: first },
    checks,
  }));
  return Object.freeze({
    connectorKey: normalized.key,
    result: "passed",
    validationLevel: "adapter_contract",
    certifiedForProduction: false,
    checks: Object.freeze(checks),
    evidenceSha256: createHash("sha256").update(evidence).digest("hex"),
  });
}
