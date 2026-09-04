export class PasskeyXApi {
  constructor({ baseUrl, accessToken, fetch: fetcher = globalThis.fetch }) {
    if (!baseUrl || !accessToken || typeof fetcher !== "function") throw new TypeError("baseUrl, accessToken, and fetch are required");
    this.baseUrl = baseUrl.replace(/\/$/u, "");
    this.accessToken = accessToken;
    this.fetch = fetcher;
  }

  async request(path, options = {}) {
    const response = await this.fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers: {
        authorization: `Bearer ${this.accessToken}`,
        "content-type": "application/json",
        ...options.headers,
      },
    });
    if (response.status === 204) return undefined;
    const body = await response.json();
    if (!response.ok) throw Object.assign(new Error(body?.error?.message ?? "Passkey-X API request failed"), { status: response.status, code: body?.error?.code, requestId: body?.error?.request_id });
    return body;
  }

  itemTypes() { return this.request("/item-types"); }
  vaultItems(workspaceId) { return this.request(`/vault-items?workspace_id=${encodeURIComponent(workspaceId)}`); }
  syncChanges(workspaceId, cursor = "0") { return this.request(`/sync/changes?workspace_id=${encodeURIComponent(workspaceId)}&cursor=${encodeURIComponent(cursor)}`); }
  createVaultItem(envelope, idempotencyKey = crypto.randomUUID()) { return this.request("/vault-items", { method: "POST", headers: { "idempotency-key": idempotencyKey }, body: JSON.stringify(envelope) }); }
  updateVaultItem(itemId, revision, envelope, idempotencyKey = crypto.randomUUID()) { return this.request(`/vault-items/${encodeURIComponent(itemId)}`, { method: "PATCH", headers: { "if-match": `"${revision}"`, "idempotency-key": idempotencyKey }, body: JSON.stringify(envelope) }); }
  deleteVaultItem(itemId, revision, idempotencyKey = crypto.randomUUID()) { return this.request(`/vault-items/${encodeURIComponent(itemId)}`, { method: "DELETE", headers: { "if-match": `"${revision}"`, "idempotency-key": idempotencyKey } }); }
}
