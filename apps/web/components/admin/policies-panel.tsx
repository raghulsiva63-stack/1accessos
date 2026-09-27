"use client";

import { useState } from "react";
import { CircleCheck, CircleOff, LoaderCircle, Pencil, Server, ShieldCheck, Smartphone } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { adminErrorMessage } from "@/components/admin/admin-console";
import {
  describePolicy, POLICY_DEFINITIONS, saveTenantPolicy, serializePolicy, setPolicyEnforced,
  type PolicyDefinition, type StoredPolicy,
} from "@/lib/enterprise/policies";
import type { WorkspaceVault } from "@/lib/vault/items";

const GROUPS: PolicyDefinition["group"][] = ["Authentication", "Vault protection", "Data movement", "Recovery"];

function initialValues(definition: PolicyDefinition, stored?: StoredPolicy) {
  const source = { ...definition.defaults, ...(stored?.configuration ?? {}) };
  const values: Record<string, string | boolean> = {};
  for (const control of definition.controls) {
    const value = source[control.key];
    values[control.key] = control.kind === "toggle" ? value === true : String(value ?? "");
  }
  return values;
}

function PolicyCard({
  definition, stored, vault, canEdit, onChanged,
}: {
  definition: PolicyDefinition;
  stored?: StoredPolicy;
  vault: WorkspaceVault;
  canEdit: boolean;
  onChanged: () => void;
}) {
  const [editing, setEditing] = useState(false);
  const [values, setValues] = useState(() => initialValues(definition, stored));
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const enforced = Boolean(stored?.enforced);

  async function save() {
    setBusy(true); setMessage("");
    try {
      await saveTenantPolicy(vault.tenantId, vault.identityId, definition.type, serializePolicy(definition.type, values));
      setEditing(false); onChanged();
    } catch (reason) { setMessage(reason instanceof Error && !("code" in reason) ? reason.message : adminErrorMessage(reason)); }
    finally { setBusy(false); }
  }

  async function disable() {
    if (!stored || !window.confirm(`Stop enforcing “${definition.title}”?`)) return;
    setBusy(true); setMessage("");
    try { await setPolicyEnforced(stored, false); onChanged(); }
    catch (reason) { setMessage(adminErrorMessage(reason)); }
    finally { setBusy(false); }
  }

  return <article className={`policy-card ${enforced ? "enforced" : ""}`}>
    <header>
      <span className="policy-state">{enforced ? <CircleCheck /> : <CircleOff />}</span>
      <div><strong>{definition.title}</strong><p>{definition.description}</p></div>
      <span className="enforcement-tag" title={definition.enforcement === "server" ? "Enforced by the database for every client" : definition.enforcement === "server+client" ? "Enforced by the database and every client" : "Enforced by every Passkey-X client"}>
        {definition.enforcement === "client" ? <Smartphone /> : <Server />}{definition.enforcement === "client" ? "Client" : "Server"}
      </span>
    </header>
    {!editing ? <footer>
      <span className={enforced ? "policy-value" : "policy-value off"}>{enforced ? describePolicy(definition.type, stored!.configuration) : "Not enforced"}</span>
      {canEdit && <div className="inline-actions">
        {enforced && <Button variant="ghost" size="sm" onClick={() => void disable()} disabled={busy}>Turn off</Button>}
        <Button variant={enforced ? "outline" : "default"} size="sm" onClick={() => { setValues(initialValues(definition, stored)); setEditing(true); }} disabled={busy}><Pencil /> {enforced ? "Edit" : "Enforce"}</Button>
      </div>}
    </footer> : <form className="policy-editor" onSubmit={(event) => { event.preventDefault(); void save(); }}>
      {definition.controls.map((control) => {
        const id = `${definition.type}-${control.key}`;
        if (control.kind === "toggle") return <label key={id} className="check-row"><input type="checkbox" checked={values[control.key] === true} onChange={(event) => setValues({ ...values, [control.key]: event.target.checked })} /> Enabled</label>;
        if (control.kind === "number") return <div key={id}><Label htmlFor={id}>{control.unit[0].toUpperCase() + control.unit.slice(1)}</Label><Input id={id} type="number" min={control.min} max={control.max} step={control.step ?? 1} value={String(values[control.key])} onChange={(event) => setValues({ ...values, [control.key]: event.target.value })} /><small className="field-hint">{control.min}–{control.max}</small></div>;
        return <div key={id}><Label htmlFor={id}>{control.key === "mode" ? "Setting" : "Minimum strength"}</Label><select id={id} value={String(values[control.key])} onChange={(event) => setValues({ ...values, [control.key]: event.target.value })}>{control.options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></div>;
      })}
      <div className="inline-actions"><Button type="submit" size="sm" disabled={busy}>{busy ? <LoaderCircle className="spin" /> : <ShieldCheck />} Save &amp; enforce</Button><Button type="button" variant="ghost" size="sm" onClick={() => setEditing(false)} disabled={busy}>Cancel</Button></div>
    </form>}
    {message && <p className="form-message" role="alert">{message}</p>}
  </article>;
}

export function PoliciesPanel({
  vault, policies, loading, onChanged, canEdit,
}: {
  vault: WorkspaceVault;
  policies: StoredPolicy[];
  loading: boolean;
  onChanged: () => void;
  canEdit: boolean;
}) {
  const scoped = policies.filter((policy) => policy.scope_type !== "tenant" && policy.enforced);
  if (loading && !policies.length) return <div className="vault-loading"><div className="loading-ring" /></div>;
  return <div className="policies-panel">
    <p className="field-hint policies-intro">Organization-wide defaults apply to every member. Department and team overrides are managed in Directory and take precedence for those people.{scoped.length ? ` ${scoped.length} scoped override${scoped.length === 1 ? " is" : "s are"} active.` : ""}</p>
    {GROUPS.map((group) => <Card key={group}>
      <CardHeader><CardTitle>{group}</CardTitle><CardDescription>{group === "Authentication" ? "How members prove who they are." : group === "Vault protection" ? "How the vault behaves on every device." : group === "Data movement" ? "Where vault data is allowed to go." : "What happens when a member loses access."}</CardDescription></CardHeader>
      <CardContent className="policy-grid">
        {POLICY_DEFINITIONS.filter((definition) => definition.group === group).map((definition) => {
          const stored = policies.find((policy) => policy.policy_type === definition.type && policy.scope_type === "tenant");
          return <PolicyCard key={`${definition.type}:${stored?.version ?? 0}`} definition={definition} stored={stored} vault={vault} canEdit={canEdit} onChanged={onChanged} />;
        })}
      </CardContent>
    </Card>)}
  </div>;
}
