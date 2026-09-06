"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import type { SupabaseClient } from "@supabase/supabase-js";
import { Activity, Bot, CircleAlert, GitBranch, KeyRound, Plus, RefreshCw, ShieldAlert, ShieldCheck, SquareStop, Waypoints } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { TenantEntitlement } from "@/lib/billing/client";
import { supabase } from "@/lib/supabase/client";
import type { WorkspaceVault } from "@/lib/vault/items";

type RuntimeDashboard = {
  activation: { control_plane_enabled: boolean; issuance_enabled: boolean; kill_switch_active: boolean; review_status: string; adapter_status: string } | null;
  resources: number;
  agents: number;
  pending_requests: number;
  active_sessions: number;
  evidence_events: number;
};
type Resource = { id: string; display_name: string; resource_type: string; adapter_key: string; adapter_stage: string; allowed_scopes: string[]; max_duration_minutes: number; status: string };
type Agent = { id: string; identity_id: string; display_name: string; allowed_scopes: string[]; max_lease_minutes: number; status: string; responsible_owner_identity_id: string };
type PrivilegeRequest = { id: string; resource_id: string; subject_identity_id: string; requested_scopes: string[]; requested_duration_minutes: number; status: string; decision_code: string | null; created_at: string };
type Evidence = { sequence: number; event_type: string; event_metadata: Record<string, unknown>; occurred_at: string; actor_identity_id: string | null };
type Simulation = { id: string; action_type: string; impact_summary: Record<string, number | string>; risk_level: string; created_at: string };
type TaskCapsule = { id: string; agent_profile_id: string; resource_ids: string[]; allowed_scopes: string[]; expires_at: string; max_uses: number; use_count: number; status: string };

const EMPTY: RuntimeDashboard = { activation: null, resources: 0, agents: 0, pending_requests: 0, active_sessions: 0, evidence_events: 0 };

function untypedClient(): SupabaseClient {
  if (!supabase) throw new Error("Supabase is unavailable.");
  return supabase as unknown as SupabaseClient;
}

async function hash(value: string) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)));
  return `\\x${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function friendlyError(reason: unknown) {
  const message = reason instanceof Error ? reason.message : String(reason ?? "");
  if (/business|entitlement/iu.test(message)) return "The Business package is required for this control.";
  if (/permission|42501|row-level/iu.test(message)) return "An owner or security administrator must perform this action.";
  if (/runtime_activation_required/iu.test(message)) return "The request was recorded but credential issuance remains blocked by the review and adapter gates.";
  return "The runtime control could not be completed. Try again.";
}

export function RuntimeAccessView({ vault, entitlement, onOpenBilling }: { vault: WorkspaceVault; entitlement: TenantEntitlement; onOpenBilling: () => void }) {
  const [dashboard, setDashboard] = useState(EMPTY);
  const [resources, setResources] = useState<Resource[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [requests, setRequests] = useState<PrivilegeRequest[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [simulations, setSimulations] = useState<Simulation[]>([]);
  const [capsules, setCapsules] = useState<TaskCapsule[]>([]);
  const [resourceName, setResourceName] = useState("");
  const [resourceType, setResourceType] = useState("database");
  const [adapterKey, setAdapterKey] = useState("custom-adapter");
  const [targetReference, setTargetReference] = useState("");
  const [resourceScopes, setResourceScopes] = useState("read, administer");
  const [agentName, setAgentName] = useState("");
  const [agentScopes, setAgentScopes] = useState("read");
  const [capsuleAgentId, setCapsuleAgentId] = useState("");
  const [capsuleResourceId, setCapsuleResourceId] = useState("");
  const [capsuleScopes, setCapsuleScopes] = useState("read");
  const [capsulePurpose, setCapsulePurpose] = useState("");
  const [simulationTarget, setSimulationTarget] = useState(vault.identityId);
  const [simulationAction, setSimulationAction] = useState("role_change");
  const [busy, setBusy] = useState("");
  const [message, setMessage] = useState("");
  const businessActive = entitlement.plan_code === "business" && (entitlement.source === "manual" || ["trialing", "active", "past_due"].includes(entitlement.subscription_status));

  const refresh = useCallback(async () => {
    if (!businessActive) return;
    setBusy("refresh");
    try {
      const client = untypedClient();
      const [summary, resourceRows, agentRows, requestRows, evidenceRows, simulationRows, capsuleRows] = await Promise.all([
        client.rpc("runtime_dashboard", { p_tenant_id: vault.tenantId }),
        client.from("privileged_resources").select("id,display_name,resource_type,adapter_key,adapter_stage,allowed_scopes,max_duration_minutes,status").eq("tenant_id", vault.tenantId).order("created_at", { ascending: false }),
        client.from("agent_profiles").select("id,identity_id,display_name,allowed_scopes,max_lease_minutes,status,responsible_owner_identity_id").eq("tenant_id", vault.tenantId).order("created_at", { ascending: false }),
        client.from("privilege_requests").select("id,resource_id,subject_identity_id,requested_scopes,requested_duration_minutes,status,decision_code,created_at").eq("tenant_id", vault.tenantId).order("created_at", { ascending: false }).limit(50),
        client.from("session_evidence").select("sequence,event_type,event_metadata,occurred_at,actor_identity_id").eq("tenant_id", vault.tenantId).order("sequence", { ascending: false }).limit(50),
        client.from("access_simulations").select("id,action_type,impact_summary,risk_level,created_at").eq("tenant_id", vault.tenantId).order("created_at", { ascending: false }).limit(10),
        client.from("agent_task_capsules").select("id,agent_profile_id,resource_ids,allowed_scopes,expires_at,max_uses,use_count,status").eq("tenant_id", vault.tenantId).order("created_at", { ascending: false }).limit(25),
      ]);
      const error = [summary.error, resourceRows.error, agentRows.error, requestRows.error, evidenceRows.error, simulationRows.error, capsuleRows.error].find(Boolean);
      if (error) throw error;
      setDashboard((summary.data as RuntimeDashboard | null) ?? EMPTY);
      setResources((resourceRows.data ?? []) as Resource[]);
      setAgents((agentRows.data ?? []) as Agent[]);
      setRequests((requestRows.data ?? []) as PrivilegeRequest[]);
      setEvidence((evidenceRows.data ?? []) as Evidence[]);
      setSimulations((simulationRows.data ?? []) as Simulation[]);
      setCapsules((capsuleRows.data ?? []) as TaskCapsule[]);
      setCapsuleAgentId((current) => current || agentRows.data?.[0]?.id || "");
      setCapsuleResourceId((current) => current || resourceRows.data?.[0]?.id || "");
      setMessage("");
    } catch (reason) { setMessage(friendlyError(reason)); }
    finally { setBusy(""); }
  }, [businessActive, vault.tenantId]);

  useEffect(() => {
    const timer = window.setTimeout(() => { void refresh(); }, 0);
    return () => window.clearTimeout(timer);
  }, [refresh]);

  async function run(label: string, action: () => Promise<unknown>, success: string) {
    setBusy(label); setMessage("");
    try { await action(); setMessage(success); await refresh(); }
    catch (reason) { setMessage(friendlyError(reason)); }
    finally { setBusy(""); }
  }

  const resourceNames = useMemo(() => new Map(resources.map((resource) => [resource.id, resource.display_name])), [resources]);
  if (!businessActive) return <div className="feature-page runtime-page"><div className="feature-intro"><div><span className="status-pill"><Waypoints /> Privileged access</span><h2>Access Twin, agents, and Flight Recorder</h2><p>The Business package includes the Phase 6 control plane. Real credential issuance also requires accepted independent review evidence and a production-certified provider adapter.</p></div><Button onClick={onOpenBilling}>Review Business package</Button></div></div>;

  const activation = dashboard.activation;
  return <div className="feature-page runtime-page">
    <div className="feature-intro"><div><span className="status-pill"><Waypoints /> Phase 6 control plane</span><h2>Privileged access and agent runtime</h2><p>Model resources, preview blast radius, approve short-lived access, stop agents, and inspect tamper-evident session metadata.</p></div><Button variant="outline" disabled={busy !== ""} onClick={() => void refresh()}><RefreshCw /> Refresh</Button></div>
    <div className={`runtime-gate ${activation?.issuance_enabled ? "ready" : "blocked"}`}><ShieldAlert /><div><strong>{activation?.issuance_enabled ? "Credential broker enabled" : "Credential issuance is fail-closed"}</strong><p>Review: {activation?.review_status ?? "pending"} · adapter: {activation?.adapter_status ?? "not configured"} · kill switch: {activation?.kill_switch_active === false ? "released" : "active"}. The control plane works now; no provider credential can be minted while these gates are closed.</p></div></div>
    {message && <p className="settings-message" role="status">{message}</p>}
    <div className="runtime-metrics"><article><KeyRound /><span><strong>{dashboard.resources}</strong>Resources</span></article><article><Bot /><span><strong>{dashboard.agents}</strong>Agents</span></article><article><GitBranch /><span><strong>{dashboard.pending_requests}</strong>Pending</span></article><article><Activity /><span><strong>{dashboard.evidence_events}</strong>Evidence events</span></article></div>
    <div className="runtime-grid">
      <Card><CardHeader><CardTitle><GitBranch /> Access Twin</CardTitle><CardDescription>Preview the current relationships affected by a grant, role change, revoke, agent kill, or account deletion. A simulation never changes access.</CardDescription></CardHeader><CardContent>
        <form className="form-stack" onSubmit={(event) => { event.preventDefault(); void run("simulate", async () => { const { error } = await untypedClient().rpc("simulate_access_impact", { p_tenant_id: vault.tenantId, p_target_identity_id: simulationTarget, p_action_type: simulationAction, p_proposed_change: { source: "web_control_plane" } }); if (error) throw error; }, "Access impact preview created."); }}>
          <div><Label htmlFor="simulation-target">Target identity ID</Label><Input id="simulation-target" required pattern="[0-9a-fA-F-]{36}" value={simulationTarget} onChange={(event) => setSimulationTarget(event.target.value)} /></div>
          <div><Label htmlFor="simulation-action">Proposed action</Label><select id="simulation-action" value={simulationAction} onChange={(event) => setSimulationAction(event.target.value)}><option value="role_change">Role change</option><option value="grant">Grant</option><option value="revoke">Revoke</option><option value="kill_agent">Kill agent</option><option value="delete_account">Delete account</option></select></div>
          <Button disabled={busy !== ""}>{busy === "simulate" ? "Computing…" : "Preview blast radius"}</Button>
        </form>
        <div className="simulation-list">{simulations.map((simulation) => <article key={simulation.id}><span className={`risk-level ${simulation.risk_level}`}>{simulation.risk_level}</span><div><strong>{simulation.action_type.replaceAll("_", " ")}</strong><small>{Object.entries(simulation.impact_summary).filter(([, value]) => typeof value === "number").map(([key, value]) => `${key.replaceAll("_", " ")}: ${value}`).join(" · ")}</small></div></article>)}{!simulations.length && <p className="field-hint">No impact previews yet.</p>}</div>
      </CardContent></Card>

      <Card><CardHeader><CardTitle><KeyRound /> Privileged resources</CardTitle><CardDescription>Target references are hashed before upload. New resources remain drafts until a provider adapter is production-certified.</CardDescription></CardHeader><CardContent>
        <form className="form-stack" onSubmit={(event) => { event.preventDefault(); void run("resource", async () => { const { error } = await untypedClient().rpc("create_privileged_resource", { p_tenant_id: vault.tenantId, p_display_name: resourceName, p_resource_type: resourceType, p_adapter_key: adapterKey, p_target_ref_sha256: await hash(targetReference), p_allowed_scopes: resourceScopes.split(",").map((value) => value.trim()).filter(Boolean), p_max_duration_minutes: 60 }); if (error) throw error; setResourceName(""); setTargetReference(""); }, "Privileged resource draft created."); }}>
          <div className="two-field-row"><div><Label htmlFor="resource-name">Display name</Label><Input id="resource-name" minLength={2} maxLength={120} required value={resourceName} onChange={(event) => setResourceName(event.target.value)} /></div><div><Label htmlFor="resource-type">Type</Label><select id="resource-type" value={resourceType} onChange={(event) => setResourceType(event.target.value)}><option value="database">Database</option><option value="server">Server</option><option value="cloud_role">Cloud role</option><option value="saas_admin">SaaS admin</option><option value="kubernetes">Kubernetes</option><option value="ssh">SSH</option><option value="rdp">RDP</option><option value="custom">Custom</option></select></div></div>
          <div><Label htmlFor="adapter-key">Adapter key</Label><Input id="adapter-key" pattern="[a-z0-9][a-z0-9_.-]{1,79}" required value={adapterKey} onChange={(event) => setAdapterKey(event.target.value.toLowerCase())} /></div>
          <div><Label htmlFor="target-reference">Provider target reference</Label><Input id="target-reference" type="password" autoComplete="off" required value={targetReference} onChange={(event) => setTargetReference(event.target.value)} /><p className="field-hint">Only a SHA-256 digest is stored; do not enter a credential.</p></div>
          <div><Label htmlFor="resource-scopes">Allowed scopes</Label><Input id="resource-scopes" required value={resourceScopes} onChange={(event) => setResourceScopes(event.target.value)} /></div>
          <Button disabled={busy !== ""}><Plus /> {busy === "resource" ? "Creating…" : "Create resource draft"}</Button>
        </form>
        <div className="runtime-list">{resources.map((resource) => <article key={resource.id}><KeyRound /><div><strong>{resource.display_name}</strong><small>{resource.resource_type.replaceAll("_", " ")} · {resource.adapter_key} · max {resource.max_duration_minutes} min</small></div><span className={`governance-state ${resource.status === "active" ? "" : "pending"}`}>{resource.status} / {resource.adapter_stage}</span></article>)}{!resources.length && <p className="field-hint">No privileged resources yet.</p>}</div>
      </CardContent></Card>

      <Card><CardHeader><CardTitle><Bot /> Agent credentials</CardTitle><CardDescription>Agents are accountable non-human identities with a responsible owner, scoped lease limits, and an immediate kill path.</CardDescription></CardHeader><CardContent>
        <form className="form-stack" onSubmit={(event) => { event.preventDefault(); void run("agent", async () => { const { error } = await untypedClient().rpc("create_agent_profile", { p_tenant_id: vault.tenantId, p_display_name: agentName, p_allowed_scopes: agentScopes.split(",").map((value) => value.trim()).filter(Boolean), p_max_lease_minutes: 15 }); if (error) throw error; setAgentName(""); }, "Agent identity created in draft state."); }}><div><Label htmlFor="agent-name">Agent name</Label><Input id="agent-name" minLength={2} maxLength={120} required value={agentName} onChange={(event) => setAgentName(event.target.value)} /></div><div><Label htmlFor="agent-scopes">Maximum scopes</Label><Input id="agent-scopes" required value={agentScopes} onChange={(event) => setAgentScopes(event.target.value)} /></div><Button disabled={busy !== ""}><Plus /> {busy === "agent" ? "Creating…" : "Create agent identity"}</Button></form>
        <div className="runtime-list">{agents.map((agent) => <article key={agent.id}><Bot /><div><strong>{agent.display_name}</strong><small>{agent.allowed_scopes.join(" · ") || "no scopes"} · max lease {agent.max_lease_minutes} min</small></div>{agent.status !== "killed" ? <Button size="sm" variant="outline" disabled={busy !== ""} onClick={() => { if (window.confirm(`Kill ${agent.display_name}? Active sessions and leases will be revoked.`)) void run(`kill-${agent.id}`, async () => { const { error } = await untypedClient().rpc("kill_agent", { p_agent_profile_id: agent.id }); if (error) throw error; }, "Agent killed and active runtime access revoked."); }}><SquareStop /> Kill</Button> : <span className="governance-state revoked">killed</span>}</article>)}{!agents.length && <p className="field-hint">No agent identities yet.</p>}</div>
        <div className="section-divider" />
        <h3>Task Capsule</h3>
        <p className="field-hint">Bind an agent to specific resources, scopes, and a one-hour window. Capsules remain suspended while the runtime activation gate is closed.</p>
        <form className="form-stack" onSubmit={(event) => { event.preventDefault(); void run("capsule", async () => {
          const scopes = capsuleScopes.split(",").map((value) => value.trim()).filter(Boolean);
          const definition = JSON.stringify({ agent: capsuleAgentId, resource: capsuleResourceId, scopes, purpose: capsulePurpose.trim(), ttlMinutes: 60, maxUses: 1 });
          const { error } = await untypedClient().rpc("create_agent_task_capsule", {
            p_agent_profile_id: capsuleAgentId,
            p_resource_ids: [capsuleResourceId],
            p_allowed_scopes: scopes,
            p_definition_sha256: await hash(definition),
            p_expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
            p_max_uses: 1,
          });
          if (error) throw error;
          setCapsulePurpose("");
        }, "Task Capsule created in fail-closed state."); }}>
          <div className="two-field-row"><div><Label htmlFor="capsule-agent">Agent</Label><select id="capsule-agent" required value={capsuleAgentId} onChange={(event) => setCapsuleAgentId(event.target.value)}><option value="" disabled>Select agent</option>{agents.filter((agent) => agent.status !== "killed").map((agent) => <option key={agent.id} value={agent.id}>{agent.display_name}</option>)}</select></div><div><Label htmlFor="capsule-resource">Resource</Label><select id="capsule-resource" required value={capsuleResourceId} onChange={(event) => setCapsuleResourceId(event.target.value)}><option value="" disabled>Select resource</option>{resources.filter((resource) => resource.status !== "retired").map((resource) => <option key={resource.id} value={resource.id}>{resource.display_name}</option>)}</select></div></div>
          <div><Label htmlFor="capsule-purpose">Task purpose</Label><Input id="capsule-purpose" minLength={3} maxLength={160} required value={capsulePurpose} onChange={(event) => setCapsulePurpose(event.target.value)} /></div>
          <div><Label htmlFor="capsule-scopes">Task scopes</Label><Input id="capsule-scopes" required value={capsuleScopes} onChange={(event) => setCapsuleScopes(event.target.value)} /></div>
          <Button disabled={busy !== "" || !capsuleAgentId || !capsuleResourceId}><Plus /> {busy === "capsule" ? "Creating…" : "Create one-hour capsule"}</Button>
        </form>
        <div className="runtime-list">{capsules.map((capsule) => <article key={capsule.id}><KeyRound /><div><strong>{agents.find((agent) => agent.id === capsule.agent_profile_id)?.display_name ?? "Agent task"}</strong><small>{capsule.allowed_scopes.join(" · ")} · {capsule.use_count}/{capsule.max_uses} uses · expires {new Date(capsule.expires_at).toLocaleString()}</small></div><span className={`governance-state ${capsule.status}`}>{capsule.status}</span></article>)}{!capsules.length && <p className="field-hint">No Task Capsules yet.</p>}</div>
      </CardContent></Card>

      <Card><CardHeader><CardTitle><ShieldCheck /> Privileged approvals</CardTitle><CardDescription>Approved requests can reach the broker only after the activation gate is open. Otherwise approval is recorded as blocked.</CardDescription></CardHeader><CardContent><div className="runtime-list">{requests.map((request) => <article key={request.id}><CircleAlert /><div><strong>{resourceNames.get(request.resource_id) ?? "Privileged resource"}</strong><small>{request.requested_scopes.join(" · ")} · {request.requested_duration_minutes} min · {request.decision_code?.replaceAll("_", " ") ?? "awaiting decision"}</small></div>{request.status === "pending" ? <div className="inline-actions"><Button size="sm" disabled={busy !== ""} onClick={() => void run(`approve-${request.id}`, async () => { const { error } = await untypedClient().rpc("decide_privilege_request", { p_request_id: request.id, p_decision: "approved" }); if (error) throw error; }, "Request evaluated against the runtime gate.")}>Approve</Button><Button size="sm" variant="ghost" disabled={busy !== ""} onClick={() => void run(`deny-${request.id}`, async () => { const { error } = await untypedClient().rpc("decide_privilege_request", { p_request_id: request.id, p_decision: "denied" }); if (error) throw error; }, "Request denied.")}>Deny</Button></div> : <span className={`governance-state ${request.status}`}>{request.status}</span>}</article>)}{!requests.length && <p className="field-hint">No privileged requests yet. Draft resources cannot receive requests.</p>}</div></CardContent></Card>
    </div>

    <Card className="flight-recorder"><CardHeader><CardTitle><Activity /> Flight Recorder</CardTitle><CardDescription>Hash-chained, append-only security metadata. Credential values, vault data, raw command output, and prompts are prohibited.</CardDescription></CardHeader><CardContent><div className="evidence-list">{evidence.map((event) => <article key={event.sequence}><span>#{event.sequence}</span><div><strong>{event.event_type.replaceAll("_", " ")}</strong><small>{new Date(event.occurred_at).toLocaleString()} · {Object.keys(event.event_metadata).join(" · ") || "no public metadata"}</small></div></article>)}{!evidence.length && <p className="field-hint">No runtime evidence events yet.</p>}</div></CardContent></Card>
    <div className="privacy-note"><ShieldCheck /><span>Access Twin is advisory. Hosted AI and deterministic simulations cannot invoke the credential broker. Every destructive action requires explicit human confirmation and current authorization.</span></div>
  </div>;
}
