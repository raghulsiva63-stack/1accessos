"use client";

import { useEffect, useState } from "react";
import {
  BriefcaseBusiness, Check, ChevronRight, Clock3, FolderKanban, Inbox, Play, Plus, Send,
  Share2, ShieldAlert, ShieldCheck, UserPlus, Users, Vault, X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { VaultItem, WorkspaceVault } from "@/lib/vault/items";
import {
  consumeAccessCapsule, createAccessCapsule, createAccessRequest, createMission,
  createSharedWorkspace, createWorkspaceInvite, decideAccessRequest, listAccessRequests,
  listMissions, listReceivedCapsules, listSentCapsules, listWorkspaceInvites, listWorkspaceMembers,
  revokeAccessCapsule, revokeWorkspaceInvite, revokeWorkspaceMember, startMission,
  type AccessRequest, type Mission, type ReceivedCapsule, type SentCapsule, type WorkspaceInvite,
  type WorkspaceMember, type WorkspaceRole, type WorkspaceSuite,
} from "@/lib/collaboration/phase2";
import { ITEM_TYPES, customerError, DetailField, CopyButton } from "@/components/app/shell/shared";

export function WorkspacesView({ identityId, rootKey, workspaces, vault, onSelect, onReload }: {
  identityId: string; rootKey: Uint8Array; workspaces: WorkspaceVault[]; vault: WorkspaceVault;
  onSelect: (id: string) => Promise<void>; onReload: (id?: string) => Promise<void>;
}) {
  const [name, setName] = useState("");
  const [suite, setSuite] = useState<WorkspaceSuite>("team");
  const [recipient, setRecipient] = useState("");
  const [role, setRole] = useState<WorkspaceRole>("viewer");
  const [expiresDays, setExpiresDays] = useState(7);
  const [shareLink, setShareLink] = useState("");
  const [members, setMembers] = useState<WorkspaceMember[]>([]);
  const [invites, setInvites] = useState<WorkspaceInvite[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  async function refreshLists(current = vault) {
    const [nextMembers, nextInvites] = await Promise.all([listWorkspaceMembers(current), listWorkspaceInvites(current)]);
    setMembers(nextMembers); setInvites(nextInvites);
  }
  useEffect(() => { let active = true; Promise.all([listWorkspaceMembers(vault), listWorkspaceInvites(vault)]).then(([nextMembers, nextInvites]) => { if (active) { setMembers(nextMembers); setInvites(nextInvites); } }).catch((reason) => { if (active) setMessage(customerError(reason, "Unable to load collaboration details. Try again.")); }); return () => { active = false; }; }, [vault]);

  async function createWorkspace(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setMessage("");
    try {
      const created = await createSharedWorkspace(identityId, rootKey, name, suite);
      created.key.fill(0); // the reload opens its own copy of the key
      await onReload(created.workspaceId); setName(""); setMessage(`${created.name} is ready.`);
    } catch (reason) { setMessage(customerError(reason, "Unable to create this workspace. Try again.")); }
    finally { setBusy(false); }
  }
  async function invite(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setMessage(""); setShareLink("");
    try {
      const link = await createWorkspaceInvite(vault, recipient, role, new Date(Date.now() + expiresDays * 86_400_000).toISOString(), window.location.origin);
      setShareLink(link); setRecipient(""); await refreshLists();
    } catch (reason) { setMessage(customerError(reason, "Unable to create this invitation. Try again.")); }
    finally { setBusy(false); }
  }
  async function revokeMember(member: WorkspaceMember) {
    if (!window.confirm("Revoke this member now? Future server access ends immediately and the workspace will be marked for key rotation.")) return;
    setBusy(true); setMessage("");
    try { await revokeWorkspaceMember(vault, member.identityId); await onReload(vault.workspaceId); setMessage("Member revoked. Cryptographic key rotation is now required."); }
    catch (reason) { setMessage(customerError(reason, "Unable to revoke this member. Try again.")); }
    finally { setBusy(false); }
  }
  async function revokeInvite(inviteRow: WorkspaceInvite) {
    setBusy(true); setMessage("");
    try { await revokeWorkspaceInvite(inviteRow.id); await refreshLists(); }
    catch (reason) { setMessage(customerError(reason, "Unable to revoke this invitation. Try again.")); }
    finally { setBusy(false); }
  }

  const canManage = vault.role === "owner" || vault.role === "manager";
  return <div className="feature-page phase2-page">
    <div className="feature-intro"><div><span className="status-pill"><Users /> Encrypted collaboration</span><h2>Share passwords with the right people</h2><p>Each workspace is a separate vault with its own encryption key — for your family, a client or a team. People you invite see only that workspace, never your personal vault.</p></div><div className="credit-meter"><span>Workspaces</span><strong>{workspaces.length}</strong><small>active</small></div></div>
    <div className="pv-explain ws-steps">
      <div><Plus /><strong>1. Create a workspace</strong><p>Give it a name, such as “Family” or “Client Aurora”.</p></div>
      <div><UserPlus /><strong>2. Invite by email</strong><p>Choose what they can do, then send them the one-time link yourself.</p></div>
      <div><ShieldCheck /><strong>3. They accept</strong><p>After they sign in with that email, the shared passwords appear in their app.</p></div>
    </div>
    {vault.suite === "personal" && workspaces.length > 1 && <div className="pv-note"><Users /><p>You are in your personal vault, which is never shared. Switch to a shared workspace below to invite people.</p></div>}
    <div className="workspace-grid">
      <Card><CardHeader><CardTitle>Your workspaces</CardTitle><CardDescription>Switching changes which client-side key is active.</CardDescription></CardHeader><CardContent><div className="workspace-list">{workspaces.map((entry) => <button key={entry.workspaceId} className={entry.workspaceId === vault.workspaceId ? "active" : ""} onClick={() => void onSelect(entry.workspaceId)}><span className="feature-icon">{entry.suite === "professional" ? <BriefcaseBusiness /> : <Users />}</span><span><strong>{entry.name}</strong><small>{entry.suite} · {entry.role}</small></span>{entry.keyRotationRequired ? <ShieldAlert /> : <ChevronRight />}</button>)}</div></CardContent></Card>
      <Card><CardHeader><CardTitle>Create a workspace</CardTitle><CardDescription>For a household, client engagement, team or multi-department office.</CardDescription></CardHeader><CardContent><form className="form-stack" onSubmit={createWorkspace}><div><Label htmlFor="workspace-name">Encrypted name</Label><Input id="workspace-name" required minLength={2} value={name} onChange={(event) => setName(event.target.value)} placeholder="Client Aurora" /></div><div><Label htmlFor="workspace-suite">Suite</Label><select id="workspace-suite" value={suite} onChange={(event) => setSuite(event.target.value as WorkspaceSuite)}><option value="family">Family</option><option value="professional">Professional / client</option><option value="team">Team · one workgroup</option><option value="business">Business · departments and teams</option></select></div><Button disabled={busy}>{busy ? "Creating…" : "Create encrypted workspace"}</Button></form></CardContent></Card>
    </div>
    {vault.keyRotationRequired && <div className="rotation-warning"><ShieldAlert /><div><strong>Workspace key rotation required</strong><p>A member was revoked. Their server access and envelopes are disabled. Because a device may have retained a previously decrypted value, move sensitive credentials into a freshly keyed workspace before future use.</p></div></div>}
    {vault.suite !== "personal" && <div className="workspace-grid">
      <Card><CardHeader><CardTitle>Invite a verified member</CardTitle><CardDescription>The full link contains a 256-bit secret in its fragment. Send it through a trusted channel.</CardDescription></CardHeader><CardContent>{canManage ? <form className="form-stack" onSubmit={invite}><div><Label htmlFor="invite-email">Recipient email</Label><Input id="invite-email" type="email" required value={recipient} onChange={(event) => setRecipient(event.target.value)} /></div><div className="inline-fields"><div><Label htmlFor="invite-role">Role</Label><select id="invite-role" value={role} onChange={(event) => setRole(event.target.value as WorkspaceRole)}><option value="manager">Manager</option><option value="editor">Member / editor</option><option value="viewer">Guest / viewer</option></select></div><div><Label htmlFor="invite-expiry">Expires</Label><select id="invite-expiry" value={expiresDays} onChange={(event) => setExpiresDays(Number(event.target.value))}><option value={1}>1 day</option><option value={7}>7 days</option><option value={30}>30 days</option></select></div></div><Button disabled={busy}><UserPlus /> {busy ? "Creating…" : "Create secure invitation"}</Button></form> : <p className="field-hint">Only workspace owners and managers can invite members.</p>}{shareLink && <div className="one-time-link"><strong>Copy this link now</strong><code>{shareLink}</code><CopyButton value={shareLink} audit={false} /><small>Passkey-X stores only its verifier. The secret cannot be recovered later.</small></div>}</CardContent></Card>
      <Card><CardHeader><CardTitle>People and invitations</CardTitle><CardDescription>Roles are enforced by row-level authorization on every request.</CardDescription></CardHeader><CardContent><div className="member-list">{members.map((member) => <article key={member.identityId}><span className="avatar">{member.role.slice(0, 1).toUpperCase()}</span><div><strong>{member.identityId === identityId ? "You" : `Member ${member.identityId.slice(0, 8)}`}</strong><small>{member.role} · {member.status}</small></div>{canManage && member.role !== "owner" && member.status === "active" && <Button variant="ghost" disabled={busy} onClick={() => void revokeMember(member)}>Revoke</Button>}</article>)}{invites.map((inviteRow) => <article key={inviteRow.id}><span className="feature-icon"><Send /></span><div><strong>Invitation {inviteRow.id.slice(0, 8)}</strong><small>{inviteRow.role} · {inviteRow.status} · expires {new Date(inviteRow.expiresAt).toLocaleDateString()}</small></div>{canManage && ["pending","accepted"].includes(inviteRow.status) && <Button variant="ghost" disabled={busy} onClick={() => void revokeInvite(inviteRow)}>Revoke</Button>}</article>)}</div></CardContent></Card>
    </div>}
    {message && <p className="settings-message" role="status">{message}</p>}
  </div>;
}

export function SharingView({ vault, items }: { vault: WorkspaceVault; items: VaultItem[] }) {
  const [itemId, setItemId] = useState(items[0]?.id ?? "");
  const [recipient, setRecipient] = useState("");
  const [policy, setPolicy] = useState<"reveal" | "fill_only">("fill_only");
  const [purpose, setPurpose] = useState("support");
  const [expiresDays, setExpiresDays] = useState(1);
  const [oneTime, setOneTime] = useState(true);
  const [sent, setSent] = useState<SentCapsule[]>([]);
  const [shareLink, setShareLink] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  async function refresh() { setSent(await listSentCapsules(vault)); }
  useEffect(() => { let active = true; listSentCapsules(vault).then((next) => { if (active) setSent(next); }).catch((reason) => { if (active) setMessage(customerError(reason, "Unable to load active shares. Try again.")); }); return () => { active = false; }; }, [vault]);
  async function submit(event: React.FormEvent) {
    event.preventDefault(); const item = items.find((candidate) => candidate.id === itemId); if (!item) return;
    setBusy(true); setMessage(""); setShareLink("");
    try { setShareLink(await createAccessCapsule(vault, item, recipient, policy, purpose, new Date(Date.now() + expiresDays * 86_400_000).toISOString(), oneTime ? 1 : 0, window.location.origin)); setRecipient(""); await refresh(); }
    catch (reason) { setMessage(customerError(reason, "Unable to create this Access Capsule. Try again.")); }
    finally { setBusy(false); }
  }
  async function revoke(capsule: SentCapsule) { if (!window.confirm("Revoke this Access Capsule?")) return; setBusy(true); try { await revokeAccessCapsule(capsule.id); await refresh(); } catch (reason) { setMessage(customerError(reason, "Unable to revoke this Access Capsule. Try again.")); } finally { setBusy(false); } }
  return <div className="feature-page phase2-page"><div className="feature-intro"><div><span className="status-pill"><Share2 /> Access Capsule</span><h2>Share a purpose, not a copied password</h2><p>Passkey-X encrypts a snapshot with a fresh share key. Email verification, expiry, usage limits and revocation control future delivery.</p></div></div><div className="workspace-grid"><Card><CardHeader><CardTitle>Create Access Capsule</CardTitle><CardDescription>No plaintext credential is placed in the link, database, audit record or email.</CardDescription></CardHeader><CardContent>{items.length ? <form className="form-stack" onSubmit={submit}><div><Label htmlFor="share-item">Item</Label><select id="share-item" value={itemId} onChange={(event) => setItemId(event.target.value)}>{items.map((item) => <option key={item.id} value={item.id}>{item.payload.title}</option>)}</select></div><div><Label htmlFor="share-email">Verified recipient email</Label><Input id="share-email" type="email" required value={recipient} onChange={(event) => setRecipient(event.target.value)} /></div><div className="inline-fields"><div><Label htmlFor="share-policy">Reveal policy</Label><select id="share-policy" value={policy} onChange={(event) => setPolicy(event.target.value as "reveal" | "fill_only")}><option value="fill_only">Fill-only / no reveal</option><option value="reveal">Reveal allowed</option></select></div><div><Label htmlFor="share-purpose">Purpose</Label><select id="share-purpose" value={purpose} onChange={(event) => setPurpose(event.target.value)}><option value="family">Family</option><option value="client">Client</option><option value="project">Project</option><option value="support">Support</option><option value="handover">Handover</option><option value="other">Other</option></select></div></div><div className="inline-fields"><div><Label htmlFor="share-expiry">Expires</Label><select id="share-expiry" value={expiresDays} onChange={(event) => setExpiresDays(Number(event.target.value))}><option value={1}>1 day</option><option value={7}>7 days</option><option value={30}>30 days</option></select></div><label className="check-row"><input type="checkbox" checked={oneTime} onChange={(event) => setOneTime(event.target.checked)} /> One-time use</label></div><Button disabled={busy}><Send /> {busy ? "Encrypting…" : "Create secure link"}</Button></form> : <div className="small-empty"><Vault /><strong>Add an item first</strong><span>Access Capsules are encrypted snapshots of an existing item.</span></div>}{shareLink && <div className="one-time-link"><strong>Copy this link now</strong><code>{shareLink}</code><CopyButton value={shareLink} audit={false} /><small>The fragment secret is shown only once.</small></div>}</CardContent></Card><Card><CardHeader><CardTitle>Sent capsules</CardTitle><CardDescription>Revocation stops future server delivery. It cannot erase knowledge already captured by a recipient device.</CardDescription></CardHeader><CardContent><div className="member-list">{sent.length ? sent.map((capsule) => <article key={capsule.id}><span className="feature-icon"><Share2 /></span><div><strong>{items.find((item) => item.id === capsule.itemId)?.payload.title ?? "Encrypted item"}</strong><small>{capsule.revealPolicy.replace("_", "-")} · {capsule.status} · {capsule.maxUses ? `${capsule.useCount}/${capsule.maxUses} uses` : "unlimited uses"}</small></div>{["pending","accepted"].includes(capsule.status) && <Button variant="ghost" disabled={busy} onClick={() => void revoke(capsule)}>Revoke</Button>}</article>) : <div className="small-empty"><Send /><strong>No active shares</strong><span>Created capsules will appear here.</span></div>}</div></CardContent></Card></div>{policy === "fill_only" && <div className="rotation-warning neutral"><ShieldAlert /><div><strong>Fill-only is not DRM</strong><p>Passkey-X hides the value in its normal interface, but a compromised recipient device or target website may still capture a filled credential.</p></div></div>}{message && <p className="settings-message" role="status">{message}</p>}</div>;
}

export function MissionsView({ vault, items }: { vault: WorkspaceVault; items: VaultItem[] }) {
  const [missions, setMissions] = useState<Mission[]>([]);
  const [title, setTitle] = useState("");
  const [duration, setDuration] = useState(60);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [active, setActive] = useState<Mission | null>(null);
  const [activeExpiresAt, setActiveExpiresAt] = useState<Date | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  async function refresh() { setMissions(await listMissions(vault)); }
  useEffect(() => { let mounted = true; listMissions(vault).then((next) => { if (mounted) setMissions(next); }).catch((reason) => { if (mounted) setMessage(customerError(reason, "Unable to load Missions. Try again.")); }); return () => { mounted = false; }; }, [vault]);
  async function submit(event: React.FormEvent) { event.preventDefault(); setBusy(true); setMessage(""); try { await createMission(vault, title, selectedIds, duration); setTitle(""); setSelectedIds([]); await refresh(); } catch (reason) { setMessage(customerError(reason, "Unable to create this Mission. Try again.")); } finally { setBusy(false); } }
  async function run(mission: Mission) { setBusy(true); setMessage(""); try { const expiresAt = await startMission(vault, mission); setActive(mission); setActiveExpiresAt(new Date(expiresAt)); } catch (reason) { setMessage(customerError(reason, "Unable to start this Mission. Try again.")); } finally { setBusy(false); } }
  function openSite(item: VaultItem) { try { const url = new URL(item.payload.url ?? ""); if (!["http:","https:"].includes(url.protocol)) throw new Error(); window.open(url.href, "_blank", "noopener,noreferrer"); } catch { setMessage("This item does not have a safe HTTP or HTTPS address."); } }
  return <div className="feature-page phase2-page"><div className="feature-intro"><div><span className="status-pill"><FolderKanban /> Mission Mode</span><h2>Open only what the task needs</h2><p>A Mission is an encrypted task definition with an explicit item set and a timeboxed run. It does not grant access outside this workspace.</p></div></div><div className="workspace-grid"><Card><CardHeader><CardTitle>Build a Mission</CardTitle><CardDescription>Choose the minimum credentials needed for one task.</CardDescription></CardHeader><CardContent>{items.length ? <form className="form-stack" onSubmit={submit}><div><Label htmlFor="mission-title">Encrypted Mission name</Label><Input id="mission-title" required value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Client Aurora support" /></div><div><Label htmlFor="mission-duration">Run duration</Label><select id="mission-duration" value={duration} onChange={(event) => setDuration(Number(event.target.value))}><option value={30}>30 minutes</option><option value={60}>1 hour</option><option value={240}>4 hours</option><option value={480}>8 hours</option></select></div><fieldset className="item-checklist"><legend>Allowed items</legend>{items.map((item) => <label key={item.id}><input type="checkbox" checked={selectedIds.includes(item.id)} onChange={(event) => setSelectedIds(event.target.checked ? [...selectedIds, item.id] : selectedIds.filter((id) => id !== item.id))} /><span><strong>{item.payload.title}</strong><small>{item.payload.url || ITEM_TYPES[item.contentType].label}</small></span></label>)}</fieldset><Button disabled={busy || selectedIds.length === 0}><Plus /> Create Mission</Button></form> : <div className="small-empty"><FolderKanban /><strong>No items available</strong><span>Add credentials before building a Mission.</span></div>}</CardContent></Card><Card><CardHeader><CardTitle>Saved Missions</CardTitle><CardDescription>Definitions decrypt only after this workspace unlocks.</CardDescription></CardHeader><CardContent><div className="mission-list">{missions.length ? missions.map((mission) => <article key={mission.id} className={active?.id === mission.id ? "active" : ""}><div><strong>{mission.title}</strong><small>{mission.itemIds.length} items · {mission.durationMinutes} minutes</small></div><Button variant="outline" disabled={busy} onClick={() => void run(mission)}><Play /> Start</Button>{active?.id === mission.id && activeExpiresAt && <div className="mission-run"><span><Clock3 /> Active until {activeExpiresAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>{mission.itemIds.map((id) => { const item = items.find((candidate) => candidate.id === id); return item ? <button key={id} onClick={() => openSite(item)}>{item.payload.title}<ChevronRight /></button> : null; })}</div>}</article>) : <div className="small-empty"><Play /><strong>No Missions yet</strong><span>Your encrypted task launchers will appear here.</span></div>}</div></CardContent></Card></div>{message && <p className="settings-message" role="status">{message}</p>}</div>;
}

export function AccessInboxView({ identityId, rootKey, vault, items }: { identityId: string; rootKey: Uint8Array; vault: WorkspaceVault; items: VaultItem[] }) {
  const [capsules, setCapsules] = useState<ReceivedCapsule[]>([]);
  const [requests, setRequests] = useState<AccessRequest[]>([]);
  const [opened, setOpened] = useState<ReceivedCapsule | null>(null);
  const [scope, setScope] = useState<AccessRequest["requestedScope"]>("reveal");
  const [itemId, setItemId] = useState(items[0]?.id ?? "");
  const [purpose, setPurpose] = useState("");
  const [duration, setDuration] = useState(60);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  async function refresh() { const [nextCapsules, nextRequests] = await Promise.all([listReceivedCapsules(identityId, rootKey), listAccessRequests(vault)]); setCapsules(nextCapsules); setRequests(nextRequests); }
  useEffect(() => { let active = true; Promise.all([listReceivedCapsules(identityId, rootKey), listAccessRequests(vault)]).then(([nextCapsules, nextRequests]) => { if (active) { setCapsules(nextCapsules); setRequests(nextRequests); } }).catch((reason) => { if (active) setMessage(customerError(reason, "Unable to load the access inbox. Try again.")); }); return () => { active = false; }; }, [identityId, rootKey, vault]);
  async function openCapsule(capsule: ReceivedCapsule) { setBusy(true); setMessage(""); try { await consumeAccessCapsule(capsule.id); setOpened(capsule); setCapsules((current) => current.filter((entry) => entry.id !== capsule.id)); } catch (reason) { setMessage(customerError(reason, "This Access Capsule is no longer available.")); } finally { setBusy(false); } }
  async function request(event: React.FormEvent) { event.preventDefault(); setBusy(true); setMessage(""); try { await createAccessRequest(vault, itemId || null, scope, purpose, duration); setPurpose(""); await refresh(); } catch (reason) { setMessage(customerError(reason, "Unable to request access. Try again.")); } finally { setBusy(false); } }
  async function decide(row: AccessRequest, decision: "approved" | "denied") { setBusy(true); setMessage(""); try { await decideAccessRequest(row.id, decision); await refresh(); } catch (reason) { setMessage(customerError(reason, "Unable to record this decision. Try again.")); } finally { setBusy(false); } }
  const canApprove = vault.role === "owner" || vault.role === "manager";
  const canRequest = vault.role !== "owner";
  return <div className="feature-page phase2-page"><div className="feature-intro"><div><span className="status-pill"><Inbox /> Access inbox</span><h2>Timeboxed access with a clear decision trail</h2><p>Purposes are encrypted with the workspace key. Decisions and expiry remain visible as authorization metadata and audit evidence.</p></div></div><div className="workspace-grid"><Card><CardHeader><CardTitle>Received Access Capsules</CardTitle><CardDescription>Opening records a use. Fill-only entries never expose the secret in this interface.</CardDescription></CardHeader><CardContent><div className="member-list">{capsules.length ? capsules.map((capsule) => <article key={capsule.id}><span className="feature-icon"><Share2 /></span><div><strong>{capsule.payload.title}</strong><small>{capsule.revealPolicy.replace("_", "-")} · expires {new Date(capsule.expiresAt).toLocaleString()}</small></div><Button variant="outline" disabled={busy} onClick={() => void openCapsule(capsule)}>Open</Button></article>) : <div className="small-empty"><Inbox /><strong>Inbox is clear</strong><span>Accepted capsules that are still valid appear here.</span></div>}</div></CardContent></Card><Card><CardHeader><CardTitle>{canRequest ? "Request temporary access" : "Pending approvals"}</CardTitle><CardDescription>{canRequest ? "Ask an owner or manager for an attributable, expiring scope." : "Review requests without exposing their vault contents."}</CardDescription></CardHeader><CardContent>{canRequest && <form className="form-stack" onSubmit={request}><div><Label htmlFor="request-item">Resource</Label><select id="request-item" value={itemId} onChange={(event) => setItemId(event.target.value)}><option value="">Whole workspace</option>{items.map((item) => <option key={item.id} value={item.id}>{item.payload.title}</option>)}</select></div><div className="inline-fields"><div><Label htmlFor="request-scope">Scope</Label><select id="request-scope" value={scope} onChange={(event) => setScope(event.target.value as AccessRequest["requestedScope"])}><option value="use">Use</option><option value="reveal">Reveal</option><option value="edit">Edit</option>{vault.role === "manager" && <option value="manage">Manage</option>}</select></div><div><Label htmlFor="request-duration">Duration</Label><select id="request-duration" value={duration} onChange={(event) => setDuration(Number(event.target.value))}><option value={30}>30 minutes</option><option value={60}>1 hour</option><option value={240}>4 hours</option><option value={480}>8 hours</option></select></div></div><div><Label htmlFor="request-purpose">Encrypted purpose</Label><textarea id="request-purpose" required rows={3} value={purpose} onChange={(event) => setPurpose(event.target.value)} placeholder="Why this access is needed" /></div><Button disabled={busy}><Send /> Submit request</Button></form>}<div className="request-list">{requests.map((row) => <article key={row.id}><div><strong>{row.requestedScope} for {row.itemId ? items.find((item) => item.id === row.itemId)?.payload.title ?? "item" : "workspace"}</strong><p>{row.purpose}</p><small>{row.status} · {row.durationMinutes} minutes · requester {row.requesterIdentityId.slice(0, 8)}</small></div>{canApprove && row.status === "pending" && <div><Button disabled={busy} onClick={() => void decide(row, "approved")}><Check /> Approve</Button><Button variant="outline" disabled={busy} onClick={() => void decide(row, "denied")}><X /> Deny</Button></div>}</article>)}</div></CardContent></Card></div>{opened && <div className="capsule-open"><div className="detail-heading"><div><span>{opened.revealPolicy.replace("_", "-")}</span><h2>{opened.payload.title}</h2></div><button aria-label="Close capsule" onClick={() => setOpened(null)}><X /></button></div>{opened.payload.username && <DetailField label="Username" value={opened.payload.username} copyable={opened.revealPolicy === "reveal"} />}{opened.revealPolicy === "reveal" && opened.payload.secret && <DetailField label="Shared secret" value={opened.payload.secret} copyable />}{opened.payload.url && <DetailField label="Website" value={opened.payload.url} copyable />}{opened.revealPolicy === "fill_only" && <div className="rotation-warning neutral"><ShieldCheck /><div><strong>Fill-only policy active</strong><p>The secret is intentionally hidden here. Use the trusted Passkey-X extension to fill it at the matching site. A compromised endpoint can still capture a filled value.</p></div></div>}</div>}{message && <p className="settings-message" role="status">{message}</p>}</div>;
}
