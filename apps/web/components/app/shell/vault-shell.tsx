"use client";

import { useEffect, useEffectEvent, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { AdminConsole } from "@/components/admin/admin-console";
import { EnterpriseProvider } from "@/components/enterprise/policy-context";
import { ComplianceBanner, type VaultPasswordFacts } from "@/components/enterprise/compliance-banner";
import { SecurityCenter } from "@/components/enterprise/security-center";
import { SecureSendView } from "@/components/enterprise/secure-send";
import { clearPendingClipboard, PolicyLifecycle, RevealAudit } from "@/components/enterprise/vault-guards";
import { CommandPalette, CommandPaletteButton } from "@/components/app/command-palette";
import { forgetBreachResults } from "@/lib/enterprise/breach-watch";
import { Download, LockKeyhole, LogOut, MoreHorizontal, Share2, Sparkles, UserPlus, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { OrganizationView } from "@/components/organization-view";
import { SaasAiManager } from "@/components/saas-ai-manager";
import { AutomationsView } from "@/components/automations-view";
import { CompanionHome } from "@/components/client-experience";
import { NativeAutofillReview } from "@/components/native-autofill";
import type { ClientMode } from "@/lib/browser/client-mode";
import { NotificationsView } from "@/components/notifications-view";
import { RuntimeAccessView } from "@/components/runtime-access-view";
import { supabase } from "@/lib/supabase/client";
import {
  createVaultItem, deleteVaultItem, type ItemKind, listVaultItemHistory, listVaultItemsWithStatus,
  listWorkspaceVaults, restoreVaultItem, type VaultHistoryEntry, type VaultItem, type VaultPayload,
  type WorkspaceVault, updateVaultItem,
} from "@/lib/vault/items";
import { WorkspaceRequestGate } from "@/lib/vault/request-gate";
import { generatePassword, passwordHealth } from "@/lib/vault/tools";
import { acceptAccessCapsule, acceptWorkspaceInvite, parseCollaborationLink, type InviteLink } from "@/lib/collaboration/phase2";
import { FREE_ENTITLEMENT, loadTenantEntitlement, readPlanSelection } from "@/lib/billing/client";
import { acceptOrganizationInvitation, parseOrganizationInvitationLink, type OrganizationInvitationLink } from "@/lib/organization/phase5";
import { ThemeToggle } from "@/components/app/theme-toggle";
import { EmergencyAccessView, EmergencyInviteBanner, EmergencyRequestNotice } from "@/components/app/emergency-access-view";
import { parseEmergencyLink, type EmergencyLink } from "@/lib/enterprise/emergency";
import { OrgRecoveryEnrollment, ProvisioningBanner } from "@/components/app/org-membership";
import { PlansView } from "@/components/billing/plans-view";
import { HelpCenter } from "@/components/app/help-center";
import { GeneratorView, AccountSecurityView, DevicesView, SettingsView } from "@/components/app/shell/account-views";
import { WorkspacesView, SharingView, MissionsView, AccessInboxView } from "@/components/app/shell/collaboration-views";
import { Dashboard } from "@/components/app/shell/home-view";
import { type CryptoProfile, type View, type VaultFilter, type Entitlement, NAV, NAV_SECTIONS, Brand, customerError } from "@/components/app/shell/shared";
import { VaultView, ItemEditor, HistoryDialog } from "@/components/app/shell/vault-view";

export function VaultShell({ clientMode, email, profile, rootKey, passwordFacts, onPasswordFacts, onProfileChange, onLock }: { clientMode: ClientMode; email: string; profile: CryptoProfile; rootKey: Uint8Array; passwordFacts: VaultPasswordFacts; onPasswordFacts: (facts: VaultPasswordFacts) => void; onProfileChange: (profile: CryptoProfile) => void; onLock: () => void }) {
  const [view, setView] = useState<View>(() => readPlanSelection() || (typeof window !== "undefined" && new URLSearchParams(window.location.search).has("billing")) ? "billing" : "home");
  const requests = useRef(new WorkspaceRequestGate());
  const workspaceLoadVersion = useRef(0);
  const [workspaces, setWorkspaces] = useState<WorkspaceVault[]>([]);
  const [vault, setVault] = useState<WorkspaceVault | null>(null);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [trash, setTrash] = useState<VaultItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<VaultFilter>("all");
  const [editor, setEditor] = useState<VaultItem | "new" | null>(null);
  const [rotateSecret, setRotateSecret] = useState<string | null>(null);
  const [selected, setSelected] = useState<VaultItem | null>(null);
  const [revealedId, setRevealedId] = useState<string | null>(null);
  const revealed = revealedId !== null && revealedId === selected?.id;
  const setRevealed = (value: boolean) => setRevealedId(value ? selected?.id ?? null : null);
  const [history, setHistory] = useState<{ itemId: string; entries: VaultHistoryEntry[] } | null>(null);
  const [pendingLink, setPendingLink] = useState<InviteLink | null>(() => typeof window === "undefined" ? null : parseCollaborationLink(window.location.hash));
  const [pendingEmergency, setPendingEmergency] = useState<EmergencyLink | null>(() => typeof window === "undefined" ? null : parseEmergencyLink(window.location.hash));
  const [pendingOrganizationInvite, setPendingOrganizationInvite] = useState<OrganizationInvitationLink | null>(() => typeof window === "undefined" ? null : parseOrganizationInvitationLink(window.location.hash));
  const [accepting, setAccepting] = useState(false);
  const [notice, setNotice] = useState("");
  const [entitlement, setEntitlement] = useState<Entitlement>(FREE_ENTITLEMENT);
  const initials = useMemo(() => email.slice(0, 2).toUpperCase(), [email]);

  async function refresh(openVault: WorkspaceVault) {
    const ticket = requests.current.issue(openVault.workspaceId, "items");
    if (!ticket) return;
    try {
      const [activeList, deletedList] = await Promise.all([listVaultItemsWithStatus(openVault), listVaultItemsWithStatus(openVault, { trash: true })]);
      if (!requests.current.accepts(ticket)) return;
      const active = activeList.items; const deleted = deletedList.items;
      const unreadable = activeList.unreadable + deletedList.unreadable;
      if (unreadable) setNotice(`${unreadable} item${unreadable === 1 ? "" : "s"} could not be decrypted on this device and ${unreadable === 1 ? "is" : "are"} hidden. The rest of the vault is safe to use.`);
      setItems(active); setTrash(deleted);
      setSelected((current) => current ? [...active, ...deleted].find((item) => item.id === current.id) ?? null : null);
    } catch (reason) { if (requests.current.accepts(ticket)) throw reason; }
  }

  async function refreshEntitlement(openVault: WorkspaceVault) {
    const ticket = requests.current.issue(openVault.workspaceId, "entitlement");
    if (!ticket) return;
    try {
      const next = await loadTenantEntitlement(openVault.tenantId);
      if (requests.current.accepts(ticket)) setEntitlement(next);
    } catch { if (requests.current.accepts(ticket)) setEntitlement(FREE_ENTITLEMENT); }
  }

  function selectWorkspace(next: WorkspaceVault) {
    requests.current.select(next.workspaceId);
    setVault(next); setItems([]); setTrash([]); setSelected(null); setEditor(null);
    setHistory(null); setRevealed(false); setEntitlement(FREE_ENTITLEMENT);
    setFilter("all"); setQuery(""); setError("");
  }

  async function reloadWorkspaces(preferredId?: string) {
    const version = ++workspaceLoadVersion.current;
    const next = await listWorkspaceVaults(profile.identity_id, rootKey);
    if (version !== workspaceLoadVersion.current) { next.forEach((entry) => entry.key.fill(0)); return; }
    const chosen = next.find((entry) => entry.workspaceId === (preferredId ?? vault?.workspaceId)) ?? next[0];
    if (!chosen) { next.forEach((entry) => entry.key.fill(0)); throw new Error("No accessible workspace."); }
    workspaces.forEach((entry) => entry.key.fill(0));
    setWorkspaces(next); setLoading(true); selectWorkspace(chosen);
    try { await Promise.all([refresh(chosen), refreshEntitlement(chosen)]); }
    finally { if (version === workspaceLoadVersion.current) setLoading(false); }
  }

  useEffect(() => {
    let active = true;
    let opened: WorkspaceVault[] = [];
    const version = ++workspaceLoadVersion.current;
    listWorkspaceVaults(profile.identity_id, rootKey).then(async (next) => {
      opened = next;
      if (!active || version !== workspaceLoadVersion.current) { next.forEach((entry) => entry.key.fill(0)); return; }
      if (!next[0]) throw new Error("No accessible workspace.");
      setWorkspaces(next); selectWorkspace(next[0]);
      await Promise.all([refresh(next[0]), refreshEntitlement(next[0])]);
    }).catch((reason) => { if (active && version === workspaceLoadVersion.current) setError(customerError(reason, "Unable to open this workspace. Try again.")); })
      .finally(() => { if (active && version === workspaceLoadVersion.current) setLoading(false); });
    const gate = requests.current;
    return () => { active = false; workspaceLoadVersion.current += 1; gate.select(null); opened.forEach((entry) => entry.key.fill(0)); };
  }, [profile.identity_id, rootKey]);

  async function switchWorkspace(workspaceId: string) {
    const next = workspaces.find((entry) => entry.workspaceId === workspaceId);
    if (!next) return;
    const version = ++workspaceLoadVersion.current;
    setLoading(true); selectWorkspace(next);
    try { await Promise.all([refresh(next), refreshEntitlement(next)]); }
    catch (reason) { if (version === workspaceLoadVersion.current) setError(customerError(reason, "Unable to switch workspaces. Try again.")); }
    finally { if (version === workspaceLoadVersion.current) setLoading(false); }
  }

  async function acceptPendingLink() {
    if (!pendingLink && !pendingOrganizationInvite) return;
    setAccepting(true); setError("");
    try {
      if (pendingOrganizationInvite) {
        await acceptOrganizationInvitation(pendingOrganizationInvite);
        window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
        setPendingOrganizationInvite(null);
        setNotice("Organization membership accepted. Vault access arrives separately through an encrypted workspace invitation.");
        setView("home");
        return;
      }
      const workspaceId = pendingLink!.kind === "invite"
        ? await acceptWorkspaceInvite(pendingLink!, rootKey)
        : (await acceptAccessCapsule(pendingLink!, rootKey), undefined);
      window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
      setPendingLink(null);
      if (workspaceId) {
        setView("workspaces");
        try { await reloadWorkspaces(workspaceId); }
        catch { setNotice("Invitation accepted. The new workspace will appear after you lock and unlock the vault."); }
      }
      else setView("inbox");
    } catch (reason) { setError(customerError(reason, "Unable to accept this secure link. Ask the sender for a new link.")); }
    finally { setAccepting(false); }
  }

  const health = useMemo(() => passwordHealth(items), [items]);
  const visibleItems = useMemo(() => { const source = filter === "trash" ? trash : items; const normalized = query.trim().toLowerCase(); return source.filter((item) => { if (filter !== "all" && filter !== "trash" && filter !== "favorites" && filter !== "archive" && item.contentType !== filter) return false; if (filter === "favorites" && !item.payload.favorite) return false; if (filter === "archive" && !item.payload.archived) return false; if (filter !== "archive" && filter !== "trash" && item.payload.archived) return false; return !normalized || [item.payload.title, item.payload.username, item.payload.url, item.payload.notes, ...(item.payload.tags ?? [])].some((value) => value?.toLowerCase().includes(normalized)); }); }, [filter, items, query, trash]);
  async function saveItem(contentType: ItemKind, payload: VaultPayload) { if (!vault) return; if (editor === "new") await createVaultItem(vault, contentType, payload); else if (editor) await updateVaultItem(vault, editor, payload); setEditor(null); try { await refresh(vault); } catch { setNotice("Saved. The list could not refresh—lock and unlock to reload it."); } }
  async function removeItem(item: VaultItem) { if (!vault || !window.confirm(`Move “${item.payload.title}” to Trash?`)) return; try { await deleteVaultItem(vault, item); setSelected(null); await refresh(vault); } catch (reason) { setError(customerError(reason, "Unable to move this item to Trash. Try again.")); } }
  async function restoreItem(item: VaultItem) { if (!vault) return; try { await restoreVaultItem(vault, item); setSelected(null); await refresh(vault); } catch (reason) { setError(customerError(reason, "Unable to restore this item. Try again.")); } }
  async function toggle(item: VaultItem, key: "favorite" | "archived") { if (!vault) return; try { await updateVaultItem(vault, item, { ...item.payload, [key]: !item.payload[key] }); await refresh(vault); } catch (reason) { setError(customerError(reason, "This item changed on another device. Refresh and try again.")); } }
  async function showHistory(item: VaultItem) { if (!vault) return; try { const entries = await listVaultItemHistory(vault, item); setHistory({ itemId: item.id, entries }); } catch (reason) { setError(customerError(reason, "Revision history could not be decrypted. Try again.")); } }
  function openVault(filterValue: VaultFilter = "all") { setFilter(filterValue); setView("vault"); setSelected(null); }
  function lockVault() { clearPendingClipboard(); forgetBreachResults(); document.documentElement.classList.add("vault-privacy-lock"); requests.current.select(null); workspaceLoadVersion.current += 1; workspaces.forEach((entry) => entry.key.fill(0)); pendingLink?.token.fill(0); pendingOrganizationInvite?.token.fill(0); pendingEmergency?.token.fill(0); onLock(); }
  async function signOut() { lockVault(); requests.current.select(null); workspaceLoadVersion.current += 1; workspaces.forEach((entry) => entry.key.fill(0)); pendingLink?.token.fill(0); pendingOrganizationInvite?.token.fill(0); await supabase!.auth.signOut(); }
  const autoLock = useEffectEvent(() => lockVault());
  useEffect(() => {
    document.documentElement.classList.remove("vault-privacy-lock");
  }, []);
  useEffect(() => () => workspaces.forEach(entry => entry.key.fill(0)), [workspaces]);
  const companion = ["mobile", "desktop", "android"].includes(clientMode);
  const quickAccess = useEffectEvent(() => {
    if (!companion) return;
    setView("home"); setSelected(null); setEditor(null);
    requestAnimationFrame(() => window.dispatchEvent(new Event("passkey-x:quick-access")));
  });
  const addFromShortcut = useEffectEvent(() => { if (companion) { setView("vault"); setEditor("new"); } });
  useEffect(() => {
    const open = () => quickAccess();
    const add = () => addFromShortcut();
    const keydown = (event: KeyboardEvent) => {
      if (!companion || !event.isTrusted || !(event.ctrlKey || event.metaKey) || event.altKey) return;
      if (event.key.toLowerCase() === "k") { event.preventDefault(); quickAccess(); }
      if (event.key.toLowerCase() === "n" && event.shiftKey) { event.preventDefault(); addFromShortcut(); }
      if (event.key.toLowerCase() === "l") { event.preventDefault(); autoLock(); }
    };
    window.addEventListener("passkey-x:open-quick-access", open);
    window.addEventListener("passkey-x:add-login", add);
    document.addEventListener("keydown", keydown);
    return () => { window.removeEventListener("passkey-x:open-quick-access", open); window.removeEventListener("passkey-x:add-login", add); document.removeEventListener("keydown", keydown); };
  }, [companion]);
  const planLabel = entitlement.plan_code[0].toUpperCase() + entitlement.plan_code.slice(1);
  return <EnterpriseProvider tenantId={vault?.tenantId ?? null} identityId={profile.identity_id} workspaceId={vault?.workspaceId ?? null} currentItemId={selected?.id ?? null}><PolicyLifecycle tenantId={vault?.tenantId ?? null} onLock={lockVault} /><RevealAudit revealed={revealed} itemId={selected?.id ?? null} /><main className={`vault-app client-${clientMode}`}>
    <aside className="vault-sidebar"><Brand /><nav>{NAV_SECTIONS.map((section) => <div className="nav-section" key={section.label}><span className="nav-section-label">{section.label}</span>{section.views.map((viewId) => { const entry = NAV.find((candidate) => candidate.id === viewId)!; const Icon = entry.icon; return <button key={entry.id} data-mobile-primary={["home", "vault", "generator", "account-security", "settings"].includes(entry.id)} className={`nav-item ${view === entry.id ? "active" : ""}`} onClick={() => { setView(entry.id); setSelected(null); }}><Icon /> {entry.label}{entry.id === "vault" && <span>{items.length}</span>}</button>; })}</div>)}</nav><div className="plan-chip"><Sparkles /><div><strong>{planLabel}</strong><span>{entitlement.ai_credits_remaining} private AI credits</span></div></div><div className="sidebar-account"><div className="avatar">{initials}</div><div><strong>{email.split("@")[0]}</strong><span>{vault?.name ?? "Opening workspace"}</span></div><MoreHorizontal /></div></aside>
    <section className="vault-content"><header><div><p className="eyebrow">Passkey-X {clientMode === "desktop" ? "Desktop" : clientMode === "android" || clientMode === "mobile" ? "Mobile" : ""} / {vault?.suite ?? "Personal"}</p><h1>{view === "home" ? companion ? "Your everyday vault" : "Home" : NAV.find((entry) => entry.id === view)?.label}</h1><select className="mobile-view-picker" aria-label="Go to section" value={view} onChange={event => { setView(event.target.value as View); setSelected(null); }}>{NAV.map(entry => <option key={entry.id} value={entry.id}>{entry.label}</option>)}</select></div><div className="header-actions">{!companion && <CommandPaletteButton />}<ThemeToggle /><Link className="client-header-link" href="/download" aria-label="Get Passkey-X apps"><Download /></Link>{workspaces.length > 0 && <select className="workspace-switcher" aria-label="Current workspace" value={vault?.workspaceId ?? ""} onChange={(event) => void switchWorkspace(event.target.value)}>{workspaces.map((entry) => <option key={entry.workspaceId} value={entry.workspaceId}>{entry.name}</option>)}</select>}<Button variant="outline" onClick={lockVault}><LockKeyhole /> Lock</Button><Button variant="ghost" size="icon" aria-label="Sign out" onClick={() => void signOut()}><LogOut /></Button></div></header>
      {error && <div className="vault-error" role="alert">{error}<button aria-label="Dismiss" onClick={() => setError("")}><X /></button></div>}
      {notice && <div className="vault-notice" role="status">{notice}<button aria-label="Dismiss" onClick={() => setNotice("")}><X /></button></div>}
      <ComplianceBanner passwordFacts={passwordFacts} onOpenAccountSecurity={() => { setView("account-security"); setSelected(null); }} onOpenSettings={() => { setView("settings"); setSelected(null); }} />
      <ProvisioningBanner onJoined={(text) => setNotice(text)} />{vault && <OrgRecoveryEnrollment tenantId={vault.tenantId} identityId={profile.identity_id} rootKey={rootKey} />}<EmergencyRequestNotice identityId={profile.identity_id} onReview={() => setView("emergency")} />{pendingEmergency && <EmergencyInviteBanner link={pendingEmergency} rootKey={rootKey} onDone={(text) => { setPendingEmergency(null); if (text) { setNotice(text); setView("emergency"); } }} />}{(pendingLink || pendingOrganizationInvite) && <div className="secure-link-banner"><span className="feature-icon">{pendingLink?.kind === "capsule" ? <Share2 /> : <UserPlus />}</span><div><strong>{pendingOrganizationInvite ? "Organization invitation" : pendingLink?.kind === "invite" ? "Workspace invitation" : "Access Capsule"}</strong><p>{pendingOrganizationInvite ? "This one-time link adds your verified account to the organization directory. It does not grant vault access or deliver encryption keys." : "This link is addressed to your verified email. Its 256-bit secret stayed in the URL fragment and was not sent to the server."}</p></div><Button disabled={accepting} onClick={() => void acceptPendingLink()}>{accepting ? "Accepting…" : "Review and accept"}</Button></div>}
      {loading ? <div className="vault-loading"><div className="loading-ring" /><p>Decrypting your workspace on this device…</p></div> : <>
        {clientMode === "android" && vault && <NativeAutofillReview key={vault.workspaceId} vault={vault} items={items} onSaved={() => refresh(vault)} />}
        {view === "home" && companion && <CompanionHome mode={clientMode} items={items} onSelect={item => { setView("vault"); setSelected(item); setRevealed(false); }} onNew={() => { setView("vault"); setEditor("new"); }} onVault={() => openVault()} onGenerator={() => setView("generator")} onSecurity={() => setView("security")} onRefresh={async () => { if (vault) { try { await refresh(vault); } catch { setError("Could not refresh. Check your connection and try again."); } } }} />}
        {view === "home" && !companion && <Dashboard items={items} trash={trash} health={health} entitlement={entitlement} identityId={profile.identity_id} tenantId={vault?.tenantId ?? null} workspaceCount={workspaces.length} onNavigate={(next) => { setView(next as View); setSelected(null); }} onOpenVault={openVault} onNew={() => { setEditor("new"); setView("vault"); }} />}
        {view === "vault" && vault && <VaultView vault={vault} items={visibleItems} allItems={items} trash={trash} filter={filter} query={query} selected={selected} revealed={revealed} onQuery={setQuery} onFilter={setFilter} onNew={() => setEditor("new")} onSelect={(item) => { setSelected(item); setRevealed(false); setHistory(null); }} onReveal={() => setRevealed(!revealed)} onClose={() => setSelected(null)} onEdit={(item) => setEditor(item)} onDelete={removeItem} onRestore={restoreItem} onToggle={toggle} onHistory={showHistory} onRotate={(item) => { setRotateSecret(generatePassword({ length: 24, uppercase: true, lowercase: true, numbers: true, symbols: true, avoidAmbiguous: true })); setEditor(item); }} onImport={() => setView("settings")} onGenerator={() => setView("generator")} />}
        {view === "workspaces" && vault && <WorkspacesView key={vault.workspaceId} identityId={profile.identity_id} rootKey={rootKey} workspaces={workspaces} vault={vault} onSelect={switchWorkspace} onReload={reloadWorkspaces} />}
        {view === "organization" && vault && <OrganizationView key={vault.tenantId} vault={vault} entitlement={entitlement} onOpenBilling={() => setView("billing")} />}
        {view === "admin" && vault && <AdminConsole key={vault.tenantId} vault={vault} entitlement={entitlement} workspaceNames={new Map(workspaces.map((entry) => [entry.workspaceId, entry.name]))} onOpenBilling={() => setView("billing")} />}
        {view === "saas-ai" && vault && <SaasAiManager key={vault.tenantId} vault={vault} entitlement={entitlement} onOpenBilling={() => setView("billing")} />}
        {view === "runtime" && vault && <RuntimeAccessView key={vault.tenantId} vault={vault} entitlement={entitlement} onOpenBilling={() => setView("billing")} />}
        {view === "notifications" && vault && <NotificationsView key={vault.tenantId} vault={vault} />}
        {view === "missions" && vault && <MissionsView key={vault.workspaceId} vault={vault} items={items} />}
        {view === "sharing" && vault && <SharingView key={vault.workspaceId} vault={vault} items={items} />}
        {view === "send" && vault && <SecureSendView key={vault.tenantId} vault={vault} />}
        {view === "emergency" && vault && <EmergencyAccessView key={vault.workspaceId} vault={vault} workspaces={workspaces} identityId={profile.identity_id} rootKey={rootKey} onOpened={(workspaceId) => reloadWorkspaces(workspaceId)} />}
        {view === "inbox" && vault && <AccessInboxView key={vault.workspaceId} identityId={profile.identity_id} rootKey={rootKey} vault={vault} items={items} />}
        {view === "security" && <SecurityCenter tenantId={vault?.tenantId ?? null} items={items} clientKind={clientMode === "desktop" ? "desktop" : clientMode === "android" ? "android" : clientMode === "mobile" ? "mobile" : "web"} onOpen={(id) => { const item = items.find((candidate) => candidate.id === id); if (item) { setView("vault"); setSelected(item); } }} onRotate={(id) => { const item = items.find((candidate) => candidate.id === id); if (item) { setRotateSecret(generatePassword({ length: 24, uppercase: true, lowercase: true, numbers: true, symbols: true, avoidAmbiguous: true })); setEditor(item); } }} />}
        {view === "account-security" && <AccountSecurityView />}
        {view === "generator" && <GeneratorView />}
        {vault && <AutomationsView key={`${vault.identityId}:${vault.tenantId}:${vault.workspaceId}`} vault={vault} items={items} visible={view === "automations"} onNavigate={setView} />}
        {view === "devices" && <DevicesView identityId={profile.identity_id} />}
        {view === "billing" && vault && <PlansView vault={vault} workspaces={workspaces} entitlement={entitlement} identityId={profile.identity_id} rootKey={rootKey} onSelectWorkspace={switchWorkspace} onRefresh={() => refreshEntitlement(vault)} onOpenHelp={() => setView("help")} onOpenAdmin={() => setView("admin")} />}
        {view === "help" && <HelpCenter onNavigate={(next) => { setView(next); setSelected(null); }} />}
        {view === "settings" && vault && <SettingsView email={email} items={items} vault={vault} profile={profile} entitlement={entitlement} onImported={() => refresh(vault)} onProfileChange={onProfileChange} onPasswordFacts={onPasswordFacts} />}
      </>}
    </section>
    <CommandPalette enabled={!companion} items={items} views={NAV} onNavigate={(next) => { setView(next as View); setSelected(null); }} onOpenItem={(item) => { setView("vault"); setFilter("all"); setSelected(item); setRevealed(false); setHistory(null); }} onNewItem={() => { setView("vault"); setEditor("new"); }} onLock={lockVault} />
    {editor && <ItemEditor key={editor === "new" ? "new" : `${editor.id}:${rotateSecret ? "rotate" : "edit"}`} item={editor === "new" ? undefined : editor} initialSecret={editor === "new" ? undefined : rotateSecret ?? undefined} onClose={() => { setEditor(null); setRotateSecret(null); }} onSave={async (kind, payload) => { await saveItem(kind, payload); setRotateSecret(null); }} />}
    {history && selected && history.itemId === selected.id && <HistoryDialog item={selected} history={history.entries} onClose={() => setHistory(null)} />}
  </main></EnterpriseProvider>;
}
