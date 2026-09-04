"use client";

import { useEffect, useMemo, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import {
  Braces,
  Copy,
  Eye,
  EyeOff,
  FileText,
  KeyRound,
  LockKeyhole,
  LogOut,
  Pencil,
  Plus,
  Search,
  ShieldCheck,
  Trash2,
  UserRound,
  Vault,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { createDeviceKeyPair, createRecoveryKey, deriveMasterKey, fromBase64Url, randomBytes, recoveryFile, saveProtectedDeviceKey, toBase64Url, toPostgresBytea, unwrapKey, WEB_KDF_PROFILE, wrapKey } from "@/lib/crypto/vault";
import { isSupabaseConfigured, supabase } from "@/lib/supabase/client";
import { createVaultItem, deleteVaultItem, type ItemKind, listVaultItems, openWorkspaceVault, type VaultItem, type VaultPayload, type WorkspaceVault, updateVaultItem } from "@/lib/vault/items";

type CryptoProfile = {
  identity_id: string;
  salt: string;
  kdf_parameters: {
    memoryKib: number;
    iterations: number;
    parallelism: number;
    hashLength: 32;
  };
  master_nonce: string;
  master_wrapped_root: string;
};

const ITEM_TYPES: Record<ItemKind, { label: string; plural: string; icon: typeof KeyRound }> = {
  login: { label: "Login", plural: "Logins", icon: UserRound },
  "api-key": { label: "API key", plural: "API keys", icon: KeyRound },
  "secure-note": { label: "Secure note", plural: "Secure notes", icon: FileText },
  "custom-secret": { label: "Custom secret", plural: "Custom secrets", icon: Braces },
};

function Logo() {
  return <div className="brand-mark" aria-label="1accessos">1<span>accessos</span></div>;
}

function bytea(value: string) {
  return value.startsWith("\\x")
    ? Uint8Array.from(value.slice(2).match(/.{2}/g) ?? [], (part) => Number.parseInt(part, 16))
    : fromBase64Url(value);
}

export default function Home() {
  const [session, setSession] = useState<Session | null>(null);
  const [profile, setProfile] = useState<CryptoProfile | null>(null);
  const [authLoading, setAuthLoading] = useState(isSupabaseConfigured);
  const [profileLoading, setProfileLoading] = useState(false);
  const [profileError, setProfileError] = useState("");
  const [rootKey, setRootKey] = useState<Uint8Array | null>(null);

  useEffect(() => {
    if (!supabase) {
      return;
    }
    supabase.auth.getSession().then(({ data }) => {
      setSession(data.session);
      setProfile(null);
      setProfileError("");
      setProfileLoading(Boolean(data.session));
      setAuthLoading(false);
    });
    const { data } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      setSession(nextSession);
      setProfile(null);
      setProfileError("");
      setProfileLoading(Boolean(nextSession));
      if (!nextSession) {
        rootKey?.fill(0);
        setRootKey(null);
      }
    });
    return () => data.subscription.unsubscribe();
  }, [rootKey]);

  useEffect(() => {
    if (!supabase || !session) return;
    let active = true;
    supabase
      .from("account_crypto_profiles")
      .select("identity_id,salt,kdf_parameters,master_nonce,master_wrapped_root")
      .maybeSingle()
      .then(({ data, error }) => {
        if (!active) return;
        if (error) setProfileError(error.message);
        setProfile(data as CryptoProfile | null);
        setProfileLoading(false);
      });
    return () => { active = false; };
  }, [session]);

  if (authLoading || profileLoading) {
    return <main className="center-screen"><div className="loading-ring" aria-label="Loading" /></main>;
  }
  if (!isSupabaseConfigured) return <ConfigurationNotice />;
  if (!session) return <AuthScreen />;
  if (profileError) return <FatalNotice message={profileError} />;
  if (!profile) return <VaultSetup email={session.user.email ?? "your account"} onComplete={setProfile} />;
  if (!rootKey) return <UnlockScreen profile={profile} email={session.user.email ?? ""} onUnlock={setRootKey} />;
  return (
    <VaultShell
      email={session.user.email ?? ""}
      profile={profile}
      rootKey={rootKey}
      onLock={() => {
        rootKey.fill(0);
        setRootKey(null);
      }}
    />
  );
}

function ConfigurationNotice() {
  return (
    <main className="center-screen">
      <Card className="auth-card">
        <CardHeader>
          <Logo />
          <CardTitle>Connect the development project</CardTitle>
          <CardDescription>
            Add the public Supabase URL and publishable key to the hosting environment.
            Secret keys are never used by the browser.
          </CardDescription>
        </CardHeader>
      </Card>
    </main>
  );
}

function FatalNotice({ message }: { message: string }) {
  return (
    <main className="center-screen">
      <Card className="auth-card">
        <CardHeader>
          <Logo />
          <CardTitle>Unable to open 1accessos</CardTitle>
          <CardDescription>{message}</CardDescription>
        </CardHeader>
        <CardContent>
          <Button variant="outline" onClick={() => supabase?.auth.signOut()}>Sign out</Button>
        </CardContent>
      </Card>
    </main>
  );
}

function AuthScreen() {
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    const result = mode === "signin"
      ? await supabase!.auth.signInWithPassword({ email, password })
      : await supabase!.auth.signUp({ email, password });
    setBusy(false);
    if (result.error) setMessage(result.error.message);
    else if (mode === "signup" && !result.data.session) {
      setMessage("Check your email to confirm the account, then sign in.");
    }
  }

  return (
    <main className="auth-layout">
      <section className="auth-story">
        <Logo />
        <div>
          <div className="security-kicker"><ShieldCheck /> Zero-knowledge vault</div>
          <h1>Your keys stay yours.</h1>
          <p>Passwords, API tokens, SSH keys, recovery codes and future credentials are encrypted on this device before storage.</p>
        </div>
        <p className="trust-note">1accessos cannot read or reset your encrypted vault.</p>
      </section>
      <section className="auth-panel">
        <Card className="auth-card">
          <CardHeader>
            <CardTitle>{mode === "signin" ? "Sign in" : "Create your account"}</CardTitle>
            <CardDescription>Account login and vault unlock are separate security steps.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="form-stack" onSubmit={submit}>
              <div>
                <Label htmlFor="email">Email</Label>
                <Input id="email" type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} />
              </div>
              <div>
                <Label htmlFor="password">Login password</Label>
                <Input id="password" type="password" autoComplete={mode === "signin" ? "current-password" : "new-password"} minLength={12} required value={password} onChange={(event) => setPassword(event.target.value)} />
              </div>
              {message && <p className="form-message" role="status">{message}</p>}
              <Button size="lg" disabled={busy}>{busy ? "Please wait…" : mode === "signin" ? "Continue" : "Create account"}</Button>
              <Button type="button" variant="ghost" onClick={() => {
                setMode(mode === "signin" ? "signup" : "signin");
                setMessage("");
              }}>
                {mode === "signin" ? "Create a new account" : "I already have an account"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </section>
    </main>
  );
}

function VaultSetup({ email, onComplete }: { email: string; onComplete: (profile: CryptoProfile) => void }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const [pendingProfile, setPendingProfile] = useState<CryptoProfile | null>(null);

  async function setup(event: React.FormEvent) {
    event.preventDefault();
    if (password !== confirm) {
      setMessage("The vault passwords do not match.");
      return;
    }
    setBusy(true);
    setMessage("");
    const salt = randomBytes(16);
    const accountRoot = randomBytes(32);
    const workspaceKey = randomBytes(32);
    let masterKey: Uint8Array | null = null;
    try {
      masterKey = await deriveMasterKey(password, salt);
      const recovery = createRecoveryKey();
      const masterWrapped = await wrapKey(masterKey, accountRoot, "1accessos:account-root:v1");
      const recoveryWrapped = await wrapKey(recovery.secret, accountRoot, "1accessos:recovery:v1");
      const workspaceWrapped = await wrapKey(accountRoot, workspaceKey, "1accessos:workspace:v1");
      const device = await createDeviceKeyPair();
      const devicePrivate = await wrapKey(accountRoot, device.privateKey, "1accessos:device-private:v1");
      await saveProtectedDeviceKey(devicePrivate);
      const { data, error } = await supabase!.rpc("bootstrap_personal_vault", {
        p_salt: toPostgresBytea(salt),
        p_kdf_parameters: WEB_KDF_PROFILE,
        p_master_nonce: toPostgresBytea(fromBase64Url(masterWrapped.nonce)),
        p_master_wrapped_root: toPostgresBytea(fromBase64Url(masterWrapped.ciphertext)),
        p_recovery_nonce: toPostgresBytea(fromBase64Url(recoveryWrapped.nonce)),
        p_recovery_wrapped_root: toPostgresBytea(fromBase64Url(recoveryWrapped.ciphertext)),
        p_workspace_nonce: toPostgresBytea(fromBase64Url(workspaceWrapped.nonce)),
        p_workspace_wrapped_key: toPostgresBytea(fromBase64Url(workspaceWrapped.ciphertext)),
        p_device_public_key: toPostgresBytea(device.publicKey),
      });
      if (error) throw error;
      const bootstrap = data as { identity_id: string };
      setRecoveryKey(recovery.display);
      setPendingProfile({
        identity_id: bootstrap.identity_id,
        salt: toBase64Url(salt),
        kdf_parameters: WEB_KDF_PROFILE,
        master_nonce: masterWrapped.nonce,
        master_wrapped_root: masterWrapped.ciphertext,
      });
      setPassword("");
      setConfirm("");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Vault setup failed.");
    } finally {
      accountRoot.fill(0);
      workspaceKey.fill(0);
      masterKey?.fill(0);
      setBusy(false);
    }
  }

  function download() {
    if (!recoveryKey) return;
    const url = URL.createObjectURL(recoveryFile(recoveryKey));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "1accessos-recovery-key.json";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <main className="center-screen setup-bg">
      <Card className="setup-card">
        <CardHeader>
          <Logo />
          <div className="step-pill">Account verified</div>
          <CardTitle>{recoveryKey ? "Save your recovery key" : "Create your vault"}</CardTitle>
          <CardDescription>
            {recoveryKey
              ? "This is the only recovery method. Keep a copy offline."
              : `Signed in as ${email}. Choose a new password used only to unlock your vault.`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {recoveryKey ? (
            <div className="form-stack">
              <div className="recovery-box"><KeyRound /><code>{recoveryKey}</code></div>
              <Button size="lg" onClick={download}>Download recovery key</Button>
              <Button variant="outline" disabled={!pendingProfile} onClick={() => {
                if (!pendingProfile) return;
                setRecoveryKey(null);
                onComplete(pendingProfile);
              }}>
                I saved it — continue
              </Button>
            </div>
          ) : (
            <form className="form-stack" onSubmit={setup}>
              <div>
                <Label htmlFor="vault-password">Vault master password</Label>
                <Input id="vault-password" type="password" minLength={12} autoComplete="new-password" required value={password} onChange={(event) => setPassword(event.target.value)} />
              </div>
              <div>
                <Label htmlFor="vault-confirm">Confirm vault password</Label>
                <Input id="vault-confirm" type="password" minLength={12} autoComplete="new-password" required value={confirm} onChange={(event) => setConfirm(event.target.value)} />
              </div>
              <p className="field-hint">Do not reuse your login password. 1accessos cannot recover this password.</p>
              {message && <p className="form-message" role="alert">{message}</p>}
              <Button size="lg" disabled={busy}>{busy ? "Securing vault…" : "Create encrypted vault"}</Button>
            </form>
          )}
        </CardContent>
      </Card>
    </main>
  );
}

function UnlockScreen({ profile, email, onUnlock }: { profile: CryptoProfile; email: string; onUnlock: (key: Uint8Array) => void }) {
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function unlock(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    let master: Uint8Array | null = null;
    try {
      master = await deriveMasterKey(password, bytea(profile.salt), { algorithm: "ARGON2ID", ...profile.kdf_parameters });
      const root = await unwrapKey(master, {
        algorithm: "AES-256-GCM",
        nonce: toBase64Url(bytea(profile.master_nonce)),
        ciphertext: toBase64Url(bytea(profile.master_wrapped_root)),
      }, "1accessos:account-root:v1");
      setPassword("");
      onUnlock(root);
    } catch {
      setMessage("That vault password could not unlock this vault.");
    } finally {
      master?.fill(0);
      setBusy(false);
    }
  }

  return (
    <main className="center-screen unlock-bg">
      <Card className="auth-card">
        <CardHeader>
          <Logo />
          <div className="vault-icon"><LockKeyhole /></div>
          <CardTitle>Unlock your vault</CardTitle>
          <CardDescription>{email}</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="form-stack" onSubmit={unlock}>
            <div>
              <Label htmlFor="unlock-password">Vault master password</Label>
              <Input id="unlock-password" type="password" autoFocus autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} />
            </div>
            {message && <p className="form-message" role="alert">{message}</p>}
            <Button size="lg" disabled={busy}>{busy ? "Unlocking…" : "Unlock vault"}</Button>
            <Button type="button" variant="ghost" onClick={() => supabase!.auth.signOut()}>Use another account</Button>
          </form>
        </CardContent>
      </Card>
    </main>
  );
}

function VaultShell({ email, profile, rootKey, onLock }: { email: string; profile: CryptoProfile; rootKey: Uint8Array; onLock: () => void }) {
  const [vault, setVault] = useState<WorkspaceVault | null>(null);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<ItemKind | "all">("all");
  const [editor, setEditor] = useState<VaultItem | "new" | null>(null);
  const [selected, setSelected] = useState<VaultItem | null>(null);
  const [revealed, setRevealed] = useState(false);
  const initials = useMemo(() => email.slice(0, 2).toUpperCase(), [email]);

  async function refresh(openVault: WorkspaceVault) {
    const nextItems = await listVaultItems(openVault);
    setItems(nextItems);
    setSelected((current) => current ? nextItems.find((item) => item.id === current.id) ?? null : null);
  }

  useEffect(() => {
    let active = true;
    let opened: WorkspaceVault | null = null;
    openWorkspaceVault(profile.identity_id, rootKey)
      .then(async (nextVault) => {
        opened = nextVault;
        if (!active) {
          nextVault.key.fill(0);
          return;
        }
        setVault(nextVault);
        await refresh(nextVault);
      })
      .catch((reason) => {
        if (active) setError(reason instanceof Error ? reason.message : "Unable to open workspace.");
      })
      .finally(() => { if (active) setLoading(false); });
    return () => {
      active = false;
      opened?.key.fill(0);
    };
  }, [profile.identity_id, rootKey]);

  const visibleItems = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return items.filter((item) => {
      if (filter !== "all" && item.contentType !== filter) return false;
      if (!normalized) return true;
      return [item.payload.title, item.payload.username, item.payload.url, item.payload.notes]
        .some((value) => value?.toLowerCase().includes(normalized));
    });
  }, [filter, items, query]);

  async function saveItem(contentType: ItemKind, payload: VaultPayload) {
    if (!vault) return;
    if (editor === "new") await createVaultItem(vault, contentType, payload);
    else if (editor) await updateVaultItem(vault, editor, payload);
    await refresh(vault);
    setEditor(null);
  }

  async function removeItem(item: VaultItem) {
    if (!vault || !window.confirm(`Delete “${item.payload.title}”? This removes it from active devices.`)) return;
    try {
      await deleteVaultItem(vault, item);
      setSelected(null);
      await refresh(vault);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Unable to delete item.");
    }
  }

  function choose(item: VaultItem) {
    setSelected(item);
    setRevealed(false);
  }

  const totalFor = (kind: ItemKind) => items.filter((item) => item.contentType === kind).length;

  return (
    <main className="vault-app">
      <aside className="vault-sidebar">
        <Logo />
        <nav>
          <button className={`nav-item ${filter === "all" ? "active" : ""}`} onClick={() => setFilter("all")}><Vault /> All items <span>{items.length}</span></button>
          {(Object.keys(ITEM_TYPES) as ItemKind[]).map((kind) => {
            const TypeIcon = ITEM_TYPES[kind].icon;
            return <button key={kind} className={`nav-item ${filter === kind ? "active" : ""}`} onClick={() => setFilter(kind)}><TypeIcon /> {ITEM_TYPES[kind].plural}<span>{totalFor(kind)}</span></button>;
          })}
        </nav>
        <div className="sidebar-account">
          <div className="avatar">{initials}</div>
          <div><strong>{email.split("@")[0]}</strong><span>Personal vault</span></div>
        </div>
      </aside>
      <section className="vault-content">
        <header>
          <div><p className="eyebrow">Personal vault</p><h1>{filter === "all" ? "All items" : ITEM_TYPES[filter].plural}</h1></div>
          <div className="header-actions">
            <Button variant="outline" onClick={onLock}><LockKeyhole /> Lock</Button>
            <Button variant="ghost" size="icon" aria-label="Sign out" onClick={() => supabase!.auth.signOut()}><LogOut /></Button>
          </div>
        </header>
        <div className="vault-toolbar">
          <div className="search-box"><Search /><input aria-label="Search vault" placeholder="Search decrypted items on this device" value={query} onChange={(event) => setQuery(event.target.value)} /></div>
          <Button onClick={() => setEditor("new")}><Plus /> New item</Button>
        </div>
        {error && <div className="vault-error" role="alert">{error}<button onClick={() => setError("")}><X /></button></div>}
        {loading ? (
          <div className="vault-loading"><div className="loading-ring" /><p>Decrypting your vault on this device…</p></div>
        ) : visibleItems.length === 0 ? (
          <div className="empty-vault">
            <div className="empty-icon"><Vault /></div>
            <h2>{items.length ? "No matching items" : "Your vault is ready"}</h2>
            <p>{items.length ? "Try another search or category." : "Add the first encrypted login, API key, secure note or custom secret."}</p>
            {!items.length && <Button onClick={() => setEditor("new")}><Plus /> Add first item</Button>}
          </div>
        ) : (
          <div className={`items-layout ${selected ? "with-detail" : ""}`}>
            <div className="item-list">
              {visibleItems.map((item) => {
                const TypeIcon = ITEM_TYPES[item.contentType].icon;
                return (
                  <button key={item.id} className={`item-row ${selected?.id === item.id ? "selected" : ""}`} onClick={() => choose(item)}>
                    <span className="item-kind-icon"><TypeIcon /></span>
                    <span className="item-summary"><strong>{item.payload.title}</strong><small>{item.payload.username || item.payload.url || ITEM_TYPES[item.contentType].label}</small></span>
                    <span className="item-type-label">{ITEM_TYPES[item.contentType].label}</span>
                  </button>
                );
              })}
            </div>
            {selected && (
              <aside className="item-detail">
                <div className="detail-heading">
                  <div><span>{ITEM_TYPES[selected.contentType].label}</span><h2>{selected.payload.title}</h2></div>
                  <button aria-label="Close details" onClick={() => setSelected(null)}><X /></button>
                </div>
                {selected.payload.username && <DetailField label="Username" value={selected.payload.username} copyable />}
                {selected.payload.secret && (
                  <div className="detail-field">
                    <span>Secret</span>
                    <div><code>{revealed ? selected.payload.secret : "••••••••••••"}</code><button aria-label={revealed ? "Hide secret" : "Reveal secret"} onClick={() => setRevealed(!revealed)}>{revealed ? <EyeOff /> : <Eye />}</button><CopyButton value={selected.payload.secret} /></div>
                  </div>
                )}
                {selected.payload.url && <DetailField label="Website" value={selected.payload.url} copyable />}
                {selected.payload.notes && <DetailField label="Notes" value={selected.payload.notes} />}
                <div className="detail-actions">
                  <Button variant="outline" onClick={() => setEditor(selected)}><Pencil /> Edit</Button>
                  <Button variant="ghost" className="danger-button" onClick={() => removeItem(selected)}><Trash2 /> Delete</Button>
                </div>
              </aside>
            )}
          </div>
        )}
      </section>
      {editor && (
        <ItemEditor
          item={editor === "new" ? undefined : editor}
          onClose={() => setEditor(null)}
          onSave={saveItem}
        />
      )}
    </main>
  );
}

function DetailField({ label, value, copyable = false }: { label: string; value: string; copyable?: boolean }) {
  return <div className="detail-field"><span>{label}</span><div><p>{value}</p>{copyable && <CopyButton value={value} />}</div></div>;
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button aria-label="Copy" onClick={async () => {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    }}>
      {copied ? <ShieldCheck /> : <Copy />}
    </button>
  );
}

function ItemEditor({ item, onClose, onSave }: { item?: VaultItem; onClose: () => void; onSave: (kind: ItemKind, payload: VaultPayload) => Promise<void> }) {
  const [kind, setKind] = useState<ItemKind>(item?.contentType ?? "login");
  const [title, setTitle] = useState(item?.payload.title ?? "");
  const [username, setUsername] = useState(item?.payload.username ?? "");
  const [secret, setSecret] = useState(item?.payload.secret ?? "");
  const [url, setUrl] = useState(item?.payload.url ?? "");
  const [notes, setNotes] = useState(item?.payload.notes ?? "");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    try {
      await onSave(kind, {
        version: 1,
        title: title.trim(),
        username: username.trim() || undefined,
        secret: secret || undefined,
        url: url.trim() || undefined,
        notes: notes.trim() || undefined,
        updatedAt: new Date().toISOString(),
      });
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : "Unable to save item.");
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <Card className="item-editor" role="dialog" aria-modal="true" aria-labelledby="editor-title">
        <CardHeader>
          <button className="modal-close" aria-label="Close" onClick={onClose}><X /></button>
          <CardTitle id="editor-title">{item ? "Edit encrypted item" : "Add encrypted item"}</CardTitle>
          <CardDescription>Fields are encrypted in your browser before they leave this device.</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="form-stack" onSubmit={submit}>
            <div>
              <Label htmlFor="item-kind">Type</Label>
              <select id="item-kind" value={kind} disabled={Boolean(item)} onChange={(event) => setKind(event.target.value as ItemKind)}>
                {(Object.keys(ITEM_TYPES) as ItemKind[]).map((value) => <option key={value} value={value}>{ITEM_TYPES[value].label}</option>)}
              </select>
            </div>
            <div><Label htmlFor="item-title">Name</Label><Input id="item-title" required autoFocus value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Production API" /></div>
            {kind !== "secure-note" && <div><Label htmlFor="item-username">{kind === "api-key" ? "Account or service" : "Username"}</Label><Input id="item-username" value={username} onChange={(event) => setUsername(event.target.value)} /></div>}
            {kind !== "secure-note" && <div><Label htmlFor="item-secret">{kind === "login" ? "Password" : "Secret"}</Label><Input id="item-secret" value={secret} onChange={(event) => setSecret(event.target.value)} /></div>}
            {(kind === "login" || kind === "custom-secret") && <div><Label htmlFor="item-url">Website</Label><Input id="item-url" type="url" value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://" /></div>}
            <div><Label htmlFor="item-notes">Notes</Label><textarea id="item-notes" rows={4} value={notes} onChange={(event) => setNotes(event.target.value)} /></div>
            {message && <p className="form-message" role="alert">{message}</p>}
            <div className="editor-actions"><Button type="button" variant="outline" onClick={onClose}>Cancel</Button><Button disabled={busy}>{busy ? "Encrypting…" : "Encrypt and save"}</Button></div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
