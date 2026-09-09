"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { KeyRound, ShieldCheck, Smartphone } from "lucide-react";
import { nativeAvailable, nativeRequest, validNativeContext, type NativeContext } from "@/lib/browser/native-autofill";
import { createVaultItem, updateVaultItem, type VaultItem, type WorkspaceVault } from "@/lib/vault/items";

export function NativeAutofillSetup({ native }: { native: boolean }) {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [message, setMessage] = useState("");
  useEffect(() => {
    if (!native || !nativeAvailable()) return;
    let active = true;
    const check = () => { void nativeRequest<{ enabled: boolean }>("status").then(result => { if (active) setEnabled(result.enabled); }).catch(() => {}); };
    check(); window.addEventListener("focus", check);
    return () => { active = false; window.removeEventListener("focus", check); };
  }, [native]);
  return <section><Smartphone /><h3>{enabled ? "Android autofill is on" : "Passwords in your apps"}</h3><p>{native ? "Enable Passkey-X in Android’s autofill settings. Compatible native apps can then offer Fill and Save. You choose every credential and confirm each save." : "This home-screen web app gives you quick vault access. Install the Android preview for password save prompts and autofill in compatible native apps."}</p>{native ? <button onClick={() => void nativeRequest("enableAutofill").catch(reason => setMessage(reason.message))}>{enabled ? "Manage autofill settings" : "Enable Android autofill"}</button> : <Link href="/download#android">Get Android autofill</Link>}<small>iPhone system autofill is not available in this release.</small>{message && <p role="status">{message}</p>}</section>;
}

export function NativeAutofillReview({ vault, items, onSaved }: { vault: WorkspaceVault; items: VaultItem[]; onSaved: () => Promise<void> }) {
  const [context, setContext] = useState<NativeContext | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [query, setQuery] = useState("");
  const [showAll, setShowAll] = useState(false);
  const [selected, setSelected] = useState("");
  const active = useRef(false);
  useEffect(() => {
    active.current = true;
    let expiry: ReturnType<typeof setTimeout>;
    void nativeRequest<unknown>("context").then(value => {
      if (!active.current || !validNativeContext(value)) return;
      setContext(value);
      expiry = setTimeout(() => { setContext(null); setMessage("This autofill request expired. Return to the other app and try again."); }, value.expiresAt - Date.now());
    }).catch(reason => { if (active.current) setMessage(reason.message); });
    return () => { active.current = false; clearTimeout(expiry); };
  }, []);
  if (!context) return message ? <p className="vault-notice" role="status">{message}</p> : null;
  const current = context;
  const logins = items.filter(item => item.contentType === "login" && !item.deletedAt && !item.payload.archived && item.payload.secret);
  const matching = logins.filter(item => item.payload.fields?.androidPackage === context.packageName);
  const choices = (showAll ? logins : matching).filter(item => [item.payload.title, item.payload.username].join(" ").toLowerCase().includes(query.toLowerCase()));
  const existing = matching.filter(item => item.payload.username === context.username);
  const duplicate = existing.some(item => item.payload.secret === context.password);
  const writable = vault.role !== "viewer" && !vault.keyRotationRequired;
  async function dismiss() {
    setContext(null);
    await nativeRequest("cancel", { operationId: current.id }).catch(() => {});
  }
  async function fill() {
    const item = choices.find(candidate => candidate.id === selected);
    if (!item || !validNativeContext(current) || busy) return;
    setBusy(true); setMessage("");
    try { await nativeRequest("fill", { operationId: current.id, username: item.payload.username ?? "", password: item.payload.secret }); }
    catch (reason) { if (active.current) setMessage(reason instanceof Error ? reason.message : "Autofill could not complete."); }
    finally { if (active.current) setBusy(false); }
  }
  async function save() {
    if (!writable || busy || !validNativeContext(current)) return;
    setBusy(true); setMessage("");
    try {
      // Confirm that native still owns this live operation before starting a write.
      const latest = await nativeRequest<unknown>("context");
      if (!active.current || !validNativeContext(latest) || latest.id !== current.id) throw new Error("The request expired. Return to the other app and try again.");
      if (!duplicate) {
        const previous = existing.length === 1 ? existing[0] : undefined;
        const payload = { ...(previous?.payload ?? { version: 1 as const, title: current.appLabel, tags: [], favorite: false }), username: current.username, secret: current.password, fields: { ...previous?.payload.fields, androidPackage: current.packageName }, updatedAt: new Date().toISOString() };
        if (previous) await updateVaultItem(vault, previous, payload);
        else await createVaultItem(vault, "login", payload);
      }
      if (!active.current) return;
      // Only report success after the encrypted server write has completed.
      await nativeRequest("saved", { operationId: current.id });
      if (active.current) { setContext(null); await onSaved(); }
    } catch (reason) { if (active.current) setMessage(reason instanceof Error ? reason.message : "Your login could not be saved. Try again."); }
    finally { if (active.current) setBusy(false); }
  }
  return <section className="native-autofill-review" aria-label="Android autofill request"><div><span className="client-tag"><ShieldCheck /> Android autofill</span><h2>{context.kind === "save" ? duplicate ? "This login is already saved" : "Save this app login?" : "Choose a login to fill"}</h2><p>For <strong>{context.appLabel}</strong> <code>{context.packageName}</code></p><p>Workspace: <strong>{vault.name}</strong>. Use the workspace selector above to change it.</p></div>
    {context.kind === "save" ? <><div className="native-login-summary"><KeyRound /><span>{context.username || "No username provided"}<small>Password hidden · Expires in two minutes</small></span></div>{!writable && <p role="alert">Choose a writable workspace that does not require key rotation.</p>}<div className="native-review-actions"><button disabled={busy || !writable} onClick={() => void save()}>{busy ? "Saving…" : duplicate ? "Done" : existing.length === 1 ? "Update saved login" : "Save encrypted login"}</button><button disabled={busy} onClick={() => void dismiss()}>Not now</button></div></> : <><p>Only fill a credential you trust for this app. App names do not prove a website association.</p><input aria-label="Search autofill logins" placeholder="Search logins" value={query} onChange={event => { setQuery(event.target.value); setSelected(""); }} /><label className="native-show-all"><input type="checkbox" checked={showAll} onChange={event => { setShowAll(event.target.checked); setSelected(""); }} /> Choose from all logins in this workspace</label>{!choices.length && <p>No linked logins. Choose from all logins to select one manually.</p>}<div className="native-login-choices">{choices.map(item => <label key={item.id}><input type="radio" name="autofill-login" value={item.id} checked={selected === item.id} onChange={() => setSelected(item.id)} /><span><strong>{item.payload.title}</strong><small>{item.payload.username}</small></span></label>)}</div><div className="native-review-actions"><button disabled={busy || !selected} onClick={() => void fill()}>{busy ? "Confirm in Android…" : "Continue to fill"}</button><button disabled={busy} onClick={() => void dismiss()}>Cancel</button></div></>}{message && <p role="status">{message}</p>}
  </section>;
}
