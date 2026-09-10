"use client";

import Image from "next/image";
import Link from "next/link";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { ArrowRight, KeyRound, Laptop, Plus, Search, ShieldCheck, Smartphone, Star, WandSparkles } from "lucide-react";
import type { ClientMode } from "@/lib/browser/client-mode";
import type { VaultItem } from "@/lib/vault/items";
import { PublicSite } from "@/components/public-site";
import { NativeAutofillSetup } from "@/components/native-autofill";

export function ClientAuthFrame({ mode, children }: { mode: ClientMode; children: ReactNode }) {
  if (mode === "web") return <PublicSite>{children}</PublicSite>;
  const mobile = mode === "mobile" || mode === "android";
  return <main className={`client-signin client-signin-${mode}`}>
    <header><Link href="/" aria-label="Passkey-X website"><Image src="/brand/passkey-x-horizontal.png" alt="Passkey-X" width={190} height={54} priority /></Link><Link href="/download">Get the apps</Link></header>
    <div className="client-signin-body"><div className="client-signin-intro"><span className="client-device-icon">{mobile ? <Smartphone /> : mode === "desktop" ? <Laptop /> : <ShieldCheck />}</span><p className="eyebrow">{mobile ? "Your mobile companion" : mode === "desktop" ? "Your desktop workspace" : "Your private vault"}</p><h1>{mobile ? "Your passwords.\nWithin reach." : mode === "desktop" ? "Open. Find.\nGet on with your day." : "Welcome back."}</h1><p>{mobile ? "Quick access to favorites, a password generator and your encrypted logins." : mode === "desktop" ? "Search your vault, manage workspaces and keep your everyday credentials close." : "Sign in, unlock your vault and pick up where you left off."}</p><div className="client-signin-trust"><ShieldCheck /> Your vault password stays on this device.</div></div>{children}</div>
    <footer>Passkey-X by Vlightsoft <Link href="/#security">Security</Link></footer>
  </main>;
}

export function CompanionHome({ mode, items, onSelect, onNew, onVault, onGenerator, onSecurity, onRefresh }: {
  mode: ClientMode; items: VaultItem[]; onSelect: (item: VaultItem) => void;
  onNew: () => void; onVault: () => void; onGenerator: () => void; onSecurity: () => void; onRefresh: () => Promise<void>;
}) {
  const mobile = mode === "mobile" || mode === "android";
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<"favorites" | "recent" | "login" | "recovery-codes">("favorites");
  const [refreshing, setRefreshing] = useState(false);
  const search = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const focus = () => search.current?.focus();
    window.addEventListener("passkey-x:quick-access", focus);
    return () => window.removeEventListener("passkey-x:quick-access", focus);
  }, []);
  const visible = items.filter(item => !item.payload.archived && !item.deletedAt)
    .filter(item => query ? [item.payload.title, item.payload.username, item.payload.url, ...(item.payload.tags ?? [])].join(" ").toLowerCase().includes(query.toLowerCase())
      : filter === "favorites" ? item.payload.favorite : filter === "recent" ? true : item.contentType === filter)
    .sort((a, b) => b.payload.updatedAt.localeCompare(a.payload.updatedAt)).slice(0, 12);
  async function refresh() { setRefreshing(true); try { await onRefresh(); } finally { setRefreshing(false); } }
  return <div className={`companion-home companion-${mobile ? "mobile" : "desktop"}`}>
    <section className="companion-search-card"><div><span className="client-tag">{mobile ? "Made for your day" : "Quick access"}</span><h2>{mobile ? "What do you need?" : "Find it. Keep moving."}</h2><p>{mobile ? "Your favorites and essential logins, one tap away." : "Search locally by name, username, website or tag."}</p></div><label className="companion-search"><Search /><input ref={search} aria-label="Search quick access" placeholder="Search your vault" value={query} onChange={event => setQuery(event.target.value)} />{!mobile && <kbd>Ctrl / ⌘ K</kbd>}</label></section>
    <div className="companion-actions"><button onClick={onNew}><Plus /><span>Add login</span></button><button onClick={onGenerator}><WandSparkles /><span>Generate password</span></button><button onClick={onSecurity}><ShieldCheck /><span>Security check</span></button></div>
    <div className="companion-columns"><section className="companion-list-card"><nav className="companion-tabs" aria-label="Quick access filter">{([['favorites', 'Favorites'], ['recent', 'Recent'], ['login', 'Logins'], ['recovery-codes', 'Recovery']] as const).map(([id, title]) => <button key={id} aria-pressed={filter === id} onClick={() => { setFilter(id); setQuery(""); }}>{title}</button>)}</nav>
      {visible.length ? <div className="companion-items">{visible.map(item => <button key={item.id} onClick={() => onSelect(item)}><span className="companion-item-icon">{item.payload.favorite ? <Star /> : <KeyRound />}</span><span><strong>{item.payload.title}</strong><small>{item.payload.username || item.contentType.replaceAll("-", " ")}</small></span><ArrowRight /></button>)}</div> : <div className="companion-empty"><Star /><strong>{query ? "No matching items" : filter === "favorites" ? "Keep your essentials here" : "Nothing here yet"}</strong><p>{query ? "Try another name, username or website." : "Open an item in your vault and add it to Favorites for quick access."}</p><button onClick={onVault}>Browse vault <ArrowRight /></button></div>}
      <div className="companion-list-footer"><button onClick={onVault}>Open full vault</button><button disabled={refreshing} onClick={() => void refresh()}>{refreshing ? "Refreshing…" : "Refresh synced items"}</button></div></section>
      <aside className="companion-tools">{mobile ? <NativeAutofillSetup native={mode === "android"} /> : <section><Laptop /><h3>Your desktop shortcuts</h3><dl><div><dt>Quick access</dt><dd>Ctrl / ⌘ K</dd></div><div><dt>Add a login</dt><dd>Ctrl / ⌘ Shift N</dd></div><div><dt>Lock vault</dt><dd>Ctrl / ⌘ L</dd></div></dl><p>These shortcuts work while the app is focused. Use the browser extension for automatic website save prompts.</p><Link href="/download#browser">Set up the extension <ArrowRight /></Link></section>}
      {mobile && <section><ShieldCheck /><h3>Private when you put it away</h3><p>Your vault locks when you leave the app. Reopen and unlock to reveal your passwords.</p></section>}</aside></div>
  </div>;
}
