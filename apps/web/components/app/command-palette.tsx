"use client";

import { useEffect, useEffectEvent, useMemo, useState } from "react";
import { ArrowRight, KeyRound, LockKeyhole, MoonStar, Plus, Search, WandSparkles } from "lucide-react";
import { THEME_EVENT } from "@/components/app/theme-toggle";
import type { VaultItem } from "@/lib/vault/items";

export const OPEN_COMMAND_PALETTE = "passkey-x:command-palette";

type Entry =
  | { kind: "action"; id: string; label: string; hint: string; icon: typeof Search; run: () => void }
  | { kind: "view"; id: string; label: string; run: () => void }
  | { kind: "item"; id: string; label: string; hint: string; run: () => void };

export function CommandPaletteButton() {
  return <button type="button" className="command-trigger" onClick={() => window.dispatchEvent(new Event(OPEN_COMMAND_PALETTE))} aria-label="Search and commands">
    <Search /><span>Search…</span><kbd>Ctrl K</kbd>
  </button>;
}

export function CommandPalette({ enabled, items, views, onNavigate, onOpenItem, onNewItem, onLock }: {
  enabled: boolean;
  items: VaultItem[];
  views: { id: string; label: string }[];
  onNavigate: (id: string) => void;
  onOpenItem: (item: VaultItem) => void;
  onNewItem: () => void;
  onLock: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);

  const show = useEffectEvent(() => { if (enabled) { setQuery(""); setActive(0); setOpen(true); } });
  const toggle = useEffectEvent(() => { if (!enabled) return; if (open) setOpen(false); else { setQuery(""); setActive(0); setOpen(true); } });
  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (!event.isTrusted || !(event.ctrlKey || event.metaKey) || event.altKey || event.key.toLowerCase() !== "k") return;
      event.preventDefault();
      toggle();
    };
    const openFromEvent = () => show();
    document.addEventListener("keydown", keydown);
    window.addEventListener(OPEN_COMMAND_PALETTE, openFromEvent);
    return () => { document.removeEventListener("keydown", keydown); window.removeEventListener(OPEN_COMMAND_PALETTE, openFromEvent); };
  }, []);

  const entries = useMemo<Entry[]>(() => {
    const needle = query.trim().toLowerCase();
    const matches = (...values: (string | undefined)[]) => !needle || values.some((value) => value?.toLowerCase().includes(needle));
    const actions: Entry[] = ([
      { kind: "action", id: "new", label: "New item", hint: "Add a password, note, card or key", icon: Plus, run: onNewItem },
      { kind: "action", id: "generate", label: "Generate a password", hint: "Open the generator", icon: WandSparkles, run: () => onNavigate("generator") },
      { kind: "action", id: "lock", label: "Lock vault", hint: "Clear keys from memory", icon: LockKeyhole, run: onLock },
      { kind: "action", id: "theme", label: "Change theme", hint: "Light, dark or match the system", icon: MoonStar, run: () => window.dispatchEvent(new Event(THEME_EVENT)) },
    ] satisfies Entry[]).filter((entry) => matches(entry.label, entry.hint));
    const viewEntries: Entry[] = views.filter((view) => matches(view.label, "go to")).map((view) => ({ kind: "view", id: `view:${view.id}`, label: view.label, run: () => onNavigate(view.id) }));
    const itemEntries: Entry[] = needle ? items.filter((item) => matches(item.payload.title, item.payload.username, item.payload.url, ...(item.payload.tags ?? []))).slice(0, 8)
      .map((item) => ({ kind: "item", id: `item:${item.id}`, label: item.payload.title, hint: item.payload.username || item.payload.url || "", run: () => onOpenItem(item) })) : [];
    return [...itemEntries, ...actions, ...viewEntries].slice(0, 14);
  }, [items, onLock, onNavigate, onNewItem, onOpenItem, query, views]);

  if (!open) return null;
  const selected = Math.min(active, Math.max(entries.length - 1, 0));
  const choose = (entry: Entry | undefined) => { if (!entry) return; setOpen(false); entry.run(); };

  return <div className="command-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) setOpen(false); }}>
    <div className="command-palette" role="dialog" aria-modal="true" aria-label="Search and commands">
      <div className="command-input"><Search /><input autoFocus value={query} placeholder="Search your vault or type a command…" aria-label="Search your vault or type a command" aria-activedescendant={entries[selected] ? `cmd-${entries[selected].id}` : undefined}
        onChange={(event) => { setQuery(event.target.value); setActive(0); }}
        onKeyDown={(event) => {
          if (event.key === "Escape") { event.preventDefault(); setOpen(false); }
          else if (event.key === "ArrowDown") { event.preventDefault(); setActive((selected + 1) % Math.max(entries.length, 1)); }
          else if (event.key === "ArrowUp") { event.preventDefault(); setActive((selected - 1 + entries.length) % Math.max(entries.length, 1)); }
          else if (event.key === "Enter") { event.preventDefault(); choose(entries[selected]); }
        }} /><kbd>Esc</kbd></div>
      <ul role="listbox" className="command-results">
        {entries.length === 0 && <li className="command-empty">No matches for “{query}”.</li>}
        {entries.map((entry, index) => {
          const icon = entry.kind === "action" ? <entry.icon /> : entry.kind === "item" ? <KeyRound /> : <ArrowRight />;
          return <li key={entry.id} id={`cmd-${entry.id}`} role="option" aria-selected={index === selected} className={index === selected ? "active" : ""} onMouseEnter={() => setActive(index)} onMouseDown={(event) => { event.preventDefault(); choose(entry); }}>
            {icon}<span><strong>{entry.label}</strong>{entry.kind !== "view" && entry.hint && <small>{entry.hint}</small>}</span><em>{entry.kind === "item" ? "Open item" : entry.kind === "view" ? "Go to" : "Action"}</em>
          </li>;
        })}
      </ul>
      <footer><span><kbd>↑</kbd><kbd>↓</kbd> navigate</span><span><kbd>Enter</kbd> select</span><span>Secrets are never shown here.</span></footer>
    </div>
  </div>;
}
