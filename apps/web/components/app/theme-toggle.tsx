"use client";

import { useEffect, useState } from "react";
import { Monitor, Moon, Sun } from "lucide-react";

export type ThemeChoice = "light" | "dark" | "system";
export const THEME_EVENT = "passkey-x:theme";
const STORAGE_KEY = "px-theme";

function readChoice(): ThemeChoice {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    return stored === "light" || stored === "dark" || stored === "system" ? stored : "system";
  } catch { return "system"; }
}

function resolved(choice: ThemeChoice) {
  if (choice !== "system") return choice;
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

/** Cycles light → dark → system. The dark palette only applies inside the signed-in app. */
export function ThemeToggle() {
  const [choice, setChoice] = useState<ThemeChoice>(() => typeof window === "undefined" ? "system" : readChoice());

  useEffect(() => {
    const apply = () => { document.documentElement.dataset.theme = resolved(choice); };
    apply();
    try { window.localStorage.setItem(STORAGE_KEY, choice); } catch { /* storage unavailable */ }
    const media = window.matchMedia?.("(prefers-color-scheme: dark)");
    media?.addEventListener("change", apply);
    return () => media?.removeEventListener("change", apply);
  }, [choice]);

  useEffect(() => {
    const cycle = () => setChoice((current) => current === "light" ? "dark" : current === "dark" ? "system" : "light");
    window.addEventListener(THEME_EVENT, cycle);
    return () => window.removeEventListener(THEME_EVENT, cycle);
  }, []);

  const Icon = choice === "dark" ? Moon : choice === "light" ? Sun : Monitor;
  const label = choice === "dark" ? "Dark theme" : choice === "light" ? "Light theme" : "System theme";
  return <button type="button" className="theme-toggle" aria-label={`${label} (click to change)`} title={label} onClick={() => window.dispatchEvent(new Event(THEME_EVENT))}><Icon /></button>;
}
