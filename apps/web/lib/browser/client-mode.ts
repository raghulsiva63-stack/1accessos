"use client";

import { useSyncExternalStore } from "react";

export type ClientMode = "web" | "login" | "mobile" | "desktop" | "android";

// Presentation only. A route must never grant native privileges or vault access.
export function resolveClientMode(path: string, hash: string, standalone: boolean, desktop: boolean): ClientMode {
  if (path === "/app/android" || path === "/app/android/") return "android";
  if (path === "/app/desktop" || path === "/app/desktop/" || desktop) return "desktop";
  if (path === "/app/mobile" || path === "/app/mobile/" || standalone) return "mobile";
  if (path === "/login" || path === "/login/" || hash === "#access") return "login";
  return "web";
}

function snapshot(): ClientMode {
  return resolveClientMode(window.location.pathname, window.location.hash,
    window.matchMedia("(display-mode: standalone)").matches || Boolean((navigator as Navigator & { standalone?: boolean }).standalone),
    Boolean(window.__TAURI_INTERNALS__));
}

function subscribe(listener: () => void) {
  const display = window.matchMedia("(display-mode: standalone)");
  window.addEventListener("hashchange", listener);
  window.addEventListener("popstate", listener);
  display.addEventListener("change", listener);
  return () => {
    window.removeEventListener("hashchange", listener);
    window.removeEventListener("popstate", listener);
    display.removeEventListener("change", listener);
  };
}

export function useClientMode(): ClientMode | null {
  return useSyncExternalStore(subscribe, snapshot, () => null);
}
