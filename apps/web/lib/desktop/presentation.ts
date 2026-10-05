// Presentation mode (desktop app): while the screen is shared or recorded, passwords can't be
// revealed and a banner says why. It switches on automatically when a sharing or recording
// program is running (Settings › This computer), or by hand from the tray menu.

import { desktop, isDesktopApp } from "@/lib/desktop/bridge";

export type PresentationState = { active: boolean; manual: boolean; detected: boolean; reasons: string[] };

const OFF: PresentationState = { active: false, manual: false, detected: false, reasons: [] };
let state: PresentationState = OFF;
const listeners = new Set<() => void>();

export const presentationState = () => state;
export const serverPresentationState = () => OFF;
export function subscribePresentation(listener: () => void) { listeners.add(listener); return () => { listeners.delete(listener); }; }

function set(next: Omit<PresentationState, "active">) {
  const active = next.manual || next.detected;
  if (active === state.active && next.manual === state.manual && next.detected === state.detected && next.reasons.join() === state.reasons.join()) return;
  state = { ...next, active };
  if (typeof document !== "undefined") document.documentElement.classList.toggle("presentation-mode", active);
  listeners.forEach((listener) => listener());
}

export function setManualPresentation(manual: boolean) { set({ ...state, manual }); }

/** Pure: the next state after a detection result. */
export function nextPresentation(current: PresentationState, detected: { sharing: boolean; reasons: string[] }, auto: boolean): PresentationState {
  const isDetected = auto && detected.sharing;
  return { manual: current.manual, detected: isDetected, reasons: isDetected ? detected.reasons : [], active: current.manual || isDetected };
}

/** Polls every 5 seconds and listens for the tray toggle. Returns a stop function. */
export function startPresentationWatch(): () => void {
  if (!isDesktopApp()) return () => undefined;
  let auto = true;
  let stopped = false;
  const check = async () => {
    try {
      auto = (await desktop.settings()).presentationAuto;
      const result = auto ? await desktop.presentation() : { sharing: false, reasons: [] };
      if (!stopped) set(nextPresentation(state, result, auto));
    } catch { /* keep the last state */ }
  };
  const toggle = () => setManualPresentation(!state.manual);
  window.addEventListener("passkey-x:presentation-toggle", toggle);
  const first = setTimeout(() => void check(), 2_000);
  const every = setInterval(() => void check(), 5_000);
  return () => { stopped = true; clearTimeout(first); clearInterval(every); window.removeEventListener("passkey-x:presentation-toggle", toggle); };
}
