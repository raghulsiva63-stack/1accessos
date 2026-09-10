"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { nativeAvailable, nativeRequest } from "@/lib/browser/native-autofill";

type InstallPrompt = Event & {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed" }>;
};
let pendingInstallPrompt: InstallPrompt | null = null;

export function AppRuntime() {
  const [offline, setOffline] = useState(false);
  const [waiting, setWaiting] = useState<ServiceWorker | null>(null);
  const [updating, setUpdating] = useState(false);
  const [nativeMessage, setNativeMessage] = useState("");
  useEffect(() => {
    const exportFile = (event: Event) => {
      if (!nativeAvailable()) return;
      const { blob, filename } = (event as CustomEvent<{ blob: Blob; filename: string }>).detail;
      if (!(blob instanceof Blob) || blob.size > 25_000_000 || typeof filename !== "string") return;
      const reader = new FileReader();
      reader.onerror = () => setNativeMessage("The export could not open. Try again.");
      reader.onload = () => {
        const base64 = String(reader.result).split(",", 2)[1];
        void nativeRequest("export", { filename, base64 }).then(() => setNativeMessage("Choose a location in Android to save your file.")).catch(reason => setNativeMessage(reason.message));
      };
      reader.readAsDataURL(blob);
    };
    window.addEventListener("passkey-x:android-export", exportFile);
    return () => window.removeEventListener("passkey-x:android-export", exportFile);
  }, []);
  useEffect(() => {
    const installAvailable = (event: Event) => {
      event.preventDefault(); pendingInstallPrompt = event as InstallPrompt;
      window.dispatchEvent(new Event("passkey-x:install-ready"));
    };
    const installed = () => { pendingInstallPrompt = null; };
    window.addEventListener("beforeinstallprompt", installAvailable);
    window.addEventListener("appinstalled", installed);
    const online = () => setOffline(!navigator.onLine);
    online();
    window.addEventListener("online", online);
    window.addEventListener("offline", online);
    let alive = true;
    let registration: ServiceWorkerRegistration | undefined;
    let installing: ServiceWorker | null = null;
    const changed = () => {
      if (alive && registration?.waiting && navigator.serviceWorker.controller) setWaiting(registration.waiting);
    };
    const updateFound = () => {
      installing?.removeEventListener("statechange", changed);
      installing = registration?.installing ?? null;
      installing?.addEventListener("statechange", changed);
    };
    if ("serviceWorker" in navigator && window.isSecureContext && !window.__TAURI_INTERNALS__ && !window.PasskeyXNative) {
      void navigator.serviceWorker.register("/sw.js", { scope: "/", updateViaCache: "none" }).then(value => {
        if (!alive) return;
        registration = value; changed();
        registration.addEventListener("updatefound", updateFound);
        updateFound();
      }).catch(() => { /* The online app continues when installation is unavailable. */ });
    }
    return () => {
      alive = false;
      window.removeEventListener("online", online); window.removeEventListener("offline", online);
      window.removeEventListener("beforeinstallprompt", installAvailable);
      window.removeEventListener("appinstalled", installed);
      registration?.removeEventListener("updatefound", updateFound);
      installing?.removeEventListener("statechange", changed);
    };
  }, []);
  function update() {
    if (!waiting || updating) return;
    // The vault clears its keys and hides its contents before an update is applied.
    window.dispatchEvent(new Event("passkey-x:lock"));
    setUpdating(true);
    navigator.serviceWorker.addEventListener("controllerchange", () => window.location.reload(), { once: true });
    waiting.postMessage({ type: "PX_ACTIVATE_UPDATE" });
  }
  return <>
    {nativeMessage && <div className="app-update-banner" role="status">{nativeMessage}<button onClick={() => setNativeMessage("")}>Dismiss</button></div>}
    {offline && <div className="app-connection-banner" role="status">You’re offline. Reconnect to sync changes or unlock your vault.</div>}
    {waiting && <div className="app-update-banner" role="status"><span>An app update is ready. Save your changes before restarting.</span><button onClick={update} disabled={updating}>{updating ? "Restarting…" : "Lock and restart"}</button></div>}
  </>;
}

export function InstallAction() {
  const [prompt, setPrompt] = useState<InstallPrompt | null>(null);
  const [installed, setInstalled] = useState(false);
  const [message, setMessage] = useState("");
  useEffect(() => {
    const display = window.matchMedia("(display-mode: standalone)");
    const check = () => setInstalled(display.matches || Boolean((navigator as Navigator & { standalone?: boolean }).standalone));
    const available = () => setPrompt(pendingInstallPrompt);
    const complete = () => { setInstalled(true); setPrompt(null); };
    check();
    available();
    display.addEventListener("change", check);
    window.addEventListener("passkey-x:install-ready", available);
    window.addEventListener("appinstalled", complete);
    return () => { display.removeEventListener("change", check); window.removeEventListener("passkey-x:install-ready", available); window.removeEventListener("appinstalled", complete); };
  }, []);
  async function install() {
    if (!prompt) return;
    try {
      await prompt.prompt();
      const choice = await prompt.userChoice;
      setMessage(choice.outcome === "accepted" ? "Installation requested. Open Passkey-X from your home screen or app launcher." : "You can install later using your browser’s app menu.");
    } catch { setMessage("Use your browser’s Install app or Add to Home Screen menu."); }
    finally { pendingInstallPrompt = null; setPrompt(null); }
  }
  return <div className="install-action">
    {installed ? <Link className="client-primary" href="/app/mobile">Open your vault</Link> : prompt ? <button className="client-primary" onClick={() => void install()}>Install Passkey-X</button> : <a className="client-primary" href="#install-steps">How to install</a>}
    <p role="status">{message || (installed ? "Passkey-X is running as an installed app." : "One account. Your encrypted vault on every device.")}</p>
  </div>;
}

declare global { interface Window { __TAURI_INTERNALS__?: unknown } }
