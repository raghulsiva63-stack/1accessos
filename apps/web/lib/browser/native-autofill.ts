type NativeBridge = { postMessage: (value: string) => void; onmessage: ((event: MessageEvent<string>) => void) | null };
declare global { interface Window { PasskeyXNative?: NativeBridge } }

export type NativeContext = {
  id: string; kind: "fill" | "save"; packageName: string; appLabel: string;
  expiresAt: number; username?: string; password?: string;
};

export function nativeAvailable() {
  return typeof window !== "undefined" && window.location.origin === "https://passkey-x.com" && Boolean(window.PasskeyXNative);
}

const channels = new WeakMap<NativeBridge, Map<string, (response: { data?: unknown; error?: unknown }) => void>>();

// Native independently checks the exact origin, main frame, pending operation and TTL.
export async function nativeRequest<T>(action: string, payload: Record<string, unknown> = {}): Promise<T> {
  if (!nativeAvailable()) throw new Error("Open the installed Android app to use autofill.");
  const bridge = window.PasskeyXNative!;
  const requestId = crypto.randomUUID();
  let pending = channels.get(bridge);
  if (!pending) {
    pending = new Map(); channels.set(bridge, pending);
    const channel = pending;
    bridge.onmessage = event => {
      try {
        const response = JSON.parse(event.data);
        if (typeof response.requestId === "string") channel.get(response.requestId)?.(response);
      } catch { /* Ignore unrelated or invalid native messages. */ }
    };
  }
  const channel = pending;
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(() => { cleanup(); reject(new Error("The Android app did not respond. Reopen it and try again.")); }, action === "fill" ? 120_000 : 15_000);
    function cleanup() { clearTimeout(timeout); channel.delete(requestId); }
    function receive(response: { data?: unknown; error?: unknown }) {
      cleanup();
      if (response.error) reject(new Error(String(response.error)));
      else resolve(response.data as T);
    }
    channel.set(requestId, receive);
    try { bridge.postMessage(JSON.stringify({ ...payload, requestId, action })); }
    catch (reason) { cleanup(); reject(reason); }
  });
}

export function validNativeContext(value: unknown, now = Date.now()): value is NativeContext {
  if (!value || typeof value !== "object") return false;
  const context = value as NativeContext;
  return typeof context.id === "string" && /^[a-f0-9-]{36}$/u.test(context.id)
    && ["fill", "save"].includes(context.kind)
    && typeof context.packageName === "string" && /^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$/u.test(context.packageName)
    && typeof context.appLabel === "string" && context.appLabel.length <= 120
    && Number.isFinite(context.expiresAt) && context.expiresAt > now && context.expiresAt <= now + 121_000
    && (context.kind !== "save" || (typeof context.password === "string" && context.password.length > 0 && context.password.length <= 4096 && typeof context.username === "string" && context.username.length <= 1024));
}
