type EventSource = Pick<EventTarget, "addEventListener" | "removeEventListener">;

/**
 * One foreground vault lifetime. It can lock once and never unlock itself.
 * `lockWhenHidden` is only turned off by the desktop app, which hides its window after a
 * quick copy and locks natively on sleep, screen lock and quit; the idle limit still applies.
 */
export function watchVaultLifetime({
  documentObject, windowObject, onLock, idleMs = 300_000, lockWhenHidden = true,
  now = Date.now, schedule = setTimeout, cancel = clearTimeout,
}: {
  documentObject: EventSource & { readonly hidden: boolean };
  windowObject: EventSource;
  onLock: () => void;
  idleMs?: number;
  lockWhenHidden?: boolean;
  now?: () => number;
  schedule?: typeof setTimeout;
  cancel?: typeof clearTimeout;
}) {
  let stopped = false;
  let lastActivity = now();
  let timer: ReturnType<typeof setTimeout>;
  function lock() {
    if (stopped) return;
    stopped = true;
    cancel(timer);
    onLock();
  }
  function check() {
    if (stopped) return;
    const remaining = idleMs - (now() - lastActivity);
    if ((lockWhenHidden && documentObject.hidden) || remaining <= 0 || remaining > idleMs) lock();
    else timer = schedule(check, remaining);
  }
  function activity(event: Event) {
    // App scripts cannot keep an unattended vault unlocked with synthetic events.
    if (!event.isTrusted || stopped) return;
    if ((lockWhenHidden && documentObject.hidden) || now() - lastActivity >= idleMs || now() < lastActivity) { lock(); return; }
    lastActivity = now();
  }
  const activityEvents = ["pointerdown", "keydown", "touchstart", "scroll"];
  for (const name of activityEvents) documentObject.addEventListener(name, activity, { passive: true, capture: true });
  documentObject.addEventListener("visibilitychange", check);
  documentObject.addEventListener("freeze", lock);
  windowObject.addEventListener("pagehide", lock);
  windowObject.addEventListener("passkey-x:lock", lock);
  check();
  return () => {
    stopped = true; cancel(timer);
    for (const name of activityEvents) documentObject.removeEventListener(name, activity, true);
    documentObject.removeEventListener("visibilitychange", check);
    documentObject.removeEventListener("freeze", lock);
    windowObject.removeEventListener("pagehide", lock);
    windowObject.removeEventListener("passkey-x:lock", lock);
  };
}
