// Chrome supplies sender metadata. Message payloads must never define authority.
type Sender = {
  id?: string;
  url?: string;
  frameId?: number;
  tab?: { id?: number; url?: string };
};
const POPUP_COMMANDS = new Set(['PX_STATUS', 'PX_CONNECT', 'PX_UNLOCK', 'PX_LOCK', 'PX_DISCONNECT', 'PX_SAVE', 'PX_DISMISS', 'PX_NEVER', 'PX_ALLOW', 'PX_FILL', 'PX_DESKTOP_PAIR', 'PX_DESKTOP_UNLOCK', 'PX_DESKTOP_UNPAIR', 'PX_GUARD_STATUS', 'PX_REPORT_PHISHING']);
// Sent by the full-page warning (warning.html), which runs in the tab it protects.
const WARNING_COMMANDS = new Set(['PX_GUARD_LEAVE', 'PX_GUARD_PROCEED', 'PX_GUARD_DISPUTE']);
function origin(value: unknown) {
  if (typeof value !== 'string') return '';
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) ? url.origin : '';
  } catch { return ''; }
}

export type PendingPairing = { nonce: string; tabId: number; expiresAt: number };
export function authorizedPairingMessage(message: unknown, sender: Sender, extensionId: string, pending?: PendingPairing, now = Date.now()): boolean {
  if (!message || typeof message !== 'object' || Array.isArray(message)) return false;
  const request = message as Record<string, unknown>;
  let senderOrigin = '';
  try { senderOrigin = new URL(sender.url ?? '').origin; } catch { return false; }
  return senderOrigin === 'https://passkey-x.com'
    && new URL(sender.url!).pathname.replace(/\/$/u, '') === '/extension/connect'
    && sender.frameId === 0 && sender.tab?.id === pending?.tabId
    && Boolean(pending && pending.expiresAt > now && pending.expiresAt <= now + 300_000)
    && typeof request.nonce === 'string' && /^[a-f0-9]{64}$/u.test(request.nonce) && request.nonce === pending?.nonce
    && request.type === 'PX_PAIR_SESSION'
    && request.extensionId === extensionId
    && typeof request.accessToken === 'string' && request.accessToken.length > 0 && request.accessToken.length <= 16384
    && typeof request.refreshToken === 'string' && request.refreshToken.length > 0 && request.refreshToken.length <= 16384;
}
export function authorizedExtensionMessage(
  message: unknown, sender: Sender, extensionId: string, popupUrl: string, warningUrl = '',
): boolean {
  if (!message || typeof message !== 'object' || Array.isArray(message) || sender.id !== extensionId) return false;
  const request = message as Record<string, unknown>;
  if (request.type === 'PX_CANDIDATE') {
    const tabOrigin = origin(sender.tab?.url);
    if (tabOrigin && ['passkey-x.com', 'www.passkey-x.com'].includes(new URL(tabOrigin).hostname)) return false;
    return sender.frameId === 0 && Number.isInteger(sender.tab?.id) && (sender.tab?.id ?? -1) >= 0
      && Boolean(tabOrigin) && origin(sender.url) === tabOrigin
      && request.origin === tabOrigin && origin(request.url) === tabOrigin
      && typeof request.url === 'string' && request.url.length <= 8192
      && typeof request.username === 'string' && request.username.length <= 4096
      && typeof request.secret === 'string' && request.secret.length > 0 && request.secret.length <= 65536;
  }
  if (request.type === 'PX_PAGE_CONTEXT') {
    const tabOrigin = origin(sender.tab?.url);
    return sender.frameId === 0 && Number.isInteger(sender.tab?.id) && (sender.tab?.id ?? -1) >= 0
      && Boolean(tabOrigin) && origin(sender.url) === tabOrigin && request.origin === tabOrigin
      && typeof request.hasPasswordField === 'boolean';
  }
  if (typeof request.type === 'string' && WARNING_COMMANDS.has(request.type)) {
    return Boolean(warningUrl) && typeof sender.url === 'string' && (sender.url === warningUrl || sender.url.startsWith(`${warningUrl}#`))
      && sender.frameId === 0 && Number.isInteger(sender.tab?.id) && (sender.tab?.id ?? -1) >= 0;
  }
  return typeof request.type === 'string' && POPUP_COMMANDS.has(request.type)
    && sender.tab === undefined && sender.url === popupUrl;
}
