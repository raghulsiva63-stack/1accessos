// Chrome supplies sender metadata. Message payloads must never define authority.
type Sender = {
  id?: string;
  url?: string;
  frameId?: number;
  tab?: { id?: number; url?: string };
};
const POPUP_COMMANDS = new Set(['PX_STATUS', 'PX_UNLOCK', 'PX_LOCK', 'PX_SAVE', 'PX_NEVER', 'PX_FILL']);
function origin(value: unknown) {
  if (typeof value !== 'string') return '';
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) ? url.origin : '';
  } catch { return ''; }
}
export function authorizedExtensionMessage(
  message: unknown, sender: Sender, extensionId: string, popupUrl: string,
): boolean {
  if (!message || typeof message !== 'object' || Array.isArray(message) || sender.id !== extensionId) return false;
  const request = message as Record<string, unknown>;
  if (request.type === 'PX_CANDIDATE') {
    const tabOrigin = origin(sender.tab?.url);
    return sender.frameId === 0 && Number.isInteger(sender.tab?.id) && (sender.tab?.id ?? -1) >= 0
      && Boolean(tabOrigin) && origin(sender.url) === tabOrigin
      && request.origin === tabOrigin && origin(request.url) === tabOrigin
      && typeof request.username === 'string' && request.username.length <= 4096
      && typeof request.secret === 'string' && request.secret.length > 0 && request.secret.length <= 65536;
  }
  return typeof request.type === 'string' && POPUP_COMMANDS.has(request.type)
    && sender.tab === undefined && sender.url === popupUrl;
}
