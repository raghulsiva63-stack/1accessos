# Extension message trust boundary

Date: 2026-09-05. Phase 1 security correction.

## Threat and change

Previously the background message listener allowed page content-script senders to select privileged commands. An extension ID alone is insufficient because content scripts share that ID. The worker now authenticates Chrome-provided sender metadata before any command or status response.

- Privileged status/unlock/lock/save/ignore/fill commands require the exact popup URL, current extension ID and no content-script tab context.
- Content scripts may submit only login candidates. Candidates require frame 0 and matching browser-reported sender, tab and payload origins, with bounded username/password lengths.
- Unknown messages fail closed before reading vault state.
- Both fill paths explicitly target frame 0; the content listener independently rejects subframes.
- Pending candidates are cleared on cross-origin navigation, tab close, lock and the existing 60-second expiry. Same-origin post-login navigation preserves the explicit save-review window.

## Verification and limits

Four executable boundary tests exercise legitimate popup/capture paths, spoofed senders, cross-frame/origin substitutions, oversized payloads and malformed commands. Existing manifest/content/worker/capsule checks also pass. The extension production build passed.

This does not protect a compromised target page from credentials deliberately filled into it; it does not replace revocation, device trust, a real-browser ceremony or independent penetration testing. No extension store release was performed.

## Rollback

Keep the sender gate and disable fill/capture if a client compatibility issue appears. Do not restore unrestricted content-script access as a rollback. No schema or encrypted data migration is needed.

References: Chrome [message passing security](https://developer.chrome.com/docs/extensions/develop/concepts/messaging) and [tabs messaging API](https://developer.chrome.com/docs/extensions/reference/api/tabs#method-sendMessage).

## Type-check gate

Fixed the extension TypeScript configuration: removed conflicting DOM/WebWorker library declarations, added DOM iteration and Vite environment types, made files modules, and pinned the Node build-tool types. `npm test` now requires `tsc --noEmit` before bundling. Final result: type check, production build and all 8 tests passed.
