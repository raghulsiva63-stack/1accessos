import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const web = fileURLToPath(new URL('../../web/', import.meta.url));
// WebAuthn is bound to the HTTPS relying-party domain, not the native webview.
// Native passkey integration requires a separate platform implementation.
execFileSync(process.execPath, ['node_modules/next/dist/bin/next', 'build'], {
  cwd: web, stdio: 'inherit', env: { ...process.env, NEXT_PUBLIC_PASSKEYS_ENABLED: 'false' },
});
