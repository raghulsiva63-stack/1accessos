import { access } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
await access(new URL('../launcher/index.html', import.meta.url));
// Generate every native icon format from the checked-in brand icon.
execFileSync(process.execPath, ['node_modules/@tauri-apps/cli/tauri.js', 'icon', 'icons/icon.png', '--output', 'src-tauri/icons'], { cwd: root, stdio: 'inherit' });
