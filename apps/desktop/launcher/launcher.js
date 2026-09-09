const status = document.querySelector('#status');
const controller = new AbortController();
const timeout = setTimeout(() => controller.abort(), 12000);
fetch('https://passkey-x.com/manifest.webmanifest', { mode: 'no-cors', cache: 'no-store', signal: controller.signal })
  .then(() => { location.replace('https://passkey-x.com/#access'); })
  .catch(() => { status.textContent = 'You appear to be offline. Reconnect, then choose Open my vault.'; })
  .finally(() => clearTimeout(timeout));
