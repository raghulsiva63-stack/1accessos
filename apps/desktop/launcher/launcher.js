const status = document.querySelector('#status');
fetch('https://passkey-x.com/manifest.webmanifest', { mode: 'no-cors', cache: 'no-store', signal: AbortSignal.timeout(12000) })
  .then(() => { location.replace('https://passkey-x.com/#access'); })
  .catch(() => { status.textContent = 'You appear to be offline. Reconnect, then choose Open my vault.'; });
