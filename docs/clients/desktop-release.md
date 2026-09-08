# Desktop release publishing

The desktop workflow packages Windows x64, universal macOS, and Linux x64.
Inspect its native boundary tests and Linux startup result. Download each GitHub
Actions artifact and verify the archive SHA-256 returned by GitHub before
extracting only its regular files into directories named for those platforms.

Run `python3 scripts/prepare-desktop-release.py ARTIFACTS SCRATCH_OUTPUT --commit COMMIT --run RUN`.
This verifies exact source/build provenance, the committed Cargo.lock, installer
bytes and each checksum sidecar. It creates a fresh, short-lived publishing token
outside the repository. Never put that token in source, logs or public assets.

Deploy `supabase/functions/publish-desktop-release` using its index and handler
plus the temporary release-config.json generated above. The function uses custom
token authentication, so the JWT gateway is disabled for this endpoint only. Its
Supabase service key stays in the function's injected server environment.

Run `python3 scripts/upload-desktop-release.py SCRATCH_OUTPUT`. The endpoint checks
token expiry, exact filename, byte count and SHA-256 before writing. It only
creates immutable objects in the dedicated public client-release bucket. Existing
vault attachment policies remain restricted to their private bucket. Public read
access to installers does not permit anonymous or authenticated client writes.

Immediately redeploy the checked-in closed release-config.json, verify HTTP 410,
and delete the temporary release token. Copy desktop-release.json to the public
`apps/web/public/releases/desktop-VERSION.json` path only after all six public
objects verify. The website proxies `/downloads/desktop/*` to these assets; its
production links must return the recorded sizes and checksums after deployment.

These packages are previews. Windows/Linux are unsigned; macOS is ad-hoc signed
and not notarized. Device acceptance and publisher signing are still required for
a production signed release. Web features load from the canonical HTTPS vault;
new shell versions need manual installation.
