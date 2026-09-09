# Desktop release publishing

The desktop workflow packages Windows x64, universal macOS, and Linux x64.
Inspect its native boundary tests and Linux startup result. Download each GitHub
Actions artifact and verify the archive SHA-256 returned by GitHub before
extracting its regular files into directories named for those platforms.

Run `python3 scripts/prepare-desktop-release.py ARTIFACTS --commit COMMIT --run RUN`.
This verifies source/build provenance, the committed Cargo.lock, installer bytes
and each checksum sidecar. It stages versioned static assets under `releases/`.
Bounded binary parts permit reliable repository connector transfers. A published
version is immutable; new installer bytes require a new version.

Run `node scripts/prepare-desktop-downloads.mjs`. It reconstructs each installer,
checks its complete SHA-256 and size, and prepares public downloads, sidecars and
a release manifest. The combined Netlify build runs this automatically. CI also
checks the hashes. Missing or altered parts fail the build.

Commit the verified parts and manifest with the matching website download links.
After the normal GitHub/Netlify deployment, verify the six public download URLs
against the recorded SHA-256 values. Installers are ordinary static site assets;
there is no additional upload endpoint, privileged runtime or storage policy.

These packages are previews. Windows/Linux are unsigned; macOS is ad-hoc signed
and not notarized. Device acceptance and publisher signing are still required for
a production signed release. Web features load from the canonical HTTPS vault;
new shell versions need manual installation.
