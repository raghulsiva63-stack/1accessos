# Passkey-X Android 0.1.0 preview

Native Android 9+ application with an online encrypted vault and an optional AutofillService. The app opens `/app/android` directly into account login/unlock. Mobile Home has favorites, recent items, logins, recovery items, search and quick actions. The App menu provides autofill settings, lock, reload and browser fallback.

The user enables Passkey-X in Android Settings. Compatible native text/password fields receive a locked dataset; selecting it opens the private autofill activity. After vault unlock and explicit credential selection, a native dialog identifies the receiving app and package. Confirming returns one dataset to Android, which fills that form without submitting it. Native applications with embedded web forms, unverified web domains, ambiguous fields or unsupported controls are excluded. There is no keyboard logger, accessibility monitor or clipboard polling.

Android's SaveInfo triggers the system save prompt. After the user approves, the service holds the candidate in a bounded process-memory store and opens vault review. The web vault explicitly selects a writable workspace and encrypts before persisting. Package association is encrypted in `payload.fields.androidPackage`; a unique same-package/same-username record is updated, with metadata preserved. The native UI only reports saved after the encrypted write succeeds.

Requests expire after two minutes and cannot be replayed. The private activity is not exported, PendingIntents are immutable and one-shot, and Intents/URLs never contain credentials. Expiry, cancellation, leaving the autofill activity and process death discard pending data. Confirmation passwords are cleared on background/expiry. Web messages require the exact production HTTPS origin and main frame; a URL parameter never authorizes native access. Screenshot/recent-app capture, app backup, webview debugging, file URLs, mixed content and automatic permission grants are disabled.

Imports use Android's document picker. Exports up to 25 MB use the location selected in Android; temporary export buffers expire after two minutes. Passkey/security checks depend on Android System WebView; the App menu can open the web vault in a browser. Internet is required; there is no offline unlock or native biometric vault unlock.

Build with JDK 17, Gradle 8.11.1 and Android SDK 35: `gradle :app:assemblePreview :app:lintPreview`. `bash scripts/check-core.sh` exercises pure native boundaries. The CI emulator uses the separate offline `fixture` app to exercise system dataset fill, save review and cancellation with synthetic credentials. It substitutes a post-unlock credential selection; a real account's encrypted save/sync, CAPTCHA and MFA still require combined device UAT.

Preview APKs are non-debuggable and signed with a temporary CI key. A future build may require uninstalling an older preview. Stable signing, Play Store review and broader device acceptance testing are release work. No iOS Credential Provider extension is included; iPhone currently uses the mobile web app. The fixture and instrumentation tests are never included in the preview APK.

Publish only checksum-verified artifacts using `scripts/prepare-android-release.py`, then select the version in `apps/web/lib/client-releases.json`. The normal website build verifies every part and complete APK before exposing a download.
