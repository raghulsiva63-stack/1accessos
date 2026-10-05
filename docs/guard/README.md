# Passkey-X Guard

Guard protects people's browsing, computers and phones. It runs in the browser extension, the desktop app and the Android app, and it reports to the organization's **Threat Center** (Admin console › Threat Center).

## What each app does

| | Browser extension (required for web protection) | Desktop app | Android app | Web app |
|---|---|---|---|---|
| **Unique job** | Checks every page before you can type into it | Checks the computer: software and security settings | Checks shared links and the phone's security | Threat Center for admins; link checker for everyone |
| Dangerous sites | Full-page red warning: **Back to safety**, or **Continue** (only when the policy allows it) | Always-on-top **emergency alert** for anything the extension finds | "Check link with Passkey-X" in the share sheet | "Check a link" in Security Center |
| Look-alike sites | Vault sites, known brands and the organization's own domains | — | Same rules for shared links | Same rules |
| Password typed on the wrong site | Red banner plus emergency alert; IT is told | Alert | — | — |
| Software | — | Compromised builds (3CX, XZ Utils, CCleaner), piracy tools, unsupported software, unapproved remote-control tools, crypto miners, adware, the organization's block list | — | — |
| Device settings | — | Disk encryption, firewall, antivirus, automatic updates, Gatekeeper, OS still supported, browsers without the extension | Screen lock, rooted, USB debugging, security patch age | — |

## Privacy: threats only

- Pages are checked **on the device**. Organizations never receive browsing history. They only see findings: the site, the reason, and whether it was blocked or the person continued.
- The device keeps a compact list of **4-byte hash prefixes**. Only when a page matches a prefix does it send that prefix (never the address) to `threat-check`. The answer is a set of full hashes, which the device compares itself.
- The installed-software list never leaves the computer. Only risky programs are reported.
- Retention: resolved findings are kept 90 days and open findings 365 days. Reviewed phishing reports are kept 180 days; devices not seen for 180 days are removed.

## Threat intelligence

| Source | Cost / licence | Enable with (Supabase function secrets) |
|---|---|---|
| On-device checks (look-alikes, risky login pages, password reuse) | Free, always on | — |
| Organization block and allow lists | Free | Threat Center › Policy |
| Passkey-X community: pages confirmed as phishing by 3 organizations are blocked for 30 days | Free | On by default; can be turned off per organization |
| Google Web Risk | Prefix lists via `computeDiff` are free. Full-hash checks (`hashes.search`) are billed per call ($50 per 1,000 at the time of writing) and are made **only on a prefix match**, cached until Google's expiry, and capped per day | `WEB_RISK_API_KEY`, optional `WEB_RISK_DAILY_LIMIT` (default 300) |
| URLhaus (abuse.ch) | Commercial use needs a Spamhaus subscription | `URLHAUS_AUTH_KEY` |
| Any licensed plain-text URL feed (for example OpenPhish premium) | Per the vendor | `THREAT_FEED_URL`, optional `THREAT_FEED_HEADER` (`Name: value`), `THREAT_FEED_THREAT` (`phishing`, `malware` or `unwanted`) |

The free OpenPhish community feed is licensed for **non-commercial use only**, so it is not used.

## Owner steps

1. **Database:** apply `supabase/migrations/20261006090000_guard.sql`. It creates the tables, functions, the private `threat-intel` storage bucket, and the jobs `px-threat-sync` (every 6 hours) and `px-guard-prune` (daily).
2. **Edge functions:** deploy `threat-sync`, `threat-intel` and `threat-check` (settings in `supabase/config.toml`).
3. **Keys (optional):** add the keys from the table above as function secrets. Web Risk: enable the Web Risk API in Google Cloud and create a restricted API key.
4. **First list:** wait for the next 6-hourly run, or run `select private.kick_threat_sync();` once in the SQL editor.
5. **Extension (store build 0.6.0):** publish it, then force-install it in every browser:
   - **Google Admin console:** Devices › Chrome › Apps & extensions › add by ID › *Force install*.
   - **Intune / Group Policy, Chrome:** `HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist`, value `1 = <id>;https://clients2.google.com/service/update2/crx`.
   - **Intune / Group Policy, Edge:** `HKLM\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist`, value `1 = <id>;https://edge.microsoft.com/extensionwebstorebase/v1/crx`.
   - **macOS (Jamf, Kandji or another MDM):** a `com.google.Chrome` / `com.microsoft.Edge` profile with `ExtensionInstallForcelist`.
   - Add the store IDs to the desktop build (`PASSKEY_X_EXTENSION_IDS`) so the desktop app shows the extension's alerts and can tell which browsers are protected.
6. **Desktop app:** deploy the MSI/PKG/deb and enforce `autoStart` with the policy templates (see `docs/desktop/managed-deployment.md`).
7. **Android:** publish through managed Google Play.

## Data that keeps Guard accurate

These tables are dated and should be reviewed with each release:

- `apps/web/lib/security/endpoint-guard.ts`: software rules (compromised builds, unsupported software), Windows 11 end-of-support dates, the oldest supported macOS version, and Ubuntu/Debian support dates.
- `apps/web/lib/security/web-guard.ts`: frequently impersonated brands and their legitimate look-alike domains.
