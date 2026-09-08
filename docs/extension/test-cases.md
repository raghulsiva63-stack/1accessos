# Passkey-X extension 0.2.0 — feature test cases

## Execution rules

Use a disposable account with synthetic credentials in isolated test workspaces.
Record result, browser version, timestamp, tester and evidence for each case.
`Automated` means executable coverage exists; `Manual pending` requires device
UAT and must not be marked passed based only on source inspection.

| ID | Feature / steps | Expected outcome | Coverage |
|---|---|---|---|
| E01 | Build with missing or nonproduction URL | Production build rejects invalid configuration | Automated |
| E02 | Inspect packaged manifest and scripts | Stable ID; MV3; bundled scripts; no remote code or secret key | Automated |
| E03 | Load unpacked in Chrome | Icon/popup/worker load without CSP errors | Manual pending |
| E04 | Load unpacked in Edge | Same ID and functional popup | Manual pending |
| E05 | Click Connect | Production page opens; no bearer token in URL | Automated + manual pending |
| E06 | Open connection route directly without request | Sign-in/pairing rejected with restart instructions | Manual pending |
| E07 | Submit incorrect login password | Error shown; no extension session stored | Manual pending |
| E08 | Complete valid password login + Turnstile | Account shown for explicit approval | Manual pending |
| E09 | Sign in using a registered account passkey | Physical ceremony succeeds on production RP domain | Device pending |
| E10 | Sign in with enrolled TOTP/phone MFA | Second factor required before approval | Manual pending |
| E11 | Invalid/expired MFA code | No pairing; error and retry remain usable | Manual pending |
| E12 | Approve a valid pending connection | Verified identity stored in session-only area | Automated + manual pending |
| E13 | Replay identical approval | Rejected; no second Auth verification or session replacement | Automated |
| E14 | Approve after five-minute expiry | Rejected; new request required | Automated |
| E15 | Send approval from another tab/frame | Rejected despite valid origin or nonce | Automated |
| E16 | Use HTTP, lookalike host, alternate port or other route | Rejected before Auth/storage | Automated |
| E17 | Wrong extension ID or malformed/oversized tokens | Rejected | Automated |
| E18 | Supabase rejects supplied access token | No session persisted | Automated with mocked Auth |
| E19 | Cancel before approval | Dedicated login revoked locally; main web session unaffected | Manual pending |
| E20 | Refresh web session while extension is connected | Independent refresh lifecycles remain valid | Manual pending |
| E21 | Correct local vault password | Authorized workspace logins load; no plaintext upload | Manual pending |
| E22 | Incorrect vault password | Vault stays locked; account stays connected | Manual pending |
| E23 | Press Lock during slow unlock/sync | Operation cannot restore keys/items after Lock | Automated generation guards; manual pending |
| E24 | Two rapid unlock/save/fill operations | Second operation rejected; no duplicate mutation | Manual pending |
| E25 | Lock normally | No matching secrets available; account remains connected | Automated session boundary + manual pending |
| E26 | Five minutes without vault action | Vault locks; stale state cannot fill | Manual pending |
| E27 | Stop/restart extension worker | Account remains; vault starts locked | Automated harness + manual pending |
| E28 | Restart browser | Reconnect required; no persistent login/vault material | Automated empty-session harness + manual pending |
| E29 | Disconnect normally | Only extension session revoked; local record removed | Automated with mocked Auth |
| E30 | Disconnect while offline | Local account removed; revocation failure clearly reported | Automated with mocked Auth |
| E31 | Submit website login while locked | Candidate ignored | Automated |
| E32 | Submit on Passkey-X vault/login page | Vault/login password never offered for capture | Automated source guard + manual pending |
| E33 | Save new submitted login while unlocked | Client-encrypted item created; browser can read it after refresh | Manual pending |
| E34 | Submit changed secret for same username/origin | Existing item revised using expected revision | Manual pending |
| E35 | Concurrent web update before extension save | Revision conflict reported; existing item preserved | Manual pending |
| E36 | Choose Never for this site | Subsequent captures ignored; only origin preference persisted | Manual pending |
| E37 | Wait more than 60 seconds / close tab | Pending candidate no longer offered | Manual pending |
| E38 | Navigate to another origin before save/fill | Rejected; no credential leaks | Automated authority checks + manual pending |
| E39 | Save URL containing query/fragment tokens | Saved URL contains only origin and path | Automated source guard + manual pending |
| E40 | Fill exact visible top-level login form | Username/password filled; form never auto-submitted | Manual pending |
| E41 | Fill hidden, disabled, read-only fields or iframe | No unauthorized fill | Manual pending |
| E42 | Fill when no visible login form exists | Visible failure; popup does not falsely report success | Manual pending |
| E43 | Use Alt+Shift+X | First exact-origin login fills; same authorization gates apply | Manual pending |
| E44 | Host/subdomain/scheme/port mismatch | No credential match or fill | Automated boundary + manual pending |
| E45 | Workspace membership revoked before fill | RLS refresh excludes credential; fill denied | Manual pending |
| E46 | Item deleted in web before fill | Reload removes item; fill denied | Manual pending |
| E47 | Accept fill-only Access Capsule and fill | Server use consumed before delivery; value not shown in popup | Manual pending |
| E48 | Capsule revoked, expired or max uses reached | Server rejects further use | Manual pending |
| E49 | Capsule consumption succeeds but page navigation prevents fill | Failure shown; use may remain consumed by design | Manual pending |
| E50 | Offline save/fill or provider failure | No false success; no authorization bypass | Manual pending |
| E51 | Keyboard-only popup and web flow | Labels, focus, disabled busy controls and status are usable | Manual pending |
| E52 | Inspect logs/storage/package for synthetic secrets | No login/vault plaintext in logs or persistent storage; only expected browser-session tokens | Manual pending |

## Cross-product regression gates

Run web lint/build/tests, root package/CLI/auth tests, and the extension suite.
Verify `/api-docs` still advertises the branded customer API, billing keeps the
selected test-mode settings, and existing recovery/signup pages still load.
These are regression checks, not acceptance of all previously unfinished web,
mobile or privileged-runtime requirements.
