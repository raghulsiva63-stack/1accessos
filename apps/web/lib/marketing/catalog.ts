export type IconName =
  | "KeyRound" | "Fingerprint" | "Braces" | "Send" | "LayoutDashboard" | "UserRound" | "Users" | "Building2"
  | "BriefcaseBusiness" | "ShieldCheck" | "Server" | "Search" | "Star" | "History" | "Paperclip" | "WandSparkles"
  | "Zap" | "Repeat2" | "Laptop" | "Smartphone" | "LockKeyhole" | "FileClock" | "FolderLock" | "SlidersHorizontal"
  | "UserX" | "Gauge" | "Link2" | "TimerOff" | "EyeOff" | "Database" | "Code2" | "Waypoints" | "Sparkles"
  | "CreditCard" | "IdCard" | "Heart" | "Activity" | "BadgeCheck" | "Share2" | "FileKey";

export type Feature = { icon: IconName; title: string; body: string };

export type MarketingEntry = {
  slug: string;
  name: string;
  navLabel: string;
  navBlurb: string;
  icon: IconName;
  kicker: string;
  title: string;
  titleAccent: string;
  intro: string;
  primaryCta: { label: string; href: string };
  secondaryCta: { label: string; href: string };
  proof: string[];
  features: Feature[];
  steps?: { title: string; body: string }[];
  highlight?: { kicker: string; title: string; body: string; bullets: string[] };
  faq: [string, string][];
  related: string[];
  metaTitle: string;
  metaDescription: string;
};

export const PRODUCTS: MarketingEntry[] = [
  {
    slug: "password-manager", name: "Password Manager", navLabel: "Password Manager", icon: "KeyRound",
    navBlurb: "Every login, card and note — encrypted on your device.",
    kicker: "Password Manager", title: "Every password, everywhere.", titleAccent: "Readable only by you.",
    intro: "Store logins, cards, identities, Wi-Fi, licences and secure notes in a vault that is encrypted on your device before it syncs. Search, fill and share without ever giving Passkey-X your vault password.",
    primaryCta: { label: "Create your free vault", href: "/login" }, secondaryCta: { label: "See pricing", href: "/pricing" },
    proof: ["Argon2id + AES-256-GCM", "Separate vault password", "Recovery key you control"],
    features: [
      { icon: "Search", title: "Instant local search", body: "Search titles, usernames, URLs, notes and tags — all on your device, after decryption." },
      { icon: "IdCard", title: "13 item types", body: "Logins, passkeys, cards, identities, Wi-Fi, licences, API and SSH keys, databases, certificates and more." },
      { icon: "WandSparkles", title: "Password generator", body: "Cryptographically random passwords and seven-word passphrases, with clipboard auto-clear." },
      { icon: "Zap", title: "Breach and health checks", body: "Find weak, reused, old and breached passwords with k-anonymity breach checks." },
      { icon: "History", title: "Revision history", body: "Every change keeps an encrypted revision, so you can see and recover earlier values." },
      { icon: "Paperclip", title: "Encrypted attachments", body: "Attach documents and keys to any item. Files are encrypted before upload." },
      { icon: "Star", title: "Favourites and archive", body: "Keep everyday logins one click away and archive what you rarely need." },
      { icon: "Laptop", title: "Web, desktop, mobile, browser", body: "One vault across your browser, desktop app, phone and browser extension." },
    ],
    steps: [
      { title: "Create your vault", body: "Sign up, choose a vault password and download your recovery key." },
      { title: "Import in minutes", body: "Bring your passwords from 1Password, Bitwarden, LastPass or any browser CSV." },
      { title: "Fix what is risky", body: "Security Center shows weak, reused and breached passwords to change first." },
    ],
    faq: [
      ["Can Passkey-X see my passwords?", "No. Items are encrypted on your device with keys derived from your vault password, which we never receive."],
      ["What if I forget my vault password?", "Use the recovery key you saved during setup. Without it nobody — including Passkey-X — can open the vault."],
      ["Is there a free plan?", "Yes. Free includes the full encrypted vault. Paid plans remove sponsor cards and add devices, sharing and more."],
    ],
    related: ["passkeys", "secure-send", "secrets-manager"],
    metaTitle: "Password Manager — Passkey-X", metaDescription: "A zero-knowledge password manager: encrypted on your device, with a separate vault password, breach checks and recovery key.",
  },
  {
    slug: "passkeys", name: "Passkeys", navLabel: "Passkeys", icon: "Fingerprint",
    navBlurb: "Phishing-resistant sign-in and passkey management.",
    kicker: "Passkeys", title: "Sign in with a fingerprint.", titleAccent: "Not a password.",
    intro: "Passkeys are phishing-resistant credentials bound to the real website. Use a passkey to sign in to Passkey-X, keep track of the passkeys you use elsewhere, and require them across your organization.",
    primaryCta: { label: "Start with passkeys", href: "/login" }, secondaryCta: { label: "How it is secured", href: "/security" },
    proof: ["WebAuthn / FIDO2", "Domain-bound", "Admin enforceable"],
    features: [
      { icon: "Fingerprint", title: "Passkey sign-in", body: "Sign in to Passkey-X with Face ID, Touch ID, Windows Hello or a security key." },
      { icon: "ShieldCheck", title: "Phishing-resistant", body: "A passkey only works on the site it was created for, so look-alike pages cannot steal it." },
      { icon: "KeyRound", title: "Passkey references", body: "Record which accounts use passkeys and where, alongside your passwords." },
      { icon: "SlidersHorizontal", title: "Enforce for your team", body: "Business admins can require passkeys or 2-step sign-in for every member." },
      { icon: "LockKeyhole", title: "Vault stays separate", body: "Signing in with a passkey never decrypts the vault on its own — the vault password still protects your data." },
      { icon: "Smartphone", title: "Authenticator app 2-step", body: "Prefer codes? Add an authenticator app (TOTP) as a second sign-in step." },
    ],
    faq: [
      ["Do I still need a vault password?", "Yes. The passkey proves who you are; the vault password is what decrypts your data. Keeping them separate protects you if your account session is ever compromised."],
      ["What devices work?", "Any device with a modern browser and a platform authenticator (Face ID, Touch ID, Windows Hello, Android) or a hardware security key."],
    ],
    related: ["password-manager", "admin-console"],
    metaTitle: "Passkeys — Passkey-X", metaDescription: "Phishing-resistant passkey sign-in, passkey tracking and organization-wide passkey enforcement.",
  },
  {
    slug: "secrets-manager", name: "Secrets Manager", navLabel: "Secrets Manager", icon: "Braces",
    navBlurb: "API keys, SSH keys and database credentials for developers.",
    kicker: "Secrets Manager for developers", title: "Stop committing secrets.", titleAccent: "Share them safely.",
    intro: "Keep API keys, SSH keys, database credentials and certificates in encrypted workspaces with roles and expiry. Use the ciphertext-only CLI and API to automate — without handing plaintext to our servers.",
    primaryCta: { label: "Start free", href: "/login" }, secondaryCta: { label: "Read the API docs", href: "/api-docs" },
    proof: ["Client-side encryption", "Ciphertext-only CLI", "Per-workspace keys"],
    features: [
      { icon: "Code2", title: "API keys and tokens", body: "Store service tokens with the account and environment they belong to." },
      { icon: "Server", title: "SSH keys and hosts", body: "Keep private keys or references next to the hosts and users they unlock." },
      { icon: "Database", title: "Database credentials", body: "Connection details and passwords for every environment, shared by role." },
      { icon: "FileKey", title: "Certificates and files", body: "Encrypted attachments for certificates, key files and configuration." },
      { icon: "Waypoints", title: "Missions", body: "Time-boxed task access: open exactly the secrets a deploy or incident needs." },
      { icon: "FolderLock", title: "Expiring access", body: "Give contractors access that expires automatically, and review it quarterly." },
    ],
    highlight: {
      kicker: "Automation", title: "Built for pipelines, not just people.",
      body: "The REST API and CLI move ciphertext. Decryption happens where the key lives — on a trusted device — so a leaked token never exposes plaintext at rest.",
      bullets: ["Versioned REST API with an OpenAPI description", "Ciphertext-only command-line client", "Tamper-evident audit of every secret reveal"],
    },
    faq: [
      ["Does the CLI send plaintext to Passkey-X?", "No. The CLI handles ciphertext; decryption requires keys held by the user or device."],
      ["Can I use it for CI/CD?", "Yes — use Missions and expiring access for pipelines, and the API for encrypted storage. Machine identities are on the roadmap."],
    ],
    related: ["password-manager", "secure-send"],
    metaTitle: "Secrets Manager — Passkey-X", metaDescription: "Encrypted storage and sharing for API keys, SSH keys, database credentials and certificates, with a ciphertext-only CLI and API.",
  },
  {
    slug: "secure-send", name: "Secure Send", navLabel: "Secure Send", icon: "Send",
    navBlurb: "Burn-after-reading links for anyone, even without an account.",
    kicker: "Secure Send", title: "Share a secret once.", titleAccent: "Then it’s gone.",
    intro: "Send a password, note or file to anyone as an end-to-end encrypted link. The key lives only in the link, the content burns after the last view, and you can revoke it any time.",
    primaryCta: { label: "Try Secure Send", href: "/login" }, secondaryCta: { label: "How it works", href: "/security" },
    proof: ["Key only in the link", "Burn after reading", "No account needed to open"],
    features: [
      { icon: "Link2", title: "Key in the URL fragment", body: "The decryption key is after the # and is never sent to our servers." },
      { icon: "TimerOff", title: "Expiry and view limits", body: "From one view to 25, and from one hour to 30 days. The last view deletes the ciphertext." },
      { icon: "LockKeyhole", title: "Optional passphrase", body: "Add a passphrase and send it separately. Wrong guesses never burn a link; ten lock it." },
      { icon: "Paperclip", title: "Text or files", body: "Send a secret or a file up to 5 MB, encrypted in your browser." },
      { icon: "UserX", title: "Revoke any time", body: "Revoking deletes the encrypted content immediately." },
      { icon: "SlidersHorizontal", title: "Admin controls", body: "Organizations decide who may create external links, and every send is audited." },
    ],
    faq: [
      ["Does the recipient need Passkey-X?", "No. Anyone with the link (and passphrase, if set) can open it in a browser."],
      ["Can Passkey-X read what I send?", "No. Content is encrypted in your browser with a key that only exists in the link you share."],
    ],
    related: ["password-manager", "admin-console"],
    metaTitle: "Secure Send — Passkey-X", metaDescription: "End-to-end encrypted, burn-after-reading links for passwords, notes and files.",
  },
  {
    slug: "admin-console", name: "Admin Console", navLabel: "Admin Console", icon: "LayoutDashboard",
    navBlurb: "Policies, audit, access reviews and lifecycle for IT.",
    kicker: "Admin Console", title: "Govern every credential.", titleAccent: "See none of them.",
    intro: "One place for IT and security to enforce policy, review access, offboard people and prove it to auditors — while every member’s vault stays encrypted on their device.",
    primaryCta: { label: "Book a demo", href: "/contact?interest=demo" }, secondaryCta: { label: "Start a Business trial", href: "/login" },
    proof: ["Zero-knowledge administration", "Hash-chained audit", "Access reviews"],
    features: [
      { icon: "Gauge", title: "Organization health", body: "Health score, members at risk, 2-step coverage and inactive accounts at a glance." },
      { icon: "SlidersHorizontal", title: "Ten enforceable policies", body: "Passkeys, 2-step, password strength, auto-lock, clipboard, breach monitoring, sharing and export." },
      { icon: "FileClock", title: "Tamper-evident audit", body: "SHA-256 chained events with one-click verification and CSV/JSON export." },
      { icon: "FolderLock", title: "Access reviews", body: "Every shared vault, who has access, last activity and expiry — with evidence export." },
      { icon: "UserX", title: "Lifecycle", body: "Suspend, reactivate and offboard with key revocation and rotation flags." },
      { icon: "Activity", title: "Audit streaming", body: "Stream audit events to your SIEM or any HTTPS endpoint with signed webhooks." },
    ],
    faq: [
      ["Can admins read member passwords?", "No. Admins manage access and policy, and see aggregate risk counts — never vault contents."],
      ["Which plan includes the Admin Console?", "Business, and Enterprise under contract."],
    ],
    related: ["passkeys", "secure-send"],
    metaTitle: "Admin Console — Passkey-X", metaDescription: "Policies, tamper-evident audit, access reviews and lifecycle management for zero-knowledge password management.",
  },
];

export const SOLUTIONS: MarketingEntry[] = [
  {
    slug: "individuals", name: "Individuals", navLabel: "Individuals", icon: "UserRound",
    navBlurb: "A private vault for your digital life.",
    kicker: "For individuals", title: "Your digital life,", titleAccent: "under your control.",
    intro: "Keep every password, card and recovery code in one private vault that only you can open — on every device you own.",
    primaryCta: { label: "Start free", href: "/login" }, secondaryCta: { label: "Compare plans", href: "/pricing" },
    proof: ["Free forever plan", "Unlimited devices on Personal", "Recovery key"],
    features: [
      { icon: "KeyRound", title: "All your logins", body: "Save and find passwords instantly, on web, desktop and mobile." },
      { icon: "Zap", title: "Know when you are exposed", body: "Breach checks and a security score tell you what to change first." },
      { icon: "Fingerprint", title: "Passkey sign-in", body: "Phishing-resistant sign-in with your fingerprint or face." },
      { icon: "Send", title: "Share safely", body: "Send a Wi-Fi password or code with a link that self-destructs." },
    ],
    faq: [["What does Personal add over Free?", "Ad-free experience and unlimited devices, plus priority features as they ship."]],
    related: ["password-manager", "passkeys"],
    metaTitle: "Passkey-X for individuals", metaDescription: "A private, zero-knowledge vault for your passwords, cards and recovery codes.",
  },
  {
    slug: "families", name: "Families", navLabel: "Families", icon: "Heart",
    navBlurb: "Shared vaults for up to six people.",
    kicker: "For families", title: "Share the Netflix password.", titleAccent: "Not your whole vault.",
    intro: "Give everyone at home their own private vault, plus shared family vaults for the accounts you use together.",
    primaryCta: { label: "Start a Family trial", href: "/login" }, secondaryCta: { label: "See Family pricing", href: "/pricing" },
    proof: ["Up to 6 people", "Private + shared vaults", "Recovery support"],
    features: [
      { icon: "Users", title: "Shared family vaults", body: "Streaming, utilities, school portals — shared with the people who need them." },
      { icon: "LockKeyhole", title: "Private by default", body: "Everyone keeps their own vault that nobody else can open." },
      { icon: "Send", title: "Send to anyone", body: "Share a one-time code with grandparents without an account." },
      { icon: "ShieldCheck", title: "Safer accounts", body: "Health checks help everyone fix weak and reused passwords." },
    ],
    faq: [["Can parents see children’s private vaults?", "No. Private vaults are private. Share what you want into family vaults."]],
    related: ["password-manager", "secure-send"],
    metaTitle: "Passkey-X for families", metaDescription: "Private and shared family vaults for up to six people.",
  },
  {
    slug: "teams", name: "Teams", navLabel: "Teams", icon: "Users",
    navBlurb: "Shared vaults, roles and approvals for one workgroup.",
    kicker: "For teams", title: "Stop sharing passwords in chat.", titleAccent: "Share access instead.",
    intro: "Team gives one workgroup encrypted shared vaults with roles, expiring invitations, approval requests and alerts — set up in minutes.",
    primaryCta: { label: "Start a Team trial", href: "/login" }, secondaryCta: { label: "Talk to sales", href: "/contact?interest=demo" },
    proof: ["3–50 users", "Roles and approvals", "21-day trial"],
    features: [
      { icon: "Users", title: "Shared vaults with roles", body: "Owner, manager, editor and viewer roles on every shared vault." },
      { icon: "Share2", title: "Access Capsules", body: "Share one item for a purpose, with expiry, one-time use and fill-only mode." },
      { icon: "Waypoints", title: "Approvals", body: "Members request time-boxed access; managers approve with a clear trail." },
      { icon: "Send", title: "Secure Send", body: "Send credentials to clients and contractors with self-destructing links." },
    ],
    faq: [["When should we choose Business instead?", "When you need departments, delegated admins, enforced policies, access reviews and lifecycle controls."]],
    related: ["password-manager", "secure-send"],
    metaTitle: "Passkey-X for teams", metaDescription: "Encrypted shared vaults, roles and approvals for small teams.",
  },
  {
    slug: "business", name: "Business", navLabel: "Business", icon: "Building2",
    navBlurb: "Departments, policies, audit and lifecycle.",
    kicker: "For business", title: "One vault platform", titleAccent: "for every department.",
    intro: "Business adds everything IT needs to run password security across the company: departments, delegated admins, enforced policies, access reviews, lifecycle and a tamper-evident audit trail.",
    primaryCta: { label: "Book a demo", href: "/contact?interest=demo" }, secondaryCta: { label: "Start a Business trial", href: "/login" },
    proof: ["5–500 users", "Admin Console", "Hash-chained audit"],
    features: [
      { icon: "LayoutDashboard", title: "Admin Console", body: "Health, risk, coverage and a one-click security baseline." },
      { icon: "SlidersHorizontal", title: "Enforced policies", body: "Ten policy types enforced by the database and every client." },
      { icon: "FolderLock", title: "Access reviews", body: "Quarterly certification with just-in-time expiry and evidence export." },
      { icon: "UserX", title: "Joiner / mover / leaver", body: "Offboard in seconds with key revocation and rotation flags." },
    ],
    faq: [["Is there an onboarding service?", "Yes — we help plan migration, baseline policies and rollout for every department."]],
    related: ["admin-console", "passkeys"],
    metaTitle: "Passkey-X for business", metaDescription: "Password security for multi-department organizations: policies, audit, access reviews and lifecycle.",
  },
  {
    slug: "msp", name: "MSPs", navLabel: "MSPs & IT partners", icon: "BriefcaseBusiness",
    navBlurb: "Manage client credentials with isolation.",
    kicker: "For MSPs and IT partners", title: "Every client isolated.", titleAccent: "Every action audited.",
    intro: "Keep each client’s credentials in its own encrypted workspace, give technicians time-boxed access, and hand clients a verifiable audit trail.",
    primaryCta: { label: "Become a partner", href: "/contact?interest=partnership" }, secondaryCta: { label: "See Enterprise", href: "/enterprise" },
    proof: ["Per-client key isolation", "Time-boxed Missions", "Audit export"],
    features: [
      { icon: "FolderLock", title: "Client workspaces", body: "Separate keys per client, so one client’s data is never exposed to another." },
      { icon: "Waypoints", title: "Technician Missions", body: "Open exactly the credentials a ticket needs, for as long as it takes." },
      { icon: "FileClock", title: "Client-ready evidence", body: "Export a hash-chained record of every access for each client." },
      { icon: "Send", title: "Secure handover", body: "Send credentials to client staff with burn-after-reading links." },
    ],
    faq: [["Do you offer partner pricing?", "Yes. Contact us about multi-tenant and reseller terms."]],
    related: ["admin-console", "secrets-manager"],
    metaTitle: "Passkey-X for MSPs", metaDescription: "Isolated client workspaces, technician Missions and client-ready audit evidence for MSPs.",
  },
];

export function findProduct(slug: string) { return PRODUCTS.find((entry) => entry.slug === slug); }
export function findSolution(slug: string) { return SOLUTIONS.find((entry) => entry.slug === slug); }
