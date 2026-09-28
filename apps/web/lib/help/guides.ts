/**
 * Plain-language guides shared by the in-app Help Center, the public /help page
 * and the printable user guide. Keep steps short and name the exact screen.
 */

export type HelpView =
  | "home" | "vault" | "workspaces" | "admin" | "organization" | "send" | "security" | "emergency"
  | "account-security" | "generator" | "devices" | "billing" | "settings";

export type Guide = {
  id: string;
  category: "start" | "protect" | "share" | "business" | "billing" | "account";
  title: string;
  summary: string;
  /** Screen in the app where this happens; the in-app Help Center links there. */
  opens?: { view: HelpView; label: string };
  steps: string[];
  tips?: string[];
};

export const HELP_CATEGORIES: { id: Guide["category"]; title: string; blurb: string }[] = [
  { id: "start", title: "Getting started", blurb: "Create your vault and save your first passwords." },
  { id: "protect", title: "Protect your account", blurb: "Sign-in security, recovery and security checks." },
  { id: "share", title: "Share safely", blurb: "Shared vaults, one-time links and emergency access." },
  { id: "business", title: "For teams and companies", blurb: "Organisations, members, roles and admin tools." },
  { id: "billing", title: "Plans and billing", blurb: "Choose, change or cancel a plan." },
  { id: "account", title: "Your account", blurb: "Devices, exports and deleting your account." },
];

export const GUIDES: Guide[] = [
  {
    id: "get-started",
    category: "start",
    title: "Get started in 5 minutes",
    summary: "Create your account, set your vault password and save your recovery key.",
    opens: { view: "home", label: "Open Home" },
    steps: [
      "Go to passkey-x.com and choose Start free. Enter your email and a login password, then confirm your email from the message we send you.",
      "Sign in. You are asked to create a vault password. This is different from your login password: it encrypts your vault on your device and we never receive it.",
      "Save your recovery key. Choose Download recovery key and keep the file somewhere safe and offline (for example a USB stick or a printed copy in a drawer).",
      "Confirm you saved it. Your vault opens and the Getting started checklist on Home shows what to do next.",
    ],
    tips: [
      "Use a long vault password you can remember, such as four or five random words.",
      "Nobody, including Passkey-X, can reset your vault password. The recovery key is your backup.",
    ],
  },
  {
    id: "add-items",
    category: "start",
    title: "Add passwords, cards and notes",
    summary: "Save anything you need to keep private: logins, cards, Wi-Fi, notes and more.",
    opens: { view: "vault", label: "Open Vault" },
    steps: [
      "Open Vault and choose Add secure item (or press the + button on Home).",
      "Pick the type: Login, Payment card, Secure note, Wi-Fi, API key and others.",
      "Fill in the fields. Use the generator button next to the password field for a strong password.",
      "Choose Save. The item is encrypted on your device before it is stored.",
    ],
    tips: ["Mark items you use often as favourites so they appear at the top."],
  },
  {
    id: "import",
    category: "start",
    title: "Import from another password manager",
    summary: "Bring your passwords over from 1Password, Bitwarden, LastPass, Dashlane or your browser.",
    opens: { view: "settings", label: "Open Settings" },
    steps: [
      "In your old password manager or browser, export your passwords as a CSV or JSON file.",
      "In Passkey-X open Settings and find Import.",
      "Choose the file. Passkey-X shows how many items it found before anything is saved.",
      "Confirm the import, then delete the exported file from your computer: it is not encrypted.",
    ],
  },
  {
    id: "apps",
    category: "start",
    title: "Install the apps and browser extension",
    summary: "Fill passwords in your browser and use Passkey-X on your phone and computer.",
    steps: [
      "Open passkey-x.com/download.",
      "Install the browser extension, the desktop app or the mobile app you need.",
      "Sign in with the same email, then unlock with your vault password.",
    ],
    tips: ["Free accounts can use 2 devices at a time. Paid plans have unlimited devices."],
  },
  {
    id: "two-step",
    category: "protect",
    title: "Turn on two-step verification or a passkey",
    summary: "Stop anyone who learns your login password from signing in.",
    opens: { view: "account-security", label: "Open Account security" },
    steps: [
      "Open Account security.",
      "Choose Add passkey to sign in with your fingerprint, face or device PIN, or choose Set up authenticator app (such as Google Authenticator or Microsoft Authenticator).",
      "For an authenticator app, scan the QR code and type the 6-digit code to confirm.",
      "Next time you sign in, Passkey-X asks for the passkey or the code.",
    ],
    tips: ["Two-step verification protects your account sign-in. Your vault password still protects the vault itself."],
  },
  {
    id: "forgot",
    category: "protect",
    title: "Forgot your vault password",
    summary: "Unlock with your recovery key, or ask your organisation for help.",
    steps: [
      "On the Unlock screen choose Use recovery key.",
      "Open the recovery key file you downloaded during setup and paste the key.",
      "Choose a new vault password. Your items stay exactly as they were.",
      "If your company turned on organisation recovery, choose Ask my organization for help instead. An administrator verifies it is you and gives you a one-time code.",
    ],
    tips: ["Forgot your login password (the one you sign in with)? Choose Forgot login password? on the sign-in screen to get a reset email."],
  },
  {
    id: "security-check",
    category: "protect",
    title: "Run a security check",
    summary: "Find weak, reused and breached passwords and fix the most important first.",
    opens: { view: "security", label: "Open Security" },
    steps: [
      "Open Security. Checks run on your device; your passwords are never sent anywhere.",
      "Start with anything marked breached or reused.",
      "Open the item, choose Edit and generate a new password (or choose Rotate when it is shown), save, then change the password on that website too.",
    ],
  },
  {
    id: "share-vault",
    category: "share",
    title: "Share a vault with family or colleagues",
    summary: "Create a shared vault and invite people with the right level of access.",
    opens: { view: "workspaces", label: "Open Workspaces" },
    steps: [
      "Open Workspaces and use Create a workspace. Give it a name and choose who it is for.",
      "Switch to the new workspace, then use Invite a verified member.",
      "Enter their email and choose a role: Manager (can invite others), Member/editor (can add and edit items) or Guest/viewer (read only).",
      "Copy the invitation link and send it to them yourself, for example by message. They open it, sign in with that email and accept.",
      "To remove someone, choose Revoke next to their name. Change any passwords they could see.",
    ],
    tips: ["The invitation link contains a one-time secret. Send it only to the person it is for."],
  },
  {
    id: "secure-send",
    category: "share",
    title: "Send a password once with Secure Send",
    summary: "Share a secret with someone who does not use Passkey-X. The link expires on its own.",
    opens: { view: "send", label: "Open Secure Send" },
    steps: [
      "Open Secure Send and type or paste the secret.",
      "Choose how many times it can be opened and when it expires. Add a passphrase for extra protection.",
      "Copy the link and send it. Send the passphrase through a different channel.",
    ],
  },
  {
    id: "emergency",
    category: "share",
    title: "Set up emergency access",
    summary: "Let someone you trust open your vault if something happens to you.",
    opens: { view: "emergency", label: "Open Emergency access" },
    steps: [
      "Open Emergency access and add a contact with their email.",
      "Choose a waiting period (for example 3 days) and how long access lasts.",
      "Send them the invitation link. They accept it with their own Passkey-X account.",
      "If they ever request access, you are alerted and can deny it during the waiting period. If you do not respond, access opens read-only.",
    ],
  },
  {
    id: "create-organisation",
    category: "business",
    title: "Set up Passkey-X for your company",
    summary: "Create an organisation, choose Team or Business and invite your people.",
    opens: { view: "billing", label: "Open Plans & billing" },
    steps: [
      "Open Plans & billing and choose Change plan.",
      "Choose My team or company, then pick Team (3 to 50 people) or Business (5 to 500 people).",
      "When asked where the plan should go, choose Create a new organisation and give it your company name. Passkey-X creates it for you.",
      "Choose how many people need a seat and continue to secure checkout.",
      "After payment, open Admin console to invite people, set policies and see the audit log.",
    ],
    tips: [
      "Team and Business apply to an organisation, not to your personal vault. Your personal vault stays private even inside a company.",
      "Administrators can manage access and policies but can never read anyone's passwords.",
    ],
  },
  {
    id: "invite-team",
    category: "business",
    title: "Invite people to your organisation",
    summary: "Add employees to your organisation and give them access to shared vaults.",
    opens: { view: "admin", label: "Open Admin console" },
    steps: [
      "Switch to your organisation with the workspace picker at the top of the screen.",
      "Open Admin console, then People, and choose Invite people. Or open Workspaces to invite someone to one specific shared vault.",
      "Each person signs in or creates a free account with that email and accepts.",
      "Using Microsoft Entra ID, Okta or Google? Admin console > Identity & SSO lets you add people automatically (Business plan).",
    ],
  },
  {
    id: "admin-console",
    category: "business",
    title: "Use the Admin console",
    summary: "Policies, alerts, access reviews, reports and the audit log.",
    opens: { view: "admin", label: "Open Admin console" },
    steps: [
      "Overview shows members, open alerts and which policies are on.",
      "Policies lets you require two-step verification, set a minimum vault password, control sharing and exports, and more.",
      "Alerts lists unusual activity such as break-glass requests or many failed actions.",
      "Access review and Reports help you prove who can access what (Business plan).",
      "Audit log keeps a tamper-evident record of every change. You can export it.",
    ],
  },
  {
    id: "choose-plan",
    category: "billing",
    title: "Choose or change your plan",
    summary: "Pick who the plan is for, choose a plan and pay securely with Stripe.",
    opens: { view: "billing", label: "Open Plans & billing" },
    steps: [
      "Open Plans & billing and choose Change plan.",
      "Answer who it is for: Just me, My family or My team or company.",
      "Pick a plan. Switch between monthly and yearly, and between INR and USD, to compare prices.",
      "Confirm where the plan applies. For family and company plans Passkey-X can create the family vault or organisation for you.",
      "Review the summary and choose Continue to secure checkout. You pay on Stripe's secure page; Passkey-X never sees your card.",
      "When you come back, the plan activates within a minute. You see a confirmation on screen.",
    ],
    tips: [
      "Each plan belongs to one vault or organisation. Personal and Professional apply to your personal vault, Family to a family vault, Team and Business to an organisation.",
      "Only an owner or admin can change a plan.",
    ],
  },
  {
    id: "manage-billing",
    category: "billing",
    title: "Update your card, change seats or cancel",
    summary: "Manage an existing subscription in the Stripe billing portal.",
    opens: { view: "billing", label: "Open Plans & billing" },
    steps: [
      "Switch to the vault or organisation that has the subscription.",
      "Open Plans & billing and choose Manage billing.",
      "In the secure Stripe portal you can update your card, download invoices, change the number of seats or cancel.",
      "Changes appear in Passkey-X within a minute. If you cancel, paid features stay on until the end of the period you paid for.",
    ],
  },
  {
    id: "devices",
    category: "account",
    title: "See and remove your devices",
    summary: "Check where you are signed in and remove lost devices.",
    opens: { view: "devices", label: "Open Devices" },
    steps: [
      "Open Devices to see every device that can unlock your vault.",
      "Choose Revoke on any device you no longer use or have lost.",
    ],
  },
  {
    id: "export",
    category: "account",
    title: "Back up or export your vault",
    summary: "Download an encrypted backup of everything in your vault.",
    opens: { view: "settings", label: "Open Settings" },
    steps: [
      "Open Settings and find Encrypted backup.",
      "Choose Export. The file is encrypted with your vault password.",
      "Keep the file somewhere safe. Your organisation may limit exports by policy.",
    ],
  },
  {
    id: "delete-account",
    category: "account",
    title: "Delete your account",
    summary: "Permanently remove your account and everything in your personal vault.",
    opens: { view: "settings", label: "Open Settings" },
    steps: [
      "If you own an organisation or shared vault with other members, make someone else an owner first.",
      "Open Settings and choose Review account deletion.",
      "Enter your login password, the code from your authenticator app if you use one, and type DELETE MY ACCOUNT.",
      "Deletion is permanent and cannot be undone.",
    ],
  },
];

export const FAQ: [string, string][] = [
  ["What is the difference between my login password and my vault password?", "Your login password signs you in to your account. Your vault password unlocks and encrypts your vault on your device. We never receive your vault password, so we cannot reset it."],
  ["Can Passkey-X or my company admin see my passwords?", "No. Everything is encrypted on your device. Admins can manage who has access to shared vaults, but they cannot read anyone's items."],
  ["Why did checkout say the plan is for a different kind of workspace?", "Each plan belongs to one kind of vault: Personal and Professional to your personal vault, Family to a family vault, Team and Business to an organisation. The Change plan steps pick or create the right one for you."],
  ["Who can change the plan?", "The owner of the vault or organisation, or an organisation admin."],
  ["Is there a free trial?", "Paid plans include a trial the first time you subscribe: 14 days for Personal, Family and Professional, 21 days for Team and Business."],
  ["Can I cancel or get a refund?", "Yes. Cancel any time in Plans & billing → Manage billing and keep access until the end of the paid period. If you are not happy, email support@vlightsoft.com within 30 days of your first payment for a full refund. Details: passkey-x.com/refunds."],
  ["How do I get help?", "Use Help & guides in the app, visit passkey-x.com/help, email support@vlightsoft.com, or contact us at passkey-x.com/contact."],
];

export function guidesByCategory(category: Guide["category"]): Guide[] {
  return GUIDES.filter((guide) => guide.category === category);
}
