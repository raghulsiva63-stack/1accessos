/**
 * Customer-facing legal text for the public site. Keep statements factual and in line with how
 * Passkey-X actually works (client-side encryption, Stripe billing, Supabase and Netlify hosting).
 * Changes here change the published policies, so bump LEGAL_UPDATED when editing.
 */

export const LEGAL_ENTITY = "Vlightsoft Pvt Ltd";
export const LEGAL_CONTACT = "support@vlightsoft.com";
export const LEGAL_UPDATED = "29 September 2026";

export type LegalSection = { heading: string; paragraphs?: string[]; bullets?: string[] };
export type LegalDocument = { slug: "privacy" | "terms" | "refunds"; title: string; summary: string; sections: LegalSection[] };

export const PRIVACY: LegalDocument = {
  slug: "privacy",
  title: "Privacy Policy",
  summary: "What we collect, why, who helps us run the service, and the choices you have. Your vault contents are encrypted on your device and we cannot read them.",
  sections: [
    {
      heading: "Who we are",
      paragraphs: [
        `Passkey-X is operated by ${LEGAL_ENTITY} ("Vlightsoft", "we", "us"). This policy covers passkey-x.com, the Passkey-X web app, desktop and mobile apps, browser extension and API.`,
        `For privacy questions or requests, write to ${LEGAL_CONTACT}.`,
      ],
    },
    {
      heading: "The short version",
      bullets: [
        "Your vault items (passwords, notes, cards, files and similar) are encrypted on your device before they are sent to us. We store only encrypted data and cannot decrypt it.",
        "Your vault password and recovery key never leave your device. We cannot reset them or recover your vault for you.",
        "We do not sell personal data, show ads, or use third-party tracking or advertising cookies.",
        "We collect the account, billing and security information needed to run the service, and nothing more.",
      ],
    },
    {
      heading: "Information we collect",
      bullets: [
        "Account details: your email address, login password (stored only as a secure hash by our authentication provider), sign-in methods such as passkeys, authenticator apps or a mobile number you choose to add.",
        "Encrypted vault data: encrypted items, attachments, workspace keys and device public keys. These are unreadable to us.",
        "Workspace and organisation information: workspace and organisation membership, roles, invitations, policies and audit events. Workspace names and many labels are encrypted on your device.",
        "Billing information: plan, subscription status, seat count and invoices. Card details are collected and stored by Stripe, not by us.",
        "Security and usage information: IP address, device and browser type, sign-in times, and security logs used to protect accounts, prevent abuse and troubleshoot problems.",
        "Messages you send us, such as support or sales requests.",
      ],
    },
    {
      heading: "How we use information",
      bullets: [
        "To create and secure your account, sync your encrypted vault and provide the features you use.",
        "To process payments, manage subscriptions and send receipts and service emails (for example sign-in, verification and security alerts).",
        "To detect and prevent fraud, abuse and security incidents, including automated bot checks at sign-in.",
        "To provide support and respond to your requests.",
        "To meet legal, tax and accounting obligations.",
      ],
      paragraphs: ["We process personal data to perform our contract with you, to comply with law, for our legitimate interest in keeping the service secure, and with your consent where the law requires it."],
    },
    {
      heading: "Optional AI features",
      paragraphs: ["Some Business features offer AI-generated security advice. Only aggregate counts (for example the number of members or unreviewed apps) are sent to the AI provider. Vault contents, passwords, names and email addresses are never sent. These features are off unless your organisation uses them."],
    },
    {
      heading: "Service providers",
      paragraphs: ["We use trusted providers who process data on our behalf under contract:"],
      bullets: [
        "Supabase — database, authentication, file storage and server functions (data is currently hosted in Tokyo, Japan).",
        "Netlify — website and app hosting and content delivery.",
        "Stripe — payments, subscriptions and invoices.",
        "Cloudflare Turnstile — bot protection on sign-in and sign-up forms.",
        "Email and SMS delivery providers — to send verification codes and service messages.",
        "An AI model provider — only for the optional aggregate-only AI features described above.",
      ],
    },
    {
      heading: "International transfers",
      paragraphs: ["Our providers may process data outside your country, including in Japan, the United States and other locations. We rely on contractual and technical safeguards, and your vault contents remain end-to-end encrypted wherever they are stored."],
    },
    {
      heading: "How long we keep data",
      bullets: [
        "Account and vault data: until you delete your account or remove the data.",
        "When you delete your account, your personal vault, devices, keys and encrypted files are erased. Any subscription for a workspace you own alone is cancelled.",
        "Organisation audit records may be kept for the period the organisation's plan or legal obligations require.",
        "Billing records: as long as tax and accounting laws require.",
        "Security logs: for a limited period, normally no longer than 12 months.",
      ],
    },
    {
      heading: "Your rights and choices",
      paragraphs: [
        "Depending on where you live (including under India's Digital Personal Data Protection Act, 2023 and the EU/UK GDPR), you may have the right to access, correct, export or erase your personal data, to withdraw consent, and to raise a grievance or complaint.",
        `You can export your vault and delete your account at any time from Settings. For any other request, email ${LEGAL_CONTACT}; we respond within 30 days. If your account belongs to an organisation, some requests may be handled together with that organisation.`,
      ],
    },
    {
      heading: "Security",
      paragraphs: ["We use client-side Argon2id and AES-256-GCM encryption, row-level access controls, optional two-step verification and passkeys, and a tamper-evident audit trail. No system is perfectly secure; please use a strong, unique vault password and keep your recovery key offline. Report vulnerabilities through our contact page."],
    },
    {
      heading: "Children",
      paragraphs: ["Passkey-X is not intended for children under 18 without the involvement of a parent or guardian, for example through a Family plan managed by an adult."],
    },
    {
      heading: "Changes to this policy",
      paragraphs: ["We will post any changes on this page and update the date above. If a change materially affects how we use your data, we will tell you by email or in the app before it takes effect."],
    },
    {
      heading: "Contact and grievance officer",
      paragraphs: [`${LEGAL_ENTITY}, Grievance Officer — ${LEGAL_CONTACT}. We aim to acknowledge grievances within 48 hours and resolve them within 30 days.`],
    },
  ],
};

export const TERMS: LegalDocument = {
  slug: "terms",
  title: "Terms of Service",
  summary: "The agreement between you and Vlightsoft for using Passkey-X.",
  sections: [
    {
      heading: "Agreement",
      paragraphs: [
        `These terms are an agreement between you and ${LEGAL_ENTITY} ("Vlightsoft", "we", "us") for the use of Passkey-X, including the website, apps, browser extension and API (the "Service"). By creating an account or using the Service you accept these terms and our Privacy Policy.`,
        "If you use the Service on behalf of a company or other organisation, you confirm you are authorised to accept these terms for it, and \"you\" includes that organisation.",
      ],
    },
    {
      heading: "Your account",
      bullets: [
        "You must be at least 18, or use the Service under the supervision of a parent or guardian.",
        "Give accurate information and keep your email address up to date.",
        "You are responsible for activity under your account and for keeping your login password, vault password, recovery key and devices safe.",
        "Tell us promptly at our support address if you believe your account has been compromised.",
      ],
    },
    {
      heading: "Your vault password and recovery key",
      paragraphs: ["Passkey-X is built so that we cannot read your vault. We cannot see, reset or recover your vault password or recovery key. If you lose both (and your organisation has not enabled organisation recovery for you), your encrypted data cannot be recovered. You accept this as part of the Service's security design."],
    },
    {
      heading: "Plans, trials and payment",
      bullets: [
        "Some features require a paid plan. Current plans and prices are shown on our pricing page and in the app, in INR or USD.",
        "Paid plans renew automatically each month or year until cancelled. Per-seat plans are charged for the number of seats you choose.",
        "Free trials convert to a paid subscription at the end of the trial unless you cancel before it ends.",
        "Payments are processed by Stripe. Prices may exclude applicable taxes, which are added where required.",
        "We may change prices with at least 30 days' notice. Changes apply from your next renewal.",
        "If a payment fails we may limit paid features until the balance is paid; your encrypted data is not deleted because of a failed payment.",
      ],
    },
    {
      heading: "Cancellation and refunds",
      paragraphs: ["You can cancel at any time from Plans & billing → Manage billing. Refunds are covered by our Refund & Cancellation Policy, which forms part of these terms."],
    },
    {
      heading: "Organisations and administrators",
      paragraphs: ["If you join a workspace or organisation, its owners and administrators can manage your membership, roles and policies, see audit records for that organisation, and, only if the organisation has enabled it and you have enrolled, help you regain access to your vault. They cannot read vault items that are not shared with them."],
    },
    {
      heading: "Acceptable use",
      paragraphs: ["You agree not to:"],
      bullets: [
        "use the Service for anything unlawful, or to store or share content you have no right to;",
        "attempt to break, probe or overload the Service, or bypass its security or usage limits (responsible security research reported to us is welcome);",
        "access another person's account or data without permission;",
        "resell or provide the Service to third parties except as a plan allows (for example an MSP plan);",
        "reverse engineer the Service except where the law allows it.",
      ],
    },
    {
      heading: "Your content",
      paragraphs: ["You keep all rights to the data you store. You give us only the permission needed to host, encrypt, sync and back up that data to provide the Service. Because vault data is encrypted on your device, we do not access its contents."],
    },
    {
      heading: "Service changes and availability",
      paragraphs: ["We work to keep the Service available and secure but do not guarantee it will be uninterrupted or error-free. We may add, change or remove features; if we remove a material paid feature, we will give reasonable notice and, where appropriate, a pro-rata refund. Keep your own encrypted export of important data."],
    },
    {
      heading: "Suspension and termination",
      paragraphs: ["You may stop using the Service and delete your account at any time. We may suspend or end access if you seriously or repeatedly breach these terms, if required by law, or to protect the Service or other users. Where reasonable we will give notice and a chance to export your data first."],
    },
    {
      heading: "Disclaimers and limitation of liability",
      paragraphs: [
        "To the extent permitted by law, the Service is provided \"as is\" and we disclaim implied warranties such as merchantability and fitness for a particular purpose.",
        "To the extent permitted by law, we are not liable for indirect, incidental, special or consequential losses, or for loss of data caused by a lost vault password or recovery key. Our total liability for any claim relating to the Service is limited to the amount you paid us in the 12 months before the claim.",
        "Nothing in these terms limits liability that cannot be limited by law, or your statutory rights as a consumer.",
      ],
    },
    {
      heading: "Governing law and disputes",
      paragraphs: ["These terms are governed by the laws of India. Please contact us first so we can try to resolve any issue informally. If a dispute cannot be resolved within 30 days, it will be subject to the jurisdiction of the competent courts in India, without affecting any mandatory consumer rights you have where you live."],
    },
    {
      heading: "Changes to these terms",
      paragraphs: ["We may update these terms. We will post changes on this page and update the date above; for material changes we will notify you by email or in the app at least 15 days before they take effect. Continuing to use the Service after that means you accept the updated terms."],
    },
    {
      heading: "Contact",
      paragraphs: [`${LEGAL_ENTITY} — ${LEGAL_CONTACT}.`],
    },
  ],
};

export const REFUNDS: LegalDocument = {
  slug: "refunds",
  title: "Refund & Cancellation Policy",
  summary: "Cancel any time. If you are not happy, ask for a full refund within 30 days of your first payment.",
  sections: [
    {
      heading: "30-day money-back guarantee",
      paragraphs: [
        "If you are not satisfied, you can ask for a full refund of your first payment for a plan within 30 days of that payment. This applies to both monthly and yearly plans.",
        "Renewal payments are refundable if you request a refund within 30 days of a renewal and have not used the paid features since that renewal, or where the law requires it.",
      ],
    },
    {
      heading: "How to cancel",
      bullets: [
        "Open Passkey-X → Plans & billing → Manage billing, then choose Cancel plan. Only workspace owners and admins can do this.",
        "After cancelling, your paid features stay active until the end of the period you have already paid for. You will not be charged again.",
        "Cancelling during a free trial means you are never charged.",
        "Deleting your account also cancels subscriptions for workspaces you own alone.",
      ],
    },
    {
      heading: "How to request a refund",
      bullets: [
        `Email ${LEGAL_CONTACT} from your account email with the workspace name and the payment date (an invoice number helps).`,
        "We confirm your request within 2 business days.",
        "Approved refunds go back to the original payment method through Stripe. Banks usually show them within 5–10 business days.",
      ],
    },
    {
      heading: "Seat changes and upgrades",
      paragraphs: ["When you change seats or plans mid-period, Stripe works out a pro-rated charge or credit for the rest of the period and shows it before you confirm. Credits are applied to your next invoices rather than paid out, unless the payment is within the 30-day guarantee."],
    },
    {
      heading: "What happens to your data",
      paragraphs: ["Cancelling or getting a refund does not delete your encrypted vault. Your workspace moves to the Free plan's limits at the end of the paid period, and you can export or delete your data at any time."],
    },
    {
      heading: "Exceptions",
      paragraphs: ["We may refuse refunds where there is clear evidence of fraud or abuse of this policy (for example repeated purchase-and-refund cycles). Enterprise contracts follow the terms in the signed agreement."],
    },
    {
      heading: "Contact",
      paragraphs: [`${LEGAL_ENTITY} — ${LEGAL_CONTACT}.`],
    },
  ],
};

export const LEGAL_DOCUMENTS = [PRIVACY, TERMS, REFUNDS];
