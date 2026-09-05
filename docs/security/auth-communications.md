# Authentication email and mobile verification boundary

Date: 2026-09-05

## Product decision

Phone number collection is **optional and post-sign-in**. Passkey-X keeps email
plus login password and passkeys as the primary account methods. A verified
mobile number is enrolled from Account security as a Supabase Phone MFA factor.
Users who enroll one complete an SMS challenge after primary sign-in to raise
the session from AAL1 to AAL2.

Passkey-X does not request a phone number during normal signup or normal
email/passkey sign-in. This avoids making a changeable telecom identifier the
account's primary identity and avoids unnecessary onboarding collection.

SMS is account-session verification only. It cannot decrypt vault ciphertext,
reset the vault password, rewrap the account root key, or replace the recovery
key. Email account-password recovery keeps the same separation.

## Supabase and Sent responsibilities

- Supabase Auth generates and verifies the OTP, applies expiration and rate
  limits, owns factor enrollment, and issues the AAL2 session.
- The signed Supabase Send SMS Hook delivers the OTP through Sent using a
  server-only `x-api-key` credential and a pinned `sms` channel.
- Every provider mutation carries a deterministic `Idempotency-Key`.
- The Sent delivery receiver verifies the raw-body HMAC, rejects timestamps
  outside five minutes, supports a two-secret rotation window, and deduplicates
  payloads before changing status.
- Backend-only delivery tables store the Auth hook ID, user ID, provider message
  ID, request ID, status, channel, and timestamps. They store no mobile number,
  OTP, or message body and grant no browser-role access.

The connected ChatGPT Sent plugin proves that the `passkey-x` Sent organization
is accessible, KYC-complete, and has an effective sending balance. Plugin OAuth
is not a runtime credential for the deployed application. The Edge Function
still needs a separate environment-scoped `SENT_DM_API_KEY`; it must never be
pasted into source code or the browser.

The owner reports custom Supabase SMTP with sender
`noreply@passkey-x.com`. This closes configuration work only after a disposable
hosted-user test proves signup confirmation, login-password recovery, and
security-notification delivery, and after SPF/DKIM/DMARC alignment and bounce
monitoring are reviewed.

## Safe activation sequence

1. Deploy `sent-sms-hook` and `sent-webhook` with JWT verification disabled;
   both functions implement their own signed-webhook authentication.
2. Store `SEND_SMS_HOOK_SECRET`, `SENT_DM_API_KEY`,
   `SENT_DM_WEBHOOK_SECRET`, and `SENT_DM_SMS_SANDBOX=true` only as Supabase Edge
   Function secrets.
3. Run a signed sandbox request and the webhook signature negative/replay tests.
4. Register the environment-specific Sent webhook for delivered, failed,
   filtered, and blocked message events; store its one-time signing secret.
5. Configure Supabase Auth's Send SMS Hook URL and matching Standard Webhooks
   secret, then enable Phone MFA enrollment and verification.
6. Change `SENT_DM_SMS_SANDBOX=false`, complete one approved real-device
   enrollment/sign-in/removal ceremony, and confirm `DELIVERED` evidence.
7. Only after that evidence, set `NEXT_PUBLIC_PHONE_MFA_ENABLED=true` in the
   matching web environment.

No test OTP mapping is allowed in production. Phone MFA must be optional for
personal users and may be required only through an explicit Business policy
with tested recovery and administrator-support procedures.

References: [Supabase Send SMS Hook](https://supabase.com/docs/guides/auth/auth-hooks/send-sms-hook),
[Supabase Phone MFA](https://supabase.com/docs/guides/auth/auth-mfa/phone), and
[Supabase custom SMTP](https://supabase.com/docs/guides/auth/auth-smtp).

## Development configuration checkpoint — 2026-09-05 follow-up

- Authenticated dashboard access succeeded through the authorized GitHub sign-in.
- Saved `SENT_DM_API_KEY`, `SENT_DM_SMS_SANDBOX=true`, and `SEND_SMS_HOOK_SECRET` in development Edge Function secrets only.
- Created the matching HTTPS Send SMS hook for the development `sent-sms-hook` endpoint with the hook **disabled**. Phone MFA remains hidden.
- Direct Sent webhook-list validation received HTTP 403 with a gateway/Cloudflare error envelope. This is not proof of provider-key validity or invalidity. Provider webhook registration, its signing secret, sandbox delivery and real-device validation remain pending.
- No SMS was sent. No production secret or deployment was changed in this follow-up.

Roadmap correction: use revised Technical Appendix G/H and ADR-0010; Phase 6 is privileged/runtime planning, and enterprise expansion is Phase 7.
