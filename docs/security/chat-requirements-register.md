# Chat requirements carried into v2.2 implementation

Date: 2026-09-05. This register preserves recoverable decisions; it does not claim every unseen message was retrieved. The personal-context lookup returned no additional old-chat content. The resubmitted ZIP exactly matches the original, so it does not independently add newer requirements.

| Requirement / decision | Recoverable evidence | Implementation treatment |
|---|---|---|
| Passkey-X by Vlightsoft branding | ADR-0005 | Preserve public branding and legacy cryptographic namespace compatibility |
| passkey-x.com domain and passwordless account sign-in | ADR-0007 and prior deployment checkpoint | Preserve RP/origin boundaries and separate vault unlock; real-device ceremony still needs evidence |
| Supabase authentication and tenant isolation | ADR-0002/0003/0009 | Continue development in 1accessos-dev; keep production separately configured |
| Optional mobile MFA after primary sign-in | auth-communications.md and visible prior chat | No required phone field at signup; Supabase owns OTP; SMS cannot decrypt/reset vault or replace recovery |
| Sent runtime credential supplied for integration | Current user instruction | Server-only development Edge secret; no values in repository; sandbox until validation |
| Branded email noreply@passkey-x.com | Prior chat and auth-communications.md | Verify SMTP delivery/DNS; configuration reports alone are not delivery evidence |
| Team versus Business office flows | ADR-0009 and public-site checkpoint | Small workgroup versus multi-department organization; scoped admin and policy controls |
| Versioned catalog, INR/USD, monthly/annual, seven suites | Commercial-experience checkpoint and v2.2 addendum | Server-authoritative immutable catalog; paid checkout requires approved provider mappings |
| GitHub sign-in for Supabase setup | Explicit authorization in current conversation | Secure credential form only; authorization is separate from actual signed-in browser state |
| Complete Phase 0–5; plan Phase 6 | Repeated current instruction | Use revised Appendix G/H; track independent reviews and pilots honestly |
| Netlify deployment | Earlier continuation deferred deploy; later dedicated deployment succeeded at 9811651 | Historical deferral does not erase later deploy; newer development source is not automatically live |

## Requirement conflicts and remaining validation

- ADR-0008's initial flat-rate subset predates the seven-suite seat-based catalog. Reconcile effective billing behavior with the immutable catalog and user-approved prices before activation; do not silently change active subscription billing.
- §20 and Appendix G use different phase numbering. ADR-0010 records the revised ordering and preserves stricter security gates.
- Additional requirements not present in the attached specification, visible chat or existing ADRs remain unverified. Do not invent them or mark them implemented.
