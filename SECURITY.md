# Security Policy

1accessos is in pre-release security design. Do not use it for real credentials until a production release is explicitly approved.

## Reporting

Report suspected vulnerabilities privately to the repository owner. Do not open a public issue containing exploit details, credentials, keys, personal data, or sensitive logs.

## Never submit

- Login or vault passwords
- Recovery keys
- API tokens
- Supabase secret or service-role keys
- Private encryption or signing keys
- Real customer vault exports

If a secret is shared accidentally, treat it as compromised and rotate it immediately.

## Development data

Use generated synthetic test data only. Tests must verify that plaintext vault values never cross the trusted-client boundary.
