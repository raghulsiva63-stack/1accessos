# Passkey-X desktop shell

This Tauri 2 shell packages the same static Next.js client as the hosted web app.
It does not add a privileged secret API: vault cryptography remains inside the
webview, and the CSP permits network connections only to the development
Supabase project.

Platform signing identities and store/notarization credentials are deliberately
not committed. Release builds must be signed by Vlightsoft in the hosting/release
environment.
