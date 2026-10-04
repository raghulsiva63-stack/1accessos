// Declares the app's native commands so each one needs an explicit permission
// (see capabilities/desktop.json). Commands not listed there cannot be invoked.
const COMMANDS: &[&str] = &[
    "desktop_info", "desktop_settings_get", "desktop_settings_set",
    "secure_get", "secure_set", "secure_remove",
    "clipboard_copy", "clipboard_clear", "quick_hide", "sign_in_listen", "update_check",
    "biometric_enrolled", "biometric_enroll", "biometric_unlock", "biometric_remove",
    "desktop_policy", "browser_link_send",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to run tauri build script");
}
