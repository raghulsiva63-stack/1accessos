// Declares the app's native commands so each one needs an explicit permission
// (see capabilities/desktop.json). Commands not listed there cannot be invoked.
const COMMANDS: &[&str] = &[
    "desktop_info", "desktop_settings_get", "desktop_settings_set",
    "secure_get", "secure_set", "secure_remove",
    "clipboard_copy", "clipboard_clear", "quick_hide", "sign_in_listen", "update_check",
    "biometric_enrolled", "biometric_enroll", "biometric_unlock", "biometric_remove",
    "desktop_policy", "browser_link_send",
    "endpoint_inventory", "endpoint_posture", "endpoint_browsers", "guard_alert", "alert_dismiss", "alert_open_main",
    "auto_type_info", "auto_type_present", "auto_type_perform",
    "ssh_agent_load", "ssh_agent_status", "ssh_agent_reply", "ssh_agent_forget", "ssh_key_generate", "ssh_key_inspect",
    "cli_reply", "cli_info", "cli_install_path",
    "downloads_recent", "download_quarantine", "reveal_path", "presentation_check",
    "sprawl_scan", "sprawl_extract", "sprawl_read_export", "sprawl_trash",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS)),
    )
    .expect("failed to run tauri build script");
}
