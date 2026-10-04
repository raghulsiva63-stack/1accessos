//! Per-computer desktop preferences (no secrets), stored as JSON in the app config folder.

use crate::managed::Policy;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Settings {
    /// Lock whenever the window loses focus (switching apps).
    pub lock_on_blur: bool,
    /// Lock whenever the window is hidden (read by the web app's idle watcher).
    pub lock_on_hide: bool,
    /// Global quick-access shortcut.
    pub hotkey_enabled: bool,
    /// Seconds before a copied secret is wiped from the clipboard.
    pub clipboard_seconds: u64,
    /// Start Passkey-X (hidden in the tray) when you sign in to the computer.
    pub auto_start: bool,
    /// Keep an encrypted copy of the vault on this computer for use without internet.
    pub offline_access: bool,
    /// Let the Passkey-X browser extension pair with this app and unlock from it.
    pub browser_integration: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            lock_on_blur: false,
            lock_on_hide: false,
            hotkey_enabled: true,
            clipboard_seconds: 30,
            auto_start: false,
            offline_access: true,
            browser_integration: false,
        }
    }
}

impl Settings {
    /// Keeps values inside safe bounds whatever the file or the page sends.
    pub fn sanitized(mut self) -> Self {
        self.clipboard_seconds = self.clipboard_seconds.clamp(10, 120);
        self
    }

    /// Applies the organization's policy: enforced values replace the person's choices.
    pub fn enforced(mut self, policy: &Policy) -> Self {
        if let Some(value) = policy.lock_on_blur { self.lock_on_blur = value; }
        if let Some(value) = policy.lock_on_hide { self.lock_on_hide = value; }
        if let Some(value) = policy.hotkey_enabled { self.hotkey_enabled = value; }
        if let Some(max) = policy.max_clipboard_seconds { self.clipboard_seconds = self.clipboard_seconds.min(max); }
        if let Some(value) = policy.auto_start { self.auto_start = value; }
        if let Some(value) = policy.offline_access { self.offline_access = value; }
        if let Some(value) = policy.browser_integration { self.browser_integration = value; }
        self
    }
}

pub struct SettingsStore {
    path: Option<PathBuf>,
    current: Mutex<Settings>,
    policy: Policy,
}

impl SettingsStore {
    pub fn load(path: Option<PathBuf>, policy: Policy) -> Self {
        let current = path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|bytes| serde_json::from_slice::<Settings>(&bytes).ok())
            .unwrap_or_default()
            .sanitized();
        Self { path, current: Mutex::new(current), policy }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The settings in effect: the person's choices with the organization's policy applied.
    pub fn get(&self) -> Settings {
        self.current.lock().map(|s| s.clone()).unwrap_or_default().enforced(&self.policy)
    }

    pub fn set(&self, next: Settings) -> Result<Settings, String> {
        let next = next.sanitized().enforced(&self.policy);
        if let Some(path) = &self.path {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|_| "settings_unavailable".to_string())?;
            }
            let bytes = serde_json::to_vec_pretty(&next).map_err(|_| "settings_unavailable".to_string())?;
            std::fs::write(path, bytes).map_err(|_| "settings_unavailable".to_string())?;
        }
        if let Ok(mut current) = self.current.lock() {
            *current = next.clone();
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_time_is_bounded_and_missing_fields_default() {
        let parsed: Settings = serde_json::from_str(r#"{"clipboardSeconds": 5000}"#).unwrap();
        let parsed = parsed.sanitized();
        assert_eq!(parsed.clipboard_seconds, 120);
        assert!(parsed.hotkey_enabled);
        assert!(!parsed.lock_on_blur);
        assert_eq!(Settings { clipboard_seconds: 1, ..Settings::default() }.sanitized().clipboard_seconds, 10);
    }

    #[test]
    fn settings_round_trip_to_disk() {
        let dir = std::env::temp_dir().join(format!("px-settings-{}", std::process::id()));
        let path = dir.join("settings.json");
        let store = SettingsStore::load(Some(path.clone()), Policy::default());
        store.set(Settings { lock_on_blur: true, ..Settings::default() }).unwrap();
        assert!(SettingsStore::load(Some(path), Policy::default()).get().lock_on_blur);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn policy_overrides_personal_choices() {
        let policy = Policy { lock_on_blur: Some(true), hotkey_enabled: Some(false), max_clipboard_seconds: Some(15),
            browser_integration: Some(false), ..Policy::default() };
        let store = SettingsStore::load(None, policy);
        let saved = store.set(Settings { lock_on_blur: false, hotkey_enabled: true, clipboard_seconds: 90, browser_integration: true, ..Settings::default() }).unwrap();
        assert!(saved.lock_on_blur);
        assert!(!saved.hotkey_enabled);
        assert_eq!(saved.clipboard_seconds, 15);
        assert!(!saved.browser_integration);
        assert_eq!(store.get(), saved);
    }
}
