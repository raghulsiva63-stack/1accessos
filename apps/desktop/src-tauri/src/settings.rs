//! Per-computer desktop preferences (no secrets), stored as JSON in the app config folder.

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
}

impl Default for Settings {
    fn default() -> Self {
        Self { lock_on_blur: false, lock_on_hide: false, hotkey_enabled: true, clipboard_seconds: 30 }
    }
}

impl Settings {
    /// Keeps values inside safe bounds whatever the file or the page sends.
    pub fn sanitized(mut self) -> Self {
        self.clipboard_seconds = self.clipboard_seconds.clamp(10, 120);
        self
    }
}

pub struct SettingsStore {
    path: Option<PathBuf>,
    current: Mutex<Settings>,
}

impl SettingsStore {
    pub fn load(path: Option<PathBuf>) -> Self {
        let current = path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|bytes| serde_json::from_slice::<Settings>(&bytes).ok())
            .unwrap_or_default()
            .sanitized();
        Self { path, current: Mutex::new(current) }
    }

    pub fn get(&self) -> Settings {
        self.current.lock().map(|s| s.clone()).unwrap_or_default()
    }

    pub fn set(&self, next: Settings) -> Result<Settings, String> {
        let next = next.sanitized();
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
        let store = SettingsStore::load(Some(path.clone()));
        store.set(Settings { lock_on_blur: true, ..Settings::default() }).unwrap();
        assert!(SettingsStore::load(Some(path)).get().lock_on_blur);
        let _ = std::fs::remove_dir_all(dir);
    }
}
