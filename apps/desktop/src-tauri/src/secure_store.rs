//! Keeps the account session (Supabase tokens) encrypted on disk.
//!
//! The data file is AES-256-GCM encrypted with a random key held in the operating system's
//! credential store (macOS Keychain, Windows Credential Manager, Linux Secret Service). The
//! vault key is never stored here. If no credential store is available the session is kept in
//! memory only and the person signs in again next time.

use crate::crypto::{self, Sealed};
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use base64::Engine;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use zeroize::Zeroizing;

const SERVICE: &str = "com.vlightsoft.passkeyx";
const KEY_ENTRY: &str = "session-encryption-key";
const AAD: &[u8] = b"passkey-x:desktop-session:v1";
const MAX_VALUE: usize = 64 * 1024;

pub fn valid_key(key: &str) -> bool {
    key.len() > 3 && key.len() <= 83 && key.starts_with("sb-") && key[3..].bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub struct SecureStore {
    path: Option<PathBuf>,
    state: Mutex<State>,
}

struct State {
    loaded: bool,
    persistent: bool,
    values: BTreeMap<String, String>,
}

impl SecureStore {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self { path, state: Mutex::new(State { loaded: false, persistent: false, values: BTreeMap::new() }) }
    }

    fn entry() -> Option<keyring::Entry> {
        keyring::Entry::new(SERVICE, KEY_ENTRY).ok()
    }

    fn file_key(create: bool) -> Option<Zeroizing<Vec<u8>>> {
        let entry = Self::entry()?;
        match entry.get_password() {
            Ok(encoded) => B64.decode(encoded.trim()).ok().filter(|k| k.len() == 32).map(Zeroizing::new),
            Err(keyring::Error::NoEntry) if create => {
                let key = crypto::random_bytes::<32>();
                entry.set_password(&B64.encode(key.as_ref())).ok()?;
                Some(Zeroizing::new(key.to_vec()))
            }
            Err(_) => None,
        }
    }

    fn ensure_loaded(&self, state: &mut State) {
        if state.loaded {
            return;
        }
        state.loaded = true;
        let Some(key) = Self::file_key(true) else { return };
        state.persistent = self.path.is_some();
        let Some(path) = &self.path else { return };
        let Ok(bytes) = std::fs::read(path) else { return };
        let Ok(sealed) = serde_json::from_slice::<Sealed>(&bytes) else { return };
        if let Ok(plain) = crypto::open(&key, &sealed, AAD) {
            if let Ok(values) = serde_json::from_slice::<BTreeMap<String, String>>(&plain) {
                state.values = values;
            }
        }
    }

    fn persist(&self, state: &State) {
        if !state.persistent {
            return;
        }
        let (Some(path), Some(key)) = (&self.path, Self::file_key(true)) else { return };
        let Ok(plain) = serde_json::to_vec(&state.values).map(Zeroizing::new) else { return };
        if let Ok(sealed) = crypto::seal(&key, &plain, AAD) {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(bytes) = serde_json::to_vec(&sealed) {
                let temp = path.with_extension("tmp");
                if std::fs::write(&temp, bytes).is_ok() {
                    let _ = std::fs::rename(&temp, path);
                }
            }
        }
    }

    pub fn is_persistent(&self) -> bool {
        let Ok(mut state) = self.state.lock() else { return false };
        self.ensure_loaded(&mut state);
        state.persistent
    }

    pub fn get(&self, key: &str) -> Option<String> {
        if !valid_key(key) {
            return None;
        }
        let mut state = self.state.lock().ok()?;
        self.ensure_loaded(&mut state);
        state.values.get(key).cloned()
    }

    pub fn set(&self, key: &str, value: String) -> Result<(), String> {
        if !valid_key(key) || value.len() > MAX_VALUE {
            return Err("invalid".into());
        }
        let mut state = self.state.lock().map_err(|_| "unavailable".to_string())?;
        self.ensure_loaded(&mut state);
        state.values.insert(key.to_string(), value);
        self.persist(&state);
        Ok(())
    }

    pub fn remove(&self, key: &str) {
        let Ok(mut state) = self.state.lock() else { return };
        self.ensure_loaded(&mut state);
        if state.values.remove(key).is_some() {
            self.persist(&state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::valid_key;

    #[test]
    fn only_supabase_session_keys_are_accepted() {
        assert!(valid_key("sb-wkkmyacbhqloubtwvjom-auth-token"));
        let long = format!("sb-{}", "a".repeat(81));
        for bad in ["", "sb-", "other", "sb-../../etc", "sb-UPPER", "sb-a b", long.as_str()] {
            assert!(!valid_key(bad), "{bad}");
        }
    }
}
