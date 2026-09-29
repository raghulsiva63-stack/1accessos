//! Copying secrets: hidden from clipboard history/sync where the system supports it, and
//! wiped after a timeout even while Passkey-X is in the background. A later copy by the
//! person (anything that is not our value) is never touched.

use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
pub struct SecretClipboard {
    // Kept alive for the app's lifetime: on Linux (X11) the copied text is served by it.
    board: Mutex<Option<arboard::Clipboard>>,
    generation: AtomicU64,
    pending: Mutex<Option<[u8; 32]>>,
}

fn digest(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

impl SecretClipboard {
    fn with_board<T>(&self, f: impl FnOnce(&mut arboard::Clipboard) -> Result<T, arboard::Error>) -> Result<T, String> {
        let mut guard = self.board.lock().map_err(|_| "clipboard_unavailable".to_string())?;
        if guard.is_none() {
            *guard = Some(arboard::Clipboard::new().map_err(|_| "clipboard_unavailable".to_string())?);
        }
        f(guard.as_mut().expect("clipboard initialised")).map_err(|_| "clipboard_unavailable".to_string())
    }

    fn write_secret(&self, text: &str) -> Result<(), String> {
        self.with_board(|board| {
            #[cfg(target_os = "windows")]
            {
                use arboard::SetExtWindows;
                return board.set().exclude_from_history().exclude_from_cloud().text(text.to_owned());
            }
            #[cfg(target_os = "linux")]
            {
                use arboard::SetExtLinux;
                return board.set().exclude_from_history().text(text.to_owned());
            }
            #[cfg(target_os = "macos")]
            {
                use arboard::SetExtApple;
                return board.set().exclude_from_history().text(text.to_owned());
            }
            #[allow(unreachable_code)]
            board.set_text(text.to_owned())
        })
    }

    /// Copies `text` and schedules a wipe after `seconds`.
    pub fn copy(self: &Arc<Self>, text: String, seconds: u64) -> Result<(), String> {
        if text.is_empty() || text.len() > 16 * 1024 {
            return Err("invalid".into());
        }
        self.write_secret(&text)?;
        let hash = digest(&text);
        drop(text);
        if let Ok(mut pending) = self.pending.lock() {
            *pending = Some(hash);
        }
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let this = Arc::clone(self);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(seconds.clamp(5, 300)));
            if this.generation.load(Ordering::SeqCst) == generation {
                this.clear_if_ours();
            }
        });
        Ok(())
    }

    /// Wipes the clipboard only if it still holds the secret we copied. If the clipboard is
    /// busy it is wiped anyway, so a secret is never left behind.
    pub fn clear_if_ours(&self) {
        let Some(expected) = self.pending.lock().ok().and_then(|p| *p) else { return };
        let mut guard = match self.board.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        if guard.is_none() {
            *guard = arboard::Clipboard::new().ok();
        }
        let Some(board) = guard.as_mut() else { return };
        let ours = match board.get_text() {
            Ok(text) => digest(&text) == expected,
            // Empty or non-text: the person copied something else, or it is already gone.
            Err(arboard::Error::ContentNotAvailable) => false,
            // Busy or unreadable: wipe to be safe.
            Err(_) => true,
        };
        if ours && board.clear().is_err() {
            return; // stays pending; the next lock retries
        }
        drop(guard);
        self.forget(expected);
    }

    fn forget(&self, expected: [u8; 32]) {
        if let Ok(mut pending) = self.pending.lock() {
            if *pending == Some(expected) {
                *pending = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::digest;

    #[test]
    fn digest_distinguishes_values() {
        assert_eq!(digest("a"), digest("a"));
        assert_ne!(digest("a"), digest("b"));
    }
}
