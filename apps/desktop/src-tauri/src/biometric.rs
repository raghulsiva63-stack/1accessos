//! Fingerprint / face unlock.
//!
//! After a normal unlock, the person can turn this on. The vault key is then stored on this
//! computer encrypted (AES-256-GCM) with a key that the operating system only releases after
//! a biometric (or device PIN) check:
//!
//! * Windows: a Windows Hello key pair (TPM-backed where available). The encryption key is
//!   derived from Hello's signature over a random challenge, so the file cannot be decrypted
//!   without Windows Hello verifying the person. (Same approach as other major password managers.)
//! * macOS: a random key kept in the login Keychain, readable only by Passkey-X, released after
//!   a Touch ID check (LocalAuthentication).
//! * Linux: not offered.
//!
//! The encrypted file is bound to the vault's current password envelope ("fingerprint"): after
//! a vault password change it no longer opens and is deleted, so the password is needed again.

use crate::crypto::{self, Sealed};
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize)]
struct Enrollment {
    version: u8,
    fingerprint: String,
    /// Windows only: random challenge that Windows Hello signs to derive the key.
    challenge: Option<String>,
    sealed: Sealed,
}

pub fn valid_account(account: &str) -> bool {
    account.len() == 36
        && account.chars().enumerate().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { c == '-' } else { c.is_ascii_hexdigit() })
}

pub fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn aad(account: &str, fingerprint: &str) -> Vec<u8> {
    format!("passkey-x:desktop-unlock:v1:{account}:{fingerprint}").into_bytes()
}

fn file(dir: &Path, account: &str) -> PathBuf {
    dir.join(format!("unlock-{account}.json"))
}

pub fn kind() -> Option<&'static str> {
    platform::kind()
}

pub fn enrolled(dir: &Path, account: &str, fingerprint: &str) -> bool {
    if !valid_account(account) || !valid_fingerprint(fingerprint) || kind().is_none() {
        return false;
    }
    match read(dir, account) {
        Some(enrollment) if enrollment.fingerprint == fingerprint => true,
        Some(_) => {
            // The vault password changed: this saved unlock is stale.
            remove(dir, account);
            false
        }
        None => false,
    }
}

fn read(dir: &Path, account: &str) -> Option<Enrollment> {
    serde_json::from_slice(&std::fs::read(file(dir, account)).ok()?).ok()
}

pub fn enroll(dir: &Path, account: &str, secret_b64: &str, fingerprint: &str) -> Result<(), String> {
    if !valid_account(account) || !valid_fingerprint(fingerprint) {
        return Err("invalid".into());
    }
    let secret = Zeroizing::new(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(secret_b64.trim_end_matches('=')).map_err(|_| "invalid".to_string())?,
    );
    if secret.len() != 32 {
        return Err("invalid".into());
    }
    let (key, challenge) = platform::create_key(account)?;
    let sealed = crypto::seal(&key, &secret, &aad(account, fingerprint))?;
    let enrollment = Enrollment { version: 1, fingerprint: fingerprint.to_string(), challenge, sealed };
    std::fs::create_dir_all(dir).map_err(|_| "storage_unavailable".to_string())?;
    let bytes = serde_json::to_vec(&enrollment).map_err(|_| "storage_unavailable".to_string())?;
    std::fs::write(file(dir, account), bytes).map_err(|_| "storage_unavailable".to_string())
}

/// Returns the vault key (base64url) after the system check, or None when there is no valid enrollment.
pub fn unlock(dir: &Path, account: &str, fingerprint: &str) -> Result<Option<String>, String> {
    if !enrolled(dir, account, fingerprint) {
        return Ok(None);
    }
    let enrollment = read(dir, account).ok_or("missing")?;
    let key = platform::open_key(account, enrollment.challenge.as_deref())?;
    match crypto::open(&key, &enrollment.sealed, &aad(account, fingerprint)) {
        Ok(secret) => Ok(Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret.as_slice()))),
        Err(_) => {
            // Key no longer matches (for example Windows Hello was reset): start over.
            remove(dir, account);
            Ok(None)
        }
    }
}

pub fn remove(dir: &Path, account: &str) {
    if !valid_account(account) {
        return;
    }
    let _ = std::fs::remove_file(file(dir, account));
    platform::delete_key(account);
}

#[allow(dead_code)]
fn derive(signature: &[u8]) -> Zeroizing<Vec<u8>> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"passkey-x:windows-hello-key:v1");
    hasher.update(signature);
    Zeroizing::new(hasher.finalize().to_vec())
}

#[allow(dead_code)]
fn encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

#[cfg(target_os = "windows")]
mod platform {
    use super::{derive, encode, B64};
    use base64::Engine;
    use windows::core::HSTRING;
    use windows::Security::Credentials::{KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus};
    use windows::Security::Cryptography::CryptographicBuffer;
    use zeroize::Zeroizing;

    fn name(account: &str) -> HSTRING {
        HSTRING::from(format!("Passkey-X desktop unlock {account}"))
    }

    pub fn kind() -> Option<&'static str> {
        let supported = KeyCredentialManager::IsSupportedAsync().and_then(|op| op.get()).unwrap_or(false);
        supported.then_some("windows-hello")
    }

    fn sign(account: &str, challenge: &[u8], create: bool) -> Result<Zeroizing<Vec<u8>>, String> {
        let name = name(account);
        let result = if create {
            KeyCredentialManager::RequestCreateAsync(&name, KeyCredentialCreationOption::ReplaceExisting)
        } else {
            KeyCredentialManager::OpenAsync(&name)
        }
        .and_then(|op| op.get())
        .map_err(|_| "hello_unavailable".to_string())?;
        if result.Status().map_err(|_| "hello_unavailable".to_string())? != KeyCredentialStatus::Success {
            return Err("cancelled".into());
        }
        let credential = result.Credential().map_err(|_| "hello_unavailable".to_string())?;
        let buffer = CryptographicBuffer::CreateFromByteArray(challenge).map_err(|_| "hello_unavailable".to_string())?;
        let signed = credential.RequestSignAsync(&buffer).and_then(|op| op.get()).map_err(|_| "cancelled".to_string())?;
        if signed.Status().map_err(|_| "cancelled".to_string())? != KeyCredentialStatus::Success {
            return Err("cancelled".into());
        }
        let output = signed.Result().map_err(|_| "hello_unavailable".to_string())?;
        let mut bytes = windows::core::Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(&output, &mut bytes).map_err(|_| "hello_unavailable".to_string())?;
        Ok(Zeroizing::new(bytes.to_vec()))
    }

    pub fn create_key(account: &str) -> Result<(Zeroizing<Vec<u8>>, Option<String>), String> {
        let challenge = crate::crypto::random_bytes::<32>();
        let signature = sign(account, challenge.as_ref(), true)?;
        Ok((derive(&signature), Some(encode(challenge.as_ref()))))
    }

    pub fn open_key(account: &str, challenge: Option<&str>) -> Result<Zeroizing<Vec<u8>>, String> {
        let challenge = B64.decode(challenge.ok_or("missing")?).map_err(|_| "corrupt".to_string())?;
        let signature = sign(account, &challenge, false)?;
        Ok(derive(&signature))
    }

    pub fn delete_key(account: &str) {
        let _ = KeyCredentialManager::DeleteAsync(&name(account)).and_then(|op| op.get());
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use crate::crypto;
    use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
    use base64::Engine;
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::time::Duration;
    use zeroize::Zeroizing;

    const SERVICE: &str = "com.vlightsoft.passkeyx.unlock";

    #[allow(unused_unsafe)]
    pub fn kind() -> Option<&'static str> {
        let context = unsafe { LAContext::new() };
        let ok = unsafe { context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics) }.is_ok();
        ok.then_some("touch-id")
    }

    #[allow(unused_unsafe)]
    fn verify(reason: &str) -> Result<(), String> {
        let (sender, receiver) = std::sync::mpsc::channel::<bool>();
        let reply = RcBlock::new(move |success: Bool, _error: *mut NSError| {
            let _ = sender.send(success.as_bool());
        });
        // Keep the context alive until the reply arrives; releasing it cancels the prompt.
        let context = unsafe { LAContext::new() };
        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthenticationWithBiometrics,
                &NSString::from_str(reason),
                &reply,
            );
        }
        let result = receiver.recv_timeout(Duration::from_secs(120));
        drop(context);
        match result {
            Ok(true) => Ok(()),
            _ => Err("cancelled".into()),
        }
    }

    fn entry(account: &str) -> Result<keyring::Entry, String> {
        keyring::Entry::new(SERVICE, account).map_err(|_| "keychain_unavailable".to_string())
    }

    pub fn create_key(account: &str) -> Result<(Zeroizing<Vec<u8>>, Option<String>), String> {
        verify("turn on Touch ID unlock for your vault")?;
        let key = crypto::random_bytes::<32>();
        entry(account)?.set_password(&B64.encode(key.as_ref())).map_err(|_| "keychain_unavailable".to_string())?;
        Ok((Zeroizing::new(key.to_vec()), None))
    }

    pub fn open_key(account: &str, _challenge: Option<&str>) -> Result<Zeroizing<Vec<u8>>, String> {
        verify("unlock your Passkey-X vault")?;
        let encoded = Zeroizing::new(entry(account)?.get_password().map_err(|_| "keychain_unavailable".to_string())?);
        let key = B64.decode(encoded.trim()).map_err(|_| "corrupt".to_string())?;
        Ok(Zeroizing::new(key))
    }

    pub fn delete_key(account: &str) {
        if let Ok(entry) = entry(account) {
            let _ = entry.delete_credential();
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod platform {
    use zeroize::Zeroizing;

    pub fn kind() -> Option<&'static str> {
        None
    }
    pub fn create_key(_account: &str) -> Result<(Zeroizing<Vec<u8>>, Option<String>), String> {
        Err("unsupported".into())
    }
    pub fn open_key(_account: &str, _challenge: Option<&str>) -> Result<Zeroizing<Vec<u8>>, String> {
        Err("unsupported".into())
    }
    pub fn delete_key(_account: &str) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_and_fingerprint_inputs_are_strict() {
        assert!(valid_account("a7100000-0000-4000-8000-000000000001"));
        for bad in ["", "../../etc/passwd", "a7100000-0000-4000-8000-00000000000g", "a7100000_0000-4000-8000-000000000001"] {
            assert!(!valid_account(bad), "{bad}");
        }
        assert!(valid_fingerprint(&"ab".repeat(32)));
        assert!(!valid_fingerprint(&"AB".repeat(32)));
        assert!(!valid_fingerprint("abc"));
    }

    #[test]
    fn stale_enrollment_is_removed_when_the_vault_password_changes() {
        let dir = std::env::temp_dir().join(format!("px-unlock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let account = "a7100000-0000-4000-8000-000000000001";
        let key = crypto::random_bytes::<32>();
        let old = "ab".repeat(32);
        let sealed = crypto::seal(key.as_ref(), &[7u8; 32], &aad(account, &old)).unwrap();
        let enrollment = Enrollment { version: 1, fingerprint: old.clone(), challenge: None, sealed };
        std::fs::write(file(&dir, account), serde_json::to_vec(&enrollment).unwrap()).unwrap();
        // Different fingerprint: never usable, and cleaned up (only where biometrics exist).
        assert!(!enrolled(&dir, account, &"cd".repeat(32)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn windows_key_derivation_is_deterministic() {
        assert_eq!(derive(b"sig").as_slice(), derive(b"sig").as_slice());
        assert_ne!(derive(b"sig").as_slice(), derive(b"other").as_slice());
    }
}
