//! Small AES-256-GCM helpers for data the app stores on disk.

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, OsRng, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Sealed {
    pub nonce: String,
    pub ciphertext: String,
}

pub fn random_bytes<const N: usize>() -> Zeroizing<[u8; N]> {
    let mut bytes = Zeroizing::new([0u8; N]);
    OsRng.fill_bytes(bytes.as_mut());
    bytes
}

pub fn seal(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Sealed, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "bad_key".to_string())?;
    let nonce_bytes = random_bytes::<12>();
    let nonce = Nonce::from_slice(nonce_bytes.as_ref());
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| "encrypt_failed".to_string())?;
    Ok(Sealed { nonce: B64.encode(nonce_bytes.as_ref()), ciphertext: B64.encode(ciphertext) })
}

pub fn open(key: &[u8], sealed: &Sealed, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "bad_key".to_string())?;
    let nonce = B64.decode(&sealed.nonce).map_err(|_| "corrupt".to_string())?;
    if nonce.len() != 12 {
        return Err("corrupt".into());
    }
    let ciphertext = B64.decode(&sealed.ciphertext).map_err(|_| "corrupt".to_string())?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| "decrypt_failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip_and_tamper_detection() {
        let key = random_bytes::<32>();
        let sealed = seal(key.as_ref(), b"secret", b"context").unwrap();
        assert_eq!(open(key.as_ref(), &sealed, b"context").unwrap().as_slice(), b"secret");
        assert!(open(key.as_ref(), &sealed, b"other").is_err());
        let wrong = random_bytes::<32>();
        assert!(open(wrong.as_ref(), &sealed, b"context").is_err());
        let mut tampered = sealed.clone();
        tampered.ciphertext.replace_range(0..1, if tampered.ciphertext.starts_with('A') { "B" } else { "A" });
        assert!(open(key.as_ref(), &tampered, b"context").is_err());
    }
}
