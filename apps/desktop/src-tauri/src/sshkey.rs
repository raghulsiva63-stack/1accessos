//! Ed25519 SSH keys in the OpenSSH formats: the private key file
//! ("-----BEGIN OPENSSH PRIVATE KEY-----", unencrypted), the public key line
//! ("ssh-ed25519 AAAA… comment"), SHA-256 fingerprints and agent signatures.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const KEY_TYPE: &str = "ssh-ed25519";
const MAGIC: &[u8] = b"openssh-key-v1\0";
const BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const END: &str = "-----END OPENSSH PRIVATE KEY-----";

pub struct Ed25519Key {
    pub seed: Zeroizing<[u8; 32]>,
    pub public: [u8; 32],
    pub comment: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    /// Not an OpenSSH private key file.
    NotOpenSsh,
    /// Protected with a passphrase.
    Encrypted,
    /// Another key type (RSA, ECDSA, …).
    Unsupported(String),
    Invalid,
}

impl KeyError {
    pub fn code(&self) -> String {
        match self {
            KeyError::NotOpenSsh => "not_openssh".into(),
            KeyError::Encrypted => "encrypted".into(),
            KeyError::Unsupported(kind) => format!("unsupported:{kind}"),
            KeyError::Invalid => "invalid".into(),
        }
    }
}

pub struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    pub fn u32(&mut self) -> Option<u32> {
        let bytes = self.take(4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn take(&mut self, length: usize) -> Option<&'a [u8]> {
        let end = self.position.checked_add(length)?;
        let bytes = self.data.get(self.position..end)?;
        self.position = end;
        Some(bytes)
    }

    pub fn string(&mut self) -> Option<&'a [u8]> {
        let length = self.u32()? as usize;
        self.take(length)
    }

    pub fn byte(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    pub fn done(&self) -> bool {
        self.position >= self.data.len()
    }
}

pub fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

pub fn public_blob(public: &[u8; 32]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(51);
    put_string(&mut blob, KEY_TYPE.as_bytes());
    put_string(&mut blob, public);
    blob
}

pub fn public_line(public: &[u8; 32], comment: &str) -> String {
    let comment: String = comment.chars().filter(|c| !c.is_control()).take(120).collect();
    format!("{KEY_TYPE} {} {comment}", STANDARD.encode(public_blob(public))).trim_end().to_string()
}

pub fn fingerprint(public: &[u8; 32]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(public_blob(public))))
}

pub fn from_seed(seed: [u8; 32], comment: &str) -> Ed25519Key {
    let signing = SigningKey::from_bytes(&seed);
    Ed25519Key { public: signing.verifying_key().to_bytes(), seed: Zeroizing::new(seed), comment: comment.chars().filter(|c| !c.is_control()).take(120).collect() }
}

/// Reads an unencrypted OpenSSH Ed25519 private key file.
pub fn parse(text: &str) -> Result<Ed25519Key, KeyError> {
    let text = text.trim();
    if text.contains("ENCRYPTED") || text.contains("Proc-Type: 4,ENCRYPTED") {
        return Err(KeyError::Encrypted);
    }
    if text.contains("BEGIN RSA PRIVATE KEY") {
        return Err(KeyError::Unsupported("rsa".into()));
    }
    if text.contains("BEGIN EC PRIVATE KEY") || text.contains("BEGIN DSA PRIVATE KEY") || text.contains("BEGIN PRIVATE KEY") {
        return Err(KeyError::Unsupported("pem".into()));
    }
    let start = text.find(BEGIN).ok_or(KeyError::NotOpenSsh)? + BEGIN.len();
    let end = text.find(END).ok_or(KeyError::NotOpenSsh)?;
    if end <= start {
        return Err(KeyError::NotOpenSsh);
    }
    let body: String = text[start..end].chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = Zeroizing::new(STANDARD.decode(body.as_bytes()).map_err(|_| KeyError::Invalid)?);
    let mut reader = Reader::new(&bytes);
    if reader.take(MAGIC.len()) != Some(MAGIC) {
        return Err(KeyError::NotOpenSsh);
    }
    let cipher = reader.string().ok_or(KeyError::Invalid)?;
    let _kdf = reader.string().ok_or(KeyError::Invalid)?;
    let _kdf_options = reader.string().ok_or(KeyError::Invalid)?;
    if cipher != b"none" {
        return Err(KeyError::Encrypted);
    }
    if reader.u32() != Some(1) {
        return Err(KeyError::Unsupported("multiple".into()));
    }
    let _public_blob = reader.string().ok_or(KeyError::Invalid)?;
    let private = reader.string().ok_or(KeyError::Invalid)?;
    let mut section = Reader::new(private);
    let (check1, check2) = (section.u32().ok_or(KeyError::Invalid)?, section.u32().ok_or(KeyError::Invalid)?);
    if check1 != check2 {
        return Err(KeyError::Invalid);
    }
    let kind = section.string().ok_or(KeyError::Invalid)?;
    if kind != KEY_TYPE.as_bytes() {
        return Err(KeyError::Unsupported(String::from_utf8_lossy(kind).chars().take(40).collect()));
    }
    let public = section.string().filter(|p| p.len() == 32).ok_or(KeyError::Invalid)?;
    let secret = section.string().filter(|s| s.len() == 64).ok_or(KeyError::Invalid)?;
    let comment = String::from_utf8_lossy(section.string().unwrap_or_default()).to_string();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&secret[..32]);
    let key = from_seed(seed, &comment);
    seed.iter_mut().for_each(|b| *b = 0);
    if key.public != public || &secret[32..] != public {
        return Err(KeyError::Invalid);
    }
    Ok(key)
}

/// Writes the key as an unencrypted OpenSSH private key file (what `ssh-keygen -N ""` writes).
pub fn encode(key: &Ed25519Key) -> Zeroizing<String> {
    let check = Sha256::digest(key.seed.as_slice());
    let mut private = Zeroizing::new(Vec::new());
    private.extend_from_slice(&check[..4]);
    private.extend_from_slice(&check[..4]);
    put_string(&mut private, KEY_TYPE.as_bytes());
    put_string(&mut private, &key.public);
    let mut secret = Zeroizing::new([0u8; 64]);
    secret[..32].copy_from_slice(key.seed.as_slice());
    secret[32..].copy_from_slice(&key.public);
    put_string(&mut private, secret.as_slice());
    put_string(&mut private, key.comment.as_bytes());
    let mut pad = 1u8;
    while private.len() % 8 != 0 {
        private.push(pad);
        pad += 1;
    }
    let mut all = Zeroizing::new(Vec::new());
    all.extend_from_slice(MAGIC);
    put_string(&mut all, b"none");
    put_string(&mut all, b"none");
    put_string(&mut all, b"");
    all.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut all, &public_blob(&key.public));
    put_string(&mut all, &private);
    let encoded = Zeroizing::new(STANDARD.encode(all.as_slice()));
    let mut out = Zeroizing::new(String::from(BEGIN));
    out.push('\n');
    for chunk in encoded.as_bytes().chunks(70) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(END);
    out.push('\n');
    out
}

/// An agent signature blob: string "ssh-ed25519" + string signature.
pub fn sign(key: &Ed25519Key, data: &[u8]) -> Vec<u8> {
    let signing = SigningKey::from_bytes(&key.seed);
    let signature = signing.sign(data).to_bytes();
    let mut blob = Vec::with_capacity(83);
    put_string(&mut blob, KEY_TYPE.as_bytes());
    put_string(&mut blob, &signature);
    blob
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // RFC 8032 test vector 1.
    const SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    ];
    const PUBLIC: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    ];

    #[test]
    fn keys_round_trip_through_the_openssh_file_format() {
        let key = from_seed(SEED, "alice@laptop");
        assert_eq!(key.public, PUBLIC);
        let pem = encode(&key);
        assert!(pem.starts_with(BEGIN) && pem.trim_end().ends_with(END));
        let parsed = parse(&pem).unwrap();
        assert_eq!(*parsed.seed, SEED);
        assert_eq!(parsed.public, PUBLIC);
        assert_eq!(parsed.comment, "alice@laptop");
        assert!(public_line(&PUBLIC, "alice@laptop").starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"));
        assert!(fingerprint(&PUBLIC).starts_with("SHA256:"));
    }

    #[test]
    fn signatures_verify_with_the_public_key() {
        let key = from_seed(SEED, "");
        let blob = sign(&key, b"session data");
        let mut reader = Reader::new(&blob);
        assert_eq!(reader.string(), Some(KEY_TYPE.as_bytes()));
        let raw: [u8; 64] = reader.string().unwrap().try_into().unwrap();
        let verifying = VerifyingKey::from_bytes(&PUBLIC).unwrap();
        assert!(verifying.verify(b"session data", &Signature::from_bytes(&raw)).is_ok());
    }

    #[test]
    fn other_formats_are_explained() {
        assert_eq!(parse("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----").err(), Some(KeyError::Unsupported("rsa".into())));
        assert_eq!(parse("hello").err(), Some(KeyError::NotOpenSsh));
        // A real passphrase-protected key starts with cipher "aes256-ctr".
        let mut all = Vec::new();
        all.extend_from_slice(MAGIC);
        put_string(&mut all, b"aes256-ctr");
        put_string(&mut all, b"bcrypt");
        put_string(&mut all, b"");
        let pem = format!("{BEGIN}\n{}\n{END}", STANDARD.encode(&all));
        assert_eq!(parse(&pem).err(), Some(KeyError::Encrypted));
        let corrupt = encode(&from_seed(SEED, "x")).replace('A', "B");
        assert!(parse(&corrupt).is_err());
    }
}
