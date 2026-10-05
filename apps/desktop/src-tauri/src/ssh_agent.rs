//! Passkey-X SSH agent: SSH keys stay in the encrypted vault and are used through this agent.
//!
//! * Private keys are handed to the agent by the unlocked vault pages and live only in memory;
//!   locking the vault erases them. Public keys are remembered (in the app config folder) so
//!   `ssh` can still list them while the vault is locked; using one asks the person to unlock.
//! * Every signature needs the person's approval in the app (optionally remembered for a few
//!   minutes per key). The prompt names the program that asked (ssh, git, …).
//! * Ed25519 keys (the OpenSSH default since 2023). Other key types are reported, not loaded.
//!
//! Protocol: draft-miller-ssh-agent — REQUEST_IDENTITIES (11) → IDENTITIES_ANSWER (12),
//! SIGN_REQUEST (13) → SIGN_RESPONSE (14), anything else → FAILURE (5).

use crate::local_ipc::{self, Conn};
use crate::sshkey::{self, Ed25519Key};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, Notify};

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const MAX_MESSAGE: usize = 256 * 1024;
const APPROVAL_WAIT: Duration = Duration::from_secs(90);
const MAX_KEYS: usize = 50;

struct AgentKey {
    id: String,
    name: String,
    public: [u8; 32],
    secret: Option<Ed25519Key>,
}

#[derive(Serialize, Deserialize)]
struct StoredKey {
    id: String,
    name: String,
    public: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInput {
    pub id: String,
    pub name: String,
    pub private_key: String,
}

impl Drop for KeyInput {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.private_key);
    }
}

type Notifier = Arc<dyn Fn(Value) + Send + Sync>;

pub struct Agent {
    keys: Mutex<Vec<AgentKey>>,
    allowed: Mutex<HashMap<String, Instant>>,
    waiting: Mutex<HashMap<String, oneshot::Sender<(bool, u64)>>>,
    stop: Mutex<Option<Arc<Notify>>>,
    endpoint: Mutex<Option<String>>,
    store: Option<PathBuf>,
    notify: Mutex<Option<Notifier>>,
}

impl Agent {
    pub fn new(store: Option<PathBuf>) -> Self {
        let keys = store
            .as_ref()
            .and_then(|path| std::fs::read(path).ok())
            .and_then(|bytes| serde_json::from_slice::<Vec<StoredKey>>(&bytes).ok())
            .unwrap_or_default()
            .into_iter()
            .filter_map(|stored| {
                let bytes = STANDARD.decode(stored.public).ok()?;
                let public: [u8; 32] = bytes.try_into().ok()?;
                Some(AgentKey { id: stored.id, name: stored.name, public, secret: None })
            })
            .take(MAX_KEYS)
            .collect();
        Self {
            keys: Mutex::new(keys),
            allowed: Mutex::new(HashMap::new()),
            waiting: Mutex::new(HashMap::new()),
            stop: Mutex::new(None),
            endpoint: Mutex::new(None),
            store,
            notify: Mutex::new(None),
        }
    }

    fn persist(&self, keys: &[AgentKey]) {
        let Some(path) = &self.store else { return };
        let stored: Vec<StoredKey> = keys.iter().map(|k| StoredKey { id: k.id.clone(), name: k.name.clone(), public: STANDARD.encode(k.public) }).collect();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(bytes) = serde_json::to_vec(&stored) {
            let _ = std::fs::write(path, bytes);
        }
    }

    /// Replaces the agent's keys with the vault's SSH keys (called by the unlocked vault pages).
    pub fn load(&self, inputs: Vec<KeyInput>) -> Vec<Value> {
        let mut results = Vec::new();
        let mut keys = Vec::new();
        for input in inputs.iter().take(MAX_KEYS) {
            let name: String = input.name.chars().filter(|c| !c.is_control()).take(120).collect();
            match sshkey::parse(&input.private_key) {
                Ok(key) => {
                    results.push(json!({ "id": input.id, "ok": true, "publicKey": sshkey::public_line(&key.public, &name), "fingerprint": sshkey::fingerprint(&key.public) }));
                    keys.push(AgentKey { id: input.id.chars().take(64).collect(), name, public: key.public, secret: Some(key) });
                }
                Err(error) => results.push(json!({ "id": input.id, "ok": false, "error": error.code() })),
            }
        }
        self.persist(&keys);
        if let Ok(mut current) = self.keys.lock() {
            *current = keys;
        }
        results
    }

    /// Locking the vault: private keys and remembered approvals are erased; public keys stay.
    pub fn forget_secrets(&self) {
        if let Ok(mut keys) = self.keys.lock() {
            for key in keys.iter_mut() {
                key.secret = None;
            }
        }
        if let Ok(mut allowed) = self.allowed.lock() {
            allowed.clear();
        }
    }

    /// Signing out: forget the keys entirely.
    pub fn remove_all(&self) {
        if let Ok(mut keys) = self.keys.lock() {
            keys.clear();
        }
        self.persist(&[]);
        if let Ok(mut allowed) = self.allowed.lock() {
            allowed.clear();
        }
    }

    /// The person's answer to an approval prompt.
    pub fn reply(&self, id: &str, allow: bool, remember_minutes: u64) {
        if let Some(sender) = self.waiting.lock().ok().and_then(|mut waiting| waiting.remove(id)) {
            let _ = sender.send((allow, remember_minutes.min(60)));
        }
    }

    pub fn status(&self) -> Value {
        let keys: Vec<Value> = self
            .keys
            .lock()
            .map(|keys| {
                keys.iter()
                    .map(|k| json!({ "id": k.id, "name": k.name, "publicKey": sshkey::public_line(&k.public, &k.name), "fingerprint": sshkey::fingerprint(&k.public), "unlocked": k.secret.is_some() }))
                    .collect()
            })
            .unwrap_or_default();
        let endpoint = self.endpoint.lock().ok().and_then(|e| e.clone());
        json!({ "running": endpoint.is_some(), "endpoint": endpoint, "keys": keys })
    }

    pub fn start(self: &Arc<Self>, notify: Notifier) -> Result<String, String> {
        if let Some(endpoint) = self.endpoint.lock().ok().and_then(|e| e.clone()) {
            return Ok(endpoint);
        }
        if let Ok(mut slot) = self.notify.lock() {
            *slot = Some(notify);
        }
        let stop = Arc::new(Notify::new());
        let agent = self.clone();
        let endpoint = local_ipc::serve("ssh-agent", stop.clone(), move |conn, pid| {
            let agent = agent.clone();
            async move { agent.serve(conn, pid).await }
        })?;
        if let Ok(mut slot) = self.stop.lock() {
            *slot = Some(stop);
        }
        if let Ok(mut slot) = self.endpoint.lock() {
            *slot = Some(endpoint.clone());
        }
        Ok(endpoint)
    }

    pub fn stop(&self) {
        if let Some(stop) = self.stop.lock().ok().and_then(|mut s| s.take()) {
            stop.notify_one();
        }
        if let Ok(mut slot) = self.endpoint.lock() {
            *slot = None;
        }
        if let Ok(mut waiting) = self.waiting.lock() {
            waiting.clear();
        }
    }

    async fn serve(self: Arc<Self>, mut conn: Box<dyn Conn>, pid: Option<u32>) {
        let client = pid.map(crate::util::process_name).filter(|n| !n.is_empty()).unwrap_or_else(|| "A program".into());
        while let Some(message) = local_ipc::read_frame(&mut conn, MAX_MESSAGE).await {
            let reply = self.handle(&message, &client).await;
            if local_ipc::write_frame(&mut conn, &reply).await.is_err() {
                break;
            }
        }
    }

    pub fn identities(&self) -> Vec<u8> {
        let keys = self.keys.lock().map(|k| k.iter().map(|k| (k.public, k.name.clone())).collect::<Vec<_>>()).unwrap_or_default();
        let mut out = vec![IDENTITIES_ANSWER];
        out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
        for (public, name) in keys {
            sshkey::put_string(&mut out, &sshkey::public_blob(&public));
            sshkey::put_string(&mut out, name.as_bytes());
        }
        out
    }

    fn sign_now(&self, public: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
        let keys = self.keys.lock().ok()?;
        let key = keys.iter().find(|k| &k.public == public)?;
        key.secret.as_ref().map(|secret| sshkey::sign(secret, data))
    }

    fn remembered(&self, id: &str) -> bool {
        self.allowed.lock().map(|allowed| allowed.get(id).is_some_and(|until| Instant::now() < *until)).unwrap_or(false)
    }

    async fn handle(&self, message: &[u8], client: &str) -> Vec<u8> {
        let mut reader = sshkey::Reader::new(message);
        match reader.byte() {
            Some(REQUEST_IDENTITIES) => self.identities(),
            Some(SIGN_REQUEST) => {
                let (Some(blob), Some(data)) = (reader.string(), reader.string()) else { return vec![FAILURE] };
                let mut key_reader = sshkey::Reader::new(blob);
                if key_reader.string() != Some(sshkey::KEY_TYPE.as_bytes()) {
                    return vec![FAILURE];
                }
                let Some(public) = key_reader.string().and_then(|p| <[u8; 32]>::try_from(p).ok()) else { return vec![FAILURE] };
                match self.approve_and_sign(&public, data, client).await {
                    Some(signature) => {
                        let mut out = vec![SIGN_RESPONSE];
                        sshkey::put_string(&mut out, &signature);
                        out
                    }
                    None => vec![FAILURE],
                }
            }
            _ => vec![FAILURE],
        }
    }

    async fn approve_and_sign(&self, public: &[u8; 32], data: &[u8], client: &str) -> Option<Vec<u8>> {
        let (id, name, unlocked) = {
            let keys = self.keys.lock().ok()?;
            let key = keys.iter().find(|k| &k.public == public)?;
            (key.id.clone(), key.name.clone(), key.secret.is_some())
        };
        if unlocked && self.remembered(&id) {
            return self.sign_now(public, data);
        }
        let request = crate::util::token();
        let (sender, receiver) = oneshot::channel();
        self.waiting.lock().ok()?.insert(request.clone(), sender);
        let notify = self.notify.lock().ok()?.clone()?;
        notify(json!({
            "id": request, "keyId": id, "keyName": name, "fingerprint": sshkey::fingerprint(public),
            "client": client, "locked": !unlocked,
        }));
        let answer = tokio::time::timeout(APPROVAL_WAIT, receiver).await;
        if let Ok(mut waiting) = self.waiting.lock() {
            waiting.remove(&request);
        }
        let (allow, remember) = answer.ok()?.ok()?;
        if !allow {
            return None;
        }
        if remember > 0 {
            if let Ok(mut allowed) = self.allowed.lock() {
                allowed.insert(id, Instant::now() + Duration::from_secs(remember * 60));
            }
        }
        self.sign_now(public, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent_with_key() -> Agent {
        let agent = Agent::new(None);
        let pem = sshkey::encode(&sshkey::from_seed([7u8; 32], "test"));
        let results = agent.load(vec![KeyInput { id: "k1".into(), name: "Work laptop".into(), private_key: pem.to_string() }]);
        assert_eq!(results[0]["ok"], true);
        agent
    }

    #[test]
    fn lists_identities_even_while_locked() {
        let agent = agent_with_key();
        let answer = agent.identities();
        assert_eq!(answer[0], IDENTITIES_ANSWER);
        assert_eq!(&answer[1..5], &1u32.to_be_bytes());
        agent.forget_secrets();
        assert_eq!(&agent.identities()[1..5], &1u32.to_be_bytes());
        assert_eq!(agent.status()["keys"][0]["unlocked"], false);
    }

    #[test]
    fn signing_needs_an_unlocked_key_and_unknown_requests_fail() {
        let agent = agent_with_key();
        let public = sshkey::from_seed([7u8; 32], "").public;
        assert!(agent.sign_now(&public, b"data").is_some());
        agent.forget_secrets();
        assert!(agent.sign_now(&public, b"data").is_none());
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        assert_eq!(runtime.block_on(agent.handle(&[99], "ssh")), vec![FAILURE]);
        assert_eq!(runtime.block_on(agent.handle(&[SIGN_REQUEST, 0, 0], "ssh")), vec![FAILURE]);
    }

    #[test]
    fn unsupported_keys_are_reported_not_loaded() {
        let agent = Agent::new(None);
        let results = agent.load(vec![KeyInput { id: "r".into(), name: "old".into(), private_key: "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----".into() }]);
        assert_eq!(results[0]["error"], "unsupported:rsa");
        assert_eq!(agent.identities()[1..5], 0u32.to_be_bytes());
    }
}
