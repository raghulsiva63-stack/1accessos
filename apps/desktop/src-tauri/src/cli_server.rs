//! The app side of the `pkx` command-line tool.
//!
//! `pkx run` and `pkx read` connect to this endpoint (see local_ipc.rs) and ask for secrets by
//! reference (`px://Vault/Item/field`). The app shows who is asking (program, command, folder)
//! and which secrets; nothing is returned unless the person approves in the unlocked vault.
//! Messages: 32-bit big-endian length + JSON.

use crate::local_ipc::{self, Conn};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{oneshot, Notify};

const MAX_MESSAGE: usize = 64 * 1024;
const MAX_REPLY: usize = 1024 * 1024;
const APPROVAL_WAIT: Duration = Duration::from_secs(120);
const MAX_REFS: usize = 50;

type Notifier = Arc<dyn Fn(Value) + Send + Sync>;

#[derive(Default)]
pub struct CliServer {
    waiting: Mutex<HashMap<String, oneshot::Sender<Value>>>,
    stop: Mutex<Option<Arc<Notify>>>,
    endpoint: Mutex<Option<String>>,
    notify: Mutex<Option<Notifier>>,
}

/// A secret reference: px://<item>/<field> or px://<vault>/<item>/<field>.
pub fn valid_reference(reference: &str) -> bool {
    let Some(rest) = reference.strip_prefix("px://") else { return false };
    let parts: Vec<&str> = rest.split('/').collect();
    reference.len() <= 300 && (2..=3).contains(&parts.len()) && parts.iter().all(|p| !p.trim().is_empty()) && !reference.chars().any(char::is_control)
}

fn text(value: &Value, key: &str, limit: usize) -> String {
    value.get(key).and_then(Value::as_str).unwrap_or("").chars().filter(|c| !c.is_control()).take(limit).collect()
}

/// Checks a request from `pkx` and turns it into what the vault pages show.
pub fn parse_request(body: &[u8]) -> Result<Value, &'static str> {
    let request: Value = serde_json::from_slice(body).map_err(|_| "invalid_request")?;
    match request.get("type").and_then(Value::as_str) {
        Some("resolve") => {
            let refs: Vec<String> = request.get("refs").and_then(Value::as_array).ok_or("invalid_request")?.iter().filter_map(|r| r.as_str().map(str::to_string)).collect();
            if refs.is_empty() || refs.len() > MAX_REFS || !refs.iter().all(|r| valid_reference(r)) {
                return Err("invalid_reference");
            }
            Ok(json!({ "refs": refs, "command": text(&request, "command", 500), "cwd": text(&request, "cwd", 500) }))
        }
        _ => Err("invalid_request"),
    }
}

impl CliServer {
    pub fn start(self: &Arc<Self>, notify: Notifier) -> Result<String, String> {
        if let Some(endpoint) = self.endpoint.lock().ok().and_then(|e| e.clone()) {
            return Ok(endpoint);
        }
        if let Ok(mut slot) = self.notify.lock() {
            *slot = Some(notify);
        }
        let stop = Arc::new(Notify::new());
        let server = self.clone();
        let endpoint = local_ipc::serve("cli", stop.clone(), move |conn, pid| {
            let server = server.clone();
            async move { server.serve(conn, pid).await }
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

    pub fn running(&self) -> Option<String> {
        self.endpoint.lock().ok().and_then(|e| e.clone())
    }

    /// The vault pages' answer: `{ "values": { ref: value } }` or `{ "error": "denied" }`.
    pub fn reply(&self, id: &str, answer: Value) {
        if let Some(sender) = self.waiting.lock().ok().and_then(|mut waiting| waiting.remove(id)) {
            let _ = sender.send(answer);
        }
    }

    fn register(&self, id: &str, sender: oneshot::Sender<Value>) -> bool {
        match self.waiting.lock() {
            Ok(mut waiting) => {
                waiting.insert(id.to_string(), sender);
                true
            }
            Err(_) => false,
        }
    }

    async fn serve(self: Arc<Self>, mut conn: Box<dyn Conn>, pid: Option<u32>) {
        let Some(body) = local_ipc::read_frame(&mut conn, MAX_MESSAGE).await else { return };
        let reply = match parse_request(&body) {
            Err(error) => json!({ "ok": false, "error": error }),
            Ok(mut request) => {
                let id = crate::util::token();
                request["id"] = json!(id);
                request["client"] = json!(pid.map(crate::util::process_name).filter(|n| !n.is_empty()).unwrap_or_else(|| "pkx".into()));
                let (sender, receiver) = oneshot::channel();
                let notify = self.notify.lock().ok().and_then(|n| n.clone());
                let registered = self.register(&id, sender);
                match (registered, notify) {
                    (true, Some(notify)) => {
                        notify(request);
                        let answer = tokio::time::timeout(APPROVAL_WAIT, receiver).await;
                        if let Ok(mut waiting) = self.waiting.lock() {
                            waiting.remove(&id);
                        }
                        match answer {
                            Ok(Ok(value)) if value.get("values").is_some_and(Value::is_object) => json!({ "ok": true, "values": value["values"] }),
                            Ok(Ok(value)) => json!({ "ok": false, "error": text(&value, "error", 60) }),
                            _ => json!({ "ok": false, "error": "timeout" }),
                        }
                    }
                    _ => json!({ "ok": false, "error": "unavailable" }),
                }
            }
        };
        let mut bytes = zeroize::Zeroizing::new(serde_json::to_vec(&reply).unwrap_or_default());
        if bytes.len() > MAX_REPLY {
            bytes = zeroize::Zeroizing::new(br#"{"ok":false,"error":"too_large"}"#.to_vec());
        }
        let _ = local_ipc::write_frame(&mut conn, &bytes).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_and_requests_are_checked() {
        assert!(valid_reference("px://GitHub/token"));
        assert!(valid_reference("px://Work/Database/password"));
        assert!(!valid_reference("px://only"));
        assert!(!valid_reference("https://x/y"));
        assert!(!valid_reference("px://a/b/c/d"));
        assert!(!valid_reference("px://a//b"));
        let ok = parse_request(br#"{"type":"resolve","refs":["px://Work/DB/password"],"command":"npm start","cwd":"/home/a/app"}"#).unwrap();
        assert_eq!(ok["refs"][0], "px://Work/DB/password");
        assert_eq!(ok["command"], "npm start");
        assert_eq!(parse_request(br#"{"type":"resolve","refs":[]}"#).err(), Some("invalid_reference"));
        assert_eq!(parse_request(br#"{"type":"shell"}"#).err(), Some("invalid_request"));
        assert_eq!(parse_request(b"nope").err(), Some("invalid_request"));
    }
}
