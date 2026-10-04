//! Pairing with the Passkey-X browser extension (Chrome, Edge, Brave) through native messaging.
//!
//! The browser starts this same program as a "native messaging host" with the extension's
//! origin as its first argument. In that mode (`run_host`) no window opens: the host only relays
//! messages between the browser (stdin/stdout, 4-byte length + JSON) and the running app over a
//! loopback connection. The app accepts that connection only with a random token from a file in
//! the person's own app data folder and only for allowed extension IDs.
//!
//! This module is a relay. Pairing (an ECDH key agreement the person approves in the app with a
//! matching code) and every vault decision happen in the app's vault pages, which never send
//! anything to an extension that has not been approved.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const HOST_NAME: &str = "com.vlightsoft.passkeyx";
/// The preview (unpacked) build of the extension has a fixed ID; store IDs are added at build
/// time with PASSKEY_X_EXTENSION_IDS or by an organization's policy.
pub const UAT_EXTENSION_ID: &str = "egkaneajfcaomheahcmopioiemmplebg";
const IDENTIFIER: &str = "com.vlightsoft.passkeyx";
const MAX_MESSAGE: usize = 64 * 1024;
const ENDPOINT_FILE: &str = "browser-link.json";

pub fn valid_extension_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

/// Extension IDs that may talk to this app.
pub fn allowed_ids(extra: &[String]) -> Vec<String> {
    let mut ids: Vec<String> = std::iter::once(UAT_EXTENSION_ID.to_string())
        .chain(option_env!("PASSKEY_X_EXTENSION_IDS").unwrap_or("").split(',').map(|id| id.trim().to_string()))
        .chain(extra.iter().cloned())
        .filter(|id| valid_extension_id(id))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// `chrome-extension://<id>/` → `<id>`.
pub fn extension_id(origin: &str) -> Option<&str> {
    let id = origin.strip_prefix("chrome-extension://")?.strip_suffix('/')?;
    valid_extension_id(id).then_some(id)
}

/// When the browser started this program as a native messaging host, the extension origin.
pub fn host_origin(args: &[String]) -> Option<String> {
    args.iter().skip(1).find(|arg| arg.starts_with("chrome-extension://")).filter(|arg| extension_id(arg).is_some()).cloned()
}

// ---------------------------------------------------------------------------
// Native messaging framing (Chromium: 32-bit native-endian length + UTF-8 JSON)
// ---------------------------------------------------------------------------

pub fn read_native(reader: &mut impl Read) -> std::io::Result<Option<Vec<u8>>> {
    let mut length = [0u8; 4];
    match reader.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let length = u32::from_ne_bytes(length) as usize;
    if length > MAX_MESSAGE {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "message too large"));
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

pub fn write_native(writer: &mut impl Write, body: &[u8]) -> std::io::Result<()> {
    writer.write_all(&(body.len() as u32).to_ne_bytes())?;
    writer.write_all(body)?;
    writer.flush()
}

/// Reads one JSON line of at most MAX_MESSAGE bytes.
fn read_line(reader: &mut impl BufRead) -> Option<Value> {
    let mut line = Vec::new();
    let read = reader.take(MAX_MESSAGE as u64 + 1).read_until(b'\n', &mut line).ok()?;
    if read == 0 || line.len() > MAX_MESSAGE || line.last() != Some(&b'\n') {
        return None;
    }
    serde_json::from_slice::<Value>(&line).ok().filter(Value::is_object)
}

fn write_line(stream: &mut impl Write, value: &Value) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| std::io::Error::other("json"))?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()
}

// ---------------------------------------------------------------------------
// Where the running app listens
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct Endpoint {
    port: u16,
    token: String,
}

/// The app's data folder, matching Tauri's app_data_dir (the host runs without Tauri).
pub fn data_dir() -> Option<PathBuf> {
    let home = || std::env::var_os("HOME").map(PathBuf::from);
    let base = if cfg!(target_os = "windows") {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        home().map(|h| h.join("Library/Application Support"))
    } else {
        std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).or_else(|| home().map(|h| h.join(".local/share")))
    }?;
    Some(base.join(IDENTIFIER))
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------
// Host mode (started by the browser)
// ---------------------------------------------------------------------------

fn error_reply(request: &Value, error: &str) -> Vec<u8> {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    serde_json::to_vec(&json!({ "type": "error", "id": id, "error": error })).unwrap_or_default()
}

/// Relays messages between the browser and the running app. Returns the process exit code.
pub fn run_host(origin: String) -> i32 {
    let stdout = Arc::new(Mutex::new(std::io::stdout()));
    let mut stdin = std::io::stdin().lock();
    let connect = || -> Option<TcpStream> {
        let bytes = std::fs::read(data_dir()?.join(ENDPOINT_FILE)).ok()?;
        let endpoint: Endpoint = serde_json::from_slice(&bytes).ok()?;
        let mut stream = TcpStream::connect_timeout(&([127, 0, 0, 1], endpoint.port).into(), Duration::from_secs(2)).ok()?;
        write_line(&mut stream, &json!({ "token": endpoint.token, "origin": origin })).ok()?;
        let reader = stream.try_clone().ok()?;
        let out = stdout.clone();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(reader);
            while let Some(message) = read_line(&mut reader) {
                let Ok(bytes) = serde_json::to_vec(&message) else { break };
                let Ok(mut out) = out.lock() else { break };
                if write_native(&mut *out, &bytes).is_err() {
                    break;
                }
            }
        });
        Some(stream)
    };
    let mut app: Option<TcpStream> = None;
    loop {
        let body = match read_native(&mut stdin) {
            Ok(Some(body)) => body,
            _ => break, // browser closed the port
        };
        let Ok(message) = serde_json::from_slice::<Value>(&body) else { continue };
        if !message.is_object() {
            continue;
        }
        if app.is_none() {
            app = connect();
        }
        let sent = app.as_mut().is_some_and(|stream| write_line(stream, &message).is_ok());
        if !sent {
            app = None;
            if let Ok(mut out) = stdout.lock() {
                let _ = write_native(&mut *out, &error_reply(&message, "desktop_unavailable"));
            }
        }
    }
    if let Some(stream) = app {
        let _ = stream.shutdown(Shutdown::Both);
    }
    0
}

// ---------------------------------------------------------------------------
// App side
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct Server {
    started: AtomicBool,
    enabled: AtomicBool,
    next: AtomicU64,
    connections: Mutex<HashMap<u64, TcpStream>>,
    allowed: Mutex<Vec<String>>,
    endpoint: Mutex<Option<PathBuf>>,
}

impl Server {
    /// Starts accepting connections from the browser host (once per run) and publishes the
    /// endpoint. `on_message(connection, origin, message)` runs on a background thread.
    pub fn enable(self: &Arc<Self>, allowed: Vec<String>, on_message: impl Fn(u64, String, Value) + Send + Sync + 'static) -> Result<(), String> {
        if let Ok(mut current) = self.allowed.lock() {
            *current = allowed;
        }
        self.enabled.store(true, Ordering::SeqCst);
        if self.started.swap(true, Ordering::SeqCst) {
            return self.publish();
        }
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|_| "browser_link_unavailable".to_string())?;
        let port = listener.local_addr().map_err(|_| "browser_link_unavailable".to_string())?.port();
        let token: String = crate::crypto::random_bytes::<32>().iter().map(|b| format!("{b:02x}")).collect();
        if let Ok(mut endpoint) = self.endpoint.lock() {
            *endpoint = data_dir().map(|dir| dir.join(ENDPOINT_FILE));
        }
        *TOKEN.lock().map_err(|_| "browser_link_unavailable".to_string())? = Some((port, token));
        self.publish()?;
        let server = self.clone();
        let on_message = Arc::new(on_message);
        std::thread::Builder::new()
            .name("passkey-x-browser-link".into())
            .spawn(move || {
                for stream in listener.incoming().flatten() {
                    if !server.enabled.load(Ordering::SeqCst) {
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    }
                    let server = server.clone();
                    let on_message = on_message.clone();
                    std::thread::spawn(move || server.serve(stream, &*on_message));
                }
            })
            .map_err(|_| "browser_link_unavailable".to_string())?;
        Ok(())
    }

    fn publish(&self) -> Result<(), String> {
        let (Some((port, token)), Some(path)) = (TOKEN.lock().ok().and_then(|t| t.clone()), self.endpoint.lock().ok().and_then(|p| p.clone())) else {
            return Err("browser_link_unavailable".into());
        };
        let bytes = serde_json::to_vec(&Endpoint { port, token }).map_err(|_| "browser_link_unavailable".to_string())?;
        write_private(&path, &bytes).map_err(|_| "browser_link_unavailable".to_string())
    }

    /// Stops accepting and closes current connections.
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
        if let Some(path) = self.endpoint.lock().ok().and_then(|p| p.clone()) {
            let _ = std::fs::remove_file(path);
        }
        if let Ok(mut connections) = self.connections.lock() {
            for (_, stream) in connections.drain() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
    }

    fn serve(&self, stream: TcpStream, on_message: &(dyn Fn(u64, String, Value) + Send + Sync)) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let Ok(reader) = stream.try_clone() else { return };
        let mut reader = BufReader::new(reader);
        let Some(hello) = read_line(&mut reader) else { return };
        let expected = TOKEN.lock().ok().and_then(|t| t.clone()).map(|(_, token)| token).unwrap_or_default();
        let token = hello.get("token").and_then(Value::as_str).unwrap_or("");
        let origin = hello.get("origin").and_then(Value::as_str).unwrap_or("").to_string();
        let allowed = extension_id(&origin)
            .is_some_and(|id| self.allowed.lock().map(|ids| ids.iter().any(|allowed| allowed == id)).unwrap_or(false));
        if expected.is_empty() || !same(token, &expected) || !allowed {
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
        let _ = stream.set_read_timeout(None);
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        if let (Ok(mut connections), Ok(clone)) = (self.connections.lock(), stream.try_clone()) {
            connections.insert(id, clone);
        }
        while let Some(message) = read_line(&mut reader) {
            if !self.enabled.load(Ordering::SeqCst) {
                break;
            }
            on_message(id, origin.clone(), message);
        }
        if let Ok(mut connections) = self.connections.lock() {
            connections.remove(&id);
        }
        on_message(id, origin, json!({ "type": "disconnected" }));
    }

    pub fn send(&self, connection: u64, message: &Value) -> Result<(), String> {
        let mut connections = self.connections.lock().map_err(|_| "unavailable".to_string())?;
        let stream = connections.get_mut(&connection).ok_or("not_connected")?;
        write_line(stream, message).map_err(|_| "not_connected".to_string())
    }
}

static TOKEN: Mutex<Option<(u16, String)>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Registering the host with the browsers (per user, no admin rights)
// ---------------------------------------------------------------------------

pub fn manifest(executable: &str, ids: &[String]) -> Value {
    json!({
        "name": HOST_NAME,
        "description": "Passkey-X desktop: unlock the Passkey-X browser extension",
        "path": executable,
        "type": "stdio",
        "allowed_origins": ids.iter().map(|id| format!("chrome-extension://{id}/")).collect::<Vec<_>>(),
    })
}

#[cfg(not(target_os = "windows"))]
fn host_dirs() -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else { return Vec::new() };
    let browsers: &[&str] = if cfg!(target_os = "macos") {
        &["Library/Application Support/Google/Chrome", "Library/Application Support/Chromium",
          "Library/Application Support/Microsoft Edge", "Library/Application Support/BraveSoftware/Brave-Browser"]
    } else {
        &[".config/google-chrome", ".config/chromium", ".config/microsoft-edge", ".config/BraveSoftware/Brave-Browser"]
    };
    browsers.iter().map(|dir| home.join(dir)).filter(|dir| dir.is_dir()).map(|dir| dir.join("NativeMessagingHosts")).collect()
}

/// Installs (or removes) the native messaging host manifest for every supported browser.
pub fn register(enabled: bool, ids: &[String]) -> Result<(), String> {
    let executable = std::env::current_exe().ok().and_then(|p| p.to_str().map(str::to_string)).ok_or("browser_link_unavailable")?;
    let body = serde_json::to_vec_pretty(&manifest(&executable, ids)).map_err(|_| "browser_link_unavailable".to_string())?;
    platform::register(enabled, &body)
}

#[cfg(target_os = "windows")]
mod platform {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{RegDeleteKeyW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ};

    const KEYS: &[&str] = &[
        r"Software\Google\Chrome\NativeMessagingHosts\com.vlightsoft.passkeyx",
        r"Software\Chromium\NativeMessagingHosts\com.vlightsoft.passkeyx",
        r"Software\Microsoft\Edge\NativeMessagingHosts\com.vlightsoft.passkeyx",
        r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\com.vlightsoft.passkeyx",
    ];

    pub fn register(enabled: bool, body: &[u8]) -> Result<(), String> {
        let path = super::data_dir().ok_or("browser_link_unavailable")?.join("native-messaging").join("com.vlightsoft.passkeyx.json");
        if !enabled {
            for key in KEYS {
                let _ = unsafe { RegDeleteKeyW(HKEY_CURRENT_USER, &HSTRING::from(*key)) };
            }
            let _ = std::fs::remove_file(&path);
            return Ok(());
        }
        super::write_private(&path, body).map_err(|_| "browser_link_unavailable".to_string())?;
        let value: Vec<u16> = path.to_string_lossy().encode_utf16().chain(std::iter::once(0)).collect();
        let mut written = false;
        for key in KEYS {
            let status = unsafe {
                RegSetKeyValueW(HKEY_CURRENT_USER, &HSTRING::from(*key), PCWSTR::null(), REG_SZ.0,
                    Some(value.as_ptr() as *const core::ffi::c_void), (value.len() * 2) as u32)
            };
            written |= status == ERROR_SUCCESS;
        }
        if written { Ok(()) } else { Err("browser_link_unavailable".into()) }
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    pub fn register(enabled: bool, body: &[u8]) -> Result<(), String> {
        for dir in super::host_dirs() {
            let path = dir.join("com.vlightsoft.passkeyx.json");
            if enabled {
                let _ = std::fs::create_dir_all(&dir);
                let _ = std::fs::write(&path, body);
            } else {
                let _ = std::fs::remove_file(&path);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_listed_extension_origins_start_host_mode() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(host_origin(&args(&["passkey-x", "chrome-extension://egkaneajfcaomheahcmopioiemmplebg/", "--parent-window=0"])),
            Some("chrome-extension://egkaneajfcaomheahcmopioiemmplebg/".into()));
        assert_eq!(host_origin(&args(&["passkey-x", "--hidden"])), None);
        assert_eq!(host_origin(&args(&["passkey-x", "chrome-extension://zzzz/"])), None);
        assert_eq!(extension_id("chrome-extension://egkaneajfcaomheahcmopioiemmplebg"), None);
        assert!(allowed_ids(&["abcdefghijklmnopabcdefghijklmnop".into(), "bad".into()]).contains(&"abcdefghijklmnopabcdefghijklmnop".to_string()));
        assert!(allowed_ids(&[]).contains(&UAT_EXTENSION_ID.to_string()));
    }

    #[test]
    fn native_framing_round_trips_and_rejects_large_messages() {
        let mut buffer = Vec::new();
        write_native(&mut buffer, br#"{"type":"hello"}"#).unwrap();
        let mut cursor = std::io::Cursor::new(buffer);
        assert_eq!(read_native(&mut cursor).unwrap().unwrap(), br#"{"type":"hello"}"#);
        assert!(read_native(&mut cursor).unwrap().is_none());
        let mut huge = std::io::Cursor::new(((MAX_MESSAGE + 1) as u32).to_ne_bytes().to_vec());
        assert!(read_native(&mut huge).is_err());
    }

    #[test]
    fn lines_must_be_complete_objects() {
        assert!(read_line(&mut std::io::Cursor::new(b"{\"a\":1}\n".to_vec())).is_some());
        assert!(read_line(&mut std::io::Cursor::new(b"[1]\n".to_vec())).is_none());
        assert!(read_line(&mut std::io::Cursor::new(b"{\"a\":1}".to_vec())).is_none());
        assert!(same("abc", "abc") && !same("abc", "abd") && !same("abc", "ab"));
    }

    #[test]
    fn relay_accepts_only_the_token_and_allowed_origin() {
        let server = Arc::new(Server::default());
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = Mutex::new(tx);
        // Use a private data folder for the endpoint file.
        let dir = std::env::temp_dir().join(format!("px-link-{}", std::process::id()));
        std::env::set_var("APPDATA", &dir);
        std::env::set_var("HOME", &dir);
        std::env::set_var("XDG_DATA_HOME", &dir);
        server.enable(vec![UAT_EXTENSION_ID.into()], move |_, origin, message| { let _ = tx.lock().unwrap().send((origin, message)); }).unwrap();
        let endpoint: Endpoint = serde_json::from_slice(&std::fs::read(data_dir().unwrap().join(ENDPOINT_FILE)).unwrap()).unwrap();
        let origin = format!("chrome-extension://{UAT_EXTENSION_ID}/");

        let mut bad = TcpStream::connect(("127.0.0.1", endpoint.port)).unwrap();
        write_line(&mut bad, &json!({ "token": "wrong", "origin": origin })).unwrap();
        write_line(&mut bad, &json!({ "type": "hello" })).unwrap();

        let mut good = TcpStream::connect(("127.0.0.1", endpoint.port)).unwrap();
        write_line(&mut good, &json!({ "token": endpoint.token, "origin": origin })).unwrap();
        write_line(&mut good, &json!({ "type": "hello" })).unwrap();
        let (seen_origin, message) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(seen_origin, origin);
        assert_eq!(message["type"], "hello");
        server.disable();
        let _ = std::fs::remove_dir_all(dir);
    }
}
