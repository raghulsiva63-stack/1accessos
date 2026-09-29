//! One-shot loopback listener for the browser sign-in (RFC 8252 §7.3).
//!
//! The app listens on 127.0.0.1 on a random port for up to ten minutes. After the person
//! approves in their browser, passkey-x.com sends the browser to
//! http://127.0.0.1:<port>/callback?code=…&state=…. Only a request with the expected state
//! and a well-formed code is accepted; the page shown in the browser never echoes input.
//! A code received here is useless without the PKCE verifier held by the app's page.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const LIFETIME: Duration = Duration::from_secs(600);

fn token(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn valid_state(state: &str) -> bool {
    token(state, 22, 64)
}

/// Parses "GET /callback?code=…&state=… HTTP/1.1" and returns the code when the state matches.
pub fn parse_request(request: &str, expected_state: &str) -> Option<String> {
    let line = request.lines().next()?;
    let mut parts = line.split(' ');
    if parts.next()? != "GET" {
        return None;
    }
    let target = parts.next()?;
    let query = target.strip_prefix("/callback?")?;
    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=')?;
        match key {
            "code" if code.is_none() && token(value, 43, 43) => code = Some(value.to_string()),
            "state" if state.is_none() => state = Some(value),
            _ => return None,
        }
    }
    (state? == expected_state).then_some(code?)
}

const DONE: &str = "<!doctype html><meta charset=utf-8><title>Passkey-X</title><body style=\"font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:90vh;margin:0\"><main style=\"max-width:420px;text-align:center\"><h1>You're signed in</h1><p>Return to the Passkey-X app. You can close this tab.</p></main>";
const NOT_FOUND: &str = "<!doctype html><meta charset=utf-8><title>Passkey-X</title><p>This link is not valid. Start again from the Passkey-X app.</p>";

fn respond(mut stream: TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

#[derive(Default)]
pub struct Loopback {
    generation: Arc<AtomicU64>,
}

impl Loopback {
    /// Starts a listener for `state` (cancelling any earlier one) and returns its port.
    /// `on_code` runs once, on the listener thread, with the accepted code.
    pub fn listen(&self, state: String, on_code: impl FnOnce(String, String) + Send + 'static) -> Result<u16, String> {
        if !valid_state(&state) {
            return Err("invalid".into());
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| "listener_unavailable".to_string())?;
        let port = listener.local_addr().map_err(|_| "listener_unavailable".to_string())?.port();
        listener.set_nonblocking(true).map_err(|_| "listener_unavailable".to_string())?;
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let current = Arc::clone(&self.generation);
        std::thread::Builder::new()
            .name("passkey-x-sign-in".into())
            .spawn(move || {
                let started = Instant::now();
                let mut on_code = Some(on_code);
                while started.elapsed() < LIFETIME && current.load(Ordering::SeqCst) == generation {
                    match listener.accept() {
                        Ok((mut stream, peer)) => {
                            if !peer.ip().is_loopback() {
                                continue;
                            }
                            let _ = stream.set_nonblocking(false);
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                            let mut buffer = [0u8; 4096];
                            let read = stream.read(&mut buffer).unwrap_or(0);
                            let request = String::from_utf8_lossy(&buffer[..read]);
                            match parse_request(&request, &state) {
                                Some(code) => {
                                    respond(stream, "200 OK", DONE);
                                    if let Some(callback) = on_code.take() {
                                        callback(code, state.clone());
                                    }
                                    return;
                                }
                                None => respond(stream, "404 Not Found", NOT_FOUND),
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(150)),
                        Err(_) => std::thread::sleep(Duration::from_millis(500)),
                    }
                }
            })
            .map_err(|_| "listener_unavailable".to_string())?;
        Ok(port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_expected_callback_is_accepted() {
        let state = "s".repeat(32);
        let code = "c".repeat(43);
        let ok = format!("GET /callback?code={code}&state={state} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
        assert_eq!(parse_request(&ok, &state), Some(code.clone()));
        for bad in [
            format!("POST /callback?code={code}&state={state} HTTP/1.1"),
            format!("GET /other?code={code}&state={state} HTTP/1.1"),
            format!("GET /callback?code={code}&state={} HTTP/1.1", "t".repeat(32)),
            format!("GET /callback?code={}&state={state} HTTP/1.1", "c".repeat(42)),
            format!("GET /callback?code={code}%27&state={state} HTTP/1.1"),
            format!("GET /callback?code={code}&state={state}&extra=1 HTTP/1.1"),
            format!("GET /callback?code={code}&code={code}&state={state} HTTP/1.1"),
            "GET /favicon.ico HTTP/1.1".to_string(),
        ] {
            assert_eq!(parse_request(&bad, &state), None, "{bad}");
        }
    }

    #[test]
    fn listener_delivers_a_valid_callback_once() {
        let loopback = Loopback::default();
        let state = "s".repeat(32);
        let code = "c".repeat(43);
        let (sender, receiver) = std::sync::mpsc::channel();
        let port = loopback.listen(state.clone(), move |code, state| { let _ = sender.send((code, state)); }).unwrap();
        // A wrong request is refused and the listener keeps waiting.
        let mut wrong = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        wrong.write_all(b"GET /callback?code=x&state=y HTTP/1.1\r\n\r\n").unwrap();
        let mut reply = String::new();
        let _ = wrong.read_to_string(&mut reply);
        assert!(reply.starts_with("HTTP/1.1 404"));
        let mut right = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        right.write_all(format!("GET /callback?code={code}&state={state} HTTP/1.1\r\n\r\n").as_bytes()).unwrap();
        let mut reply = String::new();
        let _ = right.read_to_string(&mut reply);
        assert!(reply.starts_with("HTTP/1.1 200"));
        assert!(!reply.contains(&code), "the page must not echo the code");
        assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), (code, state));
    }
}
