//! Local endpoints for the SSH agent and the `pkx` command-line tool.
//!
//! * macOS / Linux: a Unix socket in `~/.passkey-x/` (folder 0700, socket 0600), so only the
//!   person's own programs can connect. The connecting process ID comes from the kernel.
//! * Windows: a named pipe that refuses remote clients; the pipe's default security lets only
//!   the same user (and administrators) write to it. The client process ID comes from Windows.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;

pub trait Conn: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Conn for T {}

/// Where the endpoint lives: a socket path or a pipe name.
pub fn endpoint_path(name: &str) -> Option<String> {
    #[cfg(windows)]
    {
        let user: String = std::env::var("USERNAME").unwrap_or_default().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(40).collect();
        Some(format!(r"\\.\pipe\passkey-x-{name}-{}", if user.is_empty() { "user" } else { &user }))
    }
    #[cfg(not(windows))]
    {
        socket_dir().map(|dir| dir.join(format!("{name}.sock")).to_string_lossy().into_owned())
    }
}

pub fn socket_dir() -> Option<PathBuf> {
    crate::util::home_dir().map(|home| home.join(".passkey-x"))
}

/// Starts serving `name`. `handle` runs for every connection with the client's process ID.
/// The server stops when `stop` is notified.
pub fn serve<F, Fut>(name: &str, stop: Arc<Notify>, handle: F) -> Result<String, String>
where
    F: Fn(Box<dyn Conn>, Option<u32>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let path = endpoint_path(name).ok_or_else(|| "no_home".to_string())?;
    platform::serve(path.clone(), stop, Arc::new(handle))?;
    Ok(path)
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    pub fn serve<F, Fut>(path: String, stop: Arc<Notify>, handle: Arc<F>) -> Result<(), String>
    where
        F: Fn(Box<dyn Conn>, Option<u32>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let socket = PathBuf::from(&path);
        let dir = socket.parent().ok_or_else(|| "no_home".to_string())?.to_path_buf();
        std::fs::create_dir_all(&dir).map_err(|_| "endpoint_unavailable".to_string())?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(|_| "endpoint_unavailable".to_string())?;
        let _ = std::fs::remove_file(&socket);
        let listener = std::os::unix::net::UnixListener::bind(&socket).map_err(|_| "endpoint_unavailable".to_string())?;
        let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600));
        listener.set_nonblocking(true).map_err(|_| "endpoint_unavailable".to_string())?;
        tauri::async_runtime::spawn(async move {
            let Ok(listener) = tokio::net::UnixListener::from_std(listener) else { return };
            loop {
                let accepted = tokio::select! {
                    _ = stop.notified() => None,
                    result = listener.accept() => Some(result),
                };
                match accepted {
                    None => break,
                    Some(Ok((stream, _))) => {
                        let pid = stream.peer_cred().ok().and_then(|cred| cred.pid()).and_then(|pid| u32::try_from(pid).ok());
                        let handle = handle.clone();
                        let conn: Box<dyn Conn> = Box::new(stream);
                        tauri::async_runtime::spawn(async move { (handle.as_ref())(conn, pid).await });
                    }
                    Some(Err(_)) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
                }
            }
            let _ = std::fs::remove_file(&socket);
        });
        Ok(())
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;

    fn client_pid(server: &NamedPipeServer) -> Option<u32> {
        let mut pid = 0u32;
        unsafe { GetNamedPipeClientProcessId(HANDLE(server.as_raw_handle()), &mut pid) }.ok()?;
        Some(pid)
    }

    fn create(path: &str, first: bool) -> std::io::Result<NamedPipeServer> {
        ServerOptions::new().first_pipe_instance(first).reject_remote_clients(true).create(path)
    }

    pub fn serve<F, Fut>(path: String, stop: Arc<Notify>, handle: Arc<F>) -> Result<(), String>
    where
        F: Fn(Box<dyn Conn>, Option<u32>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (ready, started) = std::sync::mpsc::channel::<bool>();
        tauri::async_runtime::spawn(async move {
            let mut server = match create(&path, true) {
                Ok(server) => {
                    let _ = ready.send(true);
                    server
                }
                Err(_) => {
                    let _ = ready.send(false);
                    return;
                }
            };
            loop {
                let connected = tokio::select! {
                    _ = stop.notified() => None,
                    result = server.connect() => Some(result.is_ok()),
                };
                match connected {
                    None => break,
                    Some(false) => match create(&path, false) {
                        Ok(next) => server = next,
                        Err(_) => break,
                    },
                    Some(true) => {
                        let pid = client_pid(&server);
                        let Ok(next) = create(&path, false) else { break };
                        let client = std::mem::replace(&mut server, next);
                        let handle = handle.clone();
                        let conn: Box<dyn Conn> = Box::new(client);
                        tauri::async_runtime::spawn(async move { (handle.as_ref())(conn, pid).await });
                    }
                }
            }
        });
        match started.recv_timeout(std::time::Duration::from_secs(3)) {
            Ok(true) => Ok(()),
            _ => Err("endpoint_unavailable".into()),
        }
    }
}

/// Reads one frame: a 32-bit big-endian length and that many bytes.
pub async fn read_frame(conn: &mut Box<dyn Conn>, max: usize) -> Option<Vec<u8>> {
    let length = conn.read_u32().await.ok()? as usize;
    if length == 0 || length > max {
        return None;
    }
    let mut body = vec![0u8; length];
    conn.read_exact(&mut body).await.ok()?;
    Some(body)
}

pub async fn write_frame(conn: &mut Box<dyn Conn>, body: &[u8]) -> std::io::Result<()> {
    conn.write_u32(body.len() as u32).await?;
    conn.write_all(body).await?;
    conn.flush().await
}
