//! Small helpers shared by the desktop features: running system tools with a timeout (optionally
//! feeding them input on stdin, so secrets never appear in a process list), the person's home
//! folder, and the name of a running process.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Runs a program, writes `input` to its stdin, and returns stdout when it exits successfully
/// within `timeout`. Returns None on failure or timeout (the process is killed).
pub fn run_with_input(program: &str, args: &[&str], input: Option<&[u8]>, timeout: Duration) -> Option<String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = command.spawn().ok()?;
    if let (Some(bytes), Some(mut stdin)) = (input, child.stdin.take()) {
        let owned = zeroize::Zeroizing::new(bytes.to_vec());
        std::thread::spawn(move || {
            let _ = stdin.write_all(&owned);
            // Dropping stdin closes the pipe so the tool sees end of input.
        });
    }
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.by_ref().take(4 * 1024 * 1024).read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let bytes = reader.join().ok()?;
    status.success().then(|| String::from_utf8_lossy(&bytes).into_owned())
}

pub fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    let value = std::env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let value = std::env::var_os("HOME");
    value.map(PathBuf::from).filter(|path| path.is_absolute())
}

/// The executable name of a running process ("ssh.exe", "git", "Code"), or "" when unknown.
#[cfg(windows)]
pub fn process_name(pid: u32) -> String {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else { return String::new() };
        let mut buffer = [0u16; 1024];
        let mut length = buffer.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(buffer.as_mut_ptr()), &mut length).is_ok();
        let _ = CloseHandle(handle);
        if !ok {
            return String::new();
        }
        let path = String::from_utf16_lossy(&buffer[..length as usize]);
        base_name(&path)
    }
}

#[cfg(not(windows))]
pub fn process_name(pid: u32) -> String {
    let pid = pid.to_string();
    run_with_input("ps", &["-p", &pid, "-o", "comm="], None, Duration::from_secs(3))
        .map(|out| base_name(out.trim()))
        .unwrap_or_default()
}

/// Last path component of a program path, without control characters.
pub fn base_name(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or("").chars().filter(|c| !c.is_control()).take(80).collect()
}

/// A short random token (hex), from the system clock, a counter and the process ID, hashed.
pub fn token() -> String {
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    let count = COUNTER.fetch_add(1, Ordering::SeqCst);
    let digest = Sha256::digest(format!("{nanos}:{count}:{}", std::process::id()).as_bytes());
    digest[..12].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_names_and_tokens() {
        assert_eq!(base_name(r"C:\Windows\System32\OpenSSH\ssh.exe"), "ssh.exe");
        assert_eq!(base_name("/usr/bin/git"), "git");
        let (a, b) = (token(), token());
        assert_eq!(a.len(), 24);
        assert_ne!(a, b);
    }

    #[cfg(unix)]
    #[test]
    fn input_reaches_the_tool_on_stdin() {
        assert_eq!(run_with_input("cat", &[], Some(b"secret"), Duration::from_secs(5)).as_deref(), Some("secret"));
        assert!(run_with_input("sleep", &["5"], None, Duration::from_millis(200)).is_none());
    }
}
