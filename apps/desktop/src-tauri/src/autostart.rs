//! Start Passkey-X when the person signs in to the computer (per user, no admin rights).
//! The app starts hidden in the tray (`--hidden`); the vault stays locked until it is opened.
//!
//! * Windows: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
//! * macOS: `~/Library/LaunchAgents/com.vlightsoft.passkeyx.plist`
//! * Linux: `~/.config/autostart/passkey-x.desktop` (XDG autostart)

pub const HIDDEN_ARG: &str = "--hidden";

fn executable() -> Option<String> {
    let path = std::env::current_exe().ok()?;
    let path = path.to_str()?.to_string();
    // A path with quotes or line breaks could not be written safely into the entries below.
    (!path.contains(['"', '\n', '\r'])).then_some(path)
}

/// Escapes text for an XML property list.
fn xml(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

pub fn launch_agent(executable: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>com.vlightsoft.passkeyx</string>\n  <key>ProgramArguments</key><array><string>{}</string><string>{HIDDEN_ARG}</string></array>\n  <key>RunAtLoad</key><true/>\n  <key>ProcessType</key><string>Interactive</string>\n</dict>\n</plist>\n",
        xml(executable)
    )
}

pub fn desktop_entry(executable: &str) -> String {
    // Desktop Entry Exec values quote the program; backslashes and spaces are escaped by quoting.
    let quoted = executable.replace('\\', "\\\\").replace('`', "\\`").replace('$', "\\$");
    format!(
        "[Desktop Entry]\nType=Application\nName=Passkey-X\nComment=Zero-knowledge password vault\nExec=\"{quoted}\" {HIDDEN_ARG}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
    )
}

#[cfg(target_os = "windows")]
mod platform {
    use windows::core::HSTRING;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{RegDeleteKeyValueW, RegSetKeyValueW, HKEY_CURRENT_USER, REG_SZ};

    const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const NAME: &str = "Passkey-X";

    pub fn set(enabled: bool) -> Result<(), String> {
        let subkey = HSTRING::from(RUN);
        let name = HSTRING::from(NAME);
        if !enabled {
            let _ = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, &subkey, &name) };
            return Ok(());
        }
        let exe = super::executable().ok_or("autostart_unavailable")?;
        let command: Vec<u16> = format!("\"{exe}\" {}", super::HIDDEN_ARG).encode_utf16().chain(std::iter::once(0)).collect();
        let status = unsafe {
            RegSetKeyValueW(HKEY_CURRENT_USER, &subkey, &name, REG_SZ.0, Some(command.as_ptr() as *const core::ffi::c_void), (command.len() * 2) as u32)
        };
        if status == ERROR_SUCCESS { Ok(()) } else { Err("autostart_unavailable".into()) }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    fn path() -> Option<std::path::PathBuf> {
        Some(std::path::PathBuf::from(std::env::var_os("HOME")?).join("Library/LaunchAgents/com.vlightsoft.passkeyx.plist"))
    }

    pub fn set(enabled: bool) -> Result<(), String> {
        let path = path().ok_or("autostart_unavailable")?;
        if !enabled {
            let _ = std::fs::remove_file(&path);
            return Ok(());
        }
        let exe = super::executable().ok_or("autostart_unavailable")?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| "autostart_unavailable")?;
        }
        std::fs::write(&path, super::launch_agent(&exe)).map_err(|_| "autostart_unavailable".to_string())
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod platform {
    fn path() -> Option<std::path::PathBuf> {
        let config = std::env::var_os("XDG_CONFIG_HOME").map(std::path::PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| std::path::PathBuf::from(home).join(".config")))?;
        Some(config.join("autostart/passkey-x.desktop"))
    }

    pub fn set(enabled: bool) -> Result<(), String> {
        let path = path().ok_or("autostart_unavailable")?;
        if !enabled {
            let _ = std::fs::remove_file(&path);
            return Ok(());
        }
        // AppImage builds run from a temporary mount; point the entry at the AppImage itself.
        let exe = std::env::var("APPIMAGE").ok().filter(|p| !p.contains(['"', '\n', '\r'])).or_else(super::executable).ok_or("autostart_unavailable")?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| "autostart_unavailable")?;
        }
        std::fs::write(&path, super::desktop_entry(&exe)).map_err(|_| "autostart_unavailable".to_string())
    }
}

/// Adds or removes the sign-in entry for this user.
pub fn set(enabled: bool) -> Result<(), String> {
    platform::set(enabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_quote_the_program_and_start_hidden() {
        let plist = launch_agent("/Applications/Passkey-X.app/Contents/MacOS/passkey-x");
        assert!(plist.contains("<string>/Applications/Passkey-X.app/Contents/MacOS/passkey-x</string><string>--hidden</string>"));
        assert!(launch_agent("/tmp/a&b<c>").contains("/tmp/a&amp;b&lt;c&gt;"));
        let entry = desktop_entry("/opt/Passkey X/passkey-x");
        assert!(entry.contains("Exec=\"/opt/Passkey X/passkey-x\" --hidden\n"));
        assert!(desktop_entry("/opt/$x/`y`").contains("Exec=\"/opt/\\$x/\\`y\\`\""));
    }
}
