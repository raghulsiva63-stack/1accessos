//! Auto-type: types a login into any program (Remote Desktop, VPN clients, SAP, Outlook, games),
//! not only websites.
//!
//! 1. The auto-type shortcut captures the window that has focus (its title and program name)
//!    before Passkey-X shows anything. The capture is kept for two minutes and used once.
//! 2. The vault pages pick the login (automatically only for a window the person approved
//!    before, otherwise in a picker) and send the keystroke steps.
//! 3. Passkey-X brings that same window back, checks it still has focus before every step, and
//!    types. If the person switched to another window, typing stops.
//!
//! Windows: SendInput (Unicode). macOS: System Events through osascript, with the script on
//! stdin so nothing secret appears in the process list (needs Accessibility permission).
//! Linux: xdotool on X11 (Wayland does not allow typing into other programs).

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use zeroize::Zeroize;

const CAPTURE_TTL: Duration = Duration::from_secs(120);
const MAX_STEPS: usize = 40;
const MAX_TEXT: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Handle {
    /// Windows window handle.
    Window(isize),
    /// macOS application (bundle identifier, or name when there is none).
    App(String),
    /// X11 window ID.
    X11(String),
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetInfo {
    pub token: String,
    pub title: String,
    pub app: String,
}

#[derive(Clone, Debug)]
pub struct Target {
    pub info: TargetInfo,
    pub handle: Handle,
    at: Instant,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Step {
    Text { value: String },
    Key { key: String },
    Delay { ms: u64 },
}

impl Drop for Step {
    fn drop(&mut self) {
        if let Step::Text { value } = self {
            value.zeroize();
        }
    }
}

#[derive(Default)]
pub struct AutoType {
    pending: Mutex<Option<Target>>,
}

impl AutoType {
    /// Remembers the window that has focus right now. Fails when it is Passkey-X itself or when
    /// typing into other programs is not possible on this system.
    pub fn capture(&self) -> Result<TargetInfo, String> {
        let (handle, title, app, pid) = platform::foreground().ok_or_else(|| platform::unavailable_reason().to_string())?;
        if pid == std::process::id() {
            return Err("own_window".into());
        }
        let info = TargetInfo {
            token: crate::util::token(),
            title: title.chars().filter(|c| !c.is_control()).take(300).collect(),
            app: app.chars().filter(|c| !c.is_control()).take(120).collect(),
        };
        if let Ok(mut pending) = self.pending.lock() {
            *pending = Some(Target { info: info.clone(), handle, at: Instant::now() });
        }
        Ok(info)
    }

    /// The captured window for this token, once.
    pub fn take(&self, token: &str) -> Option<Target> {
        let mut pending = self.pending.lock().ok()?;
        let fresh = pending.as_ref().is_some_and(|target| target.info.token == token && target.at.elapsed() < CAPTURE_TTL);
        if fresh { pending.take() } else { None }
    }

    pub fn clear(&self) {
        if let Ok(mut pending) = self.pending.lock() {
            *pending = None;
        }
    }
}

/// Checks the steps the vault pages sent.
pub fn validate(steps: &[Step]) -> Result<(), String> {
    if steps.is_empty() || steps.len() > MAX_STEPS {
        return Err("invalid_sequence".into());
    }
    for step in steps {
        match step {
            Step::Text { value } if value.chars().count() > MAX_TEXT || value.chars().any(|c| c.is_control()) => return Err("invalid_sequence".into()),
            Step::Key { key } if !matches!(key.as_str(), "tab" | "enter") => return Err("invalid_sequence".into()),
            Step::Delay { ms } if *ms > 5_000 => return Err("invalid_sequence".into()),
            _ => {}
        }
    }
    Ok(())
}

/// Brings the captured window back and types the steps into it.
pub fn perform(target: &Target, steps: &[Step]) -> Result<(), String> {
    validate(steps)?;
    if !platform::is_foreground(&target.handle) {
        platform::activate(&target.handle);
        std::thread::sleep(Duration::from_millis(250));
    }
    platform::wait_for_modifiers();
    for step in steps {
        if !platform::is_foreground(&target.handle) {
            return Err("target_changed".into());
        }
        match step {
            Step::Text { value } => platform::type_text(value)?,
            Step::Key { key } => platform::press(key)?,
            Step::Delay { ms } => std::thread::sleep(Duration::from_millis(*ms)),
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    Ok(())
}

/// What typing into other programs needs on this system ("" when it works out of the box).
pub fn requirement() -> &'static str {
    platform::requirement()
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
mod platform {
    use super::Handle;
    use std::time::{Duration, Instant};
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::Input::KeyboardAndMouse::{
        GetAsyncKeyState, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
        VIRTUAL_KEY, VK_CONTROL, VK_LWIN, VK_MENU, VK_RETURN, VK_RWIN, VK_SHIFT, VK_TAB,
    };
    use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId, SetForegroundWindow};

    pub fn unavailable_reason() -> &'static str {
        "no_window"
    }

    pub fn requirement() -> &'static str {
        ""
    }

    pub fn foreground() -> Option<(Handle, String, String, u32)> {
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.0.is_null() {
                return None;
            }
            let mut buffer = [0u16; 512];
            let length = GetWindowTextW(hwnd, &mut buffer).max(0) as usize;
            let title = String::from_utf16_lossy(&buffer[..length.min(buffer.len())]);
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, Some(&mut pid as *mut u32));
            Some((Handle::Window(hwnd.0 as isize), title, crate::util::process_name(pid), pid))
        }
    }

    fn current() -> isize {
        unsafe { GetForegroundWindow().0 as isize }
    }

    pub fn is_foreground(handle: &Handle) -> bool {
        matches!(handle, Handle::Window(value) if *value == current())
    }

    pub fn activate(handle: &Handle) {
        if let Handle::Window(value) = handle {
            unsafe {
                let _ = SetForegroundWindow(HWND(*value as *mut core::ffi::c_void));
            }
        }
    }

    fn pressed(key: VIRTUAL_KEY) -> bool {
        unsafe { (GetAsyncKeyState(key.0 as i32) as u16 & 0x8000) != 0 }
    }

    /// The shortcut keys may still be held down; typing now would turn letters into shortcuts.
    pub fn wait_for_modifiers() {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && [VK_CONTROL, VK_MENU, VK_SHIFT, VK_LWIN, VK_RWIN].into_iter().any(pressed) {
            std::thread::sleep(Duration::from_millis(30));
        }
    }

    fn key_input(vk: VIRTUAL_KEY, scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: vk, wScan: scan, dwFlags: flags, time: 0, dwExtraInfo: 0 } },
        }
    }

    fn send(inputs: &[INPUT]) -> Result<(), String> {
        let sent = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
        if sent as usize == inputs.len() { Ok(()) } else { Err("typing_blocked".into()) }
    }

    pub fn type_text(text: &str) -> Result<(), String> {
        for unit in text.encode_utf16() {
            send(&[key_input(VIRTUAL_KEY(0), unit, KEYEVENTF_UNICODE), key_input(VIRTUAL_KEY(0), unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP)])?;
            std::thread::sleep(Duration::from_millis(4));
        }
        Ok(())
    }

    pub fn press(key: &str) -> Result<(), String> {
        let vk = if key == "enter" { VK_RETURN } else { VK_TAB };
        send(&[key_input(vk, 0, KEYBD_EVENT_FLAGS(0)), key_input(vk, 0, KEYEVENTF_KEYUP)])
    }
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod platform {
    use super::Handle;
    use crate::util::run_with_input;
    use std::time::Duration;

    const FRONT: &str = r#"tell application "System Events"
	set p to first application process whose frontmost is true
	set n to name of p
	set b to ""
	try
		set b to bundle identifier of p
	end try
	set i to unix id of p
	set t to ""
	try
		set t to name of front window of p
	end try
end tell
return n & linefeed & b & linefeed & (i as text) & linefeed & t"#;

    fn osascript(script: &str) -> Option<String> {
        run_with_input("/usr/bin/osascript", &["-"], Some(script.as_bytes()), Duration::from_secs(10))
    }

    pub fn unavailable_reason() -> &'static str {
        "accessibility_required"
    }

    pub fn requirement() -> &'static str {
        "accessibility"
    }

    fn front() -> Option<(String, String, u32, String)> {
        let out = osascript(FRONT)?;
        let mut lines = out.trim_end_matches('\n').splitn(4, '\n');
        let name = lines.next()?.trim().to_string();
        let bundle = lines.next().unwrap_or("").trim().to_string();
        let pid = lines.next().unwrap_or("0").trim().parse().unwrap_or(0);
        let title = lines.next().unwrap_or("").trim().to_string();
        (!name.is_empty()).then_some((name, bundle, pid, title))
    }

    pub fn foreground() -> Option<(Handle, String, String, u32)> {
        let (name, bundle, pid, title) = front()?;
        let id = if bundle.is_empty() { name.clone() } else { bundle };
        Some((Handle::App(id), title, name, pid))
    }

    pub fn is_foreground(handle: &Handle) -> bool {
        let Handle::App(id) = handle else { return false };
        front().is_some_and(|(name, bundle, _, _)| &bundle == id || &name == id)
    }

    /// AppleScript string literal.
    pub fn quoted(text: &str) -> String {
        format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
    }

    pub fn activate(handle: &Handle) {
        if let Handle::App(id) = handle {
            let script = if id.contains('.') { format!("tell application id {} to activate", quoted(id)) } else { format!("tell application {} to activate", quoted(id)) };
            let _ = osascript(&script);
        }
    }

    pub fn wait_for_modifiers() {
        std::thread::sleep(Duration::from_millis(450));
    }

    pub fn type_text(text: &str) -> Result<(), String> {
        let mut script = format!("tell application \"System Events\" to keystroke {}", quoted(text));
        let result = osascript(&script).map(|_| ()).ok_or_else(|| "accessibility_required".to_string());
        zeroize::Zeroize::zeroize(&mut script);
        result
    }

    pub fn press(key: &str) -> Result<(), String> {
        let code = if key == "enter" { 36 } else { 48 };
        osascript(&format!("tell application \"System Events\" to key code {code}")).map(|_| ()).ok_or_else(|| "accessibility_required".to_string())
    }
}

// ---------------------------------------------------------------------------
// Linux (X11)
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod platform {
    use super::Handle;
    use crate::util::run_with_input;
    use std::time::Duration;

    fn x11() -> bool {
        std::env::var_os("DISPLAY").is_some() && std::env::var("XDG_SESSION_TYPE").map(|t| t != "wayland").unwrap_or(true)
    }

    fn xdotool(args: &[&str], input: Option<&[u8]>) -> Option<String> {
        if !x11() {
            return None;
        }
        run_with_input("xdotool", args, input, Duration::from_secs(10))
    }

    pub fn unavailable_reason() -> &'static str {
        if x11() { "xdotool_required" } else { "wayland_unsupported" }
    }

    pub fn requirement() -> &'static str {
        if !x11() { "wayland" } else if xdotool(&["version"], None).is_none() { "xdotool" } else { "" }
    }

    fn active() -> Option<String> {
        xdotool(&["getactivewindow"], None).map(|id| id.trim().to_string()).filter(|id| id.bytes().all(|b| b.is_ascii_digit()) && !id.is_empty())
    }

    pub fn foreground() -> Option<(Handle, String, String, u32)> {
        let id = active()?;
        let title = xdotool(&["getwindowname", &id], None).unwrap_or_default().trim().to_string();
        let pid: u32 = xdotool(&["getwindowpid", &id], None).and_then(|p| p.trim().parse().ok()).unwrap_or(0);
        let app = if pid > 0 { std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default().trim().to_string() } else { String::new() };
        Some((Handle::X11(id), title, app, pid))
    }

    pub fn is_foreground(handle: &Handle) -> bool {
        matches!(handle, Handle::X11(id) if active().as_deref() == Some(id.as_str()))
    }

    pub fn activate(handle: &Handle) {
        if let Handle::X11(id) = handle {
            let _ = xdotool(&["windowactivate", "--sync", id], None);
        }
    }

    pub fn wait_for_modifiers() {
        std::thread::sleep(Duration::from_millis(300));
    }

    pub fn type_text(text: &str) -> Result<(), String> {
        xdotool(&["type", "--clearmodifiers", "--delay", "12", "--file", "-"], Some(text.as_bytes())).map(|_| ()).ok_or_else(|| "xdotool_required".to_string())
    }

    pub fn press(key: &str) -> Result<(), String> {
        let name = if key == "enter" { "Return" } else { "Tab" };
        xdotool(&["key", "--clearmodifiers", name], None).map(|_| ()).ok_or_else(|| "xdotool_required".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> Step {
        Step::Text { value: value.into() }
    }

    #[test]
    fn sequences_are_bounded() {
        assert!(validate(&[text("alice"), Step::Key { key: "tab".into() }, text("pw"), Step::Key { key: "enter".into() }]).is_ok());
        assert!(validate(&[]).is_err());
        assert!(validate(&[Step::Key { key: "f4".into() }]).is_err());
        assert!(validate(&[text("line\nbreak")]).is_err());
        assert!(validate(&[Step::Delay { ms: 60_000 }]).is_err());
        let many: Vec<Step> = (0..41).map(|_| text("x")).collect();
        assert!(validate(&many).is_err());
        let parsed: Vec<Step> = serde_json::from_str(r#"[{"type":"text","value":"a"},{"type":"key","key":"tab"},{"type":"delay","ms":100}]"#).unwrap();
        assert_eq!(parsed.len(), 3);
    }

    #[test]
    fn captures_are_used_once_and_expire() {
        let auto = AutoType::default();
        let info = TargetInfo { token: "t1".into(), title: "VPN".into(), app: "vpn.exe".into() };
        *auto.pending.lock().unwrap() = Some(Target { info, handle: Handle::Window(1), at: Instant::now() });
        assert!(auto.take("other").is_none());
        assert!(auto.take("t1").is_some());
        assert!(auto.take("t1").is_none());
        if let Some(old) = Instant::now().checked_sub(CAPTURE_TTL + Duration::from_secs(1)) {
            let info = TargetInfo { token: "t2".into(), title: "x".into(), app: "y".into() };
            *auto.pending.lock().unwrap() = Some(Target { info, handle: Handle::Window(1), at: old });
            assert!(auto.take("t2").is_none());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn applescript_strings_are_escaped() {
        assert_eq!(platform::quoted(r#"a"b\c"#), r#""a\"b\\c""#);
    }
}
