//! Presentation mode: notices when the screen is probably being shared or recorded, so the vault
//! pages can hide every password (Passkey-X windows are already blanked in screen captures on
//! Windows and macOS; this also covers Linux, other windows and the moment before a reveal).
//!
//! Detection is by running programs that only run while sharing or recording (Zoom's sharing
//! helper, OBS, the Windows snipping recorder, …). Meetings in a browser cannot be detected, so
//! people can also switch presentation mode on from the tray.

use serde::Serialize;

/// (program name, what it means)
const INDICATORS: &[(&str, &str)] = &[
    ("cpthost", "Zoom screen sharing"),
    ("obs64", "OBS Studio"),
    ("obs32", "OBS Studio"),
    ("obs", "OBS Studio"),
    ("screenclippinghost", "Windows screen recording"),
    ("streamlabs obs", "Streamlabs"),
    ("xsplit.core", "XSplit"),
    ("camtasia", "Camtasia recording"),
    ("camrecorder", "Camtasia recording"),
    ("screencapture", "macOS screen recording"),
    ("simplescreenrecorder", "SimpleScreenRecorder"),
    ("kazam", "Kazam"),
    ("vokoscreen", "vokoscreen"),
    ("peek", "Peek"),
];

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Presentation {
    pub sharing: bool,
    pub reasons: Vec<String>,
}

/// Matches running program names against the indicators.
pub fn detect(names: &[String]) -> Presentation {
    let mut reasons: Vec<String> = Vec::new();
    for name in names {
        let base = name.to_ascii_lowercase();
        let base = base.trim_end_matches(".exe");
        if let Some((_, reason)) = INDICATORS.iter().find(|(program, _)| *program == base) {
            if !reasons.iter().any(|r| r == reason) {
                reasons.push(reason.to_string());
            }
        }
    }
    Presentation { sharing: !reasons.is_empty(), reasons }
}

#[cfg(windows)]
fn running() -> Vec<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
    let mut names = Vec::new();
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else { return names };
        let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut ok = Process32FirstW(snapshot, &mut entry).is_ok();
        while ok {
            let length = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
            names.push(String::from_utf16_lossy(&entry.szExeFile[..length]));
            ok = Process32NextW(snapshot, &mut entry).is_ok();
        }
        let _ = CloseHandle(snapshot);
    }
    names
}

#[cfg(not(windows))]
fn running() -> Vec<String> {
    crate::util::run_with_input("ps", &["-A", "-o", "comm="], None, std::time::Duration::from_secs(3))
        .map(|out| out.lines().map(|line| crate::util::base_name(line.trim())).collect())
        .unwrap_or_default()
}

pub fn check() -> Presentation {
    detect(&running())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sharing_helpers_are_recognised() {
        let names = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let found = detect(&names(&["explorer.exe", "CptHost.exe", "obs64.exe", "Zoom.exe"]));
        assert!(found.sharing);
        assert_eq!(found.reasons, vec!["Zoom screen sharing", "OBS Studio"]);
        assert!(!detect(&names(&["Zoom.exe", "Teams.exe", "chrome"])).sharing);
        assert!(!check().reasons.iter().any(|r| r.is_empty()));
    }
}
