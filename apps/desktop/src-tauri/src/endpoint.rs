//! Endpoint Guard: facts about this computer for the security check.
//!
//! * Installed programs (name, version, publisher). The list stays on the computer; the vault
//!   pages compare it with the risk rules and report only risky programs.
//! * Security settings: disk encryption, firewall, antivirus, automatic updates, OS version.
//! * Which installed browsers have the Passkey-X extension.
//!
//! Everything is read with the person's own (standard user) rights: built-in system tools with a
//! timeout, no administrator prompt.

use serde::Serialize;
use serde_json::Value;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MAX_PROGRAMS: usize = 10_000;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Program {
    pub name: String,
    pub version: String,
    pub publisher: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Posture {
    pub os: String,
    pub os_name: String,
    pub os_version: String,
    pub os_build: Option<u32>,
    pub disk_encrypted: Option<bool>,
    pub firewall: Option<bool>,
    pub antivirus: Option<bool>,
    pub auto_updates: Option<bool>,
    pub gatekeeper: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserProtection {
    pub browser: &'static str,
    pub installed: bool,
    pub protected: bool,
}

/// Runs a system tool and returns its output, or None after the timeout or on failure.
fn run(program: &str, args: &[&str], timeout: Duration) -> Option<String> {
    let mut command = Command::new(program);
    command.args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = command.spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    // Read concurrently so a large output cannot fill the pipe and stall the tool.
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.by_ref().take(8 * 1024 * 1024).read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(40)),
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

fn clean(value: &str, limit: usize) -> String {
    value.chars().filter(|c| !c.is_control()).take(limit).collect::<String>().trim().to_string()
}

/// Parses `[{"n":..,"v":..,"p":..}]` (or a single object) as produced by the inventory scripts.
pub fn parse_programs(json: &str) -> Vec<Program> {
    let value: Value = serde_json::from_str(json.trim()).unwrap_or(Value::Null);
    let items = match value {
        Value::Array(items) => items,
        Value::Object(_) => vec![value],
        _ => Vec::new(),
    };
    let mut programs: Vec<Program> = items
        .iter()
        .filter_map(|item| {
            let name = clean(item.get("n")?.as_str()?, 200);
            (!name.is_empty()).then(|| Program {
                name,
                version: clean(item.get("v").and_then(Value::as_str).unwrap_or(""), 60),
                publisher: clean(item.get("p").and_then(Value::as_str).unwrap_or(""), 120),
            })
        })
        .collect();
    programs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()).then(a.version.cmp(&b.version)));
    programs.dedup();
    programs.truncate(MAX_PROGRAMS);
    programs
}

/// `dpkg-query` / `rpm` output: name, version and maintainer separated by tabs.
pub fn parse_package_lines(text: &str) -> Vec<Program> {
    let mut programs: Vec<Program> = text
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let name = clean(parts.next()?, 200);
            (!name.is_empty()).then(|| Program {
                name,
                version: clean(parts.next().unwrap_or(""), 60),
                publisher: clean(parts.next().unwrap_or(""), 120),
            })
        })
        .collect();
    programs.truncate(MAX_PROGRAMS);
    programs
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;

    const INVENTORY: &str = r#"$ErrorActionPreference='SilentlyContinue';
$paths=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*');
@(Get-ItemProperty $paths | Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName } |
  ForEach-Object { [pscustomobject]@{ n=[string]$_.DisplayName; v=[string]$_.DisplayVersion; p=[string]$_.Publisher } }) | ConvertTo-Json -Compress"#;

    const POSTURE: &str = r#"$ErrorActionPreference='SilentlyContinue';
$os=Get-CimInstance Win32_OperatingSystem;
$disk=$null; try { $v=(New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive).Self.ExtendedProperty('System.Volume.BitLockerProtection'); if($v -eq 1 -or $v -eq 6){$disk=$true} elseif($v -eq 2){$disk=$false} } catch {}
$fw=$null; $profiles=Get-NetFirewallProfile; if($profiles){ $fw=-not ($profiles | Where-Object { [string]$_.Enabled -eq 'False' }) }
$av=$null; $products=Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct; if($products){ $av=[bool]($products | Where-Object { (($_.productState -shr 12) -band 0xF) -eq 1 }) }
$au=$null; $policy=Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; if($policy -and $policy.NoAutoUpdate -eq 1){$au=$false}
[pscustomobject]@{ name=[string]$os.Caption; version=[string]$os.Version; build=[int]$os.BuildNumber; disk=$disk; firewall=$fw; antivirus=$av; autoUpdates=$au } | ConvertTo-Json -Compress"#;

    fn powershell(script: &str, seconds: u64) -> Option<String> {
        run("powershell.exe", &["-NoProfile", "-NonInteractive", "-Command", script], Duration::from_secs(seconds))
    }

    pub fn programs() -> Vec<Program> {
        powershell(INVENTORY, 60).map(|json| parse_programs(&json)).unwrap_or_default()
    }

    pub fn posture() -> Posture {
        let value: Value = powershell(POSTURE, 45).and_then(|json| serde_json::from_str(json.trim()).ok()).unwrap_or(Value::Null);
        let flag = |key: &str| value.get(key).and_then(Value::as_bool);
        Posture {
            os: "windows".into(),
            os_name: clean(value.get("name").and_then(Value::as_str).unwrap_or("Windows"), 80),
            os_version: clean(value.get("version").and_then(Value::as_str).unwrap_or(""), 40),
            os_build: value.get("build").and_then(Value::as_u64).map(|b| b as u32),
            disk_encrypted: flag("disk"),
            firewall: flag("firewall"),
            antivirus: flag("antivirus"),
            auto_updates: flag("autoUpdates"),
            gatekeeper: None,
        }
    }

    pub fn browser_dirs() -> Vec<(&'static str, PathBuf)> {
        let Some(local) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) else { return Vec::new() };
        vec![
            ("chrome", local.join(r"Google\Chrome\User Data")),
            ("edge", local.join(r"Microsoft\Edge\User Data")),
            ("brave", local.join(r"BraveSoftware\Brave-Browser\User Data")),
            ("chromium", local.join(r"Chromium\User Data")),
        ]
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    fn app_bundles() -> Vec<PathBuf> {
        let mut roots = vec![PathBuf::from("/Applications"), PathBuf::from("/Applications/Utilities")];
        if let Some(home) = std::env::var_os("HOME") {
            roots.push(PathBuf::from(home).join("Applications"));
        }
        let mut bundles = Vec::new();
        for root in roots {
            let Ok(entries) = std::fs::read_dir(&root) else { continue };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "app") {
                    bundles.push(path);
                }
            }
        }
        bundles.truncate(600);
        bundles
    }

    pub fn programs() -> Vec<Program> {
        let mut items = Vec::new();
        for bundle in app_bundles() {
            let plist = bundle.join("Contents/Info.plist");
            let Some(path) = plist.to_str() else { continue };
            let Some(json) = run("/usr/bin/plutil", &["-convert", "json", "-o", "-", path], Duration::from_secs(5)) else { continue };
            let Ok(info) = serde_json::from_str::<Value>(&json) else { continue };
            let text = |key: &str| info.get(key).and_then(Value::as_str).unwrap_or("").to_string();
            let fallback = bundle.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_string();
            let name = [text("CFBundleDisplayName"), text("CFBundleName"), fallback].into_iter().find(|n| !n.trim().is_empty()).unwrap_or_default();
            let version = [text("CFBundleShortVersionString"), text("CFBundleVersion")].into_iter().find(|v| !v.trim().is_empty()).unwrap_or_default();
            items.push(serde_json::json!({ "n": name, "v": version, "p": text("CFBundleIdentifier") }));
        }
        parse_programs(&Value::Array(items).to_string())
    }

    pub fn posture() -> Posture {
        let quick = Duration::from_secs(10);
        let output = |program: &str, args: &[&str]| run(program, args, quick).unwrap_or_default();
        let filevault = output("/usr/bin/fdesetup", &["status"]);
        let firewall = output("/usr/libexec/ApplicationFirewall/socketfilterfw", &["--getglobalstate"]);
        let gatekeeper = output("/usr/sbin/spctl", &["--status"]);
        let updates = output("/usr/bin/defaults", &["read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"]);
        Posture {
            os: "macos".into(),
            os_name: "macOS".into(),
            os_version: clean(&output("/usr/bin/sw_vers", &["-productVersion"]), 40),
            os_build: None,
            disk_encrypted: if filevault.contains("FileVault is On") { Some(true) } else if filevault.contains("FileVault is Off") { Some(false) } else { None },
            firewall: if firewall.contains("enabled") { Some(true) } else if firewall.contains("disabled") { Some(false) } else { None },
            antivirus: None,
            auto_updates: match updates.trim() { "1" => Some(true), "0" => Some(false), _ => None },
            gatekeeper: if gatekeeper.contains("enabled") { Some(true) } else if gatekeeper.contains("disabled") { Some(false) } else { None },
        }
    }

    pub fn browser_dirs() -> Vec<(&'static str, PathBuf)> {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else { return Vec::new() };
        let support = home.join("Library/Application Support");
        vec![
            ("chrome", support.join("Google/Chrome")),
            ("edge", support.join("Microsoft Edge")),
            ("brave", support.join("BraveSoftware/Brave-Browser")),
            ("chromium", support.join("Chromium")),
        ]
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod platform {
    use super::*;

    pub fn programs() -> Vec<Program> {
        let timeout = Duration::from_secs(30);
        if let Some(text) = run("dpkg-query", &["-W", "-f", "${binary:Package}\t${Version}\t${Maintainer}\n"], timeout) {
            return parse_package_lines(&text);
        }
        run("rpm", &["-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\n"], timeout).map(|text| parse_package_lines(&text)).unwrap_or_default()
    }

    pub fn os_release(text: &str) -> (String, String) {
        let field = |key: &str| {
            text.lines()
                .find_map(|line| line.strip_prefix(key).and_then(|rest| rest.strip_prefix('=')))
                .map(|value| value.trim_matches('"').to_string())
                .unwrap_or_default()
        };
        let name = field("PRETTY_NAME");
        (if name.is_empty() { "Linux".into() } else { clean(&name, 80) }, clean(&field("VERSION_ID"), 40))
    }

    pub fn posture() -> Posture {
        let quick = Duration::from_secs(10);
        let (os_name, os_version) = os_release(&std::fs::read_to_string("/etc/os-release").unwrap_or_default());
        let encrypted = run("lsblk", &["-rno", "TYPE"], quick).map(|types| types.lines().any(|line| line.trim() == "crypt"));
        let active = |unit: &str| run("systemctl", &["is-active", unit], quick).is_some_and(|out| out.trim() == "active");
        Posture {
            os: "linux".into(),
            os_name,
            os_version,
            os_build: None,
            disk_encrypted: encrypted,
            firewall: if active("ufw") || active("firewalld") { Some(true) } else { None },
            antivirus: None,
            auto_updates: if active("unattended-upgrades") || active("dnf-automatic.timer") { Some(true) } else { None },
            gatekeeper: None,
        }
    }

    pub fn browser_dirs() -> Vec<(&'static str, PathBuf)> {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else { return Vec::new() };
        let config = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| home.join(".config"));
        vec![
            ("chrome", config.join("google-chrome")),
            ("edge", config.join("microsoft-edge")),
            ("brave", config.join("BraveSoftware/Brave-Browser")),
            ("chromium", config.join("chromium")),
        ]
    }
}

pub fn programs() -> Vec<Program> {
    platform::programs()
}

pub fn posture() -> Posture {
    platform::posture()
}

/// True when a browser profile ("Default", "Profile 1", ...) has one of the extension IDs installed.
pub fn has_extension(user_data: &Path, ids: &[String]) -> bool {
    let Ok(entries) = std::fs::read_dir(user_data) else { return false };
    entries.flatten().filter(|entry| entry.path().is_dir()).any(|profile| {
        let name = profile.file_name();
        let name = name.to_string_lossy();
        (name == "Default" || name.starts_with("Profile ")) && ids.iter().any(|id| profile.path().join("Extensions").join(id).is_dir())
    })
}

pub fn browsers(ids: &[String]) -> Vec<BrowserProtection> {
    platform::browser_dirs()
        .into_iter()
        .map(|(browser, dir)| {
            let installed = dir.is_dir();
            BrowserProtection { browser, installed, protected: installed && has_extension(&dir, ids) }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_json_single_object_and_noise() {
        let programs = parse_programs(r#"[{"n":"Zoom","v":"6.1.0","p":"Zoom Video"},{"n":"","v":"1"},{"n":"7-Zip\u0007 23.01","v":"23.01","p":"Igor Pavlov"},{"n":"Zoom","v":"6.1.0","p":"Zoom Video"}]"#);
        assert_eq!(programs.len(), 2);
        assert_eq!(programs[0].name, "7-Zip 23.01");
        assert_eq!(programs[1], Program { name: "Zoom".into(), version: "6.1.0".into(), publisher: "Zoom Video".into() });
        assert_eq!(parse_programs(r#"{"n":"Only","v":"1","p":""}"#).len(), 1);
        assert!(parse_programs("not json").is_empty());
        assert_eq!(parse_package_lines("xz-utils\t5.6.1-1\tDebian\n\nliblzma5\t5.6.0\n")[1].version, "5.6.0");
    }

    #[test]
    fn extension_detection_looks_in_browser_profiles() {
        let dir = std::env::temp_dir().join(format!("px-browsers-{}", std::process::id()));
        let id = "egkaneajfcaomheahcmopioiemmplebg".to_string();
        std::fs::create_dir_all(dir.join("Profile 2/Extensions").join(&id)).unwrap();
        std::fs::create_dir_all(dir.join("System Profile/Extensions/abc")).unwrap();
        assert!(has_extension(&dir, &[id.clone()]));
        assert!(!has_extension(&dir, &["abcdefghijklmnopabcdefghijklmnop".into()]));
        assert!(!has_extension(&dir.join("missing"), &[id]));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn tools_time_out_instead_of_hanging() {
        assert!(run("definitely-not-a-real-tool-px", &[], Duration::from_secs(1)).is_none());
    }
}
