//! Settings an organization's IT team enforces on managed computers.
//!
//! Sources (only locations that standard users cannot write):
//! * Windows: registry values under `HKLM\SOFTWARE\Policies\Vlightsoft\Passkey-X`
//!   (Group Policy / Intune, see policy/windows/PasskeyX.admx);
//! * macOS: managed preferences for `com.vlightsoft.passkeyx` (MDM configuration profile), or
//!   values an administrator wrote to `/Library/Preferences/com.vlightsoft.passkeyx.plist`;
//! * Linux: `/etc/passkey-x/policy.json`.
//!
//! A policy only ever restricts the app or pre-configures it; it never gives anyone access to
//! vault data.

use serde::Serialize;
use serde_json::{Map, Value};

/// Every policy name, its type and how it is described in templates.
pub const FIELDS: &[(&str, Kind)] = &[
    ("organizationName", Kind::Text),
    ("supportUrl", Kind::Text),
    ("allowedEmailDomains", Kind::List),
    ("lockOnBlur", Kind::Flag),
    ("lockOnHide", Kind::Flag),
    ("hotkeyEnabled", Kind::Flag),
    ("maxClipboardSeconds", Kind::Number),
    ("idleLockMinutes", Kind::Number),
    ("disableBiometric", Kind::Flag),
    ("disableUpdates", Kind::Flag),
    ("autoStart", Kind::Flag),
    ("offlineAccess", Kind::Flag),
    ("browserIntegration", Kind::Flag),
    ("extensionIds", Kind::List),
    ("autoType", Kind::Flag),
    ("sshAgent", Kind::Flag),
    ("commandLine", Kind::Flag),
    ("downloadProtection", Kind::Flag),
];

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Flag,
    Number,
    Text,
    List,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    /// True when any policy value was found.
    pub managed: bool,
    /// Where the policy came from ("registry", "managed-preferences", "/etc/passkey-x/policy.json").
    pub source: Option<String>,
    pub organization_name: Option<String>,
    pub support_url: Option<String>,
    /// Only accounts with an email address on these domains may sign in on this computer.
    pub allowed_email_domains: Vec<String>,
    pub lock_on_blur: Option<bool>,
    pub lock_on_hide: Option<bool>,
    pub hotkey_enabled: Option<bool>,
    pub max_clipboard_seconds: Option<u64>,
    /// The vault locks after at most this many idle minutes.
    pub idle_lock_minutes: Option<u32>,
    pub disable_biometric: bool,
    /// Updates are deployed by IT; the app does not check or install them.
    pub disable_updates: bool,
    pub auto_start: Option<bool>,
    /// Keep an encrypted copy of the vault for use without internet.
    pub offline_access: Option<bool>,
    /// Allow pairing with the Passkey-X browser extension.
    pub browser_integration: Option<bool>,
    /// Additional Chromium extension IDs allowed to pair (e.g. an internally published build).
    pub extension_ids: Vec<String>,
    /// Allow the auto-type shortcut (typing logins into other programs).
    pub auto_type: Option<bool>,
    /// Allow the Passkey-X SSH agent.
    pub ssh_agent: Option<bool>,
    /// Allow the `pkx` command-line tool.
    pub command_line: Option<bool>,
    /// Check new downloads (true forces it on).
    pub download_protection: Option<bool>,
}

fn flag(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::Number(n) => n.as_i64().map(|n| n != 0),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" | "enabled" => Some(true),
            "0" | "false" | "no" | "off" | "disabled" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn number(value: &Value) -> Option<u64> {
    match value {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn text(value: &Value) -> Option<String> {
    let s = value.as_str()?.trim();
    (!s.is_empty() && s.len() <= 200 && !s.chars().any(char::is_control)).then(|| s.to_string())
}

fn list(value: &Value) -> Vec<String> {
    let items: Vec<String> = match value {
        Value::Array(items) => items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
        Value::String(s) => s.split([',', ';', '\n', ' ']).map(str::to_string).collect(),
        _ => Vec::new(),
    };
    // "@acme.com" and "acme.com" mean the same domain; strip the @ before sorting and de-duplicating.
    let mut out: Vec<String> = items.into_iter().map(|s| s.trim().trim_start_matches('@').to_ascii_lowercase()).filter(|s| !s.is_empty()).collect();
    out.sort();
    out.dedup();
    out.truncate(50);
    out
}

pub fn valid_domain(domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    domain.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
}

/// Chromium extension IDs are 32 characters a–p.
pub fn valid_extension_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

impl Policy {
    /// Builds a policy from loosely typed values (registry, plist or JSON). Unknown names and
    /// invalid values are ignored; numbers are kept inside safe bounds.
    pub fn from_values(values: &Map<String, Value>, source: &str) -> Policy {
        let get = |name: &str| values.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, v)| v);
        let mut policy = Policy {
            organization_name: get("organizationName").and_then(text),
            support_url: get("supportUrl").and_then(text).filter(|url| url.starts_with("https://")),
            allowed_email_domains: get("allowedEmailDomains").map(list).unwrap_or_default().into_iter().filter(|d| valid_domain(d)).collect(),
            lock_on_blur: get("lockOnBlur").and_then(flag),
            lock_on_hide: get("lockOnHide").and_then(flag),
            hotkey_enabled: get("hotkeyEnabled").and_then(flag),
            max_clipboard_seconds: get("maxClipboardSeconds").and_then(number).map(|n| n.clamp(10, 120)),
            idle_lock_minutes: get("idleLockMinutes").and_then(number).map(|n| n.clamp(1, 480) as u32),
            disable_biometric: get("disableBiometric").and_then(flag).unwrap_or(false),
            disable_updates: get("disableUpdates").and_then(flag).unwrap_or(false),
            auto_start: get("autoStart").and_then(flag),
            offline_access: get("offlineAccess").and_then(flag),
            browser_integration: get("browserIntegration").and_then(flag),
            extension_ids: get("extensionIds").map(list).unwrap_or_default().into_iter().filter(|id| valid_extension_id(id)).collect(),
            auto_type: get("autoType").and_then(flag),
            ssh_agent: get("sshAgent").and_then(flag),
            command_line: get("commandLine").and_then(flag),
            download_protection: get("downloadProtection").and_then(flag),
            ..Policy::default()
        };
        policy.managed = FIELDS.iter().any(|(name, _)| get(name).is_some());
        if policy.managed {
            policy.source = Some(source.to_string());
        }
        policy
    }

    /// True when this email address may sign in on this computer.
    pub fn allows_email(&self, email: &str) -> bool {
        if self.allowed_email_domains.is_empty() {
            return true;
        }
        let domain = email.rsplit_once('@').map(|(_, d)| d.trim().to_ascii_lowercase()).unwrap_or_default();
        self.allowed_email_domains.iter().any(|allowed| *allowed == domain)
    }
}

/// Reads the policy for this computer (empty when the computer is not managed).
pub fn load() -> Policy {
    platform::load()
}

#[cfg(target_os = "windows")]
mod platform {
    use super::{Policy, FIELDS};
    use serde_json::{Map, Value};
    use windows::core::HSTRING;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, REG_DWORD, REG_VALUE_TYPE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ};

    const KEY: &str = r"SOFTWARE\Policies\Vlightsoft\Passkey-X";

    fn read(name: &str) -> Option<Value> {
        let subkey = HSTRING::from(KEY);
        let value = HSTRING::from(name);
        let mut kind = REG_VALUE_TYPE::default();
        let mut size: u32 = 0;
        let status = unsafe {
            RegGetValueW(HKEY_LOCAL_MACHINE, &subkey, &value, RRF_RT_REG_SZ | RRF_RT_REG_DWORD, Some(&mut kind as *mut _), None, Some(&mut size as *mut u32))
        };
        if status != ERROR_SUCCESS || size == 0 || size > 16 * 1024 {
            return None;
        }
        let mut buffer = vec![0u8; size as usize];
        let status = unsafe {
            RegGetValueW(HKEY_LOCAL_MACHINE, &subkey, &value, RRF_RT_REG_SZ | RRF_RT_REG_DWORD, Some(&mut kind as *mut _),
                Some(buffer.as_mut_ptr() as *mut core::ffi::c_void), Some(&mut size as *mut u32))
        };
        if status != ERROR_SUCCESS {
            return None;
        }
        if kind == REG_DWORD && size >= 4 {
            return Some(Value::from(u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]])));
        }
        let wide: Vec<u16> = buffer[..size as usize].chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&c| c != 0).collect();
        Some(Value::from(String::from_utf16_lossy(&wide)))
    }

    pub fn load() -> Policy {
        let mut values = Map::new();
        for (name, _) in FIELDS {
            if let Some(value) = read(name) {
                values.insert((*name).to_string(), value);
            }
        }
        Policy::from_values(&values, "registry")
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::{Policy, FIELDS};
    use core_foundation::base::{Boolean, CFType, CFTypeRef, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::number::CFNumber;
    use core_foundation::string::{CFString, CFStringRef};
    use serde_json::{Map, Value};

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFPreferencesCopyAppValue(key: CFStringRef, application_id: CFStringRef) -> CFTypeRef;
        fn CFPreferencesAppValueIsForced(key: CFStringRef, application_id: CFStringRef) -> Boolean;
        fn CFPreferencesCopyValue(key: CFStringRef, application_id: CFStringRef, user_name: CFStringRef, host_name: CFStringRef) -> CFTypeRef;
        static kCFPreferencesAnyUser: CFStringRef;
        static kCFPreferencesAnyHost: CFStringRef;
    }

    const APP: &str = "com.vlightsoft.passkeyx";

    fn read(name: &str) -> Option<Value> {
        let key = CFString::new(name);
        let app = CFString::new(APP);
        let raw = unsafe {
            if CFPreferencesAppValueIsForced(key.as_concrete_TypeRef(), app.as_concrete_TypeRef()) != 0 {
                // Managed (MDM profile) value.
                CFPreferencesCopyAppValue(key.as_concrete_TypeRef(), app.as_concrete_TypeRef())
            } else {
                // Written by an administrator to /Library/Preferences (not user-writable).
                CFPreferencesCopyValue(key.as_concrete_TypeRef(), app.as_concrete_TypeRef(), kCFPreferencesAnyUser, kCFPreferencesAnyHost)
            }
        };
        if raw.is_null() {
            return None;
        }
        let value = unsafe { CFType::wrap_under_create_rule(raw) };
        if let Some(b) = value.downcast::<CFBoolean>() {
            return Some(Value::Bool(bool::from(b)));
        }
        if let Some(n) = value.downcast::<CFNumber>() {
            return n.to_i64().map(Value::from);
        }
        value.downcast::<CFString>().map(|s| Value::from(s.to_string()))
    }

    pub fn load() -> Policy {
        let mut values = Map::new();
        for (name, _) in FIELDS {
            if let Some(value) = read(name) {
                values.insert((*name).to_string(), value);
            }
        }
        Policy::from_values(&values, "managed-preferences")
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod platform {
    use super::Policy;

    const PATH: &str = "/etc/passkey-x/policy.json";

    pub fn load() -> Policy {
        let Ok(bytes) = std::fs::read(PATH) else { return Policy::default() };
        match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(serde_json::Value::Object(values)) => Policy::from_values(&values, PATH),
            _ => Policy::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json: &str) -> Policy {
        match serde_json::from_str::<Value>(json).unwrap() {
            Value::Object(map) => Policy::from_values(&map, "test"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn empty_policy_is_unmanaged() {
        let p = policy("{}");
        assert!(!p.managed);
        assert!(p.source.is_none());
        assert!(p.allows_email("anyone@example.com"));
    }

    #[test]
    fn parses_loose_registry_and_plist_values() {
        let p = policy(r#"{
            "OrganizationName": "Acme Corp", "supportUrl": "http://insecure.example",
            "allowedEmailDomains": "@Acme.com, acme.co.uk;bad_domain, -x.com",
            "lockOnBlur": 1, "hotkeyEnabled": "false", "maxClipboardSeconds": 999,
            "idleLockMinutes": "0", "disableBiometric": true, "autoStart": "yes",
            "extensionIds": ["abcdefghijklmnopabcdefghijklmnop", "not-an-id"]
        }"#);
        assert!(p.managed);
        assert_eq!(p.source.as_deref(), Some("test"));
        assert_eq!(p.organization_name.as_deref(), Some("Acme Corp"));
        assert_eq!(p.support_url, None);
        assert_eq!(p.allowed_email_domains, vec!["acme.co.uk", "acme.com"]);
        assert_eq!(p.lock_on_blur, Some(true));
        assert_eq!(p.hotkey_enabled, Some(false));
        assert_eq!(p.max_clipboard_seconds, Some(120));
        assert_eq!(p.idle_lock_minutes, Some(1));
        assert!(p.disable_biometric);
        assert_eq!(p.auto_start, Some(true));
        assert_eq!(p.extension_ids, vec!["abcdefghijklmnopabcdefghijklmnop"]);
    }

    #[test]
    fn email_domains_are_matched_exactly() {
        let p = policy(r#"{"allowedEmailDomains": ["acme.com"]}"#);
        assert!(p.allows_email("ann@ACME.com"));
        assert!(!p.allows_email("ann@sub.acme.com"));
        assert!(!p.allows_email("ann@acme.com.evil.io"));
        assert!(!p.allows_email("acme.com"));
    }
}
