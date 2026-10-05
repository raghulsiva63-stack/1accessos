//! Download protection: lists files that arrived in the Downloads folder, with where they came
//! from and (for programs, scripts, disk images and macro documents) their SHA-256, so the vault
//! pages can check them against Guard's rules and threat lists. Files are never uploaded.
//!
//! Where a file came from:
//! * Windows: the "Mark of the Web" (`file:Zone.Identifier`, HostUrl / ReferrerUrl);
//! * macOS: Spotlight's "where from" (kMDItemWhereFroms);
//! * Linux: the `user.xdg.origin.url` attribute set by Chrome and Firefox (needs getfattr).

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_FILES: usize = 50;
const MAX_HASH_BYTES: u64 = 200 * 1024 * 1024;

/// File types worth a closer look: programs, scripts, installers, disk images, macro documents.
pub const RISKY_EXTENSIONS: &[&str] = &[
    "exe", "msi", "msix", "appx", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta", "cpl", "jar", "lnk", "reg", "dll",
    "app", "pkg", "dmg", "command", "sh", "deb", "rpm", "appimage", "apk", "iso", "img", "vhd", "vhdx", "zip", "rar", "7z", "docm", "xlsm", "pptm",
    "dotm", "xlam", "one",
];

const PARTIAL: &[&str] = &["crdownload", "part", "partial", "download", "tmp", "opdownload"];

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadFile {
    pub path: String,
    pub name: String,
    pub size: u64,
    pub modified_ms: u64,
    pub sha256: Option<String>,
    pub source_url: Option<String>,
    pub referrer_url: Option<String>,
}

fn extension(name: &str) -> String {
    name.rsplit_once('.').map(|(_, ext)| ext.to_ascii_lowercase()).unwrap_or_default()
}

pub fn risky(name: &str) -> bool {
    RISKY_EXTENSIONS.contains(&extension(name).as_str())
}

fn hash(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 256 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Some(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// HostUrl / ReferrerUrl from a Windows Zone.Identifier stream.
pub fn parse_zone_identifier(text: &str) -> (Option<String>, Option<String>) {
    let field = |key: &str| {
        text.lines().find_map(|line| line.trim().strip_prefix(key).and_then(|rest| rest.strip_prefix('='))).map(|v| v.trim().to_string()).filter(|v| v.starts_with("http"))
    };
    (field("HostUrl"), field("ReferrerUrl"))
}

/// The quoted URLs from `mdls -raw -name kMDItemWhereFroms`.
pub fn parse_where_froms(text: &str) -> Vec<String> {
    text.split('"').skip(1).step_by(2).filter(|s| s.starts_with("http")).map(str::to_string).collect()
}

fn clean_url(url: String) -> Option<String> {
    let url: String = url.chars().filter(|c| !c.is_control()).take(2048).collect();
    (url.starts_with("https://") || url.starts_with("http://")).then_some(url)
}

#[cfg(windows)]
fn source(path: &Path) -> (Option<String>, Option<String>) {
    let stream = format!("{}:Zone.Identifier", path.display());
    std::fs::read_to_string(stream).map(|text| parse_zone_identifier(&text)).unwrap_or((None, None))
}

#[cfg(target_os = "macos")]
fn source(path: &Path) -> (Option<String>, Option<String>) {
    let Some(path) = path.to_str() else { return (None, None) };
    let urls = crate::util::run_with_input("/usr/bin/mdls", &["-raw", "-name", "kMDItemWhereFroms", path], None, std::time::Duration::from_secs(5))
        .map(|out| parse_where_froms(&out))
        .unwrap_or_default();
    (urls.first().cloned(), urls.get(1).cloned())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn source(path: &Path) -> (Option<String>, Option<String>) {
    let Some(path) = path.to_str() else { return (None, None) };
    let attr = |name: &str| crate::util::run_with_input("getfattr", &["--only-values", "-n", name, path], None, std::time::Duration::from_secs(3)).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    (attr("user.xdg.origin.url"), attr("user.xdg.referrer.url"))
}

/// Files that finished downloading after `since_ms` (newest first).
pub fn recent(dir: &Path, since_ms: u64) -> Vec<DownloadFile> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut files: Vec<(u64, PathBuf, u64)> = entries
        .flatten()
        .filter_map(|entry| {
            let meta = entry.metadata().ok()?;
            if !meta.is_file() {
                return None;
            }
            let modified = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_millis() as u64;
            let name = entry.file_name().to_string_lossy().to_string();
            (modified > since_ms && !PARTIAL.contains(&extension(&name).as_str()) && !name.starts_with('.')).then_some((modified, entry.path(), meta.len()))
        })
        .collect();
    files.sort_by(|a, b| b.0.cmp(&a.0));
    files
        .into_iter()
        .take(MAX_FILES)
        .map(|(modified, path, size)| {
            let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            let sha256 = (risky(&name) && size <= MAX_HASH_BYTES).then(|| hash(&path)).flatten();
            let (source_url, referrer_url) = source(&path);
            DownloadFile { path: path.to_string_lossy().into_owned(), name, size, modified_ms: modified, sha256, source_url: source_url.and_then(clean_url), referrer_url: referrer_url.and_then(clean_url) }
        })
        .collect()
}

/// The file, if it really is a file directly inside the Downloads folder.
pub fn inside(dir: &Path, path: &str) -> Option<PathBuf> {
    let dir = dir.canonicalize().ok()?;
    let file = Path::new(path).canonicalize().ok()?;
    (file.parent() == Some(dir.as_path()) && file.is_file()).then_some(file)
}

/// Renames a dangerous download to "<name>.blocked" so it can no longer be opened by a double click.
pub fn quarantine(dir: &Path, path: &str) -> Result<String, String> {
    let file = inside(dir, path).ok_or_else(|| "not_found".to_string())?;
    let name = file.file_name().map(|n| n.to_string_lossy().to_string()).ok_or_else(|| "not_found".to_string())?;
    let mut target = file.with_file_name(format!("{name}.blocked"));
    let mut n = 2;
    while target.exists() {
        target = file.with_file_name(format!("{name}.{n}.blocked"));
        n += 1;
    }
    std::fs::rename(&file, &target).map_err(|_| "rename_failed".to_string())?;
    Ok(target.to_string_lossy().into_owned())
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_are_read_from_platform_metadata() {
        let zone = "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://mail.example/inbox\r\nHostUrl=https://cdn.evil.example/invoice.exe\r\n";
        assert_eq!(parse_zone_identifier(zone), (Some("https://cdn.evil.example/invoice.exe".into()), Some("https://mail.example/inbox".into())));
        assert_eq!(parse_zone_identifier("[ZoneTransfer]\nZoneId=3\nHostUrl=about:internet\n"), (None, None));
        assert_eq!(parse_where_froms("(\n    \"https://a.example/f.dmg\",\n    \"https://a.example/\"\n)"), vec!["https://a.example/f.dmg", "https://a.example/"]);
        assert!(parse_where_froms("(null)").is_empty());
    }

    #[test]
    fn new_files_are_listed_hashed_and_quarantined_inside_downloads_only() {
        let dir = std::env::temp_dir().join(format!("px-downloads-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("setup.exe"), b"MZ test").unwrap();
        std::fs::write(dir.join("notes.txt"), b"hello").unwrap();
        std::fs::write(dir.join("big.iso.crdownload"), b"partial").unwrap();
        let files = recent(&dir, 0);
        assert_eq!(files.len(), 2);
        let exe = files.iter().find(|f| f.name == "setup.exe").unwrap();
        assert_eq!(exe.sha256.as_deref().map(str::len), Some(64));
        assert!(files.iter().find(|f| f.name == "notes.txt").unwrap().sha256.is_none());
        assert!(recent(&dir, now_ms() + 60_000).is_empty());
        let blocked = quarantine(&dir, &exe.path).unwrap();
        assert!(blocked.ends_with("setup.exe.blocked"));
        assert!(quarantine(&dir, "/etc/hosts").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
