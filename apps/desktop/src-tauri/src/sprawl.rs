//! Secret sprawl finder: looks for passwords, API keys and private keys left in plain files on
//! this computer (Desktop, Documents, Downloads, code folders and a few well-known credential
//! files), so they can be moved into the vault and the files deleted.
//!
//! Everything happens on this computer. Results show where a secret is and a masked preview;
//! the secret itself is read again only when the person chooses to save it into the vault.

use regex::Regex;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_FILES: usize = 60_000;
const MAX_FINDINGS: usize = 500;
const MAX_DEPTH: usize = 8;
const TIME_LIMIT: Duration = Duration::from_secs(90);

const SKIP_DIRS: &[&str] = &[
    "node_modules", ".git", ".hg", ".svn", ".venv", "venv", "__pycache__", "target", "dist", "build", ".next", ".nuxt", ".cache", ".npm", ".cargo",
    ".rustup", "vendor", "Pods", ".Trash", "Library", "AppData", ".gradle", ".m2", "bower_components", "site-packages", ".terraform", "coverage",
];

const TEXT_EXTENSIONS: &[&str] = &[
    "env", "txt", "json", "yml", "yaml", "ini", "cfg", "conf", "config", "properties", "toml", "xml", "ps1", "sh", "bash", "zsh", "bat", "cmd", "py", "js",
    "ts", "mjs", "cjs", "rb", "php", "go", "java", "cs", "tf", "tfvars", "pem", "key", "csv", "md", "sql", "ipynb", "npmrc", "pypirc", "netrc",
];

#[derive(Clone, Copy)]
pub struct Rule {
    pub id: &'static str,
    pub label: &'static str,
    pub severity: &'static str,
    pattern: &'static str,
    /// Capture group holding the secret (0 = whole match).
    group: usize,
    /// Only in configuration-like files (keeps code and prose quiet).
    config_only: bool,
}

pub const RULES: &[Rule] = &[
    Rule { id: "private_key", label: "Private key", severity: "high", pattern: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----", group: 0, config_only: false },
    Rule { id: "aws_access_key", label: "AWS access key", severity: "high", pattern: r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b", group: 1, config_only: false },
    Rule { id: "aws_secret_key", label: "AWS secret key", severity: "high", pattern: r#"(?i)aws_secret_access_key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})"#, group: 1, config_only: false },
    Rule { id: "github_token", label: "GitHub token", severity: "high", pattern: r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b", group: 1, config_only: false },
    Rule { id: "gitlab_token", label: "GitLab token", severity: "high", pattern: r"\b(glpat-[A-Za-z0-9_-]{20,})\b", group: 1, config_only: false },
    Rule { id: "slack_token", label: "Slack token", severity: "high", pattern: r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b", group: 1, config_only: false },
    Rule { id: "stripe_key", label: "Stripe live key", severity: "high", pattern: r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b", group: 1, config_only: false },
    Rule { id: "google_api_key", label: "Google API key", severity: "medium", pattern: r"\b(AIza[0-9A-Za-z_-]{35})\b", group: 1, config_only: false },
    Rule { id: "openai_key", label: "OpenAI API key", severity: "high", pattern: r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{40,})\b", group: 1, config_only: false },
    Rule { id: "anthropic_key", label: "Anthropic API key", severity: "high", pattern: r"\b(sk-ant-[A-Za-z0-9_-]{40,})\b", group: 1, config_only: false },
    Rule { id: "sendgrid_key", label: "SendGrid API key", severity: "high", pattern: r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b", group: 1, config_only: false },
    Rule { id: "azure_storage_key", label: "Azure storage key", severity: "high", pattern: r"AccountKey=([A-Za-z0-9+/=]{80,})", group: 1, config_only: false },
    Rule { id: "database_url", label: "Database password in a connection string", severity: "high", pattern: r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql)://[^:\s/@]+:([^@\s/]{3,})@", group: 1, config_only: false },
    Rule { id: "npm_token", label: "npm token", severity: "high", pattern: r"\b(npm_[A-Za-z0-9]{36})\b", group: 1, config_only: false },
    Rule {
        id: "password_assignment",
        label: "Password or secret in a settings file",
        severity: "medium",
        pattern: r#"(?i)\b(?:password|passwd|pwd|pass|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b["']?\s*[:=]\s*["']?([^\s"'#,;]{8,200})"#,
        group: 1,
        config_only: true,
    },
];

fn compiled() -> &'static Vec<Regex> {
    static COMPILED: OnceLock<Vec<Regex>> = OnceLock::new();
    COMPILED.get_or_init(|| RULES.iter().map(|rule| Regex::new(rule.pattern).expect("valid rule")).collect())
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub path: String,
    pub line: usize,
    pub rule: String,
    pub label: String,
    pub severity: String,
    pub preview: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub findings: Vec<Finding>,
    pub files_scanned: usize,
    pub roots: Vec<String>,
    pub truncated: bool,
}

/// "ghp_1234…(40)" — enough to recognise a secret without showing it.
pub fn mask(value: &str) -> String {
    let count = value.chars().count();
    let shown: String = value.chars().take(if count > 12 { 4 } else { 2 }).collect();
    format!("{shown}… ({count} characters)")
}

/// Values that are obviously not real secrets.
pub fn placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let markers = ["changeme", "change_me", "example", "your_", "your-", "<", ">", "${", "{{", "xxxx", "****", "placeholder", "password123", "process.env", "os.environ", "getenv", "env(", "dummy", "secret_here", "redacted", "todo", "none", "null", "undefined", "true", "false"];
    markers.iter().any(|m| lower.contains(m)) || value.chars().all(|c| c == value.chars().next().unwrap_or('x'))
}

fn config_like(path: &Path) -> bool {
    let name = path.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    name.starts_with(".env") || name.ends_with(".env") || ["env", "ini", "cfg", "conf", "config", "properties", "yml", "yaml", "toml", "json", "txt", "tfvars", "xml", "npmrc", "pypirc", "netrc"].contains(&ext.as_str())
        || ["credentials", ".netrc", ".npmrc", ".pypirc", ".git-credentials"].contains(&name.as_str())
}

/// Should this file be read? (text-like, by name or extension)
pub fn candidate(path: &Path) -> bool {
    let name = path.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    name.starts_with(".env") || name.starts_with("id_") || ["credentials", ".netrc", ".npmrc", ".pypirc", ".git-credentials", "config"].contains(&name.as_str())
        || TEXT_EXTENSIONS.contains(&ext.as_str())
}

/// A file whose name says it stores passwords (spreadsheets and documents are not read).
pub fn named_like_passwords(path: &Path) -> bool {
    let name = path.file_stem().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    let ext = path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    ["password", "passwords", "passwort", "contraseña", "mot de passe", "logins", "credentials", "passcodes"].iter().any(|word| name.contains(word))
        && ["txt", "csv", "xlsx", "xls", "docx", "doc", "rtf", "pages", "numbers", "odt", "ods", "md"].contains(&ext.as_str())
}

/// A browser or password-manager export (CSV with url, username and password columns).
pub fn password_export(path: &Path, first_line: &str) -> bool {
    let header = first_line.to_ascii_lowercase();
    path.extension().is_some_and(|e| e.eq_ignore_ascii_case("csv"))
        && header.contains("password")
        && (header.contains("url") || header.contains("website") || header.contains("login_uri") || header.contains("origin"))
        && (header.contains("username") || header.contains("login") || header.contains("email"))
}

/// An SSH private key without a passphrase (openssh format "none" cipher, or legacy PEM without
/// an ENCRYPTED header).
pub fn unprotected_ssh_key(text: &str) -> bool {
    if text.contains("ENCRYPTED") {
        return false;
    }
    if let Some(start) = text.find("-----BEGIN OPENSSH PRIVATE KEY-----") {
        use base64::Engine;
        let body: String = text[start + 35..].lines().take_while(|l| !l.starts_with("-----END")).collect::<String>().chars().filter(|c| !c.is_whitespace()).collect();
        let prefix: String = body.chars().take(64).collect();
        let usable = &prefix[..prefix.len() - prefix.len() % 4];
        return base64::engine::general_purpose::STANDARD.decode(usable).map(|bytes| bytes.windows(4).any(|w| w == b"none")).unwrap_or(false);
    }
    text.contains("PRIVATE KEY-----")
}

/// Findings in one file's text.
pub fn scan_text(path: &Path, text: &str) -> Vec<Finding> {
    let path_text = path.to_string_lossy().into_owned();
    let first_line = text.lines().next().unwrap_or("");
    if password_export(path, first_line) {
        let rows = text.lines().filter(|l| !l.trim().is_empty()).count().saturating_sub(1);
        return vec![Finding { path: path_text, line: 1, rule: "password_export".into(), label: "Exported passwords (browser or password manager)".into(), severity: "critical".into(), preview: format!("{rows} saved logins") }];
    }
    let config = config_like(path);
    let mut findings = Vec::new();
    let mut seen_private_key = false;
    for (index, line) in text.lines().enumerate() {
        if line.len() > 4096 {
            continue;
        }
        for (rule, regex) in RULES.iter().zip(compiled()) {
            if rule.config_only && !config {
                continue;
            }
            let Some(captures) = regex.captures(line) else { continue };
            let value = captures.get(rule.group).map(|m| m.as_str()).unwrap_or("");
            if rule.id == "private_key" {
                if seen_private_key || !unprotected_ssh_key(text) {
                    continue;
                }
                seen_private_key = true;
            } else if placeholder(value) {
                continue;
            }
            let preview = if rule.id == "private_key" { "unprotected private key".to_string() } else { mask(value) };
            findings.push(Finding { path: path_text.clone(), line: index + 1, rule: rule.id.into(), label: rule.label.into(), severity: rule.severity.into(), preview });
            break;
        }
        if findings.len() >= 20 {
            break;
        }
    }
    findings
}

/// The secret on `line` of `path` for `rule` (only when the person saves it into the vault).
pub fn extract(path: &str, line: usize, rule: &str) -> Option<String> {
    let text = read_text(Path::new(path))?;
    if rule == "private_key" {
        let start = text.find("-----BEGIN")?;
        let end = start + text[start..].find("-----END")?;
        let close = end + 8 + text[end + 8..].find("-----")? + 5;
        return Some(format!("{}\n", &text[start..close]));
    }
    let index = RULES.iter().position(|r| r.id == rule)?;
    let source = text.lines().nth(line.checked_sub(1)?)?;
    compiled()[index].captures(source)?.get(RULES[index].group).map(|m| m.as_str().to_string())
}

fn read_text(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE_BYTES {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    if bytes.iter().take(8192).any(|b| *b == 0) {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// A password export's contents (for importing it into the vault), only for files the scan flagged.
pub fn read_export(path: &str) -> Option<String> {
    let text = read_text(Path::new(path))?;
    password_export(Path::new(path), text.lines().next().unwrap_or("")).then_some(text)
}

/// Folders scanned by default.
pub fn default_roots() -> Vec<PathBuf> {
    let Some(home) = crate::util::home_dir() else { return Vec::new() };
    let mut roots: Vec<PathBuf> = ["Desktop", "Documents", "Downloads", "code", "src", "dev", "projects", "Projects", "repos", "git", "workspace", "source/repos", "go/src", ".ssh", ".aws", ".docker"]
        .iter()
        .map(|name| home.join(name))
        .filter(|path| path.is_dir())
        .collect();
    for file in [".netrc", ".npmrc", ".pypirc", ".git-credentials"] {
        let path = home.join(file);
        if path.is_file() {
            roots.push(path);
        }
    }
    roots
}

pub fn scan(roots: &[PathBuf]) -> Report {
    let started = Instant::now();
    let mut findings = Vec::new();
    let mut files = 0usize;
    let mut truncated = false;
    let mut stack: Vec<(PathBuf, usize)> = roots.iter().map(|r| (r.clone(), 0)).collect();
    while let Some((path, depth)) = stack.pop() {
        if files >= MAX_FILES || findings.len() >= MAX_FINDINGS || started.elapsed() > TIME_LIMIT {
            truncated = true;
            break;
        }
        let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            if depth >= MAX_DEPTH {
                continue;
            }
            let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if depth > 0 && SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            if let Ok(entries) = std::fs::read_dir(&path) {
                for entry in entries.flatten() {
                    stack.push((entry.path(), depth + 1));
                }
            }
            continue;
        }
        files += 1;
        if named_like_passwords(&path) && !candidate(&path) {
            findings.push(Finding { path: path.to_string_lossy().into_owned(), line: 0, rule: "password_file".into(), label: "File named like a password list".into(), severity: "medium".into(), preview: "not opened".into() });
            continue;
        }
        if !candidate(&path) || meta.len() > MAX_FILE_BYTES {
            continue;
        }
        if let Some(text) = read_text(&path) {
            let mut found = scan_text(&path, &text);
            if found.is_empty() && named_like_passwords(&path) {
                found.push(Finding { path: path.to_string_lossy().into_owned(), line: 0, rule: "password_file".into(), label: "File named like a password list".into(), severity: "medium".into(), preview: "check its contents".into() });
            }
            findings.extend(found);
        }
    }
    findings.truncate(MAX_FINDINGS);
    let rank = |s: &str| match s { "critical" => 0, "high" => 1, "medium" => 2, _ => 3 };
    findings.sort_by(|a, b| rank(&a.severity).cmp(&rank(&b.severity)).then(a.path.cmp(&b.path)));
    Report { findings, files_scanned: files, roots: roots.iter().map(|r| r.to_string_lossy().into_owned()).collect(), truncated }
}

/// Moves a file to the system trash (only a regular file inside the person's home folder).
pub fn trash(path: &str) -> Result<(), String> {
    let home = crate::util::home_dir().and_then(|h| h.canonicalize().ok()).ok_or_else(|| "not_allowed".to_string())?;
    let file = Path::new(path).canonicalize().map_err(|_| "not_found".to_string())?;
    if !file.starts_with(&home) || !file.is_file() {
        return Err("not_allowed".into());
    }
    ::trash::delete(&file).map_err(|_| "trash_failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_found(name: &str, text: &str) -> Vec<String> {
        scan_text(Path::new(name), text).into_iter().map(|f| f.rule).collect()
    }

    #[test]
    fn real_looking_secrets_are_found_and_masked() {
        // Test values are split with concat! so the source never contains a token-shaped string.
        let env = concat!("DATABASE_URL=postgres://app:S3cretPassw0rd@db.internal:5432/app\nGITHUB_TOKEN=gh", "p_abcdefghijklmnopqrstuvwxyz0123456789\nPASSWORD=Tr0ub4dor&3xyz\nAPI_KEY=${API_KEY}\n");
        assert_eq!(rules_found("/home/a/app/.env", env), vec!["database_url", "github_token", "password_assignment"]);
        assert_eq!(rules_found("notes.md", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE2"), Vec::<String>::new());
        assert_eq!(rules_found("deploy.sh", concat!("export AWS_ACCESS_KEY_ID=AK", "IAZ7Q3LKX5P2M4N6R8")), vec!["aws_access_key"]);
        let finding = &scan_text(Path::new(".env"), concat!("STRIPE=sk_", "live_51HxyzABCDEFGHIJKLMNOPqrstuv"))[0];
        assert!(finding.preview.starts_with("sk_l…"));
        assert!(!finding.preview.contains("ABCDEFGHIJ"));
    }

    #[test]
    fn code_and_placeholders_stay_quiet() {
        assert!(rules_found("app.py", "password = os.environ['DB_PASSWORD']").is_empty());
        assert!(rules_found("app.js", "const password = 'hunter2hunter2';").is_empty());
        assert!(rules_found("config.yml", "password: changeme123").is_empty());
        assert!(rules_found("settings.ini", "password=xxxxxxxxxx").is_empty());
    }

    #[test]
    fn exports_keys_and_file_names() {
        let csv = "name,url,username,password,note\nGitHub,https://github.com,alice,pw1,\nBank,https://bank.example,alice,pw2,\n";
        let found = scan_text(Path::new("Chrome Passwords.csv"), csv);
        assert_eq!(found[0].rule, "password_export");
        assert_eq!(found[0].preview, "2 saved logins");
        assert!(named_like_passwords(Path::new("/Users/a/Desktop/My Passwords.xlsx")));
        assert!(!named_like_passwords(Path::new("/Users/a/Desktop/report.xlsx")));
        let legacy = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----\n";
        assert_eq!(rules_found("id_rsa", legacy), vec!["private_key"]);
        let protected = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nabc\n-----END RSA PRIVATE KEY-----\n";
        assert!(rules_found("id_rsa", protected).is_empty());
        let pem = crate::sshkey::encode(&crate::sshkey::from_seed([3u8; 32], "x"));
        assert!(unprotected_ssh_key(&pem));
    }

    #[test]
    fn scanning_a_folder_and_extracting_on_request() {
        let dir = std::env::temp_dir().join(format!("px-sprawl-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("node_modules/pkg")).unwrap();
        std::fs::write(dir.join(".env"), concat!("SLACK=xo", "xb-123456789012-abcdefghijkl\n")).unwrap();
        std::fs::write(dir.join("node_modules/pkg/.env"), concat!("SLACK=xo", "xb-999999999999-abcdefghijkl\n")).unwrap();
        std::fs::write(dir.join("photo.png"), [0u8, 1, 2, 3]).unwrap();
        let report = scan(&[dir.clone()]);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule, "slack_token");
        assert_eq!(extract(&report.findings[0].path, 1, "slack_token").as_deref(), Some(concat!("xo", "xb-123456789012-abcdefghijkl")));
        assert!(read_export(&report.findings[0].path).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
