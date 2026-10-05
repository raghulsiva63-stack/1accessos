//! pkx — Passkey-X command-line tool.
//!
//!   pkx run [--env NAME=px://…]… [--env-file FILE]… -- <command> [args…]
//!       Runs a command with secrets from the vault as environment variables. Variables that
//!       already hold a px:// reference (in the shell or an env file) are filled in too.
//!   pkx read px://<vault>/<item>/<field>
//!       Prints one secret.
//!
//! Secrets come from the running Passkey-X desktop app after the person approves the request
//! there. Nothing is written to disk.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::ExitCode;

const HELP: &str = "pkx — use Passkey-X secrets from the command line

Usage:
  pkx run [--env NAME=px://Vault/Item/field]... [--env-file FILE]... -- <command> [args...]
  pkx read px://Vault/Item/field
  pkx help

References: px://<item>/<field> or px://<vault>/<item>/<field>.
Fields: password, username, url, notes, totp, or the name of a custom field.
Variables in your shell or env file whose value is a px:// reference are filled in as well.

The Passkey-X desktop app must be running with Settings > This computer > Command-line tool turned on.
Each request is approved in the app.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => run(&args[1..]),
        Some("read") if args.len() == 2 => read(&args[1]),
        Some("--version") | Some("-V") | Some("version") => {
            println!("pkx {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("help") | Some("--help") | Some("-h") | None => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("pkx: unknown command. Run `pkx help`.");
            ExitCode::from(64)
        }
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("pkx: {message}");
    ExitCode::from(1)
}

/// Parses an env file: NAME=value lines, `export` prefixes, quotes and comments.
fn parse_env_file(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            let (name, value) = line.split_once('=')?;
            let name = name.trim();
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return None;
            }
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
                .unwrap_or(value);
            Some((name.to_string(), value.to_string()))
        })
        .collect()
}

fn run(args: &[String]) -> ExitCode {
    let mut variables: BTreeMap<String, String> = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--" => {
                index += 1;
                break;
            }
            "--env" => {
                let Some((name, value)) = args.get(index + 1).and_then(|pair| pair.split_once('=')) else { return fail("--env needs NAME=px://reference") };
                variables.insert(name.to_string(), value.to_string());
                index += 2;
            }
            "--env-file" => {
                let Some(path) = args.get(index + 1) else { return fail("--env-file needs a file") };
                let Ok(text) = std::fs::read_to_string(path) else { return fail(&format!("cannot read {path}")) };
                variables.extend(parse_env_file(&text));
                index += 2;
            }
            _ => break,
        }
    }
    let command = &args[index..];
    if command.is_empty() {
        return fail("nothing to run. Example: pkx run --env DB_PASSWORD=px://Work/Database/password -- npm start");
    }
    // Shell variables holding a reference are resolved too (explicit options win).
    for (name, value) in std::env::vars() {
        if value.starts_with("px://") {
            variables.entry(name).or_insert(value);
        }
    }
    let mut refs: Vec<String> = variables.values().filter(|v| v.starts_with("px://")).cloned().collect();
    refs.sort();
    refs.dedup();
    let mut values = BTreeMap::new();
    if !refs.is_empty() {
        match resolve(&refs, &command.join(" ")) {
            Ok(resolved) => values = resolved,
            Err(message) => return fail(&message),
        }
    }
    let mut child = std::process::Command::new(&command[0]);
    child.args(&command[1..]);
    for (name, value) in &variables {
        let actual = values.get(value).unwrap_or(value);
        child.env(name, actual);
    }
    drop(values);
    match child.status() {
        Ok(status) => ExitCode::from(status.code().unwrap_or(1).clamp(0, 255) as u8),
        Err(_) => fail(&format!("could not start {}", command[0])),
    }
}

fn read(reference: &str) -> ExitCode {
    match resolve(&[reference.to_string()], &format!("pkx read {reference}")) {
        Ok(values) => match values.get(reference) {
            Some(value) => {
                let mut out = std::io::stdout();
                let _ = out.write_all(value.as_bytes());
                let _ = out.write_all(b"\n");
                ExitCode::SUCCESS
            }
            None => fail("not found"),
        },
        Err(message) => fail(&message),
    }
}

fn explain(error: &str) -> String {
    match error {
        "denied" => "the request was declined in Passkey-X".into(),
        "timeout" => "no answer from Passkey-X (approve the request in the app)".into(),
        "locked" => "unlock Passkey-X and try again".into(),
        "not_found" => "a reference did not match any item or field".into(),
        "ambiguous" => "a reference matches more than one item; add the vault name: px://Vault/Item/field".into(),
        "invalid_reference" => "references look like px://Vault/Item/field".into(),
        other => format!("Passkey-X could not answer ({other})"),
    }
}

fn resolve(refs: &[String], command: &str) -> Result<BTreeMap<String, String>, String> {
    let cwd = std::env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let request = serde_json::json!({ "type": "resolve", "refs": refs, "command": command, "cwd": cwd });
    let body = serde_json::to_vec(&request).map_err(|_| "internal error".to_string())?;
    let mut stream = connect()?;
    stream.write_all(&(body.len() as u32).to_be_bytes()).and_then(|_| stream.write_all(&body)).and_then(|_| stream.flush()).map_err(|_| "lost connection to Passkey-X".to_string())?;
    eprintln!("pkx: approve the request in Passkey-X…");
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).map_err(|_| "no answer from Passkey-X".to_string())?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > 1024 * 1024 {
        return Err("invalid answer from Passkey-X".into());
    }
    let mut reply = zeroize::Zeroizing::new(vec![0u8; length]);
    stream.read_exact(&mut reply).map_err(|_| "no answer from Passkey-X".to_string())?;
    let value: serde_json::Value = serde_json::from_slice(&reply).map_err(|_| "invalid answer from Passkey-X".to_string())?;
    if value["ok"] != true {
        return Err(explain(value["error"].as_str().unwrap_or("error")));
    }
    let values = value["values"].as_object().ok_or_else(|| "invalid answer from Passkey-X".to_string())?;
    Ok(values.iter().filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string()))).collect())
}

trait Stream: Read + Write {}
impl<T: Read + Write> Stream for T {}

const NOT_RUNNING: &str = "Passkey-X desktop isn't running, or its command-line tool is off (Settings > This computer > Command-line tool).";

#[cfg(unix)]
fn connect() -> Result<Box<dyn Stream>, String> {
    let path = passkey_x_lib::cli_endpoint().ok_or_else(|| NOT_RUNNING.to_string())?;
    std::os::unix::net::UnixStream::connect(path).map(|s| Box::new(s) as Box<dyn Stream>).map_err(|_| NOT_RUNNING.to_string())
}

#[cfg(windows)]
fn connect() -> Result<Box<dyn Stream>, String> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
    let path = passkey_x_lib::cli_endpoint().ok_or_else(|| NOT_RUNNING.to_string())?;
    let file = std::fs::OpenOptions::new().read(true).write(true).open(&path).map_err(|_| NOT_RUNNING.to_string())?;
    // Only talk to the Passkey-X app installed next to this tool.
    let mut pid = 0u32;
    unsafe { GetNamedPipeServerProcessId(HANDLE(file.as_raw_handle()), &mut pid) }.map_err(|_| NOT_RUNNING.to_string())?;
    let server = passkey_x_lib::process_path(pid).ok_or_else(|| NOT_RUNNING.to_string())?;
    let ours = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf()));
    let same_folder = ours.is_some_and(|dir| server.parent().is_some_and(|parent| parent.to_string_lossy().eq_ignore_ascii_case(&dir.to_string_lossy())));
    if !same_folder {
        return Err("the program answering is not the Passkey-X app installed with pkx".into());
    }
    Ok(Box::new(file))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_files_are_parsed_like_dotenv() {
        let parsed = parse_env_file("# comment\nexport DB_PASSWORD=\"px://Work/DB/password\"\nPORT=3000\nTOKEN='px://GitHub/token'\nbad line\n1X=2\n");
        assert_eq!(parsed, vec![
            ("DB_PASSWORD".to_string(), "px://Work/DB/password".to_string()),
            ("PORT".to_string(), "3000".to_string()),
            ("TOKEN".to_string(), "px://GitHub/token".to_string()),
            ("1X".to_string(), "2".to_string()),
        ]);
    }
}
