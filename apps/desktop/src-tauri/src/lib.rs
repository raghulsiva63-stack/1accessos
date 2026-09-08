use tauri::{Manager, Url, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::webview::{DownloadEvent, NewWindowResponse};
use tauri_plugin_opener::OpenerExt;

const VAULT: &str = "https://passkey-x.com/#access";
const DOWNLOADS: &str = "https://passkey-x.com/download";
const LOCK: &str = "window.dispatchEvent(new Event('passkey-x:lock'));";

fn official(url: &Url) -> bool {
    url.scheme() == "https" && url.host_str() == Some("passkey-x.com")
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty() && url.password().is_none()
}

fn launcher(url: &Url) -> bool {
    ((url.scheme() == "tauri" && url.host_str() == Some("localhost"))
        || (url.scheme() == "http" && url.host_str() == Some("tauri.localhost")))
        && url.port().is_none() && url.username().is_empty() && url.password().is_none()
        && matches!(url.path(), "/" | "/index.html")
}

fn external(url: &Url) -> bool {
    matches!(url.scheme(), "https" | "http") && url.host_str().is_some()
        && url.username().is_empty() && url.password().is_none()
}

fn lock(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.eval(LOCK);
    }
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let handle = app.handle();
            let lock_item = MenuItem::with_id(handle, "lock", "Lock vault", true, Some("CmdOrCtrl+L"))?;
            let reload = MenuItem::with_id(handle, "reload", "Reload vault", true, Some("CmdOrCtrl+R"))?;
            let browser = MenuItem::with_id(handle, "browser", "Open in browser", true, None::<&str>)?;
            let extension = MenuItem::with_id(handle, "extension", "Get browser extension", true, None::<&str>)?;
            let help = MenuItem::with_id(handle, "connection", "Connection help", true, None::<&str>)?;
            let menu = Menu::with_items(handle, &[
                &Submenu::with_items(handle, "Passkey-X", true, &[
                    &lock_item, &reload, &PredefinedMenuItem::separator(handle)?,
                    &browser, &extension, &help, &PredefinedMenuItem::separator(handle)?,
                    &PredefinedMenuItem::quit(handle, None)?,
                ])?,
                &Submenu::with_items(handle, "Edit", true, &[
                    &PredefinedMenuItem::undo(handle, None)?, &PredefinedMenuItem::redo(handle, None)?,
                    &PredefinedMenuItem::separator(handle)?, &PredefinedMenuItem::cut(handle, None)?,
                    &PredefinedMenuItem::copy(handle, None)?, &PredefinedMenuItem::paste(handle, None)?,
                    &PredefinedMenuItem::select_all(handle, None)?,
                ])?,
            ])?;
            app.set_menu(menu)?;
            let navigation_app = handle.clone();
            let new_window_app = handle.clone();
            let window = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("Passkey-X")
                .inner_size(1240.0, 820.0).min_inner_size(860.0, 620.0)
                .devtools(false)
                .on_navigation(move |url| {
                    if official(url) || launcher(url) { return true; }
                    if external(url) { let _ = navigation_app.opener().open_url(url.as_str(), None::<&str>); }
                    false
                })
                .on_new_window(move |url, _| {
                    if external(&url) { let _ = new_window_app.opener().open_url(url.as_str(), None::<&str>); }
                    NewWindowResponse::Deny
                })
                .on_download(|webview, event| {
                    if let DownloadEvent::Requested { url, destination } = event {
                        // Recovery-key and export downloads are produced by the trusted vault.
                        // Never allow a download to choose a path outside Downloads or overwrite.
                        let trusted_blob = url.scheme() == "blob"
                            && Url::parse(url.path()).map(|u| official(&u)).unwrap_or(false);
                        if !official(&url) && !trusted_blob { return false; }
                        let Ok(directory) = webview.app_handle().path().download_dir() else { return false; };
                        let filename = destination.file_name().and_then(|n| n.to_str()).unwrap_or("passkey-x-export.json");
                        let name: String = filename.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' }).take(150).collect();
                        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
                        *destination = directory.join(format!("passkey-x-{stamp}-{name}"));
                    }
                    true
                })
                .build()?;
            let focus_app = handle.clone();
            window.on_window_event(move |event| {
                if matches!(event, WindowEvent::Focused(false) | WindowEvent::CloseRequested { .. }) {
                    lock(&focus_app);
                }
            });
            Ok(())
        })
        .on_menu_event(|app, event| {
            match event.id().as_ref() {
                "lock" => lock(app),
                "reload" => {
                    lock(app);
                    if let Some(window) = app.get_webview_window("main") { let _ = window.navigate(VAULT.parse().unwrap()); }
                },
                "browser" => { lock(app); let _ = app.opener().open_url(VAULT, None::<&str>); },
                "extension" => { lock(app); let _ = app.opener().open_url(DOWNLOADS, None::<&str>); },
                "connection" => {
                    lock(app);
                    if let Some(window) = app.get_webview_window("main") {
                        let local = if cfg!(target_os = "windows") { "http://tauri.localhost/index.html" } else { "tauri://localhost/index.html" };
                        let _ = window.navigate(local.parse().unwrap());
                    }
                },
                _ => {},
            }
        })
        .run(tauri::generate_context!())
        .expect("Passkey-X desktop runtime failed");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_exact_vault_origin_can_run_in_the_app() {
        assert!(official(&VAULT.parse().unwrap()));
        for value in ["https://passkey-x.com.attacker.test", "http://passkey-x.com", "https://passkey-x.com:444", "https://user@passkey-x.com", "file:///etc/passwd", "javascript:alert(1)"] {
            assert!(!official(&value.parse().unwrap()));
        }
    }
    #[test]
    fn external_links_cannot_launch_local_programs() {
        assert!(external(&"https://example.test".parse().unwrap()));
        for value in ["file:///tmp/test", "javascript:alert(1)", "data:text/html,test", "ms-settings:privacy", "https://user:password@example.test"] {
            assert!(!external(&value.parse().unwrap()));
        }
    }
    #[test]
    fn local_navigation_is_limited_to_the_launcher() {
        assert!(launcher(&"tauri://localhost/index.html".parse().unwrap()));
        assert!(launcher(&"http://tauri.localhost/".parse().unwrap()));
        assert!(!launcher(&"http://tauri.localhost:3000/".parse().unwrap()));
        assert!(!launcher(&"tauri://localhost/private.html".parse().unwrap()));
    }
}
