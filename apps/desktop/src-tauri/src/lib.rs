//! Passkey-X desktop.
//!
//! The vault UI is bundled inside the app (dist/, built from apps/web) and runs on the app's
//! own local origin; the app never loads passkey-x.com or any other site in its window.
//! Native features are exposed only to those bundled pages through the commands below
//! (see capabilities/desktop.json):
//! * sign-in session kept encrypted with a key in the system keychain;
//! * fingerprint/face unlock (Windows Hello, Touch ID);
//! * clipboard that hides secrets from history and wipes them;
//! * screen-capture protection, lock on sleep / screen lock / quit / optional app switch;
//! * a global quick-access shortcut;
//! * browser sign-in handoff via a one-shot 127.0.0.1 listener (RFC 8252);
//! * signed automatic updates (when built with a signing key).

mod biometric;
mod clipboard;
mod crypto;
mod guard;
mod loopback;
mod secure_store;
mod settings;

use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::TrayIconBuilder;
use tauri::webview::{DownloadEvent, NewWindowResponse};
use tauri::{AppHandle, Manager, State, Url, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};
use tauri_plugin_opener::OpenerExt;

const MAIN: &str = "main";
const DOWNLOADS: &str = "https://passkey-x.com/download";
const LOCK: &str = "window.dispatchEvent(new Event('passkey-x:lock'));";
const QUICK: &str = "window.dispatchEvent(new Event('passkey-x:open-quick-access'));";
const ADD: &str = "window.dispatchEvent(new Event('passkey-x:add-login'));";

pub struct AppState {
    settings: settings::SettingsStore,
    store: secure_store::SecureStore,
    clipboard: Arc<clipboard::SecretClipboard>,
    unlock_dir: PathBuf,
    quick_mode: AtomicBool,
    hotkey_active: AtomicBool,
    has_tray: AtomicBool,
    /// A Windows Hello / Touch ID prompt is open: its window takes focus, which must not lock or hide the vault.
    native_prompt: AtomicBool,
    sign_in: loopback::Loopback,
}

// ---------------------------------------------------------------------------
// URL policy
// ---------------------------------------------------------------------------

/// The app's own bundled pages: http://tauri.localhost on Windows, tauri://localhost elsewhere.
/// (On macOS/Linux http://tauri.localhost would be a real loopback server, so it is not ours.)
fn local(url: &Url) -> bool {
    let ours = if cfg!(target_os = "windows") {
        url.scheme() == "http" && url.host_str() == Some("tauri.localhost")
    } else {
        url.scheme() == "tauri" && url.host_str() == Some("localhost")
    };
    ours && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

/// Links that may be handed to the default browser.
fn external(url: &Url) -> bool {
    matches!(url.scheme(), "https" | "http")
        && url.host_str().is_some_and(|host| host != "tauri.localhost")
        && !local(url)
        && url.username().is_empty()
        && url.password().is_none()
}

// ---------------------------------------------------------------------------
// Window helpers
// ---------------------------------------------------------------------------

fn eval(app: &AppHandle, script: &str) {
    if let Some(window) = app.get_webview_window(MAIN) {
        let _ = window.eval(script);
    }
}

fn lock(app: &AppHandle) {
    eval(app, LOCK);
    if let Some(state) = app.try_state::<AppState>() {
        state.clipboard.clear_if_ours();
    }
}

fn show(app: &AppHandle, compact: Option<bool>) {
    if let Some(window) = app.get_webview_window(MAIN) {
        let _ = window.unminimize();
        if let Some(compact) = compact {
            let _ = window.set_size(tauri::LogicalSize::new(if compact { 480.0 } else { 1240.0 }, 820.0));
        }
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// After a system prompt closes, bring the vault window back to the front.
fn refocus(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN) {
        let _ = window.set_focus();
    }
}

fn end_quick(app: &AppHandle, hide: bool) {
    let state = app.state::<AppState>();
    if state.quick_mode.swap(false, Ordering::SeqCst) {
        if let Some(window) = app.get_webview_window(MAIN) {
            let _ = window.set_always_on_top(false);
            if hide {
                let _ = window.hide();
            }
        }
    }
}

fn quick_access(app: &AppHandle) {
    let state = app.state::<AppState>();
    state.quick_mode.store(true, Ordering::SeqCst);
    show(app, Some(true));
    if let Some(window) = app.get_webview_window(MAIN) {
        let _ = window.set_always_on_top(true);
    }
    eval(app, QUICK);
}

fn hotkey() -> Shortcut {
    #[cfg(target_os = "macos")]
    let modifiers = Modifiers::SUPER | Modifiers::SHIFT;
    #[cfg(not(target_os = "macos"))]
    let modifiers = Modifiers::CONTROL | Modifiers::SHIFT;
    Shortcut::new(Some(modifiers), Code::Space)
}

fn hotkey_label() -> &'static str {
    if cfg!(target_os = "macos") { "⌘⇧Space" } else { "Ctrl+Shift+Space" }
}

fn apply_hotkey(app: &AppHandle, enabled: bool) {
    let state = app.state::<AppState>();
    let shortcuts = app.global_shortcut();
    let _ = shortcuts.unregister(hotkey());
    let active = enabled && shortcuts.register(hotkey()).is_ok();
    state.hotkey_active.store(active, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Commands (bundled pages only)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopInfo {
    version: String,
    os: &'static str,
    biometric: Option<&'static str>,
    secure_storage: bool,
    hotkey: Option<&'static str>,
    hotkey_active: bool,
    updater: bool,
    content_protection: bool,
}

#[tauri::command]
async fn desktop_info(app: AppHandle, state: State<'_, AppState>) -> Result<DesktopInfo, String> {
    let secure_storage = state.store.is_persistent();
    let biometric = tauri::async_runtime::spawn_blocking(biometric::kind).await.unwrap_or(None);
    Ok(DesktopInfo {
        version: app.package_info().version.to_string(),
        os: if cfg!(target_os = "macos") { "macos" } else if cfg!(target_os = "windows") { "windows" } else { "linux" },
        biometric,
        secure_storage,
        hotkey: Some(hotkey_label()),
        hotkey_active: state.hotkey_active.load(Ordering::SeqCst),
        updater: cfg!(feature = "updater"),
        content_protection: cfg!(any(target_os = "macos", target_os = "windows")),
    })
}

#[tauri::command]
fn desktop_settings_get(state: State<'_, AppState>) -> settings::Settings {
    state.settings.get()
}

#[tauri::command]
fn desktop_settings_set(app: AppHandle, state: State<'_, AppState>, settings: settings::Settings) -> Result<settings::Settings, String> {
    let before = state.settings.get();
    let saved = state.settings.set(settings)?;
    if before.hotkey_enabled != saved.hotkey_enabled {
        apply_hotkey(&app, saved.hotkey_enabled);
    }
    Ok(saved)
}

#[tauri::command]
async fn secure_get(state: State<'_, AppState>, key: String) -> Result<Option<String>, String> {
    Ok(state.store.get(&key))
}

#[tauri::command]
async fn secure_set(state: State<'_, AppState>, key: String, value: String) -> Result<(), String> {
    state.store.set(&key, value)
}

#[tauri::command]
async fn secure_remove(state: State<'_, AppState>, key: String) -> Result<(), String> {
    state.store.remove(&key);
    Ok(())
}

#[tauri::command]
fn clipboard_copy(app: AppHandle, state: State<'_, AppState>, text: String, clear_seconds: u64) -> Result<(), String> {
    let limit = state.settings.get().clipboard_seconds;
    state.clipboard.copy(text, clear_seconds.min(limit))?;
    // Opened with the shortcut: get out of the way so the person can paste.
    end_quick(&app, true);
    Ok(())
}

#[tauri::command]
fn clipboard_clear(state: State<'_, AppState>) {
    state.clipboard.clear_if_ours();
}

#[tauri::command]
fn quick_hide(app: AppHandle) {
    end_quick(&app, true);
}

/// Starts the one-shot 127.0.0.1 listener for the browser sign-in and returns its port.
#[tauri::command]
fn sign_in_listen(app: AppHandle, state: State<'_, AppState>, state_token: String) -> Result<u16, String> {
    let app = app.clone();
    state.sign_in.listen(state_token, move |code, state| {
        let target = app.clone();
        let _ = app.run_on_main_thread(move || {
            show(&target, None);
            // Both values were checked to be [A-Za-z0-9_-] only.
            eval(&target, &format!(
                "window.dispatchEvent(new CustomEvent('passkey-x:handoff',{{detail:{{code:'{code}',state:'{state}'}}}}));"
            ));
        });
    })
}

#[tauri::command]
async fn update_check(app: AppHandle) -> Result<&'static str, String> {
    updates::check(app, true).await
}

#[tauri::command]
async fn biometric_enrolled(state: State<'_, AppState>, account: String, fingerprint: String) -> Result<bool, String> {
    let dir = state.unlock_dir.clone();
    tauri::async_runtime::spawn_blocking(move || biometric::enrolled(&dir, &account, &fingerprint))
        .await
        .map_err(|_| "unavailable".to_string())
}

#[tauri::command]
async fn biometric_enroll(app: AppHandle, state: State<'_, AppState>, account: String, secret: String, fingerprint: String) -> Result<(), String> {
    let dir = state.unlock_dir.clone();
    let secret = zeroize::Zeroizing::new(secret);
    state.native_prompt.store(true, Ordering::SeqCst);
    let result = tauri::async_runtime::spawn_blocking(move || biometric::enroll(&dir, &account, &secret, &fingerprint))
        .await
        .map_err(|_| "unavailable".to_string());
    state.native_prompt.store(false, Ordering::SeqCst);
    refocus(&app);
    result?
}

#[tauri::command]
async fn biometric_unlock(app: AppHandle, state: State<'_, AppState>, account: String, fingerprint: String) -> Result<Option<String>, String> {
    let dir = state.unlock_dir.clone();
    state.native_prompt.store(true, Ordering::SeqCst);
    let result = tauri::async_runtime::spawn_blocking(move || biometric::unlock(&dir, &account, &fingerprint))
        .await
        .map_err(|_| "unavailable".to_string());
    state.native_prompt.store(false, Ordering::SeqCst);
    refocus(&app);
    result?
}

#[tauri::command]
async fn biometric_remove(state: State<'_, AppState>, account: String) -> Result<(), String> {
    let dir = state.unlock_dir.clone();
    tauri::async_runtime::spawn_blocking(move || biometric::remove(&dir, &account))
        .await
        .map_err(|_| "unavailable".to_string())
}

// ---------------------------------------------------------------------------
// Updates
// ---------------------------------------------------------------------------

#[cfg(feature = "updater")]
mod updates {
    use tauri::AppHandle;
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
    use tauri_plugin_updater::UpdaterExt;

    /// Checks the signed update feed. Updates whose signature does not match the public key
    /// built into the app are rejected by the updater.
    pub async fn check(app: AppHandle, interactive: bool) -> Result<&'static str, String> {
        let updater = app.updater().map_err(|_| "unavailable".to_string())?;
        let Some(update) = updater.check().await.map_err(|_| "unavailable".to_string())? else { return Ok("none") };
        let version = update.version.clone();
        let prompt = app.clone();
        let install = tauri::async_runtime::spawn_blocking(move || {
            prompt
                .dialog()
                .message(format!("Passkey-X {version} is available. Your vault will lock and the app will restart."))
                .title("Update Passkey-X")
                .buttons(MessageDialogButtons::OkCancelCustom("Install and restart".into(), "Later".into()))
                .blocking_show()
        })
        .await
        .unwrap_or(false);
        if !install {
            return Ok(if interactive { "declined" } else { "none" });
        }
        super::lock(&app);
        update.download_and_install(|_, _| {}, || {}).await.map_err(|_| "unavailable".to_string())?;
        app.restart();
    }
}

#[cfg(not(feature = "updater"))]
mod updates {
    use tauri::AppHandle;
    pub async fn check(_app: AppHandle, _interactive: bool) -> Result<&'static str, String> {
        Ok("unavailable")
    }
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

pub fn run() {
    let mut builder = tauri::Builder::default()
        // Must be first: a second launch focuses the running app.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show(app, None)))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, shortcut, event| {
                    if event.state() == ShortcutState::Pressed && *shortcut == hotkey() {
                        quick_access(app);
                    }
                })
                .build(),
        );
    #[cfg(feature = "updater")]
    {
        builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
    }
    builder = builder.invoke_handler(tauri::generate_handler![
        desktop_info,
        desktop_settings_get,
        desktop_settings_set,
        secure_get,
        secure_set,
        secure_remove,
        clipboard_copy,
        clipboard_clear,
        quick_hide,
        sign_in_listen,
        update_check,
        biometric_enrolled,
        biometric_enroll,
        biometric_unlock,
        biometric_remove,
    ]);

    builder
        .setup(|app| {
            let handle = app.handle().clone();
            let config_dir = app.path().app_config_dir().ok();
            let data_dir = app.path().app_data_dir().ok();
            app.manage(AppState {
                settings: settings::SettingsStore::load(config_dir.map(|d| d.join("settings.json"))),
                store: secure_store::SecureStore::new(data_dir.as_ref().map(|d| d.join("session.json"))),
                clipboard: Arc::new(clipboard::SecretClipboard::default()),
                unlock_dir: data_dir.unwrap_or_else(std::env::temp_dir).join("unlock"),
                quick_mode: AtomicBool::new(false),
                hotkey_active: AtomicBool::new(false),
                has_tray: AtomicBool::new(false),
                native_prompt: AtomicBool::new(false),
                sign_in: loopback::Loopback::default(),
            });

            // Menus
            let quick = MenuItem::with_id(&handle, "palette", "Quick access", true, Some("CmdOrCtrl+K"))?;
            let add = MenuItem::with_id(&handle, "add", "Add a login", true, Some("CmdOrCtrl+Shift+N"))?;
            let compact = MenuItem::with_id(&handle, "compact", "Compact window", true, None::<&str>)?;
            let full = MenuItem::with_id(&handle, "full", "Full window", true, None::<&str>)?;
            let hide = MenuItem::with_id(&handle, "hide", "Lock and hide", true, None::<&str>)?;
            let lock_item = MenuItem::with_id(&handle, "lock", "Lock vault", true, Some("CmdOrCtrl+L"))?;
            let updates = MenuItem::with_id(&handle, "updates", "Check for updates…", true, None::<&str>)?;
            let extension = MenuItem::with_id(&handle, "extension", "Get the browser extension", true, None::<&str>)?;
            let menu = Menu::with_items(&handle, &[
                &Submenu::with_items(&handle, "Passkey-X", true, &[
                    &quick, &add, &PredefinedMenuItem::separator(&handle)?,
                    &compact, &full, &hide, &lock_item, &PredefinedMenuItem::separator(&handle)?,
                    &updates, &extension, &PredefinedMenuItem::separator(&handle)?,
                    &PredefinedMenuItem::quit(&handle, None)?,
                ])?,
                &Submenu::with_items(&handle, "Edit", true, &[
                    &PredefinedMenuItem::undo(&handle, None)?, &PredefinedMenuItem::redo(&handle, None)?,
                    &PredefinedMenuItem::separator(&handle)?, &PredefinedMenuItem::cut(&handle, None)?,
                    &PredefinedMenuItem::copy(&handle, None)?, &PredefinedMenuItem::paste(&handle, None)?,
                    &PredefinedMenuItem::select_all(&handle, None)?,
                ])?,
            ])?;
            app.set_menu(menu)?;
            let tray_menu = Menu::with_items(&handle, &[
                &MenuItem::with_id(&handle, "quick", "Quick access", true, None::<&str>)?,
                &MenuItem::with_id(&handle, "full", "Open Passkey-X", true, None::<&str>)?,
                &MenuItem::with_id(&handle, "lock", "Lock vault", true, None::<&str>)?,
                &MenuItem::with_id(&handle, "quit", "Quit Passkey-X", true, None::<&str>)?,
            ])?;
            // Some Linux desktops have no tray host; the app then closes normally.
            let has_tray = app.default_window_icon().is_some_and(|icon| {
                TrayIconBuilder::new()
                    .icon(icon.clone())
                    .tooltip("Passkey-X")
                    .menu(&tray_menu)
                    .show_menu_on_left_click(true)
                    .build(app)
                    .is_ok()
            });
            app.state::<AppState>().has_tray.store(has_tray, Ordering::SeqCst);

            // Main window: bundled pages only.
            let navigation_app = handle.clone();
            let new_window_app = handle.clone();
            let window = WebviewWindowBuilder::new(app, MAIN, WebviewUrl::App("index.html".into()))
                .title("Passkey-X")
                .inner_size(1240.0, 820.0)
                .min_inner_size(380.0, 560.0)
                .content_protected(true)
                .devtools(cfg!(debug_assertions))
                .on_navigation(move |url| {
                    if local(url) {
                        return true;
                    }
                    if external(url) {
                        let _ = navigation_app.opener().open_url(url.as_str(), None::<&str>);
                    }
                    false
                })
                .on_new_window(move |url, _| {
                    if external(&url) {
                        let _ = new_window_app.opener().open_url(url.as_str(), None::<&str>);
                    }
                    NewWindowResponse::Deny
                })
                .on_download(|webview, event| {
                    if let DownloadEvent::Requested { url, destination } = event {
                        // Recovery and export files are created by the bundled vault pages as blob: URLs.
                        let trusted = url.scheme() == "blob" && Url::parse(url.path()).map(|inner| local(&inner)).unwrap_or(false);
                        if !trusted {
                            return false;
                        }
                        let Ok(directory) = webview.app_handle().path().download_dir() else { return false };
                        let filename = destination.file_name().and_then(|n| n.to_str()).unwrap_or("passkey-x-export.json");
                        let name: String = filename
                            .chars()
                            .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
                            .take(150)
                            .collect();
                        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis();
                        *destination = directory.join(format!("passkey-x-{stamp}-{name}"));
                    }
                    true
                })
                .build()?;

            let events_app = handle.clone();
            window.on_window_event(move |event| match event {
                WindowEvent::Focused(false) => {
                    let state = events_app.state::<AppState>();
                    if state.native_prompt.load(Ordering::SeqCst) {
                        // The Windows Hello / Touch ID prompt has focus.
                    } else if state.quick_mode.load(Ordering::SeqCst) {
                        end_quick(&events_app, true);
                    } else if state.settings.get().lock_on_blur {
                        lock(&events_app);
                    }
                }
                WindowEvent::CloseRequested { api, .. } => {
                    lock(&events_app);
                    end_quick(&events_app, false);
                    if events_app.state::<AppState>().has_tray.load(Ordering::SeqCst) {
                        api.prevent_close();
                        if let Some(window) = events_app.get_webview_window(MAIN) {
                            let _ = window.hide();
                        }
                    }
                }
                _ => {}
            });

            // Sleep and screen lock.
            let guard_app = handle.clone();
            guard::watch(move |_reason| {
                let app = guard_app.clone();
                let _ = guard_app.run_on_main_thread(move || lock(&app));
            });

            // Quick-access shortcut.
            apply_hotkey(&handle, app.state::<AppState>().settings.get().hotkey_enabled);

            // Background update check shortly after start.
            #[cfg(feature = "updater")]
            {
                let update_app = handle.clone();
                tauri::async_runtime::spawn(async move {
                    tokio_sleep(std::time::Duration::from_secs(20)).await;
                    let _ = updates::check(update_app, false).await;
                });
            }
            Ok(())
        })
        .on_menu_event(|app, event| match event.id().as_ref() {
            "quick" => quick_access(app),
            "palette" => {
                show(app, None);
                eval(app, QUICK);
            }
            "compact" => show(app, Some(true)),
            "full" => show(app, Some(false)),
            "add" => {
                show(app, None);
                eval(app, ADD);
            }
            "hide" => {
                lock(app);
                if let Some(window) = app.get_webview_window(MAIN) {
                    let _ = window.hide();
                }
            }
            "lock" => lock(app),
            "quit" => {
                lock(app);
                app.exit(0);
            }
            "updates" => {
                if cfg!(feature = "updater") {
                    let app = app.clone();
                    tauri::async_runtime::spawn(async move {
                        let _ = updates::check(app, true).await;
                    });
                } else {
                    let _ = app.opener().open_url(DOWNLOADS, None::<&str>);
                }
            }
            "extension" => {
                let _ = app.opener().open_url(DOWNLOADS, None::<&str>);
            }
            _ => {}
        })
        .build(tauri::generate_context!())
        .expect("Passkey-X desktop failed to start")
        .run(|app, event| {
            if let tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit = event {
                if let Some(state) = app.try_state::<AppState>() {
                    state.clipboard.clear_if_ours();
                }
            }
        });
}

#[cfg(feature = "updater")]
async fn tokio_sleep(duration: std::time::Duration) {
    let _ = tauri::async_runtime::spawn_blocking(move || std::thread::sleep(duration)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_bundled_pages_run_in_the_window() {
        let (ours, other) = if cfg!(target_os = "windows") {
            ("http://tauri.localhost/index.html", "tauri://localhost/index.html")
        } else {
            ("tauri://localhost/index.html", "http://tauri.localhost/index.html")
        };
        assert!(local(&ours.parse().unwrap()));
        assert!(!local(&other.parse().unwrap()));
        for value in [
            "https://passkey-x.com/",
            "http://tauri.localhost:3000/",
            "http://tauri.localhost.attacker.test/",
            "tauri://localhost.attacker.test/",
            "http://user@tauri.localhost/",
            "file:///etc/passwd",
        ] {
            assert!(!local(&value.parse().unwrap()), "{value}");
        }
    }

    #[test]
    fn external_links_cannot_launch_local_programs() {
        assert!(external(&"https://passkey-x.com/download".parse().unwrap()));
        for value in ["file:///tmp/test", "javascript:alert(1)", "data:text/html,test", "ms-settings:privacy", "https://user:password@example.test", "http://tauri.localhost/"] {
            assert!(!external(&value.parse().unwrap()), "{value}");
        }
    }
}
