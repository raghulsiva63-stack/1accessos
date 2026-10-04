#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Started by Chrome, Edge or Brave as the extension's native messaging host: relay only.
    if let Some(origin) = passkey_x_lib::browser_host_origin() {
        std::process::exit(passkey_x_lib::run_browser_host(origin));
    }
    passkey_x_lib::run();
}
