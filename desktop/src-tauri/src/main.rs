// Prevents an additional console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod helper;
mod helper_ipc;
#[cfg(target_os = "macos")]
mod macos_native;
mod paths;
mod profiles;
mod reconnect;
mod runner;
mod settings;
mod uri;

use std::sync::Mutex;

/// Shared app state: serializes connect/disconnect so two calls can't race.
pub struct AppState {
    pub lock: Mutex<()>,
    /// The profile that is *supposed* to be up: set by `connect`, cleared by
    /// `disconnect`. When the client dies while this is set, the reconnect
    /// watcher brings it back (see `reconnect`).
    pub active_profile: Mutex<Option<String>>,
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            lock: Mutex::new(()),
            active_profile: Mutex::new(None),
        })
        .setup(|app| {
            reconnect::spawn(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            helper::init_privileges,
            helper::daemon_info,
            helper::daemon_install,
            helper::daemon_uninstall,
            profiles::list_profiles,
            profiles::get_profile,
            profiles::save_profile,
            profiles::delete_profile,
            runner::connect,
            runner::disconnect,
            runner::status,
            runner::read_log,
            settings::get_settings,
            settings::save_settings,
            uri::import_uri,
            uri::export_uri,
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| {
            // Tear the elevated helper down when the app exits idle; it stays
            // alive (promptless reconnect/disconnect) while a tunnel runs.
            if let tauri::RunEvent::Exit = event {
                helper::on_app_exit(app_handle);
            }
        });
}
