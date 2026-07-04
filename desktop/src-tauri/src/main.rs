// Prevents an additional console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod paths;
mod profiles;
mod runner;
mod settings;
mod uri;

use std::sync::Mutex;

/// Shared app state: serializes connect/disconnect so two calls can't race.
pub struct AppState {
    pub lock: Mutex<()>,
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            lock: Mutex::new(()),
        })
        .invoke_handler(tauri::generate_handler![
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
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
