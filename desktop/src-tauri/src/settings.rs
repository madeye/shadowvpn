//! App settings (currently just the client binary path) + resolution order.

use serde::{Deserialize, Serialize};

use crate::paths;

#[derive(Serialize, Deserialize, Default)]
pub struct Settings {
    pub client_bin: Option<String>,
}

#[derive(Serialize)]
pub struct SettingsInfo {
    pub client_bin: Option<String>,
    pub resolved_client_bin: Option<String>,
    /// "settings" | "app_dir" | "dev_default" | null
    pub resolved_from: Option<String>,
    /// Full paths to policy data files bundled next to the resolved client
    /// binary, when present. These are what the client auto-discovers (and the
    /// UI shows) when a profile leaves the corresponding path field blank.
    pub bundled_gfwlist: Option<String>,
    pub bundled_chnroute: Option<String>,
    pub bundled_geoip: Option<String>,
}

/// The full path to `name` next to the resolved client binary, if it exists.
fn bundled_path(resolved_client_bin: Option<&str>, name: &str) -> Option<String> {
    let dir = std::path::Path::new(resolved_client_bin?).parent()?;
    let path = dir.join(name);
    path.is_file().then(|| path.to_string_lossy().to_string())
}

fn load_settings(app: &tauri::AppHandle) -> Result<Settings, String> {
    let path = paths::settings_file(app)?;
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| format!("invalid settings file: {e}")),
        Err(_) => Ok(Settings::default()),
    }
}

/// Resolution order: (1) `settings.client_bin` if set and it exists; (2)
/// `shadowvpn-client[.exe]` next to the running app executable; (3) the dev
/// fallback path on this machine.
pub fn resolve_client_bin(settings: &Settings) -> (Option<String>, Option<String>) {
    if let Some(bin) = settings.client_bin.as_deref().filter(|s| !s.is_empty()) {
        if std::path::Path::new(bin).exists() {
            return (Some(bin.to_string()), Some("settings".to_string()));
        }
    }

    let exe_name = if cfg!(windows) {
        "shadowvpn-client.exe"
    } else {
        "shadowvpn-client"
    };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(exe_name);
            if candidate.exists() {
                return (
                    Some(candidate.to_string_lossy().to_string()),
                    Some("app_dir".to_string()),
                );
            }
        }
    }

    const DEV_DEFAULT: &str = "/Volumes/DATA/workspace/shadowvpn/target/release/shadowvpn-client";
    if std::path::Path::new(DEV_DEFAULT).exists() {
        return (
            Some(DEV_DEFAULT.to_string()),
            Some("dev_default".to_string()),
        );
    }

    (None, None)
}

#[tauri::command]
pub fn get_settings(app: tauri::AppHandle) -> Result<SettingsInfo, String> {
    let settings = load_settings(&app)?;
    let (resolved_client_bin, resolved_from) = resolve_client_bin(&settings);
    let bin = resolved_client_bin.as_deref();
    let bundled_gfwlist = bundled_path(bin, "gfwlist.txt");
    let bundled_chnroute = bundled_path(bin, "chnroute.txt");
    let bundled_geoip = bundled_path(bin, "GeoLite2-Country.mmdb");
    Ok(SettingsInfo {
        client_bin: settings.client_bin,
        resolved_client_bin,
        resolved_from,
        bundled_gfwlist,
        bundled_chnroute,
        bundled_geoip,
    })
}

#[tauri::command]
pub fn save_settings(app: tauri::AppHandle, settings: Settings) -> Result<(), String> {
    if let Some(bin) = settings.client_bin.as_deref().filter(|s| !s.is_empty()) {
        if !std::path::Path::new(bin).exists() {
            return Err(format!("client_bin '{bin}' does not exist"));
        }
    }
    let path = paths::settings_file(&app)?;
    let data = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    paths::write_private(&path, data.as_bytes()).map_err(|e| format!("cannot write settings: {e}"))
}
