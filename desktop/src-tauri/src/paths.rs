//! App-directory helpers, built on `tauri::Manager::path()`.
//!
//! On-disk layout (see the desktop blueprint §2):
//! - `app_config_dir()/profiles/<name>.json` — one profile per file; the file
//!   IS a valid `shadowvpn-client --config` file (FileConfig keys only).
//! - `app_config_dir()/settings.json` — `{"client_bin": "..."}`.
//! - `app_data_dir()/runs/shadowvpn.log` — current/last run log.
//! - `app_data_dir()/runs/shadowvpn.log.out` — Windows only (stdout side).
//! - `app_data_dir()/runs/shadowvpn.pid` — written by the elevated wrapper.
//! - `app_data_dir()/runs/state.json` — written by the GUI at connect time.

use std::path::PathBuf;

use tauri::Manager;

/// Profile-name pattern: `^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`.
pub fn validate_profile_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.chars().count() > 64 {
        return Err(format!(
            "invalid profile name '{name}': must be 1-64 characters"
        ));
    }
    let mut chars = name.chars();
    // Safe: we just checked name is non-empty.
    let first = chars.next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return Err(format!(
            "invalid profile name '{name}': must start with a letter or digit"
        ));
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-')) {
            return Err(format!(
                "invalid profile name '{name}': only letters, digits, spaces, '.', '_', '-' are allowed"
            ));
        }
    }
    Ok(())
}

/// `create_dir_all` equivalent that creates any new directories with mode
/// 0700 on Unix (profiles hold plaintext VPN passwords). Windows needs no
/// tightening: per-user %APPDATA% ACLs already restrict access.
fn create_dir_private(dir: &std::path::Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Write `data` to `path`, creating the file with mode 0600 on Unix (and
/// retroactively tightening the permissions of a pre-existing file) so other
/// local users cannot read stored secrets such as profile passwords.
pub fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `mode(0o600)` only applies when the file is newly created; tighten
        // pre-existing files (e.g. 0644 ones written by earlier versions).
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(data)
}

fn app_config_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map_err(|e| format!("cannot resolve app config dir: {e}"))
}

fn app_data_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|e| format!("cannot resolve app data dir: {e}"))
}

/// `app_config_dir()/profiles`, created if missing.
pub fn profiles_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app_config_dir(app)?.join("profiles");
    create_dir_private(&dir).map_err(|e| format!("cannot create profiles dir: {e}"))?;
    Ok(dir)
}

/// `app_data_dir()/runs`, created if missing.
pub fn runs_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app_data_dir(app)?.join("runs");
    create_dir_private(&dir).map_err(|e| format!("cannot create runs dir: {e}"))?;
    Ok(dir)
}

/// Path of a single profile's JSON file. Does not validate the name; call
/// [`validate_profile_name`] first.
pub fn profile_path(app: &tauri::AppHandle, name: &str) -> Result<PathBuf, String> {
    Ok(profiles_dir(app)?.join(format!("{name}.json")))
}

/// `app_config_dir()/settings.json`.
pub fn settings_file(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app_config_dir(app)?;
    create_dir_private(&dir).map_err(|e| format!("cannot create config dir: {e}"))?;
    Ok(dir.join("settings.json"))
}

/// `app_data_dir()/runs/state.json`.
pub fn state_file(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(runs_dir(app)?.join("state.json"))
}

/// `app_data_dir()/runs/shadowvpn.log`.
pub fn log_file(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(runs_dir(app)?.join("shadowvpn.log"))
}

/// `app_data_dir()/runs/shadowvpn.pid`.
pub fn pid_file(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(runs_dir(app)?.join("shadowvpn.pid"))
}

/// `app_data_dir()/runs/helper.token` — the per-session shared secret for the
/// elevated helper, written 0600 by the GUI before requesting elevation.
pub fn helper_token_file(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(runs_dir(app)?.join("helper.token"))
}

/// `app_data_dir()/runs/helper.port` — where the elevated helper publishes
/// its 127.0.0.1 listening port.
pub fn helper_port_file(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(runs_dir(app)?.join("helper.port"))
}
