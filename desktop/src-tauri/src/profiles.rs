//! Profile CRUD commands + the `ProfileConfig` type.
//!
//! `ProfileConfig` is an exact mirror of `shadowvpn::config::FileConfig`
//! (src/config.rs), field-for-field, so a saved profile IS a valid
//! `shadowvpn-client --config` file. Unlike the root crate's `FileConfig`,
//! every field here is a plain `String` (not `Ipv4Addr`/`PathBuf`) so this
//! crate does not need to depend on the root `shadowvpn` crate; ipv4 fields
//! are validated with a small parse check in [`validate_config`] instead.

use serde::{Deserialize, Serialize};

use crate::paths;
use crate::settings;

/// EXACT mirror of `shadowvpn::config::FileConfig` keys, same
/// `deny_unknown_fields` + per-field `skip_serializing_if`.
/// `node_id` is not a FileConfig key and must never appear here.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tun_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tun_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tun_netmask: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tun_ip6: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nat: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_ttl_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assign_pool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reserved_ips: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assign_ttl_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keepalive_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertise_routes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_routes: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approve_routes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_approve_routes: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_listen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_local: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_remote: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gfwlist: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chnroute: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip_country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set_dns: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prewarm: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub magic_dns: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub magic_dns_suffix: Option<String>,
}

#[derive(Serialize)]
pub struct ProfileSummary {
    pub name: String,
    pub server: Option<String>,
    pub mode: Option<String>,
    pub cipher: Option<String>,
}

#[tauri::command]
pub fn list_profiles(app: tauri::AppHandle) -> Result<Vec<ProfileSummary>, String> {
    let dir = paths::profiles_dir(&app)?;
    let mut out = Vec::new();
    let entries = std::fs::read_dir(&dir).map_err(|e| format!("cannot read profiles dir: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let name = name.to_string();
        let parsed = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<ProfileConfig>(&s).ok());
        out.push(match parsed {
            Some(cfg) => ProfileSummary {
                name,
                server: cfg.server,
                mode: cfg.mode,
                cipher: cfg.cipher,
            },
            None => ProfileSummary {
                name,
                server: None,
                mode: None,
                cipher: None,
            },
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

#[tauri::command]
pub fn get_profile(app: tauri::AppHandle, name: String) -> Result<ProfileConfig, String> {
    paths::validate_profile_name(&name)?;
    let path = paths::profile_path(&app, &name)?;
    let data =
        std::fs::read_to_string(&path).map_err(|e| format!("profile '{name}' not found: {e}"))?;
    serde_json::from_str(&data).map_err(|e| format!("invalid profile '{name}': {e}"))
}

#[tauri::command]
pub fn save_profile(
    app: tauri::AppHandle,
    name: String,
    config: ProfileConfig,
) -> Result<(), String> {
    paths::validate_profile_name(&name)?;
    validate_config(&config, bundled_data(&app))?;
    let path = paths::profile_path(&app, &name)?;
    let data = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    // Profiles hold the VPN password in plaintext: write with mode 0600 on
    // Unix (and tighten pre-existing files) instead of inheriting the umask.
    paths::write_private(&path, data.as_bytes())
        .map_err(|e| format!("cannot write profile '{name}': {e}"))
}

#[tauri::command]
pub fn delete_profile(app: tauri::AppHandle, name: String) -> Result<(), String> {
    paths::validate_profile_name(&name)?;

    // Refuse to delete a profile that is currently connected/connecting.
    let status = crate::runner::current_status(&app);
    if status.profile.as_deref() == Some(name.as_str())
        && matches!(status.state.as_str(), "connected" | "connecting")
    {
        return Err(format!(
            "profile '{name}' is currently {}; disconnect first",
            status.state
        ));
    }

    let path = paths::profile_path(&app, &name)?;
    std::fs::remove_file(&path).map_err(|e| format!("profile '{name}' not found: {e}"))?;
    // Sibling `.state` holds `node_id`; leaving it would hand a later
    // same-named profile this node's assigned IP.
    unlink_profile_state(&path)
}

/// Data files the client can auto-discover next to its own binary; these mirror
/// `shadowvpn::config::DEFAULT_GEOIP_DB_NAME` / `DEFAULT_GFWLIST_NAME` (the
/// desktop crate does not depend on the client library).
const GEOIP_DB_NAME: &str = "GeoLite2-Country.mmdb";
const GFWLIST_NAME: &str = "gfwlist.txt";

/// Which bundled data files ship next to the resolved client binary. When a
/// file is present, its policy mode needs no explicit path — the client
/// auto-discovers the bundled copy.
#[derive(Clone, Copy, Default)]
struct BundledData {
    geoip: bool,
    gfwlist: bool,
}

fn bundled_data(app: &tauri::AppHandle) -> BundledData {
    let Ok(info) = settings::get_settings(app.clone()) else {
        return BundledData::default();
    };
    let Some(bin) = info.resolved_client_bin else {
        return BundledData::default();
    };
    let Some(dir) = std::path::Path::new(&bin).parent() else {
        return BundledData::default();
    };
    BundledData {
        geoip: dir.join(GEOIP_DB_NAME).is_file(),
        gfwlist: dir.join(GFWLIST_NAME).is_file(),
    }
}

/// Mirrors the client's fail-fast validation (src/config.rs) so mistakes
/// surface at save time rather than at connect time. `bundled` reflects which
/// data files the client ships and can fall back to.
fn validate_config(config: &ProfileConfig, bundled: BundledData) -> Result<(), String> {
    if config.server.as_deref().unwrap_or("").is_empty() {
        return Err("server is required".to_string());
    }
    if config.password.as_deref().unwrap_or("").is_empty() {
        return Err("password is required".to_string());
    }

    let tun_ip = config.tun_ip.as_deref().unwrap_or("");
    let peer_ip = config.peer_ip.as_deref().unwrap_or("");
    match (tun_ip.is_empty(), peer_ip.is_empty()) {
        (true, true) => {}
        (false, false) => {
            parse_ipv4("tun_ip", tun_ip)?;
            parse_ipv4("peer_ip", peer_ip)?;
        }
        _ => {
            return Err(
                "tun_ip and peer_ip must both be set, or both omitted for auto-assign".to_string(),
            );
        }
    }

    if let Some(mask) = config.tun_netmask.as_deref().filter(|s| !s.is_empty()) {
        parse_ipv4("tun_netmask", mask)?;
    }

    if let Some(cipher) = config.cipher.as_deref() {
        if !["aes-128-gcm", "aes-256-gcm", "chacha20-poly1305"].contains(&cipher) {
            return Err(format!("invalid cipher '{cipher}'"));
        }
    }

    if let Some(obfs) = config.obfs.as_deref() {
        if !["none", "quic", "base64"].contains(&obfs) {
            return Err(format!("invalid obfs '{obfs}'"));
        }
    }

    match config.mode.as_deref() {
        None | Some("full") => {}
        Some("gfwlist") => {
            let has_gfwlist = !config.gfwlist.as_deref().unwrap_or("").is_empty();
            if !has_gfwlist && !bundled.gfwlist {
                return Err(
                    "mode=gfwlist requires a gfwlist path (no gfwlist is bundled with \
                     the client)"
                        .to_string(),
                );
            }
        }
        Some("chinadns") => {
            let has_chnroute = !config.chnroute.as_deref().unwrap_or("").is_empty();
            let has_geoip = !config.geoip.as_deref().unwrap_or("").is_empty();
            if !has_chnroute && !has_geoip && !bundled.geoip {
                return Err(
                    "mode=chinadns requires chnroute or geoip (no GeoLite2 database is \
                     bundled with the client)"
                        .to_string(),
                );
            }
        }
        Some(other) => return Err(format!("invalid mode '{other}'")),
    }

    Ok(())
}

fn parse_ipv4(field: &str, s: &str) -> Result<(), String> {
    s.parse::<std::net::Ipv4Addr>()
        .map(|_| ())
        .map_err(|_| format!("invalid ipv4 address for {field}: '{s}'"))
}

/// `<profile>.json` → `<profile>.json.state` (CLI default for `-c <profile>`).
fn profile_state_path(profile_json: &std::path::Path) -> std::path::PathBuf {
    let mut s = profile_json.as_os_str().to_os_string();
    s.push(".state");
    std::path::PathBuf::from(s)
}

fn unlink_profile_state(profile_json: &std::path::Path) -> Result<(), String> {
    let state = profile_state_path(profile_json);
    match std::fs::remove_file(&state) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "cannot remove assignment state {}: {e}",
            state.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_base() -> ProfileConfig {
        ProfileConfig {
            server: Some("vpn.example.com:8388".into()),
            password: Some("pw".into()),
            ..Default::default()
        }
    }

    #[test]
    fn both_omitted_is_auto_assign() {
        validate_config(&ok_base(), BundledData::default()).unwrap();
    }

    #[test]
    fn both_set_is_static() {
        let mut c = ok_base();
        c.tun_ip = Some("10.9.0.2".into());
        c.peer_ip = Some("10.9.0.1".into());
        validate_config(&c, BundledData::default()).unwrap();
    }

    #[test]
    fn only_tun_ip_is_invalid() {
        let mut c = ok_base();
        c.tun_ip = Some("10.9.0.2".into());
        let err = validate_config(&c, BundledData::default()).unwrap_err();
        assert!(err.contains("both be set, or both omitted"));
    }

    #[test]
    fn only_peer_ip_is_invalid() {
        let mut c = ok_base();
        c.peer_ip = Some("10.9.0.1".into());
        let err = validate_config(&c, BundledData::default()).unwrap_err();
        assert!(err.contains("both be set, or both omitted"));
    }

    #[test]
    fn profile_state_path_is_json_dot_state() {
        let p = std::path::Path::new("/tmp/profiles/home.json");
        assert_eq!(
            profile_state_path(p),
            std::path::PathBuf::from("/tmp/profiles/home.json.state")
        );
    }

    #[test]
    fn unlink_profile_state_ignores_missing() {
        let p = std::env::temp_dir().join("shadowvpn-desktop-missing-profile.json");
        unlink_profile_state(&p).unwrap();
    }

    #[test]
    fn unlink_profile_state_removes_sibling() {
        let json = std::env::temp_dir().join(format!(
            "shadowvpn-desktop-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = profile_state_path(&json);
        std::fs::write(&state, b"{}").unwrap();
        unlink_profile_state(&json).unwrap();
        assert!(!state.exists());
    }

    #[test]
    fn new_fileconfig_keys_round_trip() {
        let json = r#"{
            "server": "vpn.example.com:8388",
            "password": "pw",
            "tun_ip6": "fd07:7::2/64",
            "assign_pool": "10.9.0.0/24",
            "reserved_ips": ["10.9.0.2"],
            "assign_ttl_secs": 604800,
            "lease_file": "-",
            "keepalive_secs": 15,
            "state_file": "/tmp/custom.state",
            "advertise_routes": ["192.168.200.0/24"],
            "accept_routes": true,
            "approve_routes": ["192.168.0.0/16"],
            "auto_approve_routes": false,
            "hostname": "tyo",
            "magic_dns": true,
            "magic_dns_suffix": "svpn"
        }"#;
        let cfg: ProfileConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.assign_pool.as_deref(), Some("10.9.0.0/24"));
        assert_eq!(
            cfg.reserved_ips.as_deref(),
            Some(["10.9.0.2".to_string()].as_slice())
        );
        assert_eq!(cfg.assign_ttl_secs, Some(604800));
        assert_eq!(cfg.lease_file.as_deref(), Some("-"));
        assert_eq!(cfg.state_file.as_deref(), Some("/tmp/custom.state"));
        assert_eq!(cfg.tun_ip6.as_deref(), Some("fd07:7::2/64"));
        assert_eq!(cfg.keepalive_secs, Some(15));
        assert_eq!(
            cfg.advertise_routes.as_deref(),
            Some(["192.168.200.0/24".to_string()].as_slice())
        );
        assert_eq!(cfg.accept_routes, Some(true));
        assert_eq!(
            cfg.approve_routes.as_deref(),
            Some(["192.168.0.0/16".to_string()].as_slice())
        );
        assert_eq!(cfg.auto_approve_routes, Some(false));
        assert_eq!(cfg.hostname.as_deref(), Some("tyo"));
        assert_eq!(cfg.magic_dns, Some(true));
        assert_eq!(cfg.magic_dns_suffix.as_deref(), Some("svpn"));
        let back = serde_json::to_value(&cfg).unwrap();
        assert!(back.get("node_id").is_none());
    }

    #[test]
    fn hostname_only_profile_parses() {
        // Regression: Magic DNS added `hostname` to FileConfig; a CLI-written
        // profile must open in the desktop editor.
        let json = r#"{
            "server": "vpn.example.com:8388",
            "password": "pw",
            "hostname": "tyo"
        }"#;
        let cfg: ProfileConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.hostname.as_deref(), Some("tyo"));
    }

    #[test]
    fn node_id_is_rejected() {
        let json =
            r#"{"server":"h:1","password":"pw","node_id":"c0ffee00-0000-4000-8000-000000000001"}"#;
        let err = serde_json::from_str::<ProfileConfig>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field `node_id`"));
    }
}
