//! Import/export a profile as a `shadowvpn://` URI.
//!
//! The URI format is defined by the root crate's `shadowvpn::uri` module: the
//! scheme `shadowvpn://` immediately followed by the URL-safe, unpadded Base64
//! of the configuration's JSON. Because [`ProfileConfig`] is an exact,
//! field-for-field mirror of the client's `FileConfig`, decoding a URI produced
//! by `shadowvpn-uri` (or by another ShadowVPN client) round-trips losslessly
//! here without this crate depending on the root crate.
//!
//! [`import_uri`] decodes a pasted URI into a [`ProfileConfig`] and hands it to
//! the editor (it does NOT save): a URI exported on another host may carry
//! filesystem paths (`gfwlist`, `chnroute`, `geoip`, `cache_file`) that don't
//! exist here, so the user re-points them and names the profile before saving.
//! [`export_uri`] is the inverse, for sharing a profile.

use base64::Engine;

use crate::profiles::ProfileConfig;

/// The URI scheme prefix, including the `://` separator (matches the root crate).
const SCHEME: &str = "shadowvpn://";

/// URL-safe, unpadded Base64 — the alphabet the root `uri` module emits.
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Decode a `shadowvpn://` URI into a [`ProfileConfig`] for the editor to
/// populate. Does not touch disk. Tolerates surrounding whitespace, a trailing
/// `#fragment` (some QR tools append one), and stray `=` padding.
#[tauri::command]
pub fn import_uri(uri: String) -> Result<ProfileConfig, String> {
    let body = uri
        .trim()
        .strip_prefix(SCHEME)
        .ok_or_else(|| format!("not a shadowvpn:// URI (expected the `{SCHEME}` scheme)"))?;
    // Stop at the first whitespace or fragment so trailing bytes don't poison
    // the Base64 decode, then drop any `=` padding (the alphabet is unpadded,
    // but a padded input should still import).
    let payload = body
        .split(|c: char| c == '#' || c.is_whitespace())
        .next()
        .unwrap_or("")
        .trim_end_matches('=');
    if payload.is_empty() {
        return Err("URI has an empty payload".to_string());
    }
    let bytes = B64
        .decode(payload)
        .map_err(|e| format!("invalid Base64 in URI: {e}"))?;
    let text =
        std::str::from_utf8(&bytes).map_err(|e| format!("URI payload is not valid UTF-8: {e}"))?;
    // `deny_unknown_fields` on ProfileConfig mirrors the client, so a URI
    // carrying a field this build doesn't know is rejected rather than silently
    // dropped — the same guarantee the client gives.
    serde_json::from_str(text).map_err(|e| format!("URI payload is not a valid config: {e}"))
}

/// Encode a [`ProfileConfig`] as a `shadowvpn://` URI for sharing. The config is
/// serialized to compact JSON and Base64url-encoded, byte-for-byte compatible
/// with the root `shadowvpn-uri` tool and [`import_uri`].
#[tauri::command]
pub fn export_uri(config: ProfileConfig) -> Result<String, String> {
    let json = serde_json::to_vec(&config).map_err(|e| e.to_string())?;
    Ok(format!("{SCHEME}{}", B64.encode(json)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_profile() {
        let cfg = ProfileConfig {
            server: Some("sf1.maxlv.net:443".to_string()),
            password: Some("pw".to_string()),
            cipher: Some("chacha20-poly1305".to_string()),
            obfs: Some("quic".to_string()),
            tun_ip: Some("10.9.0.2".to_string()),
            peer_ip: Some("10.9.0.1".to_string()),
            mode: Some("full".to_string()),
            ..Default::default()
        };
        let uri = export_uri(cfg).expect("export");
        assert!(uri.starts_with(SCHEME));
        let back = import_uri(uri).expect("import");
        assert_eq!(back.server.as_deref(), Some("sf1.maxlv.net:443"));
        assert_eq!(back.obfs.as_deref(), Some("quic"));
        assert_eq!(back.tun_ip.as_deref(), Some("10.9.0.2"));
    }

    #[test]
    fn tolerates_whitespace_and_fragment() {
        let uri = export_uri(ProfileConfig {
            server: Some("h:443".to_string()),
            ..Default::default()
        })
        .unwrap();
        let messy = format!("  {uri}#sf1\n");
        assert_eq!(import_uri(messy).unwrap().server.as_deref(), Some("h:443"));
    }

    #[test]
    fn rejects_wrong_scheme() {
        assert!(import_uri("ss://whatever".to_string()).is_err());
    }

    #[test]
    fn rejects_garbage_payload() {
        assert!(import_uri("shadowvpn://!!!not-base64!!!".to_string()).is_err());
    }

    #[test]
    fn round_trips_hostname() {
        let uri = export_uri(ProfileConfig {
            server: Some("h:443".to_string()),
            hostname: Some("tyo".to_string()),
            magic_dns: Some(true),
            magic_dns_suffix: Some("svpn".to_string()),
            ..Default::default()
        })
        .unwrap();
        let back = import_uri(uri).unwrap();
        assert_eq!(back.hostname.as_deref(), Some("tyo"));
        assert_eq!(back.magic_dns, Some(true));
        assert_eq!(back.magic_dns_suffix.as_deref(), Some("svpn"));
    }

    #[test]
    fn rejects_unknown_field() {
        // {"bogus":1} base64url-encoded — deny_unknown_fields must reject it.
        let json = br#"{"bogus":1}"#;
        let uri = format!("{SCHEME}{}", B64.encode(json));
        assert!(import_uri(uri).is_err());
    }
}
