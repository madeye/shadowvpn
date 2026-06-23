//! Import/export a client configuration as a `shadowvpn://` URI and QR code.
//!
//! The URI is **opaque**: the scheme `shadowvpn://` immediately followed by the
//! URL-safe Base64 (no padding) of the configuration's JSON ([`FileConfig`]).
//! Encoding the whole JSON keeps the format lossless — every field round-trips
//! verbatim, including any added later — at the cost of not being human-readable:
//!
//! ```text
//! shadowvpn://<base64url( FileConfig as JSON )>
//! ```
//!
//! Because [`FileConfig`] carries local filesystem paths (`gfwlist`, `chnroute`,
//! `geoip`, `cache_file`), a URI exported on one host may reference paths that do
//! not exist on the importing host; those fields should be re-pointed after
//! import. When sharing one server among several clients, give each client a
//! distinct `tun_ip` before (or after) exporting — the server routes return
//! traffic by inner tunnel IP, so duplicates collide.
//!
//! [`encode`] / [`decode`] handle the URI text; [`render_qr`] turns the URI into
//! a terminal-scannable QR code, and [`decode_qr_image`] reads one back from a
//! PNG/JPEG.

use std::path::Path;

use base64::Engine;

use crate::config::FileConfig;

/// The URI scheme prefix, including the `://` separator.
pub const SCHEME: &str = "shadowvpn://";

/// Base64 alphabet used for the payload: URL-safe, unpadded (QR/clipboard-clean).
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Errors from parsing a `shadowvpn://` URI.
#[derive(Debug, thiserror::Error)]
pub enum UriError {
    /// The string did not start with the `shadowvpn://` scheme.
    #[error("not a shadowvpn:// URI (expected the `{SCHEME}` scheme)")]
    Scheme,

    /// The Base64 payload could not be decoded.
    #[error("invalid Base64 in URI: {0}")]
    Base64(#[from] base64::DecodeError),

    /// The decoded payload was not valid UTF-8.
    #[error("URI payload is not valid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    /// The decoded JSON was not a valid configuration.
    #[error("URI payload is not a valid config: {0}")]
    Json(#[from] serde_json::Error),
}

/// Encode a [`FileConfig`] as a `shadowvpn://` URI.
///
/// The config is serialized to compact JSON and Base64url-encoded. Serialization
/// of a `FileConfig` cannot fail (it is plain data), so this is infallible.
pub fn encode(cfg: &FileConfig) -> String {
    let json = serde_json::to_vec(cfg).expect("FileConfig always serializes to JSON");
    format!("{SCHEME}{}", B64.encode(json))
}

/// Decode a `shadowvpn://` URI back into a [`FileConfig`].
///
/// Surrounding whitespace is tolerated, as is a trailing `#fragment` (some QR
/// tools append one), so the payload is taken up to the first whitespace or `#`.
pub fn decode(uri: &str) -> Result<FileConfig, UriError> {
    let body = uri.trim().strip_prefix(SCHEME).ok_or(UriError::Scheme)?;
    // Stop at the first whitespace or fragment so stray trailing bytes don't
    // poison the Base64 decode.
    let payload = body
        .split(|c: char| c == '#' || c.is_whitespace())
        .next()
        .unwrap_or("");
    let bytes = B64.decode(payload)?;
    let text = std::str::from_utf8(&bytes)?;
    Ok(serde_json::from_str(text)?)
}

/// Render `text` as a QR code drawn with Unicode half-blocks, suitable for
/// printing to a terminal and scanning with a phone.
pub fn render_qr(text: &str) -> Result<String, qrcode::types::QrError> {
    use qrcode::render::unicode;
    let code = qrcode::QrCode::new(text.as_bytes())?;
    Ok(code.render::<unicode::Dense1x2>().quiet_zone(true).build())
}

/// Errors from reading a QR code out of an image file.
#[derive(Debug, thiserror::Error)]
pub enum QrImageError {
    /// The image file could not be opened or decoded.
    #[error("failed to open image {path}: {source}")]
    Open {
        /// Path that failed to load.
        path: String,
        /// Underlying image error.
        #[source]
        source: image::ImageError,
    },

    /// No QR code was found in the image.
    #[error("no QR code found in the image")]
    NotFound,

    /// A QR code was located but its contents could not be decoded.
    #[error("failed to decode QR code: {0}")]
    Decode(String),
}

/// Detect and decode the first QR code in an image file (PNG/JPEG), returning
/// its textual contents (expected to be a `shadowvpn://` URI).
pub fn decode_qr_image(path: &Path) -> Result<String, QrImageError> {
    let img = image::open(path)
        .map_err(|source| QrImageError::Open {
            path: path.display().to_string(),
            source,
        })?
        .to_luma8();

    let mut prepared = rqrr::PreparedImage::prepare(img);
    let grid = prepared
        .detect_grids()
        .into_iter()
        .next()
        .ok_or(QrImageError::NotFound)?;
    let (_meta, content) = grid
        .decode()
        .map_err(|e| QrImageError::Decode(e.to_string()))?;
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    fn sample() -> FileConfig {
        FileConfig {
            server: Some("sf1.maxlv.net:443".to_string()),
            password: Some("pYGmRwycA/vVnoNlXg5aK2in5Tamsw4K".to_string()),
            cipher: Some("chacha20-poly1305".to_string()),
            obfs: Some("quic".to_string()),
            tun_ip: Some(Ipv4Addr::new(10, 9, 0, 2)),
            tun_netmask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            peer_ip: Some(Ipv4Addr::new(10, 9, 0, 1)),
            mtu: Some(1400),
            mode: Some("chinadns".to_string()),
            geoip: Some(PathBuf::from("/opt/svpn/GeoLite2-Country.mmdb")),
            geoip_country: Some("CN".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn round_trips_through_a_uri() {
        let cfg = sample();
        let uri = encode(&cfg);
        assert!(uri.starts_with(SCHEME));
        let back = decode(&uri).expect("decode");
        // Compare via canonical JSON so we don't need PartialEq on FileConfig.
        assert_eq!(
            serde_json::to_string(&cfg).unwrap(),
            serde_json::to_string(&back).unwrap()
        );
    }

    #[test]
    fn tolerates_whitespace_and_fragment() {
        let uri = encode(&sample());
        let messy = format!("  {uri}#sf1-chinadns\n");
        let back = decode(&messy).expect("decode messy");
        assert_eq!(back.server.as_deref(), Some("sf1.maxlv.net:443"));
    }

    #[test]
    fn rejects_wrong_scheme() {
        assert!(matches!(decode("ss://whatever"), Err(UriError::Scheme)));
    }

    #[test]
    fn rejects_garbage_payload() {
        // Valid scheme, but the payload is not Base64 of any JSON object.
        let err = decode("shadowvpn://!!!not-base64!!!").unwrap_err();
        assert!(matches!(err, UriError::Base64(_)));
    }

    #[test]
    fn renders_a_non_empty_qr() {
        let qr = render_qr(&encode(&sample())).expect("render");
        assert!(qr.lines().count() > 5);
    }

    #[test]
    fn qr_round_trips_through_an_image() {
        // Encode to a URI, paint a QR PNG (scaled, with a quiet zone) using only
        // the `image` crate, then decode it back with `decode_qr_image` —
        // exercises the full export/import-via-image path.
        let uri = encode(&sample());
        let code = qrcode::QrCode::new(uri.as_bytes()).unwrap();
        let w = code.width();
        let colors = code.to_colors();
        let (scale, quiet) = (6u32, 4u32);
        let dim = (w as u32 + 2 * quiet) * scale;
        let mut img = image::GrayImage::from_pixel(dim, dim, image::Luma([255u8]));
        for y in 0..w {
            for x in 0..w {
                if colors[y * w + x] == qrcode::Color::Dark {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            let px = (quiet + x as u32) * scale + dx;
                            let py = (quiet + y as u32) * scale + dy;
                            img.put_pixel(px, py, image::Luma([0u8]));
                        }
                    }
                }
            }
        }
        let path = std::env::temp_dir().join("shadowvpn-uri-test.png");
        img.save(&path).expect("save png");
        let decoded = decode_qr_image(&path).expect("decode image");
        let _ = std::fs::remove_file(&path);
        assert_eq!(decoded, uri);
    }
}
