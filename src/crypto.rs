//! AEAD crypto for ShadowVPN, implementing the shadowsocks.org AEAD **UDP**
//! wire scheme so the construction is spec-correct and interoperable.
//!
//! # Wire format (one UDP datagram)
//!
//! ```text
//! [ salt (salt_len bytes) ] ++ [ AEAD ciphertext ++ tag (16 bytes) ]
//! ```
//!
//! * `salt_len == key_len` of the cipher (16 for AES-128-GCM; 32 for
//!   AES-256-GCM and ChaCha20-Poly1305). A fresh random salt is generated for
//!   every datagram.
//! * `subkey = HKDF-SHA1(ikm = master_key, salt = salt, info = "ss-subkey",
//!   L = key_len)`.
//! * `nonce = [0u8; 12]` (all-zero, 12-byte nonce) for UDP packets. This is
//!   safe because each datagram uses a unique random salt and therefore a
//!   unique subkey, so the (subkey, nonce) pair is never reused.
//! * `master_key` is derived from the password with shadowsocks'
//!   `EVP_BytesToKey` (OpenSSL legacy MD5-based KDF), see [`evp_bytes_to_key`].
//!
//! # Deviation from ss-proxy
//!
//! Standard shadowsocks UDP relays prepend a SOCKS-style target address to the
//! plaintext. **ShadowVPN does not.** This is a fixed point-to-point tunnel,
//! not a SOCKS proxy: the plaintext is exactly the raw IP packet read from the
//! TUN interface, with no address header. Everything else (salt, HKDF subkey,
//! zero nonce, AEAD tag) matches the shadowsocks UDP AEAD scheme byte-for-byte.

use aead::{AeadInOut, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use rand::RngExt;
use sha1::Sha1;

/// AEAD nonce length in bytes. All supported ciphers use a 12-byte nonce.
pub const NONCE_LEN: usize = 12;

/// AEAD authentication tag length in bytes. All supported ciphers use a
/// 16-byte (128-bit) Poly1305 / GCM tag.
pub const TAG_LEN: usize = 16;

/// Largest key/subkey length across the supported ciphers (32 for AES-256-GCM /
/// ChaCha20-Poly1305). Lets the per-datagram subkey live on the stack instead of
/// a fresh heap `Vec` on every encrypt/decrypt.
const MAX_KEY_LEN: usize = 32;

/// HKDF `info` parameter used by the shadowsocks AEAD subkey derivation.
const SS_SUBKEY_INFO: &[u8] = b"ss-subkey";

/// Errors that can occur while encrypting or decrypting a datagram.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// The cipher name string was not one of the supported ciphers.
    #[error("unknown cipher: {0}")]
    UnknownCipher(String),

    /// An incoming datagram was shorter than `salt_len + tag_len` and so
    /// cannot possibly contain a valid salt + AEAD tag.
    #[error("datagram too short: {got} bytes, need at least {need}")]
    TooShort {
        /// Number of bytes actually received.
        got: usize,
        /// Minimum number of bytes required (`salt_len + TAG_LEN`).
        need: usize,
    },

    /// HKDF subkey derivation failed (only possible for an absurd output
    /// length; never happens for our fixed key sizes).
    #[error("subkey derivation failed")]
    Hkdf,

    /// AEAD open/seal failed. On decrypt this means authentication failed
    /// (wrong key/password, corruption, or a flipped byte).
    #[error("AEAD operation failed (authentication failure or bad key)")]
    Aead,
}

/// The set of supported AEAD ciphers.
///
/// Parse one from its shadowsocks name with [`Cipher::from_name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// AES-128-GCM. 16-byte key, 16-byte salt.
    Aes128Gcm,
    /// AES-256-GCM. 32-byte key, 32-byte salt.
    Aes256Gcm,
    /// ChaCha20-Poly1305 (IETF). 32-byte key, 32-byte salt.
    ChaCha20Poly1305,
}

impl Cipher {
    /// Parse a cipher from its shadowsocks cipher name.
    ///
    /// Accepted names: `"aes-128-gcm"`, `"aes-256-gcm"`,
    /// `"chacha20-poly1305"` (also accepts the alias
    /// `"chacha20-ietf-poly1305"`).
    pub fn from_name(name: &str) -> Result<Self, CryptoError> {
        match name {
            "aes-128-gcm" => Ok(Cipher::Aes128Gcm),
            "aes-256-gcm" => Ok(Cipher::Aes256Gcm),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(Cipher::ChaCha20Poly1305),
            other => Err(CryptoError::UnknownCipher(other.to_string())),
        }
    }

    /// The canonical shadowsocks name of this cipher.
    pub fn name(self) -> &'static str {
        match self {
            Cipher::Aes128Gcm => "aes-128-gcm",
            Cipher::Aes256Gcm => "aes-256-gcm",
            Cipher::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }

    /// Key length in bytes for this cipher. Also equals the salt length on the
    /// wire (per the shadowsocks AEAD spec).
    pub fn key_len(self) -> usize {
        match self {
            Cipher::Aes128Gcm => 16,
            Cipher::Aes256Gcm | Cipher::ChaCha20Poly1305 => 32,
        }
    }

    /// Salt length in bytes for this cipher (equal to [`Cipher::key_len`]).
    pub fn salt_len(self) -> usize {
        self.key_len()
    }
}

/// Derive the shadowsocks master key from a password using OpenSSL's legacy
/// `EVP_BytesToKey` (MD5-based) KDF.
///
/// The algorithm concatenates successive MD5 digests until at least `key_len`
/// bytes are produced:
///
/// ```text
/// d_0 = MD5(password)
/// d_i = MD5(d_{i-1} ++ password)
/// master_key = (d_0 ++ d_1 ++ ...)[..key_len]
/// ```
///
/// For 16-byte keys this is simply `MD5(password)`.
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut hasher = Md5::new();
        hasher.update(&prev);
        hasher.update(password);
        prev = hasher.finalize().to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);
    key
}

/// Derive a per-datagram subkey via `HKDF-SHA1(ikm = master_key, salt, info =
/// "ss-subkey", L = key_len)`, matching the shadowsocks AEAD subkey scheme, into
/// the caller-provided `out` (whose length is the desired key length). Writing
/// into a borrowed slice lets callers keep the subkey on the stack.
fn derive_subkey(master_key: &[u8], salt: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    let hk = Hkdf::<Sha1>::new(Some(salt), master_key);
    hk.expand(SS_SUBKEY_INFO, out)
        .map_err(|_| CryptoError::Hkdf)
}

/// AEAD-seal `buf` (the plaintext) in place with `subkey` and the all-zero UDP
/// nonce, returning the detached authentication tag. No allocation: the
/// ciphertext overwrites the plaintext and the tag is returned by value.
fn aead_seal_in_place(
    cipher: Cipher,
    subkey: &[u8],
    buf: &mut [u8],
) -> Result<[u8; TAG_LEN], CryptoError> {
    let nonce = [0u8; NONCE_LEN];
    macro_rules! seal {
        ($alg:ty) => {{
            let key = aead::Key::<$alg>::try_from(subkey).map_err(|_| CryptoError::Aead)?;
            let aead = <$alg>::new(&key);
            let tag = aead
                .encrypt_inout_detached((&nonce).into(), b"", buf.into())
                .map_err(|_| CryptoError::Aead)?;
            let mut out = [0u8; TAG_LEN];
            out.copy_from_slice(&tag);
            Ok(out)
        }};
    }
    match cipher {
        Cipher::Aes128Gcm => seal!(Aes128Gcm),
        Cipher::Aes256Gcm => seal!(Aes256Gcm),
        Cipher::ChaCha20Poly1305 => seal!(ChaCha20Poly1305),
    }
}

/// AEAD-open `buf` (the ciphertext) in place with `subkey`, the all-zero UDP
/// nonce, and the detached `tag`. On success `buf` holds the recovered
/// plaintext; returns [`CryptoError::Aead`] on authentication failure.
fn aead_open_in_place(
    cipher: Cipher,
    subkey: &[u8],
    buf: &mut [u8],
    tag: &[u8],
) -> Result<(), CryptoError> {
    let nonce = [0u8; NONCE_LEN];
    macro_rules! open {
        ($alg:ty) => {{
            let key = aead::Key::<$alg>::try_from(subkey).map_err(|_| CryptoError::Aead)?;
            let aead = <$alg>::new(&key);
            let tag = aead::Tag::<$alg>::try_from(tag).map_err(|_| CryptoError::Aead)?;
            aead.decrypt_inout_detached((&nonce).into(), b"", buf.into(), &tag)
                .map_err(|_| CryptoError::Aead)
        }};
    }
    match cipher {
        Cipher::Aes128Gcm => open!(Aes128Gcm),
        Cipher::Aes256Gcm => open!(Aes256Gcm),
        Cipher::ChaCha20Poly1305 => open!(ChaCha20Poly1305),
    }
}

/// Encrypt one plaintext IP packet into a wire datagram.
///
/// Produces `salt ++ ciphertext ++ tag`, where `salt` is `cipher.salt_len()`
/// random bytes and the AEAD subkey is `HKDF-SHA1(master_key, salt,
/// "ss-subkey")`.
///
/// * `cipher` — the negotiated AEAD cipher.
/// * `master_key` — the [`evp_bytes_to_key`]-derived master key. Its length
///   must equal `cipher.key_len()`; this is guaranteed when it is produced by
///   [`evp_bytes_to_key`] with the matching length.
/// * `plaintext` — the raw IP packet (no SOCKS address header).
pub fn encrypt_packet(
    cipher: Cipher,
    master_key: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let salt_len = cipher.salt_len();

    // Build the datagram in a single buffer: `salt ++ plaintext`, then encrypt
    // the plaintext region in place and append the tag. One allocation total.
    let mut datagram = Vec::with_capacity(salt_len + plaintext.len() + TAG_LEN);
    datagram.resize(salt_len, 0);
    // `rand::rng()` is an OS-seeded, cryptographically secure thread-local RNG;
    // each datagram gets a fresh random salt written straight into the buffer.
    rand::rng().fill(&mut datagram[..salt_len]);

    let mut subkey = [0u8; MAX_KEY_LEN];
    let subkey = &mut subkey[..cipher.key_len()];
    derive_subkey(master_key, &datagram[..salt_len], subkey)?;

    datagram.extend_from_slice(plaintext);
    let tag = aead_seal_in_place(cipher, subkey, &mut datagram[salt_len..])?;
    datagram.extend_from_slice(&tag);
    Ok(datagram)
}

/// Decrypt one wire datagram back into the plaintext IP packet.
///
/// Splits off the leading `cipher.salt_len()` salt bytes, derives the subkey,
/// and AEAD-opens the remainder. Returns [`CryptoError::TooShort`] if the
/// datagram cannot hold a salt + tag, or [`CryptoError::Aead`] if
/// authentication fails (wrong key or any flipped/truncated byte).
///
/// * `cipher` — the negotiated AEAD cipher.
/// * `master_key` — the [`evp_bytes_to_key`]-derived master key.
/// * `datagram` — the on-wire bytes `salt ++ ciphertext ++ tag`.
pub fn decrypt_packet(
    cipher: Cipher,
    master_key: &[u8],
    datagram: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let salt_len = cipher.salt_len();
    let need = salt_len + TAG_LEN;
    if datagram.len() < need {
        return Err(CryptoError::TooShort {
            got: datagram.len(),
            need,
        });
    }
    let (salt, rest) = datagram.split_at(salt_len);

    let mut subkey = [0u8; MAX_KEY_LEN];
    let subkey = &mut subkey[..cipher.key_len()];
    derive_subkey(master_key, salt, subkey)?;

    // `rest` is `ciphertext ++ tag`; decrypt the ciphertext in place into a fresh
    // owned buffer (the one allocation) and verify against the detached tag.
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);
    let mut plaintext = ciphertext.to_vec();
    aead_open_in_place(cipher, subkey, &mut plaintext, tag)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (a) `EVP_BytesToKey` reference vector: password "test", 16-byte key
    /// (aes-128-gcm) must equal MD5("test").
    #[test]
    fn evp_bytes_to_key_reference_vector() {
        let key = evp_bytes_to_key(b"test", 16);
        assert_eq!(hex_encode(&key), "098f6bcd4621d373cade4e832627b4f6");
    }

    /// `EVP_BytesToKey` for a 32-byte key concatenates MD5("test") and
    /// MD5(MD5("test") ++ "test").
    #[test]
    fn evp_bytes_to_key_32_byte_length() {
        let key = evp_bytes_to_key(b"test", 32);
        assert_eq!(key.len(), 32);
        // First 16 bytes are MD5("test").
        assert_eq!(hex_encode(&key[..16]), "098f6bcd4621d373cade4e832627b4f6");
    }

    /// (b) `encrypt_packet` then `decrypt_packet` round-trips for all ciphers.
    #[test]
    fn round_trip_all_ciphers() {
        let plaintext = b"the raw IP packet bytes that traverse the tunnel";
        for cipher in [
            Cipher::Aes128Gcm,
            Cipher::Aes256Gcm,
            Cipher::ChaCha20Poly1305,
        ] {
            let master_key = evp_bytes_to_key(b"correct horse battery staple", cipher.key_len());
            let datagram = encrypt_packet(cipher, &master_key, plaintext).expect("encrypt");

            // Wire layout sanity: salt + ciphertext + tag.
            assert_eq!(
                datagram.len(),
                cipher.salt_len() + plaintext.len() + TAG_LEN,
                "datagram length for {}",
                cipher.name()
            );

            let recovered = decrypt_packet(cipher, &master_key, &datagram).expect("decrypt");
            assert_eq!(recovered, plaintext, "round trip for {}", cipher.name());
        }
    }

    /// An empty plaintext (degenerate IP packet) still round-trips.
    #[test]
    fn round_trip_empty_plaintext() {
        let cipher = Cipher::ChaCha20Poly1305;
        let master_key = evp_bytes_to_key(b"pw", cipher.key_len());
        let datagram = encrypt_packet(cipher, &master_key, b"").expect("encrypt");
        let recovered = decrypt_packet(cipher, &master_key, &datagram).expect("decrypt");
        assert!(recovered.is_empty());
    }

    /// (c) Flipping any single byte of a datagram makes decryption fail.
    #[test]
    fn flipped_byte_is_rejected() {
        let plaintext = b"authenticate me";
        for cipher in [
            Cipher::Aes128Gcm,
            Cipher::Aes256Gcm,
            Cipher::ChaCha20Poly1305,
        ] {
            let master_key = evp_bytes_to_key(b"password", cipher.key_len());
            let datagram = encrypt_packet(cipher, &master_key, plaintext).expect("encrypt");

            // Flip a byte in the salt region.
            let mut bad_salt = datagram.clone();
            bad_salt[0] ^= 0xff;
            assert!(
                decrypt_packet(cipher, &master_key, &bad_salt).is_err(),
                "flipped salt byte must be rejected for {}",
                cipher.name()
            );

            // Flip a byte in the ciphertext/tag region.
            let mut bad_ct = datagram.clone();
            let last = bad_ct.len() - 1;
            bad_ct[last] ^= 0x01;
            assert!(
                decrypt_packet(cipher, &master_key, &bad_ct).is_err(),
                "flipped tag byte must be rejected for {}",
                cipher.name()
            );
        }
    }

    /// A datagram shorter than `salt_len + tag_len` is rejected as too short.
    #[test]
    fn too_short_datagram_is_rejected() {
        let cipher = Cipher::Aes128Gcm;
        let master_key = evp_bytes_to_key(b"pw", cipher.key_len());
        let short = vec![0u8; cipher.salt_len() + TAG_LEN - 1];
        let err = decrypt_packet(cipher, &master_key, &short).unwrap_err();
        assert!(matches!(err, CryptoError::TooShort { .. }));
    }

    /// Unknown cipher names are rejected; known names round-trip through
    /// `from_name`/`name`.
    #[test]
    fn cipher_name_parsing() {
        assert_eq!(Cipher::from_name("aes-128-gcm").unwrap(), Cipher::Aes128Gcm);
        assert_eq!(Cipher::from_name("aes-256-gcm").unwrap(), Cipher::Aes256Gcm);
        assert_eq!(
            Cipher::from_name("chacha20-poly1305").unwrap(),
            Cipher::ChaCha20Poly1305
        );
        assert_eq!(
            Cipher::from_name("chacha20-ietf-poly1305").unwrap(),
            Cipher::ChaCha20Poly1305
        );
        assert!(Cipher::from_name("rc4-md5").is_err());
        assert_eq!(Cipher::Aes256Gcm.name(), "aes-256-gcm");
    }

    /// Minimal local hex encoder so the tests need no extra dependency.
    fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}
