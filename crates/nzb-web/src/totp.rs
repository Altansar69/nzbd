//! TOTP (RFC 6238), secret encryption at rest and recovery codes (SEC-023, `AUTH_SPEC` §TOTP).
//!
//! * Codes: HMAC-SHA1, 6 digits, 30 s steps, steps -1/0/+1 accepted. Replay protection is the
//!   caller's job through `Store::second_factor_step` (it stores the last accepted step atomically).
//! * Secret: 20 random bytes, sealed with XChaCha20-Poly1305 (random 24-byte nonce prepended,
//!   AAD = user id) under the 32-byte key from `security.totp_key_file`. The key never reaches the
//!   database or the logs; `Debug` is redacted and the key is zeroized on drop.
//! * Recovery codes: 80 random bits as 16 base32 characters; only a domain-separated SHA-256 is
//!   stored (the input has far too much entropy for a slow hash to add anything).

use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::crypto::{self, RandomError, ct_eq};

/// Seconds per TOTP step.
pub const STEP_SECS: i64 = 30;
/// Digits per code.
pub const DIGITS: usize = 6;
/// Secret length in bytes (160 bits, the RFC 4226 recommendation).
pub const SECRET_LEN: usize = 20;
/// Recovery codes generated per batch.
pub const RECOVERY_CODE_COUNT: usize = 10;
/// Characters in a recovery code (80 bits).
pub const RECOVERY_CODE_CHARS: usize = 16;
/// Issuer shown in authenticator apps.
pub const ISSUER: &str = "nzbd";
const NONCE_LEN: usize = 24;
/// Longest user input examined at all (code fields are capped before any work).
const MAX_CODE_INPUT: usize = 64;
/// Bytes of randomness in an enrollment token (160 bits, 32 base32 characters).
const ENROLL_TOKEN_BYTES: usize = 20;
/// Characters in a canonical enrollment token.
pub const ENROLL_TOKEN_CHARS: usize = 32;
/// How long a printed enrollment token stays valid (24 h).
pub const ENROLL_TOKEN_TTL_SECS: i64 = 24 * 3600;
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Why sealing a secret failed (no detail on purpose).
#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    /// OS randomness unavailable.
    #[error(transparent)]
    Random(#[from] RandomError),
    /// The AEAD refused to encrypt (cannot happen with valid sizes).
    #[error("could not encrypt the TOTP secret")]
    Seal,
}

/// The 32-byte key that encrypts TOTP secrets at rest. Zeroized on drop; never printed.
pub struct TotpKey([u8; 32]);

impl TotpKey {
    /// Copies exactly 32 bytes; any other length is refused.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        <[u8; 32]>::try_from(bytes).ok().map(Self)
    }
}

impl Drop for TotpKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl std::fmt::Debug for TotpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpKey([REDACTED])")
    }
}

/// A fresh random TOTP secret.
///
/// # Errors
/// OS randomness unavailable.
pub fn generate_secret() -> Result<Zeroizing<[u8; SECRET_LEN]>, RandomError> {
    Ok(Zeroizing::new(crypto::random_bytes::<SECRET_LEN>()?))
}

/// Encrypts `secret` for storage: `nonce(24) || ciphertext || tag(16)`, AAD = big-endian user id,
/// so a blob copied to another user's row does not decrypt.
///
/// # Errors
/// Randomness or AEAD failure.
pub fn seal(key: &TotpKey, user_id: i64, secret: &[u8]) -> Result<Vec<u8>, TotpError> {
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0).map_err(|_| TotpError::Seal)?;
    let nonce = crypto::random_bytes::<NONCE_LEN>()?;
    let aad = user_id.to_be_bytes();
    let ct = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: secret,
                aad: &aad,
            },
        )
        .map_err(|_| TotpError::Seal)?;
    let mut out = Vec::with_capacity(NONCE_LEN.saturating_add(ct.len()));
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypts a blob made by [`seal`]. `None` for a wrong key, wrong user, truncation or tampering.
#[must_use]
pub fn open(key: &TotpKey, user_id: i64, blob: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let (nonce, ct) = blob.split_at_checked(NONCE_LEN)?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0).ok()?;
    let aad = user_id.to_be_bytes();
    cipher
        .decrypt(&XNonce::from(nonce), Payload { msg: ct, aad: &aad })
        .ok()
        .map(Zeroizing::new)
}

/// RFC 4226 HOTP value (6 digits) for `counter`.
fn hotp(secret: &[u8], counter: u64) -> Option<u32> {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).ok()?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest.last()? & 0x0f);
    let window = digest.get(offset..offset.checked_add(4)?)?;
    let bin = u32::from_be_bytes(window.try_into().ok()?) & 0x7fff_ffff;
    Some(bin % 1_000_000)
}

/// The 6-digit code valid in `step` (`unix_time / 30`), zero padded.
#[must_use]
pub fn code_at(secret: &[u8], step: i64) -> Option<String> {
    let counter = u64::try_from(step).ok()?;
    hotp(secret, counter).map(|v| format!("{v:06}"))
}

/// Removes what pasting adds to a code: any Unicode whitespace (NBSP, thin space, ...) and
/// hyphen-like dashes (U+2010..U+2015, U+2212). Input over [`MAX_CODE_INPUT`] bytes is refused
/// before anything is examined.
fn strip_separators(input: &str) -> Option<String> {
    if input.len() > MAX_CODE_INPUT {
        return None;
    }
    Some(
        input
            .chars()
            .filter(|c| {
                !c.is_whitespace() && !matches!(*c, '-' | '\u{2010}'..='\u{2015}' | '\u{2212}')
            })
            .collect(),
    )
}

/// Normalizes user input to exactly six ASCII digits (authenticator apps show `123 456`; pasted
/// text may carry NBSP or other separators). Length and charset are checked before any
/// cryptography runs; non-ASCII digits are rejected.
#[must_use]
pub fn parse_totp_code(input: &str) -> Option<String> {
    let digits = strip_separators(input)?;
    (digits.len() == DIGITS && digits.bytes().all(|b| b.is_ascii_digit())).then_some(digits)
}

/// The step in `now ± 1` whose code equals `code` (six ASCII digits), compared in constant time.
/// All three candidates are always computed; the highest match wins.
#[must_use]
pub fn matching_step(secret: &[u8], now: i64, code: &str) -> Option<i64> {
    let base = now.div_euclid(STEP_SECS);
    let mut found: Option<i64> = None;
    for delta in [-1_i64, 0, 1] {
        let step = base.saturating_add(delta);
        if let Some(candidate) = code_at(secret, step)
            && ct_eq(candidate.as_bytes(), code.as_bytes())
        {
            found = Some(step);
        }
    }
    found
}

/// RFC 4648 base32 without padding.
#[must_use]
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(8).div_ceil(5));
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for b in bytes {
        buf = (buf << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = usize::try_from((buf >> bits) & 31).unwrap_or(0);
            out.push(char::from(B32.get(idx).copied().unwrap_or(b'A')));
        }
        buf &= (1 << bits) - 1;
    }
    if bits > 0 {
        let idx = usize::try_from((buf << (5 - bits)) & 31).unwrap_or(0);
        out.push(char::from(B32.get(idx).copied().unwrap_or(b'A')));
    }
    out
}

/// Decodes unpadded (or padded) base32; `None` on any character outside the alphabet.
#[must_use]
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.trim_end_matches('=').bytes() {
        let v = u32::try_from(B32.iter().position(|a| *a == c.to_ascii_uppercase())?).ok()?;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).ok()?);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// `otpauth://` provisioning URI for authenticator apps. `username` is restricted to
/// `[A-Za-z0-9._-]` by the user repository, so no percent-encoding is needed.
#[must_use]
pub fn otpauth_uri(username: &str, secret: &[u8]) -> String {
    format!(
        "otpauth://totp/{ISSUER}:{username}?secret={}&issuer={ISSUER}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        base32_encode(secret)
    )
}

/// Renders `text` as a QR code and returns it as a `data:image/svg+xml;base64,...` URI for an
/// `<img>` (allowed by the CSP `img-src 'self' data:`; no inline script or style, no `|safe`,
/// no external service). The SVG is built here from module coordinates only.
#[must_use]
pub fn qr_svg_data_uri(text: &str) -> Option<String> {
    use qrcode::{Color, QrCode};
    const QUIET: usize = 4;
    let code = QrCode::new(text.as_bytes()).ok()?;
    let width = code.width();
    let size = width.checked_add(QUIET.checked_mul(2)?)?;
    let mut path = String::new();
    for (y, row) in code.to_colors().chunks(width).enumerate() {
        for (x, c) in row.iter().enumerate() {
            if *c == Color::Dark {
                let _ = write!(path, "M{} {}h1v1h-1z", x + QUIET, y + QUIET);
            }
        }
    }
    let svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" \
         shape-rendering=\"crispEdges\"><rect width=\"{size}\" height=\"{size}\" fill=\"#fff\"/>\
         <path fill=\"#000\" d=\"{path}\"/></svg>"
    );
    Some(format!(
        "data:image/svg+xml;base64,{}",
        STANDARD.encode(svg.as_bytes())
    ))
}

/// Ten fresh recovery codes in canonical form (16 base32 characters, no separators).
///
/// # Errors
/// OS randomness unavailable.
pub fn generate_recovery_codes() -> Result<Vec<String>, RandomError> {
    (0..RECOVERY_CODE_COUNT)
        .map(|_| Ok(base32_encode(&crypto::random_bytes::<10>()?)))
        .collect()
}

/// Display form `XXXX-XXXX-XXXX-XXXX` of a canonical code.
#[must_use]
pub fn format_recovery(code: &str) -> String {
    let mut out = String::with_capacity(code.len().saturating_add(3));
    for (i, ch) in code.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push('-');
        }
        out.push(ch);
    }
    out
}

/// Canonical form of user input (separators removed, upper-cased), or `None` unless it is
/// exactly 16 base32 characters. Checked before any hashing or database work.
#[must_use]
pub fn normalize_recovery(input: &str) -> Option<String> {
    let canon = strip_separators(input)?.to_ascii_uppercase();
    (canon.len() == RECOVERY_CODE_CHARS && canon.bytes().all(|b| B32.contains(&b))).then_some(canon)
}

/// A fresh one-time enrollment token in canonical form (32 base32 characters, 160 bits).
///
/// # Errors
/// OS randomness unavailable.
pub fn generate_enroll_token() -> Result<String, RandomError> {
    Ok(base32_encode(&crypto::random_bytes::<ENROLL_TOKEN_BYTES>()?))
}

/// Canonical form of a typed/pasted enrollment token, or `None` if it is not 32 base32 characters.
#[must_use]
pub fn normalize_enroll_token(input: &str) -> Option<String> {
    let canon = strip_separators(input)?.to_ascii_uppercase();
    (canon.len() == ENROLL_TOKEN_CHARS && canon.bytes().all(|b| B32.contains(&b))).then_some(canon)
}

/// Storage hash of a canonical enrollment token (domain separated SHA-256).
#[must_use]
pub fn enroll_token_hash(canonical: &str) -> [u8; 32] {
    let mut msg = Vec::with_capacity(canonical.len().saturating_add(24));
    msg.extend_from_slice(b"nzbd/enroll-token/v1\0");
    msg.extend_from_slice(canonical.as_bytes());
    crypto::sha256(&msg)
}

/// Storage hash of a canonical recovery code (domain separated SHA-256).
#[must_use]
pub fn recovery_hash(canonical: &str) -> [u8; 32] {
    let mut msg = Vec::with_capacity(canonical.len().saturating_add(24));
    msg.extend_from_slice(b"nzbd/recovery-code/v1\0");
    msg.extend_from_slice(canonical.as_bytes());
    crypto::sha256(&msg)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_sha1_vectors_truncated_to_six_digits() {
        for (t, want) in [
            (59_i64, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ] {
            assert_eq!(code_at(RFC_SECRET, t / STEP_SECS).unwrap(), want, "t={t}");
        }
    }

    #[test]
    fn window_is_plus_minus_one_step_and_reports_the_step() {
        let now = 1_111_111_109;
        let step = now / STEP_SECS;
        for d in [-1, 0, 1] {
            let code = code_at(RFC_SECRET, step + d).unwrap();
            assert_eq!(matching_step(RFC_SECRET, now, &code), Some(step + d));
        }
        for d in [-2, 2, 10] {
            let code = code_at(RFC_SECRET, step + d).unwrap();
            assert_eq!(matching_step(RFC_SECRET, now, &code), None);
        }
    }

    #[test]
    fn pasted_separators_are_normalized_but_non_ascii_digits_are_not() {
        assert_eq!(parse_totp_code("123\u{a0}456").as_deref(), Some("123456"));
        assert_eq!(parse_totp_code("123\u{202f}456").as_deref(), Some("123456"));
        assert_eq!(
            parse_totp_code("123\u{2009}456\u{200a}").as_deref(),
            Some("123456")
        );
        assert_eq!(parse_totp_code("123\u{2013}456").as_deref(), Some("123456"));
        assert_eq!(
            parse_totp_code("\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}"),
            None
        );
        let c = "ABCD\u{2010}EFGH\u{2014}IJKL\u{a0}MNOP";
        assert_eq!(normalize_recovery(c).as_deref(), Some("ABCDEFGHIJKLMNOP"));
        assert_eq!(
            normalize_recovery(&"A\u{a0}".repeat(40)),
            None,
            "byte cap first"
        );
    }

    #[test]
    fn enroll_tokens_are_160_bit_and_hash_domain_separated() {
        let t = generate_enroll_token().unwrap();
        assert_eq!(t.len(), ENROLL_TOKEN_CHARS);
        assert_ne!(t, generate_enroll_token().unwrap());
        assert_eq!(
            normalize_enroll_token(&format_recovery(&t).to_lowercase()).as_deref(),
            Some(t.as_str())
        );
        assert!(normalize_enroll_token("short").is_none());
        assert_ne!(enroll_token_hash(&t), recovery_hash(&t));
        assert_ne!(enroll_token_hash(&t), crypto::sha256(t.as_bytes()));
    }

    #[test]
    fn code_parsing_checks_length_and_charset_first() {
        assert_eq!(parse_totp_code("123456").as_deref(), Some("123456"));
        assert_eq!(parse_totp_code(" 123 456 ").as_deref(), Some("123456"));
        for bad in ["12345", "1234567", "12345a", "١٢٣٤٥٦", "", &"1".repeat(500)] {
            assert_eq!(parse_totp_code(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn seal_roundtrip_binds_key_user_and_integrity() {
        let key = TotpKey::from_slice(&[7; 32]).unwrap();
        let secret = [0x42_u8; SECRET_LEN];
        let blob = seal(&key, 1, &secret).unwrap();
        assert!(!blob.windows(SECRET_LEN).any(|w| w == secret));
        assert_eq!(&*open(&key, 1, &blob).unwrap(), &secret);
        assert!(open(&key, 2, &blob).is_none(), "AAD must bind the user");
        assert!(open(&TotpKey::from_slice(&[8; 32]).unwrap(), 1, &blob).is_none());
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(&key, 1, &bad).is_none());
        assert!(open(&key, 1, &blob[..10]).is_none());
        // Random nonce: two seals of the same secret differ.
        assert_ne!(blob, seal(&key, 1, &secret).unwrap());
        assert!(TotpKey::from_slice(&[0; 31]).is_none());
        assert_eq!(format!("{key:?}"), "TotpKey([REDACTED])");
    }

    #[test]
    fn base32_roundtrip_and_known_answer() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("MZXW6YTBOI").unwrap(), b"foobar");
        assert_eq!(base32_decode("mzxw6ytboi===").unwrap(), b"foobar");
        assert!(base32_decode("MZXW1").is_none());
        assert_eq!(base32_encode(&[0; SECRET_LEN]).len(), 32);
    }

    #[test]
    fn recovery_code_forms() {
        let codes = generate_recovery_codes().unwrap();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        for c in &codes {
            assert_eq!(c.len(), RECOVERY_CODE_CHARS);
            let shown = format_recovery(c);
            assert_eq!(shown.len(), 19);
            assert_eq!(normalize_recovery(&shown).as_deref(), Some(c.as_str()));
            assert_eq!(
                normalize_recovery(&shown.to_lowercase()).as_deref(),
                Some(c.as_str())
            );
        }
        assert_ne!(codes.first(), codes.get(1));
        for bad in ["", "ABCD", "1111-1111-1111-1111", &"A".repeat(40)] {
            assert!(normalize_recovery(bad).is_none(), "{bad:?}");
        }
        assert_ne!(
            recovery_hash("AAAAAAAAAAAAAAAA"),
            crypto::sha256(b"AAAAAAAAAAAAAAAA")
        );
    }

    #[test]
    fn otpauth_and_qr_are_well_formed() {
        let uri = otpauth_uri("alice", RFC_SECRET);
        assert!(
            uri.starts_with("otpauth://totp/nzbd:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        );
        assert!(uri.contains("digits=6") && uri.contains("period=30"));
        let data = qr_svg_data_uri(&uri).unwrap();
        let b64 = data.strip_prefix("data:image/svg+xml;base64,").unwrap();
        let svg = String::from_utf8(STANDARD.decode(b64).unwrap()).unwrap();
        assert!(svg.starts_with("<svg ") && svg.ends_with("</svg>"));
        assert!(!svg.contains("<script") && !svg.contains("http://www.w3.org/1999/xlink"));
    }
}
