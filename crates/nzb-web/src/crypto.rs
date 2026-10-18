//! Small cryptographic helpers shared by the auth modules: OS randomness, hex, constant-time
//! comparison, SHA-256 and the HMAC used for pre-session (login form) tokens.

use std::fmt::Write as _;
use std::io::Read as _;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// The kernel random source could not be read. Callers must fail the request/startup; there is
/// deliberately no weaker fallback (session ids and tokens must never be predictable).
#[derive(Debug, thiserror::Error)]
#[error("operating system random source unavailable")]
pub struct RandomError;

/// `N` bytes from the OS CSPRNG.
///
/// # Errors
/// [`RandomError`] if `/dev/urandom` cannot be read.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut buf = [0_u8; N];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| {
            tracing::error!(kind = ?e.kind(), "kernel random source failed");
            RandomError
        })?;
    Ok(buf)
}

/// Lowercase hex encoding.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        // Writing to a String cannot fail.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decodes lowercase/uppercase hex; `None` on odd length or a non-hex character.
#[must_use]
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = char::from(*pair.first()?).to_digit(16)?;
            let lo = char::from(*pair.get(1)?).to_digit(16)?;
            u8::try_from(hi.checked_mul(16)?.checked_add(lo)?).ok()
        })
        .collect()
}

/// Constant-time equality. Length differences return early (lengths are not secret here: every
/// compared secret has a fixed, public length).
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// SHA-256 of `bytes`.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 tag.
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Option<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key).ok()?;
    mac.update(msg);
    Some(mac.finalize().into_bytes().into())
}

/// Verifies an HMAC-SHA256 tag in constant time.
#[must_use]
pub fn hmac_sha256_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> bool {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    mac.update(msg);
    mac.verify_slice(tag).is_ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn hex_roundtrip_and_rejects_garbage() {
        assert_eq!(hex(&[0, 255, 16]), "00ff10");
        assert_eq!(unhex("00FF10"), Some(vec![0, 255, 16]));
        assert_eq!(unhex("0"), None);
        assert_eq!(unhex("zz"), None);
        assert_eq!(unhex("\u{e9}\u{e9}"), None);
    }

    #[test]
    fn ct_eq_basics() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }

    #[test]
    fn hmac_known_answer_rfc4231_case_2() {
        let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?").unwrap();
        assert_eq!(
            hex(&tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert!(hmac_sha256_verify(
            b"Jefe",
            b"what do ya want for nothing?",
            &tag
        ));
        assert!(!hmac_sha256_verify(b"Jefe", b"other", &tag));
    }

    #[test]
    fn random_bytes_differ() {
        assert_ne!(random_bytes::<32>().unwrap(), random_bytes::<32>().unwrap());
    }
}
