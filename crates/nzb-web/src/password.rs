//! Password policy, Argon2id hashing and verification (SEC-022).
//!
//! Parameters are fixed by SEC-022 (m = 64 MiB, t = 3, p = 1). Hashes are PHC strings, so
//! verification reads the parameters stored in the hash and old hashes stay verifiable if the
//! constants ever change. Secrets never appear in `Debug`/error output.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

/// Minimum password length in characters.
pub const MIN_PASSWORD_CHARS: usize = 12;
/// Maximum password length in characters (bounds Argon2 work and request size).
pub const MAX_PASSWORD_CHARS: usize = 256;
/// Memory cost in KiB (64 MiB).
pub const ARGON2_M_KIB: u32 = 64 * 1024;
/// Time cost (iterations).
pub const ARGON2_T: u32 = 3;
/// Parallelism.
pub const ARGON2_P: u32 = 1;
const SALT_BYTES: usize = 16;

/// Why a password was rejected or could not be processed. Messages contain no secret material.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PasswordError {
    /// Fewer than [`MIN_PASSWORD_CHARS`] characters.
    #[error("password must be at least 12 characters")]
    TooShort,
    /// More than [`MAX_PASSWORD_CHARS`] characters.
    #[error("password must be at most 256 characters")]
    TooLong,
    /// Equal to the username (case-insensitive).
    #[error("password must not be the same as the username")]
    SameAsUsername,
    /// Contains a NUL or other control character.
    #[error("password must not contain control characters")]
    ControlChars,
    /// Fewer than [`MIN_DISTINCT_CHARS`] distinct characters (covers one repeated character and
    /// all-space input).
    #[error("password must contain at least 6 different characters")]
    TooFewDistinct,
    /// No letter or digit at all (only whitespace/punctuation/symbols).
    #[error("password must contain letters or digits")]
    NoAlphanumeric,
    /// A keyboard walk or an ascending/descending run of letters or digits.
    #[error("password must not be a keyboard or sequence pattern")]
    Pattern,
    /// On the embedded list of common passwords.
    #[error("password is too common")]
    Common,
    /// Hashing failed (parameters or randomness).
    #[error("password hashing failed")]
    Hash,
}

/// Minimum number of distinct characters (T083, residual-risk L-11).
pub const MIN_DISTINCT_CHARS: usize = 6;

/// Shortest normalized form the pattern check applies to (shorter ones are mostly punctuation
/// and would match any two-letter slice of a walk).
const MIN_PATTERN_CHARS: usize = 6;

/// Embedded list of common passwords: normalized (lowercase ASCII alphanumerics), one per line,
/// `#` comments. Plain data committed to the repository; never fetched at build time.
const COMMON_PASSWORDS: &str = include_str!("common_passwords.txt");

/// Keyboard rows and runs. A candidate that is a contiguous slice of one of them (or of its
/// reverse) is a "walk". Digits wrap (`...890123`) because `123456789012` is the canonical
/// 12-character example.
const WALKS: [&str; 5] = [
    "0123456789012345678901234567890123456789",
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiopasdfghjklzxcvbnm",
    "azertyuiopqsdfghjklmwxcvbn",
    "qwertzuiopasdfghjklyxcvbnm",
];

fn common_set() -> &'static std::collections::HashSet<&'static str> {
    static SET: std::sync::OnceLock<std::collections::HashSet<&'static str>> =
        std::sync::OnceLock::new();
    SET.get_or_init(|| {
        COMMON_PASSWORDS
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    })
}

/// Lowercased ASCII letters/digits of `password`, everything else dropped: the comparison form
/// for the pattern and common-password checks.
fn normalized(password: &str) -> String {
    password
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// True when `s` is one block repeated two or more times (`abcdefabcdef`).
fn is_repetition(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    (1..=n / 2).filter(|p| n.is_multiple_of(*p)).any(|p| {
        chars
            .iter()
            .enumerate()
            .all(|(i, c)| chars.get(i % p) == Some(c))
    })
}

/// True when `s` is a contiguous slice of a walk (or its reverse), or a strict +1/-1 run by
/// code point.
fn is_sequence(s: &str) -> bool {
    if s.chars().count() < MIN_PATTERN_CHARS {
        return false;
    }
    let rev: String = s.chars().rev().collect();
    // A reversed candidate sliced out of a forward walk is the same as the candidate sliced out
    // of the reversed walk, so one reversal of the candidate covers both directions.
    if WALKS
        .iter()
        .any(|w| w.contains(s) || w.contains(rev.as_str()))
    {
        return true;
    }
    let codes: Vec<i64> = s.chars().map(|c| i64::from(u32::from(c))).collect();
    let step = |d: i64| {
        codes
            .windows(2)
            .all(|w| matches!(w, [a, b] if b.saturating_sub(*a) == d))
    };
    step(1) || step(-1)
}

/// Checks the password policy (`AUTH_SPEC`: 12-256 chars, no controls, not the username, at
/// least [`MIN_DISTINCT_CHARS`] distinct characters, some letter or digit, no obvious keyboard
/// or sequence pattern, not on the embedded common-password list). Error texts are fixed and
/// never contain the password.
///
/// # Errors
/// The first violated rule.
pub fn validate_policy(username: &str, password: &str) -> Result<(), PasswordError> {
    let n = password.chars().count();
    if n < MIN_PASSWORD_CHARS {
        return Err(PasswordError::TooShort);
    }
    if n > MAX_PASSWORD_CHARS {
        return Err(PasswordError::TooLong);
    }
    if password.chars().any(char::is_control) {
        return Err(PasswordError::ControlChars);
    }
    if password.to_lowercase() == username.to_lowercase() {
        return Err(PasswordError::SameAsUsername);
    }
    let distinct: std::collections::HashSet<char> = password.chars().collect();
    if distinct.len() < MIN_DISTINCT_CHARS {
        return Err(PasswordError::TooFewDistinct);
    }
    if !password.chars().any(char::is_alphanumeric) {
        return Err(PasswordError::NoAlphanumeric);
    }
    let norm = normalized(password);
    if is_sequence(&norm) || (norm.len() >= MIN_PATTERN_CHARS && is_repetition(&norm)) {
        return Err(PasswordError::Pattern);
    }
    if common_set().contains(norm.as_str()) {
        return Err(PasswordError::Common);
    }
    Ok(())
}

fn hasher() -> Result<Argon2<'static>, PasswordError> {
    let params =
        Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, None).map_err(|_| PasswordError::Hash)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Fills `buf` from the kernel CSPRNG (same source `nzbd keygen` uses; no extra crate).
fn fill_random(buf: &mut [u8]) -> Result<(), PasswordError> {
    use std::io::Read as _;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .map_err(|e| {
            // Kind only: never the buffer or anything secret.
            tracing::error!(kind = ?e.kind(), "kernel random source failed");
            PasswordError::Hash
        })
}

fn random_salt() -> Result<SaltString, PasswordError> {
    let mut buf = [0_u8; SALT_BYTES];
    fill_random(&mut buf)?;
    SaltString::encode_b64(&buf).map_err(|_| PasswordError::Hash)
}

/// Hashes `password` with Argon2id and a fresh random salt; returns the PHC string.
/// Does not enforce the policy (call [`validate_policy`] first).
///
/// # Errors
/// [`PasswordError::Hash`] if randomness or hashing fails.
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    let salt = random_salt()?;
    let h = hasher()?
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| PasswordError::Hash)?;
    Ok(h.to_string())
}

/// Upper bounds on work factors accepted from a stored hash (a corrupt or tampered row must not
/// be able to stall login). Generous relative to SEC-022 so future upgrades still verify.
const MAX_VERIFY_M_KIB: u32 = 1024 * 1024;
const MAX_VERIFY_T: u32 = 10;
const MAX_VERIFY_P: u32 = 8;

/// Parses a stored PHC string and applies the algorithm/work-factor sanity bounds.
fn parse_usable(phc: &str) -> Option<PasswordHash<'_>> {
    let parsed = PasswordHash::new(phc).ok()?;
    if parsed.algorithm != Algorithm::Argon2id.ident() {
        return None;
    }
    let params = Params::try_from(&parsed).ok()?;
    if params.m_cost() > MAX_VERIFY_M_KIB
        || params.t_cost() > MAX_VERIFY_T
        || params.p_cost() > MAX_VERIFY_P
    {
        return None;
    }
    Some(parsed)
}

/// True when [`verify_password`] would run a full Argon2id verification against `phc` (as opposed
/// to failing fast on a malformed or out-of-bounds hash). Login uses this to substitute the dummy
/// hash so a corrupt row costs the same as any other attempt.
#[must_use]
pub fn hash_is_usable(phc: &str) -> bool {
    parse_usable(phc).is_some()
}

/// Verifies `password` against a PHC string. Comparison is constant-time (inside Argon2).
///
/// Returns `false` for: a malformed hash, a non-Argon2id hash, work factors above the sanity
/// bounds, or a password longer than [`MAX_PASSWORD_CHARS`]. In the over-length case the first
/// [`MAX_PASSWORD_CHARS`] characters are still verified (result discarded) so the cost matches a
/// normal attempt and per-request work stays bounded.
#[must_use]
pub fn verify_password(password: &str, phc: &str) -> bool {
    let Some(parsed) = parse_usable(phc) else {
        return false;
    };
    let over = password.chars().nth(MAX_PASSWORD_CHARS).is_some();
    let bounded: String;
    let input = if over {
        bounded = password.chars().take(MAX_PASSWORD_CHARS).collect();
        bounded.as_str()
    } else {
        password
    };
    let ok = Argon2::default()
        .verify_password(input.as_bytes(), &parsed)
        .is_ok();
    ok && !over
}

/// A valid hash of a random password, used to burn equal work for unknown users (SEC-022/026).
///
/// # Errors
/// [`PasswordError::Hash`] on hashing/randomness failure.
pub fn dummy_hash() -> Result<String, PasswordError> {
    // Random, never-disclosed input: nobody can log in with it.
    let mut bytes = [0_u8; 32];
    fill_random(&mut bytes)?;
    let pw = SaltString::encode_b64(&bytes).map_err(|_| PasswordError::Hash)?;
    hash_password(pw.as_str())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// 256 distinct-enough characters that trip none of the content rules.
    fn long_ok(n: usize) -> String {
        // LCG over a 16-symbol alphabet: no short period, so no repetition rule fires.
        let alphabet: Vec<char> = "Xv9#kQ2mLp4$wz7&".chars().collect();
        let mut x: u64 = 12345;
        (0..n)
            .map(|_| {
                x = (x * 1_103_515_245 + 12345) % (1 << 31);
                *alphabet
                    .get(usize::try_from((x >> 16) % 16).unwrap())
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn sec_022_policy_length_and_username() {
        assert_eq!(
            validate_policy("alice", "short"),
            Err(PasswordError::TooShort)
        );
        assert_eq!(
            validate_policy("alice", &long_ok(11)),
            Err(PasswordError::TooShort)
        );
        assert!(validate_policy("alice", &long_ok(12)).is_ok());
        assert!(validate_policy("alice", &long_ok(256)).is_ok());
        assert_eq!(
            validate_policy("alice", &long_ok(257)),
            Err(PasswordError::TooLong)
        );
        assert_eq!(
            validate_policy("administrator", "Administrator"),
            Err(PasswordError::SameAsUsername)
        );
        assert_eq!(
            validate_policy("alice", "abcdefghijk\0l"),
            Err(PasswordError::ControlChars)
        );
        // Length counts characters, not bytes.
        assert!(validate_policy("alice", "éèêëàâäôöûüç").is_ok());
        assert_eq!(
            validate_policy("alice", &"é".repeat(12)),
            Err(PasswordError::TooFewDistinct)
        );
    }

    #[test]
    fn sec_022_policy_rejects_low_entropy_and_patterns() {
        use PasswordError::{Common, NoAlphanumeric, Pattern, TooFewDistinct};
        let cases: &[(&str, PasswordError)] = &[
            ("aaaaaaaaaaaa", TooFewDistinct),
            ("            ", TooFewDistinct),
            ("!!!!!!!!!!!!", TooFewDistinct),
            ("abababababab", TooFewDistinct),
            ("ab12ab12ab12", TooFewDistinct),
            ("abcde abcde abcde", Pattern),
            ("abcdefabcdef", Pattern),
            ("k9#Zq2k9#Zq2", Pattern),
            ("!@#$%^&*()_+-=", NoAlphanumeric),
            (" - - - . , ; : ", NoAlphanumeric),
            ("123456789012", Pattern),
            ("1234567890123", Pattern),
            ("098765432109", Pattern),
            ("qwertyuiopas", Pattern),
            ("QWERTYUIOPAS", Pattern),
            ("asdfghjklzxc", Pattern),
            ("azertyuiopqs", Pattern),
            ("abcdefghijkl", Pattern),
            ("zyxwvutsrqpo", Pattern),
            ("q-w-e-r-t-y-u-i-o-p", Pattern),
            ("1 2 3 4 5 6 7 8 9 0", Pattern),
            ("passwordpassword", Pattern),
            ("iloveyou123456", Common),
            ("Password-123!!!", Common),
            ("P a s s w o r d 1 2 3", Common),
            ("iloveyou1234", Common),
            ("Correct Horse Battery Staple", Common),
        ];
        for (pw, want) in cases {
            assert_eq!(validate_policy("alice", pw).as_ref(), Err(want), "{pw:?}");
        }
        // Reasonable passphrases and mixed passwords pass.
        for ok in [
            "correct horse battery",
            "tr0ub4dor&3-and-a-bit",
            "Xv9#kQ2m-Lp4$wz",
            "my dog ate the 7 sandwiches",
            "1357913579246",
        ] {
            assert!(validate_policy("alice", ok).is_ok(), "{ok:?}");
        }
    }

    #[test]
    fn sec_022_policy_errors_never_echo_the_password() {
        let secret = "Hunter-2-qwertyuiop-SECRET";
        for pw in ["aaaaaaaaaaaa", "123456789012", "iloveyou123456", secret] {
            if let Err(e) = validate_policy("alice", pw) {
                assert!(!e.to_string().contains(pw), "{e}");
            }
        }
    }

    #[test]
    fn sec_022_common_list_is_well_formed() {
        let mut n = 0_usize;
        let mut prev = "";
        for line in COMMON_PASSWORDS.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            n += 1;
            // Normalized, long enough to matter, sorted and unique (cheap to review and diff).
            assert!(
                line.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
                "{line}"
            );
            assert!(line.len() >= 8, "{line}");
            assert!(prev < line, "{prev} / {line}");
            prev = line;
        }
        assert!((500..=20_000).contains(&n), "{n}");
        assert_eq!(common_set().len(), n);
    }

    #[test]
    fn sec_022_argon2id_params_and_roundtrip() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"), "{h}");
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("correct horse batterz", &h));
        assert!(!verify_password("x", "not a phc string"));
        // Fresh salt per hash.
        assert_ne!(h, hash_password("correct horse battery").unwrap());
    }

    #[test]
    fn sec_022_verify_rejects_oversize_password() {
        let pw = "a".repeat(MAX_PASSWORD_CHARS);
        let h = hash_password(&pw).unwrap();
        assert!(verify_password(&pw, &h));
        // The 256-char prefix matches the hash, yet the over-length input must still fail.
        let long = format!("{pw}b");
        assert!(!verify_password(&long, &h));
        assert!(!verify_password(&"a".repeat(100_000), &h));
    }

    #[test]
    fn sec_022_verify_bounds_stored_work_factors() {
        // Valid syntax, absurd parameters: rejected without computing.
        let salt = "c2FsdHNhbHRzYWx0";
        let hash = "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g";
        for params in ["m=4194304,t=3,p=1", "m=65536,t=99,p=1", "m=65536,t=3,p=64"] {
            let phc = format!("$argon2id${}${salt}${hash}", format_args!("v=19${params}"));
            assert!(!verify_password("whatever password", &phc), "{phc}");
        }
        // Wrong algorithm variant is refused as well.
        let phc = format!("$argon2i$v=19$m=65536,t=3,p=1${salt}${hash}");
        assert!(!verify_password("whatever password", &phc));
    }

    #[test]
    fn sec_022_dummy_hash_is_valid_and_unguessable() {
        let d = dummy_hash().unwrap();
        assert!(d.starts_with("$argon2id$"));
        assert!(!verify_password("", &d));
    }
}
