//! Registration profile: the email and the self-chosen display name an invitee gives at `/invite` (T109, DECISIONS
//! D32, migration 0014). Pure validators only; the redemption transaction that uses them is
//! [`crate::SqliteDb::redeem_code_with_profile`].
//!
//! * **Display name chosen by the invitee** ([`self_display_name_is_valid`]): 3..=32 of `[A-Za-z0-9_-]`, stricter than
//!   the admin/CLI rule ([`crate::display_name_is_valid`], unchanged). Names whose refusal needs no lookup (the reserved
//!   actor names and the `user-<n>` / `acct-<n>` handle forms) are refused here, as *shape*: telling the holder "that
//!   form is reserved" reveals nothing about other accounts, so it must not burn one of the invitation's three
//!   "not available" answers.
//! * **Email** ([`normalize_email`]): a deliberately small, ASCII-only subset of RFC 5321 addresses. It is PII: it never
//!   goes into a log line, an audit `detail`, an error value or a URL, and nothing ever sends to it or resolves its
//!   domain (D3, zero outbound).

use crate::account::{is_reserved_actor_name, is_reserved_handle_form};

/// Shortest self-chosen display name in characters.
pub const MIN_SELF_DISPLAY_NAME_CHARS: usize = 3;
/// Longest self-chosen display name in characters (same ceiling as the admin rule and the column CHECK).
pub const MAX_SELF_DISPLAY_NAME_CHARS: usize = crate::account::MAX_DISPLAY_NAME_CHARS;
/// Longest stored email (RFC 5321 path limit minus the angle brackets; the column CHECK is the backstop).
pub const MAX_EMAIL_LEN: usize = 254;
/// Longest email local part.
pub const MAX_EMAIL_LOCAL_LEN: usize = 64;
/// Longest domain label.
const MAX_LABEL_LEN: usize = 63;
/// Raw input longer than this is refused before any other work (a real address plus padding is far shorter).
const MAX_EMAIL_INPUT: usize = 1024;

/// What an invitee submits at `/invite` besides the code and the password: raw form values, validated and
/// normalised by the store inside the redemption transaction, only once the code is proven valid. `Debug` redacts
/// the email (PII).
#[derive(Clone, Copy)]
pub struct RegistrationProfile<'a> {
    /// The email as typed (trimmed and lower-cased by [`normalize_email`]).
    pub email: &'a str,
    /// The display name as typed (must pass [`self_display_name_is_valid`] exactly; it is not altered).
    pub display_name: &'a str,
}

impl std::fmt::Debug for RegistrationProfile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationProfile")
            .field("email", &"[REDACTED]")
            .field("display_name", &self.display_name)
            .finish()
    }
}

/// System labels and privileged-sounding words a self-chosen display name must not imitate (`SECURITY_REVIEW` 26 L1),
/// compared with [`look_alike_key`]: the "Added by" labels of the release page (`Watch folder`, `Deleted account`,
/// `Before accounts`), the audit actor kinds and words that read as the instance itself.
const RESERVED_LOOK_ALIKES: [&str; 12] = [
    "watchfolder",
    "deletedaccount",
    "beforeaccounts",
    "operator",
    "admin",
    "administrator",
    "root",
    "nzbd",
    "system",
    "anonymous",
    "cli",
    "api",
];

/// Prefixes of the default-handle forms (`user-<id>`, `acct-<id>`) and their common abbreviation, compared with
/// [`look_alike_key`].
const HANDLE_PREFIXES: [&str; 3] = ["user", "usr", "acct"];

/// The key L1 compares on: ASCII lower-case with every `-` and `_` removed (`Watch-folder` -> `watchfolder`,
/// `user_1` -> `user1`).
fn look_alike_key(name: &str) -> String {
    name.bytes()
        .filter(|b| !matches!(b, b'-' | b'_'))
        .map(|b| char::from(b.to_ascii_lowercase()))
        .collect()
}

/// True if `key` (a [`look_alike_key`]) reads as a default handle: a handle prefix followed by a digit (as the
/// admin rule refuses `user-1abc`), or by a non-empty rest made only of digits and the digit look-alikes `o`, `i`,
/// `l` (`user-l`, `user-O7`, `usr-1`). A prefix followed by any other letter (`userland`, `username`, `acctg`) is an
/// ordinary word and stays allowed: a default handle is `<prefix>-<digits>` only, so such a name cannot be mistaken
/// for one.
fn reads_as_handle(key: &str) -> bool {
    HANDLE_PREFIXES.iter().any(|p| {
        key.strip_prefix(p).is_some_and(|rest| {
            rest.bytes().next().is_some_and(|b| b.is_ascii_digit())
                || (!rest.is_empty()
                    && rest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || matches!(b, b'o' | b'i' | b'l')))
        })
    })
}

/// Confusable skeleton of a display name (`SECURITY_REVIEW` 26 L2): ASCII lower-case, `_` -> `-`, `0` -> `o`, `1`/`i`/`l`
/// -> `l`, then `rn` -> `m` and `vv` -> `w`. Two names with the same skeleton look alike in the UI (`AIice` / `Alice`,
/// `bob_smith` / `bob-smith`, `rnike` / `mike`), so a NEW name whose skeleton equals that of another live display name is
/// not available. Other characters (the admin rule also allows space and `.`) are kept as they are.
#[must_use]
pub fn display_name_skeleton(name: &str) -> String {
    let mapped: String = name
        .chars()
        .map(|c| match c.to_ascii_lowercase() {
            '_' => '-',
            '0' => 'o',
            '1' | 'i' | 'l' => 'l',
            other => other,
        })
        .collect();
    mapped.replace("rn", "m").replace("vv", "w")
}

/// True if `prefix` followed by a digit starts `lower` (`user-1...`, `acct-2...`).
fn starts_with_handle_prefix(lower: &str, prefix: &str) -> bool {
    lower
        .strip_prefix(prefix)
        .and_then(|rest| rest.bytes().next())
        .is_some_and(|b| b.is_ascii_digit())
}

/// Shape of a display name chosen by the invitee (D32): 3..=32 of `[A-Za-z0-9_-]`, not a reserved actor name
/// (`system|cli|api|anonymous`), not of the default-handle forms `user-<digits>...` / `acct-<digits>...` (N5: those
/// belong to the account whose id they carry). Look-alikes are refused here too, as free shape errors
/// (`SECURITY_REVIEW` 26 L1): on the key "lower-case, `-` and `_` removed", anything starting with `user`, `usr` or `acct`
/// that then reads as a handle number (see `reads_as_handle`: `user_1`, `user1`, `User-l`, `usr-1`, `acct_3`), and
/// anything equal to a system label or privileged word (`Watch-folder`, `Deleted_account`, `Before_accounts`,
/// `operator`, `admin`, `administrator`, `root`, `nzbd`, ...). Availability (login names, live display names and their
/// confusable skeletons, open invitations) is a separate, counted check in the redemption transaction.
#[must_use]
pub fn self_display_name_is_valid(name: &str) -> bool {
    let n = name.len(); // ASCII-only below, so bytes == characters
    if !(MIN_SELF_DISPLAY_NAME_CHARS..=MAX_SELF_DISPLAY_NAME_CHARS).contains(&n)
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    let key = look_alike_key(name);
    !(is_reserved_actor_name(name)
        || is_reserved_handle_form(name)
        || starts_with_handle_prefix(&lower, "user-")
        || starts_with_handle_prefix(&lower, "acct-")
        || reads_as_handle(&key)
        || RESERVED_LOOK_ALIKES.contains(&key.as_str()))
}

fn email_local_ok(local: &str) -> bool {
    (1..=MAX_EMAIL_LOCAL_LEN).contains(&local.len())
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-'))
}

fn email_label_ok(label: &str) -> bool {
    (1..=MAX_LABEL_LEN).contains(&label.len())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn email_domain_ok(domain: &str) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| email_label_ok(l))
        && labels
            .last()
            .is_some_and(|tld| tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic()))
}

/// Validates and normalises an email (D32). Surrounding ASCII whitespace is trimmed, then the address must be ASCII,
/// at most 254 characters, `local@domain` with exactly one `@`; local part 1..=64 of `[A-Za-z0-9._%+-]` without a
/// leading, trailing or doubled dot; domain of 2+ labels of `[A-Za-z0-9-]{1,63}` that neither start nor end with a
/// hyphen, the last label letters only and 2+ long. Returns the lower-cased address, or `None` (IDN / Unicode,
/// quoted local parts, IP literals, comments and anything else are refused, never repaired).
#[must_use]
pub fn normalize_email(raw: &str) -> Option<String> {
    if raw.len() > MAX_EMAIL_INPUT {
        return None;
    }
    let s = raw.trim_matches(|c: char| c.is_ascii_whitespace());
    if !s.is_ascii() || s.len() > MAX_EMAIL_LEN {
        return None;
    }
    let (local, domain) = s.split_once('@')?;
    (email_local_ok(local) && email_domain_ok(domain)).then(|| s.to_ascii_lowercase())
}
