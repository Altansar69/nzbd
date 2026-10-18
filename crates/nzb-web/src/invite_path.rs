//! The configurable path of the invitation page (`security.invite_path`, T135).
//!
//! The anonymous invitation form (`AUTH_SPEC` "Accounts: creation paths" 3) is served at one
//! configured path instead of the fixed `/invite`, so an operator can keep it out of reach of
//! scanners that probe well-known paths. This is obscurity, not protection: the path is not a
//! secret (no secret handling, it may be logged like any path) and the one-time code stays the
//! only gate. The path is still never rendered on an anonymous page.
//!
//! A value of this type is always valid: the only constructors are [`InvitePath::parse`] and
//! [`Default`], so the router can mount it without a fallible step (axum refuses some route
//! syntax at runtime; the charset below excludes all of it).
//!
//! Collisions: the single segment must not equal, be a prefix of, or start with the first segment
//! of any built-in route of [`crate::routes::INVENTORY`] (case-insensitively), so a future route
//! can never be shadowed by, or shadow, the invitation page without failing startup. The
//! inventory's own invitation entry is the placeholder of this path and is skipped.

use std::sync::Arc;

use crate::routes::{INVENTORY, INVITE_PATH_PLACEHOLDER};

/// The built-in invitation path (`security.invite_path` default).
pub const DEFAULT_INVITE_PATH: &str = INVITE_PATH_PLACEHOLDER;
/// Shortest accepted segment (characters after the leading `/`).
pub const MIN_INVITE_SEGMENT: usize = 6;
/// Longest accepted segment.
pub const MAX_INVITE_SEGMENT: usize = 64;
/// Stable refusal code of an invalid `security.invite_path` (startup and `config check`).
pub const INVITE_PATH_INVALID: &str = "INVITE_PATH_INVALID";

/// Why a configured invitation path was refused. The messages name the rule, never more than
/// the (non-secret) configured value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvitePathError {
    /// It does not start with `/`.
    #[error("must start with /")]
    NoLeadingSlash,
    /// More than one segment (a `/` after the first character).
    #[error("must be a single path segment (no further /)")]
    NotSingleSegment,
    /// The segment is shorter or longer than allowed.
    #[error("must have {MIN_INVITE_SEGMENT} to {MAX_INVITE_SEGMENT} characters after the /")]
    Length,
    /// A character outside `[A-Za-z0-9_-]` (this also excludes `.`, `..`, `%`, `{`, spaces).
    #[error("may only use the characters A-Z a-z 0-9 _ -")]
    Charset,
    /// The segment collides with a built-in route.
    #[error("collides with the built-in route {0}")]
    Collides(&'static str),
    /// A custom value that starts with `invite` (review 49 I1): it would sit next to the
    /// well-known default and defeat the point of moving the page. Only `/invite` itself is
    /// accepted with that prefix.
    #[error("must not start with \"invite\" (only the default /invite itself may)")]
    InvitePrefix,
}

impl InvitePathError {
    /// The stable code of every refusal ([`INVITE_PATH_INVALID`]).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        INVITE_PATH_INVALID
    }
}

/// A validated invitation path, `/` followed by one segment of 6-64 `[A-Za-z0-9_-]` characters
/// that collides with no built-in route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitePath(Arc<str>);

impl Default for InvitePath {
    fn default() -> Self {
        Self(Arc::from(DEFAULT_INVITE_PATH))
    }
}

impl std::fmt::Display for InvitePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// First path segment of a route pattern (`/admin/users` -> `admin`; `/` -> empty).
fn first_segment(pattern: &str) -> &str {
    pattern
        .strip_prefix('/')
        .unwrap_or(pattern)
        .split('/')
        .next()
        .unwrap_or_default()
}

impl InvitePath {
    /// Validates a configured path.
    ///
    /// # Errors
    /// [`InvitePathError`] for each refused shape and for a collision with a built-in route.
    pub fn parse(raw: &str) -> Result<Self, InvitePathError> {
        let Some(segment) = raw.strip_prefix('/') else {
            return Err(InvitePathError::NoLeadingSlash);
        };
        if segment.contains('/') {
            return Err(InvitePathError::NotSingleSegment);
        }
        // Characters before length: a non-ASCII value must not pass a byte-length check by
        // accident, and every accepted character is one byte.
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(InvitePathError::Charset);
        }
        if !(MIN_INVITE_SEGMENT..=MAX_INVITE_SEGMENT).contains(&segment.len()) {
            return Err(InvitePathError::Length);
        }
        let candidate = segment.to_ascii_lowercase();
        if candidate.starts_with("invite") && raw != DEFAULT_INVITE_PATH {
            return Err(InvitePathError::InvitePrefix);
        }
        for spec in INVENTORY {
            if spec.is_invite_placeholder() {
                continue;
            }
            let builtin = first_segment(spec.path).to_ascii_lowercase();
            if builtin.is_empty() {
                // `/` itself: every path starts with it, nothing to compare.
                continue;
            }
            if candidate.starts_with(&builtin) || builtin.starts_with(&candidate) {
                return Err(InvitePathError::Collides(spec.path));
            }
        }
        Ok(Self(Arc::from(raw)))
    }

    /// The path, e.g. `/invite` or `/join-7f3k9q`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `true` for the built-in `/invite` (the login page links to it only then).
    #[must_use]
    pub fn is_default(&self) -> bool {
        &*self.0 == DEFAULT_INVITE_PATH
    }

    /// The address handed to an invitee: `address` + path when a public address is configured,
    /// else the path alone.
    #[must_use]
    pub fn url(&self, address: Option<&str>) -> String {
        match address {
            Some(a) => format!("{a}{}", self.0),
            None => self.0.to_string(),
        }
    }

    /// The concrete path of an inventory route pattern: the invitation placeholder becomes this
    /// path, every other pattern is returned unchanged (for walks over [`INVENTORY`]).
    #[must_use]
    pub fn resolve<'a>(&'a self, pattern: &'a str) -> &'a str {
        if pattern == INVITE_PATH_PLACEHOLDER {
            self.as_str()
        } else {
            pattern
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn default_is_valid_and_is_the_placeholder() {
        let d = InvitePath::default();
        assert_eq!(d.as_str(), "/invite");
        assert!(d.is_default());
        assert_eq!(InvitePath::parse("/invite").unwrap(), d);
    }

    #[test]
    fn sec_028_invite_path_shapes_are_validated() {
        for ok in [
            "/join-7f3k9q",
            "/abcdef",
            "/A_b-C_d",
            &format!("/{}", "x".repeat(64)),
        ] {
            let p = InvitePath::parse(ok).unwrap();
            assert_eq!(p.as_str(), ok);
            assert!(!p.is_default());
        }
        let cases: &[(&str, InvitePathError)] = &[
            ("", InvitePathError::NoLeadingSlash),
            ("join-7f3k9q", InvitePathError::NoLeadingSlash),
            ("/join/7f3k9q", InvitePathError::NotSingleSegment),
            ("/join-7f3k9q/", InvitePathError::NotSingleSegment),
            ("//join-7f3k9q", InvitePathError::NotSingleSegment),
            ("/../x/abcdef", InvitePathError::NotSingleSegment),
            ("/..abcdef", InvitePathError::Charset),
            ("/abc.def", InvitePathError::Charset),
            ("/abc%2fdef", InvitePathError::Charset),
            ("/abc def", InvitePathError::Charset),
            ("/{name}x", InvitePathError::Charset),
            ("/abcdé1", InvitePathError::Charset),
            ("/join?x=1", InvitePathError::Charset),
            ("/", InvitePathError::Length),
            ("/abcde", InvitePathError::Length),
            (&format!("/{}", "x".repeat(65)), InvitePathError::Length),
        ];
        for (raw, want) in cases {
            let got = InvitePath::parse(raw).unwrap_err();
            assert_eq!(&got, want, "{raw:?}");
            assert_eq!(got.code(), "INVITE_PATH_INVALID");
        }
    }

    #[test]
    fn sec_028_invite_path_cannot_collide_with_any_inventory_route() {
        // Every built-in first segment, as itself, padded to the minimum length, upper-cased, and
        // (when long enough) cut down to a prefix: all refused.
        let mut checked = 0;
        for spec in INVENTORY.iter().filter(|s| !s.is_invite_placeholder()) {
            let seg = first_segment(spec.path);
            if seg.is_empty() {
                continue;
            }
            let mut probes = vec![
                format!("/{seg}"),
                format!("/{seg}-zzzzzz"),
                format!("/{}-zzzzzz", seg.to_ascii_uppercase()),
            ];
            if seg.len() > MIN_INVITE_SEGMENT {
                probes.push(format!("/{}", &seg[..MIN_INVITE_SEGMENT]));
            }
            for p in probes {
                match InvitePath::parse(&p) {
                    Err(InvitePathError::Collides(_)) => checked += 1,
                    // Shorter than the minimum: refused anyway, never mounted.
                    Err(InvitePathError::Length) if seg.len() < MIN_INVITE_SEGMENT => checked += 1,
                    other => panic!("{p} (route {}) was not refused: {other:?}", spec.path),
                }
            }
        }
        assert!(checked > 20, "the inventory walk checked only {checked}");
        // A value that starts with a short built-in segment is caught as well.
        assert_eq!(
            InvitePath::parse("/stats-page"),
            Err(InvitePathError::Collides("/stats"))
        );
        assert_eq!(
            InvitePath::parse("/Healthz1"),
            Err(InvitePathError::Collides("/healthz"))
        );
        // The placeholder itself is not a collision, and lookalikes of other words are fine.
        assert!(InvitePath::parse("/join-now").is_ok());
        assert!(InvitePath::parse("/my-invite").is_ok());
        // Neighbours of the default are refused (review 49 I1); only `/invite` itself passes.
        for raw in [
            "/invite-abc",
            "/Invite",
            "/INVITE",
            "/invites",
            "/inviteXYZ123",
        ] {
            assert_eq!(
                InvitePath::parse(raw),
                Err(InvitePathError::InvitePrefix),
                "{raw}"
            );
        }
        assert!(InvitePath::parse("/invite").is_ok());
    }

    /// Review 49 L2: the installer's generated shape `/join-<12 [a-z0-9]>` must stay valid, so no
    /// built-in route may ever start with `join` (see the reservation note at `INVENTORY`).
    #[test]
    fn sec_028_installer_invite_prefix_is_reserved() {
        let alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..500 {
            let mut s = String::from("/join-");
            for _ in 0..12 {
                seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let i = usize::try_from(seed >> 59).unwrap() % alphabet.len();
                s.push(char::from(alphabet[i]));
            }
            assert!(InvitePath::parse(&s).is_ok(), "{s}");
        }
        for fixed in [
            "/join-000000000000",
            "/join-zzzzzzzzzzzz",
            "/join-a1b2c3d4e5f6",
        ] {
            assert!(InvitePath::parse(fixed).is_ok(), "{fixed}");
        }
        assert!(
            INVENTORY.iter().all(|s| !first_segment(s.path)
                .to_ascii_lowercase()
                .starts_with("join")),
            "a built-in route starting with `join` would break the installer's generated paths"
        );
    }

    #[test]
    fn url_and_resolve() {
        let p = InvitePath::parse("/join-7f3k9q").unwrap();
        assert_eq!(
            p.url(Some("https://nzbd.example")),
            "https://nzbd.example/join-7f3k9q"
        );
        assert_eq!(p.url(None), "/join-7f3k9q");
        assert_eq!(p.resolve("/invite"), "/join-7f3k9q");
        assert_eq!(p.resolve("/login"), "/login");
    }
}
