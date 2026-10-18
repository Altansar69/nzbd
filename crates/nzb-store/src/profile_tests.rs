//! Pure validators of the registration profile (T109, D32): self-chosen display names and emails, including hostile
//! input (Unicode look-alikes, controls, IDN, overlong, header injection).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use crate::{
    RegistrationProfile, display_name_is_valid, display_name_skeleton, normalize_email,
    self_display_name_is_valid,
};

#[test]
fn sec_085_self_display_name_charset_and_length() {
    for ok in [
        "abc",
        "Bob",
        "bob_42",
        "a-b",
        "___",
        "---",
        "UPPER-lower_09",
        "user",
        "users-1",
        "acct",
        "x".repeat(32).as_str(),
    ] {
        assert!(self_display_name_is_valid(ok), "{ok:?}");
    }
    let long = "x".repeat(33);
    for bad in [
        "",
        "a",
        "ab",
        long.as_str(),
        "has space",
        " abc",
        "abc ",
        "dot.ted",
        "a@b",
        "tab\tbed",
        "new\nline",
        "crlf\r\nX-Header: 1",
        "nul\0byte",
        "semi;colon",
        "<script>",
        "a/b",
        "a\\b",
        "quote'",
        "%41%42",
        // Unicode look-alikes and invisible characters.
        "аdmin",        // Cyrillic a
        "bob\u{200b}",  // zero-width space
        "bob\u{2010}x", // Unicode hyphen
        "ｂｏｂ",       // fullwidth
        "bób",
        "bob\u{301}",  // combining accent
        "\u{202e}bob", // RTL override
        "bob\u{ff3f}", // fullwidth low line
    ] {
        assert!(!self_display_name_is_valid(bad), "{bad:?}");
    }
    // 32 multi-byte characters are far more than 32 bytes and refused anyway (charset).
    assert!(!self_display_name_is_valid(&"é".repeat(16)));
}

#[test]
fn sec_085_self_display_name_refuses_reserved_forms_as_shape() {
    for bad in [
        "user-1",
        "USER-7",
        "User-0042",
        "user-1a",
        "acct-3",
        "ACCT-3-1",
        "acct-12x",
        "system",
        "SYSTEM",
        "cli",
        "Api",
        "anonymous",
        // `SECURITY_REVIEW` 26 L1: look-alikes of the handle forms (key: lower-case, `-`/`_` dropped; a handle prefix
        // then a digit, or a rest made only of digits and o/i/l) ...
        "user_1",
        "user1",
        "User-l",
        "user-O7",
        "user-io",
        "usr-1",
        "Usr_l0",
        "acct_3",
        "acct-ol",
        "user__1",
        "_user-1",
        // ... and of the release page's system labels and privileged words.
        "Watch-folder",
        "watch_folder",
        "WatchFolder",
        "Deleted_account",
        "Before_accounts",
        "operator",
        "admin",
        "Ad-min",
        "Administrator",
        "root",
        "nzbd",
        "Sys_tem",
        "anony-mous",
        "c-l-i",
        "a_p_i",
    ] {
        assert!(!self_display_name_is_valid(bad), "{bad:?}");
    }
    // A handle prefix followed by an ordinary word is not a handle look-alike (handles are `<prefix>-<digits>`), and
    // names merely containing a reserved word stay allowed.
    for ok in [
        "user-x",
        "acct-x1",
        "users-1",
        "my-user-1",
        "xuser-1",
        "userland",
        "username",
        "user_name",
        "usr-bin",
        "accts",
        "acctg-team",
        "user",
        "Alice",
        "Oliver",
        "admins-team",
        "rooted",
        "nzbd-fan",
        "my-watch-folder",
    ] {
        assert!(self_display_name_is_valid(ok), "{ok:?}");
    }
}

#[test]
fn sec_085_display_name_skeleton_folds_ascii_confusables() {
    for (a, b) in [
        ("Alice", "AIice"),
        ("alice", "a1ice"),
        ("bob_smith", "bob-smith"),
        ("JoO", "Jo0"),
        ("mike", "rnike"),
        ("wave", "vvave"),
        ("Bill", "BiII"),
    ] {
        assert_eq!(
            display_name_skeleton(a),
            display_name_skeleton(b),
            "{a} {b}"
        );
    }
    for (a, b) in [
        ("alice", "alicia"),
        ("bob", "rob"),
        ("bobsmith", "bob-smith"),
    ] {
        assert_ne!(
            display_name_skeleton(a),
            display_name_skeleton(b),
            "{a} {b}"
        );
    }
}

#[test]
fn sec_085_self_rule_is_stricter_than_the_admin_rule() {
    // Everything the invitee may pick, the admin rule also accepts (the column CHECK and the admin path agree).
    for n in ["abc", "a-b_c", "x".repeat(32).as_str(), "Name-01"] {
        assert!(
            self_display_name_is_valid(n) && display_name_is_valid(n),
            "{n}"
        );
    }
    // The admin rule keeps its wider shape (spaces, dots, 1-2 chars); unchanged by D32.
    for n in ["a", "ab", "First Last", "j.doe"] {
        assert!(
            display_name_is_valid(n) && !self_display_name_is_valid(n),
            "{n}"
        );
    }
}

#[test]
fn sec_085_email_accepts_and_normalises() {
    for (raw, want) in [
        ("a@b.cd", "a@b.cd"),
        ("Alice@Example.COM", "alice@example.com"),
        ("  bob@example.org\t", "bob@example.org"),
        ("\r\nbob@example.org\r\n", "bob@example.org"),
        (
            "first.last+tag@sub.example.co.uk",
            "first.last+tag@sub.example.co.uk",
        ),
        ("x_y%z-w@a-b.example", "x_y%z-w@a-b.example"),
        ("1@2.example", "1@2.example"),
    ] {
        assert_eq!(normalize_email(raw).as_deref(), Some(want), "{raw:?}");
    }
    // Limits: local part 64, label 63, total 254.
    let local64 = format!("{}@example.com", "a".repeat(64));
    assert!(normalize_email(&local64).is_some());
    let label63 = format!("a@{}.com", "b".repeat(63));
    assert!(normalize_email(&label63).is_some());
    let total254 = format!(
        "{}@{}.{}.{}.{}.com",
        "a".repeat(64),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(55),
        "e"
    );
    assert_eq!(total254.len(), 254);
    assert!(normalize_email(&total254).is_some());
    let total255 = format!("a{total254}");
    assert!(normalize_email(&total255).is_none());
}

#[test]
fn sec_085_email_refuses_hostile_input() {
    let local65 = format!("{}@example.com", "a".repeat(65));
    let label64 = format!("a@{}.com", "b".repeat(64));
    let huge = format!("{}@example.com", "a".repeat(5000));
    let padded = format!("{}a@b.cd", " ".repeat(2000));
    for bad in [
        "",
        " ",
        "@",
        "a@",
        "@b.cd",
        "a@@b.cd",
        "a@b@c.de",
        "ab.cd",
        "a@b",
        "a@b.c",
        "a@b.c1",
        "a@b.12",
        "a@1.2.3.4",
        "a@[192.0.2.1]",
        "a@-b.cd",
        "a@b-.cd",
        "a@b..cd",
        "a@.b.cd",
        "a@b.cd.",
        "a@b_c.de",
        ".a@b.cd",
        "a.@b.cd",
        "a..b@c.de",
        "\"a b\"@c.de",
        "a b@c.de",
        "a(comment)@c.de",
        "<a@b.cd>",
        "a@b.cd>",
        "a,b@c.de",
        "a;b@c.de",
        "a@b.cd\r\nBcc: x@y.zz",
        "a@b.cd\nx",
        "a\r@b.cd",
        "a@b.cd\0",
        "\0a@b.cd",
        "a\u{0}b@c.de",
        "a\u{b}@b.cd",
        "a@b.cd\u{b}",
        // IDN and Unicode look-alikes.
        "a@bücher.de",
        "a@xn--bcher-kva.de\u{200b}",
        "ä@b.cd",
        "a@b.сom", // Cyrillic s/o
        "a\u{ff20}b.cd",
        "a@b\u{3002}cd", // ideographic full stop
        "a@b\u{ff0e}cd", // fullwidth full stop
        "a@b.cd\u{a0}",
        local65.as_str(),
        label64.as_str(),
        huge.as_str(),
        padded.as_str(),
    ] {
        assert!(normalize_email(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn sec_085_profile_debug_redacts_the_email() {
    let p = RegistrationProfile {
        email: "secret.person@example.com",
        display_name: "shown",
    };
    let d = format!("{p:?}");
    assert!(
        !d.contains("secret.person") && !d.contains("example.com"),
        "{d}"
    );
    assert!(d.contains("[REDACTED]") && d.contains("shown"), "{d}");
}
