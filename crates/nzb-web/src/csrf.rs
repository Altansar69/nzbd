//! Request-origin defences (SEC-025): Host allowlist (DNS rebinding), same-origin checks,
//! pre-session login tokens and a bounded, lenient `application/x-www-form-urlencoded` parser.

use std::net::IpAddr;

use axum::http::{HeaderMap, header};

use crate::crypto::{self, ct_eq};

/// Lifetime of the signed pre-session login token.
pub const LOGIN_TOKEN_TTL_SECS: i64 = 600;
const LOGIN_TOKEN_CONTEXT: &str = "nzbd-login-csrf-v1";
/// Longest form field count parsed (anything beyond is ignored).
const MAX_FORM_FIELDS: usize = 32;

/// Splits a `Host`/authority value into a lowercase hostname (no port, no brackets, no trailing
/// dot). `None` for anything that is not a plausible host.
fn hostname(authority: &str) -> Option<String> {
    if authority.is_empty() || authority.len() > 255 {
        return None;
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (h, tail) = rest.split_once(']')?;
        // Anything after the bracket must be `:port` (rejects `[::1]junk`).
        let port = if tail.is_empty() {
            None
        } else {
            Some(tail.strip_prefix(':')?)
        };
        (h, port)
    } else {
        // An unbracketed IPv6 literal is ambiguous with host:port and never valid in `Host`.
        if authority.matches(':').count() > 1 {
            return None;
        }
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    if port.is_some_and(|p| {
        p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.parse::<u16>().is_err()
    }) {
        return None;
    }
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    if host.parse::<IpAddr>().is_ok() {
        return Some(host);
    }
    host.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        .then_some(host)
}

/// Host-header allowlist (DNS rebinding defence, review L4).
///
/// Allowed: `localhost`, any IP literal (a rebinding page is always reached by a *name*, so an
/// IP-literal Host proves the browser was pointed at the address directly), and the configured
/// names. The port is ignored.
#[must_use]
pub fn host_allowed(host_header: Option<&str>, allowed: &[String]) -> bool {
    let Some(host) = host_header.and_then(hostname) else {
        return false;
    };
    host == "localhost"
        || host.parse::<IpAddr>().is_ok()
        || allowed.iter().any(|a| a.eq_ignore_ascii_case(&host))
}

/// True when `value` is a syntactically valid hostname for `server.allowed_hosts`.
#[must_use]
pub fn valid_allowed_host(value: &str) -> bool {
    !value.contains(':')
        && value == value.to_ascii_lowercase()
        && hostname(value).is_some_and(|h| h == value)
}

/// `(is_https, host[:port])` of an absolute `http(s)` URL; `None` for other schemes or userinfo
/// tricks.
fn authority_of(url: &str) -> Option<(bool, &str)> {
    let (https, rest) = match url.strip_prefix("https://") {
        Some(r) => (true, r),
        None => (false, url.strip_prefix("http://")?),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..end)?;
    (!authority.is_empty() && !authority.contains(['@', ' ', '\\'])).then_some((https, authority))
}

/// Same-origin check for state-changing requests: `Sec-Fetch-Site` (when sent) must be
/// `same-origin`/`none`, and `Origin` (or, failing that, `Referer`) must name the request's own
/// `Host`. A request carrying neither (or `Origin: null`) is accepted only with
/// `Sec-Fetch-Site: same-origin`; see the comment in the body.
///
/// `require_https` (set whenever cookies are `Secure`, i.e. not the D16 opt-out) additionally
/// demands an `https` Origin/Referer unless the Host is `localhost` or an IP literal, where
/// browsers treat plain HTTP as a secure context. This stops an `http://` page on the same
/// name from posting to the TLS site.
#[must_use]
pub fn same_origin(headers: &HeaderMap, require_https: bool) -> bool {
    if let Some(v) = headers.get("sec-fetch-site") {
        match v.to_str() {
            Ok("same-origin" | "none") => {}
            _ => return false,
        }
    }
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let origin = headers.get(header::ORIGIN).map(|o| o.to_str().ok());
    let referer = headers.get(header::REFERER).and_then(|v| v.to_str().ok());
    let claimed = match origin {
        Some(o) => o,
        None => referer,
    };
    let Some((https, authority)) = claimed.and_then(authority_of) else {
        // `Referrer-Policy: no-referrer` (SEC-021) makes browsers serialize the Origin of
        // same-origin POSTs as the literal `null` (and send no Referer). The only proof left
        // is `Sec-Fetch-Site: same-origin`, a forbidden header pages cannot forge. Accept
        // exactly that; a `null` Origin without it (cross-site, sandboxed, old browsers) fails.
        let null_origin = origin == Some(Some("null")) || (origin.is_none() && referer.is_none());
        return null_origin
            && headers
                .get("sec-fetch-site")
                .is_some_and(|v| v.as_bytes() == b"same-origin");
    };
    if !authority.eq_ignore_ascii_case(host) {
        return false;
    }
    if require_https && !https {
        let local = hostname(host).is_some_and(|h| h == "localhost" || h.parse::<IpAddr>().is_ok());
        return local;
    }
    true
}

/// A login-form token that passed its MAC check: the token id and expiry that the single-use
/// set keys on.
#[derive(Debug, PartialEq, Eq)]
pub struct LoginTokenId {
    id: String,
    exp: i64,
}

/// Hex of the SHA-256 of the cookie nonce: what the token MAC covers, so the HMAC input never
/// contains the cookie value itself.
fn nonce_binding(cookie_nonce: &str) -> String {
    crypto::hex(&crypto::sha256(cookie_nonce.as_bytes()))
}

/// Fresh random cookie nonce (128 bits, hex) for the `__Host-` login cookie.
///
/// # Errors
/// Fails only if the OS random source is unavailable.
pub fn new_login_nonce() -> Result<String, crypto::RandomError> {
    Ok(crypto::hex(&crypto::random_bytes::<16>()?))
}

/// True for a well-formed cookie nonce (32 lowercase hex characters).
#[must_use]
pub fn valid_login_nonce(nonce: &str) -> bool {
    nonce.len() == 32
        && nonce
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Signed token embedded in the login form (10 minutes): `exp.id.hmac`. The MAC covers the hash
/// of the `HttpOnly` cookie nonce the form was issued with, so the token only works together with
/// that cookie; [`SingleUseSet`] makes it work once.
///
/// # Errors
/// Fails only if the OS random source is unavailable.
pub fn issue_login_token(
    key: &[u8; 32],
    now: i64,
    cookie_nonce: &str,
) -> Result<String, crypto::RandomError> {
    let exp = now.saturating_add(LOGIN_TOKEN_TTL_SECS);
    let id = crypto::hex(&crypto::random_bytes::<16>()?);
    let msg = format!(
        "{LOGIN_TOKEN_CONTEXT}|{exp}|{id}|{}",
        nonce_binding(cookie_nonce)
    );
    let tag = crypto::hmac_sha256(key, msg.as_bytes()).unwrap_or([0; 32]);
    Ok(format!("{exp}.{id}.{}", crypto::hex(&tag)))
}

/// Verifies a token from [`issue_login_token`] against the presented cookie nonce: valid MAC,
/// not expired, not from the far future. The caller must still consume the returned id in a
/// [`SingleUseSet`].
#[must_use]
pub fn verify_login_token(
    key: &[u8; 32],
    now: i64,
    cookie_nonce: &str,
    token: &str,
) -> Option<LoginTokenId> {
    if !valid_login_nonce(cookie_nonce) {
        return None;
    }
    let mut parts = token.split('.');
    let (Some(exp), Some(id), Some(tag), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let exp_n = exp.parse::<i64>().ok()?;
    if exp_n < now || exp_n > now.saturating_add(LOGIN_TOKEN_TTL_SECS) {
        return None;
    }
    let tag = crypto::unhex(tag)?;
    let msg = format!(
        "{LOGIN_TOKEN_CONTEXT}|{exp_n}|{id}|{}",
        nonce_binding(cookie_nonce)
    );
    crypto::hmac_sha256_verify(key, msg.as_bytes(), &tag).then(|| LoginTokenId {
        id: id.to_owned(),
        exp: exp_n,
    })
}

/// Capacity of the login-token single-use set. Entries live at most [`LOGIN_TOKEN_TTL_SECS`] and
/// `POST /login` is limited to 10/min/IP, so filling it takes a large botnet; when it is full
/// every login attempt is refused (fail closed) until entries expire.
pub const LOGIN_TOKEN_SET_CAP: usize = 4096;

/// Bounded in-memory set of consumed token ids with expiry (no migration needed: a restart
/// forgets it, which re-opens replay only for tokens issued before the restart, and those
/// are bound to a per-process MAC key that the restart also replaces, so they fail verification).
#[derive(Debug)]
pub struct SingleUseSet {
    cap: usize,
    used: std::sync::Mutex<std::collections::HashMap<String, i64>>,
}

impl SingleUseSet {
    /// Empty set holding at most `cap` live entries.
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            used: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Marks the token consumed. `true` exactly once per id; `false` for a replay, when the set
    /// is full of live entries, or if the lock is poisoned (fail closed).
    pub fn consume(&self, token: &LoginTokenId, now: i64) -> bool {
        let Ok(mut used) = self.used.lock() else {
            return false;
        };
        if used.contains_key(&token.id) {
            return false;
        }
        if used.len() >= self.cap {
            used.retain(|_, exp| *exp >= now);
            if used.len() >= self.cap {
                return false;
            }
        }
        used.insert(token.id.clone(), token.exp);
        true
    }

    /// Number of entries currently held (test/observability hook).
    #[must_use]
    pub fn len(&self) -> usize {
        self.used.lock().map_or(0, |u| u.len())
    }

    /// True when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Constant-time comparison of a presented CSRF token with the session's token.
#[must_use]
pub fn token_matches(expected: &str, presented: &str) -> bool {
    ct_eq(expected.as_bytes(), presented.as_bytes())
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        match c {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                let hi = b.get(i + 1).and_then(|h| char::from(*h).to_digit(16));
                let lo = b.get(i + 2).and_then(|h| char::from(*h).to_digit(16));
                if let (Some(hi), Some(lo)) = (hi, lo)
                    && let Ok(v) = u8::try_from(hi * 16 + lo)
                {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(c);
                    i += 1;
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parses `application/x-www-form-urlencoded` leniently (never fails; invalid escapes stay
/// literal, invalid UTF-8 is replaced). The caller bounds `body` (64 KiB request ceiling); at
/// most 32 fields are kept. Callers must apply their own per-field length rules.
#[must_use]
pub fn parse_form(body: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(body)
        .split('&')
        .filter(|p| !p.is_empty())
        .take(MAX_FORM_FIELDS)
        .map(decode_pair)
        .collect()
}

/// Like [`parse_form`] with a caller-chosen field cap that **refuses** (`None`) instead of
/// silently dropping fields: a bulk form must never lose part of its selection (T119).
#[must_use]
pub fn parse_form_strict(body: &[u8], max_fields: usize) -> Option<Vec<(String, String)>> {
    let text = String::from_utf8_lossy(body);
    let mut pairs = text.split('&').filter(|p| !p.is_empty());
    let out: Vec<_> = pairs.by_ref().take(max_fields).map(decode_pair).collect();
    pairs.next().is_none().then_some(out)
}

fn decode_pair(pair: &str) -> (String, String) {
    let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
    (pct_decode(k), pct_decode(v))
}

/// True when none of `names` occurs more than once in `form`. Single-value fields of the bulk and
/// delete forms are refused when repeated instead of being judged first-wins (T119 review I1).
#[must_use]
pub fn singletons_ok(form: &[(String, String)], names: &[&str]) -> bool {
    names
        .iter()
        .all(|n| form.iter().filter(|(k, _)| k == n).nth(1).is_none())
}

/// Every value of `name` in a parsed form, in order.
pub fn form_all<'a>(form: &'a [(String, String)], name: &'a str) -> impl Iterator<Item = &'a str> {
    form.iter()
        .filter(move |(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// First value of `name` in a parsed form.
#[must_use]
pub fn form_get<'a>(form: &'a [(String, String)], name: &str) -> Option<&'a str> {
    form.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use axum::http::HeaderValue;

    use super::*;

    fn hm(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn sec_025_host_allowlist() {
        let allowed = vec!["nzbd.lan".to_owned()];
        for ok in [
            "localhost",
            "LOCALHOST:8080",
            "127.0.0.1:8080",
            "[::1]:8080",
            "192.168.1.5",
            "nzbd.lan",
            "NZBD.LAN:443",
            "nzbd.lan.",
        ] {
            assert!(host_allowed(Some(ok), &allowed), "{ok}");
        }
        for bad in [
            "evil.example",
            "nzbd.lan.evil.example",
            "evilnzbd.lan",
            "nzbd.lan:abc",
            "nzbd.lan:",
            "",
            "nzbd.lan@evil",
            "nzbd lan",
            "[::1",
        ] {
            assert!(!host_allowed(Some(bad), &allowed), "{bad}");
        }
        assert!(!host_allowed(None, &allowed));
    }

    #[test]
    fn sec_025_same_origin_rules() {
        let ok = |p: &[(&'static str, &str)]| same_origin(&hm(p), false);
        let host = ("host", "nzbd.lan:8443");
        assert!(ok(&[host, ("origin", "https://nzbd.lan:8443")]));
        assert!(ok(&[host, ("origin", "https://NZBD.lan:8443")]));
        assert!(ok(&[
            host,
            ("referer", "https://nzbd.lan:8443/account?x=1"),
        ]));
        assert!(ok(&[
            host,
            ("origin", "https://nzbd.lan:8443"),
            ("sec-fetch-site", "same-origin"),
        ]));
        // Foreign, null, missing, userinfo tricks, wrong port, foreign fetch site.
        assert!(!ok(&[host, ("origin", "https://evil.example")]));
        assert!(!ok(&[host, ("origin", "null")]));
        assert!(!ok(&[host]));
        // Browser shape under no-referrer: null Origin proven by Sec-Fetch-Site only.
        let sfs = |v| ok(&[host, ("origin", "null"), ("sec-fetch-site", v)]);
        assert!(sfs("same-origin"));
        for bad in ["cross-site", "same-site", "none", ""] {
            assert!(!sfs(bad), "{bad}");
        }
        assert!(ok(&[host, ("sec-fetch-site", "same-origin")]));
        assert!(!ok(&[host, ("sec-fetch-site", "none")]));
        assert!(!ok(&[
            host,
            ("origin", "https://evil.example"),
            ("sec-fetch-site", "same-origin"),
        ]));
        // A garbage Origin is not "null".
        assert!(!ok(&[
            host,
            ("origin", "nul"),
            ("sec-fetch-site", "same-origin")
        ]));
        assert!(!ok(&[
            host,
            ("origin", "https://nzbd.lan:8443@evil.example")
        ]));
        assert!(!ok(&[host, ("origin", "https://nzbd.lan")]));
        assert!(!ok(&[host, ("origin", "ftp://nzbd.lan:8443")]));
        assert!(!ok(&[
            host,
            ("origin", "https://nzbd.lan:8443"),
            ("sec-fetch-site", "cross-site"),
        ]));
        assert!(!ok(&[
            host,
            ("origin", "https://nzbd.lan:8443"),
            ("sec-fetch-site", "same-site"),
        ]));
        // Origin wins over a matching Referer.
        assert!(!ok(&[
            host,
            ("origin", "https://evil.example"),
            ("referer", "https://nzbd.lan:8443/"),
        ]));
    }

    #[test]
    fn sec_025_same_origin_compares_scheme_when_https_required() {
        let ok = |p: &[(&'static str, &str)]| same_origin(&hm(p), true);
        let host = ("host", "nzbd.lan");
        assert!(ok(&[host, ("origin", "https://nzbd.lan")]));
        assert!(!ok(&[host, ("origin", "http://nzbd.lan")]));
        assert!(!ok(&[host, ("referer", "http://nzbd.lan/x")]));
        // Loopback and IP literals are secure contexts over plain HTTP.
        assert!(ok(&[
            ("host", "localhost:8080"),
            ("origin", "http://localhost:8080")
        ]));
        assert!(ok(&[
            ("host", "127.0.0.1:8080"),
            ("origin", "http://127.0.0.1:8080")
        ]));
        // The D16 opt-out does not compare schemes.
        assert!(same_origin(
            &hm(&[host, ("origin", "http://nzbd.lan")]),
            false
        ));
    }

    #[test]
    fn sec_025_hostname_rejects_malformed_authorities() {
        for bad in [
            "[::1]junk",
            "[::1]:99999",
            "nzbd.lan:65536",
            "::1",
            "[::1]:",
            "a:b:c",
        ] {
            assert!(hostname(bad).is_none(), "{bad}");
        }
        assert_eq!(hostname("[::1]:8080").as_deref(), Some("::1"));
        assert_eq!(hostname("[::1]").as_deref(), Some("::1"));
        assert_eq!(hostname("nzbd.lan:65535").as_deref(), Some("nzbd.lan"));
    }

    const N1: &str = "00112233445566778899aabbccddeeff";
    const N2: &str = "ffeeddccbbaa99887766554433221100";

    #[test]
    fn sec_025_login_token_signed_and_expiring() {
        let key = [7_u8; 32];
        let t = issue_login_token(&key, 1000, N1).unwrap();
        assert!(verify_login_token(&key, 1000, N1, &t).is_some());
        assert!(verify_login_token(&key, 1600, N1, &t).is_some());
        assert!(verify_login_token(&key, 1601, N1, &t).is_none(), "expired");
        assert!(
            verify_login_token(&[8_u8; 32], 1000, N1, &t).is_none(),
            "other key"
        );
        assert!(verify_login_token(&key, 1000, N1, "").is_none());
        assert!(verify_login_token(&key, 1000, N1, "1.2.3.4").is_none());
        // Tampered expiry (extend lifetime) must fail the MAC.
        let mut parts = t.split('.');
        let (_, id, tag) = (parts.next(), parts.next().unwrap(), parts.next().unwrap());
        assert!(verify_login_token(&key, 1000, N1, &format!("1500.{id}.{tag}")).is_none());
        // Far-future expiry is refused even with a valid-looking shape.
        assert!(verify_login_token(&key, 0, N1, &t).is_none());
    }

    #[test]
    fn sec_025_login_token_is_bound_to_the_cookie_nonce() {
        let key = [7_u8; 32];
        let t = issue_login_token(&key, 1000, N1).unwrap();
        assert!(verify_login_token(&key, 1000, N1, &t).is_some());
        // Another client's cookie, a malformed cookie and no cookie all fail.
        assert!(verify_login_token(&key, 1000, N2, &t).is_none());
        assert!(verify_login_token(&key, 1000, "", &t).is_none());
        assert!(verify_login_token(&key, 1000, "not-hex", &t).is_none());
        assert!(valid_login_nonce(&new_login_nonce().unwrap()));
        assert!(!valid_login_nonce(&N1.to_uppercase()));
    }

    #[test]
    fn sec_025_login_token_single_use_and_bounded() {
        let key = [7_u8; 32];
        let set = SingleUseSet::new(3);
        let mint = |now: i64| {
            let t = issue_login_token(&key, now, N1).unwrap();
            verify_login_token(&key, now, N1, &t).unwrap()
        };
        let a = mint(1000);
        assert!(set.consume(&a, 1000));
        assert!(!set.consume(&a, 1000), "replay");
        assert!(set.consume(&mint(1000), 1000));
        assert!(set.consume(&mint(1000), 1000));
        assert_eq!(set.len(), 3);
        // Full of live entries: fail closed.
        assert!(!set.consume(&mint(1000), 1000));
        assert!(!set.consume(&a, 1000));
        // Once they expired the table frees up again; the old id is forgotten but its token is
        // expired too, so it cannot be replayed through verification.
        assert!(set.consume(&mint(1700), 1700));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn form_parser_is_lenient_and_bounded() {
        let f = parse_form(b"a=1&b=%41%zz+x&=&c&d=%E9");
        assert_eq!(form_get(&f, "a"), Some("1"));
        assert_eq!(form_get(&f, "b"), Some("A%zz x"));
        assert_eq!(form_get(&f, "c"), Some(""));
        assert_eq!(form_get(&f, "d"), Some("\u{fffd}"));
        assert_eq!(form_get(&f, "missing"), None);
        let many = "k=v&".repeat(1000);
        assert_eq!(parse_form(many.as_bytes()).len(), MAX_FORM_FIELDS);
    }

    #[test]
    fn strict_form_parser_refuses_instead_of_truncating() {
        let f = parse_form_strict(b"id=1&id=2&x=%41&&id=3", 4).unwrap();
        assert_eq!(form_all(&f, "id").collect::<Vec<_>>(), vec!["1", "2", "3"]);
        assert_eq!(form_get(&f, "x"), Some("A"));
        assert!(parse_form_strict(b"id=1&id=2&id=3", 2).is_none());
        let g = parse_form_strict(b"id=1&id=2&action=a&code=1", 8).unwrap();
        assert!(singletons_ok(&g, &["action", "code", "sha"]));
        let d = parse_form_strict(b"action=a&code=1&action=b", 8).unwrap();
        assert!(!singletons_ok(&d, &["action", "code"]));
        assert!(singletons_ok(&d, &["code"]));
        assert_eq!(parse_form_strict(b"", 2), Some(Vec::new()));
    }

    #[test]
    fn allowed_host_config_validation() {
        assert!(valid_allowed_host("nzbd.lan"));
        assert!(!valid_allowed_host("NZBD.lan"));
        assert!(!valid_allowed_host("nzbd.lan:8080"));
        assert!(!valid_allowed_host("*.lan"));
        assert!(!valid_allowed_host(""));
    }
}
