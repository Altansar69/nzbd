//! Strict validator for the one DOCTYPE form NZB files in the wild carry (SEC-001).
//!
//! Accepted grammar over the *raw* bytes of the declaration, `<!DOCTYPE` through `>`:
//!
//! ```text
//! decl   = "<!DOCTYPE" S "nzb" ( S? ">"
//!                              | S "SYSTEM" S sys S? ">"
//!                              | S "PUBLIC" S pub S sys S? ">" )
//! S      = one or more of space, TAB, CR, LF
//! pub    = '"' PubChar* '"' | "'" PubChar* "'"
//! sys    = '"' SysChar* '"' | "'" SysChar* "'"
//! PubChar = A-Z a-z 0-9 space - ( ) + , . / : = ? ; ! * # @ $ _
//! SysChar = A-Z a-z 0-9 - . _ ~ : / ? # @ ! $ ( ) * + , ; =
//! ```
//!
//! Each literal is at most [`MAX_LITERAL_BYTES`] and the whole declaration at most
//! [`MAX_DECL_BYTES`]. There is no internal subset, no markup declaration, no parameter-entity
//! reference. The identifiers are never read by anything: there is no resolver, no fetch and no
//! storage, so the declaration is an inert header. Linear time, no allocation, no backtracking.

/// Longest accepted public or system literal (without quotes).
pub(super) const MAX_LITERAL_BYTES: usize = 256;
/// Longest accepted declaration, `<!DOCTYPE` through `>` inclusive.
pub(super) const MAX_DECL_BYTES: usize = 600;

const KEYWORD: &[u8] = b"<!DOCTYPE";

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn bump(&mut self) {
        self.i = self.i.saturating_add(1);
    }

    /// Consumes `kw` exactly (case-sensitive).
    fn keyword(&mut self, kw: &[u8]) -> bool {
        let end = self.i.saturating_add(kw.len());
        if self.b.get(self.i..end) == Some(kw) {
            self.i = end;
            true
        } else {
            false
        }
    }

    /// Consumes one or more whitespace bytes; `false` if there was none.
    fn space(&mut self) -> bool {
        let start = self.i;
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.bump();
        }
        self.i > start
    }

    /// Consumes a quoted literal whose bytes all satisfy `ok`.
    fn literal(&mut self, ok: fn(u8) -> bool) -> bool {
        let Some(q @ (b'"' | b'\'')) = self.peek() else {
            return false;
        };
        self.bump();
        let mut n: usize = 0;
        loop {
            match self.peek() {
                Some(c) if c == q => {
                    self.bump();
                    return true;
                }
                Some(c) if ok(c) && n < MAX_LITERAL_BYTES => {
                    n = n.saturating_add(1);
                    self.bump();
                }
                // Unterminated, forbidden byte (including `[`, `<`, `>`, `%`, `&`, NUL, newline)
                // or oversized: reject.
                _ => return false,
            }
        }
    }
}

fn pubid_char(c: u8) -> bool {
    // XML PubidChar minus CR/LF, `'` and `%`.
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b' ' | b'-'
                | b'('
                | b')'
                | b'+'
                | b','
                | b'.'
                | b'/'
                | b':'
                | b'='
                | b'?'
                | b';'
                | b'!'
                | b'*'
                | b'#'
                | b'@'
                | b'$'
                | b'_'
        )
}

fn system_char(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b':'
                | b'/'
                | b'?'
                | b'#'
                | b'@'
                | b'!'
                | b'$'
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
        )
}

/// `true` iff `raw` (the exact bytes of one declaration, `<!DOCTYPE` .. `>`) is in the accepted
/// grammar and nothing follows the closing `>`.
pub(super) fn is_plain_nzb_doctype(raw: &[u8]) -> bool {
    if raw.len() > MAX_DECL_BYTES {
        return false;
    }
    let mut c = Cursor { b: raw, i: 0 };
    if !(c.keyword(KEYWORD) && c.space() && c.keyword(b"nzb")) {
        return false;
    }
    // `nzbx` or `nzb[`: the name must end at whitespace or `>`.
    let had_space = c.space();
    let ok = match c.peek() {
        Some(b'>') => true,
        _ if !had_space => false,
        _ => {
            if c.keyword(b"SYSTEM") {
                c.space() && c.literal(system_char) && {
                    c.space();
                    true
                }
            } else if c.keyword(b"PUBLIC") {
                c.space() && c.literal(pubid_char) && c.space() && c.literal(system_char) && {
                    c.space();
                    true
                }
            } else {
                false
            }
        }
    };
    if !ok || c.peek() != Some(b'>') {
        return false;
    }
    c.bump();
    c.i == raw.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> bool {
        is_plain_nzb_doctype(s.as_bytes())
    }

    #[test]
    fn accepts_the_three_forms() {
        assert!(ok("<!DOCTYPE nzb>"));
        assert!(ok("<!DOCTYPE  nzb \n>"));
        assert!(ok("<!DOCTYPE nzb SYSTEM \"http://example.invalid/x.dtd\">"));
        assert!(ok("<!DOCTYPE nzb SYSTEM 'x.dtd' >"));
        assert!(ok(
            "<!DOCTYPE nzb PUBLIC \"-//newzBin//DTD NZB 1.1//EN\" \"http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd\">"
        ));
        assert!(ok("<!DOCTYPE nzb PUBLIC \"\" \"\">"));
    }

    #[test]
    fn rejects_everything_else() {
        for s in [
            "<!doctype nzb>",
            "<!DOCTYPE>",
            "<!DOCTYPE html>",
            "<!DOCTYPE nzbx>",
            "<!DOCTYPE NZB>",
            "<!DOCTYPE nzb [] >",
            "<!DOCTYPE nzb[]>",
            "<!DOCTYPE nzb [<!ENTITY a \"b\">]>",
            "<!DOCTYPE nzb SYSTEM>",
            "<!DOCTYPE nzb SYSTEM \"a\" \"b\">",
            "<!DOCTYPE nzb PUBLIC \"a\">",
            "<!DOCTYPE nzb PUBLIC \"a\"\"b\">",
            "<!DOCTYPE nzb system \"a\">",
            "<!DOCTYPE nzb SYSTEM \"a>",
            "<!DOCTYPE nzb SYSTEM \"a\"",
            "<!DOCTYPE nzb SYSTEM \"a>b\">",
            "<!DOCTYPE nzb SYSTEM \"a\nb\">",
            "<!DOCTYPE nzb SYSTEM \"a[b\">",
            "<!DOCTYPE nzb SYSTEM \"a<b\">",
            "<!DOCTYPE nzb SYSTEM \"a%b;\">",
            "<!DOCTYPE nzb SYSTEM \"a\0b\">",
            "<!DOCTYPE nzb SYSTEM \"a\" extra>",
            "<!DOCTYPE nzb>x",
            "<!DOCTYPE nzb>>",
            "<!DOCTYPE nzb PUBLIC \"a%b;\" \"c\">",
            "<!DOCTYPE nzb PUBLIC \"a\" \"c\"><!-- -->",
        ] {
            assert!(!ok(s), "{s:?}");
        }
        let long = "a".repeat(MAX_LITERAL_BYTES + 1);
        assert!(!ok(&format!("<!DOCTYPE nzb SYSTEM \"{long}\">")));
        let edge = "a".repeat(MAX_LITERAL_BYTES);
        assert!(ok(&format!("<!DOCTYPE nzb SYSTEM \"{edge}\">")));
        assert!(!ok(&format!(
            "<!DOCTYPE nzb PUBLIC \"{edge}\" \"{edge}\"{}>",
            " ".repeat(200)
        )));
    }
}
