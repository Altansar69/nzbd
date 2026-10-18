//! Reading a 2.x [`PageCursor`] (sort key + id) without changing `nzb-store`.
//!
//! `PageCursor` keeps its fields private; its wire format is documented and stable ("unchanged format",
//! `SECURITY_DELTA` 2.3): lowercase hex of `version(1) sort(1) id(i64 BE) key`, where the key is
//! `0` (undated) or `1 + posted(i64 BE)` for date sorts, `size(i64 BE)` for size sorts and the title
//! bytes for title sorts. We decode exactly that, strictly, from [`PageCursor::encode`]. When T112
//! gives `PageCursor` public accessors, this module shrinks to a call of them.

use nzb_store::{PageCursor, SortKey};

use crate::error::SearchError;

/// The parts of a cursor that position a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CursorParts {
    pub id: i64,
    pub key: CursorValue,
}

/// The sort key carried by a cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CursorValue {
    Date(Option<i64>),
    Size(i64),
    Title(String),
}

const VERSION: u8 = 1;
const BAD: SearchError = SearchError::OutOfRange("cursor");

fn sort_tag(s: SortKey) -> u8 {
    match s {
        SortKey::DateDesc => 0,
        SortKey::DateAsc => 1,
        SortKey::SizeDesc => 2,
        SortKey::SizeAsc => 3,
        SortKey::TitleAsc => 4,
        SortKey::TitleDesc => 5,
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

fn i64_at(b: &[u8], at: usize) -> Option<i64> {
    let s = b.get(at..at.checked_add(8)?)?;
    Some(i64::from_be_bytes(s.try_into().ok()?))
}

/// The parts of `at`, which must belong to `sort`.
///
/// # Errors
/// [`SearchError::OutOfRange`] for a cursor of another sort order (the conformance contract) or one
/// that cannot be encoded (a title the sanitizer never stores).
pub(crate) fn parts(at: &PageCursor, sort: SortKey) -> Result<CursorParts, SearchError> {
    if at.sort() != sort {
        return Err(SearchError::OutOfRange("cursor sort order"));
    }
    let hex = at.encode().ok_or(BAD)?;
    let digits = hex
        .bytes()
        .map(hex_val)
        .collect::<Option<Vec<u8>>>()
        .ok_or(BAD)?;
    let bytes: Vec<u8> = digits
        .chunks(2)
        .map(|p| match p {
            [hi, lo] => Some((hi << 4) | lo),
            _ => None,
        })
        .collect::<Option<Vec<u8>>>()
        .ok_or(BAD)?;
    if bytes.first() != Some(&VERSION) || bytes.get(1) != Some(&sort_tag(sort)) {
        return Err(BAD);
    }
    let id = i64_at(&bytes, 2).ok_or(BAD)?;
    let rest = bytes.get(10..).ok_or(BAD)?;
    let key = match sort {
        SortKey::DateDesc | SortKey::DateAsc => match rest {
            [0] => CursorValue::Date(None),
            [1, ..] if rest.len() == 9 => CursorValue::Date(Some(i64_at(rest, 1).ok_or(BAD)?)),
            _ => return Err(BAD),
        },
        SortKey::SizeDesc | SortKey::SizeAsc => {
            if rest.len() != 8 {
                return Err(BAD);
            }
            CursorValue::Size(i64_at(rest, 0).ok_or(BAD)?)
        }
        SortKey::TitleAsc | SortKey::TitleDesc => {
            CursorValue::Title(String::from_utf8(rest.to_vec()).map_err(|_| BAD)?)
        }
    };
    Ok(CursorParts { id, key })
}
