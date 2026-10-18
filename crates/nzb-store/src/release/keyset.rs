//! Keyset (cursor) paging of the release listing: the cursor codec and page type. The seek itself is the search
//! index's (`nzb-search`, sorted walks keyed by the same cursor).
//!
//! A cursor is the sort key of one listed row plus its unique id: a position *between* rows of the
//! total order every `ORDER BY` of [`SortKey`] defines. Paging "after" or "before" it is a range seek on
//! the sort index followed by `LIMIT n + 1`, so the cost does not depend on how deep the page is, and a
//! page cannot repeat or skip a row when releases are added or removed between two requests (an offset
//! shifts, a position does not).
//!
//! Safety. A cursor is untrusted input. It is decoded strictly ([`PageCursor::decode`]: bounded length,
//! lowercase hex only, exact layout, the sort it was made for) and only ever reaches SQL as bound
//! parameters of statements built from static fragments. It selects a position, never a row set: the
//! filters, the hidden-category exclusion and the text predicate are applied to every page regardless of
//! it, so a forged cursor can show nothing a page number could not.

use super::{Page, ReleaseRow, SortKey};

/// Longest cursor text accepted by [`PageCursor::decode`], in characters.
pub const MAX_CURSOR_CHARS: usize = 1100;
/// Longest title carried in a cursor. A (never produced) longer one makes [`PageCursor::encode`] return
/// `None`, and the caller links by page number instead.
const MAX_TITLE_KEY_BYTES: usize = 512;
const VERSION: u8 = 1;

/// Which way to travel from a [`PageCursor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekDir {
    /// The rows after the cursor in the sort order (the next page).
    After,
    /// The rows before the cursor, still returned in the sort order (the previous page).
    Before,
}

/// The sort key of the cursor row. The variant is fixed by the sort order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Key {
    /// Date sorts: `posted_at`, `None` for an undated release.
    Date(Option<i64>),
    /// Size sorts: `total_bytes`.
    Size(i64),
    /// Title sorts: the stored title (compared `COLLATE NOCASE`, like the index).
    Title(String),
}

/// A position in the listing of one sort order. Opaque outside this module: build it from a row with
/// [`PageCursor::for_row`], move it through URLs with [`PageCursor::encode`] / [`PageCursor::decode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageCursor {
    sort: SortKey,
    id: i64,
    key: Key,
}

/// A cursor that is not well-formed or was made for another sort order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid page cursor")]
pub struct CursorError;

const fn sort_tag(s: SortKey) -> u8 {
    match s {
        SortKey::DateDesc => 0,
        SortKey::DateAsc => 1,
        SortKey::SizeDesc => 2,
        SortKey::SizeAsc => 3,
        SortKey::TitleAsc => 4,
        SortKey::TitleDesc => 5,
    }
}

const fn is_date(s: SortKey) -> bool {
    matches!(s, SortKey::DateDesc | SortKey::DateAsc)
}

const fn is_size(s: SortKey) -> bool {
    matches!(s, SortKey::SizeDesc | SortKey::SizeAsc)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Sequential reader over the decoded bytes (no indexing, every step bounds-checked).
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CursorError> {
        let (head, tail) = self.0.split_at_checked(n).ok_or(CursorError)?;
        self.0 = tail;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, CursorError> {
        self.take(1)?.first().copied().ok_or(CursorError)
    }

    fn i64(&mut self) -> Result<i64, CursorError> {
        let b: [u8; 8] = self.take(8)?.try_into().map_err(|_| CursorError)?;
        Ok(i64::from_be_bytes(b))
    }
}

impl PageCursor {
    /// The position of `row` in the listing sorted by `sort`.
    #[must_use]
    pub fn for_row(sort: SortKey, row: &ReleaseRow) -> Self {
        let key = if is_date(sort) {
            Key::Date(row.posted_at)
        } else if is_size(sort) {
            Key::Size(i64::try_from(row.total_bytes).unwrap_or(i64::MAX))
        } else {
            Key::Title(row.title.clone())
        };
        Self {
            sort,
            id: row.id,
            key,
        }
    }

    /// The sort order this cursor belongs to.
    #[must_use]
    pub const fn sort(&self) -> SortKey {
        self.sort
    }

    /// Lowercase hex of a fixed layout (`version, sort, id, key`). `None` when the key does not fit
    /// [`MAX_CURSOR_CHARS`].
    #[must_use]
    pub fn encode(&self) -> Option<String> {
        let mut b = vec![VERSION, sort_tag(self.sort)];
        b.extend_from_slice(&self.id.to_be_bytes());
        match &self.key {
            Key::Date(None) => b.push(0),
            Key::Date(Some(v)) => {
                b.push(1);
                b.extend_from_slice(&v.to_be_bytes());
            }
            Key::Size(v) => b.extend_from_slice(&v.to_be_bytes()),
            Key::Title(t) => {
                // Stored titles are sanitized (no control characters); `decode` refuses them, so a
                // cursor for one that has them could never be followed.
                if t.len() > MAX_TITLE_KEY_BYTES || t.chars().any(char::is_control) {
                    return None;
                }
                b.extend_from_slice(t.as_bytes());
            }
        }
        let mut s = String::with_capacity(b.len().saturating_mul(2));
        for byte in b {
            // Writing to a String cannot fail.
            let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{byte:02x}"));
        }
        (s.len() <= MAX_CURSOR_CHARS).then_some(s)
    }

    /// Strict inverse of [`PageCursor::encode`] for a listing sorted by `sort`.
    ///
    /// # Errors
    /// [`CursorError`] for anything else: wrong length or alphabet (uppercase hex is rejected so there is
    /// one spelling), unknown version, another sort order, a non-positive id, a negative size, trailing
    /// bytes, a title that is not UTF-8.
    pub fn decode(s: &str, sort: SortKey) -> Result<Self, CursorError> {
        if s.is_empty() || s.len() > MAX_CURSOR_CHARS || !s.len().is_multiple_of(2) {
            return Err(CursorError);
        }
        let digits = s
            .bytes()
            .map(hex_val)
            .collect::<Option<Vec<u8>>>()
            .ok_or(CursorError)?;
        let bytes: Vec<u8> = digits
            .chunks(2)
            .map(|p| {
                let hi = p.first().copied().unwrap_or(0);
                let lo = p.get(1).copied().unwrap_or(0);
                (hi << 4) | lo
            })
            .collect();
        let mut r = Reader(&bytes);
        if r.byte()? != VERSION || r.byte()? != sort_tag(sort) {
            return Err(CursorError);
        }
        let id = r.i64()?;
        if id < 1 {
            return Err(CursorError);
        }
        let key = if is_date(sort) {
            match r.byte()? {
                0 => Key::Date(None),
                1 => Key::Date(Some(r.i64()?)),
                _ => return Err(CursorError),
            }
        } else if is_size(sort) {
            let v = r.i64()?;
            if v < 0 {
                return Err(CursorError);
            }
            Key::Size(v)
        } else {
            let rest = r.take(r.0.len())?;
            if rest.len() > MAX_TITLE_KEY_BYTES {
                return Err(CursorError);
            }
            let t = std::str::from_utf8(rest).map_err(|_| CursorError)?;
            if t.chars().any(char::is_control) {
                return Err(CursorError);
            }
            Key::Title(t.to_owned())
        };
        if !r.0.is_empty() {
            return Err(CursorError);
        }
        Ok(Self { sort, id, key })
    }
}

/// One page of a keyset listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeysetPage {
    /// Rows of this page, in the sort order (also when travelling [`SeekDir::Before`]).
    pub items: Vec<ReleaseRow>,
    /// Total rows matching the filters (the same count [`SqliteDb::search`] reports).
    pub total: u64,
    /// Effective (clamped) page size.
    pub limit: u32,
    /// Whether the listing continues in the direction of travel beyond this page.
    pub has_more: bool,
}

/// Converts an offset [`Page`] into the shape callers of the keyset path use (all rows, no more).
impl From<Page<ReleaseRow>> for KeysetPage {
    fn from(p: Page<ReleaseRow>) -> Self {
        let shown = u64::from(p.offset).saturating_add(u64::try_from(p.items.len()).unwrap_or(0));
        Self {
            has_more: shown < p.total,
            items: p.items,
            total: p.total,
            limit: p.limit,
        }
    }
}
