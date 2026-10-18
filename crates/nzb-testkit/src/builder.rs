//! Fluent builder for valid (and, via raw setters, slightly abnormal) NZB documents.

use crate::{json_escape, xml_escape};
use std::collections::BTreeSet;

/// Default per-segment size used by generated segments.
pub const DEFAULT_SEGMENT_BYTES: u64 = 768_000;
/// Maximum number of missing ranges reported in expected JSON (mirrors PARSER_SPEC).
const MAX_RANGES: usize = 256;

#[derive(Clone, Debug)]
struct RawSeg {
    number: String,
    bytes: String,
}

/// One `<file>` element.
#[derive(Clone, Debug)]
pub struct FileSpec {
    subject: String,
    expected_subject: Option<String>,
    poster: String,
    date: Option<String>,
    groups: Vec<String>,
    segs: Vec<RawSeg>,
    declared: Option<u32>,
}

impl FileSpec {
    /// New file with the given raw subject, no segments.
    #[must_use]
    pub fn new(subject: &str) -> Self {
        Self {
            subject: subject.to_owned(),
            expected_subject: None,
            poster: "poster@example.invalid".to_owned(),
            date: Some("1700000000".to_owned()),
            groups: vec!["alt.binaries.test".to_owned()],
            segs: Vec::new(),
            declared: None,
        }
    }
    /// Set the poster attribute.
    #[must_use]
    pub fn poster(mut self, p: &str) -> Self {
        p.clone_into(&mut self.poster);
        self
    }
    /// Set the raw `date` attribute (`None` omits it).
    #[must_use]
    pub fn date(mut self, d: Option<&str>) -> Self {
        self.date = d.map(str::to_owned);
        self
    }
    /// Replace the newsgroup list.
    #[must_use]
    pub fn groups(mut self, g: &[&str]) -> Self {
        self.groups = g.iter().map(|s| (*s).to_owned()).collect();
        self
    }
    /// Subject the parser is expected to produce after sanitizing (defaults to the raw subject).
    #[must_use]
    pub fn expect_subject(mut self, s: &str) -> Self {
        self.expected_subject = Some(s.to_owned());
        self
    }
    /// Declared total used for gap computation (should match `(n/m)` in the subject).
    #[must_use]
    pub fn declared(mut self, m: u32) -> Self {
        self.declared = Some(m);
        self
    }
    /// Append segments numbered 1..=n of [`DEFAULT_SEGMENT_BYTES`] each.
    #[must_use]
    pub fn segments(self, n: u32) -> Self {
        self.segments_of(n, DEFAULT_SEGMENT_BYTES)
    }
    /// Append segments numbered 1..=n of `bytes` each.
    #[must_use]
    pub fn segments_of(mut self, n: u32, bytes: u64) -> Self {
        for i in 1..=n {
            self.segs.push(RawSeg {
                number: i.to_string(),
                bytes: bytes.to_string(),
            });
        }
        self
    }
    /// Remove every segment numbered `n` (creates a gap).
    #[must_use]
    pub fn gap(mut self, n: u32) -> Self {
        let n = n.to_string();
        self.segs.retain(|s| s.number != n);
        self
    }
    /// Append a duplicate of segment `n` (default size).
    #[must_use]
    pub fn duplicate(self, n: u32) -> Self {
        self.raw_segment(&n.to_string(), &DEFAULT_SEGMENT_BYTES.to_string())
    }
    /// Append a segment with raw (unvalidated) `number` and `bytes` attribute text.
    #[must_use]
    pub fn raw_segment(mut self, number: &str, bytes: &str) -> Self {
        self.segs.push(RawSeg {
            number: number.to_owned(),
            bytes: bytes.to_owned(),
        });
        self
    }

    fn render(&self, idx: usize, out: &mut String) {
        out.push_str(&format!("<file poster=\"{}\"", xml_escape(&self.poster)));
        if let Some(d) = &self.date {
            out.push_str(&format!(" date=\"{}\"", xml_escape(d)));
        }
        out.push_str(&format!(
            " subject=\"{}\">\n<groups>",
            xml_escape(&self.subject)
        ));
        for g in &self.groups {
            out.push_str(&format!("<group>{}</group>", xml_escape(g)));
        }
        out.push_str("</groups>\n<segments>\n");
        for (i, s) in self.segs.iter().enumerate() {
            out.push_str(&format!(
                "<segment bytes=\"{}\" number=\"{}\">f{idx}s{i}@testkit.invalid</segment>\n",
                xml_escape(&s.bytes),
                xml_escape(&s.number),
            ));
        }
        out.push_str("</segments>\n</file>\n");
    }

    /// (distinct seen numbers, duplicates, bytes of kept segments). Raw segments that do not parse
    /// are not counted: expected JSON is only meaningful for valid documents.
    fn stats(&self) -> (BTreeSet<u32>, u64, u64) {
        let mut seen = BTreeSet::new();
        let (mut dups, mut bytes) = (0u64, 0u64);
        for s in &self.segs {
            if let (Ok(n), Ok(b)) = (s.number.parse::<u32>(), s.bytes.parse::<u64>()) {
                if seen.insert(n) {
                    bytes = bytes.saturating_add(b);
                } else {
                    dups = dups.saturating_add(1);
                }
            }
        }
        (seen, dups, bytes)
    }

    fn missing(seen: &BTreeSet<u32>, declared: Option<u32>) -> Vec<(u32, u32)> {
        let top = declared.unwrap_or_else(|| seen.last().copied().unwrap_or(0));
        let mut ranges: Vec<(u32, u32)> = Vec::new();
        for n in 1..=top {
            if seen.contains(&n) {
                continue;
            }
            match ranges.last_mut() {
                Some((_, hi)) if hi.checked_add(1) == Some(n) => *hi = n,
                _ => ranges.push((n, n)),
            }
        }
        ranges
    }
}

/// Builder for a whole NZB document.
#[derive(Clone, Debug)]
pub struct NzbBuilder {
    metas: Vec<(String, String)>,
    files: Vec<FileSpec>,
    namespace: bool,
    doctype: Option<String>,
}

impl Default for NzbBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NzbBuilder {
    /// Empty document with the standard namespace.
    #[must_use]
    pub fn new() -> Self {
        Self {
            metas: Vec::new(),
            files: Vec::new(),
            namespace: true,
            doctype: None,
        }
    }
    /// Omit the `xmlns` attribute (PARSER_SPEC: namespace is optional).
    #[must_use]
    pub fn no_namespace(mut self) -> Self {
        self.namespace = false;
        self
    }
    /// Emit `decl` (a complete `<!DOCTYPE ...>` declaration) right after the XML declaration.
    #[must_use]
    pub fn doctype(mut self, decl: &str) -> Self {
        self.doctype = Some(decl.to_owned());
        self
    }
    /// Add `<meta type="kind">value</meta>`.
    #[must_use]
    pub fn meta(mut self, kind: &str, value: &str) -> Self {
        self.metas.push((kind.to_owned(), value.to_owned()));
        self
    }
    /// Add one file.
    #[must_use]
    pub fn file(mut self, f: FileSpec) -> Self {
        self.files.push(f);
        self
    }
    /// Add `files` generated RAR-style files of `segments` segments each; for file `i` (0-based)
    /// every number in `gaps[i]` is removed. Missing `gaps` entries mean "no gaps".
    #[must_use]
    pub fn generated(mut self, files: u32, segments: u32, gaps: &[&[u32]]) -> Self {
        for i in 0..files {
            let idx = usize::try_from(i).unwrap_or(usize::MAX);
            let subject = format!(
                "[{:02}/{:02}] - \"release.part{:02}.rar\" yEnc (1/{segments})",
                i.saturating_add(1),
                files,
                i.saturating_add(1)
            );
            let mut f = FileSpec::new(&subject)
                .segments(segments)
                .declared(segments);
            for g in gaps.get(idx).copied().unwrap_or(&[]) {
                f = f.gap(*g);
            }
            self.files.push(f);
        }
        self
    }

    /// Render the document as UTF-8 bytes.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut s = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        if let Some(d) = &self.doctype {
            s.push_str(d);
            s.push('\n');
        }
        if self.namespace {
            s.push_str("<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n");
        } else {
            s.push_str("<nzb>\n");
        }
        s.push_str("<head>\n");
        for (k, v) in &self.metas {
            s.push_str(&format!(
                "<meta type=\"{}\">{}</meta>\n",
                xml_escape(k),
                xml_escape(v)
            ));
        }
        s.push_str("</head>\n");
        for (i, f) in self.files.iter().enumerate() {
            f.render(i, &mut s);
        }
        s.push_str("</nzb>\n");
        s.into_bytes()
    }

    /// Golden expectation for this (valid) document:
    /// `{"ok":{"file_count":..,"segment_count":..,"duplicate_segments":..,"total_bytes":..,"files":[..]}}`.
    /// Missing ranges follow PARSER_SPEC (declared total if set, else gaps below max seen), capped at 256.
    #[must_use]
    pub fn expected_json(&self) -> String {
        let (mut segs, mut dups, mut total) = (0usize, 0u64, 0u64);
        let mut files = Vec::new();
        for f in &self.files {
            let (seen, d, b) = f.stats();
            segs = segs.saturating_add(seen.len());
            dups = dups.saturating_add(d);
            total = total.saturating_add(b);
            let mut ranges = FileSpec::missing(&seen, f.declared);
            let more = ranges.len() > MAX_RANGES;
            ranges.truncate(MAX_RANGES);
            let r: Vec<String> = ranges.iter().map(|(a, z)| format!("[{a},{z}]")).collect();
            let subj = f.expected_subject.as_deref().unwrap_or(&f.subject);
            files.push(format!(
                "{{\"subject\":\"{}\",\"segment_count\":{},\"bytes\":{b},\"missing_ranges\":[{}],\"missing_truncated\":{more}}}",
                json_escape(subj),
                seen.len(),
                r.join(",")
            ));
        }
        format!(
            "{{\"ok\":{{\"file_count\":{},\"segment_count\":{segs},\"duplicate_segments\":{dups},\"total_bytes\":{total},\"files\":[{}]}}}}\n",
            self.files.len(),
            files.join(",")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_counts_files_segments_and_gaps() {
        let b = NzbBuilder::new().generated(3, 10, &[&[], &[2, 3, 7], &[]]);
        let xml = String::from_utf8(b.build()).unwrap_or_default();
        assert_eq!(xml.matches("<file ").count(), 3);
        assert_eq!(xml.matches("<segment ").count(), 27);
        let j = b.expected_json();
        assert!(j.contains("\"file_count\":3"));
        assert!(j.contains("\"segment_count\":27"));
        assert!(j.contains("\"missing_ranges\":[[2,3],[7,7]]"));
        assert!(j.contains("\"total_bytes\":20736000"));
    }

    #[test]
    fn duplicates_are_counted_not_summed() {
        let b = NzbBuilder::new().file(FileSpec::new("a").segments(2).duplicate(1));
        assert!(b.expected_json().contains("\"duplicate_segments\":1"));
        assert!(b.expected_json().contains("\"total_bytes\":1536000"));
    }

    #[test]
    fn attributes_are_escaped() {
        let xml = String::from_utf8(
            NzbBuilder::new()
                .file(FileSpec::new("a\"<&b").segments(1))
                .build(),
        )
        .unwrap_or_default();
        assert!(xml.contains("subject=\"a&quot;&lt;&amp;b\""));
    }
}
