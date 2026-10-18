//! Fixture catalogue: valid documents and hostile inputs (PARSER_SPEC §Required tests).
//!
//! Every [`Case`] carries its bytes and the golden expectation. Small cases are committed under
//! `crates/nzb-core/tests/fixtures/{valid,hostile}/` (regenerate with
//! `scripts/dev cargo run -p nzb-testkit --example gen_fixtures`; a test fails if they drift).
//! Large cases (`committed == false`) are generated at test time and never stored.
//!
//! Expectation format: `{"error":"<NZB_CODE>"}` for rejections, or the
//! `{"ok":{...}}` summary produced by [`NzbBuilder::expected_json`].

use crate::builder::{FileSpec, NzbBuilder};

/// A named input plus its golden expectation.
#[derive(Clone, Debug)]
pub struct Case {
    /// File stem (`<name>.nzb` / `<name>.expected.json`).
    pub name: &'static str,
    /// `true` for hostile inputs, `false` for valid fixtures.
    pub hostile: bool,
    /// Raw input bytes (not necessarily valid UTF-8 or XML).
    pub bytes: Vec<u8>,
    /// Golden JSON (with trailing newline).
    pub expected: String,
    /// Whether this case is stored in the repository (small) or only generated (large).
    pub committed: bool,
}

fn err(code: &str) -> String {
    format!("{{\"error\":\"{code}\"}}\n")
}

fn hostile(name: &'static str, bytes: Vec<u8>, code: &str) -> Case {
    let committed = bytes.len() <= MAX_COMMITTED_BYTES;
    Case {
        name,
        hostile: true,
        bytes,
        expected: err(code),
        committed,
    }
}

/// Inputs larger than this are generated, never committed.
pub const MAX_COMMITTED_BYTES: usize = 16 * 1024;

/// The DOCTYPE carried by nearly every real NZB file.
pub const NEWZBIN_DOCTYPE: &str = "<!DOCTYPE nzb PUBLIC \"-//newzBin//DTD NZB 1.1//EN\" \"http://www.newzbin.com/DTD/nzb/nzb-1.1.dtd\">";

const HDR: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

/// Minimal well-formed one-segment document wrapping an arbitrary `<file>` subject (raw, unescaped).
fn one_file_with_raw_subject(subject: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(HDR.as_bytes());
    v.extend_from_slice(b"<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\"><file poster=\"p\" date=\"1700000000\" subject=\"");
    v.extend_from_slice(subject);
    v.extend_from_slice(b"\"><groups><group>alt.binaries.test</group></groups><segments><segment bytes=\"100\" number=\"1\">a@b</segment></segments></file></nzb>");
    v
}

/// One-file document with a single segment given as raw attribute text.
fn one_segment(bytes_attr: &str, number_attr: &str) -> Vec<u8> {
    NzbBuilder::new()
        .file(FileSpec::new("\"a.rar\" yEnc (1/1)").raw_segment(number_attr, bytes_attr))
        .build()
}

/// Valid fixtures with golden summaries.
#[must_use]
pub fn valid_cases() -> Vec<Case> {
    let mk = |name: &'static str, b: &NzbBuilder| Case {
        name,
        hostile: false,
        bytes: b.build(),
        expected: b.expected_json(),
        committed: true,
    };
    let single = NzbBuilder::new()
        .meta("title", "Some.Release.2020.1080p.WEB-DL")
        .file(
            FileSpec::new("\"movie.mkv\" yEnc (1/3)")
                .segments(3)
                .declared(3),
        );
    let gaps = NzbBuilder::new().generated(3, 10, &[&[], &[2, 3, 7], &[10]]);
    let nons = NzbBuilder::new().no_namespace().file(
        FileSpec::new("\"a.nfo\" yEnc (1/1)")
            .segments(1)
            .declared(1),
    );
    let meta = NzbBuilder::new()
        .meta("title", "Pass.Protected.Release")
        .meta("password", "hunter2")
        .meta("category", "movies.hd")
        .file(
            FileSpec::new("\"x.part01.rar\" yEnc (1/2)")
                .segments(2)
                .declared(2),
        );
    let dups = NzbBuilder::new().file(
        FileSpec::new("\"d.r00\" yEnc (1/4)")
            .segments(4)
            .duplicate(2)
            .duplicate(2)
            .declared(4),
    );
    // No `(n/m)` counter at all: gaps are computed below the highest number seen.
    let nodecl = NzbBuilder::new().file(FileSpec::new("\"name.ext\" yEnc").segments(5).gap(3));
    // PARSER_SPEC fallback form `name.ext (n/m)` declares m = 57 (T014 reconciled the T012 drift).
    let fallback = NzbBuilder::new().file(
        FileSpec::new("name.ext (1/57)")
            .segments(5)
            .gap(3)
            .declared(57),
    );
    let claim = NzbBuilder::new().file(FileSpec::new("\"c.mkv\" yEnc (1/10000000)").segments(1));
    let traversal = NzbBuilder::new().file(
        FileSpec::new("\"../../etc/passwd\" yEnc (1/1)")
            .segments(1)
            .declared(1),
    );

    // Unknown elements/attributes are skipped; hand-written, so hand-written golden.
    let unknown = format!(
        "{HDR}<nzb><foo a=\"1\"><bar/></foo><file poster=\"p\" date=\"1700000000\" subject=\"s\" extra=\"x\"><groups><group>g</group></groups><segments><segment bytes=\"10\" number=\"1\" crc=\"zz\">m@h</segment></segments><unk>t</unk></file></nzb>"
    );
    let unknown_case = Case {
        name: "unknown_elements",
        hostile: false,
        bytes: unknown.into_bytes(),
        expected: "{\"ok\":{\"file_count\":1,\"segment_count\":1,\"duplicate_segments\":0,\"total_bytes\":10,\"files\":[{\"subject\":\"s\",\"segment_count\":1,\"bytes\":10,\"missing_ranges\":[],\"missing_truncated\":false}]}}\n".to_owned(),
        committed: true,
    };
    // The standard newzBin header (SEC-001 relaxation): inert, ignored, never resolved.
    let newzbin = NzbBuilder::new()
        .doctype(NEWZBIN_DOCTYPE)
        .meta("password", "s3cret")
        .meta("title", "Demo.Release.2020.1080p")
        .file(
            FileSpec::new("[1/1] - \"demo.part01.rar\" yEnc (1/28)")
                .poster("Poster <poster@example.invalid>")
                .segments_of(28, 739_683)
                .declared(28)
                .groups(&["alt.toto"]),
        );
    let ext_dtd = NzbBuilder::new()
        .doctype("<!DOCTYPE nzb SYSTEM \"http://127.0.0.1:1/evil.dtd\">")
        .file(
            FileSpec::new("\"a.nfo\" yEnc (1/1)")
                .segments(1)
                .declared(1),
        );
    let file_dtd = NzbBuilder::new()
        .doctype("<!DOCTYPE nzb PUBLIC \"-//x//y//EN\" \"file:///etc/passwd\">")
        .file(
            FileSpec::new("\"a.nfo\" yEnc (1/1)")
                .segments(1)
                .declared(1),
        );
    let bare = NzbBuilder::new().doctype("<!DOCTYPE nzb>").file(
        FileSpec::new("\"a.nfo\" yEnc (1/1)")
            .segments(1)
            .declared(1),
    );
    vec![
        mk("doctype_newzbin_standard", &newzbin),
        mk("doctype_system_unresolved", &ext_dtd),
        mk("doctype_public_file_url_unresolved", &file_dtd),
        mk("doctype_bare", &bare),
        mk("single_file", &single),
        mk("multi_file_gaps", &gaps),
        mk("no_namespace", &nons),
        mk("meta_password_category", &meta),
        mk("duplicate_segments", &dups),
        mk("no_declared_total", &nodecl),
        mk("fallback_declared_total", &fallback),
        mk("claim_10m_segments_in_subject", &claim),
        mk("traversal_filename", &traversal),
        unknown_case,
    ]
}

/// Hostile fixtures, small ones first. Large ones are generated here and flagged `committed == false`.
#[must_use]
pub fn hostile_cases() -> Vec<Case> {
    let mut v = Vec::new();

    // --- DOCTYPE family: only the plain `nzb` form is valid (see valid_cases); the rest is rejected (SEC-001).
    v.push(hostile(
        "xxe_file_passwd",
        format!("{HDR}<!DOCTYPE nzb [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<nzb><head><meta type=\"title\">&xxe;</meta></head><file subject=\"s\"/></nzb>").into_bytes(),
        "NZB_DOCTYPE_FORBIDDEN",
    ));
    let laughs = "<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\"><!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\"><!ENTITY lol4 \"&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;\">";
    v.push(hostile(
        "billion_laughs",
        format!("{HDR}<!DOCTYPE nzb [{laughs}]>\n<nzb><head><meta type=\"title\">&lol4;</meta></head><file subject=\"s\"/></nzb>").into_bytes(),
        "NZB_DOCTYPE_FORBIDDEN",
    ));
    v.push(hostile(
        "doctype_internal_subset",
        format!("{HDR}<!DOCTYPE nzb [<!ELEMENT nzb ANY>]>\n<nzb><file subject=\"s\"/></nzb>")
            .into_bytes(),
        "NZB_DOCTYPE_FORBIDDEN",
    ));
    // Rejected DOCTYPE shapes around the accepted plain form.
    for (name, doc) in [
        (
            "doctype_root_html",
            "<!DOCTYPE html>\n<nzb><file subject=\"s\"/></nzb>",
        ),
        (
            "doctype_param_entity",
            "<!DOCTYPE nzb [<!ENTITY % p SYSTEM \"http://127.0.0.1:1/x\"> %p;]>\n<nzb><file subject=\"s\"/></nzb>",
        ),
        (
            "doctype_twice",
            "<!DOCTYPE nzb>\n<!DOCTYPE nzb>\n<nzb><file subject=\"s\"/></nzb>",
        ),
        (
            "doctype_after_root",
            "<nzb><file subject=\"s\"/></nzb>\n<!DOCTYPE nzb>",
        ),
        (
            "doctype_inside_root",
            "<nzb><!DOCTYPE nzb><file subject=\"s\"/></nzb>",
        ),
        (
            "doctype_lowercase",
            "<!doctype nzb>\n<nzb><file subject=\"s\"/></nzb>",
        ),
        (
            "doctype_unterminated",
            "<!DOCTYPE nzb SYSTEM \"http://x/y.dtd\"\n<nzb><file subject=\"s\"/></nzb>",
        ),
        (
            "doctype_literal_gt",
            "<!DOCTYPE nzb SYSTEM \"a>b\">\n<nzb><file subject=\"s\"/></nzb>",
        ),
    ] {
        v.push(hostile(
            name,
            format!("{HDR}{doc}").into_bytes(),
            "NZB_DOCTYPE_FORBIDDEN",
        ));
    }
    // Prolog hygiene (T083): stray text, CDATA or a reference before the root, a misplaced XML
    // declaration, or a processing instruction after the DOCTYPE. Nothing before the root
    // element may carry content other than whitespace, comments, the one declaration and the
    // one accepted DOCTYPE.
    let root = "<nzb><file subject=\"s\"/></nzb>";
    for (name, doc, code) in [
        (
            "prolog_text_before_root",
            format!("{HDR}junk\n{root}"),
            "NZB_MALFORMED",
        ),
        (
            "prolog_text_after_doctype",
            format!("{HDR}<!DOCTYPE nzb> junk\n{root}"),
            "NZB_MALFORMED",
        ),
        (
            "prolog_bracket_before_doctype",
            format!("{HDR}[ <!DOCTYPE nzb>\n{root}"),
            "NZB_MALFORMED",
        ),
        (
            "prolog_cdata",
            format!("{HDR}<![CDATA[x]]>\n{root}"),
            "NZB_MALFORMED",
        ),
        (
            "prolog_cdata_before_doctype",
            format!("{HDR}<![CDATA[x]]><!DOCTYPE nzb>\n{root}"),
            "NZB_MALFORMED",
        ),
        (
            "prolog_reference",
            format!("{HDR}&amp;\n{root}"),
            "NZB_MALFORMED",
        ),
        (
            "prolog_pi_before_doctype",
            format!("{HDR}<?pi x?><!DOCTYPE nzb>\n{root}"),
            "NZB_DOCTYPE_FORBIDDEN",
        ),
        (
            "prolog_pi_after_doctype",
            format!("{HDR}<!DOCTYPE nzb><?pi x?>\n{root}"),
            "NZB_DOCTYPE_FORBIDDEN",
        ),
        (
            "xml_decl_after_doctype",
            format!("<!DOCTYPE nzb>\n{HDR}{root}"),
            "NZB_MALFORMED",
        ),
        (
            "xml_decl_after_comment",
            format!("<!-- c -->{HDR}{root}"),
            "NZB_MALFORMED",
        ),
        (
            "xml_decl_twice",
            format!("{HDR}{HDR}{root}"),
            "NZB_MALFORMED",
        ),
    ] {
        v.push(hostile(name, doc.into_bytes(), code));
    }
    // Entity use without any DOCTYPE: only the five predefined entities are allowed.
    v.push(hostile(
        "undefined_entity",
        one_file_with_raw_subject(b"&xxe;"),
        "NZB_MALFORMED",
    ));

    // --- Structure / depth.
    let mut deep = format!("{HDR}<nzb>");
    for _ in 0..100 {
        deep.push_str("<a>");
    }
    for _ in 0..100 {
        deep.push_str("</a>");
    }
    deep.push_str("<file subject=\"s\"/></nzb>");
    v.push(hostile(
        "nesting_100_deep",
        deep.into_bytes(),
        "NZB_LIMIT_XML_DEPTH",
    ));

    let mut trunc = NzbBuilder::new()
        .file(FileSpec::new("\"a.rar\" yEnc (1/2)").segments(2))
        .build();
    trunc.truncate(trunc.len().saturating_sub(120));
    v.push(hostile("truncated_xml", trunc, "NZB_MALFORMED"));
    v.push(hostile(
        "empty_nzb_selfclosing",
        format!("{HDR}<nzb/>").into_bytes(),
        "NZB_EMPTY",
    ));
    v.push(hostile(
        "empty_nzb_head_only",
        format!("{HDR}<nzb><head><meta type=\"title\">t</meta></head></nzb>").into_bytes(),
        "NZB_EMPTY",
    ));
    v.push(hostile("empty_input", Vec::new(), "NZB_EMPTY"));
    v.push(hostile(
        "wrong_root",
        format!("{HDR}<html><file subject=\"s\"/></html>").into_bytes(),
        "NZB_EMPTY",
    ));

    // --- Encoding.
    let mut bad_utf8 = one_file_with_raw_subject(b"bad");
    if let Some(pos) = bad_utf8.windows(3).position(|w| w == b"bad")
        && let Some(b) = bad_utf8.get_mut(pos)
    {
        *b = 0xFF;
    }
    v.push(hostile("invalid_utf8", bad_utf8, "NZB_NOT_UTF8"));
    let mut utf16 = vec![0xFF, 0xFE];
    for u in format!("{HDR}<nzb><file subject=\"s\"/></nzb>").encode_utf16() {
        utf16.extend_from_slice(&u.to_le_bytes());
    }
    v.push(hostile("utf16_bom", utf16, "NZB_NOT_UTF8"));
    // gzip magic + deflate-ish junk (a gzipped NZB is not accepted; callers must not decompress).
    v.push(hostile(
        "gzip_bytes",
        vec![
            0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xCB, 0xAB, 0x4C, 0x2A,
            0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x07, 0x00, 0x00, 0x00,
        ],
        "NZB_NOT_UTF8",
    ));

    // --- Numbers.
    v.push(hostile(
        "bytes_negative",
        one_segment("-1", "1"),
        "NZB_MALFORMED",
    ));
    v.push(hostile(
        "bytes_u64_max",
        one_segment("18446744073709551615", "1"),
        "NZB_LIMIT_SEGMENT_BYTES",
    ));
    v.push(hostile(
        "bytes_not_a_number",
        one_segment("12abc", "1"),
        "NZB_MALFORMED",
    ));
    v.push(hostile(
        "number_zero",
        one_segment("100", "0"),
        "NZB_MALFORMED",
    ));
    v.push(hostile(
        "number_u32_max",
        one_segment("100", "4294967295"),
        "NZB_LIMIT_SEGMENTS_PER_FILE",
    ));
    v.push(hostile(
        "number_u64_overflow",
        one_segment("100", "99999999999999999999"),
        "NZB_MALFORMED",
    ));

    // --- Text fields.
    // Duplicate-number case lives in valid_cases (accepted, counted). NUL + bidi are accepted but sanitized.
    let nul_bidi = one_file_with_raw_subject("a\0b\u{202E}c\u{2066}.mkv".as_bytes());
    v.push(Case {
        name: "subject_nul_bidi",
        hostile: true,
        bytes: nul_bidi,
        expected: "{\"ok\":{\"file_count\":1,\"segment_count\":1,\"duplicate_segments\":0,\"total_bytes\":100,\"files\":[{\"subject\":\"abc.mkv\",\"segment_count\":1,\"bytes\":100,\"missing_ranges\":[],\"missing_truncated\":false}]}}\n".to_owned(),
        committed: true,
    });

    // --- Generated (large) cases; never committed.
    v.push(hostile(
        "subject_10mb",
        one_file_with_raw_subject(&vec![b'A'; 10 * 1024 * 1024]),
        "NZB_LIMIT_SUBJECT_BYTES",
    ));
    v.push(hostile("poster_1mb", {
        let mut f = String::from(HDR);
        f.push_str("<nzb><file poster=\"");
        f.push_str(&"P".repeat(1024 * 1024));
        f.push_str("\" subject=\"s\"><segments><segment bytes=\"1\" number=\"1\">a@b</segment></segments></file></nzb>");
        f.into_bytes()
    }, "NZB_LIMIT_POSTER_BYTES"));
    v.push(hostile(
        "message_id_1mb",
        {
            let mut f = String::from(HDR);
            f.push_str("<nzb><file subject=\"s\"><segments><segment bytes=\"1\" number=\"1\">");
            f.push_str(&"m".repeat(1024 * 1024));
            f.push_str("</segment></segments></file></nzb>");
            f.into_bytes()
        },
        "NZB_LIMIT_MESSAGE_ID_BYTES",
    ));
    v.push(hostile(
        "empty_files_1m",
        {
            let mut f = format!("{HDR}<nzb>").into_bytes();
            for _ in 0..1_000_000 {
                f.extend_from_slice(b"<file/>\n");
            }
            f.extend_from_slice(b"</nzb>");
            f
        },
        "NZB_LIMIT_FILES",
    ));
    // 100 001 distinct segments in one file (limit is 100 000). A literal 10 M-segment document would
    // exceed max_file_bytes (64 MiB) first, so the per-file count limit is the meaningful test.
    v.push(hostile(
        "segments_per_file_100001",
        {
            let mut f = format!("{HDR}<nzb><file subject=\"s\"><segments>").into_bytes();
            for n in 1..=100_001u32 {
                f.extend_from_slice(
                    format!("<segment bytes=\"1\" number=\"{n}\">m{n}@h</segment>").as_bytes(),
                );
            }
            f.extend_from_slice(b"</segments></file></nzb>");
            f
        },
        "NZB_LIMIT_SEGMENTS_PER_FILE",
    ));
    // Over max_file_bytes (64 MiB): cheap padding inside a comment.
    v.push(hostile(
        "file_over_64mib",
        {
            let mut f = format!("{HDR}<nzb><!--").into_bytes();
            f.resize(f.len() + 64 * 1024 * 1024 + 1, b'x');
            f.extend_from_slice(b"--><file subject=\"s\"/></nzb>");
            f
        },
        "NZB_LIMIT_FILE_BYTES",
    ));

    for c in &mut v {
        c.committed = c.bytes.len() <= MAX_COMMITTED_BYTES;
    }
    v
}

/// Every case (valid then hostile).
#[must_use]
pub fn all_cases() -> Vec<Case> {
    let mut v = valid_cases();
    v.extend(hostile_cases());
    v
}
