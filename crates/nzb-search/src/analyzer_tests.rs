//! `scene` analyzer: scene-name tokens, folding, truncation, property tests and hostile input
//! (`DATA_MODEL` v3 5.2, SEC-089 `scene_analyzer`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cloned_ref_to_slice_refs,
    clippy::format_collect,
    clippy::format_push_string,
    clippy::manual_is_multiple_of,
    clippy::some_filter,
    clippy::uninlined_format_args,
    clippy::unused_async_trait_impl
)]

use proptest::prelude::*;

use crate::analyzer::{MAX_TOKEN_BYTES, analyze, cap_bytes};

/// T131: the `source_name` text drops `.nzb` extensions, appends the group, and stays within its cap.
#[test]
fn source_text_strips_the_extension_adds_the_group_and_is_capped() {
    use crate::analyzer::MAX_SOURCE_NAME_BYTES;
    let mut d = crate::testkit::doc(1, "t");
    d.source_name = "toto.PcGame-Mephisto.NZB".to_owned();
    assert_eq!(d.source_text(), "toto.PcGame-Mephisto");
    d.source_name = "a.nzb.nzb".to_owned();
    d.group = Some("GRP".to_owned());
    assert_eq!(d.source_text(), "a GRP");
    d.source_name = ".nzb".to_owned();
    d.group = None;
    assert_eq!(d.source_text(), "");
    d.source_name = "\u{e9}".repeat(400);
    d.group = Some("G".repeat(200));
    let t = d.source_text();
    assert!(t.len() <= MAX_SOURCE_NAME_BYTES);
    assert!(toks(&t).iter().all(|tok| tok.len() <= MAX_TOKEN_BYTES));
}

fn toks(s: &str) -> Vec<String> {
    analyze(s, usize::MAX)
}

#[test]
fn scene_names_split_on_punctuation_and_keep_scene_tokens_whole() {
    assert_eq!(
        toks("Show.Name.S01E02.1080p.WEB.x265-GRP Fïlm_ÆON"),
        [
            "show", "name", "s01e02", "1080p", "web", "x265", "grp", "film", "aeon"
        ]
    );
    assert_eq!(toks("DD5.1 H264 2160p"), ["dd5", "1", "h264", "2160p"]);
    assert_eq!(
        toks("[a]+(b)'c\"d*e:f^g"),
        ["a", "b", "c", "d", "e", "f", "g"]
    );
    assert_eq!(toks("Straße ÉTÉ"), ["strasse", "ete"]);
    assert_eq!(toks(""), Vec::<String>::new());
    assert_eq!(toks(" .-_ \t\n"), Vec::<String>::new());
}

#[test]
fn query_syntax_characters_are_plain_separators() {
    // Tantivy/Lucene/FTS syntax has no meaning: operators become words or vanish.
    assert_eq!(toks("title:foo AND -bar"), ["title", "foo", "and", "bar"]);
    assert_eq!(
        toks("\"x\"~2 y^3 z* [a TO b]"),
        ["x", "2", "y", "3", "z", "a", "to", "b"]
    );
    assert_eq!(toks("/re.*gex/"), ["re", "gex"]);
}

#[test]
fn long_tokens_are_truncated_at_a_char_boundary_not_dropped() {
    let long = "a".repeat(300);
    assert_eq!(toks(&long), ["a".repeat(MAX_TOKEN_BYTES)]);
    // Multi-byte chars: never split inside a char.
    let wide = "é".repeat(100); // folds to "e" (1 byte each)
    assert_eq!(toks(&wide), ["e".repeat(MAX_TOKEN_BYTES)]);
    let cjk = "漢".repeat(40); // 3 bytes each, no folding
    let t = toks(&cjk);
    assert_eq!(t.len(), 1);
    assert_eq!(t[0], "漢".repeat(21));
    assert!(t[0].len() <= MAX_TOKEN_BYTES);
    // Folding can grow a token (Æ -> ae); the cut happens after it.
    let grow = "Æ".repeat(50);
    assert_eq!(toks(&grow), ["ae".repeat(32)]);
}

#[test]
fn max_tokens_bounds_the_output() {
    let many = "a b c d e f g h i j k l m n o p q r s t";
    assert_eq!(analyze(many, 16).len(), 16);
    assert_eq!(analyze(many, 0).len(), 0);
}

#[test]
fn cap_bytes_respects_char_boundaries() {
    assert_eq!(cap_bytes("héllo", 2), "h");
    assert_eq!(cap_bytes("héllo", 3), "hé");
    assert_eq!(cap_bytes("abc", 10), "abc");
    assert_eq!(cap_bytes("€", 2), "");
}

#[test]
fn hostile_input_never_panics_and_stays_bounded() {
    let mut inputs = vec![
        "\u{0}\u{1}\u{7f}\u{202e}\u{feff}\u{200b}".to_owned(),
        "\u{10ffff}\u{e000}\u{fffd}".to_owned(),
        "İ̇ǅ ΣΑΣ ﬃ ẞ".to_owned(),
        "a\u{0301}\u{0301}\u{0301}b".to_owned(),
        "①②③ ⑴ ¼".to_owned(),
        "\r\n\t".repeat(10_000),
    ];
    // A 1 MiB mix of separators and long runs.
    inputs.push("x".repeat(512 * 1024) + &".".repeat(512 * 1024));
    for s in &inputs {
        let t = toks(s);
        assert!(
            t.iter()
                .all(|x| !x.is_empty() && x.len() <= MAX_TOKEN_BYTES)
        );
        // Tokens never exceed the number of runs in the input.
        assert!(t.len() <= s.chars().count());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn every_token_is_bounded_and_lowercase(s in ".{0,400}") {
        for t in toks(&s) {
            prop_assert!(!t.is_empty());
            prop_assert!(t.len() <= MAX_TOKEN_BYTES);
            prop_assert_eq!(t.to_lowercase(), t.clone());
        }
    }

    #[test]
    fn analysis_is_deterministic_and_separator_insensitive(
        words in prop::collection::vec("[A-Za-z0-9]{1,12}", 0..12),
        sep in "[ ._\\-+()\\[\\]]{1,3}",
    ) {
        // The same words joined by any separators give the same tokens (scene dots = spaces = dashes).
        let a = toks(&words.join(&sep));
        let b = toks(&words.join(" "));
        prop_assert_eq!(&a, &b);
        let expect: Vec<String> = words.iter().map(|w| w.to_ascii_lowercase()).collect();
        prop_assert_eq!(a, expect);
    }

    #[test]
    fn ascii_alphanumeric_runs_are_tokens(s in "[ -~]{0,200}") {
        // On printable ASCII the analyzer is exactly the 2.x split rule + lower-case + 64-byte cut.
        let expect: Vec<String> = s
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(|t| t.to_ascii_lowercase().chars().take(MAX_TOKEN_BYTES).collect())
            .collect();
        prop_assert_eq!(toks(&s), expect);
    }
}
