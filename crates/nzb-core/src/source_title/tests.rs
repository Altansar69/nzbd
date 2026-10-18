#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use super::*;
use crate::types::Sha256;

fn t(raw: &str) -> Option<String> {
    source_title(raw)
}

#[test]
fn release_names_are_usable_without_the_extension() {
    assert_eq!(
        t("toto.PcGame-Mephisto.nzb").as_deref(),
        Some("toto.PcGame-Mephisto")
    );
    assert_eq!(
        t("Some.Movie.2024.1080p.WEB-DL.H264-GRPNAME.NZB").as_deref(),
        Some("Some.Movie.2024.1080p.WEB-DL.H264-GRPNAME")
    );
    assert_eq!(
        t("Show Name S01E02.nzb.nzb").as_deref(),
        Some("Show Name S01E02")
    );
    assert_eq!(
        t("Some_Movie_2024_1080p-GRP.nzb").as_deref(),
        Some("Some_Movie_2024_1080p-GRP")
    );
    assert_eq!(
        t("Bad_Face_2024_Live.nzb").as_deref(),
        Some("Bad_Face_2024_Live")
    );
    assert_eq!(
        t("TheGreatestShowman.nzb").as_deref(),
        Some("TheGreatestShowman")
    );
    assert_eq!(t("a.nzb").as_deref(), Some("a"));
    // Only the last path component counts; nothing else of the name is interpreted.
    assert_eq!(t("../../etc/passwd.nzb").as_deref(), Some("passwd"));
    assert_eq!(t("C:\\x\\Film.Name.nzb").as_deref(), Some("Film.Name"));
    // `.nzb` is stripped only at the end; other extensions stay (the title is display data, not a scene stem).
    assert_eq!(t("archive.rar.nzb").as_deref(), Some("archive.rar"));
}

#[test]
fn generic_names_are_not_usable() {
    for n in [
        "download.nzb",
        "Download (1).nzb",
        "download(12).nzb",
        "download-3.nzb",
        "NZB.nzb",
        "file.nzb",
        "get.nzb",
        "index.nzb",
        "API.nzb",
        "untitled.nzb",
        "untitled (2).nzb",
        ".nzb",
        "  .nzb",
        "---.nzb",
        "\u{202e}\u{200b}.nzb",
        // Review 45 I2: spaced and repeated duplicate suffixes, and the analyzer's fallback form.
        "Download -1.nzb",
        "download (1)(2).nzb",
        "download (1) (2).nzb",
        "download-1-2.nzb",
        "untitled-deadbeef.nzb",
        "UNTITLED-0123ABCD.nzb",
        "untitled-deadbeef (1).nzb",
        // Review 45 I3: combining marks only (U+0345 is alphabetic but a mark), or marks and format characters.
        "\u{345}.nzb",
        "\u{301}\u{301}\u{301}.nzb",
        "\u{345}\u{200d}.nzb",
    ] {
        assert_eq!(t(n), None, "{n}");
    }
    // A generic word inside a real name is fine.
    assert!(t("download.festival.2024.nzb").is_some());
    assert!(t("downloader.nzb").is_some());
    assert!(t("untitled-deadbeefs.nzb").is_some());
    assert!(t("untitled-film.nzb").is_some());
    // A letter carrying marks is a letter.
    assert!(t("e\u{301}te\u{301}.nzb").is_some());
}

#[test]
fn digit_only_names_are_not_usable() {
    for n in [
        "12345.nzb",
        "2024-10-17.nzb",
        "0.nzb",
        "123 (1).nzb",
        "1_2_3.nzb",
    ] {
        assert_eq!(t(n), None, "{n}");
    }
}

#[test]
fn hash_like_names_are_not_usable() {
    for n in [
        "a8f3c9e1b7d24f6a9c0e.nzb",
        "d41d8cd98f00b204e9800998ecf8427e.nzb",
        "550e8400-e29b-41d4-a716-446655440000.nzb",
        "Zm9vYmFyYmF6cXV4MTIz.nzb",
        "x_Zm9vYmFyYmF6cXV4MTIz.nzb",
        "AbCdEfGh12345678.nzb",
        "a8f3c9e1b7d24f6a9c0e.part01.nzb",
        "a8f3c9e1b7d24f6a9c0e.7z.001.nzb",
    ] {
        assert_eq!(t(n), None, "{n}");
    }
    // Shorter than 16, or words around it: a name, not a hash.
    assert!(t("abc123def456.nzb").is_some());
    assert!(t("abc123def456.part01.nzb").is_some());
    assert!(t("Film.a8f3c9e1b7d24f6a9c0e.nzb").is_some());
}

#[test]
fn sec_004_hostile_file_name_titles_are_sanitized_and_capped() {
    let n = t("Evil\u{202e}gpj.\u{0}Name\u{7}\n<script>.nzb").unwrap();
    assert!(!n.chars().any(char::is_control));
    assert!(!n.contains('\u{202e}'));
    assert!(n.starts_with("Evilgpj.") && n.ends_with("<script>"), "{n}");
    let long = format!("{}.nzb", "\u{e9}".repeat(1000));
    let n = t(&long).unwrap();
    assert!(n.len() <= SOURCE_TITLE_BYTES);
}

fn analysis(title: &str) -> Analysis {
    Analysis {
        sha256: Sha256([0; 32]),
        name_candidates: Vec::new(),
        meta_name_candidates: 0,
        title: title.to_owned(),
        poster: None,
        posted_at: None,
        total_bytes: 0,
        file_count: 0,
        segment_count: 0,
        duplicate_segments: 0,
        par2_blocks: 0,
        flags: ReleaseFlags::EMPTY,
        meta_category: None,
        repairable_estimate: None,
        files: Vec::new(),
    }
}

#[test]
fn apply_prefers_a_usable_file_name_and_keeps_the_analyzer_title_otherwise() {
    let mut a = analysis("meta title");
    assert!(apply_source_title(&mut a, Some("Real.Name.nzb")));
    assert_eq!(a.title, "Real.Name");
    for unusable in [
        None,
        Some("download (1).nzb"),
        Some("a8f3c9e1b7d24f6a9c0e.nzb"),
    ] {
        let mut a = analysis("meta title");
        assert!(!apply_source_title(&mut a, unusable));
        assert_eq!(a.title, "meta title");
    }
    let mut a = analysis("x");
    apply_source_title(&mut a, Some("Film {{secret}}.nzb"));
    assert!(a.flags.contains(ReleaseFlags::PASSWORD_HINT));
}
