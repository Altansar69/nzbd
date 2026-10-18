#![allow(
    clippy::assert_is_empty,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::too_many_lines
)]

use super::*;
use nzb_testkit::{FileSpec, NzbBuilder};

struct Fake(Duration);

impl Clock for Fake {
    fn elapsed(&self) -> Duration {
        self.0
    }
    fn now_unix(&self) -> i64 {
        1_800_000_000
    }
}

fn run(b: &NzbBuilder) -> Analysis {
    analyze_with_clock(&b.build(), &Limits::default(), &Fake(Duration::ZERO)).unwrap()
}

fn f(name: &str, segs: u32) -> FileSpec {
    FileSpec::new(&format!("\"{name}\" yEnc (1/{segs})"))
        .segments(segs)
        .declared(segs)
}

#[test]
fn title_prefers_meta_title_then_name() {
    let a = run(&NzbBuilder::new()
        .meta("name", "Meta.Name")
        .meta("title", "Meta.Title")
        .file(f("x.mkv", 1)));
    assert_eq!(a.title, "Meta.Title");
    assert_eq!(a.name_candidates, vec!["Meta.Name", "Meta.Title", "x"]);
    assert_eq!(a.meta_name_candidates, 2);
    let a = run(&NzbBuilder::new()
        .meta("name", "Meta.Name")
        .file(f("x.mkv", 1)));
    assert_eq!(a.title, "Meta.Name");
}

#[test]
fn title_from_largest_archive_or_video_stripped() {
    let a = run(&NzbBuilder::new()
        .file(f("Some.Release.2020.nfo", 1))
        .file(f("Some.Release.2020.part01.rar", 2))
        .file(f("Some.Release.2020.part02.rar", 5))
        .file(f("Some.Release.2020.vol00+01.par2", 9)));
    assert_eq!(a.title, "Some.Release.2020");
    assert_eq!(a.name_candidates, vec!["Some.Release.2020"]);
    assert_eq!(a.meta_name_candidates, 0);
}

#[test]
fn title_strip_forms() {
    for (name, want) in [
        ("A.B.mkv", "A.B"),
        ("A.B.7z.001", "A.B"),
        ("A.B.r05", "A.B"),
        ("A.B.PART003.RAR", "A.B"),
        ("A.B.vol003+004.par2", "A.B"),
        ("A.B.2020.1080p.mkv", "A.B.2020.1080p"),
    ] {
        assert_eq!(strip_release_suffix(name, true), want, "{name}");
    }
    // Meta names keep scene tokens that look like extensions.
    assert_eq!(
        strip_release_suffix("Movie.2020.TS", false),
        "Movie.2020.TS"
    );
    assert_eq!(strip_release_suffix("Movie.2020.nzb", false), "Movie.2020");
    assert_eq!(
        strip_release_suffix("Movie.2020.1080p", true),
        "Movie.2020.1080p"
    );
}

#[test]
fn title_from_common_prefix_then_most_common_then_untitled() {
    let a = run(&NzbBuilder::new()
        .file(f("Album.Name.01.mp3", 1))
        .file(f("Album.Name.02.mp3", 1))
        .file(f("Album.Name.cover.jpg", 1)));
    assert_eq!(a.title, "Album.Name");
    // No shared prefix: most common stem wins (first seen on ties).
    let a = run(&NzbBuilder::new()
        .file(f("zzz.txt", 1))
        .file(f("aaa.txt", 1))
        .file(f("aaa.nfo", 1)));
    assert_eq!(a.title, "aaa");
    // Nothing usable: obfuscated subjects only.
    let b = NzbBuilder::new().file(FileSpec::new("zxcvbnm obfuscated").segments(1));
    let a = run(&b);
    assert_eq!(a.title, format!("untitled-{}", a.sha256.short()));
    assert!(a.name_candidates.is_empty());
}

#[test]
fn poster_is_most_frequent_ties_first_seen() {
    let a = run(&NzbBuilder::new()
        .file(f("a.mkv", 1).poster("b@x"))
        .file(f("b.mkv", 1).poster("a@x"))
        .file(f("c.mkv", 1).poster("a@x")));
    assert_eq!(a.poster.as_deref(), Some("a@x"));
    let a = run(&NzbBuilder::new()
        .file(f("a.mkv", 1).poster("z@x"))
        .file(f("b.mkv", 1).poster("a@x")));
    assert_eq!(a.poster.as_deref(), Some("z@x"));
}

#[test]
fn posted_at_is_max_valid_date() {
    let a = run(&NzbBuilder::new()
        .file(f("a.mkv", 1).date(Some("1600000000")))
        .file(f("b.mkv", 1).date(Some("1700000500")))
        .file(f("c.mkv", 1).date(Some("1000")))
        .file(f("d.mkv", 1).date(None)));
    assert_eq!(a.posted_at, Some(1_700_000_500));
    let a = run(&NzbBuilder::new().file(f("a.mkv", 1).date(None)));
    assert_eq!(a.posted_at, None);
}

#[test]
fn counts_and_sha256() {
    let b = NzbBuilder::new()
        .file(f("a.mkv", 3).duplicate(2))
        .file(f("a.nfo", 1));
    let bytes = b.build();
    let a = analyze_with_clock(&bytes, &Limits::default(), &Fake(Duration::ZERO)).unwrap();
    assert_eq!(a.file_count, 2);
    assert_eq!(a.segment_count, 4);
    assert_eq!(a.duplicate_segments, 1);
    assert_eq!(a.total_bytes, 4 * 768_000);
    assert_eq!(a.sha256, Sha256(Hasher::digest(&bytes).into()));
    assert!(a.flags.contains(ReleaseFlags::DUPLICATE_SEGMENTS));
    let mut other = bytes.clone();
    other.extend_from_slice(b"\n");
    let a2 = analyze_with_clock(&other, &Limits::default(), &Fake(Duration::ZERO)).unwrap();
    assert_ne!(a.sha256, a2.sha256);
    // Known vector: sha256 of the empty-ish constant is computed by sha2; check hex shape.
    assert_eq!(a.sha256.to_hex().len(), 64);
}

#[test]
fn missing_ranges_use_declared_total_for_every_subject_form() {
    // Reconciled T012 drift: the fallback `name.ext (1/57)` form declares 57.
    let a = run(&NzbBuilder::new().file(FileSpec::new("name.ext (1/57)").segments(5).gap(3)));
    let fi = &a.files[0];
    assert_eq!(fi.declared_segments, Some(57));
    assert_eq!(fi.missing_ranges, vec![(3, 3), (6, 57)]);
    assert!(a.flags.contains(ReleaseFlags::INCOMPLETE));
    // No counter at all: gaps below the highest number seen.
    let a = run(&NzbBuilder::new().file(FileSpec::new("\"name.ext\" yEnc").segments(5).gap(3)));
    assert_eq!(a.files[0].declared_segments, None);
    assert_eq!(a.files[0].missing_ranges, vec![(3, 3)]);
}

#[test]
fn flags_par2_blocks_and_executable() {
    let a = run(&NzbBuilder::new()
        .file(f("r.part01.rar", 2))
        .file(f("r.vol00+01.par2", 1))
        .file(f("r.vol01+02.par2", 1))
        .file(f("r.par2", 1))
        .file(f("setup.exe", 1)));
    assert_eq!(a.par2_blocks, 3);
    for fl in [
        ReleaseFlags::HAS_PAR2,
        ReleaseFlags::PAR2_BLOCKS,
        ReleaseFlags::HAS_EXECUTABLE,
    ] {
        assert!(a.flags.contains(fl));
    }
    assert!(!a.flags.contains(ReleaseFlags::NO_ARCHIVE_OR_VIDEO));
    assert!(!a.flags.contains(ReleaseFlags::INCOMPLETE));
    assert_eq!(a.files[1].par2_blocks, Some(1));
    assert_eq!(a.files[3].par2_blocks, None);
    assert_eq!(a.repairable_estimate, None);
}

#[test]
fn flag_no_archive_or_video_and_clean_release() {
    let a = run(&NzbBuilder::new().file(f("a.nfo", 1)).file(f("b.jpg", 1)));
    assert!(a.flags.contains(ReleaseFlags::NO_ARCHIVE_OR_VIDEO));
    let a = run(&NzbBuilder::new().file(f("a.mkv", 1)));
    assert_eq!(a.flags, ReleaseFlags::EMPTY);
}

#[test]
fn flag_obfuscated_threshold() {
    let obf = |n: &str| FileSpec::new(&format!("\"{n}\" yEnc (1/1)")).segments(1);
    let h1 = "a1b2c3d4e5f6a7b8c9d0e1f2";
    let h2 = "ffeeddccbbaa99887766554433";
    // 2 of 4 non-par2 files obfuscated -> exactly 50% -> flagged. Par2 is ignored.
    let a = run(&NzbBuilder::new()
        .file(obf(h1))
        .file(obf(h2))
        .file(f("a.mkv", 1))
        .file(f("b.nfo", 1))
        .file(f("x.vol00+01.par2", 1)));
    assert!(a.flags.contains(ReleaseFlags::OBFUSCATED));
    let a = run(&NzbBuilder::new()
        .file(obf(h1))
        .file(f("a.mkv", 1))
        .file(f("b.nfo", 1)));
    assert!(!a.flags.contains(ReleaseFlags::OBFUSCATED));
    // Unnamed subjects count as obfuscated.
    let a = run(&NzbBuilder::new().file(FileSpec::new("no name here").segments(1)));
    assert!(a.flags.contains(ReleaseFlags::OBFUSCATED));
}

#[test]
fn flag_password_hint() {
    let a = run(&NzbBuilder::new().meta("password", "x").file(f("a.mkv", 1)));
    assert!(a.flags.contains(ReleaseFlags::PASSWORD_HINT));
    let a = run(&NzbBuilder::new()
        .meta("title", "Rel{{secret}}")
        .file(f("a.mkv", 1)));
    assert!(a.flags.contains(ReleaseFlags::PASSWORD_HINT));
    let a = run(&NzbBuilder::new()
        .meta("title", "Rel PASSWORD inside")
        .file(f("a.mkv", 1)));
    assert!(a.flags.contains(ReleaseFlags::PASSWORD_HINT));
    let a = run(&NzbBuilder::new()
        .meta("title", "Rel {{ open")
        .file(f("a.mkv", 1)));
    assert!(!a.flags.contains(ReleaseFlags::PASSWORD_HINT));
    let a = run(&NzbBuilder::new().file(f("pw{{abc}}.mkv", 1)));
    assert!(a.flags.contains(ReleaseFlags::PASSWORD_HINT));
}

fn gap(names: &[&str]) -> bool {
    let mut b = NzbBuilder::new();
    for n in names {
        b = b.file(f(n, 1));
    }
    run(&b).flags.contains(ReleaseFlags::MULTIVOLUME_GAP)
}

#[test]
fn multivolume_gap_detection() {
    // part style
    assert!(!gap(&["a.part1.rar", "a.part2.rar", "a.part3.rar"]));
    assert!(gap(&["a.part01.rar", "a.part03.rar"]));
    assert!(gap(&["a.part02.rar", "a.part03.rar"])); // first volume missing
    assert!(!gap(&["a.part01.rar"]));
    // old rar style: .rar is volume 0
    assert!(!gap(&["a.rar", "a.r00", "a.r01", "a.r02"]));
    assert!(gap(&["a.rar", "a.r00", "a.r02"]));
    assert!(gap(&["a.r00", "a.r01"])); // .rar missing
    assert!(!gap(&["a.rar"]));
    // zip / 7z / raw splits
    assert!(!gap(&["a.z01", "a.z02", "a.zip"]));
    assert!(gap(&["a.z01", "a.z03", "a.zip"]));
    assert!(!gap(&["a.7z.001", "a.7z.002"]));
    assert!(gap(&["a.7z.001", "a.7z.003"]));
    // independent sets do not mask each other
    assert!(gap(&[
        "a.part1.rar",
        "a.part2.rar",
        "b.part1.rar",
        "b.part3.rar"
    ]));
    assert!(!gap(&[
        "a.part1.rar",
        "a.part2.rar",
        "b.part1.rar",
        "b.part2.rar"
    ]));
    // Non-archives and obfuscated names are ignored.
    assert!(!gap(&["a.mkv", "movie.nfo"]));
}

#[test]
fn repairable_estimate_heuristic() {
    // Missing 1 segment, 2 par2 blocks -> likely repairable.
    let b = NzbBuilder::new()
        .file(f("r.part1.rar", 5).gap(2))
        .file(f("r.vol00+02.par2", 1));
    let a = run(&b);
    assert_eq!(a.repairable_estimate, Some(true));
    // Missing 3, only 2 blocks.
    let b = NzbBuilder::new()
        .file(f("r.part1.rar", 9).gap(2).gap(4).gap(6))
        .file(f("r.vol00+02.par2", 1));
    assert_eq!(run(&b).repairable_estimate, Some(false));
    // No par2 at all.
    let b = NzbBuilder::new().file(f("r.part1.rar", 3).gap(2));
    assert_eq!(run(&b).repairable_estimate, Some(false));
    // Only a nfo is incomplete: data intact.
    let b = NzbBuilder::new()
        .file(f("a.mkv", 2))
        .file(f("a.nfo", 3).gap(2));
    let a = run(&b);
    assert!(a.flags.contains(ReleaseFlags::INCOMPLETE));
    assert_eq!(a.repairable_estimate, Some(true));
}

#[test]
fn sec_004_titles_and_filenames_are_sanitized_and_truncated() {
    let long = "T".repeat(3000);
    let a = run(&NzbBuilder::new()
        .meta("title", &format!("ti\u{202E}t\u{E0041}le\0 {long}"))
        .file(f("ev\u{202E}il\u{2060}.mkv", 1)));
    assert!(a.title.len() <= TITLE_BYTES);
    assert!(a.title.starts_with("title T"));
    assert!(a.name_candidates.iter().all(|c| c.len() <= TITLE_BYTES));
    assert_eq!(a.files[0].filename.as_deref(), Some("evil.mkv"));
    let all_clean = |s: &str| {
        !s.chars()
            .any(|c| c.is_control() || "\u{202E}\u{2060}".contains(c))
    };
    assert!(all_clean(&a.title));
    assert!(a.name_candidates.iter().all(|c| all_clean(c)));
}

#[test]
fn sec_005_path_like_filenames_are_display_names_only() {
    let a = run(&NzbBuilder::new().file(f("../../etc/passwd.mkv", 1)));
    assert_eq!(a.files[0].filename.as_deref(), Some("passwd.mkv"));
    assert_eq!(a.title, "passwd");
    let a = run(&NzbBuilder::new().file(f("..\\..\\boot.ini.mkv", 1)));
    assert_eq!(a.files[0].filename.as_deref(), Some("boot.ini.mkv"));
}

#[test]
fn meta_category_is_extracted_sanitized() {
    let a = run(&NzbBuilder::new()
        .meta("Category", " movies.hd\u{202E} ")
        .file(f("a.mkv", 1)));
    assert_eq!(a.meta_category.as_deref(), Some("movies.hd"));
}

#[test]
fn sec_003_deadline_is_enforced_by_analyze() {
    let bytes = NzbBuilder::new().file(f("a.mkv", 1)).build();
    // Deadline already in the past: Timeout even for a tiny document (final check).
    assert_eq!(
        analyze(&bytes, &Limits::default(), Instant::now()),
        Err(NzbError::Timeout)
    );
    let later = Instant::now() + Duration::from_secs(30);
    assert!(analyze(&bytes, &Limits::default(), later).is_ok());
    // Injected clock past parse_deadline.
    assert_eq!(
        analyze_with_clock(&bytes, &Limits::default(), &Fake(Duration::from_secs(21))),
        Err(NzbError::Timeout)
    );
}

#[test]
fn analyze_propagates_parser_errors() {
    let r = analyze(
        b"<!DOCTYPE x><nzb/>",
        &Limits::default(),
        Instant::now() + Duration::from_secs(5),
    );
    assert_eq!(r, Err(NzbError::DoctypeForbidden));
}

#[test]
fn repairable_counts_obfuscated_and_unnamed_data() {
    // Review M1: an extension-less hash name is `Other` but still data.
    let b = NzbBuilder::new().file(
        FileSpec::new("\"abcdef0123456789abcd\" yEnc (1/100)")
            .segments(1)
            .declared(100),
    );
    let a = run(&b);
    assert!(a.flags.contains(ReleaseFlags::INCOMPLETE));
    assert_ne!(a.repairable_estimate, Some(true));
    // Unnamed subject.
    let b = NzbBuilder::new().file(FileSpec::new("whatever (1/100)").segments(1).declared(100));
    assert_ne!(run(&b).repairable_estimate, Some(true));
    // Truncated missing list of an obfuscated file.
    let b = NzbBuilder::new().file(
        FileSpec::new("\"abcdef0123456789abcd\" yEnc (1/9000)")
            .segments(2)
            .declared(9000),
    );
    assert_eq!(run(&b).repairable_estimate, Some(false));
    // Sfv/Image/Subtitle/Nzb losses do not matter.
    let b = NzbBuilder::new()
        .file(f("a.mkv", 2))
        .file(f("a.sfv", 3).gap(2))
        .file(f("a.jpg", 3).gap(2));
    assert_eq!(run(&b).repairable_estimate, Some(true));
}

#[test]
fn repairable_distrusts_par2_filenames_and_incomplete_par2() {
    // Review M2: `vol000+9999` on a single-segment par2 credits at most one block.
    let b = NzbBuilder::new()
        .file(f("a.part1.rar", 100).gap(2).gap(3).gap(4))
        .file(f("a.vol000+9999.par2", 1));
    let a = run(&b);
    assert_eq!(a.par2_blocks, 9999); // nominal, unverified
    assert_eq!(a.repairable_estimate, Some(false));
    // Single archive segment of a 100-segment set.
    let b = NzbBuilder::new()
        .file(
            FileSpec::new("\"a.part1.rar\" yEnc (1/100)")
                .segments(1)
                .declared(100),
        )
        .file(f("a.vol000+9999.par2", 1));
    assert_eq!(run(&b).repairable_estimate, Some(false));
    // A par2 file missing its own segments is not credited at all.
    let b = NzbBuilder::new()
        .file(f("a.part1.rar", 4).gap(2))
        .file(f("a.vol000+05.par2", 6).gap(3));
    assert_eq!(run(&b).repairable_estimate, Some(false));
    // Complete par2 with plausible size is credited.
    let b = NzbBuilder::new()
        .file(f("a.part1.rar", 4).gap(2))
        .file(f("a.vol000+05.par2", 6));
    assert_eq!(run(&b).repairable_estimate, Some(true));
}

#[test]
fn volume_sets_l4() {
    // `.001` needs an archive extension in front of it.
    assert!(!gap(&["video.264", "video.266"]));
    assert!(!gap(&["clip.001", "clip.003"]));
    assert!(gap(&["a.zip.001", "a.zip.003"]));
    // `.sNN` continues `.rNN`.
    assert!(!gap(&["a.rar", "a.r00", "a.r01"]));
    let mut full = vec!["a.rar".to_owned()];
    full.extend((0..100).map(|i| format!("a.r{i:02}")));
    full.push("a.s00".to_owned());
    full.push("a.s01".to_owned());
    let refs: Vec<&str> = full.iter().map(String::as_str).collect();
    assert!(!gap(&refs));
    let mut broken = refs.clone();
    broken.retain(|n| *n != "a.s00");
    assert!(gap(&broken));
    assert!(gap(&["a.rar", "a.r00", "a.s00"])); // r01..r99 missing
    // `.s01` alone never starts a set.
    assert!(!gap(&["a.s01", "a.s02", "a.mkv"]));
    // Huge volume numbers are not volumes.
    assert!(!gap(&["a.part1234567.rar"]));
    assert_eq!(volume_of("a.part1234567.rar"), None);
}

#[test]
fn l5_meta_title_keeps_quotes_and_slashes_for_downstream_escaping() {
    // Documented downstream rule: titles are display data and may contain `"`, `\`, `/`.
    let a = run(&NzbBuilder::new()
        .meta("title", "a/b\\c\"d;e")
        .file(f("a.mkv", 1)));
    assert_eq!(a.title, "a/b\\c\"d;e");
}
