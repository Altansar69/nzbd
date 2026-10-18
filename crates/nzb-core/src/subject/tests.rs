#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::enum_glob_use,
    clippy::too_many_lines
)]

use super::*;
use std::time::Instant;

fn p(s: &str) -> ParsedSubject {
    parse_subject(s, &Limits::default())
}

#[test]
fn regexes_compile() {
    assert!(QUOTED.is_some() && PAREN_COUNT.is_some() && LEAD_INDEX.is_some());
    assert!(FALLBACK_PAREN.is_some() && FALLBACK_BRACKET.is_some());
}

type Row = (
    &'static str,
    Option<&'static str>,
    Option<u32>,
    Option<(u32, u32)>,
);

#[test]
fn subject_table() {
    // (subject, filename, declared, file_index)
    let cases: &[Row] = &[
        (
            r#""movie.mkv" yEnc (1/57)"#,
            Some("movie.mkv"),
            Some(57),
            None,
        ),
        (
            r#"[01/15] - "name.part01.rar" yEnc (1/57) 123456"#,
            Some("name.part01.rar"),
            Some(57),
            Some((1, 15)),
        ),
        (
            r#"[1/1] - "a.nfo" yEnc (1/1)"#,
            Some("a.nfo"),
            Some(1),
            Some((1, 1)),
        ),
        (
            r#"My Post [03/42] - "Some Movie 2020 1080p.r02" yEnc (12/300)"#,
            Some("Some Movie 2020 1080p.r02"),
            Some(300),
            None,
        ),
        (
            r#"("file.par2") yEnc (1/1)"#,
            Some("file.par2"),
            Some(1),
            None,
        ),
        (
            r#"<kpn> "x.vol003+004.par2" yEnc (1/8) 5000"#,
            Some("x.vol003+004.par2"),
            Some(8),
            None,
        ),
        (
            r#"re: "foo bar.mp3" - "baz.mp3" yEnc (1/3)"#,
            Some("foo bar.mp3"),
            Some(3),
            None,
        ),
        (
            r#"no quote "notafile" "real.zip" yEnc (2/9)"#,
            Some("real.zip"),
            Some(9),
            None,
        ),
        (
            r#""a (1/2).rar" yEnc (1/57)"#,
            Some("2).rar"),
            Some(57),
            None,
        ),
        (
            r#""dir/sub/evil.exe" yEnc (1/2)"#,
            Some("evil.exe"),
            Some(2),
            None,
        ),
        (
            r#""..\..\windows\evil.bat" yEnc (1/2)"#,
            Some("evil.bat"),
            Some(2),
            None,
        ),
        (r#""../../etc/passwd" yEnc (1/2)"#, None, Some(2), None),
        (r#""..""#, None, None, None),
        (r#""/" yEnc (1/1)"#, None, Some(1), None),
        ("movie.mkv (1/57)", Some("movie.mkv"), Some(57), None),
        ("movie.mkv yEnc (1/57)", Some("movie.mkv"), Some(57), None),
        (
            "Some Movie 2020.mkv [1/57]",
            Some("Some Movie 2020.mkv"),
            Some(57),
            None,
        ),
        (
            "[02/10] - Some Movie.part1.rar (1/20)",
            Some("Some Movie.part1.rar"),
            Some(20),
            Some((2, 10)),
        ),
        (
            "abcdef0123456789abcdef0123456789 yEnc (1/200)",
            None,
            Some(200),
            None,
        ),
        (
            r#""abcdef0123456789abcdef0123456789" yEnc (1/200)"#,
            None,
            Some(200),
            None,
        ),
        ("", None, None, None),
        ("   ", None, None, None),
        (r#""""#, None, None, None),
        (r#"" .mkv" yEnc (1/2)"#, None, Some(2), None),
        (r#""file.verylongext123" yEnc (1/2)"#, None, Some(2), None),
        (r#""file." yEnc (1/2)"#, None, Some(2), None),
        (r#""movie.mkv" yEnc (1/0)"#, Some("movie.mkv"), None, None),
        (
            r#""movie.mkv" yEnc (1/100001)"#,
            Some("movie.mkv"),
            None,
            None,
        ),
        (
            r#""movie.mkv" yEnc (1/100000)"#,
            Some("movie.mkv"),
            Some(100_000),
            None,
        ),
        (r#""movie.mkv" yEnc (5/3)"#, Some("movie.mkv"), None, None),
        (
            r#""movie.mkv" yEnc (1/99999999999999999999)"#,
            Some("movie.mkv"),
            None,
            None,
        ),
        (
            r#"[0/5] - "a.nfo" yEnc (1/1)"#,
            Some("a.nfo"),
            Some(1),
            None,
        ),
        (
            r#"[6/5] - "a.nfo" yEnc (1/1)"#,
            Some("a.nfo"),
            Some(1),
            None,
        ),
        (
            r#"[1/10001] - "a.nfo" yEnc (1/1)"#,
            Some("a.nfo"),
            Some(1),
            None,
        ),
        (
            r#""Ünïcödé – film.mkv" yEnc (1/3)"#,
            Some("Ünïcödé – film.mkv"),
            Some(3),
            None,
        ),
        (
            r#""日本語のファイル.flac" yEnc (1/3)"#,
            Some("日本語のファイル.flac"),
            Some(3),
            None,
        ),
        (
            r#"  "spaced.srt"   yEnc   (1/1)"#,
            Some("spaced.srt"),
            Some(1),
            None,
        ),
        (
            r#""UPPER.MKV" yEnc (1/2)"#,
            Some("UPPER.MKV"),
            Some(2),
            None,
        ),
        (
            r#"[PRiVATE] [12/48] - "x.7z.001" yEnc (1/1500) 1073741824"#,
            Some("x.7z.001"),
            Some(1500),
            None,
        ),
        (
            r#""a.b.c.d.e.tar.gz" yEnc (1/4)"#,
            Some("a.b.c.d.e.tar.gz"),
            Some(4),
            None,
        ),
        (r#"yEnc "unterminated.mkv (1/4)"#, None, Some(4), None),
        (r#""one.mkv""two.mkv""#, Some("one.mkv"), None, None),
        ("just some words", None, None, None),
        ("(1/2)", None, Some(2), None),
        ("[1/2]", None, None, Some((1, 2))),
    ];
    for (subject, name, declared, idx) in cases {
        let got = p(subject);
        assert_eq!(got.filename.as_deref(), *name, "filename of {subject:?}");
        assert_eq!(got.declared_segments, *declared, "declared of {subject:?}");
        assert_eq!(got.file_index, *idx, "index of {subject:?}");
    }
}

#[test]
fn kind_table() {
    use FileKind::*;
    let cases: &[(Option<&str>, FileKind)] = &[
        (Some("a.mkv"), Video),
        (Some("A.MP4"), Video),
        (Some("a.avi"), Video),
        (Some("a.m4v"), Video),
        (Some("a.ts"), Video),
        (Some("a.wmv"), Video),
        (Some("a.mov"), Video),
        (Some("a.mpg"), Video),
        (Some("a.mpeg"), Video),
        (Some("a.mp3"), Audio),
        (Some("a.flac"), Audio),
        (Some("a.m4a"), Audio),
        (Some("a.aac"), Audio),
        (Some("a.ogg"), Audio),
        (Some("a.wav"), Audio),
        (Some("a.opus"), Audio),
        (Some("a.rar"), Archive),
        (Some("a.part01.rar"), Archive),
        (Some("a.r00"), Archive),
        (Some("a.r123"), Archive),
        (Some("a.r1"), Other),
        (Some("a.r1234"), Other),
        (Some("a.7z"), Archive),
        (Some("a.7z.001"), Archive),
        (Some("a.zip"), Archive),
        (Some("a.z01"), Archive),
        (Some("a.001"), Archive),
        (Some("a.0001"), Other),
        (Some("a.par2"), Par2),
        (Some("a.vol00+01.par2"), Par2),
        (Some("a.nfo"), Nfo),
        (Some("a.diz"), Nfo),
        (Some("a.sfv"), Sfv),
        (Some("a.srt"), Subtitle),
        (Some("a.sub"), Subtitle),
        (Some("a.idx"), Subtitle),
        (Some("a.ass"), Subtitle),
        (Some("a.jpg"), Image),
        (Some("a.jpeg"), Image),
        (Some("a.png"), Image),
        (Some("a.gif"), Image),
        (Some("a.webp"), Image),
        (Some("a.nzb"), Nzb),
        (Some("a.exe"), Executable),
        (Some("a.scr"), Executable),
        (Some("a.bat"), Executable),
        (Some("a.cmd"), Executable),
        (Some("a.com"), Executable),
        (Some("a.msi"), Executable),
        (Some("a.ps1"), Executable),
        (Some("a.vbs"), Executable),
        (Some("a.js"), Executable),
        (Some("a.jar"), Executable),
        (Some("a.lnk"), Executable),
        (Some("a.mkv.exe"), Executable),
        (Some("a.exe.txt"), Other),
        (Some("a.txt"), Other),
        (Some("noext"), Other),
        (Some(".bashrc"), Other),
        (Some(""), Other),
        (Some("a."), Other),
        (None, Other),
    ];
    for (name, kind) in cases {
        assert_eq!(classify_kind(*name), *kind, "{name:?}");
    }
}

#[test]
fn par2_block_table() {
    let cases: &[(&str, Option<u32>)] = &[
        ("a.vol00+01.par2", Some(1)),
        ("a.vol031+032.par2", Some(32)),
        ("A.VOL01+02.PAR2", Some(2)),
        ("vol0+5.par2", Some(5)),
        ("a.par2", None),
        ("a.vol00+.par2", None),
        ("a.volxx+01.par2", None),
        ("avol00+01.par2", None),
        ("a.vol00+99999999999999.par2", None),
        ("a.vol00+01.rar", None),
    ];
    for (n, b) in cases {
        assert_eq!(par2_blocks(n), *b, "{n}");
    }
}

#[test]
fn obfuscation_table() {
    assert!(looks_obfuscated(None));
    assert!(looks_obfuscated(Some("abcdef0123456789")));
    assert!(looks_obfuscated(Some("a-b_c-d_e-f_g-h_i-j")));
    assert!(!looks_obfuscated(Some("abcdef012345678")));
    assert!(!looks_obfuscated(Some("abcdef0123456789.mkv")));
    assert!(!looks_obfuscated(Some("Movie Name With Spaces Here")));
    assert!(!looks_obfuscated(Some("ünïcödéünïcödéünïcödé")));
}

#[test]
fn sec_005_subject_never_yields_path() {
    for s in [
        r#""../../x" yEnc (1/1)"#,
        r#""/etc/passwd" yEnc (1/1)"#,
        r#""..\..\x.exe" yEnc (1/1)"#,
        r#""a/../../b.mkv" yEnc (1/1)"#,
        r#""C:\Windows\x.dll" yEnc (1/1)"#,
        "../../etc/passwd.txt (1/2)",
    ] {
        if let Some(f) = p(s).filename {
            assert!(
                !f.contains('/') && !f.contains('\\') && f != ".." && f != ".",
                "{s}: {f}"
            );
        }
    }
}

#[test]
fn sec_037_subject_regexes_are_linear() {
    let l = Limits::default();
    let big = 2_048usize;
    let inputs = [
        "\"".repeat(big),
        "(".repeat(big),
        "[1/".repeat(big / 3),
        format!("\"{}\"", "a.".repeat(big / 2)),
        format!("{} (1/2", "a".repeat(big)),
        format!("{}.mkv", " ".repeat(big)),
        "[1/2] - ".repeat(big / 8),
        "(1/2)".repeat(big / 5),
        "é".repeat(big),
        "a. ".repeat(big / 3),
    ];
    let huge = "a. (1/".repeat(2_000_000);
    // Best of three rounds (load only adds time) against a very generous ceiling.
    let best = (0..3)
        .map(|_| {
            let start = Instant::now();
            for i in &inputs {
                let _ = parse_subject(i, &l);
            }
            // A 12 MB input is capped before matching.
            let _ = parse_subject(&huge, &l);
            start.elapsed()
        })
        .min()
        .unwrap_or(std::time::Duration::MAX);
    assert!(best.as_secs() < 60, "took {best:?}");
}

#[test]
fn oversized_subject_is_capped_on_char_boundary() {
    let l = Limits {
        max_subject_bytes: 5,
        ..Limits::default()
    };
    // "é" is 2 bytes; the cap lands mid-char and must not panic.
    let _ = parse_subject("éééé\"a.mkv\"", &l);
    assert_eq!(cap("ééé", 3), "é");
    assert_eq!(parse_subject(r#""a.mkv" yEnc (1/2)"#, &l).filename, None);
}

#[test]
fn counter_must_belong_to_the_yenc_part_of_the_subject() {
    // Review L1: `(n/m)` inside a name is not a segment counter.
    assert_eq!(p("Movie (1/2).mkv").declared_segments, None);
    assert_eq!(p(r#""Movie (1/2).mkv" yEnc"#).declared_segments, None);
    assert_eq!(
        p(r#""Movie (1/2).mkv" yEnc (1/57)"#).declared_segments,
        Some(57)
    );
    // The PARSER_SPEC fallback forms still declare the total.
    assert_eq!(p("name.ext (1/57)").declared_segments, Some(57));
    assert_eq!(p("name.ext [1/57]").declared_segments, Some(57));
    // Obfuscated subjects: a counter at the end (optionally followed by a size) counts.
    assert_eq!(p("abc123def yEnc (1/40) 1234").declared_segments, Some(40));
    assert_eq!(p("abc (1/40) xyz").declared_segments, None);
    assert_eq!(p("name.ext (0/57)").declared_segments, None);
    assert_eq!(p("name.ext (58/57)").declared_segments, None);
}
