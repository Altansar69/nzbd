#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::too_many_lines)]

use std::time::{Duration, Instant};

use proptest::prelude::*;

use super::*;

fn rules() -> SceneRules {
    SceneRules::builtin().unwrap().with_max_year(2027)
}

fn p(name: &str) -> SceneInfo {
    parse_scene(name, &rules())
}

fn cat(name: &str) -> Option<u16> {
    p(name).category
}

#[track_caller]
fn assert_cat(name: &str, family: Family, category: u16) {
    let i = p(name);
    assert_eq!(
        (i.family, i.category),
        (family, Some(category)),
        "name: {name}"
    );
}

#[track_caller]
fn assert_inconclusive(name: &str) {
    let mut i = p(name);
    // The group alone is display data and may survive an inconclusive parse.
    i.release_group = None;
    assert_eq!(
        i,
        SceneInfo::default(),
        "name should be inconclusive: {name}"
    );
}

// ---- rules loading ------------------------------------------------------------------------

#[test]
fn builtin_rules_load() {
    SceneRules::builtin().unwrap();
}

#[test]
fn rules_reject_bad_input() {
    let good = include_str!("../../../../config/scene_rules.toml");
    // Unknown enum value.
    let bad = good.replace("\"cam\" = \"CAM\"", "\"cam\" = \"NOPE\"");
    assert!(matches!(
        SceneRules::from_toml_str(&bad),
        Err(SceneRulesError::Syntax(_))
    ));
    // Non-lowercase phrase.
    let bad = good.replace("\"hdtv\" = \"HDTV\"", "\"HDTV\" = \"HDTV\"");
    assert!(matches!(
        SceneRules::from_toml_str(&bad),
        Err(SceneRulesError::Invalid(_))
    ));
    // Four-word phrase.
    let bad = good.replace("\"hdtv\" = \"HDTV\"", "\"a b c d\" = \"HDTV\"");
    assert!(matches!(
        SceneRules::from_toml_str(&bad),
        Err(SceneRulesError::Invalid(_))
    ));
    // Unknown flag name.
    let bad = good.replace("\"proper\" = \"PROPER\"", "\"proper\" = \"WHATEVER\"");
    assert!(matches!(
        SceneRules::from_toml_str(&bad),
        Err(SceneRulesError::Invalid(_))
    ));
    // Duplicate key (rejected by the TOML parser).
    let bad = good.replace("[sources]", "[sources]\n\"cam\" = \"CAM\"");
    assert!(SceneRules::from_toml_str(&bad).is_err());
    // Unknown top-level table.
    assert!(SceneRules::from_toml_str(&format!("{good}\n[surprise]\nx = 1\n")).is_err());
    assert!(SceneRules::from_toml_str("").is_err());
}

// ---- rule 1: music --------------------------------------------------------------------------

#[test]
fn music_positive_lossless_lossy_audiobook() {
    let i = p("VA-Summer_Night_Grooves-(CAT123)-2CD-FLAC-2019-GRP");
    assert_eq!(i.family, Family::Music);
    assert_eq!(i.category, Some(3040));
    assert_eq!(i.artist.as_deref(), Some("VA"));
    assert_eq!(i.album.as_deref(), Some("Summer Night Grooves"));
    assert_eq!(i.medium.as_deref(), Some("2CD"));
    assert_eq!(i.catalog.as_deref(), Some("CAT123"));
    assert_eq!(i.year, Some(2019));
    assert!(i.lossless);
    assert_eq!(i.release_group.as_deref(), Some("GRP"));
    assert!(i.music_markers.contains(&"VA".to_owned()));

    assert_cat("Some_Band-Blue_Hours_EP-WEB-2021-ABC", Family::Music, 3000);
    assert_cat(
        "Some_Band-Blue_Hours-WEB-MP3-320-2021-ABC",
        Family::Music,
        3010,
    );
    assert_cat("Some_Band-Blue_Hours-CD-FLAC-1999-ABC", Family::Music, 3040);
    assert_cat("Some_Band-Blue_Hours-SACD-2003-ABC", Family::Music, 3040);
    assert_cat(
        "Jane_Roe-Long_Story-AUDIOBOOK-2015-ABC",
        Family::Music,
        3030,
    );
    assert_cat("Jane_Roe-Long_Story-ABOOK-2015-ABC", Family::Music, 3030);
    let ab = p("Jane_Roe-Long_Story-2015-ABC.m4b");
    assert_eq!((ab.family, ab.category), (Family::Music, Some(3030)));
}

#[test]
fn music_negative_each_requirement() {
    // Missing medium, year, group, parts; year out of range; video evidence.
    assert_inconclusive("Some_Band-Blue_Hours-2021-ABC");
    assert_inconclusive("Some_Band-Blue_Hours-CD-FLAC-ABC");
    assert_inconclusive("Some_Band-Blue_Hours-CD-FLAC-2021");
    assert_inconclusive("Some_Band-Blue_Hours-CD-FLAC-1949-ABC");
    assert_inconclusive("Some_Band-Blue_Hours-CD-FLAC-2099-ABC");
    assert_inconclusive("Some_Band-CD");
    assert_inconclusive("Some_Band-Blue_Hours-720p-WEB-2021-ABC");
    assert_ne!(p("Some_Show-S01E01-CD-2021-ABC").family, Family::Music);
}

// ---- rule 2: anime --------------------------------------------------------------------------

#[test]
fn anime_fansub_pattern() {
    let i = p("[SubGroup] Cool Show - 05v2 [1080p] [ABCD1234].mkv");
    assert_eq!(i.family, Family::Anime);
    assert_eq!(i.category, Some(5070));
    assert_eq!(i.title.as_deref(), Some("Cool Show"));
    assert_eq!(i.episodes, vec![5]);
    assert_eq!(i.release_group.as_deref(), Some("SubGroup"));
    assert_eq!(i.resolution, Resolution::R1080p);
    assert_cat("[Grp]_Cool_Show_-_12_(720p)", Family::Anime, 5070);
    assert_cat("[Grp] Cool Show - 1234", Family::Anime, 5070);
}

#[test]
fn anime_fansub_negative() {
    // Year-like number, text after the number, no bracketed group, group too short.
    assert_inconclusive("[Publisher] Some Book - 2019");
    assert_inconclusive("[Grp] Cool Show - 05 END");
    assert_inconclusive("Cool Show - 05 [1080p]");
    assert_inconclusive("[G] Cool Show - 05");
    assert_inconclusive("[Grp] Cool Show - 12345");
}

#[test]
fn anime_crc_token_and_markers() {
    assert_cat("Cool.Show.[1A2B3C4D]", Family::Anime, 5070);
    assert_cat(
        "Cool.Show.S01E02.Dual.Audio.1080p.BluRay.x265-GRP",
        Family::Anime,
        5070,
    );
    assert_cat("Cool.Show.OVA.E03.720p", Family::Anime, 5070);
    assert_cat("Cool.Show.Batch.S01.1080p.BD-Rip-GRP", Family::Anime, 5070);
    assert_cat(
        "Cool.Show.ANiME.Complete.Series.1080p-GRP",
        Family::Anime,
        5070,
    );
    let i = p("Cool.Show.Anime.Episode.07.720p.WEB-DL-GRP");
    assert_eq!(i.family, Family::Anime);
    assert_eq!(i.episodes, vec![7]);
    // Anime wins over TV for S01E02.
    assert_eq!(
        p("Cool.Show.ONA.S01E02.1080p.WEB-DL-GRP").family,
        Family::Anime
    );
}

#[test]
fn anime_negative() {
    // Marker without episode evidence, crc-looking digit-only token, DUBBED TV is not anime.
    assert_inconclusive("The.Anime.Collection");
    assert_inconclusive("Cool.Show.[12345678]");
    assert_inconclusive("Cool.Show.[ABCDEFAB]");
    assert_cat(
        "Some.Show.S01E02.GERMAN.DUBBED.720p.HDTV.x264-GRP",
        Family::Tv,
        5040,
    );
    assert_inconclusive("Cool.Show.Batch");
}

// ---- rule 3: TV -----------------------------------------------------------------------------

#[test]
fn tv_episode_shapes() {
    let i = p("The.Great.Show.S02E05.1080p.WEB-DL.DD5.1.H.264-GRP");
    assert_eq!(i.family, Family::Tv);
    assert_eq!(i.category, Some(5040));
    assert_eq!(i.title.as_deref(), Some("The Great Show"));
    assert_eq!((i.season, i.episodes.clone()), (Some(2), vec![5]));
    assert_eq!(i.source, Source::WEBDL);
    assert_eq!(i.audio.as_deref(), Some("DD5.1"));
    assert_eq!(i.video_codec.as_deref(), Some("h264"));
    assert_eq!(i.release_group.as_deref(), Some("GRP"));

    let multi = p("The.Great.Show.S02E05E06E07.HDTV.x264-GRP");
    assert_eq!(multi.episodes, vec![5, 6, 7]);
    assert_eq!(multi.category, Some(5030));

    let range = p("The.Great.Show.S02E05-E08.720p.HDTV.x264-GRP");
    assert_eq!(range.episode_range, Some((5, 8)));
    let range2 = p("The.Great.Show.S02E05-08.720p.HDTV.x264-GRP");
    assert_eq!(range2.episode_range, Some((5, 8)));
    // A "range" that goes backwards is not a range.
    assert_eq!(p("The.Great.Show.S02E05-E03.720p-GRP").episode_range, None);

    let split = p("The.Great.Show.S02.E05.720p-GRP");
    assert_eq!(split.episodes, vec![5]);

    let x = p("The.Great.Show.2x05.HDTV-GRP");
    assert_eq!(
        (x.family, x.season, x.episodes),
        (Family::Tv, Some(2), vec![5])
    );
}

#[test]
fn tv_episode_negative() {
    // NxNN needs a quality token; S01E02 with no title is inconclusive; resolution-like 1920x1080.
    assert_inconclusive("The.Great.Show.2x05");
    assert_inconclusive("S01E02.720p.HDTV-GRP");
    assert_inconclusive("The.Great.Show.S1000E01");
    assert_inconclusive("Photo.1920x1080.Wallpapers");
    assert_inconclusive("The.Great.Show.S01E02X.garbage");
}

#[test]
fn tv_year_and_title() {
    let i = p("Doctor.Strange.2005.S01E01.720p.HDTV.x264-GRP");
    assert_eq!(i.title.as_deref(), Some("Doctor Strange"));
    assert_eq!(i.year, Some(2005));
    // A lone token before the marker that looks like a year stays in the title.
    let i = p("2019.S01E01.720p.HDTV.x264-GRP");
    assert_eq!((i.title.as_deref(), i.year), (Some("2019"), None));
}

#[test]
fn tv_daily_and_dates() {
    let i = p("Late.Talk.2019.10.21.Some.Guest.720p.HDTV.x264-GRP");
    assert_eq!(i.family, Family::Tv);
    assert_eq!(i.air_date.as_deref(), Some("2019-10-21"));
    assert_eq!(i.title.as_deref(), Some("Late Talk"));
    assert_eq!(
        p("Late.Talk.21.10.2019.720p.HDTV.x264-GRP")
            .air_date
            .as_deref(),
        Some("2019-10-21")
    );
    assert_eq!(
        p("Late.Talk.10-21-2019.720p.HDTV.x264-GRP")
            .air_date
            .as_deref(),
        Some("2019-10-21")
    );
    // Needs a quality token; month 13 is not a date.
    assert_inconclusive("Late.Talk.2019.10.21");
    assert!(p("Late.Talk.2019.13.21.720p.HDTV").air_date.is_none());
}

#[test]
fn tv_season_packs() {
    let i = p("The.Great.Show.S03.1080p.BluRay.x264-GRP");
    assert_eq!(
        (i.family, i.season, i.season_pack),
        (Family::Tv, Some(3), true)
    );
    let i = p("The.Great.Show.Season.3.720p.HDTV-GRP");
    assert_eq!((i.season, i.season_pack), (Some(3), true));
    let i = p("The.Great.Show.COMPLETE.SERIES.720p.BluRay.x264-GRP");
    assert!(i.season_pack && i.family == Family::Tv && i.season.is_none());
    assert!(i.flags.contains(SceneFlags::COMPLETE));
    // Packs need a quality token; S1-like substrings elsewhere do not count.
    assert_inconclusive("The.Great.Show.S03");
    assert_inconclusive("Phone.S1.Review");
    assert_inconclusive("The.Great.Show.Season.3");
    assert_inconclusive("The.Great.Show.Complete.Series");
}

#[test]
fn tv_resolution_mapping() {
    assert_cat("Show.Name.S01E01.2160p.WEB-DL.x265-GRP", Family::Tv, 5045);
    assert_cat("Show.Name.S01E01.UHD.WEB-DL-GRP", Family::Tv, 5045);
    assert_cat("Show.Name.S01E01.1080i.HDTV-GRP", Family::Tv, 5040);
    assert_cat("Show.Name.S01E01.720p.HDTV.x264-GRP", Family::Tv, 5040);
    assert_cat("Show.Name.S01E01.480p.DVDRip.XviD-GRP", Family::Tv, 5030);
    assert_cat("Show.Name.S01E01.PDTV.XviD-GRP", Family::Tv, 5030);
    assert_cat("Show.Name.S01E01-GRP", Family::Tv, 5000);
    assert_cat("Show.Name.S01E01", Family::Tv, 5000);
}

#[test]
fn tv_sport_and_documentary() {
    let i = p("UFC.250.2020.05.09.PPV.720p.HDTV.x264-GRP");
    assert_eq!((i.family, i.category), (Family::Tv, Some(5060)));
    assert_eq!(i.air_date.as_deref(), Some("2020-05-09"));
    assert_cat(
        "Formula1.2019.Round05.Monaco.Race.1080p.WEB-DL-GRP",
        Family::Tv,
        5060,
    );
    assert_cat(
        "Premier.League.2020.01.11.Arsenal.vs.Spurs.720p.HDTV-GRP",
        Family::Tv,
        5060,
    );
    // Sport token without a date/round, or without quality, is not sport.
    assert_ne!(cat("UFC.Fight.Night.720p.HDTV.x264-GRP"), Some(5060));
    assert_ne!(cat("UFC.250.2020.05.09.PPV"), Some(5060));

    assert_cat(
        "Wild.Planet.S01E03.DOCUMENTARY.720p.HDTV-GRP",
        Family::Tv,
        5080,
    );
    assert_cat("Wild.Planet.S01.DOCU.1080p.WEB-DL-GRP", Family::Tv, 5080);
    // Documentary token without TV evidence does not make a TV release.
    assert_ne!(
        p("Wild.Planet.DOCUMENTARY.720p.HDTV-GRP").family,
        Family::Tv
    );
}

// ---- rule 4: movies --------------------------------------------------------------------------

#[test]
fn movie_basic_and_conclusiveness() {
    let i = p("A.Fine.Movie.2018.1080p.BluRay.x264-GRP");
    assert_eq!(i.family, Family::Movie);
    assert_eq!(i.category, Some(2040));
    assert_eq!(i.title.as_deref(), Some("A Fine Movie"));
    assert_eq!(i.year, Some(2018));

    // Group or >= 2 token kinds required.
    assert_cat("A.Fine.Movie.2018.1080p.BluRay", Family::Movie, 2040);
    assert_cat("A.Fine.Movie.2018.1080p-GRP", Family::Movie, 2040);
    assert_inconclusive("A.Fine.Movie.2018.1080p");
    assert_inconclusive("A.Fine.Movie.2018-GRP");
    assert_inconclusive("A.Fine.Movie.1080p.BluRay-GRP");
    assert_inconclusive("A.Fine.Movie.2018.GERMAN-GRP");
    // Year out of range / future.
    assert_inconclusive("A.Fine.Movie.1899.1080p.BluRay-GRP");
    assert_inconclusive("A.Fine.Movie.2099.1080p.BluRay-GRP");
}

#[test]
fn movie_year_selection() {
    // Title that contains a year-like number: the later year wins.
    let i = p("Blade.Runner.2049.2017.1080p.BluRay.x264-GRP");
    assert_eq!(
        (i.year, i.title.as_deref()),
        (Some(2017), Some("Blade Runner 2049"))
    );
    // A year at position 0 only counts when it is the whole title.
    let i = p("1917.2019.1080p.BluRay.x264-GRP");
    assert_eq!((i.year, i.title.as_deref()), (Some(2019), Some("1917")));
    let i = p("2012.1080p.BluRay.x264-GRP");
    assert_eq!((i.year, i.title.as_deref()), (Some(2012), Some("2012")));
    assert_inconclusive("2012.Some.Title.1080p.BluRay.x264-GRP");
}

#[test]
fn movie_categories() {
    assert_cat("M.2018.2160p.UHD.BluRay.x265-GRP", Family::Movie, 2045);
    assert_cat(
        "M.2018.2160p.WEB-DL.DDP5.1.HDR.x265-GRP",
        Family::Movie,
        2045,
    );
    assert_cat("M.2018.UHD.BluRay.REMUX-GRP", Family::Movie, 2045);
    assert_cat("M.2018.720p.WEBRip.x264-GRP", Family::Movie, 2040);
    assert_cat("M.2018.1080p.BluRay.REMUX.AVC-GRP", Family::Movie, 2040);
    assert_cat("M.2018.DVDRip.XviD-GRP", Family::Movie, 2030);
    assert_cat("M.2018.HDCAM.x264-GRP", Family::Movie, 2030);
    assert_cat("M.2018.TELESYNC.XviD-GRP", Family::Movie, 2030);
    assert_cat("M.2018.480p.BDRip.x264-GRP", Family::Movie, 2030);
    assert_cat("M.2018.BluRay.x264-GRP", Family::Movie, 2000);
    assert_cat("M.2018.x264-GRP", Family::Movie, 2000);
    assert_cat("M.2018.1080p.3D.HSBS.BluRay.x264-GRP", Family::Movie, 2060);
    assert_cat("M.2018.COMPLETE.BLURAY-GRP", Family::Movie, 2050);
    assert_cat("M.2018.COMPLETE.UHD.BLURAY-GRP", Family::Movie, 2050);
    assert_cat("M.2018.BD50-GRP", Family::Movie, 2050);
    assert_cat("M.2018.DVDR-GRP", Family::Movie, 2070);
    assert_cat("M.2018.NTSC.DVD9-GRP", Family::Movie, 2070);
    assert_cat("M.2018.COMPLETE.PAL.DVD-GRP", Family::Movie, 2070);
    assert_cat("M.2018.BluRay.x264-GRP.iso", Family::Movie, 2050);
    assert_cat("M.2018.NTSC.DVD-GRP", Family::Movie, 2030);
    assert_eq!(p("M.2018.1080p.3D.BluRay-GRP").source, Source::BluRay);
    assert!(
        p("M.2018.1080p.3D.BluRay-GRP")
            .flags
            .contains(SceneFlags::THREE_D)
    );
}

#[test]
fn movie_blocked_by_tv_or_anime_markers() {
    assert_eq!(p("M.2018.S01E01.1080p.BluRay.x264-GRP").family, Family::Tv);
    assert_eq!(
        p("M.2018.Season.1.1080p.BluRay.x264-GRP").family,
        Family::Tv
    );
    assert_eq!(
        p("M.2018.ONA.S01E01.1080p.BluRay.x264-GRP").family,
        Family::Anime
    );
}

// ---- attributes -------------------------------------------------------------------------------

#[test]
fn flags_languages_group() {
    let i =
        p("M.2018.PROPER.REPACK.EXTENDED.UNRATED.MULTi.TRUEFRENCH.1080p.BluRay.x264.INTERNAL-GRP");
    for f in [
        SceneFlags::PROPER,
        SceneFlags::REPACK,
        SceneFlags::EXTENDED,
        SceneFlags::UNRATED,
    ] {
        assert!(i.flags.contains(f), "{f:?}");
    }
    assert!(i.flags.contains(SceneFlags::INTERNAL));
    assert_eq!(i.languages, vec!["MULTi", "French"]);
    assert_eq!(i.release_group.as_deref(), Some("GRP"));

    let i = p("M.2018.1080p.BluRay.x264-GRP.iNTERNAL");
    assert!(i.flags.contains(SceneFlags::INTERNAL));
    assert_eq!(i.release_group.as_deref(), Some("GRP"));

    // Dashes inside known phrases are not group separators.
    let i = p("M.2018.1080p.WEB-DL");
    assert_eq!((i.source, i.release_group), (Source::WEBDL, None));
    assert_eq!(p("M.2018.1080p.Blu-ray.x264").source, Source::BluRay);
    // Words in the title are not languages or flags.
    let i = p("The.Real.French.Connection.2018.1080p.BluRay.x264-GRP");
    assert!(i.languages.is_empty() && i.flags.is_empty());
    assert_eq!(i.title.as_deref(), Some("The Real French Connection"));
    // HDR and audio.
    let i = p("M.2018.2160p.UHD.BluRay.DV.HDR10.TrueHD.Atmos.x265-GRP");
    assert_eq!(i.hdr, vec!["DV", "HDR10"]);
    assert_eq!(i.audio.as_deref(), Some("TrueHD"));
}

#[test]
fn extensions_and_wrappers_are_stripped() {
    assert_eq!(p("M.2018.1080p.BluRay.x264-GRP.nzb").category, Some(2040));
    assert_eq!(
        p("M.2018.1080p.BluRay.x264-GRP.part01.rar").category,
        Some(2040)
    );
    assert_eq!(p("M.2018.1080p.BluRay.x264-GRP.mkv").category, Some(2040));
    assert_eq!(
        p("[ www.spam.example ] M.2018.1080p.BluRay.x264-GRP").category,
        Some(2040)
    );
    assert_eq!(p("(M 2018 1080p BluRay x264)-GRP").category, Some(2040));
}

#[test]
fn scene_info_json_roundtrip_and_columns() {
    let i = p("The.Great.Show.S02E05.PROPER.1080p.WEB-DL.DD5.1.H.264-GRP");
    let json = serde_json::to_string(&i).unwrap();
    assert!(json.contains("\"PROPER\""));
    let back: SceneInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(back, i);
    assert_eq!(i.family.as_str(), Some("tv"));
    assert_eq!(i.resolution.as_str(), Some("1080p"));
    assert_eq!(i.source.as_str(), Some("WEBDL"));
    assert_eq!(Family::Unknown.as_str(), None);
    assert!(serde_json::from_str::<SceneInfo>(&json.replace("PROPER", "NOPE")).is_err());
}

// ---- SEC-037 --------------------------------------------------------------------------------------

#[test]
fn sec_037_hostile_inputs_are_inconclusive() {
    for s in [
        "",
        " ",
        "-",
        "---",
        "[]",
        "[[[[[[",
        "....",
        "\0\0\0",
        "\u{202E}S01E02\u{202D}",
        "𝔘𝔫𝔦𝔠𝔬𝔡𝔢",
    ] {
        let i = p(s);
        assert!(i.category.is_none() || i.is_conclusive(), "{s:?}");
    }
    assert_inconclusive("");
    assert_inconclusive("---");
    assert_inconclusive("[[[[[[");
}

#[test]
fn sec_037_input_capped_at_512_bytes_and_truncated_not_rejected() {
    let head = "The.Great.Show.S02E05.1080p.WEB-DL.x264-GRP";
    let long = format!("{head}{}", "X".repeat(10_000));
    // The tail is cut away: the result equals parsing the 512-byte prefix.
    let cut = &long[..MAX_SCENE_NAME_BYTES];
    assert_eq!(p(&long), p(cut));
    assert_eq!(p(&long).family, Family::Tv);
    // Marker beyond the cap is never seen.
    let late = format!("{}.S02E05.1080p", "a".repeat(600));
    assert_eq!(p(&late).family, Family::Unknown);
    // Multi-byte characters at the cut do not panic.
    let wide = "é".repeat(2000);
    let _ = p(&wide);
}

#[test]
fn sec_037_linear_time_on_pathological_10kb_names() {
    let rules = rules();
    let unit_sets: [&str; 12] = [
        "S01E01",
        "S1",
        "[ABCD1234]",
        "-",
        ".",
        "- 99 ",
        "2019.",
        "1x01.",
        "web.dl.",
        "19-",
        "[a]",
        "E01-E02-",
    ];
    let mut worst = Duration::ZERO;
    for unit in unit_sets {
        let name = unit.repeat(10_240 / unit.len() + 1);
        let name = &name[..10_240];
        // Best of three rounds per unit set: host load only adds time.
        let best = (0..3)
            .map(|_| {
                let t = Instant::now();
                for _ in 0..20 {
                    let _ = parse_scene(name, &rules);
                }
                t.elapsed()
            })
            .min()
            .unwrap_or(Duration::MAX);
        worst = worst.max(best);
    }
    // 20 parses of a 10 KB name must be far below any quadratic blow-up. Very generous ceiling
    // (unloaded this takes tens of milliseconds); the intent is only to catch a runaway.
    assert!(worst < Duration::from_secs(30), "worst {worst:?}");
}

#[test]
fn sec_037_cost_does_not_grow_with_input_size() {
    // Input is capped, so 10 KB and 1 MB hostile names cost the same order of magnitude.
    let rules = rules();
    let unit = "S01E01.2019.1x01.[ABCD1234].- 01 ";
    let small = unit.repeat(10_240 / unit.len());
    let big = unit.repeat(1_048_576 / unit.len());
    let time = |s: &str| {
        let t = Instant::now();
        for _ in 0..10 {
            let _ = parse_scene(s, &rules);
        }
        t.elapsed()
    };
    // Interleaved min-of-5 sampling so both sizes see the same load; the base is floored at
    // 20 ms so a tiny (or load-skewed) `a` cannot make the ratio meaningless. A missing input
    // cap would make `b` ~100x `a` and hundreds of ms or more, far above `floor * 20 + 500 ms`.
    let (mut a, mut b) = (Duration::MAX, Duration::MAX);
    for _ in 0..5 {
        a = a.min(time(&small));
        b = b.min(time(&big));
    }
    let base = a.max(Duration::from_millis(20));
    assert!(
        b < base * 20 + Duration::from_millis(500),
        "small {a:?} vs big {b:?}"
    );
}

#[test]
fn sec_037_category_is_taxonomy_id() {
    const ALLOWED: [u16; 17] = [
        2000, 2030, 2040, 2045, 2050, 2060, 2070, 3000, 3010, 3030, 3040, 5000, 5030, 5040, 5045,
        5060, 5070,
    ];
    for n in [
        "M.2018.1080p.BluRay.x264-GRP",
        "Show.S01E01.720p.HDTV-GRP",
        "[G] Show - 01",
        "A-B-CD-2020-GRP",
    ] {
        if let Some(c) = p(n).category {
            assert!(ALLOWED.contains(&c) || c == 5080, "{n} -> {c}");
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn sec_037_never_panics_arbitrary(s in ".{0,1200}") {
        let i = p(&s);
        prop_assert_eq!(i.category.is_some(), i.is_conclusive());
        if !i.is_conclusive() {
            // An inconclusive name keeps at most its trailing `-GROUP`; everything else stays empty.
            let group = i.release_group.clone();
            prop_assert_eq!(i, SceneInfo { release_group: group, ..SceneInfo::default() });
        }
    }

    #[test]
    fn sec_037_never_panics_scene_alphabet(s in "[A-Za-z0-9.\\-_\\[\\]() ]{0,1200}") {
        let _ = p(&s);
    }

    #[test]
    fn sec_037_never_panics_tokens(parts in proptest::collection::vec(
        prop::sample::select(vec![
            "S01E02", "S01", "E05", "2019", "1080p", "WEB", "DL", "BluRay", "x264", "-", ".", "_",
            "[ABCD1234]", "CD", "FLAC", "UFC", "3D", "Season", "1", "10", "21", "COMPLETE", "-GRP",
            "iNTERNAL", "VA", "\u{202E}", "é",
        ]), 0..120)) {
        let s: String = parts.concat();
        let i = p(&s);
        prop_assert!(i.episodes.len() <= 64);
        prop_assert!(i.title.as_ref().is_none_or(|t| t.len() <= MAX_SCENE_NAME_BYTES));
    }

    #[test]
    fn sec_037_prefix_cap_is_equivalent(s in "[A-Za-z0-9.\\-_]{513,1500}") {
        let cut: String = s.chars().take(MAX_SCENE_NAME_BYTES).collect();
        prop_assert_eq!(p(&s), p(&cut));
    }
}

#[test]
fn sec_037_quality_scan_is_not_quadratic_on_dense_names() {
    let rules = rules();
    // 512 bytes of nothing but quality tokens and markers: worst case for tokens x hits scans.
    let dense = "S01.1080p.x264.WEB.2019.".repeat(30);
    let best = (0..3)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..200 {
                let _ = parse_scene(&dense, &rules);
            }
            t.elapsed()
        })
        .min()
        .unwrap_or(Duration::MAX);
    assert!(best < Duration::from_secs(30), "{best:?}");
}

#[test]
fn sec_037_wide_episode_ranges_are_dropped() {
    assert_eq!(p("Show.S01E01-E9999.720p.HDTV-GRP").episode_range, None);
    assert_eq!(p("Show.S01E01-E1002.720p.HDTV-GRP").episode_range, None);
    assert_eq!(
        p("Show.S01E01-E1001.720p.HDTV-GRP").episode_range,
        Some((1, 1001))
    );
    assert_eq!(p("Show.S01E01-E9999.720p.HDTV-GRP").episodes, vec![1]);
}

#[test]
fn air_dates_are_calendar_valid() {
    let d = |n: &str| p(n).air_date;
    assert_eq!(d("Show.2019.02.31.720p.HDTV-GRP"), None);
    assert_eq!(d("Show.2019.02.29.720p.HDTV-GRP"), None);
    assert_eq!(
        d("Show.2020.02.29.720p.HDTV-GRP").as_deref(),
        Some("2020-02-29")
    );
    assert_eq!(d("Show.1900.02.29.720p.HDTV-GRP"), None);
    assert_eq!(
        d("Show.2000.02.29.720p.HDTV-GRP").as_deref(),
        Some("2000-02-29")
    );
    assert_eq!(d("Show.2019.04.31.720p.HDTV-GRP"), None);
    assert_eq!(
        d("Show.2019.04.30.720p.HDTV-GRP").as_deref(),
        Some("2019-04-30")
    );
}

#[test]
fn rules_labels_reject_format_characters() {
    let good = include_str!("../../../../config/scene_rules.toml");
    for bad in [r"h\u202E264", r"h\u200B264", r"h\u0000264", "h  264"] {
        let src = good.replace("\"h264\" = \"h264\"", &format!("\"h264\" = \"{bad}\""));
        assert!(
            matches!(
                SceneRules::from_toml_str(&src),
                Err(SceneRulesError::Invalid(_))
            ),
            "{bad:?}"
        );
    }
}

#[test]
fn rules_loader_caps_size_and_error_text() {
    let huge = format!("x = \"{}\"", "a".repeat(300 * 1024));
    assert!(matches!(
        SceneRules::from_toml_str(&huge),
        Err(SceneRulesError::Invalid(_))
    ));
    // 100 KB single line: under the size cap, syntax error text must stay short.
    let line = format!("max_year = {}", "9".repeat(100 * 1024));
    match SceneRules::from_toml_str(&line) {
        Err(SceneRulesError::Syntax(m)) => assert!(m.chars().count() <= 300, "{}", m.len()),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn sec_scene_inverted_episode_range_does_not_overflow() {
    for name in [
        "Show.S01E05E03-04.720p.HDTV.x264-GRP",
        "Show.S01E10E02-05.720p.HDTV.x264-GRP",
        "Show.S01E09E01-02.720p.HDTV.x264-GRP",
        "Show.S01E05E01-03.720p.HDTV.x264-GRP",
        "Show.S01E05E05-05.720p.HDTV.x264-GRP",
        "Show.S01E4294967295E1-2.720p.HDTV.x264-GRP",
        "Show.S01E99999999999999999999E1-2.720p.HDTV.x264-GRP",
        "Show.S01E01E02-99999999999999999999.720p.HDTV.x264-GRP",
    ] {
        let i = p(name);
        assert_eq!(i.episode_range, None, "{name}");
    }
    assert_eq!(
        p("Show.S01E01E02-04.720p.HDTV.x264-GRP").episode_range,
        Some((1, 4))
    );
}

#[test]
fn group_is_last_dash_part_even_when_family_unknown() {
    let g = |n: &str| p(n).release_group;
    let some = |s: &str| Some(s.to_owned());
    assert_eq!(g("Toto.Pc.Game.299133-Mephisto"), some("Mephisto"));
    assert_eq!(g("Toto.Pc.Game.299133-Mephisto.nzb"), some("Mephisto"));
    assert_eq!(g("A-B.C-GRP"), some("GRP"));
    assert_eq!(g("Some.Thing.v1-Grp_2x"), some("Grp_2x"));
    assert_eq!(g("Some.Thing-GRP99"), some("GRP99"));
    assert_eq!(g("Some.Thing.NoDash"), None);
    assert_eq!(g("Some.Thing-"), None);
    assert_eq!(g("Some.Thing-.nzb"), None);
    assert_eq!(g(&format!("Some.Thing-{}", "A".repeat(5000))), None);
    assert_eq!(g(&"-".repeat(5000)), None);
    assert_eq!(g("-GRP"), None);
    // The family stays unknown: only the group is kept.
    assert!(!p("Toto.Pc.Game.299133-Mephisto").is_conclusive());
}
