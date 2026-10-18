//! `nzbd watch rules` (T126): prints the validated `[[ingest.rules]]` and a dry run over the files
//! currently in the watch folder. Read-only: the walk is the scanner's own (no symlink following,
//! same depth and entry limits), nothing is opened, moved or ingested, the database is not touched.
//! Refused as root like every other command (review 41 L1): the walk is path-based, and as the service
//! user a sub-directory swapped for a symlink mid-walk can only lead where `serve` could read anyway.

use std::fmt::Write as _;

use clap::Subcommand;
use nzb_ingest::{DryRun, DryRunSettings, HintOrigin, WatchRules};

use crate::config::Config;

/// `nzbd watch ...`
#[derive(Subcommand)]
pub enum WatchAction {
    /// Print the watch-folder rules and, for each file now in the watch folder, the rule that
    /// would apply and its effect (dry run: nothing is moved or ingested).
    Rules,
}

/// Runs a `watch` subcommand with the configuration at `config` (or the defaults + env).
///
/// # Errors
/// An unreadable configuration, an invalid rule (stable `RULE_*` code) or an unusable taxonomy.
pub fn run(config: Option<&std::path::Path>, action: &WatchAction) -> Result<(), String> {
    let cfg = &Config::load(config).map_err(|e| e.to_string())?;
    match action {
        WatchAction::Rules => {
            let rules = cfg.watch_rules().map_err(|e| e.to_string())?;
            let tax = nzb_core::Taxonomy::builtin().map_err(|e| e.to_string())?;
            let report = nzb_ingest::dry_run(
                &DryRunSettings {
                    watch_dir: cfg.paths.watch.clone(),
                    recursive: cfg.ingest.recursive,
                    category_from_subfolder: cfg.ingest.category_from_subfolder,
                    max_file_bytes: cfg.limits.max_file_bytes,
                    max_entries: nzb_ingest::scanner::DEFAULT_MAX_ENTRIES,
                },
                &rules,
                &tax,
            );
            print!("{}", render(cfg, &rules, &report));
            Ok(())
        }
    }
}

/// The report. File paths and labels are already sanitized (no control characters reach the
/// terminal); they are printed quoted.
fn render(cfg: &Config, rules: &WatchRules, report: &DryRun) -> String {
    let mut out = format!(
        "watch rules: {} (ingest.recursive = {}, ingest.category_from_subfolder = {})\n",
        rules.rules().len(),
        cfg.ingest.recursive,
        cfg.ingest.category_from_subfolder
    );
    for (i, r) in rules.rules().iter().enumerate() {
        let _ = writeln!(out, "  #{} {}", i.saturating_add(1), r.describe());
    }
    let _ = writeln!(
        out,
        "\nwatch folder {}: {} file(s), {} other entr(ies) ignored. Dry run: nothing is moved or ingested.",
        cfg.paths.watch.display(),
        report.entries.len(),
        report.ignored
    );
    for e in &report.entries {
        let mut effect = Vec::new();
        match e.category.as_ref() {
            Some((slug, HintOrigin::Rule)) => effect.push(format!("category {slug}")),
            Some((slug, HintOrigin::Subfolder)) => {
                effect.push(format!("category {slug} (category_from_subfolder)"));
            }
            None => {}
        }
        if let Some(l) = &e.source_label {
            effect.push(format!("label {l:?} (new releases only)"));
        }
        let rule = e
            .rule
            .map_or_else(|| "no rule".to_owned(), |n| format!("rule #{n}"));
        let effect = if effect.is_empty() {
            "no change".to_owned()
        } else {
            effect.join(", ")
        };
        let _ = writeln!(out, "  {:?}: {rule}: {effect}", e.shown_path);
    }
    for d in &report.ignored_dirs {
        let _ = writeln!(
            out,
            "  {:?}: directory not scanned ({}); files inside are never ingested",
            format!("{}/", d.shown_path),
            d.why
        );
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::WatchRuleConfig;

    fn cfg(dir: &std::path::Path, rules: Vec<WatchRuleConfig>) -> Config {
        let mut c = Config::default();
        c.paths.watch = dir.to_path_buf();
        c.ingest.recursive = true;
        c.ingest.category_from_subfolder = true;
        c.ingest.rules = rules;
        c
    }

    #[test]
    fn watch_rules_cli_reports_each_file_and_moves_nothing() {
        let d = tempfile::tempdir().unwrap();
        let w = d.path();
        std::fs::create_dir(w.join("anime")).unwrap();
        std::fs::write(w.join("anime/a.nzb"), b"x").unwrap();
        std::fs::write(w.join("tv-show.nzb"), b"x").unwrap();
        std::fs::write(w.join("other.nzb"), b"x").unwrap();
        std::fs::write(w.join("bell\u{7}\u{1b}[1m.nzb"), b"x").unwrap();
        std::fs::write(w.join("notes.txt"), b"x").unwrap();
        std::fs::create_dir(w.join(".hidden")).unwrap();
        std::fs::write(w.join(".hidden/h.nzb"), b"x").unwrap();
        let c = cfg(
            w,
            vec![WatchRuleConfig {
                filename: Some("^tv-".into()),
                category: Some("tv.hd".into()),
                source_label: Some("tv \"feed\"".into()),
                ..WatchRuleConfig::default()
            }],
        );
        let rules = c.watch_rules().unwrap();
        let tax = nzb_core::Taxonomy::builtin().unwrap();
        let report = nzb_ingest::dry_run(
            &DryRunSettings {
                watch_dir: w.to_path_buf(),
                recursive: true,
                category_from_subfolder: true,
                max_file_bytes: 1000,
                max_entries: 1000,
            },
            &rules,
            &tax,
        );
        let out = render(&c, &rules, &report);
        assert!(
            out.contains("#1 filename = \"^tv-\" -> category tv.hd, label"),
            "{out}"
        );
        assert!(
            out.contains("\"tv-show.nzb\": rule #1: category tv.hd, label \"tv \\\"feed\\\"\""),
            "{out}"
        );
        assert!(
            out.contains("\"anime/a.nzb\": no rule: category anime (category_from_subfolder)"),
            "{out}"
        );
        assert!(out.contains("\"other.nzb\": no rule: no change"), "{out}");
        assert!(out.contains("4 file(s), 2 other"), "{out}");
        assert!(
            out.contains("\".hidden/\": directory not scanned (hidden directory)"),
            "{out}"
        );
        // No terminal control character reaches stdout.
        assert!(!out.contains(['\u{7}', '\u{1b}']), "{out:?}");
        // Read-only.
        assert!(w.join("anime/a.nzb").exists() && w.join("tv-show.nzb").exists());
    }

    #[test]
    fn invalid_rules_are_refused_with_stable_codes() {
        let d = tempfile::tempdir().unwrap();
        let rule = |f: fn(&mut WatchRuleConfig)| {
            let mut r = WatchRuleConfig {
                subfolder: Some("x".into()),
                category: Some("anime".into()),
                ..WatchRuleConfig::default()
            };
            f(&mut r);
            r
        };
        let cases: Vec<(Vec<WatchRuleConfig>, &str)> = vec![
            (
                vec![rule(|r| r.subfolder = Some("../x".into()))],
                "RULE_BAD_SUBFOLDER",
            ),
            (
                vec![rule(|r| {
                    r.subfolder = None;
                    r.filename = Some("(".into());
                })],
                "RULE_BAD_REGEX",
            ),
            (
                vec![rule(|r| r.category = Some("nope".into()))],
                "RULE_UNKNOWN_CATEGORY",
            ),
            (vec![rule(|r| r.category = None)], "RULE_NO_ACTION"),
            (
                vec![rule(|r| r.filename = Some("x".into()))],
                "RULE_TWO_MATCHERS",
            ),
            (vec![rule(|r| r.subfolder = None)], "RULE_NO_MATCHER"),
            (vec![rule(|_| {}); 65], "RULE_TOO_MANY"),
        ];
        for (rules, code) in cases {
            let e = cfg(d.path(), rules).watch_rules().unwrap_err().to_string();
            assert!(e.starts_with(code), "{code}: {e}");
        }
        // A subfolder rule without recursion is refused too.
        let mut c = cfg(d.path(), vec![rule(|_| {})]);
        c.ingest.recursive = false;
        assert!(
            c.watch_rules()
                .unwrap_err()
                .to_string()
                .starts_with("RULE_BAD_SUBFOLDER")
        );
    }

    #[test]
    fn rules_parse_from_toml_and_unknown_keys_are_refused() {
        let c: Config = toml::from_str(
            r#"
            [ingest]
            recursive = true
            [[ingest.rules]]
            subfolder = "anime"
            category = "anime"
            [[ingest.rules]]
            filename = '(?i)\.s\d\de\d\d\.'
            source_label = "tv"
            "#,
        )
        .unwrap();
        assert_eq!(c.ingest.rules.len(), 2);
        assert_eq!(c.watch_rules().unwrap().rules().len(), 2);
        let bad = toml::from_str::<Config>(
            r#"
            [[ingest.rules]]
            subfolder = "anime"
            path = "/etc"
            "#,
        );
        assert!(bad.is_err());
    }
}
