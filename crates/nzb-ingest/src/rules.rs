//! Watch-folder rules (T126, D38 b; `INGEST_SPEC` §Watch-folder rules).
//!
//! Operator-defined `[[ingest.rules]]` map a watch-folder file to a category hint and/or a source
//! label. Each rule has exactly one matcher:
//!
//! - `subfolder`: the name of the file's **first-level** sub-folder, compared as a string. It is
//!   never joined into a path, never resolved, never created.
//! - `filename`: a regular expression compiled once (size and nesting limits) and matched against
//!   the **sanitized display name** of the file (the same string stored as `source_name`), never
//!   the raw bytes on disk.
//!
//! The first matching rule in file order wins. A rule category is a hint exactly like an upload's
//! `X-Category` (`category_source = upload`, Scene still wins); it beats
//! `ingest.category_from_subfolder`, which keeps working for files no rule categorizes. A rule label
//! is written only when the release row is created (a duplicate never relabels). UI and API uploads
//! and `nzbd import` never see rules.
//!
//! [`dry_run`] answers "what would the rules do with the files in the watch folder right now"
//! without moving, opening or ingesting anything; it uses the scanner's own walk.

use std::path::{Path, PathBuf};

use nzb_core::{Taxonomy, sanitize_text};
use regex::{Regex, RegexBuilder};

use crate::scanner::{Seen, WalkSettings, walk};

/// Most rules accepted in one configuration.
pub const MAX_RULES: usize = 64;
/// Longest `filename` pattern, in bytes.
pub const MAX_PATTERN_BYTES: usize = 512;
/// Longest `subfolder` name, in bytes (a file-system name component).
pub const MAX_SUBFOLDER_BYTES: usize = 255;
/// Compiled program size limit of a `filename` pattern (the regex default is 10 MiB).
const REGEX_SIZE_LIMIT: usize = 256 * 1024;
/// Lazy DFA cache limit of a `filename` pattern.
const REGEX_DFA_SIZE_LIMIT: usize = 1024 * 1024;
/// Nesting limit of a `filename` pattern (the regex default is 250).
const REGEX_NEST_LIMIT: u32 = 32;
/// Longest diagnostic copied from a regex error.
const MAX_DIAGNOSTIC_BYTES: usize = 200;

/// One `[[ingest.rules]]` entry as written in the configuration (unvalidated).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSpec {
    /// Matcher: first-level sub-folder name.
    pub subfolder: Option<String>,
    /// Matcher: regular expression over the sanitized file name.
    pub filename: Option<String>,
    /// Action: taxonomy slug used as the category hint.
    pub category: Option<String>,
    /// Action: source label written on a new release row.
    pub source_label: Option<String>,
}

/// Why a rule set was refused. [`RuleError::code`] is the stable identifier; `index` is 1-based
/// in file order.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RuleError {
    /// More than [`MAX_RULES`] rules.
    #[error("at most {max} watch rules are allowed, found {count}")]
    TooMany {
        /// Rules found.
        count: usize,
        /// The limit.
        max: usize,
    },
    /// Neither `subfolder` nor `filename`.
    #[error("rule {index}: needs one matcher (subfolder or filename)")]
    NoMatcher {
        /// Rule number.
        index: usize,
    },
    /// Both `subfolder` and `filename`.
    #[error("rule {index}: has both subfolder and filename; use exactly one matcher")]
    TwoMatchers {
        /// Rule number.
        index: usize,
    },
    /// The `subfolder` value is not a plain first-level folder name, or recursion is off.
    #[error("rule {index}: subfolder {why}")]
    BadSubfolder {
        /// Rule number.
        index: usize,
        /// What is wrong.
        why: &'static str,
    },
    /// The `filename` pattern does not compile within the limits.
    #[error("rule {index}: filename pattern refused: {why}")]
    BadRegex {
        /// Rule number.
        index: usize,
        /// Short, sanitized diagnostic.
        why: String,
    },
    /// `category` is not a taxonomy slug.
    #[error("rule {index}: category is not a taxonomy slug (see `nzbd categories`)")]
    UnknownCategory {
        /// Rule number.
        index: usize,
    },
    /// Neither a category nor a (non-empty after sanitizing) source label.
    #[error("rule {index}: needs an action (category and/or a non-empty source_label)")]
    NoAction {
        /// Rule number.
        index: usize,
    },
}

impl RuleError {
    /// Stable code of the refusal.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::TooMany { .. } => "RULE_TOO_MANY",
            Self::NoMatcher { .. } => "RULE_NO_MATCHER",
            Self::TwoMatchers { .. } => "RULE_TWO_MATCHERS",
            Self::BadSubfolder { .. } => "RULE_BAD_SUBFOLDER",
            Self::BadRegex { .. } => "RULE_BAD_REGEX",
            Self::UnknownCategory { .. } => "RULE_UNKNOWN_CATEGORY",
            Self::NoAction { .. } => "RULE_NO_ACTION",
        }
    }
}

/// What a rule looks at.
#[derive(Debug, Clone)]
pub enum Matcher {
    /// Exact first-level sub-folder name.
    Subfolder(String),
    /// Compiled pattern over the sanitized file name.
    Filename(Regex),
}

/// A validated rule.
#[derive(Debug, Clone)]
pub struct WatchRule {
    /// The matcher.
    pub matcher: Matcher,
    /// Taxonomy slug (validated).
    pub category: Option<String>,
    /// Sanitized label (`clean_source_label`, at most 64 bytes).
    pub source_label: Option<String>,
}

impl WatchRule {
    fn matches(&self, subfolder: Option<&str>, file_name: Option<&str>) -> bool {
        match &self.matcher {
            Matcher::Subfolder(want) => subfolder == Some(want.as_str()),
            Matcher::Filename(re) => file_name.is_some_and(|n| re.is_match(n)),
        }
    }

    /// One-line description for the CLI (`subfolder = "anime" -> category anime`).
    #[must_use]
    pub fn describe(&self) -> String {
        let matcher = match &self.matcher {
            Matcher::Subfolder(s) => format!("subfolder = {s:?}"),
            Matcher::Filename(re) => format!("filename = {:?}", re.as_str()),
        };
        let mut actions = Vec::new();
        if let Some(c) = &self.category {
            actions.push(format!("category {c}"));
        }
        if let Some(l) = &self.source_label {
            actions.push(format!("label {l:?}"));
        }
        format!("{matcher} -> {}", actions.join(", "))
    }
}

/// The validated rule list, in file order. Cheap to clone (compiled patterns are shared).
#[derive(Debug, Clone, Default)]
pub struct WatchRules {
    rules: Vec<WatchRule>,
}

/// Where a category hint came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintOrigin {
    /// A watch rule.
    Rule,
    /// `ingest.category_from_subfolder`.
    Subfolder,
}

/// What the rules (and `category_from_subfolder`) do with one watch file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Effect<'a> {
    /// 1-based number of the matching rule.
    pub rule: Option<usize>,
    /// Category hint (a taxonomy slug) and its origin.
    pub category: Option<(&'a str, HintOrigin)>,
    /// Source label for a new release row.
    pub source_label: Option<&'a str>,
}

fn check_subfolder(name: &str, recursive: bool) -> Result<(), &'static str> {
    if !recursive {
        return Err("requires ingest.recursive = true");
    }
    if name.is_empty() || name.len() > MAX_SUBFOLDER_BYTES {
        return Err("must be 1..=255 bytes");
    }
    if name.contains(['/', '\\', '\0']) {
        return Err("must be a single folder name (no /, \\ or NUL)");
    }
    if name.contains("..") {
        return Err("must not contain ..");
    }
    if name.starts_with('.') {
        // The scanner never descends into hidden folders, so such a rule could never match.
        return Err("must not start with a dot");
    }
    if sanitize_text(name, MAX_SUBFOLDER_BYTES) != name {
        return Err("must be clean text (no control or invisible characters, no edge spaces)");
    }
    Ok(())
}

fn compile_pattern(pattern: &str) -> Result<Regex, String> {
    if pattern.is_empty() || pattern.len() > MAX_PATTERN_BYTES {
        return Err(format!("must be 1..={MAX_PATTERN_BYTES} bytes"));
    }
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
        .nest_limit(REGEX_NEST_LIMIT)
        .build()
        .map_err(|e| {
            let msg = sanitize_text(&e.to_string(), MAX_DIAGNOSTIC_BYTES);
            if matches!(e, regex::Error::CompiledTooBig(_)) {
                // Review 41 I1: Unicode classes (`\w`, `\d`, `\p{L}`) are large; the limit stays.
                format!("{msg}; {SIZE_HINT}")
            } else {
                msg
            }
        })
}

/// Appended to a `RULE_BAD_REGEX` caused by the size limit.
pub const SIZE_HINT: &str = "Unicode classes such as \\w are large: use (?-u) or explicit ASCII classes \
                             like [A-Za-z0-9_] for long repetitions";

impl WatchRules {
    /// Validates and compiles `specs` (file order). `recursive` is `ingest.recursive`; categories
    /// must be slugs of `taxonomy`.
    ///
    /// # Errors
    /// The first refused rule, see [`RuleError`].
    pub fn compile(
        specs: &[RuleSpec],
        recursive: bool,
        taxonomy: &Taxonomy,
    ) -> Result<Self, RuleError> {
        if specs.len() > MAX_RULES {
            return Err(RuleError::TooMany {
                count: specs.len(),
                max: MAX_RULES,
            });
        }
        let mut rules = Vec::with_capacity(specs.len());
        for (i, spec) in specs.iter().enumerate() {
            let index = i.saturating_add(1);
            let matcher = match (&spec.subfolder, &spec.filename) {
                (None, None) => return Err(RuleError::NoMatcher { index }),
                (Some(_), Some(_)) => return Err(RuleError::TwoMatchers { index }),
                (Some(s), None) => {
                    check_subfolder(s, recursive)
                        .map_err(|why| RuleError::BadSubfolder { index, why })?;
                    Matcher::Subfolder(s.clone())
                }
                (None, Some(p)) => Matcher::Filename(
                    compile_pattern(p).map_err(|why| RuleError::BadRegex { index, why })?,
                ),
            };
            let category = match &spec.category {
                None => None,
                Some(c) if taxonomy.entries().iter().any(|e| e.slug == *c) => Some(c.clone()),
                Some(_) => return Err(RuleError::UnknownCategory { index }),
            };
            let source_label = spec
                .source_label
                .as_deref()
                .and_then(nzb_store::clean_source_label);
            if category.is_none() && source_label.is_none() {
                return Err(RuleError::NoAction { index });
            }
            rules.push(WatchRule {
                matcher,
                category,
                source_label,
            });
        }
        Ok(Self { rules })
    }

    /// The rules in file order (rule number = position + 1).
    #[must_use]
    pub fn rules(&self) -> &[WatchRule] {
        &self.rules
    }

    /// No rules configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The first rule matching a watch file, with its 1-based number. `subfolder` is the
    /// first-level sub-folder name, `file_name` the sanitized display name.
    #[must_use]
    pub fn first_match(
        &self,
        subfolder: Option<&str>,
        file_name: Option<&str>,
    ) -> Option<(usize, &WatchRule)> {
        self.rules
            .iter()
            .enumerate()
            .find(|(_, r)| r.matches(subfolder, file_name))
            .map(|(i, r)| (i.saturating_add(1), r))
    }

    /// The full effect on a watch file: the first matching rule's actions; without a rule
    /// category, the `category_from_subfolder` hint (a first-level folder named exactly like a
    /// taxonomy slug) when that option is on.
    #[must_use]
    pub fn effect<'a>(
        &'a self,
        subfolder: Option<&'a str>,
        file_name: Option<&str>,
        category_from_subfolder: bool,
        taxonomy: &Taxonomy,
    ) -> Effect<'a> {
        let hit = self.first_match(subfolder, file_name);
        let rule_category = hit
            .and_then(|(_, r)| r.category.as_deref())
            .map(|c| (c, HintOrigin::Rule));
        let folder_category = || {
            subfolder
                .filter(|_| category_from_subfolder)
                .filter(|s| taxonomy.entries().iter().any(|e| e.slug == *s))
                .map(|s| (s, HintOrigin::Subfolder))
        };
        Effect {
            rule: hit.map(|(n, _)| n),
            category: rule_category.or_else(folder_category),
            source_label: hit.and_then(|(_, r)| r.source_label.as_deref()),
        }
    }
}

/// Settings of [`dry_run`] (the same `[ingest]`/`[limits]` values `serve` uses).
#[derive(Debug, Clone)]
pub struct DryRunSettings {
    /// `paths.watch`.
    pub watch_dir: PathBuf,
    /// `ingest.recursive`.
    pub recursive: bool,
    /// `ingest.category_from_subfolder`.
    pub category_from_subfolder: bool,
    /// `limits.max_file_bytes` (larger files are ignored by the scanner too).
    pub max_file_bytes: u64,
    /// Entry budget of the walk.
    pub max_entries: usize,
}

/// One watch file and what would happen to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRunEntry {
    /// Path relative to the watch folder, each component sanitized (display only).
    pub shown_path: String,
    /// 1-based number of the matching rule.
    pub rule: Option<usize>,
    /// Category hint (slug) and its origin.
    pub category: Option<(String, HintOrigin)>,
    /// Source label a new release would get.
    pub source_label: Option<String>,
}

/// A directory the scanner does not enter although recursion would reach it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoredDir {
    /// Path relative to the watch folder, each component sanitized (display only).
    pub shown_path: String,
    /// Why it is skipped (`hidden directory`, `non-UTF-8 directory name`).
    pub why: &'static str,
}

/// Result of [`dry_run`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DryRun {
    /// Candidate files, sorted by path.
    pub entries: Vec<DryRunEntry>,
    /// Entries the scanner would ignore (symlinks, special files, temp names, oversize, skipped
    /// directories, ...).
    pub ignored: usize,
    /// Directories skipped by the walk (hidden or non-UTF-8), sorted; also counted in `ignored`.
    /// Files inside them are never ingested.
    pub ignored_dirs: Vec<IgnoredDir>,
}

/// Display form of a path under the watch root: every component sanitized, joined with `/`.
fn shown_relative(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.components()
        .map(|c| sanitize_text(&c.as_os_str().to_string_lossy(), 255))
        .collect::<Vec<_>>()
        .join("/")
}

/// Read-only preview: walks the watch folder exactly like the scanner (no symlink following, same
/// depth and entry limits, same candidate rules) and reports, per candidate file, the rule that
/// would apply and its effect. Opens, moves and ingests nothing.
#[must_use]
pub fn dry_run(s: &DryRunSettings, rules: &WatchRules, taxonomy: &Taxonomy) -> DryRun {
    let settings = WalkSettings {
        root: s.watch_dir.clone(),
        recursive: s.recursive,
        max_file_bytes: s.max_file_bytes,
        max_entries: s.max_entries,
    };
    let mut found: Vec<(PathBuf, Option<String>)> = Vec::new();
    let mut skipped: Vec<(PathBuf, &'static str)> = Vec::new();
    let mut ignored: usize = 0;
    walk(&settings, |seen| match seen {
        Seen::Candidate {
            path, subfolder, ..
        } => found.push((path, subfolder)),
        Seen::Ignored { .. } => ignored = ignored.saturating_add(1),
        Seen::SkippedDir { path, why } => {
            ignored = ignored.saturating_add(1);
            skipped.push((path, why));
        }
    });
    found.sort_by(|a, b| a.0.cmp(&b.0));
    skipped.sort_by(|a, b| a.0.cmp(&b.0));
    let ignored_dirs = skipped
        .iter()
        .map(|(path, why)| IgnoredDir {
            shown_path: shown_relative(&s.watch_dir, path),
            why,
        })
        .collect();
    let entries = found
        .iter()
        .map(|(path, subfolder)| {
            let name = crate::pipeline::display_name(path);
            let eff = rules.effect(
                subfolder.as_deref(),
                name.as_deref(),
                s.category_from_subfolder,
                taxonomy,
            );
            DryRunEntry {
                shown_path: shown_relative(&s.watch_dir, path),
                rule: eff.rule,
                category: eff.category.map(|(c, o)| (c.to_owned(), o)),
                source_label: eff.source_label.map(str::to_owned),
            }
        })
        .collect();
    DryRun {
        entries,
        ignored,
        ignored_dirs,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;

    fn tax() -> Taxonomy {
        Taxonomy::builtin().unwrap()
    }

    fn sub(name: &str) -> RuleSpec {
        RuleSpec {
            subfolder: Some(name.into()),
            category: Some("anime".into()),
            ..RuleSpec::default()
        }
    }

    fn file(re: &str) -> RuleSpec {
        RuleSpec {
            filename: Some(re.into()),
            source_label: Some("from rule".into()),
            ..RuleSpec::default()
        }
    }

    fn code(specs: &[RuleSpec], recursive: bool) -> &'static str {
        WatchRules::compile(specs, recursive, &tax())
            .unwrap_err()
            .code()
    }

    #[test]
    fn refusal_codes() {
        assert_eq!(code(&[RuleSpec::default()], true), "RULE_NO_MATCHER");
        let both = RuleSpec {
            filename: Some("x".into()),
            ..sub("anime")
        };
        assert_eq!(code(&[both], true), "RULE_TWO_MATCHERS");
        assert_eq!(code(&[file("(")], true), "RULE_BAD_REGEX");
        let unknown = RuleSpec {
            category: Some("Anime".into()),
            ..sub("x")
        };
        assert_eq!(code(&[unknown], true), "RULE_UNKNOWN_CATEGORY");
        let numeric = RuleSpec {
            category: Some("8010".into()),
            ..sub("x")
        };
        assert_eq!(code(&[numeric], true), "RULE_UNKNOWN_CATEGORY");
        let none = RuleSpec {
            subfolder: Some("x".into()),
            ..RuleSpec::default()
        };
        assert_eq!(code(&[none], true), "RULE_NO_ACTION");
        // A label that sanitizes to nothing is no action either.
        let blank = RuleSpec {
            subfolder: Some("x".into()),
            source_label: Some(" \u{202e}\u{7} ".into()),
            ..RuleSpec::default()
        };
        assert_eq!(code(&[blank], true), "RULE_NO_ACTION");
        assert_eq!(code(&vec![sub("x"); MAX_RULES + 1], true), "RULE_TOO_MANY");
        assert!(WatchRules::compile(&vec![sub("x"); MAX_RULES], true, &tax()).is_ok());
        // The first bad rule is reported with its 1-based number.
        let e = WatchRules::compile(&[sub("ok"), file("[")], true, &tax()).unwrap_err();
        assert!(matches!(e, RuleError::BadRegex { index: 2, .. }), "{e}");
    }

    #[test]
    fn hostile_subfolder_values_are_refused() {
        for bad in [
            "",
            "a/b",
            "/abs",
            "a\\b",
            "..",
            "../x",
            "a..b",
            "x\0",
            ".hidden",
            "tab\there",
            " lead",
            "trail ",
            "rlo\u{202e}x",
            &"x".repeat(256),
        ] {
            assert_eq!(code(&[sub(bad)], true), "RULE_BAD_SUBFOLDER", "{bad:?}");
        }
        // Needs recursion: without it no sub-folder is ever scanned.
        assert_eq!(code(&[sub("anime")], false), "RULE_BAD_SUBFOLDER");
        assert!(WatchRules::compile(&[sub("My Anime (HD)")], true, &tax()).is_ok());
        // Filename rules work without recursion.
        assert!(WatchRules::compile(&[file("x")], false, &tax()).is_ok());
    }

    #[test]
    fn regex_limits_refuse_oversized_or_deep_patterns() {
        assert_eq!(code(&[file("")], false), "RULE_BAD_REGEX");
        assert_eq!(
            code(&[file(&"a".repeat(MAX_PATTERN_BYTES + 1))], false),
            "RULE_BAD_REGEX"
        );
        let deep = format!("{}a{}", "(".repeat(40), ")".repeat(40));
        assert_eq!(code(&[file(&deep)], false), "RULE_BAD_REGEX");
        // Fits in 512 bytes but compiles far beyond the size limit.
        assert_eq!(code(&[file(r"\w{1000}\w{1000}")], false), "RULE_BAD_REGEX");
        // Review 41 I1: a size-limit refusal says how to shrink the pattern; ASCII classes fit.
        let msg = WatchRules::compile(&[file(r"\w{30}")], false, &tax())
            .unwrap_err()
            .to_string();
        assert!(
            msg.contains("(?-u)") && msg.contains("[A-Za-z0-9_]"),
            "{msg}"
        );
        assert!(WatchRules::compile(&[file(r"(?-u)\w{200}")], false, &tax()).is_ok());
        assert!(WatchRules::compile(&[file(r"[A-Za-z0-9_]{100}")], false, &tax()).is_ok());
        let msg = WatchRules::compile(&[file("(")], false, &tax())
            .unwrap_err()
            .to_string();
        assert!(!msg.contains('\n'), "{msg}");
    }

    #[test]
    fn first_matching_rule_wins_in_file_order() {
        let rules = WatchRules::compile(
            &[
                RuleSpec {
                    filename: Some(r"(?i)\.s\d\de\d\d\.".into()),
                    category: Some("tv.hd".into()),
                    ..RuleSpec::default()
                },
                sub("anime"),
                file("."),
            ],
            true,
            &tax(),
        )
        .unwrap();
        let t = tax();
        let e = rules.effect(Some("anime"), Some("Show.S01E02.mkv.nzb"), false, &t);
        assert_eq!(e.rule, Some(1));
        assert_eq!(e.category, Some(("tv.hd", HintOrigin::Rule)));
        assert_eq!(e.source_label, None);
        let e = rules.effect(Some("anime"), Some("x.nzb"), false, &t);
        assert_eq!(
            (e.rule, e.category),
            (Some(2), Some(("anime", HintOrigin::Rule)))
        );
        let e = rules.effect(None, Some("x.nzb"), false, &t);
        assert_eq!(
            (e.rule, e.category, e.source_label),
            (Some(3), None, Some("from rule"))
        );
        assert_eq!(rules.effect(None, None, false, &t), Effect::default());
    }

    #[test]
    fn subfolder_is_compared_exactly_and_only_at_first_level() {
        let rules = WatchRules::compile(&[sub("Anime")], true, &tax()).unwrap();
        assert_eq!(rules.first_match(Some("Anime"), None).map(|m| m.0), Some(1));
        for other in ["anime", "ANIME", "Anime ", "Anime/x", "x/Anime"] {
            assert!(rules.first_match(Some(other), None).is_none(), "{other}");
        }
        assert!(rules.first_match(None, Some("Anime")).is_none());
    }

    #[test]
    fn rule_category_beats_category_from_subfolder_which_keeps_working() {
        let t = tax();
        let rules = WatchRules::compile(
            &[
                RuleSpec {
                    filename: Some("^special".into()),
                    category: Some("tv.hd".into()),
                    ..RuleSpec::default()
                },
                RuleSpec {
                    filename: Some("^labelled".into()),
                    source_label: Some("lab".into()),
                    ..RuleSpec::default()
                },
            ],
            true,
            &t,
        )
        .unwrap();
        let e = rules.effect(Some("anime"), Some("special.nzb"), true, &t);
        assert_eq!(e.category, Some(("tv.hd", HintOrigin::Rule)));
        // A label-only rule leaves the folder hint in place.
        let e = rules.effect(Some("anime"), Some("labelled.nzb"), true, &t);
        assert_eq!(
            (e.rule, e.category, e.source_label),
            (Some(2), Some(("anime", HintOrigin::Subfolder)), Some("lab"))
        );
        let e = rules.effect(Some("anime"), Some("other.nzb"), true, &t);
        assert_eq!(
            (e.rule, e.category),
            (None, Some(("anime", HintOrigin::Subfolder)))
        );
        // Option off: no folder hint.
        assert_eq!(
            rules.effect(Some("anime"), Some("other.nzb"), false, &t),
            Effect::default()
        );
        // Not a slug: no folder hint.
        assert_eq!(rules.effect(Some("Anime"), None, true, &t).category, None);
    }

    #[test]
    fn labels_are_sanitized_and_capped() {
        let rules = WatchRules::compile(
            &[RuleSpec {
                filename: Some("x".into()),
                source_label: Some(format!("a\u{202e}b\u{0}c {}", "z".repeat(100))),
                ..RuleSpec::default()
            }],
            false,
            &tax(),
        )
        .unwrap();
        let l = rules.rules()[0].source_label.as_deref().unwrap();
        assert!(l.starts_with("abc z") && l.len() <= 64, "{l:?}");
    }

    #[test]
    fn filename_matches_the_sanitized_name_only() {
        // A bidi override can not hide a match or fake one: the pattern sees the cleaned name.
        let rules = WatchRules::compile(&[file(r"^evil\.nzb$")], false, &tax()).unwrap();
        let shown = crate::pipeline::display_name(Path::new("/w/ev\u{202e}il.nzb"));
        assert_eq!(shown.as_deref(), Some("evil.nzb"));
        assert!(rules.first_match(None, shown.as_deref()).is_some());
    }

    fn settings(root: &Path, recursive: bool) -> DryRunSettings {
        DryRunSettings {
            watch_dir: root.to_path_buf(),
            recursive,
            category_from_subfolder: true,
            max_file_bytes: 1000,
            max_entries: 1000,
        }
    }

    #[test]
    fn dry_run_is_read_only_and_never_follows_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("o.nzb"), b"secret").unwrap();
        std::os::unix::fs::symlink(outside.path(), p.join("escape")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("o.nzb"), p.join("l.nzb")).unwrap();
        fs::create_dir(p.join("anime")).unwrap();
        fs::write(p.join("anime/a.nzb"), b"x").unwrap();
        fs::create_dir(p.join(".hid")).unwrap();
        fs::write(p.join(".hid/h.nzb"), b"x").unwrap();
        let bad_dir = p.join(std::ffi::OsStr::from_bytes(b"bad\xff"));
        fs::create_dir(&bad_dir).unwrap();
        fs::write(bad_dir.join("b.nzb"), b"x").unwrap();
        fs::write(p.join("Show.S01E01.nzb"), b"x").unwrap();
        fs::write(p.join("big.nzb"), [b'x'; 1001]).unwrap();
        fs::write(p.join("t\u{1b}[31mx.nzb"), b"x").unwrap();
        let before = tree(p);
        let rules = WatchRules::compile(
            &[RuleSpec {
                filename: Some(r"\.S\d\dE\d\d\.".into()),
                category: Some("tv.hd".into()),
                source_label: Some("tv".into()),
                ..RuleSpec::default()
            }],
            true,
            &tax(),
        )
        .unwrap();
        let r = dry_run(&settings(p, true), &rules, &tax());
        let shown: Vec<&str> = r.entries.iter().map(|e| e.shown_path.as_str()).collect();
        // The escape sequence is stripped from the display (no terminal control reaches stdout).
        assert_eq!(shown, ["Show.S01E01.nzb", "anime/a.nzb", "t[31mx.nzb"]);
        assert_eq!(r.entries[0].rule, Some(1));
        assert_eq!(
            r.entries[0].category,
            Some(("tv.hd".to_owned(), HintOrigin::Rule))
        );
        assert_eq!(r.entries[0].source_label.as_deref(), Some("tv"));
        assert_eq!(
            (r.entries[1].rule, r.entries[1].category.clone()),
            (None, Some(("anime".to_owned(), HintOrigin::Subfolder)))
        );
        assert_eq!(
            r.ignored, 5,
            "file symlink, directory symlink, oversize file, two skipped directories"
        );
        // Review 41 I3: skipped directories are reported with a reason, never silently dropped.
        let dirs: Vec<(&str, &str)> = r
            .ignored_dirs
            .iter()
            .map(|d| (d.shown_path.as_str(), d.why))
            .collect();
        assert_eq!(
            dirs,
            [
                (".hid", "hidden directory"),
                ("bad\u{fffd}", "non-UTF-8 directory name")
            ]
        );
        assert_eq!(tree(p), before, "nothing moved, created or deleted");
        // Non-recursive: the sub-folder is not walked.
        let r = dry_run(&settings(p, false), &rules, &tax());
        assert_eq!(r.entries.len(), 2);
    }

    #[test]
    fn dry_run_respects_depth_and_entry_limits() {
        let d = tempfile::tempdir().unwrap();
        let mut p = d.path().to_path_buf();
        for i in 0..6 {
            p = p.join(format!("d{i}"));
            fs::create_dir(&p).unwrap();
            fs::write(p.join("a.nzb"), b"x").unwrap();
        }
        let rules = WatchRules::default();
        assert_eq!(
            dry_run(&settings(d.path(), true), &rules, &tax())
                .entries
                .len(),
            4
        );
        let mut s = settings(d.path(), true);
        s.max_entries = 3;
        assert!(dry_run(&s, &rules, &tax()).entries.len() < 4);
    }

    fn tree(root: &Path) -> Vec<(PathBuf, u64)> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in fs::read_dir(&d).unwrap() {
                let e = e.unwrap();
                let m = fs::symlink_metadata(e.path()).unwrap();
                if m.is_dir() {
                    stack.push(e.path());
                }
                out.push((e.path(), m.len()));
            }
        }
        out.sort();
        out
    }
}
