//! Categorizer decision chain (`PARSER_SPEC` §Categorization, D17/D19, T017).
//!
//! Order: Scene rules on the release-name candidates, then the submission hint, then
//! `<meta type="category">`, then the `8010 Other/Misc` fallback with `UNCATEGORIZED`.
//! Exception (review 45 I1): a valid hint inside the XXX subtree wins over a non-XXX Scene result, so
//! hiding XXX fails closed.
//!
//! # Manual override
//! A manual UI override (`category_source = 'manual'`, `category_overridden = 1`) is owned by the
//! store: [`CategorySource`] deliberately has no `Manual` variant and [`categorize`] is a pure
//! function that never sees the stored row. Callers must not invoke it for a release whose
//! `category_overridden` is set (re-classification of an existing release is a store concern and
//! must skip overridden rows); a duplicate upload never re-categorizes anything.
//!
//! # Candidate order
//! `Analysis::name_candidates` holds the meta name/title (the first
//! `Analysis::meta_name_candidates` entries), then the derived title and the largest archive/video
//! stem. The source file stem (`Some.Release.Name.nzb`) is passed in
//! [`CategorizeRequest::source_stem`]. D39 (T131): when the file name is usable as the release title
//! ([`crate::source_title`]) its stem is the **first** candidate, consistent with the title; otherwise
//! it keeps its old place after the meta candidates.
//!
//! # Hints are hostile
//! A hint is only compared with the taxonomy allowlist ([`Taxonomy::resolve`]); an unknown value
//! is a typed error ([`CategorizeError::InvalidCategory`], code `INVALID_CATEGORY`) even when the
//! Scene result would have won, because the submission is rejected as a whole. The hint string is
//! never stored, echoed or used as a path; only resolved ids leave this module. Callers map an
//! empty form field ("auto") to `None` before calling.

use crate::sanitize::sanitize_text;
use crate::scene::{MAX_SCENE_NAME_BYTES, SceneInfo, SceneRules, SceneRulesError, parse_scene};
use crate::taxonomy::{FALLBACK_CATEGORY, Taxonomy, TaxonomyError, XXX_CATEGORY};
use crate::types::{Analysis, ReleaseFlags};

// The title stem and the Scene candidate share one cleanup and one cap (review 45 I6).
const _: () = assert!(crate::SOURCE_TITLE_BYTES == MAX_SCENE_NAME_BYTES);

/// Upper bound on candidates examined (4 from the analyzer plus the file stem, with slack).
const MAX_CANDIDATES: usize = 8;
/// Suffixes stripped from the source file stem, at most [`MAX_SUFFIX_STRIPS`] times.
const MAX_SUFFIX_STRIPS: usize = 4;

/// Rules needed by [`categorize`]: Scene token tables and the taxonomy allowlist.
#[derive(Debug, Clone)]
pub struct CategoryRules {
    /// Scene token tables. Callers should build them with `with_max_year(current_year + 1)`.
    pub scene: SceneRules,
    /// Slug / id allowlist.
    pub taxonomy: Taxonomy,
}

/// Error building [`CategoryRules`] from the embedded files.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CategoryRulesError {
    /// `config/scene_rules.toml` is broken.
    #[error(transparent)]
    Scene(#[from] SceneRulesError),
    /// `config/categories.toml` is broken.
    #[error(transparent)]
    Taxonomy(#[from] TaxonomyError),
}

impl CategoryRules {
    /// Embedded rules and taxonomy. `max_year` is `current_year + 1` (the clock stays outside
    /// this crate).
    ///
    /// # Errors
    /// Only if an embedded file is broken (covered by unit tests).
    pub fn builtin(max_year: u16) -> Result<Self, CategoryRulesError> {
        Ok(Self {
            scene: SceneRules::builtin()?.with_max_year(max_year),
            taxonomy: Taxonomy::builtin()?,
        })
    }
}

/// Which step of the chain decided. Stored in `release.category_source`; `manual` exists only in
/// the store (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CategorySource {
    /// Scene release-name rules.
    Scene,
    /// Hint given at submission (header, form field, UI dropdown, watch sub-folder).
    Upload,
    /// `<meta type="category">` of the NZB.
    Meta,
    /// Nothing matched: `8010 Other/Misc`, flag `UNCATEGORIZED`.
    Fallback,
}

impl CategorySource {
    /// Value of the `category_source` column.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scene => "scene",
            Self::Upload => "upload",
            Self::Meta => "meta",
            Self::Fallback => "fallback",
        }
    }
}

/// Typed failure of [`categorize`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CategorizeError {
    /// The hint is neither a known id nor a known slug (API `INVALID_CATEGORY`).
    #[error("INVALID_CATEGORY")]
    InvalidCategory,
}

impl CategorizeError {
    /// Stable client-facing code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidCategory => "INVALID_CATEGORY",
        }
    }
}

/// Untrusted submission context.
#[derive(Debug, Clone, Copy, Default)]
pub struct CategorizeRequest<'a> {
    /// Raw category hint (id or slug); `None` when absent. Validated here.
    pub hint: Option<&'a str>,
    /// Name of the submitted file (`Some.Release.Name.nzb`) or `X-Source-Name`: candidate 3.
    /// Display data only; sanitized and capped here, never used as a path.
    pub source_stem: Option<&'a str>,
}

/// A valid hint that differs from the Scene result (Scene wins, D19, except a hint inside the XXX
/// subtree, which wins over a non-XXX Scene result: review 45 I1). For `ingest_log.detail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HintDisagreement {
    /// Category id the hint resolved to.
    pub hint_id: u16,
    /// Category id chosen by the Scene rules.
    pub scene_id: u16,
}

/// Outcome of the decision chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Categorization {
    /// Chosen taxonomy id (always present in the taxonomy).
    pub category_id: u16,
    /// Deciding step.
    pub source: CategorySource,
    /// [`ReleaseFlags::UNCATEGORIZED`] for the fallback, otherwise empty; OR it into the
    /// release flags.
    pub flags: ReleaseFlags,
    /// Scene result of the winning candidate (default/inconclusive when none was conclusive).
    pub scene: SceneInfo,
    /// The candidate string the Scene result came from.
    pub scene_candidate: Option<String>,
    /// Set when a valid hint disagreed with a conclusive Scene result.
    pub hint_disagreement: Option<HintDisagreement>,
}

/// Runs the decision chain.
///
/// # Errors
/// [`CategorizeError::InvalidCategory`] when `request.hint` is present but not in the allowlist.
pub fn categorize(
    analysis: &Analysis,
    request: &CategorizeRequest<'_>,
    rules: &CategoryRules,
) -> Result<Categorization, CategorizeError> {
    let tax = &rules.taxonomy;
    let hint_id = match request.hint {
        None => None,
        Some(h) => Some(tax.resolve(h).ok_or(CategorizeError::InvalidCategory)?),
    };

    // 1. Scene rules, first conclusive candidate wins. The first group seen on an inconclusive
    //    candidate is kept as display data.
    let mut fallback_group: Option<String> = None;
    for cand in candidates(analysis, request.source_stem) {
        let scene = parse_scene(&cand, &rules.scene);
        if fallback_group.is_none() {
            fallback_group.clone_from(&scene.release_group);
        }
        let Some(scene_id) = scene.category.filter(|c| tax.contains(*c)) else {
            continue;
        };
        if !scene.is_conclusive() {
            continue;
        }
        let hint_disagreement = hint_id
            .filter(|h| *h != scene_id)
            .map(|hint_id| HintDisagreement { hint_id, scene_id });
        // Review 45 I1 (privacy-protective, D39): a valid hint inside the XXX subtree wins over Scene, so a
        // scene-looking name cannot move a release routed to XXX (watch rule, sub-folder, upload/API
        // category) out of it and show it to users who hide XXX. Scene attributes are kept.
        if let Some(h) = hint_id.filter(|h| is_xxx(tax, *h))
            && !is_xxx(tax, scene_id)
        {
            return Ok(Categorization {
                category_id: h,
                source: CategorySource::Upload,
                flags: ReleaseFlags::EMPTY,
                scene,
                scene_candidate: Some(cand),
                hint_disagreement,
            });
        }
        return Ok(Categorization {
            category_id: scene_id,
            source: CategorySource::Scene,
            flags: ReleaseFlags::EMPTY,
            scene,
            scene_candidate: Some(cand),
            hint_disagreement,
        });
    }

    let done = |category_id, source, flags| Categorization {
        category_id,
        source,
        flags,
        scene: SceneInfo {
            release_group: fallback_group.clone(),
            ..SceneInfo::default()
        },
        scene_candidate: None,
        hint_disagreement: None,
    };
    // 2. Submission hint.
    if let Some(id) = hint_id {
        return Ok(done(id, CategorySource::Upload, ReleaseFlags::EMPTY));
    }
    // 3. NZB meta category (untrusted file content: unknown values are ignored, not errors).
    if let Some(id) = analysis
        .meta_category
        .as_deref()
        .and_then(|m| tax.resolve_loose(m))
    {
        return Ok(done(id, CategorySource::Meta, ReleaseFlags::EMPTY));
    }
    // 4. Fallback.
    Ok(done(
        FALLBACK_CATEGORY,
        CategorySource::Fallback,
        ReleaseFlags::UNCATEGORIZED,
    ))
}

/// Whether `id` is the XXX root or one of its descendants (the subtree `ui.show_xxx` / `hide_xxx` hide).
fn is_xxx(tax: &Taxonomy, id: u16) -> bool {
    tax.subtree_ids(XXX_CATEGORY).contains(&id)
}

/// Candidate order of `PARSER_SPEC`: usable source stem (D39), meta name, meta title, source stem when
/// not usable as a title, derived title, stem of the largest archive/video; de-duplicated, each capped
/// for the Scene parser.
fn candidates(analysis: &Analysis, source_stem: Option<&str>) -> Vec<String> {
    let split = usize::from(analysis.meta_name_candidates).min(analysis.name_candidates.len());
    let (meta, rest) = analysis.name_candidates.split_at(split);
    let usable = source_stem.and_then(crate::source_title).is_some();
    let stem = source_stem.map(clean_stem).filter(|s| !s.is_empty());
    let (first, after_meta) = if usable { (stem, None) } else { (None, stem) };
    let mut out: Vec<String> = Vec::new();
    for c in first
        .into_iter()
        .chain(meta.iter().cloned())
        .chain(after_meta)
        .chain(rest.iter().cloned())
    {
        let c = cap(c);
        if !c.is_empty() && !out.contains(&c) {
            out.push(c);
        }
        if out.len() >= MAX_CANDIDATES {
            break;
        }
    }
    out
}

fn cap(s: String) -> String {
    if s.len() <= MAX_SCENE_NAME_BYTES {
        return s;
    }
    sanitize_text(&s, MAX_SCENE_NAME_BYTES)
}

/// Sanitizes a submitted file name into a release-name candidate. Derived from the title stem
/// ([`crate::source_stem`]: last path component, sanitized, `.nzb` removed; review 45 I6), so the
/// candidate and the file-name title always start from one cleanup; for the Scene parser only, trailing
/// `.rar` / `.par2` / `.partNN` (and any further `.nzb`) are also removed, a few times
/// (`Some.Name.part01.nzb`: title `Some.Name.part01`, candidate `Some.Name`).
fn clean_stem(raw: &str) -> String {
    let stem = crate::source_stem(raw);
    let mut s = stem.as_str();
    for _ in 0..MAX_SUFFIX_STRIPS {
        let Some((head, ext)) = s.rsplit_once('.') else {
            break;
        };
        let lower = ext.to_ascii_lowercase();
        let is_part = lower
            .strip_prefix("part")
            .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()));
        if matches!(lower.as_str(), "nzb" | "rar" | "par2") || is_part {
            s = head;
        } else {
            break;
        }
    }
    s.trim_end_matches([' ', '.', '_', '-']).to_owned()
}

#[cfg(test)]
mod tests;
