//! Compile-time proof that every item banned in `clippy.toml` still exists at that path (review 32
//! I2). The bans use `allow-invalid = true` (crates without tantivy share the config), so a tantivy
//! upgrade that moved or renamed one would silently disable its ban; naming each item here turns that
//! into a build failure. This module, test-only and never called, is the one place allowed to name
//! them (the lint self-test exempts it).
#![allow(dead_code, clippy::disallowed_types, clippy::disallowed_methods)]

fn banned_paths_resolve() {
    let _ = tantivy::query::QueryParser::for_index;
    let _ = tantivy::query::QueryParser::parse_query;
    let _ = tantivy::query::RegexQuery::from_pattern;
    let _ = tantivy::query::wildcard_query_to_regex_str;
    let _: Option<tantivy::query::RegexQuery> = None;
    let _: Option<tantivy::query::RegexPhraseQuery> = None;
    let _: Option<tantivy::query::FuzzyTermQuery> = None;
    let _: Option<tantivy::query::PhrasePrefixQuery> = None;
}
