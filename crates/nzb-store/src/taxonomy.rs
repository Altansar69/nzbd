//! Category seed rows, derived from nzb-core's embedded `config/categories.toml` (the single
//! source of truth, `PARSER_SPEC` §Taxonomy).

use crate::StoreError;

/// `(id, parent_id, name)` rows for the `category` table; parents appear before their children.
///
/// # Errors
/// [`StoreError::Integrity`] if the embedded taxonomy is broken (covered by nzb-core tests).
pub fn seed_rows() -> Result<Vec<(i64, Option<i64>, String)>, StoreError> {
    let tax = nzb_core::Taxonomy::builtin().map_err(|e| StoreError::Integrity(e.to_string()))?;
    Ok(tax
        .entries()
        .iter()
        .map(|c| (i64::from(c.id), c.parent.map(i64::from), c.name.clone()))
        .collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn seed_rows_equal_the_core_taxonomy() {
        let rows = seed_rows().unwrap();
        let tax = nzb_core::Taxonomy::builtin().unwrap();
        assert_eq!(rows.len(), tax.len());
        for (id, parent, name) in &rows {
            let c = tax.get(u16::try_from(*id).unwrap()).unwrap();
            assert_eq!(c.parent.map(i64::from), *parent);
            assert_eq!(&c.name, name);
        }
        // Ids that other layers hard-code.
        for id in [5000, 5040, 8010] {
            assert!(rows.iter().any(|r| r.0 == id));
        }
    }
}
