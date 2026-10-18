//! Regenerates the committed fixtures under `crates/nzb-core/tests/fixtures/`.
//! Run: `scripts/dev cargo run -p nzb-testkit --example gen_fixtures`.
#![allow(missing_docs)]

use std::fs;
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../nzb-core/tests/fixtures");
    for c in nzb_testkit::hostile::all_cases() {
        if !c.committed {
            continue;
        }
        let dir = root.join(if c.hostile { "hostile" } else { "valid" });
        fs::create_dir_all(&dir)?;
        fs::write(dir.join(format!("{}.nzb", c.name)), &c.bytes)?;
        fs::write(
            dir.join(format!("{}.expected.json", c.name)),
            c.expected.as_bytes(),
        )?;
    }
    Ok(())
}
