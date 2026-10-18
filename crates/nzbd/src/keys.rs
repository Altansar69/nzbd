//! Secret-key tooling (T104): TOTP key rotation (`nzbd keys rotate-totp`), the backup encryption key
//! loader, and `nzbd backup decrypt`.
//!
//! Keys only ever travel as 0400 files (SEC-042): never argv, never env, never logs. The only
//! things printed are counts and user ids.

use nzb_store::prelude::*;
use std::path::{Path, PathBuf};

use nzb_store::{BackupKey, Reseal, ResealReport};
use nzb_web::totp::{self, TotpKey};

use crate::config::{self, Config};

/// `nzbd keys ...`
#[derive(clap::Subcommand)]
pub enum KeysAction {
    /// Re-seal every stored TOTP secret under a new key, in one transaction. Offline operation:
    /// stop `nzbd serve` first. Generate the new key with `nzbd keygen --out FILE`; after success
    /// replace `security.totp_key_file` with the new file (the old file is never touched).
    RotateTotp {
        /// File with the new base64 32-byte key (mode 0400, owned by the process uid).
        #[arg(long)]
        new_key_file: PathBuf,
        /// Check that every secret decrypts and report counts; change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Do not take a database backup before re-sealing (not recommended).
        #[arg(long)]
        no_backup: bool,
    },
}

/// `nzbd backup decrypt ...`
#[derive(clap::Subcommand)]
pub enum BackupAction {
    /// Decrypt an encrypted backup (`nzbd-...Z.sqlite.enc`) into a new, plain SQLite file (0600).
    /// Authentication covers the whole file: on any error nothing is written.
    Decrypt {
        /// The encrypted backup.
        file: PathBuf,
        /// Where to write the plain database; must not exist.
        #[arg(long)]
        out: PathBuf,
        /// Key file (default: `maintenance.backup_encryption_key_file`).
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
}

/// Loads `maintenance.backup_encryption_key_file` when configured (SEC-042 rules).
///
/// # Errors
/// The key file is unreadable, too permissive, owned by someone else or malformed.
pub fn load_backup_key(cfg: &Config) -> Result<Option<BackupKey>, String> {
    cfg.maintenance
        .backup_encryption_key_file
        .as_deref()
        .map(|p| load_backup_key_from(p, "maintenance.backup_encryption_key_file"))
        .transpose()
}

fn load_backup_key_from(path: &Path, label: &str) -> Result<BackupKey, String> {
    let k = config::load_key_file_as(path, label).map_err(|e| e.to_string())?;
    BackupKey::from_slice(&k.0).map_err(|e| e.to_string())
}

/// Re-seals all TOTP secrets from `old` to `new` in one transaction (the testable core).
///
/// # Errors
/// A secret that opens under neither key (nothing is changed), a concurrent change, or a
/// database failure.
pub async fn rotate_totp(
    db: &nzb_store::Store,
    old: &TotpKey,
    new: &TotpKey,
    now: i64,
    dry_run: bool,
) -> Result<ResealReport, String> {
    let mut seal_failed = false;
    let rep = db
        .reseal_totp_secrets(now, dry_run, &mut |id, blob| {
            if let Some(plain) = totp::open(old, id, blob) {
                return if let Ok(b) = totp::seal(new, id, &plain) {
                    Reseal::Sealed(b)
                } else {
                    seal_failed = true;
                    Reseal::Undecryptable
                };
            }
            if totp::open(new, id, blob).is_some() {
                Reseal::AlreadyCurrent
            } else {
                Reseal::Undecryptable
            }
        })
        .await;
    if seal_failed {
        return Err(
            "could not seal a secret (OS randomness unavailable); nothing was changed".into(),
        );
    }
    rep.map_err(|e| e.to_string())
}

fn now_unix() -> Result<i64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock before 1970".to_string())
        .and_then(|d| i64::try_from(d.as_secs()).map_err(|_| "clock out of range".to_string()))
}

/// Runs `nzbd keys ...`.
pub fn run_keys(cfg: &Config, action: KeysAction) -> Result<(), String> {
    let KeysAction::RotateTotp {
        new_key_file,
        dry_run,
        no_backup,
    } = action;
    let old_raw = config::load_key_file(&cfg.security.totp_key_file).map_err(|e| e.to_string())?;
    let new_raw =
        config::load_key_file_as(&new_key_file, "--new-key-file").map_err(|e| e.to_string())?;
    if config::ct_eq(&old_raw.0, &new_raw.0) {
        return Err("--new-key-file holds the same key as security.totp_key_file".into());
    }
    let old = TotpKey::from_slice(&old_raw.0).ok_or("invalid current TOTP key")?;
    let new = TotpKey::from_slice(&new_raw.0).ok_or("invalid new TOTP key")?;
    let backup_key = load_backup_key(cfg)?;
    if let Some(b) = &backup_key
        && b.ct_eq_bytes(&new_raw.0)
    {
        return Err(
            "--new-key-file must differ from maintenance.backup_encryption_key_file".into(),
        );
    }
    if !crate::dbopen::exists(cfg) {
        return Err(format!(
            "database {} does not exist",
            cfg.paths.db.display()
        ));
    }
    let now = now_unix()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    rt.block_on(async {
        let db = crate::dbopen::open(cfg)
            .await
            .map_err(|e| format!("database: {e}"))?;
        if !dry_run && !no_backup {
            // Pre-rotation snapshot of the configured backend, taken before anything can change.
            let rep = db
                .backup(
                    &cfg.paths.backups,
                    now,
                    usize::try_from(cfg.maintenance.keep_backups).unwrap_or(usize::MAX),
                    backup_key.as_ref(),
                )
                .await;
            let rep = match rep {
                Ok(r) => r,
                Err(e) => {
                    db.close().await;
                    return Err(format!("pre-rotation backup: {e}"));
                }
            };
            println!("backup written: {}", rep.path.display());
        }
        let res = rotate_totp(&db, &old, &new, now, dry_run).await;
        db.close().await;
        let rep = res?;
        let verb = if dry_run { "would re-seal" } else { "re-sealed" };
        println!(
            "{verb} {} TOTP secret(s) ({} staged); {} already under the new key; {} user(s) without a secret",
            rep.resealed, rep.staging_resealed, rep.already_current, rep.without_secret
        );
        if !dry_run {
            println!(
                "next: replace {} with the new key file (keep the old one until a login works), then start nzbd",
                cfg.security.totp_key_file.display()
            );
        }
        Ok(())
    })
}

/// Runs `nzbd backup decrypt`.
pub fn run_decrypt(
    cfg: &Config,
    file: &Path,
    out: &Path,
    key_file: Option<&Path>,
) -> Result<(), String> {
    let key = match key_file {
        Some(p) => load_backup_key_from(p, "--key-file")?,
        None => load_backup_key(cfg)?.ok_or_else(|| {
            "no key: set maintenance.backup_encryption_key_file or pass --key-file".to_string()
        })?,
    };
    nzb_store::decrypt_file(&key, file, out).map_err(|e| e.to_string())?;
    println!("decrypted backup written: {}", out.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    fn tkey(b: u8) -> TotpKey {
        TotpKey::from_slice(&[b; 32]).unwrap()
    }

    const SECRET: &[u8; 20] = b"secret-one-20-bytes!";

    async fn db_with_user(
        dir: &tempfile::TempDir,
        k: &TotpKey,
    ) -> (nzb_store::test_backend::TestStore, i64) {
        let ts = nzb_store::test_backend::TestStore::open(dir.path()).await;
        let id = ts.store.create_user("alice", "h", 1).await.unwrap();
        let blob = totp::seal(k, id, SECRET).unwrap();
        ts.store.store_pending_totp(id, &blob, true).await.unwrap();
        (ts, id)
    }

    async fn blob(db: &nzb_store::Store, id: i64) -> Vec<u8> {
        db.get_mfa_state(id)
            .await
            .unwrap()
            .unwrap()
            .totp_secret_enc
            .unwrap()
    }

    #[tokio::test]
    async fn sec_053_rotate_totp_reseals_all_and_new_key_opens_them() {
        let dir = tempfile::tempdir().unwrap();
        let (old, new) = (tkey(1), tkey(2));
        let (ts, id) = db_with_user(&dir, &old).await;
        let db = ts.store.clone();
        let before = blob(&db, id).await;
        let dry = rotate_totp(&db, &old, &new, 10, true).await.unwrap();
        assert_eq!(dry.resealed, 1);
        assert_eq!(blob(&db, id).await, before, "dry run changes nothing");

        let rep = rotate_totp(&db, &old, &new, 11, false).await.unwrap();
        assert_eq!(rep.resealed, 1);
        let after = blob(&db, id).await;
        assert!(totp::open(&old, id, &after).is_none(), "old key is dead");
        assert_eq!(totp::open(&new, id, &after).unwrap().as_slice(), SECRET);
        // The AAD binding to the user id survives the rotation.
        assert!(totp::open(&new, id + 1, &after).is_none());
        // Idempotent re-run (crash after commit, before the key file was swapped).
        let again = rotate_totp(&db, &old, &new, 12, false).await.unwrap();
        assert_eq!((again.resealed, again.already_current), (0, 1));
    }

    #[tokio::test]
    async fn sec_053_wrong_old_key_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (ts, id) = db_with_user(&dir, &tkey(1)).await;
        let db = ts.store.clone();
        let before = blob(&db, id).await;
        let e = rotate_totp(&db, &tkey(7), &tkey(8), 10, false)
            .await
            .unwrap_err();
        assert!(e.contains("neither key"), "{e}");
        assert_eq!(blob(&db, id).await, before);
    }
}
