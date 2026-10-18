//! Maintenance of the blob store (T080): [`BlobMaintenance`] is what `store verify`, `store gc`, `store gc-restore`,
//! startup recovery and the health engine need beyond [`NzbStore`]. v3 keeps NZB files on the filesystem only
//! ([`FsStore`], D36 a / D37); the 2.x in-database blob store and the read-through pair over both are removed.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use nzb_core::Sha256;

use crate::fs_store::{GcCandidate, GcReport, NzbStore, PutOutcome, VerifyReport};
use crate::prelude::*;
use crate::{FsStore, StoreError};

/// Verification and garbage collection of the blob store.
#[async_trait]
pub trait BlobMaintenance: NzbStore {
    /// The subset of `shas` that has no blob (the quick consistency check: every blob referenced
    /// by a release row must exist). Never fails on a missing blob.
    async fn missing(&self, shas: Vec<Sha256>) -> Result<Vec<Sha256>, StoreError>;

    /// Re-hashes every stored blob. Read-only: corrupt blobs are reported, never modified. With a
    /// `deadline` the pass stops early and sets [`VerifyReport::incomplete`] (the file backend
    /// ignores it: its walk is bounded by the directory tree).
    async fn verify(&self, deadline: Option<Duration>) -> Result<VerifyReport, StoreError>;

    /// Unreferenced blobs older than `cutoff` (what a non-dry [`BlobMaintenance::gc_orphans`] would
    /// quarantine).
    async fn gc_candidates(
        &self,
        referenced: &HashSet<Sha256>,
        cutoff: SystemTime,
    ) -> Result<Vec<GcCandidate>, StoreError>;

    /// Quarantines (never deletes) blobs no release references that are older than `cutoff`,
    /// re-checking the release table for each blob right before it moves and failing closed.
    async fn gc_orphans(
        &self,
        db: &crate::Store,
        cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StoreError>;

    /// Number of blobs in the GC quarantine.
    async fn gc_trash_len(&self) -> Result<usize, StoreError>;

    /// Puts quarantined blobs back; returns how many were restored.
    async fn restore_gc_trash(&self) -> Result<usize, StoreError>;

    /// Permanently deletes quarantined blobs quarantined before `older_than`. The only place
    /// GC data is ever destroyed; never called at startup.
    async fn purge_gc_trash(&self, older_than: SystemTime) -> Result<usize, StoreError>;
}

fn join_err(e: &tokio::task::JoinError) -> StoreError {
    StoreError::Io(std::io::Error::other(e.to_string()))
}

#[async_trait]
impl BlobMaintenance for FsStore {
    async fn missing(&self, shas: Vec<Sha256>) -> Result<Vec<Sha256>, StoreError> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || FsStore::missing(&this, shas))
            .await
            .map_err(|e| join_err(&e))?
    }

    async fn verify(&self, _deadline: Option<Duration>) -> Result<VerifyReport, StoreError> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || FsStore::verify(&this))
            .await
            .map_err(|e| join_err(&e))?
    }

    async fn gc_candidates(
        &self,
        referenced: &HashSet<Sha256>,
        cutoff: SystemTime,
    ) -> Result<Vec<GcCandidate>, StoreError> {
        let (this, referenced) = (self.clone(), referenced.clone());
        tokio::task::spawn_blocking(move || FsStore::gc_candidates(&this, &referenced, cutoff))
            .await
            .map_err(|e| join_err(&e))?
    }

    async fn gc_orphans(
        &self,
        db: &crate::Store,
        cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StoreError> {
        let referenced = db.list_shas().await?;
        let (db, this) = (db.clone(), self.clone());
        let handle = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            this.gc_checked(&referenced, cutoff, dry_run, &|sha| {
                // Runs on a blocking thread, so `block_on` is allowed. A database error keeps
                // the blob (fail closed).
                matches!(
                    handle.block_on(db.get_release_by_sha(&sha.to_hex())),
                    Ok(None)
                )
            })
        })
        .await
        .map_err(|e| join_err(&e))?
    }

    async fn gc_trash_len(&self) -> Result<usize, StoreError> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || FsStore::gc_trash_len(&this))
            .await
            .map_err(|e| join_err(&e))?
    }

    async fn restore_gc_trash(&self) -> Result<usize, StoreError> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || FsStore::restore_gc_trash(&this))
            .await
            .map_err(|e| join_err(&e))?
    }

    async fn purge_gc_trash(&self, older_than: SystemTime) -> Result<usize, StoreError> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || FsStore::purge_gc_trash(&this, older_than))
            .await
            .map_err(|e| join_err(&e))?
    }
}

/// `Arc<T>` is a store/maintainer wherever `T` is (shared handles are passed around as `Arc`).
#[async_trait]
impl<T: NzbStore + ?Sized> NzbStore for Arc<T> {
    async fn put(&self, sha: Sha256, bytes: &[u8]) -> Result<PutOutcome, StoreError> {
        (**self).put(sha, bytes).await
    }
    async fn get(&self, sha: &Sha256) -> Result<Vec<u8>, StoreError> {
        (**self).get(sha).await
    }
    async fn exists(&self, sha: &Sha256) -> Result<bool, StoreError> {
        (**self).exists(sha).await
    }
    async fn delete(&self, sha: &Sha256) -> Result<(), StoreError> {
        (**self).delete(sha).await
    }
}

#[async_trait]
impl<T: BlobMaintenance + ?Sized> BlobMaintenance for Arc<T> {
    async fn missing(&self, shas: Vec<Sha256>) -> Result<Vec<Sha256>, StoreError> {
        (**self).missing(shas).await
    }
    async fn verify(&self, deadline: Option<Duration>) -> Result<VerifyReport, StoreError> {
        (**self).verify(deadline).await
    }
    async fn gc_candidates(
        &self,
        referenced: &HashSet<Sha256>,
        cutoff: SystemTime,
    ) -> Result<Vec<GcCandidate>, StoreError> {
        (**self).gc_candidates(referenced, cutoff).await
    }
    async fn gc_orphans(
        &self,
        db: &crate::Store,
        cutoff: SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StoreError> {
        (**self).gc_orphans(db, cutoff, dry_run).await
    }
    async fn gc_trash_len(&self) -> Result<usize, StoreError> {
        (**self).gc_trash_len().await
    }
    async fn restore_gc_trash(&self) -> Result<usize, StoreError> {
        (**self).restore_gc_trash().await
    }
    async fn purge_gc_trash(&self, older_than: SystemTime) -> Result<usize, StoreError> {
        (**self).purge_gc_trash(older_than).await
    }
}
