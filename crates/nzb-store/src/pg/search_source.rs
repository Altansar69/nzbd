//! The store side of the search index on Postgres (T122; `crate::search_source` has the contract and the SQLite
//! twin). Reads run on the `background` pool (the indexer's), hydration and the degraded browse on the `web` pool.

use futures_util::TryStreamExt as _;
use sqlx::Row as _;

use super::release::{release_cols, release_from_row};
use crate::StoreError;
use crate::pg::PgDb;
use crate::search_source::{
    IndexRow, OutboxEntry, OutboxLag, SearchSourceState, cut_utf8, doc_bytes, file_rows_for,
    sql_len,
};

fn u32_of(v: i32, what: &'static str) -> Result<u32, StoreError> {
    u32::try_from(v).map_err(|_| StoreError::OutOfRange(what))
}

fn index_row(row: &sqlx::postgres::PgRow, max_file_bytes: usize) -> Result<IndexRow, StoreError> {
    Ok(IndexRow {
        release: release_from_row(row)?,
        files: cut_utf8(
            row.try_get::<Option<String>, _>("files")?
                .unwrap_or_default(),
            max_file_bytes,
        ),
        category_parent: u32_of(row.try_get("cat_parent")?, "category parent")?,
        version: u64::try_from(row.try_get::<i64, _>("index_version")?)
            .map_err(|_| StoreError::OutOfRange("index_version"))?,
        added_by: row.try_get("added_by")?,
    })
}

/// `left()` takes an `integer` length.
fn pg_len(max_file_bytes: usize) -> i32 {
    i32::try_from(sql_len(max_file_bytes)).unwrap_or(i32::MAX)
}

/// The document columns: the release, its uploader and index version, the category parent and the bounded file-name
/// aggregate (`$2` characters at most, of at most `$3` file rows).
macro_rules! pg_index_select {
    () => {
        concat!(
            "SELECT ",
            release_cols!(),
            ", r.added_by, r.index_version, coalesce(c.parent_id, r.category_id) AS cat_parent, \
             (SELECT left(string_agg(f.filename, ' ' ORDER BY f.idx), $2) \
                FROM (SELECT filename, idx FROM nzb_file \
                       WHERE release_id = r.id AND filename IS NOT NULL ORDER BY idx LIMIT $3) f) AS files \
             FROM release r LEFT JOIN category c ON c.id = r.category_id "
        )
    };
}

impl PgDb {
    /// Outbox depth and the age of its oldest row (index lag), by the database clock.
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_outbox_lag(&self) -> Result<OutboxLag, StoreError> {
        let (span, age): (i64, i64) = sqlx::query_as(
            "SELECT coalesce((SELECT max(seq) FROM search_outbox) - (SELECT min(seq) FROM search_outbox) + 1, 0), \
             coalesce(nzbd.db_clock() - (SELECT enqueued_at FROM search_outbox ORDER BY seq LIMIT 1), 0)",
        )
        .fetch_one(self.background())
        .await?;
        Ok(OutboxLag::from_row(span, age))
    }

    /// The oldest `limit` outbox rows, ascending sequence.
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_outbox_read(&self, limit: usize) -> Result<Vec<OutboxEntry>, StoreError> {
        let rows: Vec<(i64, i64)> =
            sqlx::query_as("SELECT seq, release_id FROM search_outbox ORDER BY seq LIMIT $1")
                .bind(i64::try_from(limit).unwrap_or(i64::MAX))
                .fetch_all(self.background())
                .await?;
        Ok(rows
            .into_iter()
            .map(|(seq, release_id)| OutboxEntry { seq, release_id })
            .collect())
    }

    /// The current documents of `ids` in one snapshot, file names cut to `max_file_bytes` bytes.
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_index_load(
        &self,
        ids: &[i64],
        max_file_bytes: usize,
    ) -> Result<Vec<IndexRow>, StoreError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut conn = self.background().acquire().await?;
        let mut rows = sqlx::query(concat!(
            pg_index_select!(),
            "WHERE r.id = ANY($1) ORDER BY r.id"
        ))
        .bind(ids)
        .bind(pg_len(max_file_bytes))
        .bind(file_rows_for(max_file_bytes))
        .fetch(&mut *conn);
        let mut out = Vec::new();
        while let Some(row) = rows.try_next().await? {
            out.push(index_row(&row, max_file_bytes)?);
        }
        Ok(out)
    }

    /// Documents with `id > after_id`, ascending, at most `limit`, stopping once their text reaches `max_bytes`.
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_index_scan(
        &self,
        after_id: i64,
        limit: usize,
        max_bytes: usize,
        max_file_bytes: usize,
    ) -> Result<Vec<IndexRow>, StoreError> {
        let mut conn = self.background().acquire().await?;
        let mut rows = sqlx::query(concat!(
            pg_index_select!(),
            "WHERE r.id > $1 ORDER BY r.id LIMIT $4"
        ))
        .bind(after_id)
        .bind(pg_len(max_file_bytes))
        .bind(file_rows_for(max_file_bytes))
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch(&mut *conn);
        let mut out = Vec::new();
        let mut bytes = 0_usize;
        while let Some(row) = rows.try_next().await? {
            let r = index_row(&row, max_file_bytes)?;
            bytes = bytes.saturating_add(doc_bytes(&r));
            out.push(r);
            if bytes >= max_bytes {
                break;
            }
        }
        Ok(out)
    }

    /// One transaction: deletes exactly the outbox rows `seqs` and, when `search_state.replay` (read inside this
    /// transaction) is set, records `ids` in `search_replay`.
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_outbox_consume(&self, seqs: &[i64], ids: &[i64]) -> Result<(), StoreError> {
        let mut tx = self.background().begin().await?;
        let replay: bool = sqlx::query_scalar("SELECT replay FROM search_state WHERE id = 1")
            .fetch_one(&mut *tx)
            .await?;
        if replay {
            sqlx::query(
                "INSERT INTO search_replay (release_id) SELECT unnest($1::bigint[]) ON CONFLICT DO NOTHING",
            )
            .bind(ids)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("DELETE FROM search_outbox WHERE seq = ANY($1)")
            .bind(seqs)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Records a release the indexer could not index (fixed error code).
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_quarantine(&self, release_id: i64, code: &str) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO search_quarantine (release_id, error_code, at) VALUES ($1, $2, nzbd.db_clock()) \
             ON CONFLICT (release_id) DO NOTHING",
        )
        .bind(release_id)
        .bind(code)
        .execute(self.background())
        .await?;
        Ok(())
    }

    /// Epoch, outbox position, replay and rebuild flags.
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_source_state(&self) -> Result<SearchSourceState, StoreError> {
        let row = sqlx::query(
            "SELECT epoch, replay, rebuild_requested_at, rebuild_generation, \
             (SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM nzbd.search_outbox_seq_seq) AS last_seq \
             FROM search_state WHERE id = 1",
        )
        .fetch_one(self.background())
        .await?;
        let epoch: Vec<u8> = row.try_get("epoch")?;
        Ok(SearchSourceState {
            epoch: <[u8; 16]>::try_from(epoch)
                .map_err(|_| StoreError::OutOfRange("search epoch"))?,
            outbox_last_seq: row.try_get("last_seq")?,
            replay: row.try_get("replay")?,
            rebuild_requested: row
                .try_get::<Option<i64>, _>("rebuild_requested_at")?
                .is_some(),
            finished_generation: u64::try_from(row.try_get::<i32, _>("rebuild_generation")?)
                .map_err(|_| StoreError::OutOfRange("rebuild generation"))?,
        })
    }

    /// Sets the replay flag and commits, before a rebuild scan reads anything.
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_begin_rebuild(&self) -> Result<(), StoreError> {
        sqlx::query("UPDATE search_state SET replay = true WHERE id = 1")
            .execute(self.background())
            .await?;
        Ok(())
    }

    /// Ids in `search_replay` above `after_id`, ascending, at most `limit`.
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_replay_ids(
        &self,
        after_id: i64,
        limit: usize,
    ) -> Result<Vec<i64>, StoreError> {
        Ok(sqlx::query_scalar(
            "SELECT release_id FROM search_replay WHERE release_id > $1 ORDER BY release_id LIMIT $2",
        )
        .bind(after_id)
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(self.background())
        .await?)
    }

    /// One transaction: clears replay and the rebuild request, records `generation`, empties `search_replay` (the app
    /// role has no `TRUNCATE`).
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_finish_rebuild(&self, generation: u64) -> Result<(), StoreError> {
        let g = i32::try_from(generation).map_err(|_| StoreError::OutOfRange("generation"))?;
        let mut tx = self.background().begin().await?;
        sqlx::query(
            "UPDATE search_state SET replay = false, rebuild_requested_at = NULL, rebuild_generation = $1 \
             WHERE id = 1",
        )
        .bind(g)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM search_replay")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// `nzbd search rebuild`: asks the indexer of the running `serve` for a rebuild.
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_request_rebuild(&self, now: i64) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE search_state SET rebuild_requested_at = coalesce(rebuild_requested_at, $1) WHERE id = 1",
        )
        .bind(now)
        .execute(self.background())
        .await?;
        Ok(())
    }

    /// `(category id, releases)` of every category with at least one release (exact, from `category_stats`).
    ///
    /// # Errors
    /// Database errors.
    pub async fn category_totals(&self) -> Result<Vec<(u32, u64)>, StoreError> {
        let rows: Vec<(i32, i64)> = sqlx::query_as(
            "SELECT category_id, releases FROM category_stats WHERE releases > 0 ORDER BY category_id",
        )
        .fetch_all(self.web())
        .await?;
        rows.into_iter()
            .map(|(c, n)| {
                Ok((
                    u32_of(c, "category_id")?,
                    u64::try_from(n).map_err(|_| StoreError::OutOfRange("releases"))?,
                ))
            })
            .collect()
    }

    /// Quarantined release ids, for `nzbd search status` (bounded by `limit`).
    ///
    /// # Errors
    /// Database errors.
    pub async fn search_quarantined(
        &self,
        limit: u32,
    ) -> Result<std::collections::BTreeSet<i64>, StoreError> {
        let ids: Vec<i64> = sqlx::query_scalar(
            "SELECT release_id FROM search_quarantine ORDER BY release_id LIMIT $1",
        )
        .bind(i64::from(limit))
        .fetch_all(self.background())
        .await?;
        Ok(ids.into_iter().collect())
    }
}
