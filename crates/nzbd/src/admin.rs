//! Wiring of the `/admin` page (T048): turns the typed configuration and the ingest handles
//! into the plain, non-secret values `nzb_web::admin` renders.

use std::sync::{Arc, OnceLock};

use nzb_ingest as ing;
use nzb_web::admin::{AdminDeps, FAILED_ROWS, FailedItem, FailedListing, LiveStatus};

use crate::config::{Config, DuplicatesAction};

/// Non-secret configuration rows. Built field by field from typed values so a secret cannot be
/// added by accident: the TOTP key is only reported as configured (never its path or content).
pub fn config_summary(cfg: &Config) -> Vec<(&'static str, String)> {
    let yes_no = |b: bool| if b { "yes" } else { "no" }.to_owned();
    let proxies = if cfg.server.trusted_proxies.is_empty() {
        "none".to_owned()
    } else {
        cfg.server
            .trusted_proxies
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let retention = match cfg.ingest.failed_retention_days {
        0 => "keep forever".to_owned(),
        d => format!("{d} days"),
    };
    vec![
        ("Listen address", cfg.server.listen.to_string()),
        ("Trusted proxies", proxies),
        (
            "Extra allowed hosts",
            cfg.server.allowed_hosts.len().to_string(),
        ),
        ("Plain-HTTP cookies", yes_no(cfg.server.insecure_cookies)),
        ("Watch folder", cfg.paths.watch.display().to_string()),
        ("Blob store", cfg.paths.store.display().to_string()),
        ("Failed folder", cfg.paths.failed.display().to_string()),
        (
            "Duplicates folder",
            cfg.paths.duplicates.display().to_string(),
        ),
        (
            "Scan interval",
            format!("{} s", cfg.ingest.scan_interval_secs),
        ),
        ("Stable time", format!("{} s", cfg.ingest.stable_secs)),
        ("Workers", cfg.ingest.effective_workers().to_string()),
        ("Ingest queue", cfg.ingest.queue_cap.to_string()),
        (
            "Commit group",
            format!(
                "{} NZBs / {} ms",
                cfg.ingest.group_max_jobs, cfg.ingest.group_window_ms
            ),
        ),
        ("Recursive watch", yes_no(cfg.ingest.recursive)),
        (
            "Duplicates action",
            match cfg.ingest.duplicates_action {
                DuplicatesAction::Move => "move",
                DuplicatesAction::Delete => "delete",
            }
            .to_owned(),
        ),
        ("Failed-file retention", retention),
        (
            "Max NZB size",
            format!("{} bytes", cfg.limits.max_file_bytes),
        ),
        (
            "Parse deadline",
            format!("{} s", cfg.limits.parse_deadline_secs),
        ),
        (
            "Session idle timeout",
            format!("{} min", cfg.security.session_idle_mins),
        ),
        (
            "Session lifetime",
            format!("{} h", cfg.security.session_max_hours),
        ),
        ("TOTP encryption key", "configured".to_owned()),
        ("Durable database writes", "yes (always)".to_owned()),
    ]
}

/// Lists `failed/` for the page: newest first, reduced to displayable fields. Symlinks, foreign
/// names and sidecars are already ignored by `list_failed`.
fn list_failed(dir: &std::path::Path) -> Result<FailedListing, ()> {
    let mut all = ing::list_failed(dir).map_err(|_| ())?;
    all.reverse();
    let total = all.len();
    let items = all
        .into_iter()
        .take(FAILED_ROWS)
        .map(|e| FailedItem {
            name: e.name,
            code: e.reason.as_ref().map(|r| r.error_code.clone()),
            at: e.reason.as_ref().map(|r| r.at),
            size: e.size,
        })
        .collect();
    Ok(FailedListing { total, items })
}

/// Dependencies of the admin routes. `pipeline` is filled by `start_ingest` once the workers run.
pub fn deps(
    cfg: &Config,
    db: &nzb_store::Store,
    heartbeat: ing::Heartbeat,
    pipeline: Arc<OnceLock<ing::Pipeline>>,
) -> AdminDeps {
    let interval = cfg.ingest.scan_interval_secs;
    let workers = cfg.ingest.effective_workers();
    let failed_dir = cfg.paths.failed.clone();
    AdminDeps {
        db: db.clone(),
        clock: Arc::new(nzb_web::auth::SystemWallClock),
        status: Arc::new(move || {
            let stats = pipeline.get().map(ing::Pipeline::stats);
            LiveStatus {
                heartbeat_last: heartbeat.last(),
                scan_interval_secs: interval,
                ingested_ok: stats.map_or(0, |s| s.ingested_ok),
                duplicates: stats.map_or(0, |s| s.duplicates),
                failed: stats.map_or(0, |s| s.failed),
                last_success_at: stats.map(|s| s.last_success_at).filter(|t| *t > 0),
                workers,
            }
        }),
        failed: Some(Arc::new(move || list_failed(&failed_dir))),
        config: Arc::new(config_summary(cfg)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_never_mentions_the_key_file() {
        let mut cfg = Config::default();
        cfg.security.totp_key_file = "/run/secrets/very-secret-key-path".into();
        let text = format!("{:?}", config_summary(&cfg));
        assert!(!text.contains("very-secret-key-path"));
        assert!(text.contains("configured"));
    }

    #[test]
    fn failed_listing_ignores_symlinks_and_foreign_names() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path();
        std::fs::write(p.join("20240101T000000Z-deadbeef.nzb"), b"12345").unwrap();
        std::fs::write(p.join("20240102T000000Z-cafebabe.nzb"), b"1").unwrap();
        std::fs::write(p.join("evil<script>.nzb"), b"x").unwrap();
        std::fs::write(p.join("secret.txt"), b"x").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", p.join("20240103T000000Z-00000000.nzb")).unwrap();
        std::fs::create_dir(p.join("20240104T000000Z-11111111.nzb")).unwrap();
        let l = list_failed(p).unwrap();
        assert_eq!(l.total, 2);
        let names: Vec<_> = l.items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "20240102T000000Z-cafebabe.nzb",
                "20240101T000000Z-deadbeef.nzb"
            ]
        );
        assert_eq!(l.items[1].size, 5);
        assert!(l.items[0].code.is_none());
        assert!(list_failed(&p.join("missing")).is_err());
    }
}
