//! Plaintext metrics (T105; SEC-084): the text rendered by the internal-only listener
//! ([`nzb_web::metrics`]).
//!
//! Only counters and gauges of this process and of the database's aggregate counts. No label ever carries a value
//! from the database or the network: the only labels are the build version (compile-time constant) and the three
//! fixed ingest outcomes. Nothing here is per user, per release, per address or per session, so cardinality is
//! constant and a hostile NZB or account name cannot reach the output. No secret is ever read.

use std::fmt::Write as _;

use crate::health::{DbFacts, LiveFacts, ProcFacts};

/// Everything the renderer needs (gathered without writing to disk).
#[derive(Debug, Clone)]
pub struct MetricsFacts {
    /// Seconds since process start.
    pub uptime: Option<u64>,
    /// Database aggregates (`None` = unreadable).
    pub db: Option<DbFacts>,
    /// `/proc/self` facts.
    pub proc: ProcFacts,
    /// Live ingest counters.
    pub live: Option<LiveFacts>,
    /// Size of the database file.
    pub db_bytes: Option<u64>,
    /// Size of the WAL file.
    pub wal_bytes: Option<u64>,
}

struct Out(String);

impl Out {
    fn metric(&mut self, name: &str, kind: &str, help: &str, value: u64) {
        let _ = writeln!(self.0, "# HELP {name} {help}");
        let _ = writeln!(self.0, "# TYPE {name} {kind}");
        let _ = writeln!(self.0, "{name} {value}");
    }

    fn opt(&mut self, name: &str, kind: &str, help: &str, value: Option<u64>) {
        if let Some(v) = value {
            self.metric(name, kind, help, v);
        }
    }
}

fn flag(b: bool) -> u64 {
    u64::from(b)
}

fn secs(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// Renders the exposition text (format 0.0.4). Pure: a function of `f`.
#[must_use]
#[allow(clippy::too_many_lines)] // a flat list of metric definitions
pub fn render(f: &MetricsFacts) -> String {
    let mut o = Out(String::new());
    let _ = writeln!(o.0, "# HELP nzbd_build_info Build version (constant 1).");
    let _ = writeln!(o.0, "# TYPE nzbd_build_info gauge");
    let _ = writeln!(
        o.0,
        "nzbd_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    );
    o.opt(
        "nzbd_uptime_seconds",
        "gauge",
        "Seconds since the server started.",
        f.uptime,
    );
    o.opt(
        "nzbd_process_resident_memory_bytes",
        "gauge",
        "Resident set size.",
        f.proc.rss_kib.map(|k| k.saturating_mul(1024)),
    );
    o.opt(
        "nzbd_process_open_fds",
        "gauge",
        "Open file descriptors.",
        f.proc.open_fds,
    );
    o.opt(
        "nzbd_db_file_bytes",
        "gauge",
        "Size of the database file.",
        f.db_bytes,
    );
    o.opt(
        "nzbd_db_wal_bytes",
        "gauge",
        "Size of the write-ahead log file.",
        f.wal_bytes,
    );
    if let Some(l) = f.live {
        o.opt(
            "nzbd_ingest_scan_timestamp_seconds",
            "gauge",
            "Unix time of the last completed watch-folder scan.",
            l.heartbeat.map(secs),
        );
        o.opt(
            "nzbd_ingest_last_success_timestamp_seconds",
            "gauge",
            "Unix time of the last indexed or duplicate NZB.",
            l.last_success.map(secs),
        );
        let _ = writeln!(
            o.0,
            "# HELP nzbd_ingest_total NZB files handled since start, by outcome."
        );
        let _ = writeln!(o.0, "# TYPE nzbd_ingest_total counter");
        for (outcome, n) in [
            ("ok", l.ok),
            ("duplicate", l.duplicates),
            ("failed", l.failed),
        ] {
            let _ = writeln!(o.0, "nzbd_ingest_total{{outcome=\"{outcome}\"}} {n}");
        }
        o.metric(
            "nzbd_ingest_commit_groups_total",
            "counter",
            "Commit-group transactions since start (several NZBs each under load).",
            l.commit_groups,
        );
        o.metric(
            "nzbd_ingest_inflight_bytes",
            "gauge",
            "NZB bytes currently held by the ingest pipeline (bounded by ingest.max_inflight_bytes).",
            l.inflight_bytes,
        );
        o.metric(
            "nzbd_ingest_paused_for_index_lag",
            "gauge",
            "1 while the watch-folder scanner waits for the search index to catch up.",
            flag(l.lag_paused),
        );
    }
    if let Some(d) = &f.db {
        o.metric(
            "nzbd_db_writer_up",
            "gauge",
            "1 when the writer connection answers.",
            flag(d.writer_ok),
        );
        o.metric(
            "nzbd_db_reader_up",
            "gauge",
            "1 when a reader connection answers.",
            flag(d.reader_ok),
        );
        if let Some(s) = d.schema {
            o.metric(
                "nzbd_schema_version",
                "gauge",
                "Highest applied migration.",
                secs(s.latest_applied),
            );
        }
        if let Some(t) = d.totals {
            o.metric("nzbd_releases", "gauge", "Indexed releases.", t.releases);
            o.metric("nzbd_files", "gauge", "Indexed NZB files.", t.files);
            o.metric("nzbd_segments", "gauge", "Indexed segments.", t.segments);
            o.metric(
                "nzbd_library_bytes",
                "gauge",
                "Total payload bytes described by the library.",
                t.bytes,
            );
        }
        if let Some(l) = d.logs {
            o.metric(
                "nzbd_audit_log_rows",
                "gauge",
                "Rows in the audit log.",
                l.audit_rows,
            );
            o.metric(
                "nzbd_ingest_log_rows",
                "gauge",
                "Rows in the ingest log.",
                l.ingest_rows,
            );
        }
        if let Some(c) = d.audit_chain {
            o.metric(
                "nzbd_audit_chain_consistent",
                "gauge",
                "1 when the audit chain row counts and head hashes agree with the rows.",
                flag(c.consistent && c.bootstrapped && c.unchained == 0),
            );
            o.metric(
                "nzbd_audit_chain_unchained_rows",
                "gauge",
                "Audit rows without chain columns (0 on a healthy database).",
                c.unchained,
            );
        }
        if let Some(x) = d.outbox {
            o.metric(
                "nzbd_index_outbox_depth",
                "gauge",
                "Changes waiting for the search indexer (outbox sequence span).",
                x.depth,
            );
            o.metric(
                "nzbd_index_lag_seconds",
                "gauge",
                "Age of the oldest change not yet in the search index (database clock).",
                x.lag_secs,
            );
        }
        if let Some(s) = d.security {
            o.metric(
                "nzbd_sessions_active",
                "gauge",
                "Unexpired sessions.",
                s.active_sessions,
            );
            o.metric(
                "nzbd_api_keys_active",
                "gauge",
                "API keys that are not revoked.",
                s.active_api_keys,
            );
            o.metric(
                "nzbd_accounts_live",
                "gauge",
                "Live (non-tombstoned) accounts.",
                s.live_accounts,
            );
            o.metric(
                "nzbd_accounts_throttled",
                "gauge",
                "Accounts whose second-factor throttle is in force.",
                s.throttled_accounts,
            );
            o.metric(
                "nzbd_failed_logins_24h",
                "gauge",
                "Failed password and second-factor attempts in the last 24 hours.",
                s.failed_logins_recent,
            );
        }
    }
    o.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use nzb_store::{ChainQuick, LogCounts, PoolInfo, ReleaseTotals, SchemaInfo, SecurityFacts};

    fn facts() -> MetricsFacts {
        MetricsFacts {
            uptime: Some(42),
            db: Some(DbFacts {
                writer_ok: true,
                reader_ok: true,
                schema: Some(SchemaInfo {
                    latest_applied: 13,
                    applied: 12,
                    embedded_latest: 13,
                    embedded: 12,
                }),
                totals: Some(ReleaseTotals {
                    releases: 10,
                    files: 20,
                    segments: 30,
                    bytes: 40,
                }),
                logs: Some(LogCounts {
                    ingest_rows: 5,
                    audit_rows: 6,
                    ingest_oldest: None,
                    ingest_newest: None,
                }),
                pools: PoolInfo {
                    writer_open: 1,
                    readers_open: 1,
                    readers_idle: 1,
                    readers_max: 4,
                    closed: false,
                },
                security: Some(SecurityFacts {
                    user_exists: true,
                    totp_enabled: true,
                    failed_logins: 0,
                    locked: false,
                    active_sessions: 3,
                    active_api_keys: 1,
                    failed_logins_recent: 2,
                    live_accounts: 4,
                    reserved_names: 0,
                    throttled_accounts: 0,
                }),
                last_ok_ingest: None,
                audit_chain: Some(ChainQuick {
                    rows: 6,
                    unchained: 0,
                    consistent: true,
                    bootstrapped: true,
                }),
                outbox: Some(nzb_store::OutboxLag {
                    depth: 12,
                    lag_secs: 3,
                }),
            }),
            proc: ProcFacts {
                rss_kib: Some(100),
                open_fds: Some(9),
                fd_limit: None,
            },
            live: Some(LiveFacts {
                heartbeat: Some(1000),
                ok: 7,
                duplicates: 1,
                failed: 2,
                last_success: Some(990),
                commit_groups: 4,
                inflight_bytes: 2048,
                lag_paused: true,
            }),
            db_bytes: Some(4096),
            wal_bytes: None,
        }
    }

    #[test]
    fn sec_084_metrics_are_numbers_with_fixed_names_and_bounded_labels() {
        let text = render(&facts());
        let mut names = std::collections::BTreeSet::new();
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            let (series, value) = line.rsplit_once(' ').unwrap();
            assert!(value.parse::<u64>().is_ok(), "{line}");
            let name = series.split('{').next().unwrap();
            assert!(name.starts_with("nzbd_"), "{line}");
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{line}"
            );
            // Every label is one of the three allowed shapes.
            if let Some(l) = series.strip_prefix(name).filter(|l| !l.is_empty()) {
                assert!(
                    l == "{outcome=\"ok\"}"
                        || l == "{outcome=\"duplicate\"}"
                        || l == "{outcome=\"failed\"}"
                        || l == format!("{{version=\"{}\"}}", env!("CARGO_PKG_VERSION")),
                    "{line}"
                );
            }
            names.insert(name.to_owned());
        }
        assert!(names.contains("nzbd_audit_chain_consistent"));
        assert!(names.contains("nzbd_releases"));
        // T114: index lag and ingest scale facts.
        assert!(text.contains("nzbd_index_outbox_depth 12\n"));
        assert!(text.contains("nzbd_index_lag_seconds 3\n"));
        assert!(text.contains("nzbd_ingest_commit_groups_total 4\n"));
        assert!(text.contains("nzbd_ingest_inflight_bytes 2048\n"));
        assert!(text.contains("nzbd_ingest_paused_for_index_lag 1\n"));
        // No secret-bearing facts exist in the input type, and the text is plain ASCII.
        assert!(text.is_ascii());
        assert!(text.contains("nzbd_audit_chain_consistent 1\n"));
    }

    /// SEC-083: the shipped proxy configuration has exactly one upstream, the application listener, so the metrics
    /// listener (a different port, a different socket) has no route through the proxy.
    #[test]
    fn sec_083_proxy_caddyfile_exposes_no_path_to_the_metrics_listener() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy");
        let caddy = std::fs::read_to_string(dir.join("Caddyfile")).unwrap();
        let upstreams: Vec<&str> = caddy
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("reverse_proxy"))
            .collect();
        assert!(upstreams.len() >= 2, "{upstreams:?}");
        for u in upstreams {
            assert!(u.starts_with("reverse_proxy nzbd:8080"), "{u}");
        }
        assert!(!caddy.to_lowercase().contains("metrics"));
        // Structural: a `ports:` key only under the `proxy` service, and no metrics env shipped enabled.
        for f in ["compose.yaml", "compose.external-proxy.yaml"] {
            let y = std::fs::read_to_string(dir.join("compose-example").join(f)).unwrap();
            assert!(ports_only_on_proxy(&y), "{f}");
            assert!(!y.contains("NZBD__metrics__"), "{f}");
        }
        // Negative controls: the parser does flag a published port on the app service.
        assert!(!ports_only_on_proxy(
            "services:\n  nzbd:\n    ports:\n      - \"9100:9100\"\n  proxy:\n    ports: []\n"
        ));
        assert!(ports_only_on_proxy(
            "services:\n  nzbd:\n    image: x\n  proxy:\n    ports:\n      - \"8443:8443\"\n"
        ));
    }

    /// True when no service other than `proxy` has a `ports:` key (2-space services, 4-space keys).
    fn ports_only_on_proxy(yaml: &str) -> bool {
        let mut in_services = false;
        let mut svc = "";
        for l in yaml.lines() {
            if l.starts_with("services:") {
                in_services = true;
            } else if l.starts_with(|c: char| c.is_ascii_alphabetic()) {
                in_services = false;
            } else if in_services {
                if l.starts_with("  ") && !l.starts_with("   ") && l.trim_end().ends_with(':') {
                    svc = l.trim().trim_end_matches(':');
                } else if l.starts_with("    ports:") && svc != "proxy" {
                    return false;
                }
            }
        }
        true
    }

    #[test]
    fn sec_084_an_inconsistent_chain_is_visible_as_zero() {
        let mut f = facts();
        if let Some(d) = f.db.as_mut()
            && let Some(c) = d.audit_chain.as_mut()
        {
            c.consistent = false;
        }
        assert!(render(&f).contains("nzbd_audit_chain_consistent 0\n"));
    }
}
