//! Persistent WAN history + event log in SQLite, in a DB separate from
//! device-metrics. Two concerns share one store because both are small, global,
//! append-mostly time series with the same open/prune machinery:
//!
//! - **WAN history** — periodic speedtest and ISP-balance readings (the cron jobs
//!   in `state.rs` already compute these; here they are also persisted over time).
//!   Internet availability is NOT stored as a per-minute series; its ups and downs
//!   are recorded as `internet_up`/`internet_down` events instead (transitions are
//!   what matters, and that avoids ~1440 boolean points per day).
//! - **Event log** — notable events (internet up/down, low balance, new device,
//!   blacklist add/remove, disconnect) surfaced at `GET /api/v1/admin/events`.
//!
//! Design mirrors `device_metrics.rs`: a single write `Connection` behind a
//! `Mutex`, short-lived read connections (WAL), and best-effort writes (callers in
//! cron jobs log and swallow errors so history never breaks the primary work).

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde::Serialize;
use slog_scope::error;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

const SCHEMA_VERSION: i64 = 1;
const SECONDS_PER_DAY: i64 = 86_400;
/// SQLite `busy_timeout` for both the writer and short-lived readers.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Event `kind` values. Shared by `record_event` (producers) and the
/// `/admin/events` filter whitelist (consumer), so the two can never drift apart.
pub mod kind {
    pub const INTERNET_UP: &str = "internet_up";
    pub const INTERNET_DOWN: &str = "internet_down";
    pub const LOW_BALANCE: &str = "low_balance";
    pub const NEW_DEVICE: &str = "new_device";
    pub const BLACKLIST_ADD: &str = "blacklist_add";
    pub const BLACKLIST_REMOVE: &str = "blacklist_remove";
    pub const DISCONNECT: &str = "disconnect";
    pub const SHAPER_RESET: &str = "shaper_reset";

    /// All known kinds, for validating the `/admin/events?kind=` filter.
    pub const ALL: &[&str] = &[
        INTERNET_UP,
        INTERNET_DOWN,
        LOW_BALANCE,
        NEW_DEVICE,
        BLACKLIST_ADD,
        BLACKLIST_REMOVE,
        DISCONNECT,
        SHAPER_RESET,
    ];

    /// Whether `k` is a known event kind (used to reject `?kind=` junk with 400).
    pub fn is_valid(k: &str) -> bool {
        ALL.contains(&k)
    }
}

/// Append an event to the log if `history` is enabled, swallowing (but logging) any
/// error. The single best-effort entry point shared by every producer (cron jobs and
/// admin handlers) so the "if enabled -> record -> log on failure" pattern and the
/// error-message format live in exactly one place.
pub fn record_event_best_effort(
    history: Option<&HistoryStore>,
    kind: &str,
    mac: Option<&str>,
    detail: Option<&str>,
) {
    if let Some(h) = history {
        if let Err(err) = h.record_event(chrono::Utc::now().timestamp(), kind, mac, detail) {
            error!("history: record event {kind} failed: {err:#}");
        }
    }
}

/// The internet-availability transition implied by a new ping result, or `None` if
/// nothing changed. A `None` previous reading (first run after a fresh install)
/// yields `None` — we don't emit a spurious event for the very first sample.
pub fn net_transition(old: Option<bool>, new: bool) -> Option<&'static str> {
    match old {
        Some(prev) if prev != new => Some(if new {
            kind::INTERNET_UP
        } else {
            kind::INTERNET_DOWN
        }),
        _ => None,
    }
}

/// Whether the balance just crossed from at-or-above the threshold to below it.
/// A `None` previous reading yields `false` (no transition on the first sample),
/// and a balance that was already below the threshold yields `false` (so the event
/// fires once on the way down, not every tick while it stays low).
pub fn balance_crossed_low(prev: Option<f64>, new: f64, threshold: f64) -> bool {
    matches!(prev, Some(p) if p >= threshold) && new < threshold
}

/// One persisted speedtest reading (`ts` = unix sec UTC).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SpeedtestPoint {
    pub ts: i64,
    pub download: f64,
    pub upload: f64,
    pub ping: f64,
}

/// One persisted balance reading (`ts` = unix sec UTC).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct BalancePoint {
    pub ts: i64,
    pub balance: f64,
}

/// One event-log row.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EventRow {
    pub id: i64,
    pub ts: i64,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

pub struct HistoryStore {
    path: PathBuf,
    write: Mutex<Connection>,
    /// Drop rows older than this many days on each write. `<= 0` disables pruning.
    retention_days: i64,
}

fn configure(conn: &Connection) -> Result<()> {
    conn.busy_timeout(BUSY_TIMEOUT)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
    Ok(())
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS wan_speedtest (
            ts INTEGER PRIMARY KEY,
            download REAL NOT NULL,
            upload REAL NOT NULL,
            ping REAL NOT NULL
         );
         CREATE TABLE IF NOT EXISTS wan_balance (
            ts INTEGER PRIMARY KEY,
            balance REAL NOT NULL
         );
         CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            ts INTEGER NOT NULL,
            kind TEXT NOT NULL,
            mac TEXT,
            detail TEXT
         );
         CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);",
    )?;
    // Fresh-only schema: every table is created above, so a version bump is all
    // that's needed. No ALTERs yet (kept for symmetry / future migrations).
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < SCHEMA_VERSION {
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }
    Ok(())
}

impl HistoryStore {
    /// Open (creating parent dirs + file if needed) and initialize the schema.
    ///
    /// # Errors
    /// Returns an error if the parent dir cannot be created, the DB cannot be
    /// opened, or the PRAGMA/schema setup fails.
    pub fn open(path: &Path, retention_days: i64) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {parent:?}"))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open history DB {path:?}"))?;
        configure(&conn)?;
        init_schema(&conn)?;
        Ok(Self {
            path: path.to_path_buf(),
            write: Mutex::new(conn),
            retention_days,
        })
    }

    fn read_conn(&self) -> Result<Connection> {
        let conn = Connection::open(&self.path)
            .with_context(|| format!("failed to open history DB {:?}", self.path))?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        Ok(conn)
    }

    /// Drop rows older than the retention window from all tables. Cheap (indexed /
    /// PK range delete) and run on every write.
    fn prune_locked(&self, conn: &Connection, now: i64) -> Result<()> {
        if self.retention_days <= 0 {
            return Ok(());
        }
        // `saturating_*` so an absurd retention can't overflow the cutoff.
        let cutoff = now.saturating_sub(self.retention_days.saturating_mul(SECONDS_PER_DAY));
        for table in ["wan_speedtest", "wan_balance", "events"] {
            conn.execute(
                &format!("DELETE FROM {table} WHERE ts < ?1"),
                params![cutoff],
            )?;
        }
        Ok(())
    }

    fn writer(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A panicking write rolls back, so recovering a poisoned guard is safe.
        self.write.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record a speedtest reading. `ON CONFLICT(ts)` keeps the last value for a
    /// given second (two readings in one second are vanishingly rare).
    pub fn record_speedtest(&self, now: i64, download: f64, upload: f64, ping: f64) -> Result<()> {
        let conn = self.writer();
        conn.execute(
            "INSERT INTO wan_speedtest (ts, download, upload, ping) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(ts) DO UPDATE SET
               download = excluded.download, upload = excluded.upload, ping = excluded.ping",
            params![now, download, upload, ping],
        )?;
        self.prune_locked(&conn, now)?;
        Ok(())
    }

    /// Record a balance reading (last-wins per second).
    pub fn record_balance(&self, now: i64, balance: f64) -> Result<()> {
        let conn = self.writer();
        conn.execute(
            "INSERT INTO wan_balance (ts, balance) VALUES (?1, ?2)
             ON CONFLICT(ts) DO UPDATE SET balance = excluded.balance",
            params![now, balance],
        )?;
        self.prune_locked(&conn, now)?;
        Ok(())
    }

    /// Append an event. `kind` should be one of [`kind::ALL`].
    pub fn record_event(
        &self,
        now: i64,
        kind: &str,
        mac: Option<&str>,
        detail: Option<&str>,
    ) -> Result<()> {
        let conn = self.writer();
        conn.execute(
            "INSERT INTO events (ts, kind, mac, detail) VALUES (?1, ?2, ?3, ?4)",
            params![now, kind, mac, detail],
        )?;
        self.prune_locked(&conn, now)?;
        Ok(())
    }

    /// Speedtest readings in `[from, to]`, newest first.
    pub fn speedtest_series(&self, from: i64, to: i64) -> Result<Vec<SpeedtestPoint>> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare(
            "SELECT ts, download, upload, ping FROM wan_speedtest
             WHERE ts BETWEEN ?1 AND ?2 ORDER BY ts DESC",
        )?;
        let rows = stmt
            .query_map(params![from, to], |r| {
                Ok(SpeedtestPoint {
                    ts: r.get(0)?,
                    download: r.get(1)?,
                    upload: r.get(2)?,
                    ping: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Balance readings in `[from, to]`, newest first.
    pub fn balance_series(&self, from: i64, to: i64) -> Result<Vec<BalancePoint>> {
        let conn = self.read_conn()?;
        let mut stmt = conn.prepare(
            "SELECT ts, balance FROM wan_balance WHERE ts BETWEEN ?1 AND ?2 ORDER BY ts DESC",
        )?;
        let rows = stmt
            .query_map(params![from, to], |r| {
                Ok(BalancePoint {
                    ts: r.get(0)?,
                    balance: r.get(1)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Events in `[from, to]`, newest first, optionally filtered by `kind`, capped at
    /// `limit` (range + filter + LIMIT all pushed into SQL via `idx_events_ts`).
    pub fn list_events(
        &self,
        from: i64,
        to: i64,
        kind: Option<&str>,
        limit: i64,
    ) -> Result<Vec<EventRow>> {
        let conn = self.read_conn()?;
        let limit = limit.clamp(1, 10_000);
        // `limit` is a server-clamped integer (never a user string) — safe to inline.
        let tail = format!(" ORDER BY ts DESC, id DESC LIMIT {limit}");
        let select = "SELECT id, ts, kind, mac, detail FROM events WHERE ts BETWEEN ?1 AND ?2";
        let to_row = |r: &rusqlite::Row| -> rusqlite::Result<EventRow> {
            Ok(EventRow {
                id: r.get(0)?,
                ts: r.get(1)?,
                kind: r.get(2)?,
                mac: r.get(3)?,
                detail: r.get(4)?,
            })
        };
        let rows = match kind {
            Some(k) => {
                let mut stmt = conn.prepare(&format!("{select} AND kind = ?3{tail}"))?;
                let out: Vec<EventRow> = stmt
                    .query_map(params![from, to, k], to_row)?
                    .collect::<rusqlite::Result<_>>()?;
                out
            }
            None => {
                let mut stmt = conn.prepare(&format!("{select}{tail}"))?;
                let out: Vec<EventRow> = stmt
                    .query_map(params![from, to], to_row)?
                    .collect::<rusqlite::Result<_>>()?;
                out
            }
        };
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn store() -> HistoryStore {
        // Unique dir per call so parallel tests never share a DB (or its -wal/-shm).
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("history-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        HistoryStore::open(&dir.join("history.sqlite"), 90).unwrap()
    }

    #[test]
    fn net_transition_only_on_change() {
        assert_eq!(net_transition(None, true), None); // first reading -> no event
        assert_eq!(net_transition(None, false), None);
        assert_eq!(net_transition(Some(true), true), None); // unchanged
        assert_eq!(net_transition(Some(false), false), None);
        assert_eq!(net_transition(Some(true), false), Some(kind::INTERNET_DOWN));
        assert_eq!(net_transition(Some(false), true), Some(kind::INTERNET_UP));
    }

    #[test]
    fn balance_crossed_low_fires_once_on_the_way_down() {
        assert!(!balance_crossed_low(None, 100.0, 1200.0)); // first reading
        assert!(balance_crossed_low(Some(1500.0), 1000.0, 1200.0)); // above -> below
        assert!(!balance_crossed_low(Some(1000.0), 900.0, 1200.0)); // already below
        assert!(!balance_crossed_low(Some(1000.0), 1500.0, 1200.0)); // recovering
        assert!(!balance_crossed_low(Some(1200.0), 1200.0, 1200.0)); // at threshold, no cross
    }

    #[test]
    fn all_emitted_kinds_pass_the_filter_whitelist() {
        for k in kind::ALL {
            assert!(kind::is_valid(k), "{k} not accepted by is_valid");
        }
        assert!(!kind::is_valid("bogus"));
    }

    #[test]
    fn speedtest_and_balance_round_trip_newest_first() {
        let s = store();
        s.record_speedtest(100, 10.0, 1.0, 5.0).unwrap();
        s.record_speedtest(200, 20.0, 2.0, 6.0).unwrap();
        let series = s.speedtest_series(0, 1000).unwrap();
        assert_eq!(series.len(), 2);
        assert_eq!(series[0].ts, 200); // newest first
        assert_eq!(series[1].download, 10.0);

        s.record_balance(150, 1500.0).unwrap();
        let bal = s.balance_series(0, 1000).unwrap();
        assert_eq!(
            bal,
            vec![BalancePoint {
                ts: 150,
                balance: 1500.0
            }]
        );
        // Range excludes out-of-window points.
        assert!(s
            .speedtest_series(0, 150)
            .unwrap()
            .iter()
            .all(|p| p.ts <= 150));
    }

    #[test]
    fn record_overwrites_same_second() {
        let s = store();
        s.record_balance(100, 1000.0).unwrap();
        s.record_balance(100, 2000.0).unwrap(); // same ts -> last wins
        let bal = s.balance_series(0, 1000).unwrap();
        assert_eq!(bal.len(), 1);
        assert_eq!(bal[0].balance, 2000.0);
    }

    #[test]
    fn events_filter_by_kind_and_limit() {
        let s = store();
        s.record_event(100, kind::NEW_DEVICE, Some("aa:bb"), Some("10.0.0.1"))
            .unwrap();
        s.record_event(200, kind::INTERNET_DOWN, None, None)
            .unwrap();
        s.record_event(300, kind::NEW_DEVICE, Some("cc:dd"), None)
            .unwrap();

        let all = s.list_events(0, 1000, None, 100).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].ts, 300); // newest first

        let new_only = s.list_events(0, 1000, Some(kind::NEW_DEVICE), 100).unwrap();
        assert_eq!(new_only.len(), 2);
        assert!(new_only.iter().all(|e| e.kind == kind::NEW_DEVICE));

        let limited = s.list_events(0, 1000, None, 1).unwrap();
        assert_eq!(limited.len(), 1);
        assert_eq!(limited[0].ts, 300); // newest within the limit
    }

    #[test]
    fn prune_drops_rows_older_than_retention() {
        // retention 90d; insert an ancient row then a current one and confirm the
        // ancient row is pruned by the current write.
        let s = store();
        let now = 1_000_000_000;
        let ancient = now - 200 * SECONDS_PER_DAY;
        s.record_balance(ancient, 1.0).unwrap();
        s.record_balance(now, 2.0).unwrap();
        let bal = s.balance_series(0, now + 1).unwrap();
        assert_eq!(bal.len(), 1);
        assert_eq!(bal[0].ts, now);
    }
}
