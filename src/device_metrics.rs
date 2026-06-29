//! Persistent per-device metrics (first/last seen, accumulated traffic, IP
//! history) in SQLite, populated by a periodic sampler from dhcpd leases + ipset
//! counters (see the sampler in `state.rs`).
//!
//! Design notes:
//! - **Best-effort.** If the DB can't be opened the store is simply absent and the
//!   rest of the backend runs; read failures surface as `null` metrics, never 500.
//! - **Concurrency.** A single write connection (behind a `Mutex`) is used by the
//!   sampler; read paths open short-lived connections. WAL mode lets readers run
//!   without blocking the writer, so there is no global connection lock.
//! - **Traffic is approximate.** ipset counters are cumulative and reset when an
//!   entry is recreated; we store the last raw sample per IP and add the delta
//!   (treating `current < previous` as a reset). Traffic used between two samples
//!   while an entry is recreated is lost. The first observation of an IP only sets
//!   a baseline (delta 0) so a pre-existing counter is never counted retroactively.
//! - **Retention.** Each sampling pass prunes data older than `retention_days`:
//!   daily traffic buckets, IP history (`device_ips`), devices whose `last_seen`
//!   has aged out, and orphaned `ip_samples` baselines left after IP history is
//!   pruned. This keeps dead MACs/IPs from accumulating forever.

use anyhow::{Context, Result};
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

const SCHEMA_VERSION: i64 = 3;
const SECONDS_PER_DAY: i64 = 86_400;
/// SQLite `busy_timeout` for both the writer and short-lived readers.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// Rolling window (in days) for the `bytes_7d` aggregate, inclusive of today.
const TRAFFIC_WINDOW_DAYS: i64 = 7;
/// Rolling window (in days) for the `bytes_30d` aggregate, inclusive of today.
/// Also the widest window queried, so `traffic_daily` is read once per call.
const MONTH_WINDOW_DAYS: i64 = 30;

/// Per-device metrics joined into API listings. All optional so a device with no
/// row (or a transient DB error) serializes as `null`s without breaking the response.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct DeviceMetrics {
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    pub bytes_total: Option<i64>,
    pub packets_total: Option<i64>,
    pub bytes_today: Option<i64>,
    pub bytes_7d: Option<i64>,
    pub bytes_30d: Option<i64>,
    /// Average throughput over the last sampler interval (bytes/sec), or `null`
    /// when the device wasn't active in the latest tick / no interval yet.
    pub rate_bps: Option<i64>,
    /// Had traffic in the most recent (fresh) sampler interval — see [`is_online`].
    pub online: bool,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
}

/// One row of the `/api/v1/admin/devices` inventory.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceRow {
    pub mac: String,
    pub last_ip: Option<String>,
    pub ips: Vec<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    pub bytes_total: i64,
    pub packets_total: i64,
    pub bytes_today: i64,
    pub bytes_7d: i64,
    pub bytes_30d: i64,
    pub rate_bps: Option<i64>,
    /// Had traffic in the most recent (fresh) sampler interval — see [`is_online`].
    pub online: bool,
}

/// Aggregate dashboard stats for `/admin/status`.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardStats {
    pub devices_total: i64,
    pub devices_online: i64,
    pub new_today: i64,
    pub traffic_today_bytes: i64,
    pub traffic_7d_bytes: i64,
    pub total_rate_bps: i64,
    pub top_talkers: Vec<TopTalker>,
}

/// One entry of the dashboard "top talkers by today's traffic" list.
#[derive(Debug, Clone, Serialize)]
pub struct TopTalker {
    pub mac: String,
    pub last_ip: Option<String>,
    pub hostname: Option<String>,
    pub bytes_today: i64,
}

/// One day of traffic for a device, for the per-device history endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct DailyPoint {
    pub day: i64,
    pub bytes: i64,
    pub packets: i64,
}

/// A device row plus its daily traffic series (for `/admin/devices/{mac}`).
/// `online`/`is_unlimited` are filled by the HTTP layer (need leases / store).
pub struct DeviceDetailData {
    pub device: DeviceRow,
    pub daily: Vec<DailyPoint>,
}

/// One active-lease observation fed to [`DeviceMetricsStore::sample`]. Decoupled
/// from the dhcp/ipset types so the store is testable in isolation.
#[derive(Debug, Clone)]
pub struct LeaseObservation {
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    /// Lease `cltt` (last client transaction) as unix epoch seconds — the device's
    /// real "last seen on the network". `None` if the lease has no cltt, in which
    /// case the sampler falls back to `now` only when first inserting the device.
    pub last_seen: Option<i64>,
}

/// One ipset counter reading fed to [`DeviceMetricsStore::sample`].
#[derive(Debug, Clone)]
pub struct IpsetCounter {
    pub ip: String,
    pub bytes: i64,
    pub packets: i64,
}

/// Summary of a [`DeviceMetricsStore::sample`] pass, for logging.
#[derive(Debug, Default, PartialEq)]
pub struct SampleStats {
    pub devices: usize,
    pub ips: usize,
    pub bytes_added: i64,
    pub resets: usize,
}

/// Retention windows for the three traffic rollup levels, passed to
/// [`DeviceMetricsStore::sample`]. A value `<= 0` disables pruning for that level.
#[derive(Debug, Clone, Copy)]
pub struct Retention {
    pub daily_days: i64,
    pub hourly_days: i64,
    pub fivemin_hours: i64,
}

/// Traffic rollup granularity for the `/devices/{mac}/traffic` endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granularity {
    Day,
    Hour,
    FiveMin,
}

impl Granularity {
    /// Parse the API `granularity` query value. `None` for anything else (-> 400).
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "day" => Some(Self::Day),
            "hour" => Some(Self::Hour),
            "5m" => Some(Self::FiveMin),
            _ => None,
        }
    }

    /// The wire/serialized value (matches [`Granularity::parse`]).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Day => "day",
            Self::Hour => "hour",
            Self::FiveMin => "5m",
        }
    }

    /// Backing `(table, bucket_column)` — both compile-time constants, never user
    /// input, so they are safe to interpolate into SQL (mac/from/to stay bound).
    fn table_col(self) -> (&'static str, &'static str) {
        match self {
            Self::Day => ("traffic_daily", "day"),
            Self::Hour => ("traffic_hourly", "hour"),
            Self::FiveMin => ("traffic_5min", "ts"),
        }
    }
}

/// One bucket of a device's traffic series (`ts` = bucket start, unix sec UTC).
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TrafficPoint {
    pub ts: i64,
    pub bytes: i64,
    pub packets: i64,
}

pub struct DeviceMetricsStore {
    path: PathBuf,
    write: Mutex<Connection>,
}

fn configure(conn: &Connection) -> Result<()> {
    conn.busy_timeout(BUSY_TIMEOUT)?;
    // WAL: concurrent readers don't block the single writer. NORMAL: skip the
    // per-commit fsync (acceptable for a local metrics DB; spares SD-card writes).
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
    Ok(())
}

fn init_schema(conn: &Connection) -> Result<()> {
    // Fresh DBs get the full v3 schema here (rate columns + `meta` + rollup tables).
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            last_ip TEXT,
            last_hostname TEXT,
            last_vendor TEXT,
            bytes_total INTEGER NOT NULL DEFAULT 0,
            packets_total INTEGER NOT NULL DEFAULT 0,
            last_delta_bytes INTEGER NOT NULL DEFAULT 0,
            last_delta_at INTEGER NOT NULL DEFAULT 0
         );
         CREATE TABLE IF NOT EXISTS device_ips (
            mac TEXT NOT NULL,
            ip TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            PRIMARY KEY (mac, ip)
         );
         CREATE TABLE IF NOT EXISTS ip_samples (
            ip TEXT PRIMARY KEY,
            mac TEXT,
            last_bytes INTEGER NOT NULL,
            last_packets INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS traffic_daily (
            mac TEXT NOT NULL,
            day INTEGER NOT NULL,
            bytes INTEGER NOT NULL DEFAULT 0,
            packets INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (mac, day)
         );
         CREATE TABLE IF NOT EXISTS traffic_hourly (
            mac TEXT NOT NULL,
            hour INTEGER NOT NULL,
            bytes INTEGER NOT NULL DEFAULT 0,
            packets INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (mac, hour)
         );
         CREATE TABLE IF NOT EXISTS traffic_5min (
            mac TEXT NOT NULL,
            ts INTEGER NOT NULL,
            bytes INTEGER NOT NULL DEFAULT 0,
            packets INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (mac, ts)
         );
         CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER);
         CREATE INDEX IF NOT EXISTS idx_traffic_daily_day ON traffic_daily(day);
         CREATE INDEX IF NOT EXISTS idx_traffic_hourly_hour ON traffic_hourly(hour);
         CREATE INDEX IF NOT EXISTS idx_traffic_5min_ts ON traffic_5min(ts);",
    )?;
    migrate(conn)?;
    Ok(())
}

/// Idempotent schema migration. All tables/columns added in v3 (rollup tables) and
/// for fresh DBs already exist from the `CREATE TABLE IF NOT EXISTS` batch above, so
/// those upgrades need only the `user_version` bump. The one thing CREATE can't do
/// retroactively is add columns to an existing table, so a v1 DB additionally gains
/// the rate columns via ALTER — gated strictly on `== 1` so it can never run twice.
fn migrate(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version == 1 {
        conn.execute_batch(
            "ALTER TABLE devices ADD COLUMN last_delta_bytes INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE devices ADD COLUMN last_delta_at INTEGER NOT NULL DEFAULT 0;",
        )?;
    }
    if version < SCHEMA_VERSION {
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }
    Ok(())
}

fn day_start(now: i64) -> i64 {
    now / SECONDS_PER_DAY * SECONDS_PER_DAY
}

const SECONDS_PER_HOUR: i64 = 3600;
const SECONDS_PER_5MIN: i64 = 300;

fn hour_start(now: i64) -> i64 {
    now / SECONDS_PER_HOUR * SECONDS_PER_HOUR
}

fn fivemin_start(now: i64) -> i64 {
    now / SECONDS_PER_5MIN * SECONDS_PER_5MIN
}

/// Start of the rolling `bytes_7d` window (inclusive of `today`).
fn week_start(today: i64) -> i64 {
    today - (TRAFFIC_WINDOW_DAYS - 1) * SECONDS_PER_DAY
}

/// Start of the rolling `bytes_30d` window (inclusive of `today`). This is the
/// widest window read, so callers query `traffic_daily WHERE day >= month_start`.
fn month_start(today: i64) -> i64 {
    today - (MONTH_WINDOW_DAYS - 1) * SECONDS_PER_DAY
}

/// Fold `(mac, day, bytes)` rows (pre-filtered to the 30-day window) into per-MAC
/// `(bytes_today, bytes_7d, bytes_30d)` totals.
fn fold_daily(
    rows: impl IntoIterator<Item = (String, i64, i64)>,
    today: i64,
    week_ago: i64,
) -> HashMap<String, (i64, i64, i64)> {
    let mut acc: HashMap<String, (i64, i64, i64)> = HashMap::new();
    for (mac, day, bytes) in rows {
        let entry = acc.entry(mac).or_insert((0, 0, 0));
        entry.2 += bytes; // bytes_30d (whole window)
        if day >= week_ago {
            entry.1 += bytes; // bytes_7d
        }
        if day == today {
            entry.0 += bytes; // bytes_today
        }
    }
    acc
}

/// Read `(last_sample_at, sample_interval)` from `meta` (0/0 if absent). Used to
/// derive `rate_bps`: a device's rate is valid only when it was active in the
/// latest tick (`last_delta_at == last_sample_at`) and the interval is positive.
fn read_sample_meta(conn: &Connection) -> Result<(i64, i64)> {
    let last_sample_at = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'last_sample_at'",
            [],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    let interval = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'sample_interval'",
            [],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    Ok((last_sample_at, interval))
}

/// Compute `rate_bps` from a device's last-tick delta. `None` unless the device
/// was active in the latest tick and the interval is positive (no division by 0).
fn rate_bps(
    last_delta_bytes: i64,
    last_delta_at: i64,
    last_sample_at: i64,
    interval: i64,
) -> Option<i64> {
    if interval > 0 && last_delta_at == last_sample_at && last_sample_at != 0 {
        Some(last_delta_bytes / interval)
    } else {
        None
    }
}

/// Slack added to the sampler interval when judging "freshness" for `online`,
/// to tolerate tick jitter.
const ONLINE_SLACK_SECS: i64 = 60;
/// Freshness fallback when no interval has been measured yet (first ticks).
const ONLINE_FALLBACK_WINDOW_SECS: i64 = 360;

/// Whether a device counts as **online**: it had positive traffic in the most
/// recent sampler tick, and that tick is still fresh (the sampler isn't stalled).
/// This is "had traffic in roughly the last sampler interval (~5 min)", not "holds
/// a DHCP lease" — an idle-but-leased device reads as offline by design.
fn is_online(
    last_delta_bytes: i64,
    last_delta_at: i64,
    last_sample_at: i64,
    interval: i64,
    now: i64,
) -> bool {
    let window = if interval > 0 {
        interval + ONLINE_SLACK_SECS
    } else {
        ONLINE_FALLBACK_WINDOW_SECS
    };
    last_sample_at != 0
        && last_delta_at == last_sample_at
        && last_delta_bytes > 0
        && now - last_sample_at <= window
}

impl DeviceMetricsStore {
    /// Open (creating if needed) the metrics DB and ensure the schema exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory cannot be created, the DB file
    /// cannot be opened, or the PRAGMA/schema setup fails (DB/SQL error).
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {parent:?}"))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("failed to open device-metrics DB {path:?}"))?;
        configure(&conn)?;
        init_schema(&conn)?;
        Ok(Self {
            path: path.to_path_buf(),
            write: Mutex::new(conn),
        })
    }

    fn read_conn(&self) -> Result<Connection> {
        let conn = Connection::open(&self.path)
            .with_context(|| format!("failed to open device-metrics DB {:?}", self.path))?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        Ok(conn)
    }

    /// One transactional sampling pass. `now` is unix epoch seconds. Idempotent:
    /// re-running with identical inputs adds no traffic (per-IP delta is 0). Each
    /// traffic delta is rolled into the daily / hourly / 5-minute buckets, then old
    /// buckets are pruned per `retention` (one window per rollup level).
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction cannot be opened/committed or any of
    /// its statements fail (DB/SQL error). On error the transaction is rolled
    /// back, so persisted data stays consistent.
    pub fn sample(
        &self,
        leases: &[LeaseObservation],
        counters: &[IpsetCounter],
        now: i64,
        retention: Retention,
    ) -> Result<SampleStats> {
        // `std::Mutex` stays poisoned forever after a writer panic, which would
        // make every subsequent tick panic too. A panicking transaction is rolled
        // back during unwind, so the DB is consistent and recovering the guard is
        // safe.
        let mut conn = self.write.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let mut stats = SampleStats::default();
        // Bucket starts for the three rollup levels (all floored, UTC).
        let day = day_start(now);
        let hour = hour_start(now);
        let five_min = fivemin_start(now);

        // Previous tick time, to compute the rate interval at the end.
        let prev_sample_at: i64 = tx
            .query_row(
                "SELECT value FROM meta WHERE key = 'last_sample_at'",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);

        let ip_to_mac: HashMap<&str, &str> = leases
            .iter()
            .map(|l| (l.ip.as_str(), l.mac.as_str()))
            .collect();

        // 1) Upsert device + IP-history rows from active leases.
        //    - `last_seen` tracks the lease `cltt` (real last-seen on the network),
        //      NOT `now`: an unexpired-but-idle lease (cltt old) must not inflate it.
        //      `MAX(last_seen, COALESCE(cltt, now))` keeps it monotonic; only a lease
        //      with NO cltt at all falls back to `now` (we are observing it now).
        //    - `first_seen` stays `now` (first time WE observed the MAC).
        //    - Reset the per-tick rate accumulator (`last_delta_bytes=0`) and stamp
        //      `last_delta_at=now` for EVERY active device, so an active-but-idle
        //      device reads as "active in the latest tick" (rate 0).
        for l in leases {
            tx.execute(
                "INSERT INTO devices (mac, first_seen, last_seen, last_ip, last_hostname, last_vendor, last_delta_at, last_delta_bytes)
                 VALUES (?1, ?2, COALESCE(?6, ?2), ?3, ?4, ?5, ?2, 0)
                 ON CONFLICT(mac) DO UPDATE SET
                   last_seen = MAX(last_seen, COALESCE(?6, ?2)),
                   last_ip = excluded.last_ip,
                   last_hostname = COALESCE(excluded.last_hostname, last_hostname),
                   last_vendor = COALESCE(excluded.last_vendor, last_vendor),
                   last_delta_at = excluded.last_delta_at,
                   last_delta_bytes = 0",
                params![l.mac, now, l.ip, l.hostname, l.vendor, l.last_seen],
            )?;
            tx.execute(
                "INSERT INTO device_ips (mac, ip, first_seen, last_seen)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(mac, ip) DO UPDATE SET last_seen = excluded.last_seen",
                params![l.mac, l.ip, now],
            )?;
            stats.devices += 1;
        }

        // 2) Traffic deltas per IP, attributed to the IP's current MAC.
        for c in counters {
            let mac = match ip_to_mac.get(c.ip.as_str()) {
                Some(m) => *m,
                None => continue, // IP without an active lease -> can't attribute
            };
            let prev: Option<(i64, i64)> = tx
                .query_row(
                    "SELECT last_bytes, last_packets FROM ip_samples WHERE ip = ?1",
                    params![c.ip],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let (dbytes, dpackets) = match prev {
                // First observation: only set the baseline so a pre-existing counter
                // isn't counted retroactively.
                None => (0, 0),
                Some((pb, pp)) => {
                    let db = if c.bytes >= pb {
                        c.bytes - pb
                    } else {
                        stats.resets += 1;
                        c.bytes
                    };
                    let dp = if c.packets >= pp {
                        c.packets - pp
                    } else {
                        c.packets
                    };
                    (db, dp)
                }
            };
            tx.execute(
                "INSERT INTO ip_samples (ip, mac, last_bytes, last_packets)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(ip) DO UPDATE SET
                   mac = excluded.mac, last_bytes = excluded.last_bytes,
                   last_packets = excluded.last_packets",
                params![c.ip, mac, c.bytes, c.packets],
            )?;
            if dbytes > 0 || dpackets > 0 {
                tx.execute(
                    "UPDATE devices SET bytes_total = bytes_total + ?2,
                       packets_total = packets_total + ?3,
                       last_delta_bytes = last_delta_bytes + ?2 WHERE mac = ?1",
                    params![mac, dbytes, dpackets],
                )?;
                // Three rollup levels, all upsert (cron jitter can land two ticks
                // in one bucket -> sum, never overwrite/conflict).
                for (sql, bucket) in [
                    (
                        "INSERT INTO traffic_daily (mac, day, bytes, packets) VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(mac, day) DO UPDATE SET
                           bytes = bytes + excluded.bytes, packets = packets + excluded.packets",
                        day,
                    ),
                    (
                        "INSERT INTO traffic_hourly (mac, hour, bytes, packets) VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(mac, hour) DO UPDATE SET
                           bytes = bytes + excluded.bytes, packets = packets + excluded.packets",
                        hour,
                    ),
                    (
                        "INSERT INTO traffic_5min (mac, ts, bytes, packets) VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(mac, ts) DO UPDATE SET
                           bytes = bytes + excluded.bytes, packets = packets + excluded.packets",
                        five_min,
                    ),
                ] {
                    tx.execute(sql, params![mac, bucket, dbytes, dpackets])?;
                }
                stats.bytes_added += dbytes;
            }
            stats.ips += 1;
        }

        // 3) Retention: drop old rollup buckets, stale IP history, aged-out
        //    devices, and the IP baselines orphaned by the device_ips prune.
        // `saturating_*` so an absurd retention config can't overflow the cutoff
        // (a saturated cutoff prunes nothing, which is safe).
        if retention.daily_days > 0 {
            let cutoff = day.saturating_sub(retention.daily_days.saturating_mul(SECONDS_PER_DAY));
            tx.execute("DELETE FROM traffic_daily WHERE day < ?1", params![cutoff])?;
            tx.execute(
                "DELETE FROM device_ips WHERE last_seen < ?1",
                params![cutoff],
            )?;
            tx.execute("DELETE FROM devices WHERE last_seen < ?1", params![cutoff])?;
            tx.execute(
                "DELETE FROM ip_samples WHERE ip NOT IN (SELECT ip FROM device_ips)",
                [],
            )?;
        }
        if retention.hourly_days > 0 {
            let cutoff = hour.saturating_sub(retention.hourly_days.saturating_mul(SECONDS_PER_DAY));
            tx.execute(
                "DELETE FROM traffic_hourly WHERE hour < ?1",
                params![cutoff],
            )?;
        }
        if retention.fivemin_hours > 0 {
            let cutoff =
                five_min.saturating_sub(retention.fivemin_hours.saturating_mul(SECONDS_PER_HOUR));
            tx.execute("DELETE FROM traffic_5min WHERE ts < ?1", params![cutoff])?;
        }

        // Record this tick + the interval since the previous, for rate reads.
        let interval = if prev_sample_at > 0 && now > prev_sample_at {
            now - prev_sample_at
        } else {
            0
        };
        for (key, value) in [("last_sample_at", now), ("sample_interval", interval)] {
            tx.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )?;
        }

        tx.commit()?;
        Ok(stats)
    }

    /// Batch-load metrics for the given MACs in two queries (no N+1). `now` sets the
    /// today / last-7-days windows.
    ///
    /// # Errors
    ///
    /// Returns an error if a read connection cannot be opened or any query fails
    /// (DB/SQL error).
    pub fn get_many(&self, macs: &[String], now: i64) -> Result<HashMap<String, DeviceMetrics>> {
        let mut out: HashMap<String, DeviceMetrics> = HashMap::new();
        if macs.is_empty() {
            return Ok(out);
        }
        let conn = self.read_conn()?;
        let today = day_start(now);
        let week_ago = week_start(today);
        let month_ago = month_start(today);
        let (last_sample_at, interval) = read_sample_meta(&conn)?;
        let placeholders = vec!["?"; macs.len()].join(",");

        let sql = format!(
            "SELECT mac, first_seen, last_seen, last_hostname, last_vendor, bytes_total,
                    packets_total, last_delta_bytes, last_delta_at
             FROM devices WHERE mac IN ({placeholders})"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(macs.iter()), |r| {
            let last_delta_bytes: i64 = r.get(7)?;
            let last_delta_at: i64 = r.get(8)?;
            Ok((
                r.get::<_, String>(0)?,
                DeviceMetrics {
                    first_seen: r.get(1)?,
                    last_seen: r.get(2)?,
                    hostname: r.get(3)?,
                    vendor: r.get(4)?,
                    bytes_total: r.get(5)?,
                    packets_total: r.get(6)?,
                    rate_bps: rate_bps(last_delta_bytes, last_delta_at, last_sample_at, interval),
                    online: is_online(
                        last_delta_bytes,
                        last_delta_at,
                        last_sample_at,
                        interval,
                        now,
                    ),
                    bytes_today: Some(0),
                    bytes_7d: Some(0),
                    bytes_30d: Some(0),
                },
            ))
        })?;
        for row in rows {
            let (mac, m) = row?;
            out.insert(mac, m);
        }

        // Daily traffic over the 30-day window (small), aggregated in Rust.
        let mut stmt = conn.prepare("SELECT mac, day, bytes FROM traffic_daily WHERE day >= ?1")?;
        let rows = stmt
            .query_map(params![month_ago], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (mac, (today_bytes, week_bytes, month_bytes)) in fold_daily(rows, today, week_ago) {
            if let Some(m) = out.get_mut(&mac) {
                m.bytes_today = Some(today_bytes);
                m.bytes_7d = Some(week_bytes);
                m.bytes_30d = Some(month_bytes);
            }
        }
        Ok(out)
    }

    /// Full device inventory for `/devices` (assembled in 3 queries). Caller applies
    /// filter/sort/pagination.
    ///
    /// # Errors
    ///
    /// Returns an error if a read connection cannot be opened or any query fails
    /// (DB/SQL error).
    pub fn all_devices(&self, now: i64) -> Result<Vec<DeviceRow>> {
        let conn = self.read_conn()?;
        let today = day_start(now);
        let week_ago = week_start(today);
        let month_ago = month_start(today);
        let (last_sample_at, interval) = read_sample_meta(&conn)?;

        let mut by_mac: HashMap<String, DeviceRow> = HashMap::new();
        let mut stmt = conn.prepare(
            "SELECT mac, last_ip, last_hostname, last_vendor, first_seen, last_seen,
                    bytes_total, packets_total, last_delta_bytes, last_delta_at
             FROM devices",
        )?;
        let rows = stmt.query_map([], |r| {
            let last_delta_bytes: i64 = r.get(8)?;
            let last_delta_at: i64 = r.get(9)?;
            Ok(DeviceRow {
                mac: r.get(0)?,
                last_ip: r.get(1)?,
                hostname: r.get(2)?,
                vendor: r.get(3)?,
                first_seen: r.get(4)?,
                last_seen: r.get(5)?,
                bytes_total: r.get(6)?,
                packets_total: r.get(7)?,
                rate_bps: rate_bps(last_delta_bytes, last_delta_at, last_sample_at, interval),
                online: is_online(
                    last_delta_bytes,
                    last_delta_at,
                    last_sample_at,
                    interval,
                    now,
                ),
                bytes_today: 0,
                bytes_7d: 0,
                bytes_30d: 0,
                ips: Vec::new(),
            })
        })?;
        for row in rows {
            let d = row?;
            by_mac.insert(d.mac.clone(), d);
        }

        let mut stmt = conn.prepare("SELECT mac, ip FROM device_ips ORDER BY ip")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (mac, ip) = row?;
            if let Some(d) = by_mac.get_mut(&mac) {
                d.ips.push(ip);
            }
        }

        let mut stmt = conn.prepare("SELECT mac, day, bytes FROM traffic_daily WHERE day >= ?1")?;
        let rows = stmt
            .query_map(params![month_ago], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (mac, (today_bytes, week_bytes, month_bytes)) in fold_daily(rows, today, week_ago) {
            if let Some(dev) = by_mac.get_mut(&mac) {
                dev.bytes_today = today_bytes;
                dev.bytes_7d = week_bytes;
                dev.bytes_30d = month_bytes;
            }
        }

        Ok(by_mac.into_values().collect())
    }

    /// Aggregate dashboard stats. Best-effort (caller logs/degrades on error).
    ///
    /// # Errors
    /// Returns an error if a read connection or any aggregate query fails.
    pub fn dashboard(&self, now: i64, top_n: usize) -> Result<DashboardStats> {
        let conn = self.read_conn()?;
        let today = day_start(now);
        let week_ago = week_start(today);
        let (last_sample_at, interval) = read_sample_meta(&conn)?;

        let scalar = |sql: &str, p: &[&dyn rusqlite::ToSql]| -> Result<i64> {
            Ok(conn
                .query_row(sql, p, |r| r.get::<_, Option<i64>>(0))?
                .unwrap_or(0))
        };

        let devices_total = scalar("SELECT COUNT(*) FROM devices", &[])?;
        // online = had traffic in the latest tick, and that tick is fresh (mirrors
        // `is_online`). Freshness is the same for all rows, so gate it once.
        let window = if interval > 0 {
            interval + ONLINE_SLACK_SECS
        } else {
            ONLINE_FALLBACK_WINDOW_SECS
        };
        let devices_online = if last_sample_at != 0 && now - last_sample_at <= window {
            scalar(
                "SELECT COUNT(*) FROM devices WHERE last_delta_at = ?1 AND last_delta_bytes > 0",
                &[&last_sample_at],
            )?
        } else {
            0
        };
        let new_today = scalar(
            "SELECT COUNT(*) FROM devices WHERE first_seen >= ?1",
            &[&today],
        )?;
        let traffic_today_bytes = scalar(
            "SELECT SUM(bytes) FROM traffic_daily WHERE day = ?1",
            &[&today],
        )?;
        let traffic_7d_bytes = scalar(
            "SELECT SUM(bytes) FROM traffic_daily WHERE day >= ?1",
            &[&week_ago],
        )?;
        let total_rate_bps = if interval > 0 && last_sample_at != 0 {
            scalar(
                "SELECT SUM(last_delta_bytes) FROM devices WHERE last_delta_at = ?1",
                &[&last_sample_at],
            )? / interval
        } else {
            0
        };

        let mut stmt = conn.prepare(
            "SELECT t.mac, d.last_ip, d.last_hostname, SUM(t.bytes) AS b
             FROM traffic_daily t LEFT JOIN devices d ON d.mac = t.mac
             WHERE t.day = ?1 GROUP BY t.mac ORDER BY b DESC LIMIT ?2",
        )?;
        let top_talkers = stmt
            .query_map(params![today, top_n as i64], |r| {
                Ok(TopTalker {
                    mac: r.get(0)?,
                    last_ip: r.get(1)?,
                    hostname: r.get(2)?,
                    bytes_today: r.get::<_, Option<i64>>(3)?.unwrap_or(0),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(DashboardStats {
            devices_total,
            devices_online,
            new_today,
            traffic_today_bytes,
            traffic_7d_bytes,
            total_rate_bps,
            top_talkers,
        })
    }

    /// Per-device detail + daily traffic series over the last `days`. `None` if the
    /// MAC is unknown. `online`/`is_unlimited` are filled by the caller.
    ///
    /// # Errors
    /// Returns an error if a read connection or any query fails.
    pub fn device_detail(
        &self,
        mac: &str,
        now: i64,
        days: i64,
    ) -> Result<Option<DeviceDetailData>> {
        let conn = self.read_conn()?;
        let today = day_start(now);
        let week_ago = week_start(today);
        let month_ago = month_start(today);
        let series_start = today - (days.max(1) - 1) * SECONDS_PER_DAY;
        let (last_sample_at, interval) = read_sample_meta(&conn)?;

        let device: Option<DeviceRow> = conn
            .query_row(
                "SELECT mac, last_ip, last_hostname, last_vendor, first_seen, last_seen,
                        bytes_total, packets_total, last_delta_bytes, last_delta_at
                 FROM devices WHERE mac = ?1",
                params![mac],
                |r| {
                    let last_delta_bytes: i64 = r.get(8)?;
                    let last_delta_at: i64 = r.get(9)?;
                    Ok(DeviceRow {
                        mac: r.get(0)?,
                        last_ip: r.get(1)?,
                        hostname: r.get(2)?,
                        vendor: r.get(3)?,
                        first_seen: r.get(4)?,
                        last_seen: r.get(5)?,
                        bytes_total: r.get(6)?,
                        packets_total: r.get(7)?,
                        rate_bps: rate_bps(
                            last_delta_bytes,
                            last_delta_at,
                            last_sample_at,
                            interval,
                        ),
                        online: is_online(
                            last_delta_bytes,
                            last_delta_at,
                            last_sample_at,
                            interval,
                            now,
                        ),
                        bytes_today: 0,
                        bytes_7d: 0,
                        bytes_30d: 0,
                        ips: Vec::new(),
                    })
                },
            )
            .optional()?;
        let mut device = match device {
            Some(d) => d,
            None => return Ok(None),
        };

        let mut stmt = conn.prepare("SELECT ip FROM device_ips WHERE mac = ?1 ORDER BY ip")?;
        device.ips = stmt
            .query_map(params![mac], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        // bytes_today/7d/30d from the 30-day window.
        let mut stmt =
            conn.prepare("SELECT mac, day, bytes FROM traffic_daily WHERE mac = ?1 AND day >= ?2")?;
        let agg = stmt
            .query_map(params![mac, month_ago], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if let Some((t, w, m)) = fold_daily(agg, today, week_ago).remove(mac) {
            device.bytes_today = t;
            device.bytes_7d = w;
            device.bytes_30d = m;
        }

        // The daily series (most-recent-first) over `days`.
        let mut stmt = conn.prepare(
            "SELECT day, bytes, packets FROM traffic_daily WHERE mac = ?1 AND day >= ?2 ORDER BY day DESC",
        )?;
        let daily = stmt
            .query_map(params![mac, series_start], |r| {
                Ok(DailyPoint {
                    day: r.get(0)?,
                    bytes: r.get(1)?,
                    packets: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(Some(DeviceDetailData { device, daily }))
    }

    /// Traffic series for one device at the given `granularity`, bucket starts in
    /// `[from, to]` (inclusive), newest-first. `Ok(None)` if the MAC is unknown
    /// (-> 404); `Ok(Some([]))` for a known device with no traffic in the window.
    ///
    /// # Errors
    /// Returns an error if a read connection or any query fails (DB/SQL error).
    pub fn traffic_series(
        &self,
        mac: &str,
        granularity: Granularity,
        from: i64,
        to: i64,
    ) -> Result<Option<Vec<TrafficPoint>>> {
        let conn = self.read_conn()?;
        // Unknown MAC -> None (404). A known device with no buckets -> Some([]).
        let known: bool = conn
            .query_row("SELECT 1 FROM devices WHERE mac = ?1", params![mac], |_| {
                Ok(())
            })
            .optional()?
            .is_some();
        if !known {
            return Ok(None);
        }
        // `table`/`col` are compile-time constants from the Granularity enum (never
        // user input); mac/from/to are bound. No user input is interpolated.
        let (table, col) = granularity.table_col();
        let sql = format!(
            "SELECT {col}, bytes, packets FROM {table}
             WHERE mac = ?1 AND {col} BETWEEN ?2 AND ?3 ORDER BY {col} DESC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let points = stmt
            .query_map(params![mac, from, to], |r| {
                Ok(TrafficPoint {
                    ts: r.get(0)?,
                    bytes: r.get(1)?,
                    packets: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some(points))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn store() -> (DeviceMetricsStore, std::path::PathBuf) {
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("dm-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("m.sqlite");
        let _ = std::fs::remove_file(&path);
        (DeviceMetricsStore::open(&path).unwrap(), dir)
    }

    fn lease(mac: &str, ip: &str) -> LeaseObservation {
        LeaseObservation {
            mac: mac.into(),
            ip: ip.into(),
            hostname: Some("host".into()),
            vendor: None,
            last_seen: None,
        }
    }
    fn ctr(ip: &str, bytes: i64) -> IpsetCounter {
        IpsetCounter {
            ip: ip.into(),
            bytes,
            packets: bytes / 100,
        }
    }
    /// Test retention with the given daily window + production hourly/5min defaults.
    fn retention(daily: i64) -> Retention {
        Retention {
            daily_days: daily,
            hourly_days: 90,
            fivemin_hours: 48,
        }
    }

    #[test]
    fn open_is_idempotent() {
        let (s, dir) = store();
        // re-open same path: schema already there, no error
        let again = DeviceMetricsStore::open(&s.path);
        assert!(again.is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn first_sample_sets_baseline_no_traffic() {
        let (s, dir) = store();
        let now = 1_000_000;
        let st = s
            .sample(
                &[lease("aa:bb:cc:dd:ee:01", "10.0.0.2")],
                &[ctr("10.0.0.2", 5000)],
                now,
                retention(730),
            )
            .unwrap();
        assert_eq!(st.bytes_added, 0, "first observation only sets baseline");
        let m = s.get_many(&["aa:bb:cc:dd:ee:01".into()], now).unwrap();
        assert_eq!(m["aa:bb:cc:dd:ee:01"].bytes_total, Some(0));
        assert_eq!(m["aa:bb:cc:dd:ee:01"].first_seen, Some(now));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn delta_accumulates_and_detects_reset() {
        let (s, dir) = store();
        let mac = "aa:bb:cc:dd:ee:01";
        s.sample(
            &[lease(mac, "10.0.0.2")],
            &[ctr("10.0.0.2", 1000)],
            1000,
            retention(730),
        )
        .unwrap(); // baseline
        let st = s
            .sample(
                &[lease(mac, "10.0.0.2")],
                &[ctr("10.0.0.2", 1500)],
                2000,
                retention(730),
            )
            .unwrap();
        assert_eq!(st.bytes_added, 500); // 1500-1000
                                         // counter reset: current (300) < previous (1500) -> add current
        let st = s
            .sample(
                &[lease(mac, "10.0.0.2")],
                &[ctr("10.0.0.2", 300)],
                3000,
                retention(730),
            )
            .unwrap();
        assert_eq!(st.resets, 1);
        assert_eq!(st.bytes_added, 300);
        let m = s.get_many(&[mac.into()], 3000).unwrap();
        assert_eq!(m[mac].bytes_total, Some(800)); // 500 + 300
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sample_is_idempotent() {
        let (s, dir) = store();
        let mac = "aa:bb:cc:dd:ee:01";
        s.sample(
            &[lease(mac, "10.0.0.2")],
            &[ctr("10.0.0.2", 1000)],
            1000,
            retention(730),
        )
        .unwrap();
        s.sample(
            &[lease(mac, "10.0.0.2")],
            &[ctr("10.0.0.2", 2000)],
            2000,
            retention(730),
        )
        .unwrap();
        // same inputs again -> no extra traffic
        let st = s
            .sample(
                &[lease(mac, "10.0.0.2")],
                &[ctr("10.0.0.2", 2000)],
                2000,
                retention(730),
            )
            .unwrap();
        assert_eq!(st.bytes_added, 0);
        let m = s.get_many(&[mac.into()], 2000).unwrap();
        assert_eq!(m[mac].bytes_total, Some(1000));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ip_without_lease_is_not_attributed() {
        let (s, dir) = store();
        // counter for an IP with no active lease this tick -> skipped
        let st = s
            .sample(&[], &[ctr("10.0.0.9", 5000)], 1000, retention(730))
            .unwrap();
        assert_eq!(st.ips, 0);
        assert_eq!(st.bytes_added, 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn today_and_7d_windows() {
        let (s, dir) = store();
        let mac = "aa:bb:cc:dd:ee:01";
        let day = SECONDS_PER_DAY;
        // baseline 8 days ago, then traffic today
        s.sample(
            &[lease(mac, "10.0.0.2")],
            &[ctr("10.0.0.2", 0)],
            10 * day,
            retention(730),
        )
        .unwrap();
        s.sample(
            &[lease(mac, "10.0.0.2")],
            &[ctr("10.0.0.2", 2000)],
            10 * day + 100,
            retention(730),
        )
        .unwrap();
        let m = s.get_many(&[mac.into()], 10 * day + 100).unwrap();
        assert_eq!(m[mac].bytes_today, Some(2000));
        assert_eq!(m[mac].bytes_7d, Some(2000));
        // a week later: today=0, but total persists
        let m = s.get_many(&[mac.into()], 20 * day).unwrap();
        assert_eq!(m[mac].bytes_today, Some(0));
        assert_eq!(m[mac].bytes_total, Some(2000));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ip_history_and_inventory() {
        let (s, dir) = store();
        let mac = "aa:bb:cc:dd:ee:01";
        s.sample(&[lease(mac, "10.0.0.2")], &[], 1000, retention(730))
            .unwrap();
        s.sample(&[lease(mac, "10.0.0.5")], &[], 2000, retention(730))
            .unwrap(); // roamed
        let devs = s.all_devices(2000).unwrap();
        assert_eq!(devs.len(), 1);
        let d = &devs[0];
        assert_eq!(d.last_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(d.first_seen, Some(1000));
        assert_eq!(d.ips.len(), 2); // history of both IPs
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retention_prunes_old_daily() {
        let (s, dir) = store();
        let mac = "aa:bb:cc:dd:ee:01";
        let day = SECONDS_PER_DAY;
        s.sample(
            &[lease(mac, "10.0.0.2")],
            &[ctr("10.0.0.2", 0)],
            0,
            retention(730),
        )
        .unwrap();
        s.sample(
            &[lease(mac, "10.0.0.2")],
            &[ctr("10.0.0.2", 1000)],
            100,
            retention(730),
        )
        .unwrap(); // day 0
                   // 1000 days later with retention 30 -> day-0 bucket pruned, bytes_7d empty
        s.sample(
            &[lease(mac, "10.0.0.2")],
            &[ctr("10.0.0.2", 1000)],
            1000 * day,
            retention(30),
        )
        .unwrap();
        let m = s.get_many(&[mac.into()], 1000 * day).unwrap();
        assert_eq!(m[mac].bytes_7d, Some(0));
        assert_eq!(m[mac].bytes_total, Some(1000)); // total is not pruned
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retention_prunes_aged_out_devices() {
        let (s, dir) = store();
        let day = SECONDS_PER_DAY;
        let stale = "aa:bb:cc:dd:ee:01";
        let fresh = "aa:bb:cc:dd:ee:02";
        // `stale` last seen at t=0, never observed again.
        s.sample(&[lease(stale, "10.0.0.2")], &[], 0, retention(730))
            .unwrap();
        // 1000 days later a different device ticks with retention 30 days; the
        // cutoff (970 days) is past `stale`'s last_seen, so it is pruned.
        s.sample(&[lease(fresh, "10.0.0.3")], &[], 1000 * day, retention(30))
            .unwrap();
        let devs = s.all_devices(1000 * day).unwrap();
        let macs: Vec<&str> = devs.iter().map(|d| d.mac.as_str()).collect();
        assert!(!macs.contains(&stale), "aged-out device must be pruned");
        assert!(macs.contains(&fresh), "recently seen device must remain");
        // Its IP baseline must be cleaned up too (no orphan in ip_samples).
        let m = s.get_many(&[stale.into()], 1000 * day).unwrap();
        assert!(!m.contains_key(stale));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rate_bps_from_last_interval() {
        let (s, dir) = store();
        let a = "aa:bb:cc:dd:ee:01"; // active with traffic in tick 2
        let b = "aa:bb:cc:dd:ee:02"; // active but idle in tick 2
        s.sample(
            &[lease(a, "10.0.0.2"), lease(b, "10.0.0.3")],
            &[ctr("10.0.0.2", 5000)],
            1000,
            retention(730),
        )
        .unwrap();
        // +3000 bytes on `a` over a 300s interval -> 10 bytes/sec.
        s.sample(
            &[lease(a, "10.0.0.2"), lease(b, "10.0.0.3")],
            &[ctr("10.0.0.2", 8000)],
            1300,
            retention(730),
        )
        .unwrap();
        let m = s.get_many(&[a.into(), b.into()], 1300).unwrap();
        assert_eq!(m[a].rate_bps, Some(10));
        assert_eq!(m[b].rate_bps, Some(0), "active but idle -> 0, not null");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rate_bps_none_when_inactive_in_latest_tick() {
        let (s, dir) = store();
        let a = "aa:bb:cc:dd:ee:01";
        let b = "aa:bb:cc:dd:ee:02";
        s.sample(
            &[lease(a, "10.0.0.2"), lease(b, "10.0.0.3")],
            &[],
            1000,
            retention(730),
        )
        .unwrap();
        // Only `a` ticks now; `b` wasn't observed in the latest tick.
        s.sample(&[lease(a, "10.0.0.2")], &[], 1300, retention(730))
            .unwrap();
        let m = s.get_many(&[a.into(), b.into()], 1300).unwrap();
        assert_eq!(m[a].rate_bps, Some(0));
        assert_eq!(m[b].rate_bps, None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dashboard_aggregates() {
        let (s, dir) = store();
        let now = 1_000_000;
        let a = "aa:bb:cc:dd:ee:01";
        let b = "aa:bb:cc:dd:ee:02";
        s.sample(
            &[lease(a, "10.0.0.2"), lease(b, "10.0.0.3")],
            &[ctr("10.0.0.2", 1000), ctr("10.0.0.3", 2000)],
            now,
            retention(730),
        )
        .unwrap();
        // `a` gains +4000 over 300s; `b` is flat.
        s.sample(
            &[lease(a, "10.0.0.2"), lease(b, "10.0.0.3")],
            &[ctr("10.0.0.2", 5000), ctr("10.0.0.3", 2000)],
            now + 300,
            retention(730),
        )
        .unwrap();
        let d = s.dashboard(now + 300, 5).unwrap();
        assert_eq!(d.devices_total, 2);
        // online = had traffic in the latest tick: only `a` (b was flat).
        assert_eq!(d.devices_online, 1);
        assert_eq!(d.traffic_today_bytes, 4000);
        assert_eq!(d.total_rate_bps, 13); // 4000 / 300
        assert_eq!(d.top_talkers.first().unwrap().mac, a);
        std::fs::remove_dir_all(&dir).ok();
    }

    fn lease_cltt(mac: &str, ip: &str, cltt: i64) -> LeaseObservation {
        LeaseObservation {
            mac: mac.into(),
            ip: ip.into(),
            hostname: None,
            vendor: None,
            last_seen: Some(cltt),
        }
    }

    #[test]
    fn last_seen_tracks_cltt_not_now() {
        let (s, dir) = store();
        let now = 1_000_000;
        let a = "aa:bb:cc:dd:ee:01";
        let cltt = now - 3600; // device last talked to dhcpd an hour ago
        s.sample(&[lease_cltt(a, "10.0.0.2", cltt)], &[], now, retention(730))
            .unwrap();
        let m = s.get_many(&[a.into()], now).unwrap();
        assert_eq!(m[a].last_seen, Some(cltt), "last_seen = cltt, not now");
        assert_eq!(m[a].first_seen, Some(now), "first_seen = first observation");

        // Newer cltt advances last_seen; older cltt must NOT move it back (monotonic).
        s.sample(
            &[lease_cltt(a, "10.0.0.2", now - 60)],
            &[],
            now + 300,
            retention(730),
        )
        .unwrap();
        assert_eq!(
            s.get_many(&[a.into()], now + 300).unwrap()[a].last_seen,
            Some(now - 60)
        );
        s.sample(
            &[lease_cltt(a, "10.0.0.2", now - 99_999)],
            &[],
            now + 600,
            retention(730),
        )
        .unwrap();
        assert_eq!(
            s.get_many(&[a.into()], now + 600).unwrap()[a].last_seen,
            Some(now - 60),
            "older cltt must not move last_seen backward"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn online_requires_recent_traffic_and_fresh_sample() {
        let (s, dir) = store();
        let now = 1_000_000;
        let a = "aa:bb:cc:dd:ee:01"; // has traffic in tick 2
        let b = "aa:bb:cc:dd:ee:02"; // active lease but idle
        s.sample(
            &[lease(a, "10.0.0.2"), lease(b, "10.0.0.3")],
            &[ctr("10.0.0.2", 1000)],
            now,
            retention(730),
        )
        .unwrap();
        s.sample(
            &[lease(a, "10.0.0.2"), lease(b, "10.0.0.3")],
            &[ctr("10.0.0.2", 5000)],
            now + 300,
            retention(730),
        )
        .unwrap();
        let m = s.get_many(&[a.into(), b.into()], now + 300).unwrap();
        assert!(m[a].online, "traffic in last tick -> online");
        assert!(!m[b].online, "idle-but-leased -> offline");

        // A stale sample (read far in the future) -> nobody is online.
        let m = s.get_many(&[a.into()], now + 300 + 100_000).unwrap();
        assert!(!m[a].online, "stale sample -> offline");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn device_detail_returns_series_and_none_for_unknown() {
        let (s, dir) = store();
        let now = 1_000_000;
        let a = "aa:bb:cc:dd:ee:01";
        s.sample(
            &[lease(a, "10.0.0.2")],
            &[ctr("10.0.0.2", 1000)],
            now,
            retention(730),
        )
        .unwrap();
        s.sample(
            &[lease(a, "10.0.0.2")],
            &[ctr("10.0.0.2", 4000)],
            now + 300,
            retention(730),
        )
        .unwrap();
        let detail = s.device_detail(a, now + 300, 30).unwrap().unwrap();
        assert_eq!(detail.device.mac, a);
        assert_eq!(detail.device.bytes_today, 3000);
        assert_eq!(detail.daily.len(), 1);
        assert_eq!(detail.daily[0].bytes, 3000);
        assert!(s
            .device_detail("ff:ff:ff:ff:ff:ff", now + 300, 30)
            .unwrap()
            .is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn migration_v1_to_v2_preserves_data() {
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("dm-mig-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v1.sqlite");
        let _ = std::fs::remove_file(&path);

        // Hand-build a v1 DB (old schema, no rate columns / meta, user_version=1).
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE devices (
                    mac TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
                    last_ip TEXT, last_hostname TEXT, last_vendor TEXT,
                    bytes_total INTEGER NOT NULL DEFAULT 0, packets_total INTEGER NOT NULL DEFAULT 0);
                 CREATE TABLE device_ips (mac TEXT NOT NULL, ip TEXT NOT NULL, first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL, PRIMARY KEY (mac, ip));
                 CREATE TABLE ip_samples (ip TEXT PRIMARY KEY, mac TEXT, last_bytes INTEGER NOT NULL,
                    last_packets INTEGER NOT NULL);
                 CREATE TABLE traffic_daily (mac TEXT NOT NULL, day INTEGER NOT NULL,
                    bytes INTEGER NOT NULL DEFAULT 0, packets INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (mac, day));",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO devices (mac, first_seen, last_seen, last_ip, bytes_total, packets_total)
                 VALUES ('aa:bb:cc:dd:ee:01', 100, 200, '10.0.0.2', 4242, 7)",
                [],
            )
            .unwrap();
            conn.pragma_update(None, "user_version", 1i64).unwrap();
        }

        // Opening migrates v1 -> current (adds rate columns + meta + rollup tables),
        // preserving rows.
        let s = DeviceMetricsStore::open(&path).unwrap();
        let conn = Connection::open(&path).unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        let m = s
            .get_many(&["aa:bb:cc:dd:ee:01".into()], 1_000_000)
            .unwrap();
        assert_eq!(m["aa:bb:cc:dd:ee:01"].bytes_total, Some(4242));
        assert_eq!(m["aa:bb:cc:dd:ee:01"].packets_total, Some(7));
        assert_eq!(m["aa:bb:cc:dd:ee:01"].rate_bps, None);

        // Re-opening is a no-op (idempotent; ALTER must not run twice).
        assert!(DeviceMetricsStore::open(&path).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn granularity_parse_roundtrip() {
        for (s, g) in [
            ("day", Granularity::Day),
            ("hour", Granularity::Hour),
            ("5m", Granularity::FiveMin),
        ] {
            assert_eq!(Granularity::parse(s), Some(g));
            assert_eq!(g.as_str(), s);
        }
        assert_eq!(Granularity::parse("minute"), None);
        assert_eq!(Granularity::parse("5min"), None);
        assert_eq!(Granularity::parse(""), None);
    }

    #[test]
    fn sample_writes_rollups_and_jitter_sums() {
        let (s, dir) = store();
        let a = "aa:bb:cc:dd:ee:01";
        let ip = "10.0.0.2";
        // Baseline (first observation -> delta 0, no bucket row).
        s.sample(&[lease(a, ip)], &[ctr(ip, 1000)], 999_900, retention(730))
            .unwrap();
        // +2000 then +2000 — both land in the SAME 5min (999_900) and hour bucket,
        // so the upsert must SUM (jitter), not overwrite.
        s.sample(&[lease(a, ip)], &[ctr(ip, 3000)], 999_960, retention(730))
            .unwrap();
        s.sample(&[lease(a, ip)], &[ctr(ip, 5000)], 1_000_050, retention(730))
            .unwrap();

        let five = s
            .traffic_series(a, Granularity::FiveMin, 0, 2_000_000)
            .unwrap()
            .unwrap();
        assert_eq!(five.len(), 1, "all three ticks share one 5min bucket");
        assert_eq!(five[0].ts, fivemin_start(999_960));
        assert_eq!(five[0].bytes, 4000, "jitter must sum, not overwrite");

        let hourly = s
            .traffic_series(a, Granularity::Hour, 0, 2_000_000)
            .unwrap()
            .unwrap();
        assert_eq!(hourly.len(), 1);
        assert_eq!(hourly[0].ts, hour_start(999_960));
        assert_eq!(hourly[0].bytes, 4000);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn traffic_series_unknown_mac_and_empty_window() {
        let (s, dir) = store();
        let a = "aa:bb:cc:dd:ee:01";
        s.sample(
            &[lease(a, "10.0.0.2")],
            &[ctr("10.0.0.2", 1000)],
            1_000_000,
            retention(730),
        )
        .unwrap();
        s.sample(
            &[lease(a, "10.0.0.2")],
            &[ctr("10.0.0.2", 5000)],
            1_000_300,
            retention(730),
        )
        .unwrap();

        // Unknown MAC -> None (404 at the HTTP layer).
        assert!(s
            .traffic_series("ff:ff:ff:ff:ff:ff", Granularity::Hour, 0, 2_000_000)
            .unwrap()
            .is_none());
        // Known MAC, window with no buckets -> Some([]) (200, not an error).
        assert!(s
            .traffic_series(a, Granularity::FiveMin, 5_000_000, 6_000_000)
            .unwrap()
            .unwrap()
            .is_empty());
        // Day granularity carries the +4000 delta.
        let day = s
            .traffic_series(a, Granularity::Day, 0, 2_000_000)
            .unwrap()
            .unwrap();
        assert_eq!(day.iter().map(|p| p.bytes).sum::<i64>(), 4000);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn retention_prunes_rollups_keeps_daily() {
        let (s, dir) = store();
        let a = "aa:bb:cc:dd:ee:01";
        let ip = "10.0.0.2";
        s.sample(&[lease(a, ip)], &[ctr(ip, 1000)], 1_000_000, retention(730))
            .unwrap();
        s.sample(&[lease(a, ip)], &[ctr(ip, 5000)], 1_000_300, retention(730))
            .unwrap();
        // 100 days later, short rollup retention (hourly 7d, 5min 1h) prunes the
        // old rollup buckets; daily (730d) keeps them.
        let later = 1_000_000 + 100 * 24 * 3600;
        let ret = Retention {
            daily_days: 730,
            hourly_days: 7,
            fivemin_hours: 1,
        };
        s.sample(&[lease(a, ip)], &[], later, ret).unwrap();

        assert!(s
            .traffic_series(a, Granularity::FiveMin, 0, 9_000_000_000)
            .unwrap()
            .unwrap()
            .is_empty());
        assert!(s
            .traffic_series(a, Granularity::Hour, 0, 9_000_000_000)
            .unwrap()
            .unwrap()
            .is_empty());
        let day = s
            .traffic_series(a, Granularity::Day, 0, 9_000_000_000)
            .unwrap()
            .unwrap();
        assert!(day.iter().any(|p| p.bytes == 4000), "daily must survive");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn migration_v2_to_v3_adds_rollup_tables() {
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("dm-mig3-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("v2.sqlite");
        let _ = std::fs::remove_file(&path);

        // Hand-build a v2 DB (rate columns + meta, no rollup tables, user_version=2).
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE devices (mac TEXT PRIMARY KEY, first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL, last_ip TEXT, last_hostname TEXT, last_vendor TEXT,
                    bytes_total INTEGER NOT NULL DEFAULT 0, packets_total INTEGER NOT NULL DEFAULT 0,
                    last_delta_bytes INTEGER NOT NULL DEFAULT 0, last_delta_at INTEGER NOT NULL DEFAULT 0);
                 CREATE TABLE device_ips (mac TEXT NOT NULL, ip TEXT NOT NULL, first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL, PRIMARY KEY (mac, ip));
                 CREATE TABLE ip_samples (ip TEXT PRIMARY KEY, mac TEXT, last_bytes INTEGER NOT NULL,
                    last_packets INTEGER NOT NULL);
                 CREATE TABLE traffic_daily (mac TEXT NOT NULL, day INTEGER NOT NULL,
                    bytes INTEGER NOT NULL DEFAULT 0, packets INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (mac, day));
                 CREATE TABLE meta (key TEXT PRIMARY KEY, value INTEGER);",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO devices (mac, first_seen, last_seen, bytes_total) VALUES ('aa:bb:cc:dd:ee:01', 100, 200, 4242)",
                [],
            ).unwrap();
            conn.execute(
                "INSERT INTO traffic_daily (mac, day, bytes, packets) VALUES ('aa:bb:cc:dd:ee:01', 86400, 4242, 7)",
                [],
            ).unwrap();
            conn.pragma_update(None, "user_version", 2i64).unwrap();
        }

        let s = DeviceMetricsStore::open(&path).unwrap();
        let conn = Connection::open(&path).unwrap();
        let v: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 3);

        // Existing daily data preserved.
        let day = s
            .traffic_series("aa:bb:cc:dd:ee:01", Granularity::Day, 0, 200_000)
            .unwrap()
            .unwrap();
        assert_eq!(day.len(), 1);
        assert_eq!(day[0].bytes, 4242);
        // New rollup tables exist and are queryable (empty).
        assert!(s
            .traffic_series("aa:bb:cc:dd:ee:01", Granularity::FiveMin, 0, 200_000)
            .unwrap()
            .unwrap()
            .is_empty());
        assert!(s
            .traffic_series("aa:bb:cc:dd:ee:01", Granularity::Hour, 0, 200_000)
            .unwrap()
            .unwrap()
            .is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}
