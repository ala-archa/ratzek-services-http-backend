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

const SCHEMA_VERSION: i64 = 1;
const SECONDS_PER_DAY: i64 = 86_400;
/// SQLite `busy_timeout` for both the writer and short-lived readers.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// Rolling window (in days) for the `bytes_7d` aggregate, inclusive of today.
const TRAFFIC_WINDOW_DAYS: i64 = 7;

/// Per-device metrics joined into API listings. All optional so a device with no
/// row (or a transient DB error) serializes as `null`s without breaking the response.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct DeviceMetrics {
    pub first_seen: Option<i64>,
    pub last_seen: Option<i64>,
    pub bytes_total: Option<i64>,
    pub bytes_today: Option<i64>,
    pub bytes_7d: Option<i64>,
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
    pub bytes_today: i64,
    pub bytes_7d: i64,
}

/// One active-lease observation fed to [`DeviceMetricsStore::sample`]. Decoupled
/// from the dhcp/ipset types so the store is testable in isolation.
#[derive(Debug, Clone)]
pub struct LeaseObservation {
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
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
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            last_ip TEXT,
            last_hostname TEXT,
            last_vendor TEXT,
            bytes_total INTEGER NOT NULL DEFAULT 0,
            packets_total INTEGER NOT NULL DEFAULT 0
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
         CREATE INDEX IF NOT EXISTS idx_traffic_daily_day ON traffic_daily(day);",
    )?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(())
}

fn day_start(now: i64) -> i64 {
    now / SECONDS_PER_DAY * SECONDS_PER_DAY
}

/// Start of the rolling `bytes_7d` window (inclusive of `today`).
fn window_start(today: i64) -> i64 {
    today - (TRAFFIC_WINDOW_DAYS - 1) * SECONDS_PER_DAY
}

/// Fold `(mac, day, bytes)` rows from `traffic_daily` into per-MAC
/// `(bytes_today, bytes_7d)` totals. Callers pre-filter rows to the 7-day
/// window via SQL, so every row contributes to `bytes_7d`; rows for `today`
/// additionally contribute to `bytes_today`.
fn fold_daily(
    rows: impl IntoIterator<Item = (String, i64, i64)>,
    today: i64,
) -> HashMap<String, (i64, i64)> {
    let mut acc: HashMap<String, (i64, i64)> = HashMap::new();
    for (mac, day, bytes) in rows {
        let entry = acc.entry(mac).or_insert((0, 0));
        entry.1 += bytes; // bytes_7d
        if day == today {
            entry.0 += bytes; // bytes_today
        }
    }
    acc
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
    /// re-running with identical inputs adds no traffic (per-IP delta is 0).
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
        retention_days: i64,
    ) -> Result<SampleStats> {
        // `std::Mutex` stays poisoned forever after a writer panic, which would
        // make every subsequent tick panic too. A panicking transaction is rolled
        // back during unwind, so the DB is consistent and recovering the guard is
        // safe.
        let mut conn = self.write.lock().unwrap_or_else(|e| e.into_inner());
        let tx = conn.transaction()?;
        let mut stats = SampleStats::default();
        let day = day_start(now);

        let ip_to_mac: HashMap<&str, &str> = leases
            .iter()
            .map(|l| (l.ip.as_str(), l.mac.as_str()))
            .collect();

        // 1) Upsert device + IP-history rows from active leases.
        for l in leases {
            tx.execute(
                "INSERT INTO devices (mac, first_seen, last_seen, last_ip, last_hostname, last_vendor)
                 VALUES (?1, ?2, ?2, ?3, ?4, ?5)
                 ON CONFLICT(mac) DO UPDATE SET
                   last_seen = excluded.last_seen,
                   last_ip = excluded.last_ip,
                   last_hostname = COALESCE(excluded.last_hostname, last_hostname),
                   last_vendor = COALESCE(excluded.last_vendor, last_vendor)",
                params![l.mac, now, l.ip, l.hostname, l.vendor],
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
                       packets_total = packets_total + ?3 WHERE mac = ?1",
                    params![mac, dbytes, dpackets],
                )?;
                tx.execute(
                    "INSERT INTO traffic_daily (mac, day, bytes, packets)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(mac, day) DO UPDATE SET
                       bytes = bytes + excluded.bytes, packets = packets + excluded.packets",
                    params![mac, day, dbytes, dpackets],
                )?;
                stats.bytes_added += dbytes;
            }
            stats.ips += 1;
        }

        // 3) Retention: drop old daily buckets, stale IP history, aged-out
        //    devices, and the IP baselines orphaned by the device_ips prune.
        if retention_days > 0 {
            let cutoff = day - retention_days * SECONDS_PER_DAY;
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
        let week_ago = window_start(today);
        let placeholders = vec!["?"; macs.len()].join(",");

        let sql = format!(
            "SELECT mac, first_seen, last_seen, last_hostname, last_vendor, bytes_total
             FROM devices WHERE mac IN ({placeholders})"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(macs.iter()), |r| {
            Ok((
                r.get::<_, String>(0)?,
                DeviceMetrics {
                    first_seen: r.get(1)?,
                    last_seen: r.get(2)?,
                    hostname: r.get(3)?,
                    vendor: r.get(4)?,
                    bytes_total: r.get(5)?,
                    bytes_today: Some(0),
                    bytes_7d: Some(0),
                },
            ))
        })?;
        for row in rows {
            let (mac, m) = row?;
            out.insert(mac, m);
        }

        // Recent daily traffic (small: macs x <=7 days), aggregated in Rust.
        let mut stmt = conn.prepare("SELECT mac, day, bytes FROM traffic_daily WHERE day >= ?1")?;
        let rows = stmt
            .query_map(params![week_ago], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (mac, (today_bytes, week_bytes)) in fold_daily(rows, today) {
            if let Some(m) = out.get_mut(&mac) {
                m.bytes_today = Some(today_bytes);
                m.bytes_7d = Some(week_bytes);
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
        let week_ago = window_start(today);

        let mut by_mac: HashMap<String, DeviceRow> = HashMap::new();
        let mut stmt = conn.prepare(
            "SELECT mac, last_ip, last_hostname, last_vendor, first_seen, last_seen, bytes_total
             FROM devices",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(DeviceRow {
                mac: r.get(0)?,
                last_ip: r.get(1)?,
                hostname: r.get(2)?,
                vendor: r.get(3)?,
                first_seen: r.get(4)?,
                last_seen: r.get(5)?,
                bytes_total: r.get(6)?,
                bytes_today: 0,
                bytes_7d: 0,
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
            .query_map(params![week_ago], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (mac, (today_bytes, week_bytes)) in fold_daily(rows, today) {
            if let Some(dev) = by_mac.get_mut(&mac) {
                dev.bytes_today = today_bytes;
                dev.bytes_7d = week_bytes;
            }
        }

        Ok(by_mac.into_values().collect())
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
        }
    }
    fn ctr(ip: &str, bytes: i64) -> IpsetCounter {
        IpsetCounter {
            ip: ip.into(),
            bytes,
            packets: bytes / 100,
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
                730,
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
            730,
        )
        .unwrap(); // baseline
        let st = s
            .sample(
                &[lease(mac, "10.0.0.2")],
                &[ctr("10.0.0.2", 1500)],
                2000,
                730,
            )
            .unwrap();
        assert_eq!(st.bytes_added, 500); // 1500-1000
                                         // counter reset: current (300) < previous (1500) -> add current
        let st = s
            .sample(
                &[lease(mac, "10.0.0.2")],
                &[ctr("10.0.0.2", 300)],
                3000,
                730,
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
            730,
        )
        .unwrap();
        s.sample(
            &[lease(mac, "10.0.0.2")],
            &[ctr("10.0.0.2", 2000)],
            2000,
            730,
        )
        .unwrap();
        // same inputs again -> no extra traffic
        let st = s
            .sample(
                &[lease(mac, "10.0.0.2")],
                &[ctr("10.0.0.2", 2000)],
                2000,
                730,
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
        let st = s.sample(&[], &[ctr("10.0.0.9", 5000)], 1000, 730).unwrap();
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
            730,
        )
        .unwrap();
        s.sample(
            &[lease(mac, "10.0.0.2")],
            &[ctr("10.0.0.2", 2000)],
            10 * day + 100,
            730,
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
        s.sample(&[lease(mac, "10.0.0.2")], &[], 1000, 730).unwrap();
        s.sample(&[lease(mac, "10.0.0.5")], &[], 2000, 730).unwrap(); // roamed
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
        s.sample(&[lease(mac, "10.0.0.2")], &[ctr("10.0.0.2", 0)], 0, 730)
            .unwrap();
        s.sample(
            &[lease(mac, "10.0.0.2")],
            &[ctr("10.0.0.2", 1000)],
            100,
            730,
        )
        .unwrap(); // day 0
                   // 1000 days later with retention 30 -> day-0 bucket pruned, bytes_7d empty
        s.sample(
            &[lease(mac, "10.0.0.2")],
            &[ctr("10.0.0.2", 1000)],
            1000 * day,
            30,
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
        s.sample(&[lease(stale, "10.0.0.2")], &[], 0, 730).unwrap();
        // 1000 days later a different device ticks with retention 30 days; the
        // cutoff (970 days) is past `stale`'s last_seen, so it is pruned.
        s.sample(&[lease(fresh, "10.0.0.3")], &[], 1000 * day, 30)
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
}
