//! In-memory live per-device traffic (bytes over the last minute + current rate),
//! sampled every ~15s from ipset byte counters + dhcpd leases (IP→MAC). Powers the
//! `bytes_last_min` / `rate_bps_live` fields in `GET /api/v1/admin/devices` — i.e.
//! "who is using the channel right now". The 5-minute `device_metrics` sampler is
//! too coarse and too laggy for that question; this is a separate, lightweight,
//! purely in-memory path.
//!
//! Design notes:
//! - **Ephemeral.** Held entirely in memory; lost on restart — intentional. Live
//!   speed must be fresh (<60s), so persistence buys nothing on a host that reboots
//!   often. After a restart the fields read `null` until the first sample lands.
//! - **Total, not up/down.** ipset exposes a single byte counter per IP; direction
//!   is not separated (splitting would need two nft/ipset counters, out of scope for
//!   this backend).
//! - **Approximate.** Counters are cumulative and reset when an ipset entry is
//!   recreated (timeout re-add / manual counter reset); we treat `current < prev` as
//!   a reset and count `current` as the fresh delta (same as `device_metrics`). The
//!   first observation of an IP only sets a baseline (no sample), so a pre-existing
//!   counter isn't counted retroactively. Traffic while a device roams IPs
//!   mid-interval can be lost (counters are per-IP, not per-MAC).
//! - **Clock-safe.** The host has no reliable RTC. A backward clock jump clears the
//!   series; a non-positive / oversized interval yields a `null` rate (never divides
//!   by zero, which would panic and poison the lock).

use crate::device_metrics::IpsetCounter;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;
use std::time::Duration;

/// Defensive per-MAC sample cap. With a 60s window and ~15s ticks a deque holds ~4
/// points; this only bounds pathological backlogs (ticks piling up after a stall).
const MAX_SAMPLES_PER_MAC: usize = 8;
/// Interval (s) above which a rate is not "live" (the tick came from the background
/// after a stall). Matches the device-metrics 5-min cadence; larger → `rate_bps_live`
/// is reported as `null` instead of a misleadingly-averaged value.
const MAX_DT_SECS: i64 = 300;
/// Implausible-rate ceiling (~10 Gbit/s in bytes/s): a computed rate above this is
/// treated as a counter anomaly and reported as `null` rather than a bogus spike.
const MAX_PLAUSIBLE_RATE_BPS: i64 = 1_250_000_000;

/// Last raw ipset byte counter for an IP (baseline for the next delta).
struct RawCounter {
    bytes: i64,
}

/// One per-MAC delta observation within the window. `dt` is stored per-sample so an
/// irregular cadence (a skipped tick under the overlap-guard) still yields a correct
/// rate rather than assuming a fixed interval.
struct Sample {
    ts: i64,
    delta_bytes: i64,
    dt: i64,
}

#[derive(Default)]
struct Inner {
    /// Last raw ipset reading per IP (baseline for the next delta).
    prev: HashMap<String, RawCounter>,
    /// Recent per-MAC deltas within the window.
    series: HashMap<String, VecDeque<Sample>>,
    /// Timestamp of the last ingest, to detect a backward clock jump and to derive
    /// the per-tick interval.
    last_sample_ts: i64,
}

/// Per-MAC live traffic surfaced to the API.
#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq)]
pub struct LivePoint {
    /// Total bytes (up+down) attributed to the MAC within the window.
    pub bytes_last_min: i64,
    /// Current throughput (bytes/sec) from the latest tick, or `None` when the
    /// interval is unusable (clock skew / stale / implausible).
    pub rate_bps_live: Option<i64>,
}

/// Summary of one [`LiveTraffic::ingest`] pass, for logging.
#[derive(Debug, Default, PartialEq)]
pub struct SampleStats {
    pub macs_tracked: usize,
    pub series_points: usize,
    pub ips_read: usize,
}

/// Compute a live rate from a single tick's delta, guarding every degenerate case:
/// non-positive / oversized interval → `None` (no division by zero, no stale
/// averaging); implausibly-high rate → `None` (counter anomaly).
fn rate_bps(delta_bytes: i64, dt: i64) -> Option<i64> {
    if dt <= 0 || dt > MAX_DT_SECS {
        return None;
    }
    let r = delta_bytes / dt;
    if r > MAX_PLAUSIBLE_RATE_BPS {
        None
    } else {
        Some(r)
    }
}

pub struct LiveTraffic {
    inner: RwLock<Inner>,
    window_secs: i64,
}

impl LiveTraffic {
    pub fn new(window: Duration) -> Self {
        Self {
            inner: RwLock::new(Inner::default()),
            window_secs: (window.as_secs() as i64).max(1),
        }
    }

    /// Feed one sample: raw ipset counters + the current IP→MAC map. Computes per-IP
    /// deltas since the last reading, attributes them to MACs, trims the window and
    /// drops IPs that vanished from ipset. Purely in-memory; never panics (a poisoned
    /// lock is recovered). `now` is a unix timestamp in seconds; callers must use the
    /// same clock across calls.
    pub fn ingest(
        &self,
        counters: &[IpsetCounter],
        ip_to_mac: &HashMap<String, String>,
        now: i64,
    ) -> SampleStats {
        // Recover a poisoned lock rather than propagating the panic: a partially
        // applied prior pass is self-corrected by this and later ticks.
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        let window = self.window_secs;

        // Backward clock jump (no RTC): existing samples are timestamped in the
        // "future"; drop them all so the window math stays sane.
        if now < inner.last_sample_ts {
            inner.series.clear();
        }
        // Per-tick interval (0 on the very first ingest — but there are no baselines
        // yet, so no samples are pushed that tick).
        let tick_dt = now - inner.last_sample_ts;

        // Sum this tick's delta per MAC (borrowing MAC strings from `ip_to_mac`).
        let active_ips: HashSet<&str> = counters.iter().map(|c| c.ip.as_str()).collect();
        let mut delta_by_mac: HashMap<&str, i64> = HashMap::new();
        for c in counters {
            let Some(p) = inner.prev.get(&c.ip) else {
                // First observation of this IP: baseline only, no sample (don't count
                // a pre-existing counter as a burst).
                inner
                    .prev
                    .insert(c.ip.clone(), RawCounter { bytes: c.bytes });
                continue;
            };
            // `current < prev` = ipset entry recreated: count `current` as fresh
            // traffic (matches device_metrics reset handling).
            let delta = if c.bytes < p.bytes {
                c.bytes
            } else {
                c.bytes - p.bytes
            };
            inner
                .prev
                .insert(c.ip.clone(), RawCounter { bytes: c.bytes });
            if let Some(mac) = ip_to_mac.get(&c.ip) {
                *delta_by_mac.entry(mac.as_str()).or_insert(0) += delta;
            }
        }

        // Push one sample per MAC seen this tick (delta may be 0 for an active-idle
        // device — that legitimately reads as "online, no bandwidth").
        for (mac, delta) in delta_by_mac {
            inner
                .series
                .entry(mac.to_string())
                .or_default()
                .push_back(Sample {
                    ts: now,
                    delta_bytes: delta,
                    dt: tick_dt,
                });
        }

        // Trim every MAC's deque by window then hard-cap, and drop emptied MACs.
        inner.series.retain(|_mac, dq| {
            while dq.front().is_some_and(|s| s.ts < now - window) {
                dq.pop_front();
            }
            while dq.len() > MAX_SAMPLES_PER_MAC {
                dq.pop_front();
            }
            !dq.is_empty()
        });

        // Drop baselines for IPs that vanished from ipset (else `prev` leaks forever).
        inner.prev.retain(|ip, _| active_ips.contains(ip.as_str()));

        inner.last_sample_ts = now;

        SampleStats {
            macs_tracked: inner.series.len(),
            series_points: inner.series.values().map(|d| d.len()).sum(),
            ips_read: counters.len(),
        }
    }

    /// Snapshot per-MAC live points. Fast in-memory read; MACs with no fresh samples
    /// (within the window) are simply absent (the caller renders them as `null`).
    /// `now` is a unix timestamp in seconds and must match the `ingest` clock.
    pub fn snapshot(&self, now: i64) -> HashMap<String, LivePoint> {
        let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
        let window = self.window_secs;
        let mut out = HashMap::with_capacity(inner.series.len());
        for (mac, dq) in &inner.series {
            // Only points within the window (ingest trims, but guard for reads
            // happening between ticks).
            let bytes_last_min: i64 = dq
                .iter()
                .filter(|s| s.ts >= now - window)
                .map(|s| s.delta_bytes)
                .sum();
            // Rate from the latest sample, but only if it is itself recent.
            let rate_bps_live = dq
                .back()
                .filter(|s| s.ts >= now - window)
                .and_then(|s| rate_bps(s.delta_bytes, s.dt));
            out.insert(
                mac.clone(),
                LivePoint {
                    bytes_last_min,
                    rate_bps_live,
                },
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctr(ip: &str, bytes: i64) -> IpsetCounter {
        IpsetCounter {
            ip: ip.into(),
            bytes,
            packets: bytes / 100,
        }
    }

    /// IP→MAC map from `(ip, mac)` pairs.
    fn macs(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(ip, mac)| (ip.to_string(), mac.to_string()))
            .collect()
    }

    fn new_lt() -> LiveTraffic {
        LiveTraffic::new(Duration::from_secs(60))
    }

    #[test]
    fn first_observation_is_baseline_only() {
        let lt = new_lt();
        let m = macs(&[("10.0.0.1", "aa")]);
        // First tick: only a baseline, no sample yet -> MAC absent from snapshot.
        lt.ingest(&[ctr("10.0.0.1", 1000)], &m, 100);
        assert!(!lt.snapshot(100).contains_key("aa"));
    }

    #[test]
    fn normal_delta_and_rate() {
        let lt = new_lt();
        let m = macs(&[("10.0.0.1", "aa")]);
        lt.ingest(&[ctr("10.0.0.1", 1000)], &m, 100); // baseline
        lt.ingest(&[ctr("10.0.0.1", 1600)], &m, 110); // +600 over 10s
        let p = lt.snapshot(110)["aa"];
        assert_eq!(p.bytes_last_min, 600);
        assert_eq!(p.rate_bps_live, Some(60));
    }

    #[test]
    fn reset_counts_current_as_delta() {
        let lt = new_lt();
        let m = macs(&[("10.0.0.1", "aa")]);
        lt.ingest(&[ctr("10.0.0.1", 5000)], &m, 100); // baseline
                                                      // Entry recreated: current(300) < prev(5000) -> delta = 300, not 0 nor huge.
        lt.ingest(&[ctr("10.0.0.1", 300)], &m, 110);
        let p = lt.snapshot(110)["aa"];
        assert_eq!(p.bytes_last_min, 300);
        assert_eq!(p.rate_bps_live, Some(30));
    }

    #[test]
    fn multiple_ips_per_mac_sum() {
        let lt = new_lt();
        let m = macs(&[("10.0.0.1", "aa"), ("10.0.0.2", "aa")]);
        lt.ingest(&[ctr("10.0.0.1", 100), ctr("10.0.0.2", 200)], &m, 100);
        lt.ingest(&[ctr("10.0.0.1", 400), ctr("10.0.0.2", 700)], &m, 110); // +300 +500
        let p = lt.snapshot(110)["aa"];
        assert_eq!(p.bytes_last_min, 800);
    }

    #[test]
    fn window_trims_old_samples() {
        let lt = new_lt();
        let m = macs(&[("10.0.0.1", "aa")]);
        lt.ingest(&[ctr("10.0.0.1", 0)], &m, 100); // baseline
        lt.ingest(&[ctr("10.0.0.1", 500)], &m, 110); // sample @110
        lt.ingest(&[ctr("10.0.0.1", 900)], &m, 180); // sample @180, @110 now >60s old
        let p = lt.snapshot(180)["aa"];
        // Only the @180 delta (400) remains in the 60s window.
        assert_eq!(p.bytes_last_min, 400);
    }

    #[test]
    fn hard_cap_bounds_deque() {
        let lt = new_lt();
        let m = macs(&[("10.0.0.1", "aa")]);
        // Many ticks 1s apart within the window -> capped at MAX_SAMPLES_PER_MAC.
        lt.ingest(&[ctr("10.0.0.1", 0)], &m, 1000);
        for i in 1..=20 {
            lt.ingest(&[ctr("10.0.0.1", i * 10)], &m, 1000 + i);
        }
        let inner = lt.inner.read().unwrap();
        assert!(inner.series["aa"].len() <= MAX_SAMPLES_PER_MAC);
    }

    #[test]
    fn vanished_ip_pruned_from_prev() {
        let lt = new_lt();
        let m = macs(&[("10.0.0.1", "aa")]);
        lt.ingest(&[ctr("10.0.0.1", 100)], &m, 100);
        // Next tick without that IP -> its baseline is dropped.
        lt.ingest(&[], &macs(&[]), 110);
        let inner = lt.inner.read().unwrap();
        assert!(inner.prev.is_empty());
    }

    #[test]
    fn nonpositive_and_oversized_dt_yield_null_rate() {
        let lt = new_lt();
        let m = macs(&[("10.0.0.1", "aa")]);
        lt.ingest(&[ctr("10.0.0.1", 0)], &m, 100); // baseline
                                                   // Same-timestamp tick (dt = 0): bytes counted, rate is null (no panic).
        lt.ingest(&[ctr("10.0.0.1", 500)], &m, 100);
        let p = lt.snapshot(100)["aa"];
        assert_eq!(p.bytes_last_min, 500);
        assert_eq!(p.rate_bps_live, None);

        // Oversized interval (> MAX_DT_SECS) -> null rate.
        let lt2 = new_lt();
        lt2.ingest(&[ctr("10.0.0.1", 0)], &m, 100);
        lt2.ingest(&[ctr("10.0.0.1", 1_000_000)], &m, 100 + MAX_DT_SECS + 1);
        assert_eq!(
            lt2.snapshot(100 + MAX_DT_SECS + 1)["aa"].rate_bps_live,
            None
        );
    }

    #[test]
    fn backward_clock_jump_clears_stale_series() {
        let lt = new_lt();
        let m = macs(&[("10.0.0.1", "aa")]);
        lt.ingest(&[ctr("10.0.0.1", 0)], &m, 1000);
        lt.ingest(&[ctr("10.0.0.1", 500)], &m, 1010); // sample @1010 (500 bytes)
                                                      // Clock jumps back: the future-stamped 500-byte sample is dropped; only the
                                                      // fresh delta remains, and its rate is null (negative interval, no panic).
        lt.ingest(&[ctr("10.0.0.1", 600)], &m, 500); // +100
        let p = lt.snapshot(500)["aa"];
        assert_eq!(p.bytes_last_min, 100);
        assert_eq!(p.rate_bps_live, None);
    }

    #[test]
    fn empty_store_snapshot_is_empty() {
        assert!(new_lt().snapshot(100).is_empty());
    }
}
