//! Per-client (per-IP) byte-quota window reset for the `shaper` ipset.
//!
//! **The problem.** On the host, the "speed limit" is a byte quota enforced entirely
//! in iptables: every forwarded packet hits `-j SET --add-set shaper src/dst`, which
//! for the `bitmap:ip … timeout 10800 counters` set re-adds the client on every
//! packet — resetting its 3h timeout AND accumulating bytes — and a
//! `--match-set shaper src --bytes-gt <quota> -j MARK 333` rule throttles (via tc)
//! any client whose counter passes the quota. Because traffic keeps refreshing the
//! timeout, the entry only expires (and its counter resets to 0) after ~3h of *zero*
//! traffic. A device with background traffic (phone push/sync) never goes fully idle
//! for 3h, so its counter stays above the quota and it is throttled indefinitely.
//! There was no periodic quota reset anywhere in the system.
//!
//! **The fix.** This module runs a scheduled job that gives each client a personal
//! rolling window: ~3h after a client is first seen in the set (and every ~3h after),
//! its counter is reset with `ipset del shaper <ip>`. The entry is re-created from
//! zero by the client's next packet (the `SET --add-set` rule precedes the accept /
//! `--bytes-gt` rules in FORWARD), so there is no disconnect and the throttle mark
//! clears immediately. This is the exact `IPSet::del` the manual
//! `admin_device_reset_shaper_counter` endpoint already uses in production.
//!
//! **Design notes.**
//! - **In-memory, ephemeral.** Windows live only in memory (like `live_traffic`),
//!   never on the flaky USB-SSD. On restart windows re-seed; the worst case is a
//!   reset deferred by ≤ one window, and any *reboot* wipes the kernel ipset (all
//!   counters → 0) anyway, so persistence would buy almost nothing.
//! - **Time-only.** The reset decision is purely time-based. It deliberately does
//!   NOT key off the DHCP MAC (spoofable on a captive portal → quota bypass; a leases
//!   read failure would false-reset everyone). Counter inheritance on IP reassignment
//!   is bounded by the 3h window regardless.
//! - **Clock-safe.** The host has no reliable RTC. A backward wall-clock jump
//!   (`now < window_start`) is treated as "expired → reset now" — the safe
//!   (un-throttle) direction — never a permanent non-reset.
//! - **Anti-herd.** A new member's window is seeded at `now - rand(0..period)`, so
//!   the members present at startup expire staggered across the first window instead
//!   of all resetting in one tick.

use crate::ipset::IPSet;
use rand::Rng;
use slog_scope::{debug, error, info, warn};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::RwLock;

/// Pure classification of the current shaper members against the tracked windows.
/// No I/O and no RNG, so it is unit-tested directly.
#[derive(Debug, Default, PartialEq)]
struct Decision {
    /// Members with no window yet — a fresh (jittered) window must be seeded.
    new: Vec<String>,
    /// Members whose window elapsed (`now - start >= period`) or whose clock jumped
    /// backward (`now < start`) — reset their counter now.
    expired: Vec<String>,
    /// Tracked IPs no longer in the set — drop them so `windows` can't leak.
    stale: Vec<String>,
}

/// Classify `members` (IPs currently in the shaper set) against `windows`
/// (ip → window_start, unix secs). Pure.
fn plan_resets(
    members: &HashSet<&str>,
    windows: &HashMap<String, i64>,
    now: i64,
    period: i64,
) -> Decision {
    let mut d = Decision::default();
    for &ip in members {
        match windows.get(ip) {
            None => d.new.push(ip.to_string()),
            // `now < start`: RTC-less host jumped backward → treat as expired (reset),
            // the un-throttle direction. `>=`: the window fully elapsed.
            Some(&start) if now < start || now - start >= period => d.expired.push(ip.to_string()),
            Some(_) => {}
        }
    }
    for ip in windows.keys() {
        if !members.contains(ip.as_str()) {
            d.stale.push(ip.clone());
        }
    }
    d
}

/// Outcome of one reset pass, for logging + metrics.
#[derive(Debug, Default, PartialEq)]
struct PassStats {
    /// Current shaper members this tick.
    members: usize,
    /// Counters reset (successful `ipset del`).
    resets: u64,
    /// Per-IP `ipset del` failures (retried next tick; window not advanced).
    errors: u64,
    /// Members currently past the byte quota (for a gauge; informational).
    over_quota: usize,
}

/// Apply one pass to `windows`, deleting expired entries via the `del` closure.
/// Split out (RNG + del injected) so it is fully unit-testable without real ipset.
///
/// `seed` yields the initial `window_start` for a new member (prod: `now - jitter`).
/// `del(ip)` returns `true` on a successful counter reset. A member's window is
/// advanced to `now` ONLY on success, so a failed `del` is retried next tick.
fn apply_pass(
    windows: &mut HashMap<String, i64>,
    members: &HashSet<&str>,
    now: i64,
    period: i64,
    mut seed: impl FnMut() -> i64,
    mut del: impl FnMut(&str) -> bool,
) -> (u64, u64) {
    let d = plan_resets(members, windows, now, period);
    for ip in d.new {
        windows.insert(ip, seed());
    }
    for ip in &d.stale {
        windows.remove(ip);
    }
    let (mut resets, mut errors) = (0u64, 0u64);
    for ip in d.expired {
        if del(&ip) {
            windows.insert(ip, now);
            resets += 1;
        } else {
            // Leave window_start unchanged → next ~60s tick retries this IP.
            errors += 1;
        }
    }
    (resets, errors)
}

/// In-memory per-IP quota-window tracker + reset driver, plus its own monitoring
/// counters. Cheap; always constructed (the job is gated by config at scheduling
/// time, not here). Held as an `Arc` in `State`; `run_and_record` runs inside a
/// `spawn_blocking` and folds its outcome straight into the atomics below, so
/// `State` needs no separate metric fields.
pub struct ShaperQuota {
    windows: RwLock<HashMap<String, i64>>,
    shaper_set: String,
    period_secs: i64,
    quota_bytes: u64,
    /// Unix epoch of the last successful pass (0 = never), for the staleness gauge.
    last_run: AtomicI64,
    /// Monotonic count of counter resets performed (successful `ipset del`).
    resets_total: AtomicI64,
    /// Monotonic count of per-IP `ipset del` failures.
    errors_total: AtomicI64,
    /// Members past the byte quota at the last pass (gauge).
    over_quota: AtomicI64,
}

impl ShaperQuota {
    /// Build a tracker for `shaper_set` with a `period_secs` per-client window and a
    /// `quota_bytes` throttle threshold (used only for the over-quota gauge; the real
    /// threshold lives in iptables). `period_secs` is floored to `>= 1` defensively —
    /// config `validate()` already rejects `<= 0`.
    pub fn new(shaper_set: String, period_secs: i64, quota_bytes: u64) -> Self {
        Self {
            windows: RwLock::new(HashMap::new()),
            shaper_set,
            period_secs: period_secs.max(1),
            quota_bytes,
            last_run: AtomicI64::new(0),
            resets_total: AtomicI64::new(0),
            errors_total: AtomicI64::new(0),
            over_quota: AtomicI64::new(0),
        }
    }

    /// Run one reset pass and fold the outcome into the monitoring counters. Logs the
    /// result; never returns (best-effort, like the other samplers). Blocking (shells
    /// out to `ipset`) — the caller runs it inside `spawn_blocking`. `now` is a unix
    /// timestamp (seconds).
    pub fn run_and_record(&self, now: i64) {
        match self.run_pass(now) {
            Ok(stats) => {
                // Relaxed: these are independent counters/gauges; no reader depends on
                // ordering between them. `last_run` is stored LAST so a scrape that
                // sees an advanced age also sees the updated counters.
                self.resets_total
                    .fetch_add(stats.resets as i64, Ordering::Relaxed);
                self.errors_total
                    .fetch_add(stats.errors as i64, Ordering::Relaxed);
                self.over_quota.store(stats.over_quota as i64, Ordering::Relaxed);
                self.last_run.store(now, Ordering::Relaxed);
                // Routine ticks with nothing to do stay quiet; log only when something moved.
                if stats.resets > 0 || stats.errors > 0 {
                    info!(
                        "shaper-quota pass: {} members, {} resets, {} errors, {} over quota",
                        stats.members, stats.resets, stats.errors, stats.over_quota
                    );
                } else {
                    debug!(
                        "shaper-quota pass: {} members, 0 resets, {} over quota",
                        stats.members, stats.over_quota
                    );
                }
            }
            Err(err) => error!("shaper-quota pass failed: {:#}", err),
        }
    }

    /// Monitoring snapshot: (last-run epoch, resets total, errors total,
    /// members-over-quota). `last_run == 0` means the job never ran.
    pub fn stats(&self) -> (i64, i64, i64, i64) {
        (
            self.last_run.load(Ordering::Relaxed),
            self.resets_total.load(Ordering::Relaxed),
            self.errors_total.load(Ordering::Relaxed),
            self.over_quota.load(Ordering::Relaxed),
        )
    }

    /// One reset pass. Reads the shaper set, seeds/advances/prunes windows, and
    /// `ipset del`s expired members. Blocking (shells out to `ipset`).
    ///
    /// # Errors
    /// Returns `Err` only if the whole `ipset save` read failed (nothing was touched;
    /// the caller logs and retries next tick). Per-IP `del` failures are counted in
    /// `PassStats.errors`, not fatal.
    fn run_pass(&self, now: i64) -> anyhow::Result<PassStats> {
        let set = IPSet::new(&self.shaper_set);
        let entries = set.entries()?;
        let over_quota = entries
            .iter()
            .filter(|e| e.bytes.is_some_and(|b| b as u64 > self.quota_bytes))
            .count();
        let member_ips: Vec<String> = entries.into_iter().map(|e| e.ip).collect();
        let members: HashSet<&str> = member_ips.iter().map(String::as_str).collect();
        let period = self.period_secs;

        // Recover a poisoned lock rather than propagate the panic (a partial prior
        // pass is self-corrected by this and later ticks).
        let mut windows = self.windows.write().unwrap_or_else(|e| e.into_inner());
        let (resets, errors) = apply_pass(
            &mut windows,
            &members,
            now,
            period,
            || now - jitter(period),
            |ip| match set.del(ip) {
                Ok(()) => true,
                Err(err) => {
                    // Expected/tolerable per-IP failure → warn (not error): a transient
                    // ipset hiccup shouldn't page; whole-pass failure surfaces via the
                    // staleness gauge instead.
                    warn!("shaper-quota: ipset del {} failed: {:#}", ip, err);
                    false
                }
            },
        );
        Ok(PassStats {
            members: member_ips.len(),
            resets,
            errors,
            over_quota,
        })
    }
}

/// Random offset in `[0, period)` used to desynchronize new members' first reset.
fn jitter(period: i64) -> i64 {
    if period <= 1 {
        0
    } else {
        rand::thread_rng().gen_range(0..period)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set<'a>(ips: &[&'a str]) -> HashSet<&'a str> {
        ips.iter().copied().collect()
    }

    fn sorted(mut v: Vec<String>) -> Vec<String> {
        v.sort();
        v
    }

    #[test]
    fn new_member_is_classified_new() {
        let members = set(&["10.0.0.1"]);
        let windows = HashMap::new();
        let d = plan_resets(&members, &windows, 1000, 10800);
        assert_eq!(d.new, vec!["10.0.0.1"]);
        assert!(d.expired.is_empty() && d.stale.is_empty());
    }

    #[test]
    fn not_expired_before_period_and_at_boundary_uses_ge() {
        let members = set(&["a", "b"]);
        let mut windows = HashMap::new();
        windows.insert("a".to_string(), 1000); // exactly period old at now
        windows.insert("b".to_string(), 1001); // one second short
        // now == start + period → expired (>=). now == start+period-1 → not yet.
        let d = plan_resets(&members, &windows, 1000 + 10800, 10800);
        assert_eq!(sorted(d.expired), vec!["a"]);
    }

    #[test]
    fn backward_clock_jump_expires() {
        let members = set(&["a"]);
        let mut windows = HashMap::new();
        windows.insert("a".to_string(), 5000);
        // now < window_start (clock jumped back) → expired (safe un-throttle).
        let d = plan_resets(&members, &windows, 4000, 10800);
        assert_eq!(d.expired, vec!["a"]);
    }

    #[test]
    fn absent_member_is_stale() {
        let members = set(&["a"]);
        let mut windows = HashMap::new();
        windows.insert("a".to_string(), 1000);
        windows.insert("gone".to_string(), 1000);
        let d = plan_resets(&members, &windows, 1100, 10800);
        assert_eq!(d.stale, vec!["gone"]);
        assert!(d.expired.is_empty());
    }

    #[test]
    fn apply_seeds_new_and_prunes_stale() {
        let mut windows = HashMap::new();
        windows.insert("gone".to_string(), 500);
        let members = set(&["fresh"]);
        let (resets, errors) = apply_pass(&mut windows, &members, 1000, 10800, || 777, |_| true);
        assert_eq!((resets, errors), (0, 0));
        assert_eq!(windows.get("fresh"), Some(&777)); // seeded
        assert!(!windows.contains_key("gone")); // pruned
    }

    #[test]
    fn apply_advances_window_only_on_successful_del() {
        // Expired member, del succeeds → window advances to now, counted as reset.
        let mut windows = HashMap::new();
        windows.insert("a".to_string(), 0);
        let members = set(&["a"]);
        let (resets, errors) = apply_pass(&mut windows, &members, 20000, 10800, || 0, |_| true);
        assert_eq!((resets, errors), (1, 0));
        assert_eq!(windows.get("a"), Some(&20000));
    }

    #[test]
    fn apply_leaves_window_on_del_failure() {
        // Expired member, del fails → window unchanged (retried next tick), error counted.
        let mut windows = HashMap::new();
        windows.insert("a".to_string(), 0);
        let members = set(&["a"]);
        let (resets, errors) = apply_pass(&mut windows, &members, 20000, 10800, || 0, |_| false);
        assert_eq!((resets, errors), (0, 1));
        assert_eq!(windows.get("a"), Some(&0)); // NOT advanced
    }

    #[test]
    fn jitter_is_within_range_and_zero_for_degenerate_period() {
        assert_eq!(jitter(0), 0);
        assert_eq!(jitter(1), 0);
        for _ in 0..1000 {
            let j = jitter(10800);
            assert!((0..10800).contains(&j), "jitter out of range: {j}");
        }
    }
}
