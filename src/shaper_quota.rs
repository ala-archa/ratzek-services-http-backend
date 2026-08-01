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
//! **The fix — two reset triggers.**
//! 1. *Periodic (this job):* purely time-based — ~`period` after a client is first seen
//!    in the set (and every `period` after) its counter is reset with
//!    `ipset del shaper <ip>` (the entry is re-created from zero by the next packet, so
//!    no disconnect and the throttle mark clears at once). It does NOT read DHCP leases
//!    (a leases-read failure must not false-reset everyone), so it is MAC-agnostic.
//! 2. *At registration (`note_registration`, from `client_register`):* resets the
//!    counter when the IP changes hands — the tracked MAC differs from the one the
//!    client authenticated with. That MAC is read server-side from the dhcpd lease by
//!    source IP (not from the request body), so it can't be spoofed via the API, and a
//!    re-registration by the same client (same lease MAC) does NOT reset (prevents a
//!    trivial quota bypass on the open `POST /api/v1/client`). This fixes a new tenant
//!    inheriting the previous tenant's byte counter on a reused IP.
//!
//! **Design notes.**
//! - **In-memory, ephemeral.** Windows live only in memory (like `live_traffic`),
//!   never on the flaky USB-SSD. On restart windows re-seed; any *reboot* wipes the
//!   kernel ipset (counters → 0) anyway, so persistence would buy almost nothing.
//! - **Reset only on a KNOWN-different MAC.** An unknown previous MAC (`None`:
//!   job-seeded, or after a process restart while the kernel ipset survived) adopts the
//!   MAC without resetting — so registration never zeroes a counter without positive
//!   evidence of a hand-over (no bypass). That residual inheritance self-heals within
//!   one period via trigger #1.
//! - **`window_start` moves only on an actual reset**, so a same-MAC re-registration
//!   never pushes the window forward (no "throttled forever" regression).
//! - **Clock-safe.** The host has no reliable RTC. A backward wall-clock jump
//!   (`now < window_start`) is treated as "expired → reset now" — the safe
//!   (un-throttle) direction. The registration reset is MAC-only, time-independent.
//! - **Anti-herd.** A new member's window is seeded at `now - rand(0..period)`, so the
//!   members present at startup expire staggered across the first window.

use crate::ipset::IPSet;
use rand::Rng;
use slog_scope::{debug, error, info, warn};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::RwLock;

/// Per-IP quota window: when the counter was last zeroed, and the last MAC known to
/// hold the IP (`None` = unknown: job-seeded or not yet learned via registration).
#[derive(Debug, Clone, PartialEq)]
struct Window {
    window_start: i64,
    mac: Option<String>,
}

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

/// Classify `members` (IPs currently in the shaper set) against `windows`. Pure.
fn plan_resets(
    members: &HashSet<&str>,
    windows: &HashMap<String, Window>,
    now: i64,
    period: i64,
) -> Decision {
    let mut d = Decision::default();
    for &ip in members {
        match windows.get(ip) {
            None => d.new.push(ip.to_string()),
            // `now < start`: RTC-less host jumped backward → treat as expired (reset),
            // the un-throttle direction. `>=`: the window fully elapsed.
            Some(w) if now < w.window_start || now - w.window_start >= period => {
                d.expired.push(ip.to_string())
            }
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

/// Phase 1 of a pass (runs under the write lock): seed new members (`mac: None` — the
/// job never reads leases), prune stale IPs, and return the expired IPs to reset. Does
/// NO ipset I/O — the blocking `ipset del` for the returned IPs runs OUTSIDE the lock
/// (see `run_pass`), so a concurrent registration never stalls behind a whole pass.
fn plan_and_prepare(
    windows: &mut HashMap<String, Window>,
    members: &HashSet<&str>,
    now: i64,
    period: i64,
    mut seed: impl FnMut() -> i64,
) -> Vec<String> {
    let d = plan_resets(members, windows, now, period);
    for ip in d.new {
        windows.insert(
            ip,
            Window {
                window_start: seed(),
                mac: None,
            },
        );
    }
    for ip in &d.stale {
        windows.remove(ip);
    }
    d.expired
}

/// Phase 3 of a pass (runs under the write lock): advance the window of each IP whose
/// counter was actually reset, **preserving** its learned `mac`. IPs whose `ipset del`
/// failed are simply not passed here, so their window is left unchanged (retried next
/// tick).
fn advance_windows(windows: &mut HashMap<String, Window>, ips: &[String], now: i64) {
    for ip in ips {
        if let Some(w) = windows.get_mut(ip) {
            w.window_start = now;
        }
    }
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

/// In-memory per-IP quota-window tracker + reset driver, plus its own monitoring
/// counters. Cheap; always constructed (the job is gated by config at scheduling
/// time, not here). Held as an `Arc` in `State`; `run_and_record` runs inside a
/// `spawn_blocking` and folds its outcome straight into the atomics below, so
/// `State` needs no separate metric fields.
pub struct ShaperQuota {
    windows: RwLock<HashMap<String, Window>>,
    shaper_set: String,
    period_secs: i64,
    quota_bytes: u64,
    /// Unix epoch of the last successful pass (0 = never), for the staleness gauge.
    last_run: AtomicI64,
    /// Monotonic count of counter resets performed by the periodic job.
    resets_total: AtomicI64,
    /// Monotonic count of per-IP `ipset del` failures in the periodic job.
    errors_total: AtomicI64,
    /// Members past the byte quota at the last pass (gauge).
    over_quota: AtomicI64,
    /// Monotonic count of counter resets performed at registration (MAC change on IP).
    register_resets: AtomicI64,
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
            register_resets: AtomicI64::new(0),
        }
    }

    /// Record a captive-portal registration for `ip` by `mac` (the dhcpd-lease MAC, not
    /// a request field). Returns `Some(old_mac)` when this is a KNOWN change of tenant
    /// on the IP — the caller must then `ipset del <ip>` (outside this lock) to zero the
    /// inherited counter — else `None` (fresh IP, unknown-previous, or same MAC: no
    /// reset). `window_start` is advanced only on an actual reset. In-memory only; the
    /// critical section is tiny and does no I/O.
    pub fn note_registration(&self, ip: &str, mac: &str, now: i64) -> Option<String> {
        let mut windows = self.windows.write().unwrap_or_else(|e| e.into_inner());
        match windows.get_mut(ip) {
            Some(w) => match &w.mac {
                // Same client re-registering: no reset, leave the window untouched.
                Some(cur) if cur == mac => None,
                // Known different MAC → IP changed hands → reset the inherited counter.
                Some(_) => {
                    let old = w.mac.replace(mac.to_string());
                    w.window_start = now;
                    self.register_resets.fetch_add(1, Ordering::Relaxed);
                    old
                }
                // Unknown previous MAC (job-seeded / post-restart): learn it, no reset.
                None => {
                    w.mac = Some(mac.to_string());
                    None
                }
            },
            // Brand-new IP: learn it, no reset (counter is presumed the client's own).
            None => {
                windows.insert(
                    ip.to_string(),
                    Window {
                        window_start: now,
                        mac: Some(mac.to_string()),
                    },
                );
                None
            }
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

    /// Total counter resets performed at registration (MAC change on an IP).
    pub fn register_resets(&self) -> i64 {
        self.register_resets.load(Ordering::Relaxed)
    }

    /// One reset pass. Reads the shaper set, seeds/prunes windows, and `ipset del`s
    /// expired members. The blocking `ipset del`s run OUTSIDE the `windows` lock (the
    /// lock is only held for the tiny seed/prune and advance phases) so a concurrent
    /// registration never stalls behind the whole pass. Blocking (shells out to `ipset`).
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

        // Phase 1 (short lock): seed new / prune stale / collect expired. No ipset I/O.
        // Recover a poisoned lock rather than propagate the panic (a partial prior pass
        // is self-corrected by this and later ticks) — MUST match `note_registration`.
        let expired = {
            let mut windows = self.windows.write().unwrap_or_else(|e| e.into_inner());
            plan_and_prepare(&mut windows, &members, now, period, || now - jitter(period))
        };

        // Phase 2 (NO lock): reset each expired counter via a blocking `ipset del`.
        let mut succeeded: Vec<String> = Vec::new();
        let mut errors = 0u64;
        for ip in expired {
            match set.del(&ip) {
                Ok(()) => succeeded.push(ip),
                Err(err) => {
                    // Expected/tolerable per-IP failure → warn (not error): a transient
                    // ipset hiccup shouldn't page; whole-pass failure surfaces via the
                    // staleness gauge instead.
                    warn!("shaper-quota: ipset del {} failed: {:#}", ip, err);
                    errors += 1;
                }
            }
        }

        // Phase 3 (short lock): advance the windows we actually reset (preserve mac).
        {
            let mut windows = self.windows.write().unwrap_or_else(|e| e.into_inner());
            advance_windows(&mut windows, &succeeded, now);
        }

        Ok(PassStats {
            members: member_ips.len(),
            resets: succeeded.len() as u64,
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

    fn win(start: i64, mac: Option<&str>) -> Window {
        Window {
            window_start: start,
            mac: mac.map(str::to_string),
        }
    }

    fn store(set_name: &str) -> ShaperQuota {
        ShaperQuota::new(set_name.to_string(), 10800, 1_073_741_824)
    }

    // ---- plan_resets (time-window classification) ----

    #[test]
    fn new_member_is_classified_new() {
        let d = plan_resets(&set(&["10.0.0.1"]), &HashMap::new(), 1000, 10800);
        assert_eq!(d.new, vec!["10.0.0.1"]);
        assert!(d.expired.is_empty() && d.stale.is_empty());
    }

    #[test]
    fn not_expired_before_period_and_at_boundary_uses_ge() {
        let mut windows = HashMap::new();
        windows.insert("a".to_string(), win(1000, Some("aa"))); // exactly period old at now
        windows.insert("b".to_string(), win(1001, Some("bb"))); // one second short
        let d = plan_resets(&set(&["a", "b"]), &windows, 1000 + 10800, 10800);
        assert_eq!(sorted(d.expired), vec!["a"]);
    }

    #[test]
    fn backward_clock_jump_expires() {
        let mut windows = HashMap::new();
        windows.insert("a".to_string(), win(5000, Some("aa")));
        // now < window_start (clock jumped back) → expired (safe un-throttle).
        let d = plan_resets(&set(&["a"]), &windows, 4000, 10800);
        assert_eq!(d.expired, vec!["a"]);
    }

    #[test]
    fn absent_member_is_stale() {
        let mut windows = HashMap::new();
        windows.insert("a".to_string(), win(1000, None));
        windows.insert("gone".to_string(), win(1000, Some("gg")));
        let d = plan_resets(&set(&["a"]), &windows, 1100, 10800);
        assert_eq!(d.stale, vec!["gone"]);
        assert!(d.expired.is_empty());
    }

    // ---- plan_and_prepare / advance_windows (job phases) ----

    #[test]
    fn prepare_seeds_new_with_none_mac_and_prunes_stale() {
        let mut windows = HashMap::new();
        windows.insert("gone".to_string(), win(500, Some("gg")));
        let expired = plan_and_prepare(&mut windows, &set(&["fresh"]), 1000, 10800, || 777);
        assert!(expired.is_empty());
        assert_eq!(windows.get("fresh"), Some(&win(777, None))); // seeded, mac unknown
        assert!(!windows.contains_key("gone")); // pruned
    }

    #[test]
    fn prepare_returns_expired_without_touching_them() {
        let mut windows = HashMap::new();
        windows.insert("a".to_string(), win(0, Some("aa")));
        let expired = plan_and_prepare(&mut windows, &set(&["a"]), 20000, 10800, || 0);
        assert_eq!(expired, vec!["a"]);
        // Not advanced yet — that happens only after a successful del (phase 3).
        assert_eq!(windows.get("a"), Some(&win(0, Some("aa"))));
    }

    #[test]
    fn advance_preserves_mac_only_for_given_ips() {
        let mut windows = HashMap::new();
        windows.insert("ok".to_string(), win(0, Some("aa")));
        windows.insert("failed".to_string(), win(0, Some("bb")));
        // Simulate: del succeeded for "ok", failed for "failed" (not passed in).
        advance_windows(&mut windows, &["ok".to_string()], 20000);
        assert_eq!(windows.get("ok"), Some(&win(20000, Some("aa")))); // advanced, mac kept
        assert_eq!(windows.get("failed"), Some(&win(0, Some("bb")))); // untouched
    }

    // ---- note_registration (registration-time MAC-change reset) ----

    #[test]
    fn register_brand_new_ip_learns_without_reset() {
        let q = store("s");
        assert_eq!(q.note_registration("10.0.0.1", "aa", 100), None);
        assert_eq!(q.register_resets(), 0);
    }

    #[test]
    fn register_same_mac_does_not_reset_and_keeps_window() {
        let q = store("s");
        q.note_registration("10.0.0.1", "aa", 100);
        // Re-register far later with the SAME mac → no reset, window NOT pushed forward.
        assert_eq!(q.note_registration("10.0.0.1", "aa", 99999), None);
        assert_eq!(q.register_resets(), 0);
        assert_eq!(
            q.windows.read().unwrap().get("10.0.0.1"),
            Some(&win(100, Some("aa")))
        );
    }

    #[test]
    fn register_known_different_mac_resets_and_reanchors() {
        let q = store("s");
        q.note_registration("10.0.0.1", "aa", 100);
        // New tenant on the same IP → reset, returns the old mac, window re-anchored.
        assert_eq!(q.note_registration("10.0.0.1", "bb", 5000), Some("aa".to_string()));
        assert_eq!(q.register_resets(), 1);
        assert_eq!(
            q.windows.read().unwrap().get("10.0.0.1"),
            Some(&win(5000, Some("bb")))
        );
    }

    #[test]
    fn register_unknown_previous_mac_learns_without_reset() {
        let q = store("s");
        // Job seeded the IP with mac:None (never reads leases).
        q.windows
            .write()
            .unwrap()
            .insert("10.0.0.1".to_string(), win(50, None));
        // First registration must NOT reset — no positive evidence of a hand-over.
        assert_eq!(q.note_registration("10.0.0.1", "aa", 100), None);
        assert_eq!(q.register_resets(), 0);
        // MAC learned; window_start preserved (still the job-seeded value).
        assert_eq!(
            q.windows.read().unwrap().get("10.0.0.1"),
            Some(&win(50, Some("aa")))
        );
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
