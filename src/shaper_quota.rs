//! Per-client (per-IP) byte-quota reset for the `shaper` ipset.
//!
//! **The problem.** On the host, the "speed limit" is a byte quota enforced entirely
//! in iptables: every forwarded packet hits `-j SET --add-set shaper src/dst`, which
//! for the `bitmap:ip … timeout 10800 counters` set re-adds the client on every
//! packet — resetting its 3h timeout AND accumulating bytes — and a
//! `--match-set shaper src --bytes-gt <quota> -j MARK 333` rule throttles (via tc)
//! any client whose counter passes the quota. Because traffic keeps refreshing the
//! timeout, the entry only expires (and its counter resets to 0) after ~3h of *zero*
//! traffic. A device with background traffic never goes idle for 3h, so its counter
//! stays above the quota and it is throttled indefinitely.
//!
//! **Two reset triggers (both in this scheduled job).**
//! 1. *Time-window:* ~`period` after a client is first seen in the set (and every
//!    `period` after), its counter is reset with `ipset del shaper <ip>` — the entry
//!    is re-created from zero by the next packet (the `SET --add-set` rule precedes the
//!    accept / `--bytes-gt` rules in FORWARD), so no disconnect and the throttle mark
//!    clears at once.
//! 2. *MAC change (inheritance fix):* the `shaper` counter is IP-keyed, so when a DHCP
//!    lease moves to a NEW tenant of a reused IP the new client inherits the previous
//!    tenant's counter (and is instantly throttled). Each tick the job reads the dnsmasq
//!    leases (ip→mac) and, when the tracked MAC for an IP differs from the current lease
//!    MAC, resets the counter. The MAC is server-authoritative (from the lease, not a
//!    request), so it can't be spoofed; a same-MAC client (e.g. a heavy user re-login)
//!    is NOT reset — that is the intended anti-bypass, they get fresh quota only via
//!    trigger #1.
//!
//! **Design notes.**
//! - **In-memory, ephemeral.** Windows live only in memory (like `live_traffic`),
//!   never on the flaky USB-SSD. Any *reboot* wipes the kernel ipset (counters → 0),
//!   so there is nothing to inherit after a reboot; on a bare process restart the store
//!   re-seeds from current leases (see residual cases below).
//! - **Leases-read failure is safe.** If the leases file can't be read this tick, the
//!   MAC logic is skipped entirely (NO resets from it) and only the time-window trigger
//!   runs. A missing/absent lease for an in-set IP is treated as "unknown" — never a
//!   MAC change. So a torn/partial/failed read can never mass-reset (un-throttle)
//!   everyone.
//! - **Reset only on a KNOWN-different MAC.** `mac=None` (job hasn't learned it yet, or
//!   no active lease) is adopted without a reset; `window_start` moves only on an actual
//!   reset, so a same-MAC re-appearance never pushes the window forward.
//! - **Clock-safe.** No reliable RTC; a backward wall-clock jump (`now < window_start`)
//!   is treated as time-expired → reset (the un-throttle direction). MAC-change is a
//!   string compare, time-independent.
//! - **Anti-herd.** A new member's window is seeded at `now - rand(0..period)`.
//! - **Residual (accepted, self-heals ≤ one `period` via the time-window):** a handover
//!   straddling a bare process restart (ipset survives, store re-seeds from the NEW
//!   lease) or a handover while the old tenant's lease had dropped from the file
//!   (`None`→learn) is not caught as a MAC change; the time-window clears it. All
//!   residual misses fail in the un-throttle (availability-safe) direction.

use crate::ipset::IPSet;
use rand::Rng;
use slog_scope::{debug, error, info, warn};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::RwLock;

/// Per-IP quota window: when the counter was last zeroed, and the last MAC known to
/// hold the IP (`None` = unknown: not yet learned from a lease).
#[derive(Debug, Clone, PartialEq)]
struct Window {
    window_start: i64,
    mac: Option<String>,
}

/// A detected IP hand-over: the tracked MAC (`old`) differs from the current dnsmasq
/// lease MAC (`new`) for `ip` → the inherited counter is reset and the window re-anchored
/// to `new`. Named fields (vs a 3-tuple of `String`s) keep ip/old/new unmistakable.
#[derive(Debug, PartialEq)]
struct MacChange {
    ip: String,
    old: String,
    new: String,
}

/// Classify shaper members against the tracked windows for one pass; also applies the
/// no-I/O mutations (seed new members, learn a MAC for a `None` window, prune stale)
/// and returns the IPs whose counter must be `ipset del`-reset (done OUTSIDE the lock
/// by the caller). Two reset reasons are returned separately because phase 3 differs:
/// a time-window reset KEEPS the learned MAC, a MAC-change reset OVERWRITES it.
///
/// `leases` is `None` when the leases file couldn't be read this tick → MAC logic is
/// skipped (only the time-window path runs). `over_quota_ips` is used only to emit a
/// "why NOT reset" debug line for a same-MAC over-quota client.
// 7 params: all are genuinely-needed pure inputs (this is the unit-tested seam); grouping
// them buys nothing and the `over_quota_ips` param exists for a forensic debug line.
#[allow(clippy::too_many_arguments)]
fn plan_and_prepare(
    windows: &mut HashMap<String, Window>,
    members: &HashSet<&str>,
    leases: Option<&HashMap<String, String>>,
    over_quota_ips: &HashSet<String>,
    now: i64,
    period: i64,
    mut seed: impl FnMut() -> i64,
) -> (Vec<String>, Vec<MacChange>) {
    let mut time_expired: Vec<String> = Vec::new();
    let mut mac_changed: Vec<MacChange> = Vec::new();

    for &ip in members {
        let lease_mac: Option<&str> = leases.and_then(|m| m.get(ip)).map(String::as_str);
        let Some(w) = windows.get_mut(ip) else {
            // New member: seed with the lease MAC if known (else None → learn later).
            windows.insert(
                ip.to_string(),
                Window {
                    window_start: seed(),
                    mac: lease_mac.map(str::to_string),
                },
            );
            continue;
        };
        match (w.mac.as_deref(), lease_mac) {
            // Known different MAC → IP changed hands → reset the inherited counter.
            (Some(old), Some(new)) if old != new => {
                mac_changed.push(MacChange {
                    ip: ip.to_string(),
                    old: old.to_string(),
                    new: new.to_string(),
                });
                // NB: mac/window_start updated in phase 3, only after a successful del.
            }
            // Unknown previous MAC → learn it (no reset).
            (None, Some(new)) => {
                debug!("shaper-quota learn mac: ip={} mac={}", ip, new);
                w.mac = Some(new.to_string());
            }
            // Same MAC, or lease unknown/absent → MAC never "changed"; time-window only.
            _ => {
                if now < w.window_start || now - w.window_start >= period {
                    time_expired.push(ip.to_string());
                } else if over_quota_ips.contains(ip) {
                    debug!("shaper-quota over-quota kept: ip={} mac={:?}", ip, w.mac);
                }
            }
        }
    }

    // Prune tracked IPs no longer in the set (their counter is gone → nothing to keep).
    windows.retain(|ip, _| members.contains(ip.as_str()));

    (time_expired, mac_changed)
}

/// Phase 3 (under lock): advance the window of time-window-reset IPs, KEEPING the mac.
fn advance_time(windows: &mut HashMap<String, Window>, ips: &[String], now: i64) {
    for ip in ips {
        if let Some(w) = windows.get_mut(ip) {
            w.window_start = now;
        }
    }
}

/// Phase 3 (under lock): advance the window of MAC-change-reset IPs AND overwrite the
/// stored mac with the new tenant's — else the change re-fires every tick.
fn advance_mac(windows: &mut HashMap<String, Window>, changes: &[(String, String)], now: i64) {
    for (ip, new) in changes {
        if let Some(w) = windows.get_mut(ip) {
            w.window_start = now;
            w.mac = Some(new.clone());
        }
    }
}

/// Outcome of one reset pass, for logging + metrics.
#[derive(Debug, Default, PartialEq)]
struct PassStats {
    members: usize,
    /// Time-window resets (successful `ipset del`).
    time_resets: u64,
    /// MAC-change resets (successful `ipset del`).
    mac_resets: u64,
    /// Per-IP `ipset del` failures (retried next tick).
    errors: u64,
    /// Members past the byte quota at this pass (gauge).
    over_quota: usize,
}

/// In-memory per-IP quota-window tracker + reset driver, plus its own monitoring
/// counters. Always constructed; the job is gated by config at scheduling time.
pub struct ShaperQuota {
    windows: RwLock<HashMap<String, Window>>,
    shaper_set: String,
    period_secs: i64,
    quota_bytes: u64,
    /// dnsmasq leases file + parse params (read each tick for the ip→mac map).
    leases_path: PathBuf,
    dhcp_params: crate::dhcp::DhcpParams,
    /// Unix epoch of the last successful pass (0 = never), for the staleness gauge.
    last_run: AtomicI64,
    /// Monotonic count of time-window resets.
    resets_total: AtomicI64,
    /// Monotonic count of MAC-change (inheritance) resets.
    mac_change_resets: AtomicI64,
    /// Monotonic count of per-IP `ipset del` failures.
    errors_total: AtomicI64,
    /// Members past the byte quota at the last pass (gauge).
    over_quota: AtomicI64,
    /// Monotonic count of leases-read failures (MAC trigger disabled those ticks).
    leases_read_failures: AtomicI64,
    /// Whether the last leases read succeeded — to log only on ok↔fail transitions
    /// (a chronically unreadable file must not warn every tick).
    leases_healthy: AtomicBool,
}

impl ShaperQuota {
    /// Build a tracker for `shaper_set` with a `period_secs` per-client window and a
    /// `quota_bytes` throttle threshold (over-quota gauge only; the real threshold lives
    /// in iptables). `leases_path`/`dhcp_params` feed the per-tick ip→mac map for the
    /// MAC-change trigger. `period_secs` is floored to `>= 1` (config `validate()`
    /// already rejects `<= 0`).
    pub fn new(
        shaper_set: String,
        period_secs: i64,
        quota_bytes: u64,
        leases_path: PathBuf,
        dhcp_params: crate::dhcp::DhcpParams,
    ) -> Self {
        Self {
            windows: RwLock::new(HashMap::new()),
            shaper_set,
            period_secs: period_secs.max(1),
            quota_bytes,
            leases_path,
            dhcp_params,
            last_run: AtomicI64::new(0),
            resets_total: AtomicI64::new(0),
            mac_change_resets: AtomicI64::new(0),
            errors_total: AtomicI64::new(0),
            over_quota: AtomicI64::new(0),
            leases_read_failures: AtomicI64::new(0),
            leases_healthy: AtomicBool::new(true),
        }
    }

    /// Run one reset pass and fold the outcome into the monitoring counters. Logs the
    /// result; never returns (best-effort). Blocking (shells out to `ipset` + reads the
    /// leases file) — the caller runs it inside `spawn_blocking`.
    pub fn run_and_record(&self, now: i64) {
        match self.run_pass(now) {
            Ok(s) => {
                // Relaxed: independent counters/gauges; `last_run` stored LAST so a
                // scrape that sees a fresh age also sees the updated counters.
                self.resets_total
                    .fetch_add(s.time_resets as i64, Ordering::Relaxed);
                self.mac_change_resets
                    .fetch_add(s.mac_resets as i64, Ordering::Relaxed);
                self.errors_total.fetch_add(s.errors as i64, Ordering::Relaxed);
                self.over_quota.store(s.over_quota as i64, Ordering::Relaxed);
                self.last_run.store(now, Ordering::Relaxed);
                if s.time_resets > 0 || s.mac_resets > 0 || s.errors > 0 {
                    info!(
                        "shaper-quota pass: {} members, {} time-resets, {} mac-resets, {} errors, {} over quota",
                        s.members, s.time_resets, s.mac_resets, s.errors, s.over_quota
                    );
                } else {
                    debug!(
                        "shaper-quota pass: {} members, 0 resets, {} over quota",
                        s.members, s.over_quota
                    );
                }
            }
            Err(err) => error!("shaper-quota pass failed: {:#}", err),
        }
    }

    /// Monitoring snapshot: (last-run epoch, time-window resets, errors, over-quota).
    pub fn stats(&self) -> (i64, i64, i64, i64) {
        (
            self.last_run.load(Ordering::Relaxed),
            self.resets_total.load(Ordering::Relaxed),
            self.errors_total.load(Ordering::Relaxed),
            self.over_quota.load(Ordering::Relaxed),
        )
    }

    /// Total MAC-change (inheritance) resets performed.
    pub fn mac_change_resets(&self) -> i64 {
        self.mac_change_resets.load(Ordering::Relaxed)
    }

    /// Total leases-read failures (each disabled the MAC trigger for that tick).
    pub fn leases_read_failures(&self) -> i64 {
        self.leases_read_failures.load(Ordering::Relaxed)
    }

    /// One reset pass. Reads the shaper set + dnsmasq leases, seeds/learns/prunes windows,
    /// and `ipset del`s time-window-expired and MAC-changed members. The blocking
    /// `ipset del`s run OUTSIDE the `windows` lock (held only for the tiny classify and
    /// advance phases). Blocking.
    ///
    /// # Errors
    /// Returns `Err` only if the whole `ipset save` read failed (nothing touched; caller
    /// retries next tick). A leases-read failure is NOT fatal: MAC logic is skipped and
    /// only the time-window trigger runs. Per-IP `del` failures are counted, not fatal.
    fn run_pass(&self, now: i64) -> anyhow::Result<PassStats> {
        let set = IPSet::new(&self.shaper_set);
        let entries = set.entries()?;
        let mut over_quota_ips: HashSet<String> = HashSet::new();
        let mut member_ips: Vec<String> = Vec::with_capacity(entries.len());
        for e in entries {
            if e.bytes.is_some_and(|b| b as u64 > self.quota_bytes) {
                over_quota_ips.insert(e.ip.clone());
            }
            member_ips.push(e.ip);
        }
        let over_quota = over_quota_ips.len();
        let members: HashSet<&str> = member_ips.iter().map(String::as_str).collect();
        let period = self.period_secs;

        // Leases: owned Result → Option. A read failure must NOT abort the pass (the
        // time-window backstop must survive it) and must NOT be read as MAC changes.
        // Log only on ok↔fail transitions so a chronically unreadable file doesn't warn
        // every ~60s; the count is tracked for the RatzekShaperQuotaLeasesUnreadable alert.
        let leases = match crate::dhcp::active_ip_to_mac(&self.leases_path, self.dhcp_params) {
            Ok(m) => {
                if !self.leases_healthy.swap(true, Ordering::Relaxed) {
                    info!("shaper-quota: leases read recovered");
                }
                Some(m)
            }
            Err(err) => {
                self.leases_read_failures.fetch_add(1, Ordering::Relaxed);
                if self.leases_healthy.swap(false, Ordering::Relaxed) {
                    warn!(
                        "shaper-quota: leases read failed: {:#}; mac logic skipped (repeats at debug)",
                        err
                    );
                } else {
                    debug!("shaper-quota: leases read still failing: {:#}", err);
                }
                None
            }
        };

        // Phase 1 (short lock): classify, seed/learn/prune, collect resets. No ipset I/O.
        let (time_expired, mac_changed) = {
            let mut windows = self.windows.write().unwrap_or_else(|e| e.into_inner());
            plan_and_prepare(
                &mut windows,
                &members,
                leases.as_ref(),
                &over_quota_ips,
                now,
                period,
                || now - jitter(period),
            )
        };

        // Phase 2 (NO lock): reset each counter via a blocking `ipset del`.
        let mut time_ok: Vec<String> = Vec::new();
        let mut mac_ok: Vec<(String, String)> = Vec::new();
        let mut errors = 0u64;
        for ip in time_expired {
            match set.del(&ip) {
                Ok(()) => {
                    debug!("shaper-quota time-window reset: ip={}", ip);
                    time_ok.push(ip);
                }
                Err(err) => {
                    warn!("shaper-quota: ipset del {} (time) failed: {:#}", ip, err);
                    errors += 1;
                }
            }
        }
        for MacChange { ip, old, new } in mac_changed {
            match set.del(&ip) {
                Ok(()) => {
                    info!("shaper-quota mac-change reset: ip={} {}->{}", ip, old, new);
                    mac_ok.push((ip, new));
                }
                Err(err) => {
                    warn!("shaper-quota: ipset del {} (mac-change) failed: {:#}", ip, err);
                    errors += 1;
                }
            }
        }

        // Phase 3 (short lock): advance windows we actually reset (mac-change overwrites
        // the mac; time-window keeps it). Failed dels are excluded → retried next tick.
        {
            let mut windows = self.windows.write().unwrap_or_else(|e| e.into_inner());
            advance_time(&mut windows, &time_ok, now);
            advance_mac(&mut windows, &mac_ok, now);
        }

        Ok(PassStats {
            members: member_ips.len(),
            time_resets: time_ok.len() as u64,
            mac_resets: mac_ok.len() as u64,
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

    fn win(start: i64, mac: Option<&str>) -> Window {
        Window {
            window_start: start,
            mac: mac.map(str::to_string),
        }
    }

    fn leases(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(ip, mac)| (ip.to_string(), mac.to_string()))
            .collect()
    }

    /// Run phase-1 classification with a fixed seed and no over-quota set.
    fn prep(
        windows: &mut HashMap<String, Window>,
        members: &HashSet<&str>,
        lease: Option<&HashMap<String, String>>,
        now: i64,
        period: i64,
    ) -> (Vec<String>, Vec<MacChange>) {
        plan_and_prepare(windows, members, lease, &HashSet::new(), now, period, || 0)
    }

    #[test]
    fn heavy_user_same_mac_is_not_reset() {
        // The .193/Rezeda regression: same lease MAC, window not elapsed → no reset.
        let mut w = HashMap::from([("ip".to_string(), win(1000, Some("aa")))]);
        let l = leases(&[("ip", "aa")]);
        let (time, mac) = prep(&mut w, &set(&["ip"]), Some(&l), 1500, 10800);
        assert!(time.is_empty() && mac.is_empty());
    }

    #[test]
    fn known_different_mac_is_a_mac_change() {
        let mut w = HashMap::from([("ip".to_string(), win(1000, Some("aa")))]);
        let l = leases(&[("ip", "bb")]);
        let (time, mac) = prep(&mut w, &set(&["ip"]), Some(&l), 1500, 10800);
        assert!(time.is_empty());
        assert_eq!(
            mac,
            vec![MacChange {
                ip: "ip".to_string(),
                old: "aa".to_string(),
                new: "bb".to_string()
            }]
        );
        // Not mutated yet (phase 3 does that after a successful del).
        assert_eq!(w["ip"], win(1000, Some("aa")));
        // Phase 3 overwrites mac + advances window.
        advance_mac(&mut w, &[("ip".to_string(), "bb".to_string())], 1500);
        assert_eq!(w["ip"], win(1500, Some("bb")));
    }

    #[test]
    fn lease_missing_for_member_is_not_a_mac_change() {
        // Torn/expired lease: IP in set, no active lease → treat as unknown, never reset.
        let mut w = HashMap::from([("ip".to_string(), win(1000, Some("aa")))]);
        let l = leases(&[]); // no entry for "ip"
        let (time, mac) = prep(&mut w, &set(&["ip"]), Some(&l), 1500, 10800);
        assert!(time.is_empty() && mac.is_empty());
        assert_eq!(w["ip"], win(1000, Some("aa"))); // mac untouched
    }

    #[test]
    fn leases_none_skips_mac_logic_but_time_window_still_fires() {
        let mut w = HashMap::from([
            // Recent window: would be a MAC change if leases were read, but must NOT
            // time-expire — proves the mac path is skipped, not that it expired.
            ("fresh".to_string(), win(19500, Some("aa"))),
            ("old".to_string(), win(0, Some("bb"))), // genuinely time-expired
        ]);
        let (time, mac) = prep(&mut w, &set(&["fresh", "old"]), None, 20000, 10800);
        assert!(mac.is_empty(), "no mac resets when leases unavailable");
        assert_eq!(time, vec!["old".to_string()]);
    }

    #[test]
    fn unknown_previous_mac_is_learned_without_reset() {
        let mut w = HashMap::from([("ip".to_string(), win(50, None))]);
        let l = leases(&[("ip", "aa")]);
        let (time, mac) = prep(&mut w, &set(&["ip"]), Some(&l), 100, 10800);
        assert!(time.is_empty() && mac.is_empty());
        assert_eq!(w["ip"], win(50, Some("aa"))); // learned, window kept
    }

    #[test]
    fn new_member_seeds_with_lease_mac_or_none_no_reset() {
        let mut w = HashMap::new();
        let l = leases(&[("known", "aa")]);
        let (time, mac) = prep(&mut w, &set(&["known", "unknown"]), Some(&l), 100, 10800);
        assert!(time.is_empty() && mac.is_empty());
        assert_eq!(w["known"], win(0, Some("aa")));
        assert_eq!(w["unknown"], win(0, None));
    }

    #[test]
    fn stale_member_is_pruned() {
        let mut w = HashMap::from([
            ("live".to_string(), win(1000, Some("aa"))),
            ("gone".to_string(), win(1000, Some("bb"))),
        ]);
        let l = leases(&[("live", "aa")]);
        prep(&mut w, &set(&["live"]), Some(&l), 1500, 10800);
        assert!(w.contains_key("live") && !w.contains_key("gone"));
    }

    #[test]
    fn time_window_reset_boundary_and_advance_keeps_mac() {
        let mut w = HashMap::from([("ip".to_string(), win(1000, Some("aa")))]);
        let l = leases(&[("ip", "aa")]);
        // now == start + period → expired.
        let (time, mac) = prep(&mut w, &set(&["ip"]), Some(&l), 1000 + 10800, 10800);
        assert!(mac.is_empty());
        assert_eq!(time, vec!["ip".to_string()]);
        advance_time(&mut w, &time, 1000 + 10800);
        assert_eq!(w["ip"], win(1000 + 10800, Some("aa"))); // window advanced, mac kept
    }

    #[test]
    fn backward_clock_jump_time_expires() {
        let mut w = HashMap::from([("ip".to_string(), win(5000, Some("aa")))]);
        let l = leases(&[("ip", "aa")]);
        let (time, _) = prep(&mut w, &set(&["ip"]), Some(&l), 4000, 10800);
        assert_eq!(time, vec!["ip".to_string()]);
    }

    #[test]
    fn del_fail_left_window_unchanged() {
        // Phase 3 is only called for successful dels; an IP whose del failed is simply
        // not passed to advance_*, so its window/mac stay put and it retries next tick.
        let mut w = HashMap::from([("ip".to_string(), win(0, Some("aa")))]);
        advance_time(&mut w, &[], 20000); // del failed → empty success list
        assert_eq!(w["ip"], win(0, Some("aa")));
    }

    #[test]
    fn jitter_is_within_range_and_zero_for_degenerate_period() {
        assert_eq!(jitter(0), 0);
        assert_eq!(jitter(1), 0);
        for _ in 0..1000 {
            assert!((0..10800).contains(&jitter(10800)));
        }
    }
}
