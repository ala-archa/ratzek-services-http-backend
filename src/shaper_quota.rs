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
//! **Three reset triggers (all in this scheduled job).**
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
//! 3. *None-learn inheritance (0.1.39):* trigger #2 only fires when the PREVIOUS owner is
//!    known (`Some(old) → Some(new)`). When the tracked owner is `None` (never learned —
//!    the IP took a live counter while no attributable lease existed) and a lease appears,
//!    the store would otherwise silently learn the new tenant onto the inherited counter.
//!    Instead, if that counter already exceeds `quota_bytes / INHERIT_THRESHOLD_DIVISOR`
//!    (a just-learned owner can't have earned it — see [`is_inherit_suspect`]), it is
//!    reset. This is consulted ONLY under the `Some(new)` learn arm, so a leases-read
//!    failure can never trigger it.
//!
//! **Design notes.**
//! - **`window_start` in-memory; owning-MAC durable.** The per-IP `window_start` lives
//!   only in memory (re-seeded `now - rand(period)` on restart — a clock-agnostic,
//!   un-throttle-safe reset of the time-window). The per-IP *owning-MAC* is persisted by
//!   a separate best-effort job (`persist_once`) to `owner_state_path`, so the
//!   inheritance (MAC-change) trigger survives a bare process restart (which otherwise
//!   re-seeds the store from the NEW lease and never sees the hand-over). Persistence is
//!   the ONLY disk touch and is fully decoupled from the reset pass (see below); an empty
//!   path disables it (pure in-memory, pre-0.1.38 behavior). A *reboot* wipes the kernel
//!   ipset (counters → 0), so a MAC recorded for an IP no longer in the set is naturally
//!   dropped — nothing to inherit.
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
//! - **Persist is decoupled from the reset pass.** A separate scheduled job runs
//!   `persist_once` (its own overlap-guard) — the reset pass (`run_pass`) never touches
//!   the disk. So a wedged `fsync` on the flaky USB-SSD can stall only the persist job
//!   (durability degrades to the in-memory/time-window backstop), never the resets.
//! - **Residual (accepted, self-heals ≤ one `period` via the time-window).** The FIRST
//!   hand-over of an IP after a fresh deploy (owning-MAC not yet persisted) is missed as a
//!   MAC change; the time-window clears it. The 0.1.39 None-learn trigger (#3) now also
//!   catches such a hand-over immediately once the inherited counter exceeds the threshold,
//!   so the only remaining misses are sub-threshold inherited counters and, after a bare
//!   restart with a correlated owner-file + leases read failure, a batch un-throttle of
//!   heavy users (a *reboot* wipes the ipset → counters 0 → not affected). All residual
//!   misses fail in the un-throttle (availability-safe) direction.

use crate::ipset::IPSet;
use rand::Rng;
use serde::{Deserialize, Serialize};
use slog_scope::{debug, error, info, warn};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Mutex, RwLock};

/// Schema version of the persisted owner file. Bump on any breaking layout change; a
/// file with a higher version is treated as unreadable (empty store) — availability-safe.
const OWNER_SCHEMA_VERSION: u32 = 1;

/// Per-IP quota window: when the counter was last zeroed, and the last MAC known to
/// hold the IP (`None` = unknown: not yet learned from a lease).
#[derive(Debug, Clone, PartialEq)]
struct Window {
    window_start: i64,
    mac: Option<String>,
}

/// One persisted `ip → owning-mac` pair. A flat list (not a map) keeps the on-disk YAML
/// consistent with the other stores (`Vec<UnlimitedClient>` / `Vec<BlacklistEntry>`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct OwnerEntry {
    ip: String,
    mac: String,
}

/// Versioned on-disk form of the owning-MAC store. Only IPs with a known MAC are written;
/// `window_start` is deliberately NOT persisted (clock-agnostic re-seed on restart).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OwnerFile {
    #[serde(default = "default_owner_schema_version")]
    version: u32,
    #[serde(default)]
    owners: Vec<OwnerEntry>,
}

fn default_owner_schema_version() -> u32 {
    OWNER_SCHEMA_VERSION
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

/// A None-owner learn on an IP whose counter is already too large to be the new tenant's
/// own traffic → treated as inheritance: the counter is reset and `new` recorded as owner.
/// Unlike [`MacChange`] there is no `old` (the previous owner was never learned). This is
/// the residual the durable-MAC (0.1.38) fix left open — see the module doc.
#[derive(Debug, PartialEq)]
struct InheritReset {
    ip: String,
    new: String,
}

/// Divisor for the inheritance-reset threshold: `quota_bytes / INHERIT_THRESHOLD_DIVISOR`.
/// On the ~15 Mbit uplink a client transfers at most ~107 MiB in one 60s tick, so `/4`
/// (256 MiB at the 1 GiB quota) sits well above a single tick's worth yet below the quota.
const INHERIT_THRESHOLD_DIVISOR: u64 = 4;

/// Whether a shaper counter is too large to plausibly be a just-learned owner's own
/// traffic (so it must be inherited). `threshold` = [`ShaperQuota::inherit_threshold`]; a
/// freshly-learned owner already past it can't have earned it. A counter-less entry is
/// never suspect.
fn is_inherit_suspect(bytes: Option<usize>, threshold: u64) -> bool {
    bytes.is_some_and(|b| b as u64 > threshold)
}

/// Classify shaper members against the tracked windows for one pass; also applies the
/// no-I/O mutations (seed new members, learn a MAC for a `None` window, prune stale)
/// and returns the IPs whose counter must be `ipset del`-reset (done OUTSIDE the lock
/// by the caller). Two reset reasons are returned separately because phase 3 differs:
/// a time-window reset KEEPS the learned MAC, a MAC-change reset OVERWRITES it.
///
/// `leases` is `None` when the leases file couldn't be read this tick → MAC logic is
/// skipped (only the time-window path runs). `over_quota_ips` is used only to emit a
/// "why NOT reset" debug line for a same-MAC over-quota client. `inherit_reset_ips` are
/// members whose counter is inheritance-suspect (see [`is_inherit_suspect`]) — consulted
/// ONLY under the `Some(new)` learn arm, so a leases-read failure can never trigger an
/// inheritance reset.
// 8 params: all are genuinely-needed pure inputs (this is the unit-tested seam); grouping
// them buys nothing. The two IP sets drive distinct branches (forensic debug / inherit-reset).
#[allow(clippy::too_many_arguments)]
fn plan_and_prepare(
    windows: &mut HashMap<String, Window>,
    members: &HashSet<&str>,
    leases: Option<&HashMap<String, String>>,
    over_quota_ips: &HashSet<String>,
    inherit_reset_ips: &HashSet<String>,
    now: i64,
    period: i64,
    mut seed: impl FnMut() -> i64,
) -> (Vec<String>, Vec<MacChange>, Vec<InheritReset>) {
    let mut time_expired: Vec<String> = Vec::new();
    let mut mac_changed: Vec<MacChange> = Vec::new();
    let mut inherited: Vec<InheritReset> = Vec::new();

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
            // Unknown previous owner + already-large counter → the counter predates this
            // tenant → inheritance → reset (mac recorded in phase 3, after a successful del).
            (None, Some(new)) if inherit_reset_ips.contains(ip) => {
                inherited.push(InheritReset {
                    ip: ip.to_string(),
                    new: new.to_string(),
                });
            }
            // Unknown previous MAC, small counter → just learn it (no reset).
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

    (time_expired, mac_changed, inherited)
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

/// Pure projection of the tracked windows to the durable `ip → owning-mac` map. Only IPs
/// with a known MAC are included (a `None` window has nothing to inherit). `BTreeMap` for
/// a deterministic file (stable diff) and an order-independent dedup vs `last_persisted`.
fn project_owners(windows: &HashMap<String, Window>) -> BTreeMap<String, String> {
    windows
        .iter()
        .filter_map(|(ip, w)| w.mac.as_ref().map(|m| (ip.clone(), m.clone())))
        .collect()
}

/// Parse the owner file's bytes into a validated `ip → mac` map. A higher schema version,
/// malformed YAML, or a non-normalizable MAC yields an empty/filtered result rather than
/// an error — a corrupt file must degrade to the in-memory backstop, never abort startup.
fn parse_owner_bytes(bytes: &[u8]) -> BTreeMap<String, String> {
    let parsed: OwnerFile = match serde_yaml::from_slice(bytes) {
        Ok(f) => f,
        Err(err) => {
            warn!("shaper-quota: owner file unparsable, ignoring: {}", err);
            return BTreeMap::new();
        }
    };
    if parsed.version > OWNER_SCHEMA_VERSION {
        warn!(
            "shaper-quota: owner file version {} > {}, ignoring",
            parsed.version, OWNER_SCHEMA_VERSION
        );
        return BTreeMap::new();
    }
    parsed
        .owners
        .into_iter()
        .filter_map(|e| crate::unlimited_clients::normalize_mac(&e.mac).map(|m| (e.ip, m)))
        .collect()
}

/// Serialize an `ip → mac` map to the versioned on-disk YAML form.
fn serialize_owners(owners: &BTreeMap<String, String>) -> anyhow::Result<String> {
    let file = OwnerFile {
        version: OWNER_SCHEMA_VERSION,
        owners: owners
            .iter()
            .map(|(ip, mac)| OwnerEntry {
                ip: ip.clone(),
                mac: mac.clone(),
            })
            .collect(),
    };
    Ok(serde_yaml::to_string(&file)?)
}

/// One shaper member in the admin diagnostics snapshot. `mac`/`window_start`/`age_secs`
/// are null for an IP present in the set but not yet classified into a window.
#[derive(Debug, Clone, Serialize)]
pub struct QuotaClient {
    pub ip: String,
    pub mac: Option<String>,
    pub window_start: Option<i64>,
    pub age_secs: Option<i64>,
    pub bytes: Option<u64>,
    pub over_quota: bool,
}

/// Admin diagnostics snapshot of the shaper-quota tracker (see [`ShaperQuota::dump`]).
/// A dedicated DTO so the private `Window` type never leaks into the public API.
#[derive(Debug, Clone, Serialize)]
pub struct QuotaDump {
    pub period_secs: i64,
    pub quota_bytes: u64,
    pub last_run: i64,
    pub resets_total: i64,
    pub mac_change_resets_total: i64,
    pub inheritance_resets_total: i64,
    /// Effective inheritance-reset threshold (`quota_bytes / 4`) of the RUNNING binary —
    /// for incident forensics (confirm the threshold without reading the source).
    pub inherit_threshold_bytes: u64,
    pub errors_total: i64,
    /// Count of members past the byte quota at the last pass (mirrors the
    /// `ratzek_shaper_clients_over_quota` gauge) — distinct from `QuotaClient.over_quota`.
    pub clients_over_quota: i64,
    pub leases_read_failures: i64,
    pub leases_healthy: bool,
    pub persist_enabled: bool,
    pub owner_path: Option<String>,
    pub owner_persist_failures: i64,
    pub owner_persist_last_success: i64,
    pub owners_persisted: i64,
    pub clients: Vec<QuotaClient>,
}

/// Outcome of one reset pass, for logging + metrics.
#[derive(Debug, Default, PartialEq)]
struct PassStats {
    members: usize,
    /// Time-window resets (successful `ipset del`).
    time_resets: u64,
    /// MAC-change resets (successful `ipset del`).
    mac_resets: u64,
    /// None-learn inheritance resets (successful `ipset del`).
    inherit_resets: u64,
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
    /// Monotonic count of MAC-change (known-old → new) resets.
    mac_change_resets: AtomicI64,
    /// Monotonic count of None-learn inheritance resets (unknown previous owner + large
    /// counter). Separate from `mac_change_resets` so a runaway is visible on its own alert.
    inheritance_resets: AtomicI64,
    /// Monotonic count of per-IP `ipset del` failures.
    errors_total: AtomicI64,
    /// Members past the byte quota at the last pass (gauge).
    over_quota: AtomicI64,
    /// Monotonic count of leases-read failures (MAC trigger disabled those ticks).
    leases_read_failures: AtomicI64,
    /// Whether the last leases read succeeded — to log only on ok↔fail transitions
    /// (a chronically unreadable file must not warn every tick).
    leases_healthy: AtomicBool,
    /// Durable owning-MAC store: file the separate persist-job writes (`None` disables
    /// persistence → pure in-memory, pre-0.1.38 behavior).
    owner_path: Option<PathBuf>,
    /// Last projection written to `owner_path` — only the persist-job touches it, so a
    /// plain `Mutex` (with poison-recovery) suffices. Used to skip a no-op write.
    last_persisted: Mutex<BTreeMap<String, String>>,
    /// Whether the last owner-file write succeeded — for ok↔fail transition logging.
    persist_healthy: AtomicBool,
    /// Monotonic count of owner-file write failures (fail-fast errors; a D-state hang
    /// never returns and is instead surfaced by a stale `owner_persist_last_success`).
    owner_persist_failures: AtomicI64,
    /// Unix epoch of the last HEALTHY persist pass — a successful write OR a no-op skip
    /// (nothing changed). 0 = never. A wedged writer never reaches this → the age gauge
    /// grows → `RatzekShaperQuotaOwnerPersistStalled` fires.
    owner_persist_last_success: AtomicI64,
    /// Number of owning-MACs currently persisted (gauge).
    owners_persisted: AtomicI64,
}

impl ShaperQuota {
    /// Build a tracker for `shaper_set` with a `period_secs` per-client window and a
    /// `quota_bytes` throttle threshold (over-quota gauge only; the real threshold lives
    /// in iptables). `leases_path`/`dhcp_params` feed the per-tick ip→mac map for the
    /// MAC-change trigger. `period_secs` is floored to `>= 1` (config `validate()`
    /// already rejects `<= 0`).
    ///
    /// `owner_path` (`Some` = persistence enabled) is read best-effort here: each stored
    /// `ip → mac` pre-seeds a window (`mac = persisted`, fresh `window_start`) so a
    /// hand-over that happened during downtime is detected on the first pass. A missing /
    /// unreadable / higher-version file yields an empty store (pre-0.1.38 behavior).
    pub fn new(
        shaper_set: String,
        period_secs: i64,
        quota_bytes: u64,
        leases_path: PathBuf,
        dhcp_params: crate::dhcp::DhcpParams,
        owner_path: Option<PathBuf>,
    ) -> Self {
        let period = period_secs.max(1);
        // Best-effort load: a read error (absent file) or a corrupt one both degrade to
        // an empty store — never block startup.
        let persisted = owner_path
            .as_ref()
            .and_then(|p| match std::fs::read(p) {
                Ok(bytes) => Some(parse_owner_bytes(&bytes)),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => {
                    warn!("shaper-quota: owner file read failed, ignoring: {:#}", err);
                    None
                }
            })
            .unwrap_or_default();
        if !persisted.is_empty() {
            info!(
                "shaper-quota: loaded {} persisted IP owner(s)",
                persisted.len()
            );
        }
        // Pre-seed windows from the persisted owners with a fresh (clock-agnostic) window.
        let now = chrono::Utc::now().timestamp();
        let windows: HashMap<String, Window> = persisted
            .iter()
            .map(|(ip, mac)| {
                (
                    ip.clone(),
                    Window {
                        window_start: now - jitter(period),
                        mac: Some(mac.clone()),
                    },
                )
            })
            .collect();
        let owners_persisted = persisted.len() as i64;
        Self {
            windows: RwLock::new(windows),
            shaper_set,
            period_secs: period,
            quota_bytes,
            leases_path,
            dhcp_params,
            last_run: AtomicI64::new(0),
            resets_total: AtomicI64::new(0),
            mac_change_resets: AtomicI64::new(0),
            inheritance_resets: AtomicI64::new(0),
            errors_total: AtomicI64::new(0),
            over_quota: AtomicI64::new(0),
            leases_read_failures: AtomicI64::new(0),
            leases_healthy: AtomicBool::new(true),
            owner_path,
            last_persisted: Mutex::new(persisted),
            persist_healthy: AtomicBool::new(true),
            owner_persist_failures: AtomicI64::new(0),
            owner_persist_last_success: AtomicI64::new(0),
            owners_persisted: AtomicI64::new(owners_persisted),
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
                self.inheritance_resets
                    .fetch_add(s.inherit_resets as i64, Ordering::Relaxed);
                self.errors_total.fetch_add(s.errors as i64, Ordering::Relaxed);
                self.over_quota.store(s.over_quota as i64, Ordering::Relaxed);
                self.last_run.store(now, Ordering::Relaxed);
                if s.time_resets > 0 || s.mac_resets > 0 || s.inherit_resets > 0 || s.errors > 0 {
                    info!(
                        "shaper-quota pass: {} members, {} time-resets, {} mac-resets, {} inherit-resets, {} errors, {} over quota",
                        s.members, s.time_resets, s.mac_resets, s.inherit_resets, s.errors, s.over_quota
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

    /// Total MAC-change (known-old → new) resets performed.
    pub fn mac_change_resets(&self) -> i64 {
        self.mac_change_resets.load(Ordering::Relaxed)
    }

    /// Total None-learn inheritance resets performed (unknown previous owner + large counter).
    pub fn inheritance_resets(&self) -> i64 {
        self.inheritance_resets.load(Ordering::Relaxed)
    }

    /// Effective inheritance-reset threshold: a None-owner IP past this counter is treated
    /// as inherited (see [`is_inherit_suspect`]). Single source for both `run_pass` and `dump`.
    fn inherit_threshold(&self) -> u64 {
        self.quota_bytes / INHERIT_THRESHOLD_DIVISOR
    }

    /// Total leases-read failures (each disabled the MAC trigger for that tick).
    pub fn leases_read_failures(&self) -> i64 {
        self.leases_read_failures.load(Ordering::Relaxed)
    }

    /// Owner-persist monitoring: `(enabled, failures_total, last_success_epoch, owners_persisted)`.
    /// `enabled` is `false` when persistence is off (`owner_path` is `None`) — the exporter
    /// then omits the age gauge so the staleness alert can't fire on a disabled instance.
    pub fn persist_stats(&self) -> (bool, i64, i64, i64) {
        (
            self.owner_path.is_some(),
            self.owner_persist_failures.load(Ordering::Relaxed),
            self.owner_persist_last_success.load(Ordering::Relaxed),
            self.owners_persisted.load(Ordering::Relaxed),
        )
    }

    /// One persist pass: durably write the current `ip → owning-mac` projection to
    /// `owner_path` if it changed since the last write. Best-effort and fully decoupled
    /// from the reset pass — a wedged `fsync` stalls only this job (durability degrades to
    /// the in-memory/time-window backstop), never the resets. No-op when persistence is
    /// disabled. Blocking (fs I/O) — the caller runs it inside `spawn_blocking`.
    pub fn persist_once(&self) {
        let Some(path) = self.owner_path.as_ref() else {
            return;
        };
        // Short read-lock: clone the projection, then release before any fs I/O.
        let projection = {
            let windows = self.windows.read().unwrap_or_else(|e| e.into_inner());
            project_owners(&windows)
        };

        let mut last = self.last_persisted.lock().unwrap_or_else(|e| e.into_inner());
        let now = chrono::Utc::now().timestamp();
        // Skip the write only when nothing changed AND the file is actually on disk — so an
        // externally deleted file (the runbook suggests deleting it) is recreated promptly
        // instead of staying gone until the next projection change.
        if *last == projection && path.exists() {
            // No-op: nothing changed. The writer is alive and in sync → this counts as a
            // HEALTHY pass, so advance `last_success` (else the staleness alert would fire
            // on a quiet network where the projection legitimately doesn't change).
            self.mark_persist_healthy(now);
            return;
        }

        let content = match serialize_owners(&projection) {
            Ok(c) => c,
            Err(err) => {
                // Serialization can't realistically fail for a String map, but treat it as
                // a persist failure rather than panicking.
                self.record_persist_failure(&format!("serialize owner file: {err:#}"));
                return;
            }
        };
        // 0o600: the file carries mac↔ip (PII) on a shared disk.
        match crate::persistent_state::atomic_write(path, content.as_bytes(), 0o600) {
            Ok(()) => {
                *last = projection;
                self.owners_persisted
                    .store(last.len() as i64, Ordering::Relaxed);
                self.mark_persist_healthy(now);
            }
            Err(err) => {
                // Leave `last_persisted` unchanged → retried next tick.
                self.record_persist_failure(&format!("write {}: {:#}", path.display(), err));
            }
        }
    }

    /// Mark a healthy persist pass (write or no-op): advance the liveness timestamp and
    /// log recovery on a fail→ok transition.
    fn mark_persist_healthy(&self, now: i64) {
        self.owner_persist_last_success.store(now, Ordering::Relaxed);
        if !self.persist_healthy.swap(true, Ordering::Relaxed) {
            info!("shaper-quota: owner persist recovered");
        }
    }

    /// Count a persist failure and warn only on the ok→fail transition (a chronically
    /// unwritable disk must not warn every tick; repeats drop to debug).
    fn record_persist_failure(&self, msg: &str) {
        self.owner_persist_failures.fetch_add(1, Ordering::Relaxed);
        if self.persist_healthy.swap(false, Ordering::Relaxed) {
            warn!("shaper-quota: owner persist failed: {} (repeats at debug)", msg);
        } else {
            debug!("shaper-quota: owner persist still failing: {}", msg);
        }
    }

    /// Snapshot the tracker for the admin diagnostics endpoint: current shaper members
    /// (from `ipset save`) joined with the tracked window/MAC. An IP in the set but not
    /// yet classified into a window appears with `mac`/`window_start` null. Blocking
    /// (`ipset save`) — the caller runs it inside `spawn_blocking`.
    ///
    /// # Errors
    /// Returns `Err` if the `ipset save` read fails (missing set / no permission); the
    /// HTTP caller maps it to a 500.
    pub fn dump(&self, now: i64) -> anyhow::Result<QuotaDump> {
        let entries = IPSet::new(&self.shaper_set).entries()?;
        // Clone the windows under a short read-lock, then release before building the DTO.
        let windows = {
            let w = self.windows.read().unwrap_or_else(|e| e.into_inner());
            w.clone()
        };
        let mut clients: Vec<QuotaClient> = entries
            .into_iter()
            .map(|e| {
                let w = windows.get(&e.ip);
                QuotaClient {
                    ip: e.ip,
                    mac: w.and_then(|w| w.mac.clone()),
                    window_start: w.map(|w| w.window_start),
                    age_secs: w.map(|w| now - w.window_start),
                    bytes: e.bytes.map(|b| b as u64),
                    over_quota: e.bytes.is_some_and(|b| b as u64 > self.quota_bytes),
                }
            })
            .collect();
        clients.sort_by(|a, b| a.ip.cmp(&b.ip));
        let (persist_enabled, persist_failures, last_success, owners_persisted) =
            self.persist_stats();
        Ok(QuotaDump {
            period_secs: self.period_secs,
            quota_bytes: self.quota_bytes,
            last_run: self.last_run.load(Ordering::Relaxed),
            resets_total: self.resets_total.load(Ordering::Relaxed),
            mac_change_resets_total: self.mac_change_resets.load(Ordering::Relaxed),
            inheritance_resets_total: self.inheritance_resets.load(Ordering::Relaxed),
            inherit_threshold_bytes: self.inherit_threshold(),
            errors_total: self.errors_total.load(Ordering::Relaxed),
            clients_over_quota: self.over_quota.load(Ordering::Relaxed),
            leases_read_failures: self.leases_read_failures.load(Ordering::Relaxed),
            leases_healthy: self.leases_healthy.load(Ordering::Relaxed),
            persist_enabled,
            owner_path: self.owner_path.as_ref().map(|p| p.display().to_string()),
            owner_persist_failures: persist_failures,
            owner_persist_last_success: last_success,
            owners_persisted,
            clients,
        })
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
        // Past this a just-learned owner can't have earned the counter (see
        // `is_inherit_suspect`) → the counter is inherited and must be reset, not learned.
        let inherit_threshold = self.inherit_threshold();
        let mut over_quota_ips: HashSet<String> = HashSet::new();
        let mut inherit_reset_ips: HashSet<String> = HashSet::new();
        let mut member_ips: Vec<String> = Vec::with_capacity(entries.len());
        for e in entries {
            if e.bytes.is_some_and(|b| b as u64 > self.quota_bytes) {
                over_quota_ips.insert(e.ip.clone());
            }
            if is_inherit_suspect(e.bytes, inherit_threshold) {
                inherit_reset_ips.insert(e.ip.clone());
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
        let (time_expired, mac_changed, inherited) = {
            let mut windows = self.windows.write().unwrap_or_else(|e| e.into_inner());
            plan_and_prepare(
                &mut windows,
                &members,
                leases.as_ref(),
                &over_quota_ips,
                &inherit_reset_ips,
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
        // None-learn inheritance resets: same reset+adopt flow as mac-change, but the
        // previous owner was never known (learned owner inherited a large counter).
        let mut inherited_ok: Vec<(String, String)> = Vec::new();
        for InheritReset { ip, new } in inherited {
            match set.del(&ip) {
                Ok(()) => {
                    info!(
                        "shaper-quota inheritance reset: ip={} learned={} bytes>{}",
                        ip, new, inherit_threshold
                    );
                    inherited_ok.push((ip, new));
                }
                Err(err) => {
                    warn!("shaper-quota: ipset del {} (inheritance) failed: {:#}", ip, err);
                    errors += 1;
                }
            }
        }

        // Phase 3 (short lock): advance windows we actually reset (mac-change and
        // inheritance overwrite the mac; time-window keeps it). Failed dels are excluded →
        // retried next tick.
        {
            let mut windows = self.windows.write().unwrap_or_else(|e| e.into_inner());
            advance_time(&mut windows, &time_ok, now);
            advance_mac(&mut windows, &mac_ok, now);
            advance_mac(&mut windows, &inherited_ok, now);
        }

        Ok(PassStats {
            members: member_ips.len(),
            time_resets: time_ok.len() as u64,
            mac_resets: mac_ok.len() as u64,
            inherit_resets: inherited_ok.len() as u64,
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

    /// Run phase-1 classification with a fixed seed, no over-quota and no inherit-reset set.
    /// Absorbs the (unused here) `inherited` return so all existing call sites keep the
    /// original 2-tuple shape; inheritance behavior is exercised via [`prep_inherit`].
    fn prep(
        windows: &mut HashMap<String, Window>,
        members: &HashSet<&str>,
        lease: Option<&HashMap<String, String>>,
        now: i64,
        period: i64,
    ) -> (Vec<String>, Vec<MacChange>) {
        let (time, mac, _inherited) = plan_and_prepare(
            windows,
            members,
            lease,
            &HashSet::new(),
            &HashSet::new(),
            now,
            period,
            || 0,
        );
        (time, mac)
    }

    /// Like [`prep`] but with an explicit `inherit_reset_ips` set and returning the
    /// `inherited` bucket, for the None-learn inheritance tests.
    fn prep_inherit(
        windows: &mut HashMap<String, Window>,
        members: &HashSet<&str>,
        lease: Option<&HashMap<String, String>>,
        inherit_reset_ips: &HashSet<String>,
        now: i64,
        period: i64,
    ) -> (Vec<String>, Vec<MacChange>, Vec<InheritReset>) {
        plan_and_prepare(
            windows,
            members,
            lease,
            &HashSet::new(),
            inherit_reset_ips,
            now,
            period,
            || 0,
        )
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

    // --- Durable owning-MAC persistence ---

    fn tmp_owner_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "shaper-quota-owners-{}-{}.yaml",
            tag,
            std::process::id()
        ))
    }

    /// A tracker that never touches ipset/leases in these tests (only `new`/`persist_once`
    /// exercise the owner file). The shaper-set name is intentionally unused here.
    fn quota(owner: Option<PathBuf>) -> ShaperQuota {
        ShaperQuota::new(
            "test-shaper-set".to_string(),
            10800,
            1 << 30,
            PathBuf::from("/nonexistent/leases"),
            crate::dhcp::DhcpParams { lease_secs: 43200 },
            owner,
        )
    }

    #[test]
    fn project_owners_skips_none_and_is_ordered() {
        let w = HashMap::from([
            ("10.0.0.2".to_string(), win(1, Some("bb:bb:bb:bb:bb:bb"))),
            ("10.0.0.1".to_string(), win(1, Some("aa:aa:aa:aa:aa:aa"))),
            ("10.0.0.3".to_string(), win(1, None)), // no mac → nothing to inherit → skipped
        ]);
        let p = project_owners(&w);
        assert_eq!(p.len(), 2);
        assert!(!p.contains_key("10.0.0.3"));
        // BTreeMap → deterministic key order (stable file + order-independent dedup).
        assert_eq!(p.keys().collect::<Vec<_>>(), vec!["10.0.0.1", "10.0.0.2"]);
    }

    #[test]
    fn parse_owner_bytes_edge_cases() {
        assert!(parse_owner_bytes(b"").is_empty()); // empty file
        assert!(parse_owner_bytes(b"}{ not yaml").is_empty()); // malformed
        // Higher schema version → treated as unreadable.
        let hi = format!(
            "version: {}\nowners:\n- ip: 1.2.3.4\n  mac: aa:bb:cc:dd:ee:ff\n",
            OWNER_SCHEMA_VERSION + 1
        );
        assert!(parse_owner_bytes(hi.as_bytes()).is_empty());
        // Unknown keys tolerated; a non-normalizable MAC is filtered out.
        let ok = "version: 1\nextra: 9\nowners:\n- ip: 1.2.3.4\n  mac: AA:BB:CC:DD:EE:FF\n- ip: 9.9.9.9\n  mac: not-a-mac\n";
        let m = parse_owner_bytes(ok.as_bytes());
        assert_eq!(m.len(), 1);
        assert_eq!(m.get("1.2.3.4").map(String::as_str), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn missing_owner_file_yields_empty_store() {
        let path = tmp_owner_path("missing");
        let _ = std::fs::remove_file(&path);
        let sq = quota(Some(path));
        assert!(sq.windows.read().unwrap().is_empty());
        let (enabled, failures, last_success, owners) = sq.persist_stats();
        assert!(enabled && failures == 0 && last_success == 0 && owners == 0);
    }

    #[test]
    fn persisted_owner_loads_and_detects_handover() {
        let path = tmp_owner_path("load");
        let _ = std::fs::remove_file(&path);
        let file = serialize_owners(&BTreeMap::from([(
            "10.0.0.5".to_string(),
            "aa:bb:cc:dd:ee:ff".to_string(),
        )]))
        .unwrap();
        std::fs::write(&path, file).unwrap();

        let sq = quota(Some(path.clone()));
        // Loaded into a window with the persisted MAC.
        assert_eq!(
            sq.windows.read().unwrap()["10.0.0.5"].mac.as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        // A DIFFERENT current lease MAC for the same IP → detected as a hand-over even
        // though the store started empty in memory (the durable-MAC invariant).
        let mut w = sq.windows.read().unwrap().clone();
        let l = leases(&[("10.0.0.5", "11:22:33:44:55:66")]);
        let (time, mac) = prep(&mut w, &set(&["10.0.0.5"]), Some(&l), 999_999, 10800);
        assert!(time.is_empty());
        assert_eq!(
            mac,
            vec![MacChange {
                ip: "10.0.0.5".to_string(),
                old: "aa:bb:cc:dd:ee:ff".to_string(),
                new: "11:22:33:44:55:66".to_string(),
            }]
        );
        // Same MAC across restart → no reset (legitimate counter preserved).
        let ws = sq.windows.read().unwrap()["10.0.0.5"].window_start;
        let mut w2 = sq.windows.read().unwrap().clone();
        let same = leases(&[("10.0.0.5", "aa:bb:cc:dd:ee:ff")]);
        let (t2, m2) = prep(&mut w2, &set(&["10.0.0.5"]), Some(&same), ws + 100, 10800);
        assert!(t2.is_empty() && m2.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn persist_once_round_trips_through_new() {
        let path = tmp_owner_path("roundtrip");
        let _ = std::fs::remove_file(&path);
        let sq = quota(Some(path.clone()));
        {
            let mut w = sq.windows.write().unwrap();
            w.insert("10.0.0.7".to_string(), win(100, Some("aa:bb:cc:dd:ee:01")));
            w.insert("10.0.0.8".to_string(), win(100, Some("aa:bb:cc:dd:ee:02")));
            w.insert("10.0.0.9".to_string(), win(100, None)); // no mac → not persisted
        }
        sq.persist_once();
        let (enabled, failures, last_success, owners) = sq.persist_stats();
        assert!(enabled && failures == 0 && last_success > 0 && owners == 2);

        // Fresh instance loads exactly what was written (closes writer→reader).
        let sq2 = quota(Some(path.clone()));
        let loaded = project_owners(&sq2.windows.read().unwrap());
        assert_eq!(
            loaded,
            BTreeMap::from([
                ("10.0.0.7".to_string(), "aa:bb:cc:dd:ee:01".to_string()),
                ("10.0.0.8".to_string(), "aa:bb:cc:dd:ee:02".to_string()),
            ])
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn persist_once_noop_skips_write_but_stays_healthy() {
        let path = tmp_owner_path("noop");
        let _ = std::fs::remove_file(&path);
        let sq = quota(Some(path.clone()));
        {
            let mut w = sq.windows.write().unwrap();
            w.insert("10.0.0.7".to_string(), win(100, Some("aa:bb:cc:dd:ee:01")));
        }
        sq.persist_once(); // first write
        assert!(path.exists());
        let (_, _, ls1, _) = sq.persist_stats();

        // Tamper the file with a sentinel; an unchanged projection with the file still on
        // disk must be a no-op (dedup skip) → the sentinel survives (file NOT rewritten),
        // yet the pass still counts as healthy (last_success advances).
        std::fs::write(&path, b"SENTINEL").unwrap();
        sq.persist_once();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"SENTINEL",
            "no-op must not rewrite the file"
        );
        let (_, failures, ls2, _) = sq.persist_stats();
        assert_eq!(failures, 0);
        assert!(ls2 >= ls1, "no-op still advances last_success (liveness)");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn persist_once_recreates_externally_deleted_file() {
        let path = tmp_owner_path("recreate");
        let _ = std::fs::remove_file(&path);
        let sq = quota(Some(path.clone()));
        {
            let mut w = sq.windows.write().unwrap();
            w.insert("10.0.0.7".to_string(), win(100, Some("aa:bb:cc:dd:ee:01")));
        }
        sq.persist_once();
        assert!(path.exists());
        // Projection unchanged, but the file is deleted out from under us → the next pass
        // must recreate it (durability isn't silently lost until the owner set changes).
        std::fs::remove_file(&path).unwrap();
        sq.persist_once();
        assert!(path.exists(), "deleted owner file must be recreated");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn persistence_disabled_is_inert() {
        let sq = quota(None);
        {
            let mut w = sq.windows.write().unwrap();
            w.insert("10.0.0.7".to_string(), win(100, Some("aa:bb:cc:dd:ee:01")));
        }
        sq.persist_once(); // no path → no file, no panic
        let (enabled, failures, last_success, owners) = sq.persist_stats();
        assert!(!enabled && failures == 0 && last_success == 0 && owners == 0);
    }

    #[test]
    fn persist_once_write_error_counts_and_does_not_advance_success() {
        // Owner path whose PARENT is an existing regular file → create_dir_all fails →
        // atomic_write returns Err → the failure counter increments, last_success stays 0,
        // and last_persisted is not advanced (so the next tick retries).
        let file = tmp_owner_path("errpath");
        let _ = std::fs::remove_file(&file);
        std::fs::write(&file, b"x").unwrap();
        let bad = file.join("owners.yaml"); // parent (`file`) is a file, not a dir
        let sq = quota(Some(bad));
        {
            let mut w = sq.windows.write().unwrap();
            w.insert("10.0.0.7".to_string(), win(100, Some("aa:bb:cc:dd:ee:01")));
        }
        sq.persist_once();
        let (_, failures, last_success, owners) = sq.persist_stats();
        assert_eq!(failures, 1, "write error must be counted");
        assert_eq!(last_success, 0, "a failed write must not mark healthy");
        assert_eq!(owners, 0, "owners_persisted only updates on a successful write");
        // last_persisted untouched → the next tick still sees a diff and retries.
        sq.persist_once();
        assert_eq!(sq.persist_stats().1, 2, "unchanged projection retries the write");
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn quota_dump_dto_serializes_with_nulls() {
        let dump = QuotaDump {
            period_secs: 10800,
            quota_bytes: 1 << 30,
            last_run: 0,
            resets_total: 0,
            mac_change_resets_total: 0,
            inheritance_resets_total: 0,
            inherit_threshold_bytes: 1 << 28,
            errors_total: 0,
            clients_over_quota: 0,
            leases_read_failures: 0,
            leases_healthy: true,
            persist_enabled: false,
            owner_path: None,
            owner_persist_failures: 0,
            owner_persist_last_success: 0,
            owners_persisted: 0,
            clients: vec![QuotaClient {
                ip: "10.0.0.1".to_string(),
                mac: None,
                window_start: None,
                age_secs: None,
                bytes: None,
                over_quota: false,
            }],
        };
        let j = serde_json::to_string(&dump).unwrap();
        assert!(j.contains("\"mac\":null"));
        assert!(j.contains("\"owner_path\":null"));
    }

    // --- None-learn inheritance reset ---

    #[test]
    fn is_inherit_suspect_boundary() {
        let t = 256 * 1024 * 1024;
        assert!(is_inherit_suspect(Some(t as usize + 1), t)); // strictly over → suspect
        assert!(!is_inherit_suspect(Some(t as usize), t)); // exactly at → not suspect
        assert!(!is_inherit_suspect(Some(0), t));
        assert!(!is_inherit_suspect(None, t)); // counter-less entry is never suspect
    }

    #[test]
    fn none_learn_with_large_counter_is_inheritance_reset() {
        // Owner unknown (None) + IP flagged inherit-suspect + a lease appears → reset,
        // NOT a silent learn. mac stays None until phase 3 (after a successful del).
        let mut w = HashMap::from([("ip".to_string(), win(1000, None))]);
        let l = leases(&[("ip", "bb")]);
        let suspect: HashSet<String> = ["ip".to_string()].into_iter().collect();
        let (time, mac, inherited) =
            prep_inherit(&mut w, &set(&["ip"]), Some(&l), &suspect, 1500, 10800);
        assert!(time.is_empty() && mac.is_empty());
        assert_eq!(
            inherited,
            vec![InheritReset {
                ip: "ip".to_string(),
                new: "bb".to_string()
            }]
        );
        assert_eq!(w["ip"], win(1000, None)); // not mutated yet
        // Phase 3 adopts the new owner + re-anchors the window (same helper as mac-change).
        advance_mac(&mut w, &[("ip".to_string(), "bb".to_string())], 1500);
        assert_eq!(w["ip"], win(1500, Some("bb")));
    }

    #[test]
    fn none_learn_with_small_counter_just_learns() {
        // Owner unknown + IP NOT suspect (small counter) → learn as before, no reset.
        let mut w = HashMap::from([("ip".to_string(), win(1000, None))]);
        let l = leases(&[("ip", "bb")]);
        let (time, mac, inherited) =
            prep_inherit(&mut w, &set(&["ip"]), Some(&l), &HashSet::new(), 1500, 10800);
        assert!(time.is_empty() && mac.is_empty() && inherited.is_empty());
        assert_eq!(w["ip"], win(1000, Some("bb"))); // learned, no reset
    }

    #[test]
    fn leases_none_never_forms_inheritance_reset() {
        // Safety invariant: a leases-read failure (leases=None) must NEVER trigger an
        // inheritance reset, even for a suspect IP — the threshold is consulted only under
        // the Some(new) learn arm. Guards against a refactor moving the check out of it.
        let mut w = HashMap::from([("ip".to_string(), win(1000, None))]);
        let suspect: HashSet<String> = ["ip".to_string()].into_iter().collect();
        let (time, mac, inherited) =
            prep_inherit(&mut w, &set(&["ip"]), None, &suspect, 1500, 10800);
        assert!(mac.is_empty() && inherited.is_empty());
        // window not time-expired (1500 - 1000 < period) → nothing, mac untouched.
        assert!(time.is_empty());
        assert_eq!(w["ip"], win(1000, None));
    }

    #[test]
    fn suspect_with_known_same_mac_is_not_inheritance_reset() {
        // Anti-bypass: a heavy user (counter > threshold) whose owner is already KNOWN and
        // matches the lease must NOT be inheritance-reset (that's for None-owner only). This
        // guards the `(None, ...)` precondition against a future refactor silently dropping it.
        let mut w = HashMap::from([("ip".to_string(), win(1000, Some("aa")))]);
        let l = leases(&[("ip", "aa")]);
        let suspect: HashSet<String> = ["ip".to_string()].into_iter().collect();
        let (time, mac, inherited) =
            prep_inherit(&mut w, &set(&["ip"]), Some(&l), &suspect, 1500, 10800);
        assert!(time.is_empty() && mac.is_empty() && inherited.is_empty());
        assert_eq!(w["ip"], win(1000, Some("aa"))); // untouched
    }
}
