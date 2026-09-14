//! Client IP → MAC resolution for the portal endpoints (`/api/v1/client`).
//!
//! The kernel ARP table is checked first: the request reached us over an established
//! TCP connection from an L2 neighbour, so a complete (`ATF_COM`) entry names the real
//! sender of *this* request. The dnsmasq lease is the fallback and the cross-check — it
//! can be stale (the clock is behind after boot so expired leases look Active, phones
//! rotate private MACs, clients reuse a cached IP before doing DHCP). When both exist and
//! disagree, the ARP MAC wins.
//!
//! dnsmasq rewrites its lease file in place (rewind + ftruncate + rewrite), so a read can
//! observe an empty or partial file; the lease lookup is retried once when the read looks
//! like that race.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use slog_scope::{debug, error, warn};

use crate::dhcp::DhcpParams;
use crate::unlimited_clients::normalize_mac;

const PROC_NET_ARP: &str = "/proc/net/arp";
/// `ARPHRD_ETHER` as printed in `/proc/net/arp`.
const HW_TYPE_ETHER: &str = "0x1";
/// `ATF_COM`: the entry is complete (REACHABLE/STALE/DELAY/PROBE). FAILED entries keep
/// the previous MAC with this bit cleared, so they must not be trusted.
const ATF_COM: u32 = 0x2;
const ZERO_MAC: &str = "00:00:00:00:00:00";
/// dnsmasq's in-place rewrite of the lease file takes milliseconds.
const LEASE_RETRY_DELAY: Duration = Duration::from_millis(50);
/// The same outcome for the same key is logged at warn level at most this often; the
/// portal polls every 5 s, so without a gate one lease-less tab floods the journal.
const WARN_INTERVAL: Duration = Duration::from_secs(600);
/// Soft bound on the rate-limiter state; entries older than `WARN_INTERVAL` are pruned
/// once it is exceeded.
const WARN_STATE_SOFT_LIMIT: usize = 1024;

/// Outcome of one resolution; exported as the `result` label of
/// `ratzek_client_mac_lookup_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupResult {
    /// ARP and the active lease agree.
    Agree,
    /// Only the ARP table knows the client (no active lease).
    ArpOnly,
    /// Both know the client with different MACs; the ARP MAC is used.
    Mismatch,
    /// Only the active lease knows the client (no complete ARP entry).
    LeaseOnly,
    /// Found in the lease file on the second read (in-place rewrite race).
    LeaseRetry,
    /// Unlimited client: resolved by IP without a MAC lookup (recorded by the caller).
    Whitelist,
    /// Neither source knows the client.
    NotFound,
}

impl LookupResult {
    /// Declaration order; doubles as the index into `LOOKUPS`.
    const ALL: [LookupResult; 7] = [
        LookupResult::Agree,
        LookupResult::ArpOnly,
        LookupResult::Mismatch,
        LookupResult::LeaseOnly,
        LookupResult::LeaseRetry,
        LookupResult::Whitelist,
        LookupResult::NotFound,
    ];

    pub fn label(self) -> &'static str {
        match self {
            LookupResult::Agree => "agree",
            LookupResult::ArpOnly => "arp_only",
            LookupResult::Mismatch => "mismatch",
            LookupResult::LeaseOnly => "lease_only",
            LookupResult::LeaseRetry => "lease_retry",
            LookupResult::Whitelist => "whitelist",
            LookupResult::NotFound => "not_found",
        }
    }
}

/// Source read failure; exported as the `stage` label of
/// `ratzek_client_mac_lookup_errors_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorStage {
    Leases,
    Arp,
    Join,
}

impl ErrorStage {
    /// Declaration order; doubles as the index into `ERRORS`.
    const ALL: [ErrorStage; 3] = [ErrorStage::Leases, ErrorStage::Arp, ErrorStage::Join];

    fn label(self) -> &'static str {
        match self {
            ErrorStage::Leases => "leases",
            ErrorStage::Arp => "arp",
            ErrorStage::Join => "join",
        }
    }
}

// Process-global counters (single-process exporter, so plain statics are sufficient).
static LOOKUPS: [AtomicU64; 7] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static ERRORS: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

static WARN_STATE: Mutex<Option<HashMap<String, (&'static str, Instant)>>> = Mutex::new(None);

/// Count one resolution outcome.
pub fn record(result: LookupResult) {
    LOOKUPS[result as usize].fetch_add(1, Ordering::Relaxed);
}

fn record_error(stage: ErrorStage) {
    ERRORS[stage as usize].fetch_add(1, Ordering::Relaxed);
}

/// `(result label, count)` for every outcome, for `/metrics`.
pub fn lookup_counts() -> Vec<(&'static str, u64)> {
    LookupResult::ALL
        .iter()
        .map(|r| (r.label(), LOOKUPS[*r as usize].load(Ordering::Relaxed)))
        .collect()
}

/// `(stage label, count)` for every read-failure stage, for `/metrics`.
pub fn error_counts() -> Vec<(&'static str, u64)> {
    ErrorStage::ALL
        .iter()
        .map(|s| (s.label(), ERRORS[*s as usize].load(Ordering::Relaxed)))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// MAC to use for the client; `None` when it can't be determined.
    pub mac: Option<String>,
    pub result: LookupResult,
    arp_mac: Option<String>,
    lease_mac: Option<String>,
}

/// Find the complete ARP entry for `ip` in `/proc/net/arp` content and return its
/// normalized MAC. Incomplete/FAILED entries, non-Ethernet entries and all-zero MACs
/// are ignored.
pub(crate) fn parse_proc_net_arp(s: &str, ip: &str) -> Option<String> {
    s.lines().skip(1).find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        // IP address | HW type | Flags | HW address | Mask | Device
        if f.len() < 6 || f[0] != ip || f[1] != HW_TYPE_ETHER {
            return None;
        }
        let flags = u32::from_str_radix(f[2].strip_prefix("0x")?, 16).ok()?;
        if flags & ATF_COM == 0 {
            return None;
        }
        normalize_mac(f[3]).filter(|mac| mac != ZERO_MAC)
    })
}

/// Combine the two sources; the ARP MAC wins on disagreement.
pub(crate) fn decide(arp: Option<String>, lease: Option<String>) -> Resolved {
    let (mac, result) = match (&arp, &lease) {
        (Some(a), Some(l)) if a == l => (Some(a.clone()), LookupResult::Agree),
        (Some(a), Some(_)) => (Some(a.clone()), LookupResult::Mismatch),
        (Some(a), None) => (Some(a.clone()), LookupResult::ArpOnly),
        (None, Some(l)) => (Some(l.clone()), LookupResult::LeaseOnly),
        (None, None) => (None, LookupResult::NotFound),
    };
    Resolved {
        mac,
        result,
        arp_mac: arp,
        lease_mac: lease,
    }
}

/// Look `ip` up in the active-lease map. The flag is true when the read looks like the
/// in-place rewrite race (read error or no active leases at all), i.e. a retry may help.
fn lookup_lease(
    ip: &str,
    read_leases: &mut impl FnMut() -> Result<HashMap<String, String>>,
) -> (Option<String>, bool) {
    match read_leases() {
        Ok(map) => {
            let racy = map.is_empty();
            (map.get(ip).cloned(), racy)
        }
        Err(err) => {
            record_error(ErrorStage::Leases);
            if should_warn("error:leases", "error", Instant::now()) {
                error!("client-mac: reading DHCP leases failed: {err:#}");
            }
            (None, true)
        }
    }
}

/// Blocking resolution with injectable I/O (tests pass stubs; `resolve` passes the
/// real procfs/lease-file readers and `std::thread::sleep`).
pub(crate) fn resolve_with(
    ip: &str,
    mut read_arp: impl FnMut() -> Result<String>,
    mut read_leases: impl FnMut() -> Result<HashMap<String, String>>,
    mut sleep: impl FnMut(Duration),
) -> Resolved {
    let arp = match read_arp() {
        Ok(s) => parse_proc_net_arp(&s, ip),
        Err(err) => {
            record_error(ErrorStage::Arp);
            if should_warn("error:arp", "error", Instant::now()) {
                error!("client-mac: reading {PROC_NET_ARP} failed: {err:#}");
            }
            None
        }
    };
    let (lease, racy) = lookup_lease(ip, &mut read_leases);
    // Only a lease-less, ARP-less client whose lease read looked racy is worth a retry;
    // a VPN/L3 client with a healthy lease file goes straight to NotFound.
    if arp.is_none() && lease.is_none() && racy {
        sleep(LEASE_RETRY_DELAY);
        if let (Some(mac), _) = lookup_lease(ip, &mut read_leases) {
            return Resolved {
                mac: Some(mac.clone()),
                result: LookupResult::LeaseRetry,
                arp_mac: None,
                lease_mac: Some(mac),
            };
        }
    }
    decide(arp, lease)
}

/// Resolve the MAC of the portal client at `ip`, record the outcome and log noteworthy
/// ones (rate-limited per IP).
pub async fn resolve(leases: PathBuf, params: DhcpParams, ip: String) -> Resolved {
    let task_ip = ip.clone();
    // Both reads are blocking file I/O; the rare 50 ms retry sleep also stays on the
    // blocking pool rather than an async worker.
    let joined = tokio::task::spawn_blocking(move || {
        resolve_with(
            &task_ip,
            || {
                std::fs::read_to_string(PROC_NET_ARP)
                    .with_context(|| format!("Failed to read {PROC_NET_ARP}"))
            },
            || crate::dhcp::active_ip_to_mac(&leases, params),
            std::thread::sleep,
        )
    })
    .await;
    let resolved = match joined {
        Ok(v) => v,
        Err(err) => {
            record_error(ErrorStage::Join);
            error!("client-mac: lookup task for {ip} failed: {err}");
            decide(None, None)
        }
    };
    record(resolved.result);
    report(&ip, &resolved);
    resolved
}

fn report(ip: &str, r: &Resolved) {
    if !matches!(
        r.result,
        LookupResult::ArpOnly
            | LookupResult::Mismatch
            | LookupResult::LeaseRetry
            | LookupResult::NotFound
    ) {
        return;
    }
    let msg = format!(
        "client-mac: ip={ip} result={} arp_mac={} lease_mac={}",
        r.result.label(),
        r.arp_mac.as_deref().unwrap_or("-"),
        r.lease_mac.as_deref().unwrap_or("-"),
    );
    if should_warn(ip, r.result.label(), Instant::now()) {
        warn!("{msg}");
    } else {
        debug!("{msg}");
    }
}

/// True when `tag` for `key` should be logged at warn level: the tag changed since the
/// last warn, or `WARN_INTERVAL` has passed.
fn should_warn(key: &str, tag: &'static str, now: Instant) -> bool {
    let mut guard = WARN_STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let state = guard.get_or_insert_with(HashMap::new);
    if state.len() > WARN_STATE_SOFT_LIMIT {
        state.retain(|_, (_, at)| now.saturating_duration_since(*at) < WARN_INTERVAL);
    }
    match state.get(key) {
        Some((prev, at)) if *prev == tag && now.saturating_duration_since(*at) < WARN_INTERVAL => {
            false
        }
        _ => {
            state.insert(key.to_string(), (tag, now));
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    // Shape taken from the production host (iproute2 5.9, kernel 6.1).
    const ARP: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
10.11.5.213      0x1         0x2         fa:aa:e1:6e:a3:f5     *        eth0
10.11.5.122      0x1         0x0         a6:e3:48:a6:db:18     *        eth0
10.11.5.126      0x1         0x2         f6:8c:07:99:d5:89     *        eth0
10.11.5.137      0x1         0x0         f6:8c:07:99:d5:89     *        eth0
10.11.5.21       0x1         0x2         AA:BB:CC:DD:EE:21     *        eth0
10.11.5.30       0x1         0x2         00:00:00:00:00:00     *        eth0
10.11.5.31       0x1         0xZZ        aa:bb:cc:dd:ee:31     *        eth0
10.11.5.32       0x20        0x2         aa:bb:cc:dd:ee:32     *        ib0
";

    fn leases(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(ip, mac)| (ip.to_string(), mac.to_string()))
            .collect()
    }

    #[test]
    fn arp_complete_entry_yields_mac() {
        assert_eq!(
            parse_proc_net_arp(ARP, "10.11.5.213").as_deref(),
            Some("fa:aa:e1:6e:a3:f5")
        );
    }

    #[test]
    fn arp_failed_entry_with_stale_mac_is_ignored() {
        assert_eq!(parse_proc_net_arp(ARP, "10.11.5.122"), None);
        // Same MAC as the complete .126 entry must not leak onto the FAILED .137.
        assert_eq!(parse_proc_net_arp(ARP, "10.11.5.137"), None);
    }

    #[test]
    fn arp_matches_ip_exactly_and_normalizes() {
        assert_eq!(parse_proc_net_arp(ARP, "10.11.5.2"), None);
        assert_eq!(
            parse_proc_net_arp(ARP, "10.11.5.21").as_deref(),
            Some("aa:bb:cc:dd:ee:21")
        );
    }

    #[test]
    fn arp_rejects_zero_mac_bad_flags_non_ether_and_header_only() {
        assert_eq!(parse_proc_net_arp(ARP, "10.11.5.30"), None);
        assert_eq!(parse_proc_net_arp(ARP, "10.11.5.31"), None);
        assert_eq!(parse_proc_net_arp(ARP, "10.11.5.32"), None);
        let header = ARP.lines().next().unwrap();
        assert_eq!(parse_proc_net_arp(header, "10.11.5.213"), None);
    }

    #[test]
    fn decide_covers_all_combinations() {
        let a = || Some("aa:aa:aa:aa:aa:aa".to_string());
        let b = || Some("bb:bb:bb:bb:bb:bb".to_string());

        let r = decide(a(), a());
        assert_eq!((r.mac, r.result), (a(), LookupResult::Agree));
        let r = decide(a(), b());
        assert_eq!((r.mac, r.result), (a(), LookupResult::Mismatch));
        let r = decide(a(), None);
        assert_eq!((r.mac, r.result), (a(), LookupResult::ArpOnly));
        let r = decide(None, b());
        assert_eq!((r.mac, r.result), (b(), LookupResult::LeaseOnly));
        let r = decide(None, None);
        assert_eq!((r.mac, r.result), (None, LookupResult::NotFound));
    }

    #[test]
    fn arp_hit_skips_retry() {
        let mut slept = 0;
        let r = resolve_with(
            "10.11.5.213",
            || Ok(ARP.to_string()),
            || Ok(HashMap::new()),
            |_| slept += 1,
        );
        assert_eq!(r.result, LookupResult::ArpOnly);
        assert_eq!(slept, 0);
    }

    #[test]
    fn empty_lease_read_is_retried_once() {
        let mut reads = 0;
        let mut slept = 0;
        let r = resolve_with(
            "10.11.5.99",
            || Ok(ARP.to_string()),
            || {
                reads += 1;
                Ok(if reads == 1 {
                    HashMap::new()
                } else {
                    leases(&[("10.11.5.99", "cc:cc:cc:cc:cc:cc")])
                })
            },
            |d| {
                assert_eq!(d, LEASE_RETRY_DELAY);
                slept += 1;
            },
        );
        assert_eq!(r.result, LookupResult::LeaseRetry);
        assert_eq!(r.mac.as_deref(), Some("cc:cc:cc:cc:cc:cc"));
        assert_eq!((reads, slept), (2, 1));
    }

    #[test]
    fn lease_read_error_is_retried() {
        let mut reads = 0;
        let r = resolve_with(
            "10.11.5.99",
            || Ok(ARP.to_string()),
            || {
                reads += 1;
                if reads == 1 {
                    Err(anyhow!("truncated"))
                } else {
                    Ok(leases(&[("10.11.5.99", "cc:cc:cc:cc:cc:cc")]))
                }
            },
            |_| {},
        );
        assert_eq!(r.result, LookupResult::LeaseRetry);
    }

    #[test]
    fn healthy_lease_file_without_client_does_not_sleep() {
        let mut slept = 0;
        let r = resolve_with(
            "10.8.0.1",
            || Ok(ARP.to_string()),
            || Ok(leases(&[("10.11.5.60", "aa:bb:cc:dd:ee:01")])),
            |_| slept += 1,
        );
        assert_eq!((r.mac, r.result), (None, LookupResult::NotFound));
        assert_eq!(slept, 0);
    }

    #[test]
    fn arp_read_error_falls_back_to_lease_and_is_counted() {
        let before = error_counts()
            .into_iter()
            .find(|(stage, _)| *stage == "arp")
            .unwrap()
            .1;
        let r = resolve_with(
            "10.11.5.60",
            || Err(anyhow!("no procfs")),
            || Ok(leases(&[("10.11.5.60", "aa:bb:cc:dd:ee:01")])),
            |_| {},
        );
        assert_eq!(r.result, LookupResult::LeaseOnly);
        assert_eq!(r.mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        let after = error_counts()
            .into_iter()
            .find(|(stage, _)| *stage == "arp")
            .unwrap()
            .1;
        assert!(after > before);
    }

    #[test]
    fn warn_gate_limits_repeats_per_key() {
        let t0 = Instant::now();
        let key = "test:warn-gate";
        assert!(should_warn(key, "arp_only", t0));
        assert!(!should_warn(key, "arp_only", t0 + Duration::from_secs(5)));
        assert!(should_warn(key, "not_found", t0 + Duration::from_secs(10)));
        assert!(should_warn(
            key,
            "not_found",
            t0 + Duration::from_secs(10) + WARN_INTERVAL
        ));
    }
}
