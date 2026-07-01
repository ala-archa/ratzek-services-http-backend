//! Backend-owned DHCP lease model + parsers, abstracting over the DHCP server
//! flavor (EOL ISC dhcpd vs dnsmasq). Consumers depend only on [`Lease`] /
//! [`Leases`] here, never on `dhcpd_parser` directly, so the flavor can be swapped
//! at runtime and the parser dependency dropped once ISC is gone.
//!
//! The model is a **superset**: the ISC adapter fills every field (behavior stays
//! byte-identical to the old code), while the dnsmasq adapter leaves ISC-only fields
//! `None` and derives what it can from the leaner `dnsmasq.leases` format.

use anyhow::{anyhow, Context, Result};
use std::path::Path;

/// Which DHCP server the box is running. Selected once at startup (see
/// `State::dhcp_flavor`) from the active daemon; the whole rest of the backend
/// reads that single snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Isc,
    Dnsmasq,
}

/// Systemd unit names probed by [`Flavor::detect`].
const DNSMASQ_UNIT: &str = "dnsmasq";
const ISC_UNIT: &str = "isc-dhcp-server";

impl Flavor {
    fn is_active(unit: &str) -> bool {
        std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", unit])
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Auto-detect the flavor from the active daemon (blocking: spawns `systemctl`).
    /// neither-active → `Isc` (the known-good fallback); both-active → `Isc` + warns.
    /// Callers must run this off the async executor (see `State::new` — it wraps this
    /// in `spawn_blocking` + a timeout so a hung systemd can't block startup).
    pub fn detect() -> Self {
        let dnsmasq = Self::is_active(DNSMASQ_UNIT);
        let isc = Self::is_active(ISC_UNIT);
        match (dnsmasq, isc) {
            (true, true) => {
                slog_scope::error!(
                    "DHCP flavor auto-detect: BOTH dnsmasq and isc-dhcp-server active — \
                     falling back to isc (known-good). Fix the cutover state."
                );
                Self::Isc
            }
            (true, false) => Self::Dnsmasq,
            // dnsmasq inactive (incl. neither active) -> isc fallback.
            (false, _) => Self::Isc,
        }
    }
}

/// Config value for the DHCP flavor (`auto` by default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FlavorSetting {
    #[default]
    Auto,
    Isc,
    Dnsmasq,
}

/// The two lease-parsing inputs that always travel together: the resolved server
/// `flavor` and the configured lease length (for the dnsmasq `last_seen` approx).
/// Snapshot once from `State` (see `State::dhcp_params`) and pass to `Dhcp::read`.
#[derive(Debug, Clone, Copy)]
pub struct DhcpParams {
    pub flavor: Flavor,
    pub lease_secs: i64,
}

/// Lease binding state (backend-owned so `dhcpd_parser` can be removed at finalize).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingState {
    Active,
    Free,
    Abandoned,
}

/// One DHCP lease, superset over ISC and dnsmasq. See module docs.
#[derive(Debug, Clone)]
pub struct Lease {
    /// Hardware (MAC) address as written by the server. `None` if absent (ISC can
    /// have MAC-less leases; dnsmasq always has one).
    pub mac: Option<String>,
    pub ip: String,
    pub hostname: Option<String>,
    /// ISC `client-hostname`. Always `None` under dnsmasq.
    pub client_hostname: Option<String>,
    /// ISC `vendor-class-identifier`. Always `None` under dnsmasq.
    pub vendor: Option<String>,
    pub binding_state: BindingState,
    /// ISC `starts` as its raw display string. `None` under dnsmasq (kept a string,
    /// NOT epoch, to preserve the `/dhcp` contract).
    pub starts: Option<String>,
    /// ISC `ends` as its raw display string. `None` under dnsmasq.
    pub ends: Option<String>,
    /// Client-last-transaction time ("last seen"), unix epoch sec UTC. Under dnsmasq
    /// this is approximated as `expiry - lease_secs` (`None` for an infinite lease).
    pub cltt: Option<i64>,
    /// Last transaction time, unix epoch sec UTC. Under dnsmasq = the lease `expiry`.
    pub tstp: Option<i64>,
}

/// A parsed set of leases. Thin owned wrapper so call sites keep reading `.all()`.
pub struct Leases(Vec<Lease>);

impl Leases {
    pub fn all(self) -> Vec<Lease> {
        self.0
    }

    pub fn of_ip(self, ip: &str) -> Option<Lease> {
        self.0.into_iter().find(|l| l.ip == ip)
    }
}

pub struct Dhcp;

impl Dhcp {
    /// Parse the lease file for the given [`DhcpParams`] (flavor + lease length).
    ///
    /// # Errors
    /// Returns an error if the file cannot be read, or (ISC only) fails to parse.
    pub fn read(leases: &Path, params: DhcpParams) -> Result<Leases> {
        let s = std::fs::read_to_string(leases)
            .with_context(|| format!("Failed to read {leases:?}"))?;
        let v = match params.flavor {
            Flavor::Isc => parse_isc(&s, leases)?,
            Flavor::Dnsmasq => parse_dnsmasq(&s, params.lease_secs, chrono::Utc::now().timestamp()),
        };
        Ok(Leases(v))
    }

    /// Find the lease for `ip`.
    ///
    /// # Errors
    /// Returns an error if the file can't be read/parsed, or no lease matches `ip`.
    pub fn of_ip(leases: &Path, params: DhcpParams, ip: &str) -> Result<Lease> {
        Self::read(leases, params)?
            .of_ip(ip)
            .ok_or_else(|| anyhow!("DHCP lease not found"))
    }
}

/// ISC `dhcpd.leases` adapter — fills the full superset (behaviour identical to the
/// pre-migration code).
fn parse_isc(s: &str, path: &Path) -> Result<Vec<Lease>> {
    use dhcpd_parser::leases::BindingState as B;
    use dhcpd_parser::parser::LeasesMethods;
    let parsed = dhcpd_parser::parser::parse(s.to_string())
        .map_err(|err| anyhow!("Failed to parse {:?}: {}", path, err))?;
    let out = parsed
        .leases
        .all()
        .into_iter()
        .map(|l| Lease {
            mac: l.hardware.map(|h| h.mac),
            ip: l.ip,
            hostname: l.hostname,
            client_hostname: l.client_hostname,
            vendor: l.vendor_class_identifier,
            binding_state: match l.binding_state {
                B::Active => BindingState::Active,
                B::Free => BindingState::Free,
                B::Abandoned => BindingState::Abandoned,
            },
            starts: l.dates.starts.map(|d| d.to_string()),
            ends: l.dates.ends.map(|d| d.to_string()),
            cltt: l.dates.cltt.as_ref().and_then(date_to_epoch),
            tstp: l.dates.tstp.as_ref().and_then(date_to_epoch),
        })
        .collect();
    Ok(out)
}

/// dnsmasq lease-file adapter. Each lease is a line:
/// `<expiry_epoch> <mac> <ip> <hostname|*> <clientid|*>`. IPv6/DUID lines (which
/// carry `duid` on their own line or a non-dotted address) are skipped silently;
/// any OTHER malformed line is skipped but counted and logged once (so a corrupt
/// lease file doesn't make clients vanish without a trace).
fn parse_dnsmasq(s: &str, lease_secs: i64, now: i64) -> Vec<Lease> {
    let mut out = Vec::new();
    let mut malformed = 0usize;
    for line in s.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // `duid <hex>` header and blank lines are legitimate, not corruption.
        if f.is_empty() || f[0] == "duid" {
            continue;
        }
        let ip = match f.get(2) {
            // IPv6 lease — not handled by this v4 backend (legitimate skip).
            Some(ip) if ip.contains('.') => *ip,
            Some(_) => continue,
            None => {
                malformed += 1;
                continue;
            }
        };
        let expiry: i64 = match f[0].parse() {
            Ok(v) => v,
            Err(_) => {
                malformed += 1;
                continue;
            }
        };
        let non_sentinel = |v: &str| (v != "*").then(|| v.to_string());
        // dnsmasq writes `0` for an infinite lease. Only active leases normally
        // appear in the file; an expired-but-not-yet-pruned one maps to Free.
        let binding_state = if expiry == 0 || expiry > now {
            BindingState::Active
        } else {
            BindingState::Free
        };
        out.push(Lease {
            mac: Some(f[1].to_string()),
            ip: ip.to_string(),
            hostname: f.get(3).and_then(|v| non_sentinel(v)),
            client_hostname: None,
            vendor: None,
            binding_state,
            starts: None,
            ends: None,
            // No client-last-transaction timestamp in dnsmasq -> approximate.
            cltt: (expiry != 0).then(|| expiry - lease_secs),
            tstp: (expiry != 0).then_some(expiry),
        });
    }
    if malformed > 0 {
        slog_scope::warn!("parse_dnsmasq: skipped {malformed} malformed lease line(s)");
    }
    out
}

/// Convert a dhcpd lease `Date` (UTC, as written in `dhcpd.leases`) to unix epoch
/// seconds. `None` if the calendar fields don't form a valid UTC instant.
fn date_to_epoch(d: &dhcpd_parser::common::Date) -> Option<i64> {
    use chrono::TimeZone;
    chrono::Utc
        .with_ymd_and_hms(
            i32::try_from(d.year).ok()?,
            u32::try_from(d.month).ok()?,
            u32::try_from(d.day).ok()?,
            u32::try_from(d.hour).ok()?,
            u32::try_from(d.minute).ok()?,
            u32::try_from(d.second).ok()?,
        )
        .single()
        .map(|dt| dt.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_to_epoch_converts_utc() {
        use dhcpd_parser::common::Date;
        let at = |year, month, day, hour, minute, second| {
            date_to_epoch(&Date {
                weekday: 0,
                year,
                month,
                day,
                hour,
                minute,
                second,
            })
        };
        assert_eq!(at(1970, 1, 1, 0, 0, 0), Some(0));
        assert_eq!(at(2000, 1, 1, 0, 0, 0), Some(946_684_800));
        assert_eq!(at(2020, 13, 1, 0, 0, 0), None);
    }

    #[test]
    fn dnsmasq_parse_basic_and_sentinels() {
        let now = 1_000_000_000;
        let lease_secs = 43_200;
        // active with hostname; unknown hostname `*`; infinite (0); expired; IPv6 skip; header skip.
        let s = "\
1000043200 aa:bb:cc:dd:ee:01 10.11.5.60 laptop 01:aa:bb:cc:dd:ee:01
1000043200 aa:bb:cc:dd:ee:02 10.11.5.61 * *
0 aa:bb:cc:dd:ee:03 10.11.5.62 forever *
999999999 aa:bb:cc:dd:ee:04 10.11.5.63 old *
1000043200 aa:bb:cc:dd:ee:05 fe80::1 v6host *
duid 00:01:00:01
";
        let v = parse_dnsmasq(s, lease_secs, now);
        assert_eq!(v.len(), 4, "v6 + duid header skipped");
        assert_eq!(v[0].ip, "10.11.5.60");
        assert_eq!(v[0].hostname.as_deref(), Some("laptop"));
        assert_eq!(v[0].binding_state, BindingState::Active);
        assert_eq!(v[0].cltt, Some(1000043200 - lease_secs));
        assert_eq!(v[0].tstp, Some(1000043200));
        assert_eq!(v[0].vendor, None);
        assert_eq!(v[0].starts, None);
        // `*` hostname -> None
        assert_eq!(v[1].hostname, None);
        // infinite lease
        assert_eq!(v[2].binding_state, BindingState::Active);
        assert_eq!(v[2].cltt, None);
        assert_eq!(v[2].tstp, None);
        // expired -> Free, cltt still approximated from expiry.
        assert_eq!(v[3].binding_state, BindingState::Free);
        assert_eq!(v[3].cltt, Some(999_999_999 - lease_secs));
    }

    #[test]
    fn isc_adapter_maps_fields_verbatim() {
        // Guards the "inert under flavor=isc" invariant: the superset must carry the
        // same field values the consumers read from `dhcpd_parser` directly before.
        let s = "\
lease 10.11.5.60 {
  starts 5 2024/01/05 10:00:00;
  ends 5 2024/01/05 22:00:00;
  cltt 5 2024/01/05 10:00:00;
  binding state active;
  hardware ethernet aa:bb:cc:dd:ee:01;
  client-hostname \"laptop\";
}";
        let v = parse_isc(s, Path::new("test")).unwrap();
        let l = v
            .iter()
            .find(|l| l.ip == "10.11.5.60")
            .expect("lease parsed");
        assert_eq!(l.mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        assert_eq!(l.binding_state, BindingState::Active);
        // cltt 2024-01-05 10:00:00 UTC -> epoch, computed inside the adapter (was
        // `date_to_epoch(dates.cltt)` in the consumer before).
        assert_eq!(l.cltt, Some(1_704_448_800));
        // starts/ends stay display strings (contract of /dhcp), not epochs.
        assert!(l.starts.is_some() && l.ends.is_some());
    }
}
