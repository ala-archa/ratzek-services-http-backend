//! Backend-owned DHCP lease model + dnsmasq lease-file parser. Consumers depend
//! only on [`Lease`] / [`Leases`] here. (Historically this abstracted over ISC
//! dhcpd too; after the dnsmasq migration finalized, the ISC adapter and the
//! `dhcpd_parser` dependency were dropped — the backend is dnsmasq-only.)

use anyhow::{anyhow, Context, Result};
use std::path::Path;

/// Lease-parsing input: the configured DHCP lease length, used to approximate
/// `last_seen`/`cltt` (dnsmasq's lease file has no client-last-transaction time).
/// Snapshot once from `State` (see `State::dhcp_params`) and pass to `Dhcp::read`.
#[derive(Debug, Clone, Copy)]
pub struct DhcpParams {
    pub lease_secs: i64,
}

/// Lease binding state. dnsmasq's lease file normally holds only active leases;
/// an expired-but-not-yet-pruned one maps to `Free`. `Abandoned` is retained for
/// the API contract but never produced under dnsmasq.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingState {
    Active,
    Free,
    Abandoned,
}

/// One DHCP lease. Some fields (`client_hostname`, `vendor`, `starts`, `ends`) are
/// ISC-era and always `None` under dnsmasq — kept so the `/dhcp` API contract (the
/// frontend expects these keys) is preserved.
#[derive(Debug, Clone)]
pub struct Lease {
    /// Hardware (MAC) address as written by the server.
    pub mac: Option<String>,
    pub ip: String,
    pub hostname: Option<String>,
    /// Always `None` under dnsmasq (kept for the `/dhcp` contract).
    pub client_hostname: Option<String>,
    /// Always `None` under dnsmasq (kept for the `/dhcp` contract).
    pub vendor: Option<String>,
    pub binding_state: BindingState,
    /// Always `None` under dnsmasq (kept for the `/dhcp` contract).
    pub starts: Option<String>,
    /// Always `None` under dnsmasq (kept for the `/dhcp` contract).
    pub ends: Option<String>,
    /// Client-last-transaction time ("last seen"), unix epoch sec UTC — approximated
    /// as `expiry - lease_secs` (`None` for an infinite lease).
    pub cltt: Option<i64>,
    /// Last transaction time, unix epoch sec UTC = the lease `expiry`.
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
    /// Parse the dnsmasq lease file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read.
    pub fn read(leases: &Path, params: DhcpParams) -> Result<Leases> {
        let s = std::fs::read_to_string(leases)
            .with_context(|| format!("Failed to read {leases:?}"))?;
        let v = parse_dnsmasq(&s, params.lease_secs, chrono::Utc::now().timestamp());
        // A non-empty file that yields zero leases usually means a wrong path or a
        // non-dnsmasq lease format — surface it rather than silently showing "no clients".
        if v.is_empty() && !s.trim().is_empty() {
            slog_scope::warn!(
                "Dhcp::read: {leases:?} is non-empty but parsed 0 leases — wrong path or format?"
            );
        }
        Ok(Leases(v))
    }

    /// Find the lease for `ip`.
    ///
    /// # Errors
    /// Returns an error if the file can't be read, or no lease matches `ip`.
    pub fn of_ip(leases: &Path, params: DhcpParams, ip: &str) -> Result<Lease> {
        Self::read(leases, params)?
            .of_ip(ip)
            .ok_or_else(|| anyhow!("DHCP lease not found"))
    }
}

/// dnsmasq lease-file parser. Each lease is a line:
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn dnsmasq_parse_skips_malformed_lines() {
        // <3 fields, and a non-numeric expiry — both malformed, dropped from output.
        let s = "\
too few
notanumber aa:bb:cc:dd:ee:09 10.11.5.70 name *
1000043200 aa:bb:cc:dd:ee:01 10.11.5.60 laptop *
";
        let v = parse_dnsmasq(s, 43_200, 1_000_000_000);
        assert_eq!(v.len(), 1, "only the well-formed line survives");
        assert_eq!(v[0].ip, "10.11.5.60");
    }

    #[test]
    fn leases_of_ip_hit_and_miss() {
        let v = parse_dnsmasq("1000043200 aa:bb:cc:dd:ee:01 10.11.5.60 x *", 43_200, 1);
        let leases = Leases(v);
        // consuming of_ip: build twice to test hit then miss.
        assert!(leases.of_ip("10.11.5.60").is_some());
        let leases2 = Leases(parse_dnsmasq(
            "1000043200 aa:bb:cc:dd:ee:01 10.11.5.60 x *",
            43_200,
            1,
        ));
        assert!(leases2.of_ip("10.11.5.99").is_none());
    }
}
