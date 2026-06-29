use anyhow::{anyhow, Result};

pub struct Dhcp;

impl Dhcp {
    pub fn read(leases: &std::path::Path) -> Result<dhcpd_parser::leases::Leases> {
        let s = std::fs::read_to_string(leases)
            .map_err(|err| anyhow!("Failed to read {:?}: {}", leases, err))?;
        let leases = dhcpd_parser::parser::parse(s)
            .map_err(|err| anyhow!("Failed to parse {:?}: {}", leases, err))?;
        Ok(leases.leases)
    }

    pub fn of_ip(leases: &std::path::Path, ip: &str) -> Result<dhcpd_parser::leases::Lease> {
        use dhcpd_parser::parser::LeasesMethods;
        Self::read(leases)?
            .all()
            .into_iter()
            .find(|lease| lease.ip == ip)
            .ok_or_else(|| anyhow!("DHCP lease not found"))
    }
}

/// Convert a dhcpd lease `Date` (UTC, as written in `dhcpd.leases`) to unix epoch
/// seconds. `None` if the calendar fields don't form a valid UTC instant. Shared by
/// the `/dhcp` serializer and the device-metrics sampler (cltt = last-seen).
pub fn date_to_epoch(d: &dhcpd_parser::common::Date) -> Option<i64> {
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
        // Out-of-range calendar fields don't form a valid instant -> None.
        assert_eq!(at(2020, 13, 1, 0, 0, 0), None);
    }
}
