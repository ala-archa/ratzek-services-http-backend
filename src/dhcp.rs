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
