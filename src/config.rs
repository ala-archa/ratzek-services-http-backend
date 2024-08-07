use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr};

#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum LogLevel {
    Critical,
    Error,
    Warning,
    Info,
    Debug,
    Trace,
}

impl From<LogLevel> for slog::Level {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Critical => slog::Level::Critical,
            LogLevel::Error => slog::Level::Error,
            LogLevel::Warning => slog::Level::Warning,
            LogLevel::Info => slog::Level::Info,
            LogLevel::Debug => slog::Level::Debug,
            LogLevel::Trace => slog::Level::Trace,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub log_level: LogLevel,
    pub ipset_shaper_name: String,
    pub ipset_acl_name: String,
    pub ipset_no_shape_name: String,
    pub http_listen: String,
    pub bytes_unlimited_limit: usize,
    pub wide_network_ip: IpAddr,
    pub dhcpd_leases: std::path::PathBuf,
    #[serde(default)]
    pub blacklisted_macs: Vec<String>,
    #[serde(default)]
    pub no_shaping_ips: HashSet<String>,
    pub no_shaping_timeout: u64,
    pub shaping_timeout: u64,
}

impl Config {
    fn validate(&self) -> Result<()> {
        Ok(())
    }

    pub fn read(file: &str) -> Result<Self> {
        let config = std::fs::read_to_string(file)
            .with_context(|| format!("Failed to load config file {:?}", file))?;
        let config: Self = serde_yaml::from_str(&config)
            .with_context(|| format!("Failed to parse config file {:?}", file))?;

        config.validate()?;
        Ok(config)
    }
}
