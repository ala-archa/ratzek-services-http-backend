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
pub struct SpeedTest {
    pub speedtest_cli_path: std::path::PathBuf,
    pub crontab: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Ping {
    pub server: IpAddr,
    pub crontab: String,
}

fn default_cookie_secure() -> bool {
    true
}

fn default_unlimited_clients_path() -> std::path::PathBuf {
    "/var/lib/ala-archa-http-backend/unlimited-clients.yaml".into()
}

fn default_unlimited_subnet() -> String {
    "10.11.5.0/24".to_string()
}

fn default_dhcpd_validate_command() -> String {
    "dhcpd -t".to_string()
}

fn default_dhcpd_reload_command() -> String {
    "systemctl restart isc-dhcp-server".to_string()
}

/// How the backend manages dhcpd `host` reservations: it owns an include file
/// (referenced from `dhcpd.conf` via `include "...";`), regenerates it from the
/// unlimited-clients store, validates the config with `validate_command`, then
/// applies it with `reload_command`. Replaces the OMAPI/omshell path, which is
/// unreliable on this host. See `src/dhcp_hosts.rs`.
#[derive(Serialize, Deserialize, Clone)]
pub struct DhcpReservations {
    /// Absolute path to the include file the backend owns and rewrites.
    pub include_path: std::path::PathBuf,
    /// Command that exits non-zero if the dhcpd config (incl. the include) is
    /// invalid. Gates every restart so a bad file can't take dhcpd down.
    #[serde(default = "default_dhcpd_validate_command")]
    pub validate_command: String,
    /// Command that makes dhcpd load the regenerated include.
    #[serde(default = "default_dhcpd_reload_command")]
    pub reload_command: String,
}

/// Admin panel credentials. A single administrator authenticates with a login
/// and an argon2 password hash (generate it via the `hash-password` subcommand).
#[derive(Serialize, Deserialize, Clone)]
pub struct Admin {
    pub login: String,
    /// argon2 PHC string, e.g. `$argon2id$v=19$m=...$...`.
    pub password_hash: String,
    /// Set the `Secure` flag on the session cookie. Keep `true` in production
    /// (behind a TLS-terminating proxy); set `false` only for local http tests.
    #[serde(default = "default_cookie_secure")]
    pub cookie_secure: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub log_level: LogLevel,
    pub ipset_shaper_name: String,
    pub ipset_acl_name: String,
    pub ipset_no_shape_name: String,
    pub http_listen: String,
    pub bytes_unlimited_limit: usize,
    pub dhcpd_leases: std::path::PathBuf,
    #[serde(default)]
    pub blacklisted_macs: Vec<String>,
    /// Deprecated: superseded by the unlimited-clients store. Kept only so the
    /// `migrate-unlimited` command can still read it; not used for classification.
    #[serde(default)]
    pub no_shaping_ips: HashSet<String>,
    pub no_shaping_timeout: u64,
    pub shaping_timeout: u64,
    pub speedtest: SpeedTest,
    pub ping: Ping,
    #[serde(default)]
    pub telegram: Option<crate::telegram::Telegram>,
    #[serde(default)]
    pub mobile_provider: Option<crate::mobile_provider::MobileProvider>,
    pub persistent_state_path: std::path::PathBuf,
    #[serde(default)]
    pub admin: Option<Admin>,
    /// File backing the runtime-managed unlimited-clients store.
    #[serde(default = "default_unlimited_clients_path")]
    pub unlimited_clients_path: std::path::PathBuf,
    /// CIDR an admin may pick unlimited-client IPs from.
    #[serde(default = "default_unlimited_subnet")]
    pub unlimited_subnet: String,
    #[serde(default)]
    pub dhcp_reservations: Option<DhcpReservations>,
}

impl Config {
    fn validate(&self) -> Result<()> {
        // Fail fast on a malformed admin password hash so the process refuses to
        // start instead of failing on the first login attempt.
        if let Some(admin) = &self.admin {
            argon2::PasswordHash::new(&admin.password_hash)
                .map_err(|err| anyhow::anyhow!("Invalid admin.password_hash: {err}"))?;
        }

        // Fail fast on an unparseable unlimited_subnet CIDR.
        self.unlimited_subnet
            .parse::<ipnet::IpNet>()
            .map_err(|err| {
                anyhow::anyhow!(
                    "Invalid unlimited_subnet {:?}: {err}",
                    self.unlimited_subnet
                )
            })?;

        if let Some(dr) = &self.dhcp_reservations {
            // Absolute path: the file is written by a root daemon and referenced
            // from dhcpd.conf; a relative path would be ambiguous.
            if !std::path::Path::new(&dr.include_path).is_absolute() {
                anyhow::bail!(
                    "dhcp_reservations.include_path must be absolute, got {:?}",
                    dr.include_path
                );
            }
            if dr.validate_command.trim().is_empty() || dr.reload_command.trim().is_empty() {
                anyhow::bail!(
                    "dhcp_reservations.validate_command and reload_command must be non-empty"
                );
            }
        }

        Ok(())
    }

    /// Parsed `unlimited_subnet` (already validated in [`Config::validate`]).
    pub fn parsed_unlimited_subnet(&self) -> ipnet::IpNet {
        self.unlimited_subnet
            .parse()
            .expect("unlimited_subnet validated at startup")
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
