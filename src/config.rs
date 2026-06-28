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

fn default_omapi_server() -> String {
    "127.0.0.1".to_string()
}

fn default_omapi_port() -> u16 {
    7911
}

fn default_omshell_path() -> String {
    "/usr/bin/omshell".to_string()
}

/// OMAPI connection settings used to create/delete dhcpd `host` reservations on
/// the live server (no dhcpd restart). Requires `omapi-port` + a matching `key`
/// in `dhcpd.conf`.
#[derive(Serialize, Deserialize, Clone)]
pub struct Omapi {
    #[serde(default = "default_omapi_server")]
    pub server: String,
    #[serde(default = "default_omapi_port")]
    pub port: u16,
    /// Name of the `key` directive in dhcpd.conf.
    pub key_name: String,
    /// Base64 HMAC-MD5 secret matching that key. Secret — never log it.
    pub key_secret: String,
    /// Absolute path to the `omshell` binary.
    #[serde(default = "default_omshell_path")]
    pub omshell_path: String,
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
    pub omapi: Option<Omapi>,
}

/// An OMAPI key secret is safe only if non-empty and purely alphanumeric — see
/// the note in [`Config::validate`] about omshell truncating base64 specials.
fn is_valid_omapi_secret(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric())
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
            .map_err(|err| anyhow::anyhow!("Invalid unlimited_subnet {:?}: {err}", self.unlimited_subnet))?;

        if let Some(omapi) = &self.omapi {
            // omshell must be an absolute path (avoid PATH hijacking).
            if !std::path::Path::new(&omapi.omshell_path).is_absolute() {
                anyhow::bail!(
                    "omapi.omshell_path must be absolute, got {:?}",
                    omapi.omshell_path
                );
            }
            // The secret is passed unquoted to `omshell key <name> <secret>`, whose
            // tokenizer truncates at base64 specials ('/', '+', '='), so the key it
            // uses silently differs from dhcpd's -> auth fails with "dhcpctl_connect:
            // no more". Require a purely alphanumeric secret.
            if !is_valid_omapi_secret(&omapi.key_secret) {
                anyhow::bail!(
                    "omapi.key_secret must be non-empty and alphanumeric (no '/','+','='); \
                     generate e.g. `openssl rand -base64 64 | tr -d '/+=' | head -c 40`"
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

#[cfg(test)]
mod tests {
    use super::is_valid_omapi_secret;

    #[test]
    fn omapi_secret_validation() {
        assert!(is_valid_omapi_secret("abcDEF123"));
        assert!(!is_valid_omapi_secret("")); // empty
        assert!(!is_valid_omapi_secret("ab/cd")); // base64 '/'
        assert!(!is_valid_omapi_secret("ab+cd")); // base64 '+'
        assert!(!is_valid_omapi_secret("abcd==")); // base64 padding
    }
}
