use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

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

fn default_blacklist_path() -> std::path::PathBuf {
    "/var/lib/ala-archa-http-backend/blacklist.yaml".into()
}

fn default_unlimited_subnet() -> String {
    "10.11.5.0/24".to_string()
}

/// How the backend manages dnsmasq reservations: it owns the `dhcp-hostsfile`
/// (`include_path`), regenerates it from the unlimited-clients store, validates the
/// config with `validate_command` (`dnsmasq --test`), then reloads dnsmasq with
/// `reload_command` (SIGHUP). Replaces the OMAPI/omshell path, which was unreliable
/// on this host. See `src/dhcp_hosts.rs`.
#[derive(Serialize, Deserialize, Clone)]
pub struct DhcpReservations {
    /// Absolute path to the dnsmasq `dhcp-hostsfile` the backend owns and rewrites.
    /// (Historically named `include_path` from the ISC-include era; semantically it
    /// is now the hostsfile.)
    pub include_path: std::path::PathBuf,
    /// Command that exits non-zero if the config (incl. the hostsfile) is invalid,
    /// e.g. `dnsmasq --test -C /etc/ratzek-dnsmasq.conf`. Gates every reload. Required
    /// (no default — the exact command is host-specific).
    pub validate_command: String,
    /// Command that makes the daemon load the regenerated hostsfile, e.g.
    /// `systemctl reload dnsmasq-ratzek`. Required (host-specific).
    pub reload_command: String,
    /// Optional systemd unit that `apply()` verifies is `is-active` BEFORE running
    /// `reload_command`; if inactive, the reload is skipped
    /// (`Applied::SkippedInactive`) instead of (re)starting the daemon — so a stale
    /// reconcile can't revive a deliberately-stopped daemon. Unset (default) → no guard.
    #[serde(default)]
    pub active_unit: Option<String>,
    /// Optional post-reload log scrape. dnsmasq applies `dhcp-hostsfile` silently
    /// (`dnsmasq --test` can NOT catch a bad reservation line), so the only way to
    /// detect a rejected reservation is to read its log after the SIGHUP reload. A
    /// match triggers a full rollback. Unset (default) → no scrape.
    #[serde(default)]
    pub reload_log: Option<ReloadLog>,
}

/// Post-reload log scrape config (dnsmasq). The daemon must log to `file`
/// (`log-facility=<file>` + `log-dhcp` in dnsmasq.conf).
#[derive(Serialize, Deserialize, Clone)]
pub struct ReloadLog {
    /// Absolute path to the dnsmasq log file to scrape.
    pub file: std::path::PathBuf,
    /// Substring marking that the reload finished reading the hostsfile (stop
    /// scraping once a line with the hostsfile path + this is seen). Default `read`.
    #[serde(default = "default_reload_success_contains")]
    pub success_contains: String,
    /// Substring on a hostsfile-referencing line that signals a rejected
    /// reservation (dnsmasq logs `… at line N of <file>`). Default `at line`.
    #[serde(default = "default_reload_error_contains")]
    pub error_contains: String,
    /// Bounded poll timeout (seconds) waiting for the success marker, `1..=60`
    /// (it runs under the reservation mutation lock). Default 3.
    #[serde(default = "default_reload_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_reload_success_contains() -> String {
    "read".to_string()
}

fn default_reload_error_contains() -> String {
    "at line".to_string()
}

fn default_reload_timeout_secs() -> u64 {
    3
}

fn default_device_metrics_crontab() -> String {
    // Every 5 minutes (6-field cron). Kept modest to spare SD-card writes.
    "0 */5 * * * *".to_string()
}

fn default_device_metrics_retention_days() -> i64 {
    730
}

fn default_device_metrics_retention_hourly_days() -> i64 {
    90
}

fn default_device_metrics_retention_5min_hours() -> i64 {
    48
}

/// Optional per-device metrics: a periodic sampler records first/last seen and
/// accumulated traffic (from dhcpd leases + ipset counters) into a SQLite DB,
/// surfaced in the admin API. Omit to disable. See `src/device_metrics.rs`.
#[derive(Serialize, Deserialize, Clone)]
pub struct DeviceMetricsConfig {
    /// Absolute path to the SQLite DB the backend owns.
    pub db_path: std::path::PathBuf,
    /// 6-field cron for the sampler (default every 5 min).
    #[serde(default = "default_device_metrics_crontab")]
    pub crontab: String,
    /// Drop daily traffic buckets / IP history older than this many days.
    #[serde(default = "default_device_metrics_retention_days")]
    pub retention_days: i64,
    /// Drop hourly traffic buckets older than this many days (default 90).
    #[serde(default = "default_device_metrics_retention_hourly_days")]
    pub retention_hourly_days: i64,
    /// Drop 5-minute traffic buckets older than this many hours (default 48).
    #[serde(default = "default_device_metrics_retention_5min_hours")]
    pub retention_5min_hours: i64,
}

fn default_live_traffic_enabled() -> bool {
    true
}

fn default_live_traffic_crontab() -> String {
    // Every 15 seconds (6-field cron). Two `ipset save` calls per tick is modest even
    // on the Pi; 15s trades a little freshness for less subprocess churn than 10s.
    "*/15 * * * * *".to_string()
}

fn default_live_traffic_window_secs() -> i64 {
    60
}

/// Optional live per-device bandwidth sampler: an in-memory task reads ipset byte
/// counters every ~15s and exposes `bytes_last_min` (total bytes over the last
/// minute) + `rate_bps_live` (current bytes/sec) on `GET /api/v1/admin/devices` —
/// "who is using the channel right now". Data is ephemeral (lost on restart). Omit
/// the section to disable; `enabled: false` also disables. See `src/live_traffic.rs`.
#[derive(Serialize, Deserialize, Clone)]
pub struct LiveTrafficConfig {
    /// Enable the sampler (default true when the section is present).
    #[serde(default = "default_live_traffic_enabled")]
    pub enabled: bool,
    /// 6-field cron for the sampler (default every 15s).
    #[serde(default = "default_live_traffic_crontab")]
    pub crontab: String,
    /// Rolling window (seconds) for `bytes_last_min` / rate freshness (default 60).
    #[serde(default = "default_live_traffic_window_secs")]
    pub window_secs: i64,
}

fn default_history_retention_days() -> i64 {
    90
}

/// Optional WAN history + event log: persists periodic speedtest/balance readings
/// and notable events (internet up/down, low balance, new device, blacklist
/// changes, disconnect) into a SQLite DB, surfaced at `GET /api/v1/admin/wan/*` and
/// `GET /api/v1/admin/events`. Omit to disable. See `src/history.rs`.
#[derive(Serialize, Deserialize, Clone)]
pub struct HistoryConfig {
    /// Absolute path to the SQLite DB the backend owns.
    pub db_path: std::path::PathBuf,
    /// Drop WAN readings / events older than this many days (default 90).
    #[serde(default = "default_history_retention_days")]
    pub retention_days: i64,
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

fn default_alert_queue_max_size() -> usize {
    1000
}

/// Optional Alertmanager→Telegram alerting sink. Alertmanager (on this host) POSTs
/// its webhook to `POST /alertmanager/webhook`; the handler authenticates with
/// `webhook_token` (Bearer), formats the alerts, and enqueues them onto the shared
/// Telegram queue (reuses `telegram.bot_token`) addressed to `telegram_chat_ids`.
/// Requires the top-level `telegram` section (the queue + bot live there). Omit to
/// disable (the endpoint then returns 404). See `src/alertmanager.rs`.
#[derive(Serialize, Deserialize, Clone)]
pub struct Alerting {
    /// Shared secret the webhook requires in `Authorization: Bearer <token>`.
    /// Compared in constant time. Minimum 16 chars (validated); prefer a 32+ byte
    /// random value.
    pub webhook_token: String,
    /// Telegram chat id(s) the alerts are sent to (a dedicated alerts group;
    /// negative id for groups). Kept separate from `mobile_provider.telegram_chat_ids`.
    pub telegram_chat_ids: Vec<String>,
    /// Cap on the persisted Telegram queue length: on enqueue from the webhook,
    /// oldest messages beyond this are dropped (backpressure against an alert storm
    /// on a resource-constrained host). Default 1000.
    #[serde(default = "default_alert_queue_max_size")]
    pub queue_max_size: usize,
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
    pub no_shaping_timeout: u64,
    pub shaping_timeout: u64,
    pub speedtest: SpeedTest,
    pub ping: Ping,
    #[serde(default)]
    pub telegram: Option<crate::telegram::Telegram>,
    #[serde(default)]
    pub alerting: Option<Alerting>,
    #[serde(default)]
    pub mobile_provider: Option<crate::mobile_provider::MobileProvider>,
    pub persistent_state_path: std::path::PathBuf,
    #[serde(default)]
    pub admin: Option<Admin>,
    /// File backing the runtime-managed unlimited-clients store.
    #[serde(default = "default_unlimited_clients_path")]
    pub unlimited_clients_path: std::path::PathBuf,
    /// File backing the runtime-managed MAC blacklist store (union with the
    /// static `blacklisted_macs`).
    #[serde(default = "default_blacklist_path")]
    pub blacklist_path: std::path::PathBuf,
    /// CIDR an admin may pick unlimited-client IPs from.
    #[serde(default = "default_unlimited_subnet")]
    pub unlimited_subnet: String,
    #[serde(default)]
    pub dhcp_reservations: Option<DhcpReservations>,
    #[serde(default)]
    pub device_metrics: Option<DeviceMetricsConfig>,
    #[serde(default)]
    pub history: Option<HistoryConfig>,
    #[serde(default)]
    pub live_traffic: Option<LiveTrafficConfig>,
    /// Configured DHCP lease length in seconds. Only used to approximate `last_seen`
    /// under dnsmasq (whose lease file lacks a client-last-transaction timestamp).
    /// Keep in sync with the dnsmasq lease time (default 12h = 43200).
    #[serde(default = "default_dhcp_lease_secs")]
    pub dhcp_lease_secs: i64,
}

fn default_dhcp_lease_secs() -> i64 {
    43_200
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
            // Absolute path: the hostsfile is written by a root daemon and read by
            // dnsmasq (`dhcp-hostsfile=`); a relative path would be ambiguous.
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
            if let Some(rl) = &dr.reload_log {
                if !std::path::Path::new(&rl.file).is_absolute() {
                    anyhow::bail!(
                        "dhcp_reservations.reload_log.file must be absolute, got {:?}",
                        rl.file
                    );
                }
                // Empty markers are footguns: an empty error_contains matches EVERY
                // line (constant false rollback → network churn); an empty
                // success_contains matches immediately (scrape never detects errors).
                if rl.success_contains.trim().is_empty() || rl.error_contains.trim().is_empty() {
                    anyhow::bail!(
                        "dhcp_reservations.reload_log.success_contains and error_contains \
                         must be non-empty"
                    );
                }
                // Bound the scrape: it runs under the reservation mutation lock.
                if rl.timeout_secs == 0 || rl.timeout_secs > 60 {
                    anyhow::bail!(
                        "dhcp_reservations.reload_log.timeout_secs must be in 1..=60, got {}",
                        rl.timeout_secs
                    );
                }
            }
        }

        if let Some(dm) = &self.device_metrics {
            if !std::path::Path::new(&dm.db_path).is_absolute() {
                anyhow::bail!(
                    "device_metrics.db_path must be absolute, got {:?}",
                    dm.db_path
                );
            }
            if dm.crontab.trim().is_empty() {
                anyhow::bail!("device_metrics.crontab must be non-empty");
            }
            if dm.retention_days < 0 {
                anyhow::bail!("device_metrics.retention_days must be >= 0");
            }
            if dm.retention_hourly_days < 0 {
                anyhow::bail!("device_metrics.retention_hourly_days must be >= 0");
            }
            if dm.retention_5min_hours < 0 {
                anyhow::bail!("device_metrics.retention_5min_hours must be >= 0");
            }
        }

        if let Some(h) = &self.history {
            if !std::path::Path::new(&h.db_path).is_absolute() {
                anyhow::bail!("history.db_path must be absolute, got {:?}", h.db_path);
            }
            if h.retention_days < 0 {
                anyhow::bail!("history.retention_days must be >= 0");
            }
        }

        if let Some(lt) = &self.live_traffic {
            if lt.crontab.trim().is_empty() {
                anyhow::bail!("live_traffic.crontab must be non-empty");
            }
            if lt.window_secs <= 0 {
                anyhow::bail!(
                    "live_traffic.window_secs must be > 0, got {}",
                    lt.window_secs
                );
            }
        }

        if let Some(a) = &self.alerting {
            // Delivery reuses the Telegram queue + bot, so `telegram` is required.
            if self.telegram.is_none() {
                anyhow::bail!("alerting is set but the top-level `telegram` section is missing");
            }
            // A blank token would let any local process post alerts; require a real secret.
            if a.webhook_token.len() < 16 {
                anyhow::bail!("alerting.webhook_token must be at least 16 chars");
            }
            if a.telegram_chat_ids.is_empty() {
                anyhow::bail!("alerting.telegram_chat_ids must be non-empty");
            }
            if a.queue_max_size == 0 {
                anyhow::bail!("alerting.queue_max_size must be > 0");
            }
        }

        // A non-positive lease length would make the dnsmasq `last_seen` approximation
        // (`expiry - dhcp_lease_secs`) land in the future / past the expiry.
        if self.dhcp_lease_secs <= 0 {
            anyhow::bail!("dhcp_lease_secs must be > 0, got {}", self.dhcp_lease_secs);
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
