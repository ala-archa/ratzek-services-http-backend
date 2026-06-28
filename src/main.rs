use actix_web::web;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use slog::{o, Drain};
use slog_scope::error;

mod config;
mod dhcp;
mod error;
mod http;
mod ipset;
mod mobile_provider;
mod omapi;
mod persistent_state;
mod session;
mod speedtest;
mod state;
mod telegram;
mod unlimited_clients;

const CONFIG_DEFAULT_PATH: &str = "/etc/ala-archa-http-backend.yaml";

#[derive(Subcommand)]
enum GetCommand {
    /// Get and update balance
    Balance,
    /// Measure and update Speedtest
    Speedtest,
}

// Example of subcommands
#[derive(Subcommand)]
enum CommandLine {
    /// Dump parsed config file. Helps to find typos
    DumpConfig,
    /// Run HTTP server
    Run,
    /// Update state
    #[command(subcommand)]
    Get(GetCommand),
    /// Generate an argon2 hash for an admin password (for the `admin` config section)
    HashPassword {
        /// Plaintext password to hash
        password: String,
    },
    /// Build the unlimited-clients store file from no_shaping_ips + dhcpd.conf
    /// hosts (one-time migration; writes the file, applies nothing).
    MigrateUnlimited {
        /// Path to the existing dhcpd.conf to read host reservations from
        dhcpd_conf: String,
    },
}

/// Ala-Archa HTTP backend
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Application {
    /// Path to configuration file
    #[clap(short, default_value = CONFIG_DEFAULT_PATH)]
    config_path: String,
    /// Subcommand
    #[clap(subcommand)]
    command: CommandLine,
}

impl Application {
    fn init_syslog_logger(log_level: slog::Level) -> Result<slog_scope::GlobalLoggerGuard> {
        let logger = slog_syslog::SyslogBuilder::new()
            .facility(slog_syslog::Facility::LOG_USER)
            .level(log_level)
            .unix("/dev/log")
            .start()?;

        let logger = slog::Logger::root(logger.fuse(), o!());
        Ok(slog_scope::set_global_logger(logger))
    }

    fn init_env_logger() -> Result<slog_scope::GlobalLoggerGuard> {
        Ok(slog_envlogger::init()?)
    }

    fn init_logger(&self, config: &config::Config) -> Result<slog_scope::GlobalLoggerGuard> {
        if std::env::var("RUST_LOG").is_ok() {
            Self::init_env_logger()
        } else {
            Self::init_syslog_logger(config.log_level.into())
        }
    }

    async fn run_command(&self, config: config::Config) -> Result<()> {
        match &self.command {
            CommandLine::DumpConfig => {
                let config =
                    serde_yaml::to_string(&config).with_context(|| "Failed to dump config")?;
                println!("{}", config);
                Ok(())
            }
            CommandLine::Run => {
                let http_listen = config.http_listen.clone();
                let state = crate::state::State::new(&config).await?;
                crate::state::State::init_cronjobs(state.clone()).await?;
                let session_store = web::Data::new(crate::session::SessionStore::new());

                // Heal unlimited-clients drift on boot. Non-fatal and bounded so a
                // half-available OMAPI can't block startup.
                match tokio::time::timeout(
                    // Generous: reconcile may create many OMAPI hosts via omshell
                    // (each up to OMSHELL_TIMEOUT). Non-fatal — heals on next start.
                    std::time::Duration::from_secs(90),
                    async { state.lock().await.reconcile_unlimited().await },
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => error!("Unlimited reconcile failed: {:#}", err),
                    Err(_) => error!("Unlimited reconcile timed out; will heal on next start"),
                }

                actix_web::HttpServer::new(move || {
                    actix_web::App::new()
                        .app_data(web::Data::new(state.clone()))
                        .app_data(session_store.clone())
                        .service(http::client_get)
                        .service(http::client_register)
                        .service(http::dhcp_leases)
                        .service(http::prometheus_exporter)
                        .service(http::admin_login)
                        .service(http::admin_logout)
                        .service(http::admin_me)
                        .service(http::admin_status)
                        .service(http::unlimited_list)
                        .service(http::unlimited_get)
                        .service(http::unlimited_create)
                        .service(http::unlimited_delete)
                        .service(http::unlimited_patch)
                })
                .bind(&http_listen)?
                .run()
                .await?;
                Ok(())
            }
            CommandLine::HashPassword { .. } => {
                // Handled early in `run()` before the config/logger are loaded.
                Ok(())
            }
            CommandLine::MigrateUnlimited { dhcpd_conf } => {
                migrate_unlimited(&config, dhcpd_conf)
            }
            CommandLine::Get(GetCommand::Balance) => {
                let state = crate::state::State::new(&config).await?;
                let state_guard = state.lock().await;
                let balance = state_guard.get_balance().await;

                match balance {
                    Ok(balance) => {
                        println!("{}", balance);
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
            CommandLine::Get(GetCommand::Speedtest) => {
                let state = crate::state::State::new(&config).await?;
                let state_guard = state.lock().await;
                let speedtest = state_guard.get_speedtest().await;

                match speedtest {
                    Ok(speedtest) => {
                        let speedtest = serde_yaml::to_string(&speedtest)
                            .with_context(|| "Failed to dump speedtest")?;
                        println!("{}", speedtest);
                        Ok(())
                    }
                    Err(err) => Err(err),
                }
            }
        }
    }

    pub async fn run(&self) {
        // Hashing a password needs neither a config file nor a logger, and a
        // valid config already requires a hash — so handle it before reading one.
        if let CommandLine::HashPassword { password } = &self.command {
            match crate::session::hash_password(password) {
                Ok(hash) => println!("{}", hash),
                Err(err) => eprintln!("Failed to hash password: {:#}", err),
            }
            return;
        }

        let config = config::Config::read(&self.config_path).expect("Config");
        let _logger_guard = self.init_logger(&config).expect("Logger");

        if let Err(err) = self.run_command(config).await {
            error!("Failed with error: {:#}", err);
        }
    }
}

/// One-time migration: cross-reference `no_shaping_ips` with the `host`
/// reservations in `dhcpd.conf` and print the resulting unlimited-clients YAML
/// to stdout (review, then redirect into `unlimited_clients_path`). Applies
/// nothing to the live system.
fn migrate_unlimited(config: &config::Config, dhcpd_conf: &str) -> Result<()> {
    use std::collections::{HashMap, HashSet};

    let content = std::fs::read_to_string(dhcpd_conf)
        .with_context(|| format!("Failed to read {:?}", dhcpd_conf))?;
    let parsed = dhcpd_parser::parser::parse(content)
        .map_err(|err| anyhow::anyhow!("Failed to parse {:?}: {}", dhcpd_conf, err))?;

    let mut host_by_ip: HashMap<&str, &dhcpd_parser::parser::Host> = HashMap::new();
    for host in &parsed.hosts {
        for ip in &host.fixed_addresses {
            host_by_ip.insert(ip.as_str(), host);
        }
    }

    let mut clients: Vec<unlimited_clients::UnlimitedClient> = Vec::new();
    let mut seen_names: HashSet<String> = HashSet::new();
    let mut skipped = 0usize;

    let mut ips: Vec<&String> = config.no_shaping_ips.iter().collect();
    ips.sort();
    for ip in ips {
        let host = match host_by_ip.get(ip.as_str()) {
            Some(h) => h,
            None => {
                eprintln!("WARNING: no host block for {ip} in {dhcpd_conf}; skipped");
                skipped += 1;
                continue;
            }
        };
        let mac = host
            .mac
            .as_deref()
            .and_then(unlimited_clients::normalize_mac);
        let mac = match mac {
            Some(m) => m,
            None => {
                eprintln!("WARNING: host {} ({ip}) has no usable MAC; skipped", host.name);
                skipped += 1;
                continue;
            }
        };
        if !seen_names.insert(host.name.clone()) {
            eprintln!("WARNING: duplicate host name {} ({ip}); skipped", host.name);
            skipped += 1;
            continue;
        }
        clients.push(unlimited_clients::UnlimitedClient {
            name: host.name.clone(),
            mac,
            ip: ip.clone(),
            comment: None,
        });
    }

    clients.sort_by(|a, b| a.name.cmp(&b.name));
    print!("{}", serde_yaml::to_string(&clients)?);
    eprintln!(
        "Migrated {} client(s), {} skipped. Review, then write to {:?}.",
        clients.len(),
        skipped,
        config.unlimited_clients_path
    );
    Ok(())
}

#[actix_web::main]
async fn main() {
    Application::parse().run().await;
}
