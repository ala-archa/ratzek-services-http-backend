use actix_web::web;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use slog::{o, Drain};
use slog_scope::error;

mod alertmanager;
mod blacklist;
mod config;
mod device_metrics;
mod dhcp;
mod dhcp_hosts;
mod error;
mod history;
mod http;
mod ipset;
mod live_traffic;
mod mobile_provider;
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
    /// Render the unlimited-clients store as a dnsmasq `--dhcp-hostsfile` and write
    /// it to `--out`. Used to pre-populate reservations before dnsmasq starts, so no
    /// reserved IP can be handed to a dynamic client in the start→reconcile window.
    RenderDnsmasqHostsfile {
        /// Absolute path to write the hostsfile to.
        #[clap(long)]
        out: String,
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
                // failed dhcpd reload / ipset op can't block startup.
                match tokio::time::timeout(
                    // Generous: reconcile may regenerate the dnsmasq hostsfile and
                    // reload dnsmasq. Non-fatal — heals on next start.
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
                        .service(http::alertmanager_webhook)
                        .service(http::admin_login)
                        .service(http::admin_logout)
                        .service(http::admin_me)
                        .service(http::admin_status)
                        .service(http::unlimited_list)
                        .service(http::unlimited_get)
                        .service(http::unlimited_create)
                        .service(http::unlimited_delete)
                        .service(http::unlimited_patch)
                        .service(http::admin_devices)
                        .service(http::admin_device_detail)
                        .service(http::admin_device_traffic)
                        .service(http::admin_devices_disconnect_all)
                        .service(http::admin_device_disconnect)
                        .service(http::admin_device_reset_shaper_counter)
                        .service(http::admin_wan_speedtest)
                        .service(http::admin_wan_balance)
                        .service(http::admin_events)
                        .service(http::blacklist_list)
                        .service(http::blacklist_get)
                        .service(http::blacklist_create)
                        .service(http::blacklist_delete)
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
            CommandLine::RenderDnsmasqHostsfile { out } => {
                let store =
                    unlimited_clients::UnlimitedClientsStore::load(&config.unlimited_clients_path)?;
                let clients = store.list().await;
                let content = dhcp_hosts::render(&clients);
                std::fs::write(out, &content)
                    .with_context(|| format!("failed to write hostsfile {:?}", out))?;
                eprintln!("Wrote {} reservation(s) to {:?}", clients.len(), out);
                Ok(())
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

#[actix_web::main]
async fn main() {
    Application::parse().run().await;
}
