use std::sync::Arc;

use actix_web::web;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use slog::{o, Drain};
use slog_scope::error;
use tokio::sync::Mutex;

mod config;
mod dhcp;
mod http;
mod ipset;
mod state;

const CONFIG_DEFAULT_PATH: &str = "/etc/ala-archa-http-backend.yaml";

// Example of subcommands
#[derive(Subcommand)]
enum CommandLine {
    /// Dump parsed config file. Helps to find typos
    DumpConfig,
    /// Run HTTP server
    Run,
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
                let state = Arc::new(Mutex::new(crate::state::State::new(&config)));
                crate::state::ticker(state.clone());
                actix_web::HttpServer::new(move || {
                    actix_web::App::new()
                        .app_data(web::Data::new(state.clone()))
                        .service(http::client_get)
                        .service(http::client_register)
                        .service(http::dhcp_leases)
                        .service(http::prometheus_exporter)
                })
                .bind(&http_listen)?
                .run()
                .await?;
                Ok(())
            }
        }
    }

    pub async fn run(&self) {
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
