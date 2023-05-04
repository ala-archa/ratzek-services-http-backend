use anyhow::{anyhow, Result};
use slog_scope::info;
use std::process::Stdio;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct State {
    config: crate::config::Config,
    is_wide_network_available: bool,
    active_wifi_stations: usize,
}

impl State {
    pub fn new(config: &crate::config::Config) -> Self {
        Self {
            config: config.clone(),
            is_wide_network_available: false,
            active_wifi_stations: 0,
        }
    }

    pub fn wide_network_available(&self) -> bool {
        self.is_wide_network_available
    }

    pub fn active_wifi_stations(&self) -> usize {
        self.active_wifi_stations
    }

    pub fn config(&self) -> &crate::config::Config {
        &self.config
    }

    fn update_wifi_stations(&mut self) -> Result<()> {
        let output = std::process::Command::new("hostapd_cli")
            .args(&[
                "-p",
                &self.config().hostap_control_path.to_string_lossy(),
                "list_sta",
            ])
            .stdout(Stdio::piped())
            .output()?;

        let output = String::from_utf8(output.stdout)
            .map_err(|err| anyhow!("Decode command output: {}", err))?;

        self.active_wifi_stations = output.lines().count();
        info!("active_wifi_stations = {}", self.active_wifi_stations);

        Ok(())
    }

    async fn update_is_wide_network_available(&mut self) {
        let ping_client = match surge_ping::Client::new(&surge_ping::Config::new()) {
            Ok(v) => v,
            Err(err) => {
                slog_scope::error!("Unable to initialize pinger: {err}");
                return;
            }
        };
        let mut pinger = ping_client
            .pinger(
                self.config.wide_network_ip,
                surge_ping::PingIdentifier::from(1),
            )
            .await;
        pinger.timeout(std::time::Duration::from_secs(10));
        let r = pinger
            .ping(surge_ping::PingSequence::from(1), &[1, 2, 3])
            .await
            .is_ok();

        info!("is_wide_network_available = {r}");

        self.is_wide_network_available = r
    }

    pub async fn update(&mut self) {
        self.update_is_wide_network_available().await;

        if let Err(err) = self.update_wifi_stations() {
            slog_scope::error!("Unable to calculate number of active wifi stations: {err}");
        }
    }
}

pub fn ticker(state: Arc<Mutex<State>>) {
    actix_web::rt::spawn(async move {
        loop {
            {
                let mut state = state.lock().await;
                state.update().await;
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await
        }
    });
}
