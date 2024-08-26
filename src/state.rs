use slog_scope::info;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct State {
    config: crate::config::Config,
    is_wide_network_available: bool,
}

impl State {
    pub fn new(config: &crate::config::Config) -> Self {
        Self {
            config: config.clone(),
            is_wide_network_available: false,
        }
    }

    pub fn wide_network_available(&self) -> bool {
        self.is_wide_network_available
    }

    pub fn config(&self) -> &crate::config::Config {
        &self.config
    }

    pub async fn update(&mut self) {
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
        let mut success = false;
        for seq in 0..3 {
            if pinger
                .ping(surge_ping::PingSequence::from(seq), &[1, 2, 3])
                .await
                .is_ok()
            {
                success = true;
                break;
            } else {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }

        info!("is_wide_network_available = {success}");

        self.is_wide_network_available = success
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
