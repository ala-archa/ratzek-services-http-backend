use crate::speedtest::SpeedTest;
use serde::{Deserialize, Serialize};
use slog_scope::{error, info};
use std::sync::Arc;
use tokio::sync::Mutex;

async fn check_is_wide_internet_available(config: &crate::config::Ping) -> bool {
    let ping_client = match surge_ping::Client::new(&surge_ping::Config::new()) {
        Ok(v) => v,
        Err(err) => {
            error!("Unable to initialize pinger: {err}");
            return false;
        }
    };
    let mut pinger = ping_client
        .pinger(config.server, surge_ping::PingIdentifier::from(1))
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

    success
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct PersistentState {
    pub is_wide_network_available: Option<bool>,
    pub speedtest: Option<SpeedTest>,
    pub last_tariff_update: Option<chrono::DateTime<chrono::Utc>>,
    pub balance: Option<f64>,
}

impl PersistentState {
    pub fn load_from_yaml(path: &std::path::Path) -> Self {
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) => {
                error!("Unable to read persistent state: {err}");
                return Self::default();
            }
        };
        match serde_yaml::from_str(&content) {
            Ok(state) => state,
            Err(err) => {
                error!("Unable to parse persistent state: {err}");
                Self::default()
            }
        }
    }
}

pub struct PersistentStateGuard {
    state: Arc<Mutex<PersistentState>>,
}

impl PersistentStateGuard {
    pub fn load_from_yaml(path: &std::path::Path) -> Self {
        Self {
            state: Arc::new(Mutex::new(PersistentState::load_from_yaml(path))),
        }
    }

    pub async fn update<F>(&self, config: &crate::config::Config, f: F) -> anyhow::Result<()>
    where
        F: FnOnce(&mut PersistentState),
    {
        let mut state = self.state.lock().await;
        f(&mut state);
        let content = serde_yaml::to_string(&*state)?;
        std::fs::write(&config.persistent_state_path, content)?;
        Ok(())
    }

    pub async fn get(&self) -> PersistentState {
        self.state.lock().await.clone()
    }
}

pub struct State {
    config: crate::config::Config,
    scheduler: tokio_cron_scheduler::JobScheduler,
    persistent_state: PersistentStateGuard,
}

impl State {
    async fn init_cronjobs(state: Arc<Mutex<Self>>) -> anyhow::Result<()> {
        use tokio_cron_scheduler::Job;
        let state1 = state.clone();
        let state_guard = state.lock().await;
        state_guard
            .scheduler
            .add(Job::new_async(
                &state_guard.config.ping.crontab,
                move |_uuid, _l| {
                    let state1 = state1.clone();
                    Box::pin(async move {
                        let config = { state1.lock().await.config.ping.clone() };
                        let is_wide_network_available =
                            check_is_wide_internet_available(&config).await;
                        let state = state1.lock().await;
                        let r = state
                            .persistent_state
                            .update(&state.config, |persistent_state| {
                                persistent_state.is_wide_network_available =
                                    Some(is_wide_network_available)
                            })
                            .await;
                        if let Err(err) = r {
                            error!("Unable to update persistent state: {err}");
                        }
                    })
                },
            )?)
            .await?;

        let state1 = state.clone();
        state_guard
            .scheduler
            .add(Job::new_async(
                &state_guard.config.speedtest.crontab,
                move |_uuid, _l| {
                    let state1 = state1.clone();
                    Box::pin(async move {
                        let config = { state1.lock().await.config.speedtest.clone() };
                        match SpeedTest::run(&config).await {
                            Ok(speedtest) => {
                                let state = state1.lock().await;
                                let r = state
                                    .persistent_state
                                    .update(&state.config, |persistent_state| {
                                        persistent_state.speedtest = Some(speedtest)
                                    })
                                    .await;
                                if let Err(err) = r {
                                    error!("Unable to update persistent state: {err}");
                                }

                                if let Some(mobile_provider) = &state.config.mobile_provider {
                                    mobile_provider
                                        .update_tariff(&state.config, &state.persistent_state)
                                        .await;
                                }
                            }
                            Err(err) => {
                                error!("Unable to run speedtest: {err}");
                            }
                        }
                    })
                },
            )?)
            .await?;

        if let Some(provider) = &state_guard.config.mobile_provider {
            if let Some(crontab) = &provider.get_balance_crontab {
                let state1 = state.clone();
                let provider1 = provider.clone();
                state_guard
                .scheduler
                .add(Job::new_async(
                    crontab,
                    move |_uuid, _l| {
                        let state1 = state1.clone();
                        let provider1 = provider1.clone();
                        Box::pin(async move {
                            let config = { state1.lock().await.config.clone() };
                            let telegram = match config.telegram {
                                Some(ref v) => v,
                                None => {
                                    info!("Telegram is not defined in config file, skipping balance check");
                                    return
                                },
                            };
                            let balance = match provider1.get_and_alert_balance(telegram).await {
                                Ok(balance) => balance,
                                Err(err) => {
                                    error!("Unable to get balance: {err}");
                                    return
                                },
                            };
                            let r = state1.lock().await.persistent_state.update(&config, |state| {
                                state.balance = Some(balance);
                            }).await;

                            if let Err(err) = r {
                                error!("Unable to update balance in persistent storage: {err}")
                            }
                        })
                    },
                )?)
                .await?;
            }
        }

        Ok(())
    }

    async fn schedule_update_persistent_state(state: Arc<Mutex<Self>>) {
        let state = state.clone();
        let config = {
            let state_guard = state.lock().await;
            state_guard.config.clone()
        };
        let is_wide_network_available = check_is_wide_internet_available(&config.ping).await;
        let speedtest = match SpeedTest::run(&config.speedtest).await {
            Ok(speedtest) => Some(speedtest),
            Err(err) => {
                error!("Unable to run speedtest: {err}");
                None
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let r = state
                .lock()
                .await
                .persistent_state
                .update(&config, |persistent_state| {
                    persistent_state.is_wide_network_available = Some(is_wide_network_available);
                    persistent_state.speedtest = speedtest;
                })
                .await;
            if let Err(err) = r {
                error!("Unable to update persistent state: {err}");
            }
        });
    }

    pub async fn new(config: &crate::config::Config) -> anyhow::Result<Arc<Mutex<Self>>> {
        use tokio_cron_scheduler::JobScheduler;

        let state = Arc::new(Mutex::new(Self {
            config: config.clone(),
            persistent_state: PersistentStateGuard::load_from_yaml(&config.persistent_state_path),
            scheduler: JobScheduler::new().await?,
        }));

        Self::schedule_update_persistent_state(state.clone()).await;
        Self::init_cronjobs(state.clone()).await?;

        Ok(state)
    }

    pub async fn persistent_state(&self) -> PersistentState {
        self.persistent_state.get().await
    }

    pub fn config(&self) -> &crate::config::Config {
        &self.config
    }
}
