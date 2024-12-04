use crate::speedtest::SpeedTest;
use anyhow::bail;
use slog_scope::{error, info};
use std::sync::Arc;
use tokio::sync::Mutex;

async fn check_is_wide_internet_available(config: &crate::config::Ping) -> bool {
    info!("Checking if wide network is available");
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

pub struct State {
    config: crate::config::Config,
    scheduler: tokio_cron_scheduler::JobScheduler,
    persistent_state: crate::persistent_state::PersistentStateGuard,
}

impl State {
    pub async fn init_cronjobs(state: Arc<Mutex<Self>>) -> anyhow::Result<()> {
        use tokio_cron_scheduler::Job;
        let state1 = state.clone();
        let state_guard = state.lock().await;
        info!("Starting ping scheduled processor");
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
                            .update(|persistent_state| {
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
        info!("Starting speedtest scheduled processor");
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
                                    .update(|persistent_state| {
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
                let persistent_state = state_guard.persistent_state.clone();
                info!("Starting balance scheduled processor");
                state_guard
                    .scheduler
                    .add(Job::new_async(crontab, move |_uuid, _l| {
                        let state1 = state1.clone();
                        let provider1 = provider1.clone();
                        let persistent_state = persistent_state.clone();
                        Box::pin(async move {
                            let config = { state1.lock().await.config.clone() };
                            let balance = match provider1
                                .get_and_alert_balance(&persistent_state, &config.telegram)
                                .await
                            {
                                Ok(balance) => balance,
                                Err(err) => {
                                    error!("Unable to get balance: {err}");
                                    return;
                                }
                            };
                            let r = state1
                                .lock()
                                .await
                                .persistent_state
                                .update(|state| {
                                    state.balance = Some(balance);
                                })
                                .await;

                            if let Err(err) = r {
                                error!("Unable to update balance in persistent storage: {err}")
                            }
                        })
                    })?)
                    .await?;
            }
        }

        if let Some(telegram) = &state_guard.config.telegram {
            let persistent_state = state_guard.persistent_state.clone();
            let telegram1 = telegram.clone();
            info!("Starting telegram queue scheduled processor");
            state_guard
                .scheduler
                .add(Job::new_async(
                    &telegram.retry_crontab,
                    move |_uuid, _l| {
                        let persistent_state = persistent_state.clone();
                        let telegram = telegram1.clone();
                        Box::pin(async move {
                            if let Err(err) = telegram.process_queue(&persistent_state).await {
                                error!("Unable to process telegram queue: {err}");
                            }
                        })
                    },
                )?)
                .await?;
        }

        state_guard.scheduler.start().await?;

        Ok(())
    }

    pub async fn get_balance(&self) -> anyhow::Result<f64> {
        let config = self.config.clone();
        let balance = match config.mobile_provider {
            Some(ref provider) => provider.get_balance().await?,
            None => bail!("Section mobile_provider is not defined in configuration"),
        };
        let r = self
            .persistent_state
            .update(|persistent_state| {
                persistent_state.balance = Some(balance);
            })
            .await;
        if let Err(err) = r {
            error!("Unable to update persistent state: {err}");
        }

        Ok(balance)
    }

    pub async fn get_speedtest(&self) -> anyhow::Result<crate::speedtest::SpeedTest> {
        let config = self.config.clone();
        let speedtest = SpeedTest::run(&config.speedtest).await?;
        let speedtest1 = speedtest.clone();
        let r = self
            .persistent_state
            .update(|persistent_state| {
                persistent_state.speedtest = Some(speedtest1);
            })
            .await;
        if let Err(err) = r {
            error!("Unable to update persistent state: {err}");
        }

        Ok(speedtest)
    }

    pub async fn new(config: &crate::config::Config) -> anyhow::Result<Arc<Mutex<Self>>> {
        use tokio_cron_scheduler::JobScheduler;

        let state = Arc::new(Mutex::new(Self {
            config: config.clone(),
            persistent_state: crate::persistent_state::PersistentStateGuard::load_from_yaml(
                &config.persistent_state_path,
            ),
            scheduler: JobScheduler::new().await?,
        }));

        Ok(state)
    }

    pub async fn persistent_state(&self) -> crate::persistent_state::PersistentState {
        self.persistent_state.get().await
    }

    pub fn config(&self) -> &crate::config::Config {
        &self.config
    }
}
