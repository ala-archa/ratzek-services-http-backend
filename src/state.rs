use crate::speedtest::SpeedTest;
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
    async fn init_cronjobs(state: Arc<Mutex<Self>>) -> anyhow::Result<()> {
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

    async fn schedule_update_persistent_state(state: Arc<Mutex<Self>>) {
        let state = state.clone();
        let config = {
            let state_guard = state.lock().await;
            state_guard.config.clone()
        };
        let persistent_state = {
            let state_guard = state.lock().await;
            state_guard.persistent_state.clone()
        };
        let is_wide_network_available = check_is_wide_internet_available(&config.ping).await;
        let (speedtest, last_speedtest_check) = if let Some(ref last_speetest_check) =
            persistent_state.get().await.last_speedtest_check
        {
            if chrono::Utc::now() - last_speetest_check < chrono::Duration::hours(1) {
                info!("Speedtest check was run less than 1 hour ago");
                let persistent_state = persistent_state.get().await;
                (
                    persistent_state.speedtest,
                    persistent_state.last_speedtest_check,
                )
            } else {
                match SpeedTest::run(&config.speedtest).await {
                    Ok(speedtest) => (Some(speedtest), Some(chrono::Utc::now())),
                    Err(err) => {
                        error!("Unable to run speedtest: {err}");
                        let persistent_state = persistent_state.get().await;
                        (
                            persistent_state.speedtest,
                            persistent_state.last_speedtest_check,
                        )
                    }
                }
            }
        } else {
            match SpeedTest::run(&config.speedtest).await {
                Ok(speedtest) => (Some(speedtest), Some(chrono::Utc::now())),
                Err(err) => {
                    error!("Unable to run speedtest: {err}");
                    let persistent_state = persistent_state.get().await;
                    (
                        persistent_state.speedtest,
                        persistent_state.last_speedtest_check,
                    )
                }
            }
        };

        let balance = match config.mobile_provider {
            Some(ref provider) => match provider
                .get_and_alert_balance(&persistent_state, &config.telegram)
                .await
            {
                Ok(balance) => Some(balance),
                Err(err) => {
                    error!("Unable to get balance: {err}");
                    None
                }
            },
            None => None,
        };
        let state = state.clone();
        tokio::spawn(async move {
            let r = state
                .lock()
                .await
                .persistent_state
                .update(|persistent_state| {
                    persistent_state.is_wide_network_available = Some(is_wide_network_available);
                    persistent_state.speedtest = speedtest;
                    persistent_state.last_speedtest_check = last_speedtest_check;
                    persistent_state.balance = balance;
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
            persistent_state: crate::persistent_state::PersistentStateGuard::load_from_yaml(
                &config.persistent_state_path,
            ),
            scheduler: JobScheduler::new().await?,
        }));

        // Закомменчено, надо вынести в командную строчку
        // Self::schedule_update_persistent_state(state.clone()).await;

        Self::init_cronjobs(state.clone()).await?;

        Ok(state)
    }

    pub async fn persistent_state(&self) -> crate::persistent_state::PersistentState {
        self.persistent_state.get().await
    }

    pub fn config(&self) -> &crate::config::Config {
        &self.config
    }
}
