use crate::speedtest::SpeedTest;
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

pub struct State {
    config: crate::config::Config,
    is_wide_network_available: bool,
    speedtest: SpeedTest,
    scheduler: tokio_cron_scheduler::JobScheduler,
}

impl State {
    pub async fn new(config: &crate::config::Config) -> anyhow::Result<Arc<Mutex<Self>>> {
        use tokio_cron_scheduler::{Job, JobScheduler};

        let is_wide_network_available = check_is_wide_internet_available(&config.ping).await;
        let speedtest = match SpeedTest::run(&config.speedtest).await {
            Ok(speedtest) => speedtest,
            Err(err) => {
                error!("Unable to run speedtest: {err}");
                SpeedTest::default()
            }
        };

        let state = Arc::new(Mutex::new(Self {
            config: config.clone(),
            is_wide_network_available,
            speedtest,
            scheduler: JobScheduler::new().await?,
        }));

        {
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
                            let mut state = state1.lock().await;
                            state.is_wide_network_available = is_wide_network_available;
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
                                    let mut state = state1.lock().await;
                                    state.speedtest = speedtest
                                }
                                Err(err) => {
                                    error!("Unable to run speedtest: {err}");
                                }
                            }
                        })
                    },
                )?)
                .await?;
        }

        Ok(state)
    }

    pub fn wide_network_available(&self) -> bool {
        self.is_wide_network_available
    }

    pub fn speedtest_result(&self) -> &SpeedTest {
        &self.speedtest
    }

    pub fn config(&self) -> &crate::config::Config {
        &self.config
    }
}
