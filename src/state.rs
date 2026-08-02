use crate::speedtest::SpeedTest;
use anyhow::bail;
use slog_scope::{debug, error, info, warn};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Default retention for device metrics when not set in config.
/// Mirror `config::default_device_metrics_retention_*`.
const SAMPLER_DEFAULT_RETENTION_DAYS: i64 = 730;
pub const SAMPLER_DEFAULT_RETENTION_HOURLY_DAYS: i64 = 90;
pub const SAMPLER_DEFAULT_RETENTION_5MIN_HOURS: i64 = 48;

/// RAII guard that resets a "running" flag on drop, so the flag is cleared even
/// if the sampling task panics (preventing the sampler from getting stuck).
struct RunningGuard(Arc<std::sync::atomic::AtomicBool>);

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

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

/// One device-metrics sampling pass: read active leases + ACL ipset counters and
/// feed them to the store. The heavy (blocking) work runs in `spawn_blocking`.
/// Best-effort: any failure is logged and the next tick retries.
async fn sample_device_metrics(state: Arc<Mutex<State>>) {
    let (store, leases_path, traffic_sets, retention, last_sample, history, params) = {
        let s = state.lock().await;
        let store = match s.device_metrics.clone() {
            Some(st) => st,
            None => return,
        };
        let dm = s.config.device_metrics.as_ref();
        let retention = crate::device_metrics::Retention {
            daily_days: dm
                .map(|d| d.retention_days)
                .unwrap_or(SAMPLER_DEFAULT_RETENTION_DAYS),
            hourly_days: dm
                .map(|d| d.retention_hourly_days)
                .unwrap_or(SAMPLER_DEFAULT_RETENTION_HOURLY_DAYS),
            fivemin_hours: dm
                .map(|d| d.retention_5min_hours)
                .unwrap_or(SAMPLER_DEFAULT_RETENTION_5MIN_HOURS),
        };
        (
            store,
            s.config.dhcpd_leases.clone(),
            // Per-client byte/packet counters live on the shaper (rate-limited) and
            // no_shape (unlimited) sets — a client is in exactly one of them. The
            // acl set has no counters.
            vec![
                s.config.ipset_shaper_name.clone(),
                s.config.ipset_no_shape_name.clone(),
            ],
            retention,
            s.metrics_last_sample.clone(),
            s.history.clone(),
            s.dhcp_params(),
        )
    };

    let now = chrono::Utc::now().timestamp();
    let result = tokio::task::spawn_blocking(
        move || -> anyhow::Result<crate::device_metrics::SampleStats> {
            let observations: Vec<crate::device_metrics::LeaseObservation> =
                crate::dhcp::Dhcp::read(&leases_path, params)?
                    .all()
                    .into_iter()
                    .filter(|l| l.binding_state == crate::dhcp::BindingState::Active)
                    .filter_map(|l| {
                        let mac = l
                            .mac
                            .as_ref()
                            .and_then(|m| crate::unlimited_clients::normalize_mac(m))?;
                        Some(crate::device_metrics::LeaseObservation {
                            mac,
                            ip: l.ip.clone(),
                            hostname: l.hostname.clone(),
                            vendor: l.vendor.clone(),
                            // cltt = real "last seen on the network" (not sample time).
                            last_seen: l.cltt,
                        })
                    })
                    .collect();

            // Union counters from all traffic sets, deduped by IP (an IP should be
            // in only one set, but dedup defensively so it's never double-counted).
            let mut by_ip: std::collections::HashMap<String, crate::device_metrics::IpsetCounter> =
                std::collections::HashMap::new();
            for set in &traffic_sets {
                for e in crate::ipset::IPSet::new(set).entries()? {
                    by_ip.insert(
                        e.ip.clone(),
                        crate::device_metrics::IpsetCounter {
                            ip: e.ip,
                            bytes: e.bytes.unwrap_or(0) as i64,
                            packets: e.packets.unwrap_or(0) as i64,
                        },
                    );
                }
            }
            let counters: Vec<crate::device_metrics::IpsetCounter> = by_ip.into_values().collect();

            store.sample(&observations, &counters, now, retention)
        },
    )
    .await;

    match result {
        Ok(Ok(stats)) => {
            last_sample.store(now, Ordering::SeqCst);
            info!(
                "device-metrics sample: {} devices, {} ips, +{} bytes, {} counter resets, {} new",
                stats.devices,
                stats.ips,
                stats.bytes_added,
                stats.resets,
                stats.new_macs.len()
            );
            for (mac, ip) in &stats.new_macs {
                crate::history::record_event_best_effort(
                    history.as_deref(),
                    crate::history::kind::NEW_DEVICE,
                    Some(mac),
                    Some(ip),
                );
            }
        }
        Ok(Err(err)) => error!("device-metrics sample failed: {err:#}"),
        Err(err) => error!("device-metrics sample task panicked: {err}"),
    }
}

/// One live-traffic sampling pass: read active leases (IP→MAC) + ipset counters and
/// feed them to the in-memory store. Heavy (blocking) work runs in `spawn_blocking`.
/// Best-effort: any failure is logged and the next tick retries. No SQLite — purely
/// in-memory, so it never touches the (flaky) SSD.
async fn sample_live_traffic(state: Arc<Mutex<State>>) {
    let (live, live_last_sample, leases_path, traffic_sets, params) = {
        let s = state.lock().await;
        (
            s.live_traffic.clone(),
            s.live_last_sample.clone(),
            s.config.dhcpd_leases.clone(),
            // Same counter sets as device-metrics: shaper (rate-limited) + no_shape
            // (unlimited). A client is in exactly one; acl has no counters.
            vec![
                s.config.ipset_shaper_name.clone(),
                s.config.ipset_no_shape_name.clone(),
            ],
            s.dhcp_params(),
        )
    };

    let now = chrono::Utc::now().timestamp();
    let result = tokio::task::spawn_blocking(
        move || -> anyhow::Result<crate::live_traffic::SampleStats> {
            // IP -> MAC from active leases. Without it no counter can be attributed,
            // so a leases read failure aborts the whole tick (propagated as Err).
            let ip_to_mac = crate::dhcp::active_ip_to_mac(&leases_path, params)?;

            // Union counters from all traffic sets, deduped by IP. Best-effort per
            // set: a failing set is logged and skipped (partial data beats no data).
            let mut by_ip: std::collections::HashMap<String, crate::device_metrics::IpsetCounter> =
                std::collections::HashMap::new();
            for set in &traffic_sets {
                match crate::ipset::IPSet::new(set).entries() {
                    Ok(entries) => {
                        for e in entries {
                            by_ip.insert(
                                e.ip.clone(),
                                crate::device_metrics::IpsetCounter {
                                    ip: e.ip,
                                    bytes: e.bytes.unwrap_or(0) as i64,
                                    packets: e.packets.unwrap_or(0) as i64,
                                },
                            );
                        }
                    }
                    Err(err) => warn!("live-traffic: ipset {set} read failed: {err:#}"),
                }
            }
            let counters: Vec<crate::device_metrics::IpsetCounter> = by_ip.into_values().collect();

            Ok(live.ingest(&counters, &ip_to_mac, now))
        },
    )
    .await;

    match result {
        Ok(Ok(stats)) => {
            live_last_sample.store(now, Ordering::SeqCst);
            // Routine → debug (this ticks every ~15s; don't flood the journal).
            debug!(
                "live-traffic sample: {} macs, {} series points, {} counters",
                stats.macs_tracked, stats.series_points, stats.ips_read
            );
        }
        Ok(Err(err)) => error!("live-traffic sample failed: {err:#}"),
        Err(err) => error!("live-traffic sample task panicked: {err}"),
    }
}

pub struct State {
    config: crate::config::Config,
    scheduler: tokio_cron_scheduler::JobScheduler,
    persistent_state: crate::persistent_state::PersistentStateGuard,
    unlimited_clients: crate::unlimited_clients::UnlimitedClientsStore,
    /// Optional device-metrics store (None if disabled or the DB couldn't open).
    device_metrics: Option<Arc<crate::device_metrics::DeviceMetricsStore>>,
    /// Unix epoch of the last successful metrics sample (0 = never), for monitoring.
    metrics_last_sample: Arc<AtomicI64>,
    /// Runtime MAC blacklist (union with `config.blacklisted_macs`).
    blacklist: crate::blacklist::BlacklistStore,
    /// Optional WAN-history + event-log store (None if disabled or DB couldn't open).
    history: Option<Arc<crate::history::HistoryStore>>,
    /// In-memory live-traffic store (always present, cheap; empty when the sampler
    /// is disabled). Populated by `sample_live_traffic`, read by `/admin/devices`.
    live_traffic: Arc<crate::live_traffic::LiveTraffic>,
    /// Unix epoch of the last successful live-traffic sample (0 = never), for monitoring.
    live_last_sample: Arc<AtomicI64>,
    /// In-memory per-client shaper byte-quota window tracker (always present, cheap;
    /// the job is gated by config at scheduling time). Owns its own monitoring
    /// counters (last-run / resets / errors / over-quota). See `crate::shaper_quota`.
    shaper_quota: Arc<crate::shaper_quota::ShaperQuota>,
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
                        // Update under the lock; return the PREVIOUS value, then drop the
                        // lock BEFORE the history write (don't hold State across SQLite I/O).
                        let (history, r) = {
                            let state = state1.lock().await;
                            let history = state.history.clone();
                            let r = state
                                .persistent_state
                                .update(|persistent_state| {
                                    let prev = persistent_state.is_wide_network_available;
                                    persistent_state.is_wide_network_available =
                                        Some(is_wide_network_available);
                                    prev
                                })
                                .await;
                            (history, r)
                        };
                        match r {
                            Ok(prev) => {
                                if let Some(kind) =
                                    crate::history::net_transition(prev, is_wide_network_available)
                                {
                                    crate::history::record_event_best_effort(
                                        history.as_deref(),
                                        kind,
                                        None,
                                        None,
                                    );
                                }
                            }
                            Err(err) => error!("Unable to update persistent state: {err}"),
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
                                let history = state.history.clone();
                                // Clone before the value moves into the update closure.
                                let st = speedtest.clone();
                                let r = state
                                    .persistent_state
                                    .update(|persistent_state| {
                                        persistent_state.speedtest = Some(speedtest)
                                    })
                                    .await;
                                if let Err(err) = r {
                                    error!("Unable to update persistent state: {err}");
                                }
                                if let Some(h) = &history {
                                    let now = chrono::Utc::now().timestamp();
                                    if let Err(err) =
                                        h.record_speedtest(now, st.download, st.upload, st.ping)
                                    {
                                        error!("history: record speedtest failed: {err:#}");
                                    }
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
                            let st = state1.lock().await;
                            let history = st.history.clone();
                            let threshold = provider1.low_balance_threshold;
                            // Return the PREVIOUS balance to detect a downward crossing.
                            let r = st
                                .persistent_state
                                .update(|state| {
                                    let prev = state.balance;
                                    state.balance = Some(balance);
                                    prev
                                })
                                .await;
                            drop(st);

                            match r {
                                Ok(prev) => {
                                    if let Some(h) = &history {
                                        let now = chrono::Utc::now().timestamp();
                                        if let Err(err) = h.record_balance(now, balance) {
                                            error!("history: record balance failed: {err:#}");
                                        }
                                        if crate::history::balance_crossed_low(
                                            prev, balance, threshold,
                                        ) {
                                            crate::history::record_event_best_effort(
                                                history.as_deref(),
                                                crate::history::kind::LOW_BALANCE,
                                                None,
                                                Some(&balance.to_string()),
                                            );
                                        }
                                    }
                                }
                                Err(err) => {
                                    error!("Unable to update balance in persistent storage: {err}")
                                }
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

        if let Some(dm_cfg) = &state_guard.config.device_metrics {
            let state1 = state.clone();
            // Guards against overlapping ticks if a sample runs longer than the interval.
            let running = Arc::new(std::sync::atomic::AtomicBool::new(false));
            info!("Starting device-metrics sampler");
            state_guard
                .scheduler
                .add(Job::new_async(&dm_cfg.crontab, move |_uuid, _l| {
                    let state1 = state1.clone();
                    let running = running.clone();
                    Box::pin(async move {
                        if running.swap(true, Ordering::SeqCst) {
                            warn!("device-metrics: previous sample still running, skipping tick");
                            return;
                        }
                        // Resets the flag on drop, even if the sample panics.
                        let _guard = RunningGuard(running.clone());
                        sample_device_metrics(state1).await;
                    })
                })?)
                .await?;
        }

        if let Some(lt_cfg) = &state_guard.config.live_traffic {
            if lt_cfg.enabled {
                let state1 = state.clone();
                // Ticks are frequent (~15s) and `ipset save` isn't instant, so guard
                // against overlapping ticks (a hung tick just skips the next ones;
                // freshness is surfaced via `ratzek_live_traffic_age_seconds`).
                let running = Arc::new(std::sync::atomic::AtomicBool::new(false));
                info!(
                    "Starting live-traffic sampler (window={}s)",
                    lt_cfg.window_secs
                );
                state_guard
                    .scheduler
                    .add(Job::new_async(&lt_cfg.crontab, move |_uuid, _l| {
                        let state1 = state1.clone();
                        let running = running.clone();
                        Box::pin(async move {
                            if running.swap(true, Ordering::SeqCst) {
                                warn!("live-traffic: previous sample still running, skipping tick");
                                return;
                            }
                            let _guard = RunningGuard(running.clone());
                            sample_live_traffic(state1).await;
                        })
                    })?)
                    .await?;
            } else {
                info!("live-traffic sampler disabled (enabled=false)");
            }
        }

        if let Some(sq_cfg) = &state_guard.config.shaper_quota_reset {
            if sq_cfg.enabled {
                let state1 = state.clone();
                // Overlap guard. NB: the guard is handed to the BLOCKING task (not the
                // async closure), so it clears only when the real `ipset` work finishes.
                // If `ipset` ever wedges, the flag stays set and later ticks skip —
                // no thread/subprocess pile-up — and staleness surfaces via
                // `ratzek_shaper_quota_age_seconds` (there is no async timeout that would
                // otherwise release the flag while the orphan thread keeps running).
                let running = Arc::new(std::sync::atomic::AtomicBool::new(false));
                info!(
                    "Starting shaper-quota reset job (period={}s, quota={}B)",
                    sq_cfg.period_secs, sq_cfg.quota_bytes
                );
                state_guard
                    .scheduler
                    .add(Job::new_async(&sq_cfg.crontab, move |_uuid, _l| {
                        let state1 = state1.clone();
                        let running = running.clone();
                        Box::pin(async move {
                            if running.swap(true, Ordering::SeqCst) {
                                warn!("shaper-quota: previous pass still running, skipping tick");
                                return;
                            }
                            let quota = state1.lock().await.shaper_quota();
                            let now = chrono::Utc::now().timestamp();
                            let join = tokio::task::spawn_blocking(move || {
                                // Guard released only when the blocking pass truly ends.
                                let _guard = RunningGuard(running);
                                quota.run_and_record(now);
                            });
                            if let Err(err) = join.await {
                                error!("shaper-quota pass task panicked: {err}");
                            }
                        })
                    })?)
                    .await?;

                // Owner-MAC persist job — SEPARATE from the reset job (own overlap guard).
                // Decoupling is deliberate: a wedged `fsync` on the flaky USB-SSD stalls
                // only this job (durability degrades to the in-memory/time-window backstop),
                // never the resets. Gated on a non-empty owner_state_path (kill-switch).
                if !sq_cfg.owner_state_path.trim().is_empty() {
                    // 6-field cron: every 2 minutes. This cadence IS the write coalescing —
                    // no manual timestamp (so no clock-jump sensitivity); a no-op tick is
                    // near-free (a lock + a BTreeMap compare).
                    const PERSIST_CRONTAB: &str = "0 */2 * * * *";
                    let state2 = state.clone();
                    let persist_running = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    info!(
                        "Starting shaper-quota owner-persist job ({})",
                        sq_cfg.owner_state_path.trim()
                    );
                    state_guard
                        .scheduler
                        .add(Job::new_async(PERSIST_CRONTAB, move |_uuid, _l| {
                            let state2 = state2.clone();
                            let persist_running = persist_running.clone();
                            Box::pin(async move {
                                if persist_running.swap(true, Ordering::SeqCst) {
                                    warn!("shaper-quota: previous persist still running, skipping tick");
                                    return;
                                }
                                let quota = state2.lock().await.shaper_quota();
                                let join = tokio::task::spawn_blocking(move || {
                                    let _guard = RunningGuard(persist_running);
                                    quota.persist_once();
                                });
                                if let Err(err) = join.await {
                                    error!("shaper-quota persist task panicked: {err}");
                                }
                            })
                        })?)
                        .await?;
                }
            } else {
                info!("shaper-quota reset job disabled (enabled=false)");
            }
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

        let unlimited_clients =
            crate::unlimited_clients::UnlimitedClientsStore::load(&config.unlimited_clients_path)?;

        // Best-effort: a metrics-DB failure disables metrics but never blocks startup.
        let device_metrics = config.device_metrics.as_ref().and_then(|dm| {
            match crate::device_metrics::DeviceMetricsStore::open(&dm.db_path) {
                Ok(store) => Some(Arc::new(store)),
                Err(err) => {
                    error!("device-metrics DB unavailable, metrics disabled: {err:#}");
                    None
                }
            }
        });

        // Fail-open: a blacklist load failure must NOT block all clients; fall back
        // to an empty store (enforcement continues via config.blacklisted_macs).
        let blacklist = crate::blacklist::BlacklistStore::load(&config.blacklist_path)
            .unwrap_or_else(|err| {
                error!("blacklist store unavailable, using config-only: {err:#}");
                crate::blacklist::BlacklistStore::empty(&config.blacklist_path)
            });

        // Best-effort: a history-DB failure disables WAN history / events but never
        // blocks startup (same policy as device-metrics).
        let history =
            config.history.as_ref().and_then(|h| {
                match crate::history::HistoryStore::open(&h.db_path, h.retention_days) {
                    Ok(store) => Some(Arc::new(store)),
                    Err(err) => {
                        error!("history DB unavailable, WAN history/events disabled: {err:#}");
                        None
                    }
                }
            });

        info!(
            "DHCP: dnsmasq lease file {:?}, lease_secs={}",
            config.dhcpd_leases, config.dhcp_lease_secs
        );

        // Live-traffic window from config (default 60s); the store is always present.
        let live_window_secs = config
            .live_traffic
            .as_ref()
            .map(|c| c.window_secs)
            .unwrap_or(60)
            .max(1);
        let live_traffic = Arc::new(crate::live_traffic::LiveTraffic::new(
            std::time::Duration::from_secs(live_window_secs as u64),
        ));

        // Shaper-quota window tracker. Period/quota fall back to the SAME config
        // `#[serde(default)]` fns when the section is absent (single source of truth,
        // no drift); the job itself is only scheduled when the section is present and
        // enabled.
        let shaper_quota = {
            let sq = config.shaper_quota_reset.as_ref();
            // Owner-persistence path: `None` when the section is absent or the path is
            // empty (kill-switch → pure in-memory, pre-0.1.38 behavior). Validated
            // absolute + distinct-from-other-state-files by `config::validate()`.
            let owner_path = sq.and_then(|c| {
                let p = c.owner_state_path.trim();
                (!p.is_empty()).then(|| std::path::PathBuf::from(p))
            });
            Arc::new(crate::shaper_quota::ShaperQuota::new(
                config.ipset_shaper_name.clone(),
                sq.map(|c| c.period_secs)
                    .unwrap_or_else(crate::config::default_shaper_quota_period_secs),
                sq.map(|c| c.quota_bytes)
                    .unwrap_or_else(crate::config::default_shaper_quota_bytes),
                config.dhcpd_leases.clone(),
                crate::dhcp::DhcpParams {
                    lease_secs: config.dhcp_lease_secs,
                },
                owner_path,
            ))
        };

        let state = Arc::new(Mutex::new(Self {
            config: config.clone(),
            persistent_state: crate::persistent_state::PersistentStateGuard::load_from_yaml(
                &config.persistent_state_path,
            ),
            scheduler: JobScheduler::new().await?,
            unlimited_clients,
            device_metrics,
            metrics_last_sample: Arc::new(AtomicI64::new(0)),
            blacklist,
            history,
            live_traffic,
            live_last_sample: Arc::new(AtomicI64::new(0)),
            shaper_quota,
        }));

        Ok(state)
    }

    pub async fn persistent_state(&self) -> crate::persistent_state::PersistentState {
        self.persistent_state.get().await
    }

    /// The persistent-state handle (for enqueuing Telegram messages).
    pub fn persistent_state_guard(&self) -> crate::persistent_state::PersistentStateGuard {
        self.persistent_state.clone()
    }

    pub fn config(&self) -> &crate::config::Config {
        &self.config
    }

    /// Lease-parsing input (lease length) for `Dhcp::read`.
    pub fn dhcp_params(&self) -> crate::dhcp::DhcpParams {
        crate::dhcp::DhcpParams {
            lease_secs: self.config.dhcp_lease_secs,
        }
    }

    pub fn unlimited_clients(&self) -> &crate::unlimited_clients::UnlimitedClientsStore {
        &self.unlimited_clients
    }

    pub fn device_metrics(&self) -> Option<&Arc<crate::device_metrics::DeviceMetricsStore>> {
        self.device_metrics.as_ref()
    }

    /// Unix epoch of the last successful metrics sample (0 = never).
    pub fn metrics_last_sample(&self) -> i64 {
        self.metrics_last_sample.load(Ordering::SeqCst)
    }

    pub fn blacklist(&self) -> &crate::blacklist::BlacklistStore {
        &self.blacklist
    }

    /// In-memory live-traffic store (per-MAC recent bandwidth).
    pub fn live_traffic(&self) -> &Arc<crate::live_traffic::LiveTraffic> {
        &self.live_traffic
    }

    /// Unix epoch of the last successful live-traffic sample (0 = never).
    pub fn live_last_sample(&self) -> i64 {
        self.live_last_sample.load(Ordering::SeqCst)
    }

    /// Whether the live-traffic sampler is enabled in config.
    pub fn live_traffic_enabled(&self) -> bool {
        self.config
            .live_traffic
            .as_ref()
            .map(|c| c.enabled)
            .unwrap_or(false)
    }

    /// Whether the shaper-quota reset job is enabled in config.
    pub fn shaper_quota_enabled(&self) -> bool {
        self.config
            .shaper_quota_reset
            .as_ref()
            .map(|c| c.enabled)
            .unwrap_or(false)
    }

    /// Shared handle to the shaper-quota tracker (for the scheduled job).
    pub fn shaper_quota(&self) -> Arc<crate::shaper_quota::ShaperQuota> {
        self.shaper_quota.clone()
    }

    /// Shaper-quota monitoring snapshot: (last-run epoch, resets total, errors total,
    /// members-over-quota). `last_run == 0` means the job never ran / is disabled.
    pub fn shaper_quota_stats(&self) -> (i64, i64, i64, i64) {
        self.shaper_quota.stats()
    }

    /// Optional WAN-history + event-log store (None if disabled or DB couldn't open).
    pub fn history(&self) -> Option<&Arc<crate::history::HistoryStore>> {
        self.history.as_ref()
    }

    /// Whether a (normalized, lowercase) MAC is blacklisted — runtime store in
    /// union with the static `config.blacklisted_macs`. O(1) on the hot client
    /// path (in-memory set + small config Vec). Single source of truth for the
    /// blacklist check in `client_get`/`client_register`.
    pub async fn is_blacklisted(&self, mac: &str) -> bool {
        self.config
            .blacklisted_macs
            .iter()
            .any(|v| v.to_lowercase() == mac)
            || self.blacklist.contains(mac).await
    }

    /// Apply the unlimited-clients store to the live system, healing drift in
    /// both directions. Best-effort and non-fatal: logs and continues so a
    /// failed dhcpd reload / ipset op can't block startup. Run under a timeout by the caller.
    pub async fn reconcile_unlimited(&self) -> anyhow::Result<()> {
        let clients = self.unlimited_clients.list().await;
        info!("Reconciling {} unlimited client(s)", clients.len());

        let no_shape = crate::ipset::IPSet::new(&self.config.ipset_no_shape_name);
        let acl = crate::ipset::IPSet::new(&self.config.ipset_acl_name);

        // 1) Ensure every stored client is applied (store ⊆ system).
        let mut applied = 0usize;
        let mut failed = 0usize;
        for client in &clients {
            let mut ok = true;
            // timeout 0 = permanent; these entries are owned by CRUD/reconcile.
            if let Err(err) = no_shape.add(&client.ip, Some(0)) {
                error!("reconcile: ipset add no_shape {} failed: {err}", client.ip);
                ok = false;
            }
            if let Err(err) = acl.add(&client.ip, Some(0)) {
                error!("reconcile: ipset add acl {} failed: {err}", client.ip);
                ok = false;
            }
            if ok {
                applied += 1;
            } else {
                failed += 1;
            }
        }
        info!("Reconcile applied {applied} client(s), {failed} failed");

        let managed_ips: std::collections::HashSet<&str> =
            clients.iter().map(|c| c.ip.as_str()).collect();

        // 2) Regenerate the dnsmasq reservations hostsfile from the store. The
        //    file is fully derived from the store, so removed clients drop out
        //    automatically — no separate orphan-reservation prune is needed.
        if let Some(dr) = &self.config.dhcp_reservations {
            let content = crate::dhcp_hosts::render(&clients);
            match crate::dhcp_hosts::apply(dr, &content).await {
                Ok(applied) => info!("reconcile: dhcp reservations {applied:?}"),
                Err(err) => error!("reconcile: dhcp reservations apply failed: {err}"),
            }
        }

        // 3) Prune ipset orphans (system ⊄ store). NB: never prune `acl` — it
        //    holds all clients, not only the unlimited ones.
        match no_shape.entries() {
            Ok(entries) => {
                for entry in entries {
                    if !managed_ips.contains(entry.ip.as_str()) {
                        info!("reconcile: removing orphan no_shape entry {}", entry.ip);
                        if let Err(err) = no_shape.del(&entry.ip) {
                            error!("reconcile: ipset del no_shape {} failed: {err}", entry.ip);
                        }
                    }
                }
            }
            Err(err) => error!("reconcile: unable to list no_shape entries: {err}"),
        }

        Ok(())
    }

    /// Apply the global aggregate shaping cap: set the tc class ceil to `limit`
    /// (bits/sec) when `Some`, or the configured `disabled_ceil` when `None`.
    /// Synchronous (one `tc` subprocess), mirroring how reconcile runs ipset.
    pub fn apply_global_shaping(&self, limit: Option<u64>) -> anyhow::Result<()> {
        let sh = &self.config.shaping;
        let ceil = match limit {
            Some(bps) => crate::tc::bps_to_tc(bps),
            None => sh.disabled_ceil.clone(),
        };
        crate::tc::Tc::new(&sh.interface).set_class_limit(&sh.classid, &ceil)
    }

    /// Re-apply the persisted global-shaping state on boot: a reboot resets the tc
    /// class ceil to the boot-script default (disabled), so if a cap was enabled we
    /// restore it here. Best-effort; run under a timeout by the caller.
    pub async fn reconcile_global_shaping(&self) -> anyhow::Result<()> {
        let limit = self.persistent_state.get().await.global_shaping_limit_bps;
        match limit {
            Some(bps) => info!("Reconciling global shaping: enabled at {bps} bps"),
            None => info!("Reconciling global shaping: disabled"),
        }
        self.apply_global_shaping(limit)
    }
}
