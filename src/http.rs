use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::{future::Future, sync::Arc};

use actix_web::{
    cookie::{Cookie, SameSite},
    delete, get, patch, post,
    web::{self, Data},
    HttpRequest, HttpResponse,
};
use serde::{Deserialize, Serialize};
use slog_scope::{error, info, warn};
use tokio::sync::Mutex;

use crate::device_metrics::Granularity;
use crate::error::APIError;
use crate::session::{AuthSession, SessionStore, SESSION_COOKIE};
use crate::state::State;
use crate::unlimited_clients::{is_valid_name, normalize_mac, UnlimitedClient};

#[derive(Serialize)]
struct ClientConnectionInfo {
    pub bytes_sent: usize,
    pub bytes_unlimited_limit: usize,
    pub shaper_reset_secs: u64,
    pub connection_forget_secs: u64,
}

#[derive(Serialize)]
enum InternetConnectionStatus {
    Inactive,
    Connected(ClientConnectionInfo),
    ClientBlacklisted,
}

#[derive(PartialEq)]
enum Client {
    Whitelist,
    Mac(String),
}

#[derive(Serialize)]
struct ServiceInfo {
    pub internet_connection_status: InternetConnectionStatus,
    pub internet_clients_connected: usize,
    pub is_internet_available: bool,
}

fn client_ip(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        // Trust X-Real-IP only if it parses as an IP. Rejects a forged header
        // (e.g. with embedded newlines) so it can't be used for log injection
        // when the backend is reached without the trusted reverse proxy.
        .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
        .map(|s| s.to_string())
        .or_else(|| req.peer_addr().map(|v| v.ip().to_string()))
}

async fn with_client<CB, Fut>(
    state: Data<Arc<Mutex<State>>>,
    req: &HttpRequest,
    cb: CB,
) -> Result<String, APIError>
where
    CB: FnOnce(String, Client) -> Fut,
    Fut: Future<Output = Result<String, APIError>>,
{
    let client_ip = match client_ip(req) {
        Some(v) => v,
        None => {
            error!("Unable to get client IP");
            return Err(APIError::InternalError);
        }
    };

    info!("Request from {}: {}", client_ip, req.uri());

    let is_no_shape = {
        let state = state.lock().await;
        // The unlimited-clients store is the single source of truth (legacy
        // config.no_shaping_ips is no longer consulted; migrated into the store).
        state.unlimited_clients().contains_ip(&client_ip).await
    };
    if is_no_shape {
        info!("Client is in no_shape list");
        return cb(client_ip, Client::Whitelist).await;
    }

    let dhcp_lease = {
        let state = state.lock().await;
        match crate::dhcp::Dhcp::of_ip(
            &state.config().dhcpd_leases,
            state.dhcp_params(),
            &client_ip,
        ) {
            Ok(v) => v,
            Err(err) => {
                error!("{}", err);
                return Err(APIError::InternalError);
            }
        }
    };

    let client_mac = match dhcp_lease.mac {
        Some(v) => v.to_lowercase(),
        None => {
            error!("Client's MAC not defined in DHCP leases file");
            return Err(APIError::InternalError);
        }
    };

    slog_scope::scope(
        &slog_scope::logger().new(
            slog::slog_o!("client_ip" => client_ip.clone(), "client_mac" => client_mac.clone()),
        ),
        || cb(client_ip, Client::Mac(client_mac)),
    )
    .await
}

#[get("/api/v1/client")]
async fn client_get(state: Data<Arc<Mutex<State>>>, req: HttpRequest) -> Result<String, APIError> {
    with_client(
        state.clone(),
        &req,
        |client_ip: String, client: Client| async move {
            info!("Client requested service info");
            let state = state.lock().await;

            let ipset_shaper = crate::ipset::IPSet::new(&state.config().ipset_shaper_name);
            let shaper_entries = match ipset_shaper.entries() {
                Ok(v) => v,
                Err(err) => {
                    error!("Unable to get ipset list: {}", err);
                    return Err(APIError::InternalError);
                }
            };

            if let Client::Mac(client_mac) = client {
                if state.is_blacklisted(&client_mac).await {
                    let resp = ServiceInfo {
                        internet_clients_connected: shaper_entries.len(),
                        internet_connection_status: InternetConnectionStatus::ClientBlacklisted,
                        is_internet_available: state
                            .persistent_state()
                            .await
                            .is_wide_network_available
                            .unwrap_or(false),
                    };
                    return Ok(serde_json::ser::to_string(&resp).unwrap());
                }
            }

            let ipset_acl = crate::ipset::IPSet::new(&state.config().ipset_acl_name);
            let acl_entries = match ipset_acl.entries() {
                Ok(v) => v,
                Err(err) => {
                    error!("Unable to get ipset list: {}", err);
                    return Err(APIError::InternalError);
                }
            };

            let acl_info = acl_entries.iter().find(|v| v.ip == client_ip);
            let internet_connection_status = if let Some(acl_info) = acl_info {
                let shaper_info = shaper_entries.iter().find(|v| v.ip == client_ip);

                InternetConnectionStatus::Connected(ClientConnectionInfo {
                    bytes_sent: shaper_info.and_then(|v| v.bytes).unwrap_or_default(),
                    bytes_unlimited_limit: state.config().bytes_unlimited_limit,
                    shaper_reset_secs: shaper_info
                        .and_then(|v| v.timeout.map(|v| v.as_secs()))
                        .unwrap_or_default(),
                    connection_forget_secs: acl_info
                        .timeout
                        .map(|v| v.as_secs())
                        .unwrap_or_default(),
                })
            } else {
                InternetConnectionStatus::Inactive
            };

            let resp = ServiceInfo {
                internet_clients_connected: shaper_entries.len(),
                internet_connection_status,
                is_internet_available: state
                    .persistent_state()
                    .await
                    .is_wide_network_available
                    .unwrap_or(false),
            };
            Ok(serde_json::ser::to_string(&resp).unwrap())
        },
    )
    .await
}

#[post("/api/v1/client")]
async fn client_register(
    state: Data<Arc<Mutex<State>>>,
    req: HttpRequest,
) -> Result<String, APIError> {
    with_client(
        state.clone(),
        &req,
        |client_ip: String, client: Client| async move {
            info!("Client requested registration");

            let state = state.lock().await;

            let ipset_acl = crate::ipset::IPSet::new(&state.config().ipset_acl_name);

            let (ipset_shaper, ipset_name, timeout) = match client {
                Client::Whitelist => {
                    let ipset_no_shape =
                        crate::ipset::IPSet::new(&state.config().ipset_no_shape_name);
                    (
                        ipset_no_shape,
                        "no_shape",
                        Some(state.config().no_shaping_timeout),
                    )
                }
                Client::Mac(mac) => {
                    if state.is_blacklisted(&mac).await {
                        error!("Blacklisted client attempted to register");
                        return Err(APIError::InternalError);
                    }
                    let ipset_shaper = crate::ipset::IPSet::new(&state.config().ipset_shaper_name);
                    (ipset_shaper, "shaper", Some(state.config().shaping_timeout))
                }
            };

            info!("Adding {client_ip} to ACL ipset");
            if let Err(err) = ipset_acl.add(&client_ip, timeout) {
                error!("Unable to add client to ACL ipset: {}", err);
                return Err(APIError::InternalError);
            }

            info!("Adding {client_ip} to {ipset_name} ipset");
            if let Err(err) = ipset_shaper.add(&client_ip, timeout) {
                error!("Unable to add client to {:?} ipset: {}", ipset_name, err);
                return Err(APIError::InternalError);
            }

            Ok(String::new())
        },
    )
    .await
}

#[derive(Serialize)]
struct DhcpRecord {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub client_hostname: Option<String>,
    pub vendor_class_identifier: Option<String>,
    pub starts: Option<String>,
    pub ends: Option<String>,
    /// Client-last-transaction time (cltt) — when the device last talked to dhcpd
    /// ("last seen on the network"), as **unix epoch seconds (UTC)**. The ipset
    /// `acl`/`shaper` entries also carry `bytes`/`packets` counters.
    pub last_seen: Option<i64>,
    /// Last time dhcpd recorded a transaction for this lease, **unix epoch seconds (UTC)**.
    pub tstp: Option<i64>,
    pub acl: Option<crate::ipset::Entry>,
    pub shaper: Option<crate::ipset::Entry>,
}

#[get("/api/v1/dhcp")]
async fn dhcp_leases(
    state: Data<Arc<Mutex<State>>>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, APIError> {
    info!("Client requested DHCP leases");

    let params = parse_list_params(
        &query,
        &["ip", "mac", "hostname", "ends", "last_seen"],
        "ip",
    )?;
    let ip_prefix = query.get("ip_prefix").cloned();
    let has_mac = parse_bool_param(&query, "has_mac")?;
    let has_acl = parse_bool_param(&query, "has_acl")?;
    let has_shaper = parse_bool_param(&query, "has_shaper")?;

    let state = state.lock().await;

    // Fetch each ipset once (was an N+1: re-read per lease).
    let acl_entries = crate::ipset::IPSet::new(&state.config().ipset_acl_name)
        .entries()
        .map_err(|err| {
            error!("failed to get ACL entries: {err}");
            APIError::InternalError
        })?;
    let shaper_entries = crate::ipset::IPSet::new(&state.config().ipset_shaper_name)
        .entries()
        .map_err(|err| {
            error!("failed to get shaper entries: {err}");
            APIError::InternalError
        })?;

    let mut items: Vec<DhcpRecord> =
        crate::dhcp::Dhcp::read(&state.config().dhcpd_leases, state.dhcp_params())
            .map_err(|err| {
                error!("failed to read DHCP leases: {err}");
                APIError::InternalError
            })?
            .all()
            .into_iter()
            .map(|lease| DhcpRecord {
                mac: lease.mac,
                hostname: lease.hostname,
                client_hostname: lease.client_hostname,
                vendor_class_identifier: lease.vendor,
                starts: lease.starts,
                ends: lease.ends,
                last_seen: lease.cltt,
                tstp: lease.tstp,
                acl: acl_entries.iter().find(|e| e.ip == lease.ip).cloned(),
                shaper: shaper_entries.iter().find(|e| e.ip == lease.ip).cloned(),
                ip: lease.ip,
            })
            .collect();

    // Domain filters (for the admin "pick an IP" form).
    if let Some(prefix) = &ip_prefix {
        items.retain(|r| r.ip.starts_with(prefix));
    }
    if let Some(want) = has_mac {
        items.retain(|r| r.mac.as_deref().is_some_and(|m| !m.is_empty()) == want);
    }
    if let Some(want) = has_acl {
        items.retain(|r| r.acl.is_some() == want);
    }
    if let Some(want) = has_shaper {
        items.retain(|r| r.shaper.is_some() == want);
    }
    // Free-text filter.
    if let Some(q) = &params.q {
        items.retain(|r| {
            r.ip.to_lowercase().contains(q)
                || r.mac
                    .as_deref()
                    .is_some_and(|s| s.to_lowercase().contains(q))
                || r.hostname
                    .as_deref()
                    .is_some_and(|s| s.to_lowercase().contains(q))
                || r.client_hostname
                    .as_deref()
                    .is_some_and(|s| s.to_lowercase().contains(q))
        });
    }

    items.sort_by(|a, b| {
        let primary = match params.sort.as_str() {
            "mac" => opt_str_cmp(&a.mac, &b.mac),
            "hostname" => opt_str_cmp(&a.hostname, &b.hostname),
            "ends" => opt_str_cmp(&a.ends, &b.ends),
            "last_seen" => a.last_seen.cmp(&b.last_seen),
            _ => cmp_ip(&a.ip, &b.ip),
        };
        // Stable: secondary by ip regardless of order.
        ordered(primary, params.order).then_with(|| cmp_ip(&a.ip, &b.ip))
    });

    let total = items.len();
    let page = paginate(items, &params);
    Ok(json_with_total(&page, total))
}

#[derive(Serialize)]
struct LeaseCounts {
    free: usize,
    active: usize,
    abandoned: usize,
}

/// System status snapshot. Shared by `/metrics` (rendered to Prometheus text)
/// and `GET /api/v1/admin/status` (returned as JSON).
#[derive(Serialize)]
struct AdminStatus {
    internet_available: bool,
    speedtest: Option<crate::speedtest::SpeedTest>,
    isp_balance: Option<f64>,
    last_tariff_update_secs: Option<i64>,
    clients_in_acl: usize,
    clients_in_shaper: usize,
    dhcp_leases: LeaseCounts,
    /// Device-metrics dashboard aggregates (`null` if metrics disabled/unavailable).
    metrics: Option<crate::device_metrics::DashboardStats>,
    /// Distinct blacklisted MACs (runtime store ∪ static config).
    blacklisted_count: usize,
    /// Unlimited clients whose reserved IP is actively leased to a different MAC.
    stale_reservations: usize,
}

/// Collect the system status once, from persistent state + ipsets + DHCP leases.
async fn collect_status(state: &State) -> Result<AdminStatus, APIError> {
    let cfg = state.config();

    let count_set = |name: &str| -> Result<usize, APIError> {
        crate::ipset::IPSet::new(name)
            .entries()
            .map(|e| e.len())
            .map_err(|err| {
                error!("failed to get {name} entries: {err}");
                APIError::InternalError
            })
    };
    let clients_in_acl = count_set(&cfg.ipset_acl_name)?;
    let clients_in_shaper = count_set(&cfg.ipset_shaper_name)?;

    let leases = crate::dhcp::Dhcp::read(&cfg.dhcpd_leases, state.dhcp_params())
        .map_err(|err| {
            error!("failed to read DHCP leases: {err}");
            APIError::InternalError
        })?
        .all();
    let count =
        |s: crate::dhcp::BindingState| leases.iter().filter(|v| v.binding_state == s).count();
    // Under dnsmasq the lease file normally holds only active leases (expired ones
    // are pruned), so free/abandoned are usually 0.
    let lease_counts = LeaseCounts {
        free: count(crate::dhcp::BindingState::Free),
        active: count(crate::dhcp::BindingState::Active),
        abandoned: count(crate::dhcp::BindingState::Abandoned),
    };

    // Device-metrics dashboard (best-effort: null on error/disabled).
    let now = chrono::Utc::now().timestamp();
    let metrics = state
        .device_metrics()
        .and_then(|m| match m.dashboard(now, 5) {
            Ok(d) => Some(d),
            Err(err) => {
                error!("dashboard query failed: {err:#}");
                None
            }
        });

    // Distinct blacklisted MACs (store ∪ config).
    let blacklisted_count = build_blacklisted_set(state.blacklist(), &cfg.blacklisted_macs)
        .await
        .len();

    // Stale reservations: unlimited client IPs actively leased to another MAC.
    let mut active_mac: HashMap<String, Option<String>> = HashMap::new();
    for l in &leases {
        if l.binding_state == crate::dhcp::BindingState::Active {
            active_mac.insert(l.ip.clone(), l.mac.as_ref().and_then(|m| normalize_mac(m)));
        }
    }
    let stale_reservations = state
        .unlimited_clients()
        .list()
        .await
        .into_iter()
        .filter(|c| {
            active_mac
                .get(&c.ip)
                .is_some_and(|lease_mac| lease_mac.as_deref() != Some(c.mac.as_str()))
        })
        .count();

    let ps = state.persistent_state().await;
    Ok(AdminStatus {
        internet_available: ps.is_wide_network_available.unwrap_or(false),
        speedtest: ps.speedtest,
        isp_balance: ps.balance,
        last_tariff_update_secs: ps
            .last_tariff_update
            .map(|t| (t - chrono::Utc::now()).num_seconds()),
        clients_in_acl,
        clients_in_shaper,
        dhcp_leases: lease_counts,
        metrics,
        blacklisted_count,
        stale_reservations,
    })
}

fn gauge(name: &str, help: &str, value: f64) -> String {
    use prometheus_exporter_base::prelude::*;
    PrometheusMetric::build()
        .with_name(name)
        .with_metric_type(MetricType::Gauge)
        .with_help(help)
        .build()
        .render_and_append_instance(&PrometheusInstance::new().with_value(value))
        .render()
}

#[get("/metrics")]
async fn prometheus_exporter(state: Data<Arc<Mutex<State>>>) -> Result<String, APIError> {
    info!("Client requested prometheus exporter data");
    let status = collect_status(&*state.lock().await).await?;

    let mut out = String::new();
    out += &gauge(
        "ratzek_internet_available",
        "Flag of wide internet availability",
        status.internet_available as i64 as f64,
    );
    if let Some(st) = &status.speedtest {
        out += &gauge(
            "ratzek_speedtest_download",
            "Speedtest download speed",
            st.download,
        );
        out += &gauge(
            "ratzek_speedtest_upload",
            "Speedtest upload speed",
            st.upload,
        );
        out += &gauge("ratzek_speedtest_ping", "Speedtest ping speed", st.ping);
    }
    if let Some(balance) = status.isp_balance {
        out += &gauge("ratzek_isp_balance", "ISP balance", balance);
    }
    if let Some(secs) = status.last_tariff_update_secs {
        out += &gauge(
            "ratzek_last_tariff_update",
            "Last tariff update",
            secs as f64,
        );
    }
    out += &gauge(
        "ratzek_clients_in_acl",
        "Number of clients in ACL",
        status.clients_in_acl as f64,
    );
    out += &gauge(
        "ratzek_clients_in_shaper",
        "Number of clients in shaper",
        status.clients_in_shaper as f64,
    );
    out += &gauge(
        "ratzek_dhcp_leases_free",
        "Number of free DHCP leases",
        status.dhcp_leases.free as f64,
    );
    out += &gauge(
        "ratzek_dhcp_leases_active",
        "Number of active DHCP leases",
        status.dhcp_leases.active as f64,
    );
    out += &gauge(
        "ratzek_dhcp_leases_abandoned",
        "Number of abandoned DHCP leases",
        status.dhcp_leases.abandoned as f64,
    );
    // Seconds since the device-metrics sampler last succeeded (0 = never sampled
    // yet / metrics disabled). Lets monitoring alert on a stalled sampler.
    let (metrics_last_sample, metrics_enabled) = {
        let s = state.lock().await;
        (s.metrics_last_sample(), s.device_metrics().is_some())
    };
    // Whether device-metrics collection is enabled at all. Together with the
    // age-gauge this distinguishes "metrics off" from "sampler never ran yet".
    out += &gauge(
        "ratzek_device_metrics_enabled",
        "Whether device-metrics collection is enabled (1) or off (0)",
        metrics_enabled as i64 as f64,
    );
    if metrics_last_sample > 0 {
        let age = (chrono::Utc::now().timestamp() - metrics_last_sample).max(0);
        out += &gauge(
            "ratzek_device_metrics_age_seconds",
            "Seconds since the last successful device-metrics sample",
            age as f64,
        );
    }
    Ok(out)
}

#[derive(Deserialize)]
struct LoginRequest {
    login: String,
    password: String,
}

#[post("/api/v1/admin/login")]
async fn admin_login(
    state: Data<Arc<Mutex<State>>>,
    store: Data<SessionStore>,
    req: HttpRequest,
    body: web::Json<LoginRequest>,
) -> Result<HttpResponse, APIError> {
    let client_ip = client_ip(&req).unwrap_or_else(|| "unknown".to_string());

    let admin = { state.lock().await.config().admin.clone() };
    let admin = match admin {
        Some(admin) => admin,
        None => {
            warn!("Admin login attempt but no admin configured (from {client_ip})");
            return Err(APIError::Unauthorized);
        }
    };

    // argon2 verification is CPU-bound; keep it off the async worker thread.
    let password_hash = admin.password_hash.clone();
    let password = body.password.clone();
    let verified = tokio::task::spawn_blocking(move || {
        crate::session::verify_password(&password_hash, &password)
    })
    .await
    .map_err(|err| {
        error!("Password verification task failed: {err}");
        APIError::InternalError
    })?
    .map_err(|err| {
        error!("Password verification error: {err}");
        APIError::InternalError
    })?;

    if body.login != admin.login || !verified {
        warn!("Failed admin login for {:?} from {client_ip}", body.login);
        return Err(APIError::Unauthorized);
    }

    let token = store.create(admin.login.clone());
    info!("Admin {:?} logged in from {client_ip}", admin.login);

    let cookie = Cookie::build(SESSION_COOKIE, token)
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(admin.cookie_secure)
        .path("/")
        .finish();

    Ok(HttpResponse::Ok()
        .cookie(cookie)
        .json(serde_json::json!({ "login": admin.login })))
}

#[post("/api/v1/admin/logout")]
async fn admin_logout(store: Data<SessionStore>, req: HttpRequest) -> HttpResponse {
    let client_ip = client_ip(&req).unwrap_or_else(|| "unknown".to_string());

    if let Some(token) = req.cookie(SESSION_COOKIE) {
        store.remove(token.value());
    }
    info!("Admin logout from {client_ip}");

    let mut cookie = Cookie::build(SESSION_COOKIE, "").path("/").finish();
    cookie.make_removal();

    HttpResponse::Ok().cookie(cookie).finish()
}

#[get("/api/v1/admin/me")]
async fn admin_me(auth: AuthSession) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "login": auth.login }))
}

#[get("/api/v1/admin/status")]
async fn admin_status(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
) -> Result<HttpResponse, APIError> {
    let status = collect_status(&*state.lock().await).await?;
    Ok(HttpResponse::Ok().json(status))
}

// --- Unlimited clients CRUD (admin-only via AuthSession) ---

/// Config + store snapshot taken under the State lock so handlers can operate
/// without holding it across dhcp-reservation/ipset calls.
struct UnlimitedCtx {
    store: crate::unlimited_clients::UnlimitedClientsStore,
    subnet: ipnet::IpNet,
    dhcp_reservations: Option<crate::config::DhcpReservations>,
    leases: std::path::PathBuf,
    params: crate::dhcp::DhcpParams,
    no_shape_name: String,
    acl_name: String,
}

fn unlimited_ctx(state: &State) -> UnlimitedCtx {
    let c = state.config();
    UnlimitedCtx {
        store: state.unlimited_clients().clone(),
        subnet: c.parsed_unlimited_subnet(),
        dhcp_reservations: c.dhcp_reservations.clone(),
        leases: c.dhcpd_leases.clone(),
        params: state.dhcp_params(),
        no_shape_name: c.ipset_no_shape_name.clone(),
        acl_name: c.ipset_acl_name.clone(),
    }
}

/// Re-render the dnsmasq hostsfile from the current store and re-apply it, undoing a
/// reservation written earlier in a transaction that then failed. Best-effort;
/// startup reconcile heals any residue.
async fn revert_reservations(
    dr: &crate::config::DhcpReservations,
    store: &crate::unlimited_clients::UnlimitedClientsStore,
) {
    let clients = store.list().await;
    let content = crate::dhcp_hosts::render(&clients);
    if let Err(err) = crate::dhcp_hosts::apply(dr, &content).await {
        error!("rollback: dhcp reservations revert failed: {err} (reconcile will heal)");
    }
}

fn rollback_ipset(set: &crate::ipset::IPSet, ip: &str) {
    if let Err(err) = set.del(ip) {
        error!("rollback: ipset del {ip} failed: {err} (manual cleanup may be needed)");
    }
}

#[derive(Deserialize)]
struct CreateUnlimitedClient {
    name: String,
    ip: String,
    #[serde(default)]
    comment: Option<String>,
}

// --- Server-side list pagination/sort/filter (see doc/backend-pagination-spec.md) ---

#[derive(Clone, Copy, PartialEq)]
enum SortOrder {
    Asc,
    Desc,
}

/// Parsed shared list query params. `page`/`per_page` are `None` when omitted,
/// which selects "return everything" mode.
struct ListParams {
    page: Option<usize>,
    per_page: Option<usize>,
    sort: String,
    order: SortOrder,
    /// Lowercased free-text filter, if any.
    q: Option<String>,
}

/// Parse/validate `page`/`per_page`/`sort`/`order`/`q`. `sort` must be in
/// `whitelist`; any invalid value yields `400` (not silently ignored).
///
/// Invariant: every entry in `whitelist` must have a matching arm in the caller's
/// `sort_by` block — otherwise that field validates OK but falls through to the
/// default sort (a silent bug). Keep the two in sync per endpoint.
fn parse_list_params(
    query: &HashMap<String, String>,
    whitelist: &[&str],
    default_sort: &str,
) -> Result<ListParams, APIError> {
    let page = match query.get("page") {
        None => None,
        Some(s) => Some(
            s.parse::<usize>()
                .ok()
                .filter(|&p| p >= 1)
                .ok_or(APIError::BadRequest)?,
        ),
    };
    let per_page = match query.get("per_page") {
        None => None,
        Some(s) => Some(
            s.parse::<usize>()
                .ok()
                .filter(|&p| (1..=200).contains(&p))
                .ok_or(APIError::BadRequest)?,
        ),
    };
    let sort = match query.get("sort") {
        None => default_sort.to_string(),
        Some(s) if whitelist.contains(&s.as_str()) => s.clone(),
        Some(_) => return Err(APIError::BadRequest),
    };
    let order = match query.get("order").map(String::as_str) {
        None | Some("asc") => SortOrder::Asc,
        Some("desc") => SortOrder::Desc,
        Some(_) => return Err(APIError::BadRequest),
    };
    let q = query
        .get("q")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase);
    Ok(ListParams {
        page,
        per_page,
        sort,
        order,
        q,
    })
}

/// Apply the page window. Returns everything when both `page` and `per_page`
/// are absent; otherwise defaults to page=1, per_page=25.
fn paginate<T>(items: Vec<T>, p: &ListParams) -> Vec<T> {
    if p.page.is_none() && p.per_page.is_none() {
        return items;
    }
    let page = p.page.unwrap_or(1);
    let per_page = p.per_page.unwrap_or(25);
    items
        .into_iter()
        .skip((page - 1) * per_page)
        .take(per_page)
        .collect()
}

/// JSON array body + `X-Total-Count` (count after filtering, before pagination).
fn json_with_total<T: Serialize>(items: &[T], total: usize) -> HttpResponse {
    HttpResponse::Ok()
        .insert_header(("X-Total-Count", total.to_string()))
        .json(items)
}

/// Parse an optional boolean query filter: `true`/`1` -> `Some(true)`,
/// `false`/`0` -> `Some(false)`, absent -> `None`, anything else -> `400`.
fn parse_bool_param(query: &HashMap<String, String>, key: &str) -> Result<Option<bool>, APIError> {
    match query.get(key).map(String::as_str) {
        None => Ok(None),
        Some("true") | Some("1") => Ok(Some(true)),
        Some("false") | Some("0") => Ok(Some(false)),
        Some(_) => Err(APIError::BadRequest),
    }
}

/// Compare IP strings numerically when both parse (so `10.11.5.9` < `10.11.5.30`),
/// else lexicographically.
fn cmp_ip(a: &str, b: &str) -> Ordering {
    match (a.parse::<std::net::IpAddr>(), b.parse::<std::net::IpAddr>()) {
        (Ok(x), Ok(y)) => x.cmp(&y),
        _ => a.cmp(b),
    }
}

fn opt_str_cmp(a: &Option<String>, b: &Option<String>) -> Ordering {
    a.as_deref().unwrap_or("").cmp(b.as_deref().unwrap_or(""))
}

fn ordered(primary: Ordering, order: SortOrder) -> Ordering {
    if order == SortOrder::Desc {
        primary.reverse()
    } else {
        primary
    }
}

// --- Device metadata enrichment for admin listings (see doc/admin-api.md §10/§11) ---

struct LeaseInfo {
    mac: Option<String>,
    active: bool,
    hostname: Option<String>,
    vendor: Option<String>,
}

/// Build an `ip -> latest lease` map from the leases file (empty on error). The
/// last lease block for an IP wins (most recent).
fn read_leases_map(
    path: &std::path::Path,
    params: crate::dhcp::DhcpParams,
) -> HashMap<String, LeaseInfo> {
    let dhcp = match crate::dhcp::Dhcp::read(path, params) {
        Ok(d) => d,
        Err(err) => {
            error!("device enrichment: failed to read leases: {err}");
            return HashMap::new();
        }
    };
    dhcp.all()
        .into_iter()
        .map(|l| {
            (
                l.ip.clone(),
                LeaseInfo {
                    mac: l.mac.as_ref().and_then(|m| normalize_mac(m)),
                    active: l.binding_state == crate::dhcp::BindingState::Active,
                    hostname: l.hostname.clone(),
                    vendor: l.vendor.clone(),
                },
            )
        })
        .collect()
}

/// An unlimited client plus live/derived metadata. All extra fields are additive
/// (tolerant clients ignore unknown fields).
#[derive(Serialize)]
struct UnlimitedClientView {
    name: String,
    mac: String,
    ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    created_at: Option<i64>,
    updated_at: Option<i64>,
    online: bool,
    /// True when the reserved IP currently has an active lease held by a different
    /// MAC than the reservation (a stale/conflicting reservation).
    stale_reservation: bool,
    hostname: Option<String>,
    vendor: Option<String>,
    first_seen: Option<i64>,
    last_seen: Option<i64>,
    bytes_total: Option<i64>,
    packets_total: Option<i64>,
    bytes_today: Option<i64>,
    bytes_7d: Option<i64>,
    bytes_30d: Option<i64>,
    rate_bps: Option<i64>,
}

fn build_unlimited_view(
    c: UnlimitedClient,
    leases: &HashMap<String, LeaseInfo>,
    metrics: &HashMap<String, crate::device_metrics::DeviceMetrics>,
) -> UnlimitedClientView {
    let lease = leases.get(&c.ip);
    let m = metrics.get(&c.mac).cloned().unwrap_or_default();
    // online = had traffic in the last sampler interval (from metrics), NOT "holds
    // a lease". stale = the reserved IP is actively leased to a DIFFERENT MAC (a
    // separate, lease-derived concern).
    let online = m.online;
    let stale_reservation = lease
        .map(|l| l.active && l.mac.as_deref() != Some(c.mac.as_str()))
        .unwrap_or(false);
    let hostname = lease.and_then(|l| l.hostname.clone()).or(m.hostname);
    let vendor = lease.and_then(|l| l.vendor.clone()).or(m.vendor);
    UnlimitedClientView {
        name: c.name,
        mac: c.mac,
        ip: c.ip,
        comment: c.comment,
        created_at: c.created_at,
        updated_at: c.updated_at,
        online,
        stale_reservation,
        hostname,
        vendor,
        first_seen: m.first_seen,
        last_seen: m.last_seen,
        bytes_total: m.bytes_total,
        packets_total: m.packets_total,
        bytes_today: m.bytes_today,
        bytes_7d: m.bytes_7d,
        bytes_30d: m.bytes_30d,
        rate_bps: m.rate_bps,
    }
}

/// Enrich clients with lease + metrics data. Heavy reads run in `spawn_blocking`;
/// failures degrade to empty maps (null metrics, offline).
async fn enrich_unlimited(
    clients: Vec<UnlimitedClient>,
    leases_path: std::path::PathBuf,
    params: crate::dhcp::DhcpParams,
    metrics: Option<Arc<crate::device_metrics::DeviceMetricsStore>>,
    now: i64,
) -> Vec<UnlimitedClientView> {
    let macs: Vec<String> = clients.iter().map(|c| c.mac.clone()).collect();
    let (leases_map, metrics_map) = tokio::task::spawn_blocking(move || {
        let leases_map = read_leases_map(&leases_path, params);
        let metrics_map = metrics
            .and_then(|m| {
                m.get_many(&macs, now)
                    .map_err(|e| error!("device-metrics get_many failed: {e:#}"))
                    .ok()
            })
            .unwrap_or_default();
        (leases_map, metrics_map)
    })
    .await
    .unwrap_or_default();
    clients
        .into_iter()
        .map(|c| build_unlimited_view(c, &leases_map, &metrics_map))
        .collect()
}

/// MAC set that is blacklisted (runtime store ∪ static config), for joining whole
/// device lists in one pass (batched counterpart of per-MAC `State::is_blacklisted`).
async fn build_blacklisted_set(
    store: &crate::blacklist::BlacklistStore,
    config_macs: &[String],
) -> HashSet<String> {
    let mut set: HashSet<String> = store.list().await.into_iter().map(|e| e.mac).collect();
    for m in config_macs {
        set.insert(normalize_mac(m).unwrap_or_else(|| m.to_lowercase()));
    }
    set
}

/// Live access classification of a device (ipset membership by IP).
#[derive(Default)]
struct AccessFlags {
    has_acl: bool,
    has_shaper: bool,
    has_no_shape: bool,
}

/// IP membership of the three access-control ipsets, for device classification.
struct IpsetMembership {
    acl: HashSet<String>,
    shaper: HashSet<String>,
    no_shape: HashSet<String>,
}

impl IpsetMembership {
    fn empty() -> Self {
        Self {
            acl: HashSet::new(),
            shaper: HashSet::new(),
            no_shape: HashSet::new(),
        }
    }

    /// Read the three sets into IP sets. Best-effort: a failing set logs and yields
    /// empty, so a transient ipset error degrades the flags rather than failing the
    /// whole listing. Blocking (subprocess) — call inside `spawn_blocking`.
    fn read(acl: &str, shaper: &str, no_shape: &str) -> Self {
        let read = |name: &str| -> HashSet<String> {
            match crate::ipset::IPSet::new(name).entries() {
                Ok(es) => es.into_iter().map(|e| e.ip).collect(),
                Err(e) => {
                    error!("device classification: ipset {name} read failed: {e:#}");
                    HashSet::new()
                }
            }
        };
        Self {
            acl: read(acl),
            shaper: read(shaper),
            no_shape: read(no_shape),
        }
    }

    /// Flags for a device, given its CURRENT IPs (from live leases) — a set holds if
    /// ANY current IP is a member. Empty `ips` (offline / no lease) → all false.
    /// Using live-lease IPs (not the possibly-stale metrics `last_ip`) keeps the flags
    /// consistent with the `disconnect` action, which also operates on live IPs.
    fn flags_for(&self, ips: &[String]) -> AccessFlags {
        let any = |set: &HashSet<String>| ips.iter().any(|ip| set.contains(ip));
        AccessFlags {
            has_acl: any(&self.acl),
            has_shaper: any(&self.shaper),
            has_no_shape: any(&self.no_shape),
        }
    }
}

/// Build `normalized MAC -> current IPs` from active dhcpd leases (for live
/// classification + disconnect). Blocking (file read) — call inside `spawn_blocking`.
fn active_lease_ips(
    leases_path: &std::path::Path,
    params: crate::dhcp::DhcpParams,
) -> anyhow::Result<HashMap<String, Vec<String>>> {
    let leases = crate::dhcp::Dhcp::read(leases_path, params)?;
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for l in leases.all() {
        if l.binding_state != crate::dhcp::BindingState::Active {
            continue;
        }
        if let Some(mac) = l.mac.as_ref().and_then(|m| normalize_mac(m)) {
            let ips = map.entry(mac).or_default();
            if !ips.contains(&l.ip) {
                ips.push(l.ip);
            }
        }
    }
    Ok(map)
}

/// Best-effort variant for classification: a read failure logs and yields an empty
/// map (degrades the flags instead of failing the listing).
fn active_lease_ips_or_empty(
    leases_path: &std::path::Path,
    params: crate::dhcp::DhcpParams,
) -> HashMap<String, Vec<String>> {
    active_lease_ips(leases_path, params).unwrap_or_else(|e| {
        error!("device classification: failed to read leases: {e:#}");
        HashMap::new()
    })
}

/// Everything the device-classification handlers clone out of `State` under one
/// lock (named fields instead of a wide positional tuple).
struct ClassifyDeps {
    metrics: Option<std::sync::Arc<crate::device_metrics::DeviceMetricsStore>>,
    unlimited: crate::unlimited_clients::UnlimitedClientsStore,
    blacklist: crate::blacklist::BlacklistStore,
    leases_path: std::path::PathBuf,
    params: crate::dhcp::DhcpParams,
    acl_name: String,
    shaper_name: String,
    no_shape_name: String,
    config_macs: Vec<String>,
}

impl ClassifyDeps {
    fn snapshot(s: &State) -> Self {
        let c = s.config();
        Self {
            metrics: s.device_metrics().cloned(),
            unlimited: s.unlimited_clients().clone(),
            blacklist: s.blacklist().clone(),
            leases_path: c.dhcpd_leases.clone(),
            params: s.dhcp_params(),
            acl_name: c.ipset_acl_name.clone(),
            shaper_name: c.ipset_shaper_name.clone(),
            no_shape_name: c.ipset_no_shape_name.clone(),
            config_macs: c.blacklisted_macs.clone(),
        }
    }
}

#[derive(Serialize)]
struct DeviceView {
    // `device` carries `online` (traffic-derived) which flattens to the top level.
    #[serde(flatten)]
    device: crate::device_metrics::DeviceRow,
    is_unlimited: bool,
    // Live access classification (ipset membership by IP, blacklist by MAC).
    has_acl: bool,
    has_shaper: bool,
    has_no_shape: bool,
    is_blacklisted: bool,
}

#[get("/api/v1/admin/devices")]
async fn admin_devices(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, APIError> {
    let params = parse_list_params(
        &query,
        &[
            "last_seen",
            "first_seen",
            "bytes_total",
            "bytes_today",
            "bytes_7d",
            "rate_bps",
            "mac",
            "last_ip",
        ],
        "last_seen",
    )?;
    let online_filter = parse_bool_param(&query, "online")?;
    let unlimited_filter = parse_bool_param(&query, "is_unlimited")?;
    let acl_filter = parse_bool_param(&query, "has_acl")?;
    let shaper_filter = parse_bool_param(&query, "has_shaper")?;
    let no_shape_filter = parse_bool_param(&query, "has_no_shape")?;
    let blacklisted_filter = parse_bool_param(&query, "is_blacklisted")?;
    let seen_within_days = match query.get("seen_within_days") {
        None => None,
        Some(s) => Some(
            s.parse::<i64>()
                .ok()
                .filter(|&n| n >= 0)
                .ok_or(APIError::BadRequest)?,
        ),
    };

    let deps = {
        let s = state.lock().await;
        ClassifyDeps::snapshot(&s)
    };
    // Metrics disabled -> empty inventory (not an error).
    let metrics = match deps.metrics {
        Some(m) => m,
        None => return Ok(json_with_total(&Vec::<DeviceView>::new(), 0)),
    };
    let unlimited_macs: HashSet<String> = deps
        .unlimited
        .list()
        .await
        .into_iter()
        .map(|c| c.mac)
        .collect();
    let blacklisted = build_blacklisted_set(&deps.blacklist, &deps.config_macs).await;
    let (acl_name, shaper_name, no_shape_name, leases_path, dhcp_params) = (
        deps.acl_name,
        deps.shaper_name,
        deps.no_shape_name,
        deps.leases_path,
        deps.params,
    );

    let now = chrono::Utc::now().timestamp();
    let (rows, membership, lease_ips) = tokio::task::spawn_blocking(move || {
        let rows = metrics.all_devices(now).unwrap_or_else(|e| {
            error!("device-metrics all_devices failed: {e:#}");
            Vec::new()
        });
        let membership = IpsetMembership::read(&acl_name, &shaper_name, &no_shape_name);
        let lease_ips = active_lease_ips_or_empty(&leases_path, dhcp_params);
        (rows, membership, lease_ips)
    })
    .await
    .unwrap_or_else(|_| (Vec::new(), IpsetMembership::empty(), HashMap::new()));

    let no_ips: Vec<String> = Vec::new();
    let mut views: Vec<DeviceView> = rows
        .into_iter()
        .map(|d| {
            let is_unlimited = unlimited_macs.contains(&d.mac);
            let is_blacklisted = blacklisted.contains(&d.mac);
            let flags = membership.flags_for(lease_ips.get(&d.mac).unwrap_or(&no_ips));
            DeviceView {
                device: d,
                is_unlimited,
                has_acl: flags.has_acl,
                has_shaper: flags.has_shaper,
                has_no_shape: flags.has_no_shape,
                is_blacklisted,
            }
        })
        .collect();

    if let Some(want) = online_filter {
        views.retain(|v| v.device.online == want);
    }
    if let Some(want) = unlimited_filter {
        views.retain(|v| v.is_unlimited == want);
    }
    if let Some(want) = acl_filter {
        views.retain(|v| v.has_acl == want);
    }
    if let Some(want) = shaper_filter {
        views.retain(|v| v.has_shaper == want);
    }
    if let Some(want) = no_shape_filter {
        views.retain(|v| v.has_no_shape == want);
    }
    if let Some(want) = blacklisted_filter {
        views.retain(|v| v.is_blacklisted == want);
    }
    if let Some(days) = seen_within_days {
        let cutoff = now.saturating_sub(days.saturating_mul(86_400));
        views.retain(|v| v.device.last_seen.is_some_and(|ls| ls >= cutoff));
    }
    if let Some(q) = &params.q {
        views.retain(|v| {
            v.device.mac.to_lowercase().contains(q)
                || v.device
                    .last_ip
                    .as_deref()
                    .is_some_and(|s| s.to_lowercase().contains(q))
                || v.device
                    .hostname
                    .as_deref()
                    .is_some_and(|s| s.to_lowercase().contains(q))
                || v.device.ips.iter().any(|ip| ip.to_lowercase().contains(q))
        });
    }
    views.sort_by(|a, b| {
        let primary = match params.sort.as_str() {
            "first_seen" => a.device.first_seen.cmp(&b.device.first_seen),
            "bytes_total" => a.device.bytes_total.cmp(&b.device.bytes_total),
            "bytes_today" => a.device.bytes_today.cmp(&b.device.bytes_today),
            "bytes_7d" => a.device.bytes_7d.cmp(&b.device.bytes_7d),
            "rate_bps" => a.device.rate_bps.cmp(&b.device.rate_bps),
            "mac" => a.device.mac.cmp(&b.device.mac),
            "last_ip" => cmp_ip(
                a.device.last_ip.as_deref().unwrap_or(""),
                b.device.last_ip.as_deref().unwrap_or(""),
            ),
            _ => a.device.last_seen.cmp(&b.device.last_seen),
        };
        ordered(primary, params.order).then_with(|| a.device.mac.cmp(&b.device.mac))
    });

    let total = views.len();
    let page = paginate(views, &params);
    Ok(json_with_total(&page, total))
}

/// A device row + daily traffic series + live flags (for `/devices/{mac}`).
#[derive(Serialize)]
struct DeviceDetailView {
    // `device` carries `online` (traffic-derived) which flattens to the top level.
    #[serde(flatten)]
    device: crate::device_metrics::DeviceRow,
    is_unlimited: bool,
    has_acl: bool,
    has_shaper: bool,
    has_no_shape: bool,
    is_blacklisted: bool,
    daily: Vec<crate::device_metrics::DailyPoint>,
}

/// Number of days of daily traffic history returned by `/devices/{mac}` when the
/// `days` query param is absent, and the inclusive cap on what may be requested.
const DEVICE_DETAIL_DEFAULT_DAYS: i64 = 30;
const DEVICE_DETAIL_MAX_DAYS: i64 = 365;

#[get("/api/v1/admin/devices/{mac}")]
async fn admin_device_detail(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    path: web::Path<String>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, APIError> {
    let mac = normalize_mac(&path.into_inner()).ok_or(APIError::BadRequest)?;
    // Optional `days` window for the daily series (clamped to a sane range).
    let days = query
        .get("days")
        .map(|v| v.parse::<i64>().map_err(|_| APIError::BadRequest))
        .transpose()?
        .unwrap_or(DEVICE_DETAIL_DEFAULT_DAYS)
        .clamp(1, DEVICE_DETAIL_MAX_DAYS);
    let deps = {
        let s = state.lock().await;
        ClassifyDeps::snapshot(&s)
    };
    let metrics = match deps.metrics {
        Some(m) => m,
        None => return Err(APIError::NotFound),
    };
    let is_unlimited = deps
        .unlimited
        .list()
        .await
        .into_iter()
        .any(|c| c.mac == mac);
    let is_blacklisted = build_blacklisted_set(&deps.blacklist, &deps.config_macs)
        .await
        .contains(&mac);
    let (acl_name, shaper_name, no_shape_name, leases_path, dhcp_params) = (
        deps.acl_name,
        deps.shaper_name,
        deps.no_shape_name,
        deps.leases_path,
        deps.params,
    );

    let now = chrono::Utc::now().timestamp();
    let mac_q = mac.clone();
    let (detail_res, membership, lease_ips) = tokio::task::spawn_blocking(move || {
        (
            metrics.device_detail(&mac_q, now, days),
            IpsetMembership::read(&acl_name, &shaper_name, &no_shape_name),
            active_lease_ips_or_empty(&leases_path, dhcp_params),
        )
    })
    .await
    .map_err(|err| {
        error!("device_detail task panicked: {err}");
        APIError::InternalError
    })?;

    let detail = match detail_res {
        Ok(Some(d)) => d,
        Ok(None) => return Err(APIError::NotFound),
        Err(err) => {
            error!("device_detail failed: {err:#}");
            return Err(APIError::InternalError);
        }
    };
    let flags = membership.flags_for(lease_ips.get(&mac).map(Vec::as_slice).unwrap_or(&[]));
    // `online` (traffic-derived) is carried by `detail.device` and flattens out.
    Ok(HttpResponse::Ok().json(DeviceDetailView {
        device: detail.device,
        is_unlimited,
        has_acl: flags.has_acl,
        has_shaper: flags.has_shaper,
        has_no_shape: flags.has_no_shape,
        is_blacklisted,
        daily: detail.daily,
    }))
}

/// Traffic series for the device-detail chart. `bytes` is the per-bucket sum (NOT
/// a rate); the current (open) bucket is partial — that's expected.
#[derive(Serialize)]
struct TrafficSeriesResponse {
    granularity: &'static str,
    from: i64,
    to: i64,
    points: Vec<crate::device_metrics::TrafficPoint>,
}

/// Default series window (seconds) when `from` is omitted, per granularity.
fn traffic_default_window(g: Granularity) -> i64 {
    match g {
        Granularity::Day => 30 * 86_400,
        Granularity::Hour => 7 * 86_400,
        Granularity::FiveMin => 24 * 3_600,
    }
}

#[get("/api/v1/admin/devices/{mac}/traffic")]
async fn admin_device_traffic(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    path: web::Path<String>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, APIError> {
    let mac = normalize_mac(&path.into_inner()).ok_or(APIError::BadRequest)?;
    let granularity = query
        .get("granularity")
        .and_then(|s| Granularity::parse(s))
        .ok_or(APIError::BadRequest)?;
    let parse_opt = |k: &str| -> Result<Option<i64>, APIError> {
        query
            .get(k)
            .map(|v| v.parse::<i64>().map_err(|_| APIError::BadRequest))
            .transpose()
    };
    let from_q = parse_opt("from")?;
    let to_q = parse_opt("to")?;

    // Longest window the rollup's retention can actually back, in seconds — used to
    // clamp `from` (avoids a misleading empty tail). Derived from config (defaults
    // shared with the sampler), not hard-coded. `saturating_*` guards an absurd
    // retention config from overflowing.
    let (metrics, cap) = {
        use crate::state::{
            SAMPLER_DEFAULT_RETENTION_5MIN_HOURS, SAMPLER_DEFAULT_RETENTION_HOURLY_DAYS,
        };
        let s = state.lock().await;
        let dm = s.config().device_metrics.as_ref();
        let cap = match granularity {
            Granularity::Day => 365_i64.saturating_mul(86_400),
            Granularity::Hour => dm
                .map(|d| d.retention_hourly_days)
                .unwrap_or(SAMPLER_DEFAULT_RETENTION_HOURLY_DAYS)
                .saturating_mul(86_400),
            Granularity::FiveMin => dm
                .map(|d| d.retention_5min_hours)
                .unwrap_or(SAMPLER_DEFAULT_RETENTION_5MIN_HOURS)
                .saturating_mul(3_600),
        };
        (s.device_metrics().cloned(), cap)
    };
    let metrics = match metrics {
        Some(m) => m,
        None => return Err(APIError::NotFound),
    };

    let now = chrono::Utc::now().timestamp();
    let to = to_q.unwrap_or(now);
    let from = from_q
        .unwrap_or(to.saturating_sub(traffic_default_window(granularity)))
        .max(to.saturating_sub(cap));

    let series =
        tokio::task::spawn_blocking(move || metrics.traffic_series(&mac, granularity, from, to))
            .await
            .map_err(|err| {
                error!("traffic_series task panicked: {err}");
                APIError::InternalError
            })?;
    let points = match series {
        Ok(Some(p)) => p,
        Ok(None) => return Err(APIError::NotFound),
        Err(err) => {
            error!("traffic_series failed: {err:#}");
            return Err(APIError::InternalError);
        }
    };
    Ok(HttpResponse::Ok().json(TrafficSeriesResponse {
        granularity: granularity.as_str(),
        from,
        to,
        points,
    }))
}

/// Immediately revoke a device's internet access: remove every active-lease IP of
/// the MAC from the acl/shaper/no_shape ipsets. Complements the blacklist (which
/// only blocks future registration). Resolves IPs from LIVE dhcpd leases (not the
/// possibly-stale device-metrics `last_ip`), so it works without device_metrics.
#[post("/api/v1/admin/devices/{mac}/disconnect")]
async fn admin_device_disconnect(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, APIError> {
    let admin_ip = client_ip(&req).unwrap_or_else(|| "unknown".to_string());
    let mac = normalize_mac(&path.into_inner()).ok_or(APIError::BadRequest)?;
    let (leases_path, params, acl, shaper, no_shape, history) = {
        let s = state.lock().await;
        let c = s.config();
        (
            c.dhcpd_leases.clone(),
            s.dhcp_params(),
            c.ipset_acl_name.clone(),
            c.ipset_shaper_name.clone(),
            c.ipset_no_shape_name.clone(),
            s.history().cloned(),
        )
    };

    let mac_q = mac.clone();
    // Returns: (read_ok, ips of this MAC, any del failed).
    let (read_ok, ips, any_err) = tokio::task::spawn_blocking(move || {
        let leases = match active_lease_ips(&leases_path, params) {
            Ok(m) => m,
            Err(e) => {
                error!("disconnect: failed to read leases: {e:#}");
                return (false, Vec::new(), false);
            }
        };
        let ips = leases.get(&mac_q).cloned().unwrap_or_default();
        // Try ALL dels (don't abort on the first error); `del` is idempotent.
        let mut any_err = false;
        for ip in &ips {
            for set in [&acl, &shaper, &no_shape] {
                if let Err(e) = crate::ipset::IPSet::new(set).del(ip) {
                    error!("disconnect: ipset del {set} {ip} failed: {e:#}");
                    any_err = true;
                }
            }
        }
        (true, ips, any_err)
    })
    .await
    .map_err(|err| {
        error!("disconnect task panicked: {err}");
        APIError::InternalError
    })?;

    if !read_ok {
        return Err(APIError::InternalError); // couldn't read leases (distinct from "no lease")
    }
    if ips.is_empty() {
        return Err(APIError::NotFound); // no active lease for this MAC -> nothing to disconnect
    }
    // Audit the attempt regardless of partial failure (the dels that DID succeed
    // already took effect).
    info!("Admin disconnected mac={mac} ips={ips:?} from {admin_ip} (errors={any_err})");
    // The successful dels already took effect, so log the event even on partial failure.
    crate::history::record_event_best_effort(
        history.as_deref(),
        crate::history::kind::DISCONNECT,
        Some(&mac),
        Some(&ips.join(",")),
    );
    if any_err {
        return Err(APIError::InternalError);
    }
    Ok(HttpResponse::NoContent().finish())
}

/// Reset a client's shaper byte counter by removing its active-lease IP(s) from the
/// `shaper` ipset. The counter lives on the ipset entry, so dropping the entry zeroes
/// it (`client_get` then reports `bytes_sent` 0). The client keeps internet access
/// (stays in `acl`) and is re-added to `shaper` with a fresh counter on its next
/// registration. Does NOT change the shaping class — the byte counter is observational
/// in this backend (no byte quota); resetting it only affects the indicator/metrics.
#[post("/api/v1/admin/devices/{mac}/reset-shaper-counter")]
async fn admin_device_reset_shaper_counter(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, APIError> {
    let admin_ip = client_ip(&req).unwrap_or_else(|| "unknown".to_string());
    let mac = normalize_mac(&path.into_inner()).ok_or(APIError::BadRequest)?;
    let (leases_path, params, shaper, history) = {
        let s = state.lock().await;
        let c = s.config();
        (
            c.dhcpd_leases.clone(),
            s.dhcp_params(),
            c.ipset_shaper_name.clone(),
            s.history().cloned(),
        )
    };

    let mac_q = mac.clone();
    // Returns: (read_ok, IPs that were in shaper [del attempted], any del failed).
    let (read_ok, reset_ips, any_err) = tokio::task::spawn_blocking(move || {
        let leases = match active_lease_ips(&leases_path, params) {
            Ok(m) => m,
            Err(e) => {
                error!("reset-shaper: failed to read leases: {e:#}");
                return (false, Vec::new(), false);
            }
        };
        let set = crate::ipset::IPSet::new(&shaper);
        let members: HashSet<String> = match set.entries() {
            Ok(es) => es.into_iter().map(|e| e.ip).collect(),
            Err(e) => {
                error!("reset-shaper: failed to read shaper set {shaper}: {e:#}");
                return (false, Vec::new(), false);
            }
        };
        // Only the MAC's live IPs that are actually in shaper (del is idempotent, but
        // we report exactly what was reset and 404 when nothing matched).
        let reset_ips: Vec<String> = match leases.get(&mac_q) {
            Some(ips) => ips
                .iter()
                .filter(|ip| members.contains(ip.as_str()))
                .cloned()
                .collect(),
            None => Vec::new(),
        };
        let mut any_err = false;
        for ip in &reset_ips {
            if let Err(e) = set.del(ip) {
                error!("reset-shaper: ipset del {shaper} {ip} failed: {e:#}");
                any_err = true;
            }
        }
        (true, reset_ips, any_err)
    })
    .await
    .map_err(|err| {
        error!("reset-shaper task panicked: {err}");
        APIError::InternalError
    })?;

    if !read_ok {
        return Err(APIError::InternalError); // couldn't read leases or the shaper set
    }
    if reset_ips.is_empty() {
        return Err(APIError::NotFound); // no live IP of this MAC is in shaper
    }
    // Audit the attempt regardless of partial failure (the dels that DID succeed
    // already took effect).
    info!(
        "Admin reset shaper counter mac={mac} ips={reset_ips:?} from {admin_ip} (errors={any_err})"
    );
    crate::history::record_event_best_effort(
        history.as_deref(),
        crate::history::kind::SHAPER_RESET,
        Some(&mac),
        Some(&reset_ips.join(",")),
    );
    if any_err {
        return Err(APIError::InternalError);
    }
    Ok(HttpResponse::NoContent().finish())
}

// --- WAN history + event log (require the optional `history` store) ---

/// Default look-back window for the WAN series when `from` is omitted. Independent
/// of `history.retention_days` (just the default view span; older data, if retained
/// longer, is still reachable via an explicit `from`).
const HISTORY_SERIES_DEFAULT_WINDOW_SECS: i64 = 90 * 86_400;
/// Default look-back window and page size for `/admin/events`.
const EVENTS_DEFAULT_WINDOW_SECS: i64 = 30 * 86_400;
const EVENTS_DEFAULT_LIMIT: i64 = 200;

/// Parse an optional `i64` query param (`400` on a non-integer value).
fn parse_opt_i64(query: &HashMap<String, String>, key: &str) -> Result<Option<i64>, APIError> {
    query
        .get(key)
        .map(|v| v.parse::<i64>().map_err(|_| APIError::BadRequest))
        .transpose()
}

/// Resolve the `[from, to]` window for a history query: `to` defaults to `now`,
/// `from` to `to - default_window`. `400` on a non-integer or inverted (`from > to`)
/// range.
fn parse_window(
    query: &HashMap<String, String>,
    now: i64,
    default_window: i64,
) -> Result<(i64, i64), APIError> {
    let to = parse_opt_i64(query, "to")?.unwrap_or(now);
    let from = parse_opt_i64(query, "from")?.unwrap_or(to.saturating_sub(default_window));
    if from > to {
        return Err(APIError::BadRequest);
    }
    Ok((from, to))
}

#[derive(Serialize)]
struct WanSpeedtestResponse {
    from: i64,
    to: i64,
    points: Vec<crate::history::SpeedtestPoint>,
}

#[get("/api/v1/admin/wan/speedtest")]
async fn admin_wan_speedtest(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, APIError> {
    let history = { state.lock().await.history().cloned() };
    let history = history.ok_or(APIError::NotFound)?; // feature off -> 404 (distinct from empty 200)
    let now = chrono::Utc::now().timestamp();
    let (from, to) = parse_window(&query, now, HISTORY_SERIES_DEFAULT_WINDOW_SECS)?;
    let points = tokio::task::spawn_blocking(move || history.speedtest_series(from, to))
        .await
        .map_err(|err| {
            error!("wan speedtest task panicked: {err}");
            APIError::InternalError
        })?
        .map_err(|err| {
            error!("wan speedtest read failed: {err:#}");
            APIError::InternalError
        })?;
    Ok(HttpResponse::Ok().json(WanSpeedtestResponse { from, to, points }))
}

#[derive(Serialize)]
struct WanBalanceResponse {
    from: i64,
    to: i64,
    points: Vec<crate::history::BalancePoint>,
}

#[get("/api/v1/admin/wan/balance")]
async fn admin_wan_balance(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, APIError> {
    let history = { state.lock().await.history().cloned() };
    let history = history.ok_or(APIError::NotFound)?;
    let now = chrono::Utc::now().timestamp();
    let (from, to) = parse_window(&query, now, HISTORY_SERIES_DEFAULT_WINDOW_SECS)?;
    let points = tokio::task::spawn_blocking(move || history.balance_series(from, to))
        .await
        .map_err(|err| {
            error!("wan balance task panicked: {err}");
            APIError::InternalError
        })?
        .map_err(|err| {
            error!("wan balance read failed: {err:#}");
            APIError::InternalError
        })?;
    Ok(HttpResponse::Ok().json(WanBalanceResponse { from, to, points }))
}

#[derive(Serialize)]
struct EventsResponse {
    from: i64,
    to: i64,
    points: Vec<crate::history::EventRow>,
}

#[get("/api/v1/admin/events")]
async fn admin_events(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, APIError> {
    let history = { state.lock().await.history().cloned() };
    let history = history.ok_or(APIError::NotFound)?;
    let now = chrono::Utc::now().timestamp();
    let (from, to) = parse_window(&query, now, EVENTS_DEFAULT_WINDOW_SECS)?;
    let limit = parse_opt_i64(&query, "limit")?.unwrap_or(EVENTS_DEFAULT_LIMIT);
    // Unknown `kind` -> 400 (not a silent empty result).
    let kind = match query.get("kind") {
        Some(k) if crate::history::kind::is_valid(k) => Some(k.clone()),
        Some(_) => return Err(APIError::BadRequest),
        None => None,
    };
    let points =
        tokio::task::spawn_blocking(move || history.list_events(from, to, kind.as_deref(), limit))
            .await
            .map_err(|err| {
                error!("events task panicked: {err}");
                APIError::InternalError
            })?
            .map_err(|err| {
                error!("events read failed: {err:#}");
                APIError::InternalError
            })?;
    Ok(HttpResponse::Ok().json(EventsResponse { from, to, points }))
}

// --- MAC blacklist CRUD (union with config.blacklisted_macs) ---

#[derive(Serialize)]
struct BlacklistEntryView {
    mac: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    created_at: Option<i64>,
    /// "store" (runtime, editable) or "config" (static, read-only).
    source: &'static str,
}

/// Snapshot of the runtime store + static config entries as views.
async fn blacklist_views(state: &Data<Arc<Mutex<State>>>) -> Vec<BlacklistEntryView> {
    let (store, config_macs) = {
        let s = state.lock().await;
        (s.blacklist().clone(), s.config().blacklisted_macs.clone())
    };
    let mut views: Vec<BlacklistEntryView> = store
        .list()
        .await
        .into_iter()
        .map(|e| BlacklistEntryView {
            mac: e.mac,
            comment: e.comment,
            created_at: e.created_at,
            source: "store",
        })
        .collect();
    let store_macs: std::collections::HashSet<String> =
        views.iter().map(|v| v.mac.clone()).collect();
    for m in config_macs {
        let norm = normalize_mac(&m).unwrap_or_else(|| m.to_lowercase());
        if !store_macs.contains(&norm) {
            views.push(BlacklistEntryView {
                mac: norm,
                comment: None,
                created_at: None,
                source: "config",
            });
        }
    }
    views
}

#[get("/api/v1/admin/blacklist")]
async fn blacklist_list(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, APIError> {
    let params = parse_list_params(&query, &["mac", "created_at"], "mac")?;
    // `source` filter: runtime store vs static config entries.
    let source_filter: Option<&str> = match query.get("source").map(String::as_str) {
        None => None,
        Some(s @ ("store" | "config")) => Some(s),
        Some(_) => return Err(APIError::BadRequest),
    };
    let mut items = blacklist_views(&state).await;
    if let Some(src) = source_filter {
        items.retain(|v| v.source == src);
    }
    if let Some(q) = &params.q {
        items.retain(|v| {
            v.mac.to_lowercase().contains(q)
                || v.comment
                    .as_deref()
                    .is_some_and(|s| s.to_lowercase().contains(q))
        });
    }
    items.sort_by(|a, b| {
        let primary = match params.sort.as_str() {
            "created_at" => a.created_at.cmp(&b.created_at),
            _ => a.mac.cmp(&b.mac),
        };
        ordered(primary, params.order).then_with(|| a.mac.cmp(&b.mac))
    });
    let total = items.len();
    let page = paginate(items, &params);
    Ok(json_with_total(&page, total))
}

#[get("/api/v1/admin/blacklist/{mac}")]
async fn blacklist_get(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    path: web::Path<String>,
) -> Result<HttpResponse, APIError> {
    let mac = normalize_mac(&path.into_inner()).ok_or(APIError::BadRequest)?;
    match blacklist_views(&state)
        .await
        .into_iter()
        .find(|v| v.mac == mac)
    {
        Some(v) => Ok(HttpResponse::Ok().json(v)),
        None => Err(APIError::NotFound),
    }
}

#[derive(Deserialize)]
struct CreateBlacklist {
    mac: String,
    #[serde(default)]
    comment: Option<String>,
}

#[post("/api/v1/admin/blacklist")]
async fn blacklist_create(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    req: HttpRequest,
    body: web::Json<CreateBlacklist>,
) -> Result<HttpResponse, APIError> {
    let admin_ip = client_ip(&req).unwrap_or_else(|| "unknown".to_string());
    let mac = normalize_mac(&body.mac).ok_or(APIError::BadRequest)?;
    // Validate the comment here (client error -> 400) so a store.add() failure can
    // be treated unambiguously as a server error (persist I/O -> 500).
    if body
        .comment
        .as_ref()
        .is_some_and(|c| c.len() > crate::blacklist::MAX_COMMENT_LEN)
    {
        return Err(APIError::BadRequest);
    }
    let (store, history) = {
        let s = state.lock().await;
        (s.blacklist().clone(), s.history().cloned())
    };
    let _guard = store.lock_for_mutation().await;
    if store.get(&mac).await.is_some() {
        return Err(APIError::Conflict);
    }
    let created_at = chrono::Utc::now().timestamp();
    let entry = crate::blacklist::BlacklistEntry {
        mac: mac.clone(),
        comment: body.comment.clone(),
        created_at: Some(created_at),
    };
    if let Err(err) = store.add(entry).await {
        error!("blacklist persist failed: {err}");
        return Err(APIError::InternalError);
    }
    info!("Admin blacklisted mac={mac} from {admin_ip}");
    crate::history::record_event_best_effort(
        history.as_deref(),
        crate::history::kind::BLACKLIST_ADD,
        Some(&mac),
        Some(&admin_ip),
    );
    Ok(HttpResponse::Created().json(BlacklistEntryView {
        mac,
        comment: body.comment.clone(),
        created_at: Some(created_at),
        source: "store",
    }))
}

#[delete("/api/v1/admin/blacklist/{mac}")]
async fn blacklist_delete(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, APIError> {
    let admin_ip = client_ip(&req).unwrap_or_else(|| "unknown".to_string());
    let mac = normalize_mac(&path.into_inner()).ok_or(APIError::BadRequest)?;
    let (store, history) = {
        let s = state.lock().await;
        (s.blacklist().clone(), s.history().cloned())
    };
    let _guard = store.lock_for_mutation().await;
    match store.remove(&mac).await {
        Ok(true) => {
            info!("Admin un-blacklisted mac={mac} from {admin_ip}");
            crate::history::record_event_best_effort(
                history.as_deref(),
                crate::history::kind::BLACKLIST_REMOVE,
                Some(&mac),
                Some(&admin_ip),
            );
            Ok(HttpResponse::NoContent().finish())
        }
        // Not in the store: either unknown or a read-only config entry.
        Ok(false) => Err(APIError::NotFound),
        Err(err) => {
            error!("blacklist remove failed: {err}");
            Err(APIError::InternalError)
        }
    }
}

#[get("/api/v1/admin/unlimited-clients")]
async fn unlimited_list(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, APIError> {
    let params = parse_list_params(
        &query,
        &[
            "name",
            "ip",
            "mac",
            "comment",
            "last_seen",
            "bytes_total",
            "created_at",
        ],
        "name",
    )?;
    let stale_filter = parse_bool_param(&query, "stale_reservation")?;
    let online_filter = parse_bool_param(&query, "online")?;

    let (store, leases_path, dhcp_params, metrics) = {
        let s = state.lock().await;
        (
            s.unlimited_clients().clone(),
            s.config().dhcpd_leases.clone(),
            s.dhcp_params(),
            s.device_metrics().cloned(),
        )
    };
    let mut items = store.list().await;

    // q-filter on the raw client (name/ip/mac/comment are available pre-enrichment).
    if let Some(q) = &params.q {
        items.retain(|c| {
            c.name.to_lowercase().contains(q)
                || c.ip.to_lowercase().contains(q)
                || c.mac.to_lowercase().contains(q)
                || c.comment
                    .as_deref()
                    .is_some_and(|s| s.to_lowercase().contains(q))
        });
    }

    // Enrich the whole (q-filtered) list — the set is small (~tens) — so the
    // metrics/lease-derived fields are available for filtering and sorting.
    let now = chrono::Utc::now().timestamp();
    let mut views = enrich_unlimited(items, leases_path, dhcp_params, metrics, now).await;

    if let Some(want) = stale_filter {
        views.retain(|v| v.stale_reservation == want);
    }
    if let Some(want) = online_filter {
        views.retain(|v| v.online == want);
    }

    views.sort_by(|a, b| {
        let primary = match params.sort.as_str() {
            "ip" => cmp_ip(&a.ip, &b.ip),
            "mac" => a.mac.cmp(&b.mac),
            "comment" => opt_str_cmp(&a.comment, &b.comment),
            "last_seen" => a.last_seen.cmp(&b.last_seen),
            "bytes_total" => a.bytes_total.cmp(&b.bytes_total),
            "created_at" => a.created_at.cmp(&b.created_at),
            _ => a.name.cmp(&b.name),
        };
        // Stable: secondary by name (ascending) regardless of order.
        ordered(primary, params.order).then_with(|| a.name.cmp(&b.name))
    });

    let total = views.len();
    let page = paginate(views, &params);
    Ok(json_with_total(&page, total))
}

#[get("/api/v1/admin/unlimited-clients/{name}")]
async fn unlimited_get(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    path: web::Path<String>,
) -> Result<HttpResponse, APIError> {
    let (store, leases_path, dhcp_params, metrics) = {
        let s = state.lock().await;
        (
            s.unlimited_clients().clone(),
            s.config().dhcpd_leases.clone(),
            s.dhcp_params(),
            s.device_metrics().cloned(),
        )
    };
    match store.get(&path.into_inner()).await {
        Some(client) => {
            let now = chrono::Utc::now().timestamp();
            let mut views =
                enrich_unlimited(vec![client], leases_path, dhcp_params, metrics, now).await;
            Ok(HttpResponse::Ok().json(views.remove(0)))
        }
        None => Err(APIError::NotFound),
    }
}

#[post("/api/v1/admin/unlimited-clients")]
async fn unlimited_create(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    req: HttpRequest,
    body: web::Json<CreateUnlimitedClient>,
) -> Result<HttpResponse, APIError> {
    let admin_ip = client_ip(&req).unwrap_or_else(|| "unknown".to_string());
    let ctx = { unlimited_ctx(&*state.lock().await) };

    let dr = match &ctx.dhcp_reservations {
        Some(d) => d.clone(),
        None => {
            error!("unlimited-clients CRUD requires the `dhcp_reservations` config section");
            return Err(APIError::InternalError);
        }
    };

    // Serialize the whole transaction against concurrent CRUD requests.
    let _guard = ctx.store.lock_for_mutation().await;

    if !is_valid_name(&body.name) {
        warn!("Rejected unlimited client: invalid name {:?}", body.name);
        return Err(APIError::BadRequest);
    }

    // Derive the MAC from a current, active lease for the requested IP.
    let lease = match crate::dhcp::Dhcp::of_ip(&ctx.leases, ctx.params, &body.ip) {
        Ok(l) => l,
        Err(err) => {
            warn!(
                "DHCP lease lookup for {:?} failed (from {admin_ip}): {err}",
                body.ip
            );
            return Err(APIError::BadRequest);
        }
    };
    if lease.binding_state != crate::dhcp::BindingState::Active {
        warn!("Lease for {:?} is not active", body.ip);
        return Err(APIError::BadRequest);
    }
    let mac = match lease.mac.and_then(|m| normalize_mac(&m)) {
        Some(m) => m,
        None => {
            warn!("Lease for {:?} has no usable MAC", body.ip);
            return Err(APIError::BadRequest);
        }
    };

    let client = UnlimitedClient {
        name: body.name.clone(),
        mac,
        ip: body.ip.clone(),
        comment: body.comment.clone(),
        ..Default::default()
    };
    if let Err(err) = client.validate(ctx.subnet) {
        warn!("Rejected unlimited client: {err}");
        return Err(APIError::BadRequest);
    }

    if ctx.store.contains_name(&client.name).await || ctx.store.contains_ip(&client.ip).await {
        return Err(APIError::Conflict);
    }

    let no_shape = crate::ipset::IPSet::new(&ctx.no_shape_name);
    let acl = crate::ipset::IPSet::new(&ctx.acl_name);

    // Transaction: dhcp reservation (gated by `dnsmasq --test`) -> ipset -> store.
    // Compensate in reverse on failure; store is written last so it never records
    // a client whose side effects didn't land.
    let mut desired = ctx.store.list().await;
    desired.push(client.clone());
    match crate::dhcp_hosts::apply(&dr, &crate::dhcp_hosts::render(&desired)).await {
        // Daemon deliberately down: the reservation is left pending
        // for the next reconcile. ipset + store still proceed (store is the source of
        // truth); surface it so the deferral isn't silent.
        Ok(crate::dhcp_hosts::Applied::SkippedInactive) => warn!(
            "unlimited create {}: DHCP reload skipped (daemon inactive) — reservation \
             pending until reconcile",
            client.ip
        ),
        Ok(_) => {}
        Err(err) => {
            error!("dhcp reservation apply failed: {err}");
            return Err(APIError::InternalError);
        }
    }
    if let Err(err) = no_shape.add(&client.ip, Some(0)) {
        error!("ipset add no_shape failed: {err}");
        revert_reservations(&dr, &ctx.store).await;
        return Err(APIError::InternalError);
    }
    if let Err(err) = acl.add(&client.ip, Some(0)) {
        error!("ipset add acl failed: {err}");
        rollback_ipset(&no_shape, &client.ip);
        revert_reservations(&dr, &ctx.store).await;
        return Err(APIError::InternalError);
    }
    if let Err(err) = ctx.store.add(client.clone()).await {
        error!("unlimited store add failed: {err}");
        rollback_ipset(&acl, &client.ip);
        rollback_ipset(&no_shape, &client.ip);
        revert_reservations(&dr, &ctx.store).await;
        return Err(APIError::InternalError);
    }

    info!(
        "Admin created unlimited client {} ip={} mac={} from {admin_ip}",
        client.name, client.ip, client.mac
    );
    // Return the enriched, timestamp-stamped record (same shape as the listing).
    let now = chrono::Utc::now().timestamp();
    let stored = ctx
        .store
        .get(&client.name)
        .await
        .unwrap_or_else(|| client.clone());
    let metrics = { state.lock().await.device_metrics().cloned() };
    let view = enrich_unlimited(vec![stored], ctx.leases.clone(), ctx.params, metrics, now)
        .await
        .remove(0);
    Ok(HttpResponse::Created().json(view))
}

#[delete("/api/v1/admin/unlimited-clients/{name}")]
async fn unlimited_delete(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> Result<HttpResponse, APIError> {
    let admin_ip = client_ip(&req).unwrap_or_else(|| "unknown".to_string());
    let name = path.into_inner();
    let ctx = { unlimited_ctx(&*state.lock().await) };

    let _guard = ctx.store.lock_for_mutation().await;

    let client = match ctx.store.get(&name).await {
        Some(c) => c,
        None => return Err(APIError::NotFound),
    };

    // Side effects first (idempotent). If any fails, keep the store entry so the
    // client stays consistently unlimited; admin retries.
    // Regenerate the dnsmasq hostsfile without this client (gated by `dnsmasq --test`).
    if let Some(dr) = &ctx.dhcp_reservations {
        let remaining: Vec<_> = ctx
            .store
            .list()
            .await
            .into_iter()
            .filter(|c| c.name != client.name)
            .collect();
        match crate::dhcp_hosts::apply(dr, &crate::dhcp_hosts::render(&remaining)).await {
            Ok(crate::dhcp_hosts::Applied::SkippedInactive) => warn!(
                "unlimited delete {}: DHCP reload skipped (daemon inactive) — removal \
                 pending until reconcile",
                client.name
            ),
            Ok(_) => {}
            Err(err) => {
                error!("dhcp reservation apply (delete) failed: {err}");
                return Err(APIError::InternalError);
            }
        }
    }
    let no_shape = crate::ipset::IPSet::new(&ctx.no_shape_name);
    let acl = crate::ipset::IPSet::new(&ctx.acl_name);
    if let Err(err) = no_shape.del(&client.ip) {
        error!("ipset del no_shape failed: {err}");
        return Err(APIError::InternalError);
    }
    if let Err(err) = acl.del(&client.ip) {
        error!("ipset del acl failed: {err}");
        return Err(APIError::InternalError);
    }

    if let Err(err) = ctx.store.remove(&name).await {
        error!("unlimited store remove failed: {err}");
        return Err(APIError::InternalError);
    }

    info!(
        "Admin deleted unlimited client {} ip={} from {admin_ip}",
        client.name, client.ip
    );
    Ok(HttpResponse::NoContent().finish())
}

#[derive(Deserialize)]
struct PatchUnlimitedClient {
    /// New comment (or `null` to clear). Only the comment can be edited; to
    /// change ip/name, delete and recreate.
    #[serde(default)]
    comment: Option<String>,
}

#[patch("/api/v1/admin/unlimited-clients/{name}")]
async fn unlimited_patch(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    req: HttpRequest,
    path: web::Path<String>,
    body: web::Json<PatchUnlimitedClient>,
) -> Result<HttpResponse, APIError> {
    let admin_ip = client_ip(&req).unwrap_or_else(|| "unknown".to_string());
    let name = path.into_inner();
    let store = { state.lock().await.unlimited_clients().clone() };

    let _guard = store.lock_for_mutation().await;
    match store.set_comment(&name, body.comment.clone()).await {
        Ok(true) => {
            info!("Admin updated comment of unlimited client {name} from {admin_ip}");
            match store.get(&name).await {
                Some(client) => Ok(HttpResponse::Ok().json(client)),
                None => Err(APIError::NotFound),
            }
        }
        Ok(false) => Err(APIError::NotFound),
        Err(err) => {
            warn!("Rejected comment update for {name} (from {admin_ip}): {err}");
            Err(APIError::BadRequest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_status_serializes_to_documented_shape() {
        let full = AdminStatus {
            internet_available: true,
            speedtest: Some(crate::speedtest::SpeedTest {
                download: 1.0,
                upload: 2.0,
                ping: 3.0,
            }),
            isp_balance: Some(42.0),
            last_tariff_update_secs: Some(-10),
            clients_in_acl: 5,
            clients_in_shaper: 3,
            dhcp_leases: LeaseCounts {
                free: 1,
                active: 2,
                abandoned: 0,
            },
            metrics: None,
            blacklisted_count: 4,
            stale_reservations: 2,
        };
        let v = serde_json::to_value(&full).unwrap();
        assert_eq!(v["internet_available"], true);
        assert_eq!(v["speedtest"]["download"], 1.0);
        assert_eq!(v["clients_in_acl"], 5);
        assert_eq!(v["dhcp_leases"]["active"], 2);

        // Optional fields serialize as null when absent.
        let empty = AdminStatus {
            internet_available: false,
            speedtest: None,
            isp_balance: None,
            last_tariff_update_secs: None,
            clients_in_acl: 0,
            clients_in_shaper: 0,
            dhcp_leases: LeaseCounts {
                free: 0,
                active: 0,
                abandoned: 0,
            },
            metrics: None,
            blacklisted_count: 0,
            stale_reservations: 0,
        };
        let v = serde_json::to_value(&empty).unwrap();
        assert!(v["speedtest"].is_null());
        assert!(v["isp_balance"].is_null());
    }

    fn qmap(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn ipset_membership_flags_for_joins_by_ip() {
        let m = IpsetMembership {
            acl: ["10.0.0.1".to_string()].into_iter().collect(),
            shaper: ["10.0.0.1".to_string()].into_iter().collect(),
            no_shape: HashSet::new(),
        };
        let f = |ips: &[&str]| {
            let owned: Vec<String> = ips.iter().map(|s| s.to_string()).collect();
            let g = m.flags_for(&owned);
            (g.has_acl, g.has_shaper, g.has_no_shape)
        };
        // A set holds if ANY current IP is a member.
        assert_eq!(f(&["10.0.0.1"]), (true, true, false));
        assert_eq!(f(&["10.0.0.9"]), (false, false, false));
        assert_eq!(f(&["10.0.0.9", "10.0.0.1"]), (true, true, false));
        assert_eq!(f(&[]), (false, false, false));
    }

    #[tokio::test]
    async fn build_blacklisted_set_unions_store_and_normalized_config() {
        let dir = std::env::temp_dir().join(format!("bl-set-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bl.yaml");
        let _ = std::fs::remove_file(&path);
        let store = crate::blacklist::BlacklistStore::load(&path).unwrap();
        store
            .add(crate::blacklist::BlacklistEntry {
                mac: "aa:bb:cc:dd:ee:01".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        // Config MAC in a non-canonical (upper) form must be normalized into the set.
        let set = build_blacklisted_set(&store, &["AA:BB:CC:DD:EE:02".to_string()]).await;
        assert!(set.contains("aa:bb:cc:dd:ee:01")); // from store
        assert!(set.contains("aa:bb:cc:dd:ee:02")); // from config, normalized
        assert_eq!(set.len(), 2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn parse_bool_param_accepts_bool_forms_and_rejects_junk() {
        for v in ["true", "1"] {
            assert_eq!(
                parse_bool_param(&qmap(&[("f", v)]), "f").unwrap(),
                Some(true)
            );
        }
        for v in ["false", "0"] {
            assert_eq!(
                parse_bool_param(&qmap(&[("f", v)]), "f").unwrap(),
                Some(false)
            );
        }
        // Absent -> None (no filter).
        assert_eq!(parse_bool_param(&HashMap::new(), "f").unwrap(), None);
        // Anything else -> 400.
        for v in ["yes", "TRUE", "2", ""] {
            assert!(parse_bool_param(&qmap(&[("f", v)]), "f").is_err());
        }
    }

    #[test]
    fn parse_list_params_defaults_validation_and_lowercasing() {
        let wl = &["name", "ip"];

        // No params -> "return everything" mode + defaults.
        let p = parse_list_params(&HashMap::new(), wl, "name").unwrap();
        assert!(p.page.is_none() && p.per_page.is_none());
        assert_eq!(p.sort, "name");
        assert!(matches!(p.order, SortOrder::Asc));
        assert!(p.q.is_none());

        let p = parse_list_params(
            &qmap(&[
                ("page", "2"),
                ("per_page", "10"),
                ("sort", "ip"),
                ("order", "desc"),
                ("q", "Foo"),
            ]),
            wl,
            "name",
        )
        .unwrap();
        assert_eq!(p.page, Some(2));
        assert_eq!(p.per_page, Some(10));
        assert_eq!(p.sort, "ip");
        assert!(matches!(p.order, SortOrder::Desc));
        assert_eq!(p.q.as_deref(), Some("foo")); // lowercased

        let bad = |k: &str, v: &str| parse_list_params(&qmap(&[(k, v)]), wl, "name").is_err();
        assert!(bad("page", "0"));
        assert!(bad("page", "x"));
        assert!(bad("per_page", "0"));
        assert!(bad("per_page", "201"));
        assert!(bad("sort", "secret_field"));
        assert!(bad("order", "up"));
    }

    #[test]
    fn paginate_window_and_return_all() {
        let all: Vec<usize> = (1..=10).collect();
        let mk = |page, per_page| ListParams {
            page,
            per_page,
            sort: "x".into(),
            order: SortOrder::Asc,
            q: None,
        };
        // Both absent -> everything.
        assert_eq!(paginate(all.clone(), &mk(None, None)).len(), 10);
        // page 2 of size 3.
        assert_eq!(paginate(all.clone(), &mk(Some(2), Some(3))), vec![4, 5, 6]);
        // Beyond data -> empty (not an error).
        assert!(paginate(all.clone(), &mk(Some(99), Some(3))).is_empty());
        // Only per_page -> page defaults to 1.
        assert_eq!(paginate(all, &mk(None, Some(4))), vec![1, 2, 3, 4]);
    }

    #[test]
    fn cmp_ip_is_numeric_not_lexical() {
        assert_eq!(cmp_ip("10.11.5.9", "10.11.5.30"), Ordering::Less);
        assert_eq!(cmp_ip("10.11.5.221", "10.11.5.30"), Ordering::Greater);
        // non-IP falls back to string compare
        assert_eq!(cmp_ip("abc", "abd"), Ordering::Less);
    }

    // --- Device enrichment ---

    fn client(mac: &str, ip: &str) -> UnlimitedClient {
        UnlimitedClient {
            name: "alice".into(),
            mac: mac.into(),
            ip: ip.into(),
            ..Default::default()
        }
    }

    fn lease(mac: Option<&str>, active: bool, hostname: Option<&str>) -> LeaseInfo {
        LeaseInfo {
            mac: mac.map(|s| s.to_string()),
            active,
            hostname: hostname.map(|s| s.to_string()),
            vendor: None,
        }
    }

    #[test]
    fn build_unlimited_view_no_lease_is_offline() {
        let leases = HashMap::new();
        let metrics = HashMap::new();
        let view = build_unlimited_view(client("aa:bb:cc:dd:ee:ff", "10.0.0.1"), &leases, &metrics);
        assert!(!view.online);
        assert!(!view.stale_reservation);
    }

    #[test]
    fn build_unlimited_view_online_comes_from_metrics_not_lease() {
        let mac = "aa:bb:cc:dd:ee:ff";
        // Active lease for the same MAC, but no recent traffic in metrics -> offline:
        // holding a lease must NOT imply online.
        let mut leases = HashMap::new();
        leases.insert("10.0.0.1".to_string(), lease(Some(mac), true, None));
        let empty = HashMap::new();
        let view = build_unlimited_view(client(mac, "10.0.0.1"), &leases, &empty);
        assert!(!view.online, "lease alone must not imply online");
        assert!(!view.stale_reservation);

        // Recent traffic in metrics -> online (lease same MAC -> not stale).
        let mut metrics = HashMap::new();
        metrics.insert(
            mac.to_string(),
            crate::device_metrics::DeviceMetrics {
                online: true,
                ..Default::default()
            },
        );
        let view = build_unlimited_view(client(mac, "10.0.0.1"), &leases, &metrics);
        assert!(view.online);
        assert!(!view.stale_reservation);
    }

    #[test]
    fn build_unlimited_view_active_lease_other_mac_is_stale() {
        let mut leases = HashMap::new();
        leases.insert(
            "10.0.0.1".to_string(),
            lease(Some("11:11:11:11:11:11"), true, None),
        );
        let metrics = HashMap::new();
        let view = build_unlimited_view(client("aa:bb:cc:dd:ee:ff", "10.0.0.1"), &leases, &metrics);
        // IP held by another MAC: the reserved device is NOT online, and the
        // reservation is stale (online/stale are mutually exclusive).
        assert!(!view.online);
        assert!(view.stale_reservation);
    }

    #[test]
    fn build_unlimited_view_lease_hostname_wins_over_metrics() {
        let mac = "aa:bb:cc:dd:ee:ff";
        let mut leases = HashMap::new();
        leases.insert(
            "10.0.0.1".to_string(),
            lease(Some(mac), true, Some("from-lease")),
        );
        let mut metrics = HashMap::new();
        metrics.insert(
            mac.to_string(),
            crate::device_metrics::DeviceMetrics {
                hostname: Some("from-metrics".into()),
                first_seen: Some(123),
                ..Default::default()
            },
        );
        let view = build_unlimited_view(client(mac, "10.0.0.1"), &leases, &metrics);
        assert_eq!(view.hostname.as_deref(), Some("from-lease"));
        // Metrics still flow through for fields the lease doesn't carry.
        assert_eq!(view.first_seen, Some(123));
    }

    #[test]
    fn device_view_flatten_keeps_fields_at_top_level() {
        let view = DeviceView {
            device: crate::device_metrics::DeviceRow {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                last_ip: Some("10.0.0.1".into()),
                ips: vec!["10.0.0.1".into()],
                hostname: Some("host".into()),
                vendor: None,
                first_seen: Some(100),
                last_seen: Some(200),
                bytes_total: 10,
                packets_total: 2,
                bytes_today: 5,
                bytes_7d: 7,
                bytes_30d: 9,
                rate_bps: Some(11),
                online: true,
            },
            is_unlimited: false,
            has_acl: true,
            has_shaper: false,
            has_no_shape: true,
            is_blacklisted: false,
        };
        let v = serde_json::to_value(&view).unwrap();
        // Flatten must not nest the row under a "device" key.
        assert!(v.get("device").is_none());
        assert_eq!(v["has_acl"], true);
        assert_eq!(v["is_blacklisted"], false);
        assert_eq!(v["mac"], "aa:bb:cc:dd:ee:ff");
        assert_eq!(v["online"], true);
        assert_eq!(v["is_unlimited"], false);
        assert_eq!(v["first_seen"], 100);
    }

    #[test]
    fn unlimited_client_view_serializes_new_fields() {
        let mut metrics = HashMap::new();
        metrics.insert(
            "aa:bb:cc:dd:ee:ff".to_string(),
            crate::device_metrics::DeviceMetrics {
                first_seen: Some(1),
                last_seen: Some(2),
                bytes_total: Some(3),
                bytes_today: Some(4),
                bytes_7d: Some(5),
                hostname: Some("h".into()),
                vendor: Some("v".into()),
                ..Default::default()
            },
        );
        let leases = HashMap::new();
        let view = build_unlimited_view(client("aa:bb:cc:dd:ee:ff", "10.0.0.1"), &leases, &metrics);
        let v = serde_json::to_value(&view).unwrap();
        for key in [
            "online",
            "stale_reservation",
            "hostname",
            "vendor",
            "first_seen",
            "last_seen",
            "bytes_total",
            "bytes_today",
            "bytes_7d",
        ] {
            assert!(v.get(key).is_some(), "missing field {key}");
        }
        assert_eq!(v["bytes_7d"], 5);
        assert_eq!(v["vendor"], "v");
    }

    #[test]
    fn traffic_series_response_serializes_to_documented_shape() {
        let resp = TrafficSeriesResponse {
            granularity: Granularity::Hour.as_str(),
            from: 1_751_000_000,
            to: 1_751_600_000,
            points: vec![crate::device_metrics::TrafficPoint {
                ts: 1_751_596_800,
                bytes: 104_857_600,
                packets: 90_000,
            }],
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["granularity"], "hour");
        assert_eq!(v["from"], 1_751_000_000_i64);
        assert_eq!(v["to"], 1_751_600_000_i64);
        assert_eq!(v["points"][0]["ts"], 1_751_596_800_i64);
        assert_eq!(v["points"][0]["bytes"], 104_857_600_i64);
        assert_eq!(v["points"][0]["packets"], 90_000);
    }
}
