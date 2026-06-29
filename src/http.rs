use std::cmp::Ordering;
use std::collections::HashMap;
use std::{future::Future, sync::Arc};

use actix_web::{
    cookie::{Cookie, SameSite},
    delete, get, patch, post,
    web::{self, Data},
    HttpRequest, HttpResponse,
};
use dhcpd_parser::leases::BindingState;
use dhcpd_parser::parser::LeasesMethods;
use serde::{Deserialize, Serialize};
use slog_scope::{error, info, warn};
use tokio::sync::Mutex;

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
        match crate::dhcp::Dhcp::of_ip(&state.config().dhcpd_leases, &client_ip) {
            Ok(v) => v,
            Err(err) => {
                error!("{}", err);
                return Err(APIError::InternalError);
            }
        }
    };

    let client_mac = match dhcp_lease.hardware {
        Some(v) => v.mac.to_lowercase(),
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
                if state
                    .config()
                    .blacklisted_macs
                    .iter()
                    .map(|v| v.to_lowercase())
                    .any(|v| v == client_mac)
                {
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
                    if state
                        .config()
                        .blacklisted_macs
                        .iter()
                        .map(|v| v.to_lowercase())
                        .any(|v| v == mac)
                    {
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
    /// Client-last-transaction time — when the device last talked to dhcpd
    /// ("last seen on the network"). The ipset `acl`/`shaper` entries also carry
    /// `bytes`/`packets` counters.
    pub last_seen: Option<String>,
    /// Last time dhcpd recorded a transaction for this lease.
    pub tstp: Option<String>,
    pub acl: Option<crate::ipset::Entry>,
    pub shaper: Option<crate::ipset::Entry>,
}

#[get("/api/v1/dhcp")]
async fn dhcp_leases(
    state: Data<Arc<Mutex<State>>>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, APIError> {
    info!("Client requested DHCP leases");

    let params = parse_list_params(&query, &["ip", "mac", "hostname", "ends"], "ip")?;
    let ip_prefix = query.get("ip_prefix").cloned();
    let has_mac = match query.get("has_mac").map(String::as_str) {
        None => None,
        Some("true") | Some("1") => Some(true),
        Some("false") | Some("0") => Some(false),
        Some(_) => return Err(APIError::BadRequest),
    };

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

    let mut items: Vec<DhcpRecord> = crate::dhcp::Dhcp::read(&state.config().dhcpd_leases)
        .map_err(|err| {
            error!("failed to read DHCP leases: {err}");
            APIError::InternalError
        })?
        .all()
        .into_iter()
        .map(|lease| DhcpRecord {
            mac: lease.hardware.map(|v| v.mac),
            hostname: lease.hostname,
            client_hostname: lease.client_hostname,
            vendor_class_identifier: lease.vendor_class_identifier,
            starts: lease.dates.starts.map(|v| v.to_string()),
            ends: lease.dates.ends.map(|v| v.to_string()),
            last_seen: lease.dates.cltt.map(|v| v.to_string()),
            tstp: lease.dates.tstp.map(|v| v.to_string()),
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

    let leases = crate::dhcp::Dhcp::read(&cfg.dhcpd_leases)
        .map_err(|err| {
            error!("failed to read DHCP leases: {err}");
            APIError::InternalError
        })?
        .all();
    let count = |s: dhcpd_parser::leases::BindingState| {
        leases.iter().filter(|v| v.binding_state == s).count()
    };
    let lease_counts = LeaseCounts {
        free: count(dhcpd_parser::leases::BindingState::Free),
        active: count(dhcpd_parser::leases::BindingState::Active),
        abandoned: count(dhcpd_parser::leases::BindingState::Abandoned),
    };

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
        no_shape_name: c.ipset_no_shape_name.clone(),
        acl_name: c.ipset_acl_name.clone(),
    }
}

/// Re-render the dhcpd include from the current store and re-apply it, undoing a
/// reservation written earlier in a transaction that then failed. Best-effort;
/// startup reconcile heals any residue.
async fn revert_reservations(
    dr: &crate::config::DhcpReservations,
    store: &crate::unlimited_clients::UnlimitedClientsStore,
) {
    let clients = store.list().await;
    if let Err(err) = crate::dhcp_hosts::apply(dr, &crate::dhcp_hosts::render(&clients)).await {
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
fn read_leases_map(path: &std::path::Path) -> HashMap<String, LeaseInfo> {
    let dhcp = match crate::dhcp::Dhcp::read(path) {
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
                    mac: l.hardware.as_ref().and_then(|h| normalize_mac(&h.mac)),
                    active: l.binding_state == BindingState::Active,
                    hostname: l.hostname.clone(),
                    vendor: l.vendor_class_identifier.clone(),
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
    bytes_today: Option<i64>,
    bytes_7d: Option<i64>,
}

fn build_unlimited_view(
    c: UnlimitedClient,
    leases: &HashMap<String, LeaseInfo>,
    metrics: &HashMap<String, crate::device_metrics::DeviceMetrics>,
) -> UnlimitedClientView {
    let lease = leases.get(&c.ip);
    let online = lease.map(|l| l.active).unwrap_or(false);
    let stale_reservation = lease
        .map(|l| l.active && l.mac.as_deref() != Some(c.mac.as_str()))
        .unwrap_or(false);
    let m = metrics.get(&c.mac).cloned().unwrap_or_default();
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
        bytes_today: m.bytes_today,
        bytes_7d: m.bytes_7d,
    }
}

/// Enrich clients with lease + metrics data. Heavy reads run in `spawn_blocking`;
/// failures degrade to empty maps (null metrics, offline).
async fn enrich_unlimited(
    clients: Vec<UnlimitedClient>,
    leases_path: std::path::PathBuf,
    metrics: Option<Arc<crate::device_metrics::DeviceMetricsStore>>,
    now: i64,
) -> Vec<UnlimitedClientView> {
    let macs: Vec<String> = clients.iter().map(|c| c.mac.clone()).collect();
    let (leases_map, metrics_map) = tokio::task::spawn_blocking(move || {
        let leases_map = read_leases_map(&leases_path);
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

/// A device-inventory row plus live flags.
#[derive(Serialize)]
struct DeviceView {
    #[serde(flatten)]
    device: crate::device_metrics::DeviceRow,
    online: bool,
    is_unlimited: bool,
}

#[get("/api/v1/admin/devices")]
async fn admin_devices(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, APIError> {
    let params = parse_list_params(
        &query,
        &["last_seen", "first_seen", "bytes_total", "mac", "last_ip"],
        "last_seen",
    )?;

    let (metrics, leases_path, store) = {
        let s = state.lock().await;
        (
            s.device_metrics().cloned(),
            s.config().dhcpd_leases.clone(),
            s.unlimited_clients().clone(),
        )
    };
    // Metrics disabled -> empty inventory (not an error).
    let metrics = match metrics {
        Some(m) => m,
        None => return Ok(json_with_total(&Vec::<DeviceView>::new(), 0)),
    };
    let unlimited_macs: std::collections::HashSet<String> =
        store.list().await.into_iter().map(|c| c.mac).collect();

    let now = chrono::Utc::now().timestamp();
    let (rows, leases_map) = tokio::task::spawn_blocking(move || {
        let rows = metrics.all_devices(now).unwrap_or_else(|e| {
            error!("device-metrics all_devices failed: {e:#}");
            Vec::new()
        });
        let leases = read_leases_map(&leases_path);
        (rows, leases)
    })
    .await
    .unwrap_or_default();

    let mut views: Vec<DeviceView> = rows
        .into_iter()
        .map(|d| {
            let online = d
                .last_ip
                .as_ref()
                .and_then(|ip| leases_map.get(ip))
                .map(|l| l.active)
                .unwrap_or(false);
            let is_unlimited = unlimited_macs.contains(&d.mac);
            DeviceView {
                device: d,
                online,
                is_unlimited,
            }
        })
        .collect();

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

#[get("/api/v1/admin/unlimited-clients")]
async fn unlimited_list(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, APIError> {
    let params = parse_list_params(&query, &["name", "ip", "mac", "comment"], "name")?;

    let (store, leases_path, metrics) = {
        let s = state.lock().await;
        (
            s.unlimited_clients().clone(),
            s.config().dhcpd_leases.clone(),
            s.device_metrics().cloned(),
        )
    };
    let mut items = store.list().await;

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

    items.sort_by(|a, b| {
        let primary = match params.sort.as_str() {
            "ip" => cmp_ip(&a.ip, &b.ip),
            "mac" => a.mac.cmp(&b.mac),
            "comment" => opt_str_cmp(&a.comment, &b.comment),
            _ => a.name.cmp(&b.name),
        };
        // Stable: secondary by name (ascending) regardless of order.
        ordered(primary, params.order).then_with(|| a.name.cmp(&b.name))
    });

    let total = items.len();
    let page = paginate(items, &params);
    // Enrich only the page (metrics + lease join) to keep lookups bounded.
    let now = chrono::Utc::now().timestamp();
    let views = enrich_unlimited(page, leases_path, metrics, now).await;
    Ok(json_with_total(&views, total))
}

#[get("/api/v1/admin/unlimited-clients/{name}")]
async fn unlimited_get(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    path: web::Path<String>,
) -> Result<HttpResponse, APIError> {
    let (store, leases_path, metrics) = {
        let s = state.lock().await;
        (
            s.unlimited_clients().clone(),
            s.config().dhcpd_leases.clone(),
            s.device_metrics().cloned(),
        )
    };
    match store.get(&path.into_inner()).await {
        Some(client) => {
            let now = chrono::Utc::now().timestamp();
            let mut views = enrich_unlimited(vec![client], leases_path, metrics, now).await;
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
    let lease = match crate::dhcp::Dhcp::of_ip(&ctx.leases, &body.ip) {
        Ok(l) => l,
        Err(err) => {
            warn!(
                "DHCP lease lookup for {:?} failed (from {admin_ip}): {err}",
                body.ip
            );
            return Err(APIError::BadRequest);
        }
    };
    if lease.binding_state != BindingState::Active {
        warn!("Lease for {:?} is not active", body.ip);
        return Err(APIError::BadRequest);
    }
    let mac = match lease.hardware.and_then(|h| normalize_mac(&h.mac)) {
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

    // Transaction: dhcp reservation (gated by `dhcpd -t`) -> ipset -> store.
    // Compensate in reverse on failure; store is written last so it never records
    // a client whose side effects didn't land.
    let mut desired = ctx.store.list().await;
    desired.push(client.clone());
    if let Err(err) = crate::dhcp_hosts::apply(&dr, &crate::dhcp_hosts::render(&desired)).await {
        error!("dhcp reservation apply failed: {err}");
        return Err(APIError::InternalError);
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
    let view = enrich_unlimited(vec![stored], ctx.leases.clone(), metrics, now)
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
    // Regenerate the dhcpd include without this client (gated by `dhcpd -t`).
    if let Some(dr) = &ctx.dhcp_reservations {
        let remaining: Vec<_> = ctx
            .store
            .list()
            .await
            .into_iter()
            .filter(|c| c.name != client.name)
            .collect();
        if let Err(err) = crate::dhcp_hosts::apply(dr, &crate::dhcp_hosts::render(&remaining)).await
        {
            error!("dhcp reservation apply (delete) failed: {err}");
            return Err(APIError::InternalError);
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
    fn build_unlimited_view_active_lease_same_mac_is_online_not_stale() {
        let mac = "aa:bb:cc:dd:ee:ff";
        let mut leases = HashMap::new();
        leases.insert("10.0.0.1".to_string(), lease(Some(mac), true, None));
        let metrics = HashMap::new();
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
        assert!(view.online);
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
                bytes_today: 5,
                bytes_7d: 7,
            },
            online: true,
            is_unlimited: false,
        };
        let v = serde_json::to_value(&view).unwrap();
        // Flatten must not nest the row under a "device" key.
        assert!(v.get("device").is_none());
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
}
