use std::{future::Future, sync::Arc};

use actix_web::{
    cookie::{Cookie, SameSite},
    delete, get, post,
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
        .and_then(|v| v.to_str().ok().map(|v| v.to_string()))
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
        // The runtime store is the source of truth; `no_shaping_ips` from the
        // static config is kept as a transitional fallback until migration.
        state.config().no_shaping_ips.contains(&client_ip)
            || state.unlimited_clients().contains_ip(&client_ip).await
    };
    if is_no_shape {
        info!("Client is in no_shape list");
        slog_scope::logger().new(slog::slog_o!("client_ip" => client_ip.clone()));
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
    pub acl: Option<crate::ipset::Entry>,
    pub shaper: Option<crate::ipset::Entry>,
}

#[get("/api/v1/dhcp")]
async fn dhcp_leases(state: Data<Arc<Mutex<State>>>) -> Result<String, APIError> {
    info!("Client requested DHCP leases");
    let state = state.lock().await;

    let ipset_acl = crate::ipset::IPSet::new(&state.config().ipset_acl_name);
    let ipset_shaper = crate::ipset::IPSet::new(&state.config().ipset_acl_name);

    let mut leases = Vec::new();
    for lease in crate::dhcp::Dhcp::read(&state.config().dhcpd_leases)
        .map_err(|_| APIError::InternalError)?
        .all()
    {
        let record = DhcpRecord {
            mac: lease.hardware.map(|v| v.mac),
            hostname: lease.hostname,
            client_hostname: lease.client_hostname,
            vendor_class_identifier: lease.vendor_class_identifier,
            starts: lease.dates.starts.map(|v| v.to_string()),
            ends: lease.dates.ends.map(|v| v.to_string()),
            acl: ipset_acl
                .entries()
                .map_err(|_| APIError::InternalError)?
                .into_iter()
                .find(|acl| acl.ip == lease.ip),
            shaper: ipset_shaper
                .entries()
                .map_err(|_| APIError::InternalError)?
                .into_iter()
                .find(|acl| acl.ip == lease.ip),
            ip: lease.ip,
        };

        leases.push(record)
    }

    Ok(serde_json::ser::to_string(&leases).unwrap())
}

#[get("/metrics")]
async fn prometheus_exporter(state: Data<Arc<Mutex<State>>>) -> Result<String, APIError> {
    use prometheus_exporter_base::prelude::*;

    info!("Client requested prometheus exporter data");

    let state = state.lock().await;

    let ipset_acl = crate::ipset::IPSet::new(&state.config().ipset_acl_name);
    let ipset_shaper = crate::ipset::IPSet::new(&state.config().ipset_shaper_name);

    let persistent_state = state.persistent_state().await;

    let mut metrics = Vec::new();
    metrics.push(
        PrometheusMetric::build()
            .with_name("ratzek_internet_available")
            .with_metric_type(MetricType::Gauge)
            .with_help("Flag of wide internet availability")
            .build()
            .render_and_append_instance(
                &PrometheusInstance::new()
                    .with_value(persistent_state.is_wide_network_available.unwrap_or(false) as i8),
            )
            .render(),
    );

    if let Some(speedtest_result) = persistent_state.speedtest {
        metrics.push(
            PrometheusMetric::build()
                .with_name("ratzek_speedtest_download")
                .with_metric_type(MetricType::Gauge)
                .with_help("Speedtest download speed")
                .build()
                .render_and_append_instance(
                    &PrometheusInstance::new().with_value(speedtest_result.download),
                )
                .render(),
        );
        metrics.push(
            PrometheusMetric::build()
                .with_name("ratzek_speedtest_upload")
                .with_metric_type(MetricType::Gauge)
                .with_help("Speedtest upload speed")
                .build()
                .render_and_append_instance(
                    &PrometheusInstance::new().with_value(speedtest_result.upload),
                )
                .render(),
        );
        metrics.push(
            PrometheusMetric::build()
                .with_name("ratzek_speedtest_ping")
                .with_metric_type(MetricType::Gauge)
                .with_help("Speedtest ping speed")
                .build()
                .render_and_append_instance(
                    &PrometheusInstance::new().with_value(speedtest_result.ping),
                )
                .render(),
        );
    }

    if let Some(balance) = persistent_state.balance {
        metrics.push(
            PrometheusMetric::build()
                .with_name("ratzek_isp_balance")
                .with_metric_type(MetricType::Gauge)
                .with_help("ISP balance")
                .build()
                .render_and_append_instance(&PrometheusInstance::new().with_value(balance))
                .render(),
        );
    }

    if let Some(last_tariff_update) = persistent_state.last_tariff_update {
        metrics.push(
            PrometheusMetric::build()
                .with_name("ratzek_last_tariff_update")
                .with_metric_type(MetricType::Gauge)
                .with_help("Last tariff update")
                .build()
                .render_and_append_instance(
                    &PrometheusInstance::new()
                        .with_value((last_tariff_update - chrono::Utc::now()).num_seconds()),
                )
                .render(),
        );
    }

    metrics.push(
        PrometheusMetric::build()
            .with_name("ratzek_clients_in_acl")
            .with_metric_type(MetricType::Gauge)
            .with_help("Number of clients in ACL")
            .build()
            .render_and_append_instance(
                &PrometheusInstance::new().with_value(
                    ipset_acl
                        .entries()
                        .map_err(|err| {
                            error!("failed to get ACL entries: {}", err);
                            APIError::InternalError
                        })?
                        .len(),
                ),
            )
            .render(),
    );
    metrics.push(
        PrometheusMetric::build()
            .with_name("ratzek_clients_in_shaper")
            .with_metric_type(MetricType::Gauge)
            .with_help("Number of clients in shaper")
            .build()
            .render_and_append_instance(
                &PrometheusInstance::new().with_value(
                    ipset_shaper
                        .entries()
                        .map_err(|err| {
                            error!("failed to get shaper entries: {}", err);
                            APIError::InternalError
                        })?
                        .len(),
                ),
            )
            .render(),
    );

    let leases = crate::dhcp::Dhcp::read(&state.config().dhcpd_leases)
        .map_err(|_| APIError::InternalError)?
        .all();

    for (name, state) in [
        ("free", dhcpd_parser::leases::BindingState::Free),
        ("active", dhcpd_parser::leases::BindingState::Active),
        ("abandoned", dhcpd_parser::leases::BindingState::Abandoned),
    ] {
        metrics.push(
            PrometheusMetric::build()
                .with_name(&format!("ratzek_dhcp_leases_{}", name))
                .with_metric_type(MetricType::Gauge)
                .with_help(&format!("Number of {} DHCP leases", name))
                .build()
                .render_and_append_instance(
                    &PrometheusInstance::new()
                        .with_value(leases.iter().filter(|v| v.binding_state == state).count()),
                )
                .render(),
        )
    }

    Ok(metrics.join(""))
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

// --- Unlimited clients CRUD (admin-only via AuthSession) ---

/// Config + store snapshot taken under the State lock so handlers can operate
/// without holding it across OMAPI/ipset calls.
struct UnlimitedCtx {
    store: crate::unlimited_clients::UnlimitedClientsStore,
    subnet: ipnet::IpNet,
    omapi: Option<crate::config::Omapi>,
    leases: std::path::PathBuf,
    no_shape_name: String,
    acl_name: String,
}

fn unlimited_ctx(state: &State) -> UnlimitedCtx {
    let c = state.config();
    UnlimitedCtx {
        store: state.unlimited_clients().clone(),
        subnet: c.parsed_unlimited_subnet(),
        omapi: c.omapi.clone(),
        leases: c.dhcpd_leases.clone(),
        no_shape_name: c.ipset_no_shape_name.clone(),
        acl_name: c.ipset_acl_name.clone(),
    }
}

/// Best-effort compensation for a failed create transaction. A failure here
/// leaves drift that startup reconcile will heal, but it must be visible.
async fn rollback_omapi(omapi: &crate::config::Omapi, name: &str) {
    if let Err(err) = crate::omapi::remove_host(omapi, name).await {
        error!("rollback: OMAPI remove_host {name} failed: {err} (manual cleanup may be needed)");
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

#[get("/api/v1/admin/unlimited-clients")]
async fn unlimited_list(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
) -> Result<HttpResponse, APIError> {
    let store = { state.lock().await.unlimited_clients().clone() };
    Ok(HttpResponse::Ok().json(store.list().await))
}

#[get("/api/v1/admin/unlimited-clients/{name}")]
async fn unlimited_get(
    _auth: AuthSession,
    state: Data<Arc<Mutex<State>>>,
    path: web::Path<String>,
) -> Result<HttpResponse, APIError> {
    let store = { state.lock().await.unlimited_clients().clone() };
    match store.get(&path.into_inner()).await {
        Some(client) => Ok(HttpResponse::Ok().json(client)),
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

    let omapi = match &ctx.omapi {
        Some(o) => o.clone(),
        None => {
            error!("unlimited-clients CRUD requires the `omapi` config section");
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
            warn!("DHCP lease lookup for {} failed (from {admin_ip}): {err}", body.ip);
            return Err(APIError::BadRequest);
        }
    };
    if lease.binding_state != BindingState::Active {
        warn!("Lease for {} is not active", body.ip);
        return Err(APIError::BadRequest);
    }
    let mac = match lease.hardware.and_then(|h| normalize_mac(&h.mac)) {
        Some(m) => m,
        None => {
            warn!("Lease for {} has no usable MAC", body.ip);
            return Err(APIError::BadRequest);
        }
    };

    let client = UnlimitedClient {
        name: body.name.clone(),
        mac,
        ip: body.ip.clone(),
        comment: body.comment.clone(),
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

    // Transaction: OMAPI -> ipset -> store. Compensate in reverse on failure;
    // store is written last so it never records a client without side effects.
    if let Err(err) = crate::omapi::add_host(&omapi, &client.name, &client.mac, &client.ip).await {
        error!("OMAPI add_host failed: {err}");
        return Err(APIError::InternalError);
    }
    if let Err(err) = no_shape.add(&client.ip, Some(0)) {
        error!("ipset add no_shape failed: {err}");
        rollback_omapi(&omapi, &client.name).await;
        return Err(APIError::InternalError);
    }
    if let Err(err) = acl.add(&client.ip, Some(0)) {
        error!("ipset add acl failed: {err}");
        rollback_ipset(&no_shape, &client.ip);
        rollback_omapi(&omapi, &client.name).await;
        return Err(APIError::InternalError);
    }
    if let Err(err) = ctx.store.add(client.clone()).await {
        error!("unlimited store add failed: {err}");
        rollback_ipset(&acl, &client.ip);
        rollback_ipset(&no_shape, &client.ip);
        rollback_omapi(&omapi, &client.name).await;
        return Err(APIError::InternalError);
    }

    info!(
        "Admin created unlimited client {} ip={} mac={} from {admin_ip}",
        client.name, client.ip, client.mac
    );
    Ok(HttpResponse::Created().json(client))
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
    if let Some(omapi) = &ctx.omapi {
        if let Err(err) = crate::omapi::remove_host(omapi, &client.name).await {
            error!("OMAPI remove_host failed: {err}");
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
