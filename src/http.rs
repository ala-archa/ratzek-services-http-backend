use std::sync::Arc;

use actix_web::{
    get,
    http::{header::ContentType, StatusCode},
    post,
    web::Data,
    HttpRequest, HttpResponse,
};
use derive_more::{Display, Error};
use dhcpd_parser::parser::LeasesMethods;
use serde::Serialize;
use slog_scope::{error, info};
use tokio::sync::Mutex;

use crate::state::State;

#[derive(Debug, Display, Error)]
enum APIError {
    #[display(fmt = "internal error")]
    InternalError,
}

impl actix_web::error::ResponseError for APIError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::html())
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

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

async fn client(
    state: Data<Arc<Mutex<State>>>,
    req: &HttpRequest,
) -> std::result::Result<(String, String), APIError> {
    let client_ip = match client_ip(req) {
        Some(v) => v,
        None => {
            error!("Unable to get client IP");
            return Err(APIError::InternalError);
        }
    };

    info!("Request from {}", client_ip);

    let state = state.lock().await;

    let dhcp_lease = match crate::dhcp::Dhcp::of_ip(&state.config().dhcpd_leases, &client_ip) {
        Ok(v) => v,
        Err(err) => {
            error!("{}", err);
            return Err(APIError::InternalError);
        }
    };

    let client_mac = match dhcp_lease.hardware {
        Some(v) => v.mac.to_lowercase(),
        None => {
            error!("Client's MAC not defined in DHCP leases file");
            return Err(APIError::InternalError);
        }
    };

    Ok((client_ip, client_mac))
}

#[get("/api/v1/client")]
async fn client_get(state: Data<Arc<Mutex<State>>>, req: HttpRequest) -> Result<String, APIError> {
    let (client_ip, client_mac) = client(state.clone(), &req).await?;

    let state = state.lock().await;

    let ipset_shaper = crate::ipset::IPSet::new(&state.config().ipset_shaper_name);
    let shaper_entries = match ipset_shaper.entries() {
        Ok(v) => v,
        Err(err) => {
            error!("Unable to get ipset list: {}", err);
            return Err(APIError::InternalError);
        }
    };

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
            is_internet_available: state.wide_network_available(),
        };
        return Ok(serde_json::ser::to_string(&resp).unwrap());
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
            connection_forget_secs: acl_info.timeout.map(|v| v.as_secs()).unwrap_or_default(),
        })
    } else {
        InternetConnectionStatus::Inactive
    };

    let resp = ServiceInfo {
        internet_clients_connected: shaper_entries.len(),
        internet_connection_status,
        is_internet_available: state.wide_network_available(),
    };
    Ok(serde_json::ser::to_string(&resp).unwrap())
}

#[post("/api/v1/client")]
async fn client_register(
    state: Data<Arc<Mutex<State>>>,
    req: HttpRequest,
) -> Result<String, APIError> {
    let (client_ip, client_mac) = client(state.clone(), &req).await?;

    let state = state.lock().await;

    if state
        .config()
        .blacklisted_macs
        .iter()
        .map(|v| v.to_lowercase())
        .any(|v| v == client_mac)
    {
        error!("Blacklisted client attempted to register");
        return Err(APIError::InternalError);
    }

    let ipset_acl = crate::ipset::IPSet::new(&state.config().ipset_acl_name);

    if let Err(err) = ipset_acl.add(&client_ip) {
        error!("Unable to add client to ACL ipset: {}", err);
        return Err(APIError::InternalError);
    }

    if state
        .config()
        .no_shaping_macs
        .iter()
        .map(|v| v.to_lowercase())
        .any(|v| v == client_mac)
    {
        let ipset_no_shape = crate::ipset::IPSet::new(&state.config().ipset_no_shape_name);

        if let Err(err) = ipset_no_shape.add(&client_ip) {
            error!("Unable to add client to no_shape ipset: {}", err);
            return Err(APIError::InternalError);
        }
    }

    Ok(String::new())
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

    let state = state.lock().await;

    let ipset_acl = crate::ipset::IPSet::new(&state.config().ipset_acl_name);
    let ipset_shaper = crate::ipset::IPSet::new(&state.config().ipset_acl_name);

    let mut metrics = Vec::new();
    metrics.push(
        PrometheusMetric::build()
            .with_name("ratzek_internet_available")
            .with_metric_type(MetricType::Counter)
            .with_help("Flag of wide internet availability")
            .build()
            .render_and_append_instance(
                &PrometheusInstance::new().with_value(state.wide_network_available() as i8),
            )
            .render(),
    );
    metrics.push(
        PrometheusMetric::build()
            .with_name("ratzek_clients_in_acl")
            .with_metric_type(MetricType::Counter)
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
            .with_metric_type(MetricType::Counter)
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
                .with_metric_type(MetricType::Counter)
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
