use actix_web::{
    get,
    http::{header::ContentType, StatusCode},
    post,
    web::Data,
    HttpRequest, HttpResponse,
};
use derive_more::{Display, Error};
use serde::Serialize;
use slog_scope::{error, info};

use crate::config::Config;

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
    pub shaper_reset_timeout: u64,
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
}

#[get("/api/v1/client")]
async fn client_get(config: Data<Config>, req: HttpRequest) -> Result<String, APIError> {
    let client_addr = match req.peer_addr() {
        Some(v) => v,
        None => {
            error!("Unable to get client IP");
            return Err(APIError::InternalError);
        }
    };
    let client_ip = client_addr.ip().to_string();

    info!("Request from {}:{}", client_ip, client_addr.port());

    let ipset_acl = crate::ipset::IPSet::new(&config.ipset_shaper_name);
    let acl_entries = match ipset_acl.entries() {
        Ok(v) => v,
        Err(err) => {
            error!("Unable to get ipset list: {}", err);
            return Err(APIError::InternalError);
        }
    };

    let ipset_shaper = crate::ipset::IPSet::new(&config.ipset_shaper_name);
    let shaper_entries = match ipset_shaper.entries() {
        Ok(v) => v,
        Err(err) => {
            error!("Unable to get ipset list: {}", err);
            return Err(APIError::InternalError);
        }
    };

    let is_user_in_acl = acl_entries.iter().any(|v| v.ip == client_ip);
    let internet_connection_status = if is_user_in_acl {
        let shaper_info = shaper_entries.iter().find(|v| v.ip == client_ip);

        InternetConnectionStatus::Connected(ClientConnectionInfo {
            bytes_sent: shaper_info.and_then(|v| v.bytes).unwrap_or_default(),
            bytes_unlimited_limit: config.bytes_unlimited_limit,
            shaper_reset_timeout: shaper_info
                .and_then(|v| v.timeout.map(|v| v.as_secs()))
                .unwrap_or_default(),
        })
    } else {
        InternetConnectionStatus::Inactive
    };

    let resp = ServiceInfo {
        internet_clients_connected: shaper_entries.len(),
        internet_connection_status,
    };
    Ok(serde_json::ser::to_string(&resp).unwrap())
}

#[post("/api/v1/client")]
async fn client_register(config: Data<Config>, req: HttpRequest) -> Result<String, APIError> {
    let client_addr = match req.peer_addr() {
        Some(v) => v,
        None => {
            error!("Unable to get client IP");
            return Err(APIError::InternalError);
        }
    };
    let client_ip = client_addr.ip().to_string();

    info!("Request from {}:{}", client_ip, client_addr.port());

    let ipset_acl = crate::ipset::IPSet::new(&config.ipset_acl_name);

    if let Err(err) = ipset_acl.add(&client_ip) {
        error!("Unable to add client to ACL ipset: {}", err);
        return Err(APIError::InternalError);
    }

    Ok(String::new())
}
