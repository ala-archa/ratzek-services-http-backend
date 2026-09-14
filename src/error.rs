use actix_web::http::{
    header::{self, ContentType},
    StatusCode,
};
use actix_web::HttpResponse;
use derive_more::{Display, Error};

/// Seconds a client should wait before retrying a `ServiceUnavailable` request; matches
/// the portal's poll period.
const RETRY_AFTER_SECS: u32 = 5;

/// Error type shared by the HTTP handlers and request guards. Lives in its own
/// module so `session`/`unlimited_clients` can depend on it without a
/// back-edge into `http`.
#[derive(Debug, Display, Error)]
pub enum APIError {
    #[display(fmt = "internal error")]
    InternalError,
    #[display(fmt = "unauthorized")]
    Unauthorized,
    #[display(fmt = "forbidden")]
    Forbidden,
    #[display(fmt = "bad request")]
    BadRequest,
    #[display(fmt = "not found")]
    NotFound,
    #[display(fmt = "conflict")]
    Conflict,
    /// Temporary: the request can't be served yet (e.g. the client's MAC isn't known
    /// before DHCP). Carries `Retry-After`.
    #[display(fmt = "service unavailable")]
    ServiceUnavailable,
}

impl actix_web::error::ResponseError for APIError {
    fn error_response(&self) -> HttpResponse {
        let mut resp = HttpResponse::build(self.status_code());
        resp.insert_header(ContentType::html());
        if matches!(self, Self::ServiceUnavailable) {
            resp.insert_header((header::RETRY_AFTER, RETRY_AFTER_SECS.to_string()));
        }
        resp.body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
            Self::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::error::ResponseError;

    #[test]
    fn service_unavailable_carries_retry_after() {
        let resp = APIError::ServiceUnavailable.error_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("5")
        );
    }

    #[test]
    fn other_errors_have_no_retry_after() {
        let resp = APIError::Forbidden.error_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(resp.headers().get(header::RETRY_AFTER).is_none());
    }
}
