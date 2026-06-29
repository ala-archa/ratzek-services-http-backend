use actix_web::http::{header::ContentType, StatusCode};
use actix_web::HttpResponse;
use derive_more::{Display, Error};

/// Error type shared by the HTTP handlers and request guards. Lives in its own
/// module so `session`/`unlimited_clients` can depend on it without a
/// back-edge into `http`.
#[derive(Debug, Display, Error)]
pub enum APIError {
    #[display(fmt = "internal error")]
    InternalError,
    #[display(fmt = "unauthorized")]
    Unauthorized,
    #[display(fmt = "bad request")]
    BadRequest,
    #[display(fmt = "not found")]
    NotFound,
    #[display(fmt = "conflict")]
    Conflict,
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
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
        }
    }
}
