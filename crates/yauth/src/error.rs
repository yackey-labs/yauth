use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum YAuthError {
    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Too many requests")]
    TooManyRequests,

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Database error: {0}")]
    Database(#[from] sea_orm::DbErr),
}

impl IntoResponse for YAuthError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            YAuthError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            YAuthError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            YAuthError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            YAuthError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            YAuthError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            YAuthError::TooManyRequests => {
                (StatusCode::TOO_MANY_REQUESTS, "Too many requests".into())
            }
            YAuthError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".into())
            }
            YAuthError::Database(e) => {
                tracing::error!("Database error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal error".into())
            }
        };

        (status, axum::Json(json!({ "error": message }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_of(err: YAuthError) -> StatusCode {
        let response = err.into_response();
        response.status()
    }

    #[test]
    fn bad_request_returns_400() {
        assert_eq!(status_of(YAuthError::BadRequest("x".into())), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn unauthorized_returns_401() {
        assert_eq!(status_of(YAuthError::Unauthorized("x".into())), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn forbidden_returns_403() {
        assert_eq!(status_of(YAuthError::Forbidden("x".into())), StatusCode::FORBIDDEN);
    }

    #[test]
    fn not_found_returns_404() {
        assert_eq!(status_of(YAuthError::NotFound("x".into())), StatusCode::NOT_FOUND);
    }

    #[test]
    fn conflict_returns_409() {
        assert_eq!(status_of(YAuthError::Conflict("x".into())), StatusCode::CONFLICT);
    }

    #[test]
    fn too_many_requests_returns_429() {
        assert_eq!(status_of(YAuthError::TooManyRequests), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn internal_returns_500() {
        assert_eq!(status_of(YAuthError::Internal("x".into())), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
