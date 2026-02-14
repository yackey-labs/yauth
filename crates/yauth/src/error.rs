use axum::Json;
use axum::http::StatusCode;

pub type ApiError = (StatusCode, Json<serde_json::Value>);

pub fn api_err(status: StatusCode, msg: &str) -> ApiError {
    (status, Json(serde_json::json!({ "error": msg })))
}
