use axum::{Json, Router, extract::State, routing::get};

use crate::plugin::{PluginContext, YAuthPlugin};
use crate::state::YAuthState;

pub struct StatusPlugin;

impl YAuthPlugin for StatusPlugin {
    fn name(&self) -> &'static str {
        "status"
    }

    fn public_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        None
    }

    fn protected_routes(&self, _ctx: &PluginContext) -> Option<Router<YAuthState>> {
        Some(Router::new().route("/status", get(get_status)))
    }
}

async fn get_status(State(state): State<YAuthState>) -> Json<serde_json::Value> {
    let plugins: Vec<&str> = state.plugins.iter().map(|p| p.name()).collect();
    Json(serde_json::json!({ "plugins": plugins }))
}
