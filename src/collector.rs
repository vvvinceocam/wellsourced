mod api;
mod metrics;
mod report;
mod template;

use axum::{
    Router,
    http::HeaderMap,
    routing::{get, post},
};
use color_eyre::{Result, eyre::Context};
use reqwest::Client;
use tracing::info;

use crate::collector::{
    api::{get_healthcheck, get_metrics, post_report},
    metrics::Metrics,
};

#[derive(Debug, Clone)]
pub struct CollectorConfig {
    pub address: String,
    pub webhook_url: String,
    pub webhook_template: String,
    pub webhook_headers: HeaderMap,
}

#[derive(Debug, Clone)]
pub struct AppState {
    client: Client,
    webhook_url: String,
    webhook_template: String,
    webhook_headers: HeaderMap,
    metrics: Metrics,
}

pub async fn start_server(config: CollectorConfig) -> Result<()> {
    let state = AppState {
        client: Client::new(),
        webhook_url: config.webhook_url,
        webhook_template: config.webhook_template,
        webhook_headers: config.webhook_headers,
        metrics: Metrics::new()?,
    };

    info!("starting server listening on {}", config.address);
    let app = Router::new()
        .route("/report", post(post_report))
        .route("/metrics", get(get_metrics))
        .route("/health", get(get_healthcheck))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.address)
        .await
        .wrap_err("failed to bind port")?;
    axum::serve(listener, app)
        .await
        .wrap_err("failed to start HTTP server")?;

    Ok(())
}
