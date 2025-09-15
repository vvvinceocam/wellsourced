mod template;

use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use color_eyre::{Result, eyre::Context};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::collector::template::render;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LegacyWrapper<T> {
    pub csp_report: T,
}

/// Content Security Policy Level 2 violation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LegacyReport {
    blocked_uri: String,
    document_uri: String,
    effective_directive: String,
    original_policy: String,
    referrer: String,
    status_code: u16,
    violated_directive: String,
    #[serde(default = "LegacyReport::default_source_file")]
    source_file: String,
    #[serde(default)]
    line_number: u32,
    #[serde(default)]
    column_number: u32,
}

impl LegacyReport {
    fn default_source_file() -> String {
        String::from("<no-file>")
    }
}

/// Produce logs and asynchronously send a webhook report.
async fn post_report(
    State(state): State<AppState>,
    Json(LegacyWrapper { csp_report }): Json<LegacyWrapper<LegacyReport>>,
) {
    info!(
        message = "report received",
        "blockedUri" = csp_report.blocked_uri,
        "documentUri" = csp_report.document_uri,
        "effectiveDirective" = csp_report.effective_directive,
        "referrer" = csp_report.referrer,
        "statusCode" = csp_report.status_code,
        "violatedDirective" = csp_report.violated_directive,
        "sourceFile" = csp_report.source_file,
        "lineNumber" = csp_report.line_number,
        "columnNumber" = csp_report.column_number,
    );

    tokio::spawn(async move {
        let payload = match render(&state.webhook_template, &csp_report) {
            Ok(payload) => payload,
            Err(err) => {
                error!(
                    message = "failed to render webhook payload",
                    error = err.to_string(),
                );
                return;
            }
        };

        let response = state
            .client
            .post(state.webhook_url)
            .headers(state.webhook_headers)
            .header("Content-Type", "application/json")
            .body(payload)
            .send()
            .await;

        let response = match response {
            Ok(response) => response,
            Err(err) => {
                error!(message = "failed to post webhook", error = err.to_string());
                return;
            }
        };

        if !response.status().is_success() {
            let status_code = response.status().as_u16();
            let error = response.text().await.unwrap_or("<empty>".to_string());
            error!(message = "webhook response is error", status_code, error);
        };
    });
}

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
}

pub async fn start_server(config: CollectorConfig) -> Result<()> {
    let state = AppState {
        client: Client::new(),
        webhook_url: config.webhook_url,
        webhook_template: config.webhook_template,
        webhook_headers: config.webhook_headers,
    };

    info!("starting server listening on {}", config.address);
    let app = Router::new()
        .route("/", post(post_report))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.address)
        .await
        .wrap_err("failed to bind port")?;
    axum::serve(listener, app)
        .await
        .wrap_err("failed to start HTTP server")?;

    Ok(())
}
