use axum::{Json, Router, extract::State, routing::post};
use handlebars::{Handlebars, no_escape};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LegacyWrapper<T> {
    pub csp_report: T,
}

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
    source_file: Option<String>,
    line_number: Option<u32>,
    column_number: Option<u32>,
}

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
    let mut reg = Handlebars::new();
    reg.register_escape_fn(no_escape);

    let payload = reg
        .render_template(&state.webhook_template, &csp_report)
        .unwrap();

    let response = state
        .client
        .post(state.webhook_url)
        .header("Content-Type", "application/json")
        .body(payload)
        .send()
        .await
        .unwrap();

    if !response.status().is_success() {
        error!("failed to post webhook");
    }
}

#[derive(Debug, Clone)]
pub struct CollectorConfig {
    pub address: String,
    pub webhook_url: String,
    pub webhook_template: String,
}

#[derive(Debug, Clone)]
pub struct AppState {
    client: Client,
    webhook_url: String,
    webhook_template: String,
}

pub async fn start_server(config: CollectorConfig) {
    let state = AppState {
        client: Client::new(),
        webhook_url: config.webhook_url,
        webhook_template: config.webhook_template,
    };

    info!("starting server listening on {}", config.address);
    let app = Router::new()
        .route("/", post(post_report))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.address).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
