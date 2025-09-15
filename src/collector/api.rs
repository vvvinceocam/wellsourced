use axum::{Json, extract::State, http::StatusCode};
use tracing::{error, info};

use crate::collector::{
    AppState,
    report::{LegacyReport, LegacyWrapper},
    template::render,
};

/// Healthcheck endpoint.
pub async fn get_healthcheck() -> &'static str {
    "OK"
}

/// Prometheus metrics endpoint.
pub async fn get_metrics(State(state): State<AppState>) -> (StatusCode, String) {
    match state.metrics.encode() {
        Ok(metrics) => (StatusCode::OK, metrics),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

/// Produce logs and asynchronously send a webhook report.
pub async fn post_report(
    State(state): State<AppState>,
    Json(LegacyWrapper { csp_report }): Json<LegacyWrapper<LegacyReport>>,
) {
    state.metrics.inc_report();
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
                state.metrics.inc_webhooks("unreachable");
                error!(message = "failed to post webhook", error = err.to_string());
                return;
            }
        };

        let status_code = response.status();
        state.metrics.inc_webhooks(status_code.as_str());

        if !status_code.is_success() {
            let status_code = response.status().as_u16();
            let error = response.text().await.unwrap_or("<empty>".to_string());
            error!(message = "webhook response is error", status_code, error);
        };
    });
}
