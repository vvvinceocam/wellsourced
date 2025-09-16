use axum::{
    body::Bytes,
    extract::{FromRequest, Request, rejection::BytesRejection},
    http::HeaderMap,
    response::IntoResponse,
};
use reqwest::{StatusCode, header::CONTENT_TYPE};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Error as JsonError;

static REPORT_LEVEL_2_CONTENT_TYPE: &str = "application/csp-report";

fn report_content_type(headers: &HeaderMap) -> bool {
    headers
        .get_all(CONTENT_TYPE)
        .iter()
        .any(|value| value == REPORT_LEVEL_2_CONTENT_TYPE)
}

#[derive(Debug, Clone, Copy, Default)]
#[must_use]
pub struct Report<T>(pub T);

pub enum ReportRejection {
    MissingReportContentType,
    MalformedJson(JsonError),
    BadBody(BytesRejection),
}

impl IntoResponse for ReportRejection {
    fn into_response(self) -> axum::response::Response {
        match self {
            ReportRejection::MissingReportContentType => {
                (StatusCode::BAD_REQUEST, "Bad Content Type").into_response()
            }
            ReportRejection::MalformedJson(err) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Malformed report: {}", err),
            )
                .into_response(),
            ReportRejection::BadBody(bytes_rejection) => bytes_rejection.into_response(),
        }
    }
}

impl<T, S> FromRequest<S> for Report<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ReportRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        if !report_content_type(req.headers()) {
            return Err(ReportRejection::MissingReportContentType);
        }

        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(ReportRejection::BadBody)?;
        serde_json::from_slice::<T>(&bytes)
            .map(Report)
            .map_err(ReportRejection::MalformedJson)
    }
}

/// Content Security Policy Level 2 violation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ReportLevel2 {
    pub csp_report: BodyLevel2,
}

impl ReportLevel2 {
    fn default_source_file() -> String {
        String::from("<no-file>")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct BodyLevel2 {
    pub blocked_uri: String,
    pub document_uri: String,
    pub effective_directive: String,
    pub original_policy: String,
    pub referrer: String,
    pub status_code: u16,
    pub violated_directive: String,
    #[serde(default = "ReportLevel2::default_source_file")]
    pub source_file: String,
    #[serde(default)]
    pub line_number: u32,
    #[serde(default)]
    pub column_number: u32,
}
