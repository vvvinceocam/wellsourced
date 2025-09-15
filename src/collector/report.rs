use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LegacyWrapper<T> {
    pub csp_report: T,
}

/// Content Security Policy Level 2 violation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct LegacyReport {
    pub blocked_uri: String,
    pub document_uri: String,
    pub effective_directive: String,
    pub original_policy: String,
    pub referrer: String,
    pub status_code: u16,
    pub violated_directive: String,
    #[serde(default = "LegacyReport::default_source_file")]
    pub source_file: String,
    #[serde(default)]
    pub line_number: u32,
    #[serde(default)]
    pub column_number: u32,
}

impl LegacyReport {
    fn default_source_file() -> String {
        String::from("<no-file>")
    }
}
