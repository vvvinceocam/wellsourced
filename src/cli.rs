use clap::{Parser, Subcommand};

#[derive(Debug, Clone, Parser)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    /// Audit a website for CSP issues.
    Audit {
        /// Whether to process source as a raw policy string.
        #[arg(short, long, default_value_t = false)]
        raw: bool,

        /// Whether to follow redirects when fetching the source.
        #[arg(short, long, default_value_t = false)]
        follow_redirects: bool,

        /// Additional headers to send with the request.
        ///
        /// Can be specified multiple times.
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,

        /// Source URL to audit. Or raw policy string if --raw is set.
        source: String,
    },
    /// Run a web server to collect CSP reports.
    ///
    /// Reports are logged to stdout and sent to the webhook URL.
    Collect {
        /// Address to bind to the web server.
        #[arg(short, long, env = "WELLSOURCED_ADDRESS", default_value_t = String::from("0.0.0.0:8080"))]
        address: String,

        /// Webhook URL to send reports to.
        #[arg(short = 'u', long, env = "WELLSOURCED_WEBHOOK_URL")]
        webhook_url: String,

        /// Webhook template to use for reports
        ///
        /// Use `{{ variable }}` syntax to insert variables into the template.
        ///
        /// Available variables: blocked-uri, document-uri, effective-directive,
        /// original-policy, referrer, status-code, violated-directive,
        /// source-file, line-number, column-number
        #[arg(short = 't', long, env = "WELLSOURCED_WEBHOOK_TEMPLATE")]
        webhook_template: String,

        /// Additional headers to send with the webhook request.
        ///
        /// Can be specified multiple times.
        #[arg(short = 'H', long = "webhook-header", env = "WELLSOURCED_WEBHOOK_HEADERS", num_args = 0..)]
        webhook_headers: Vec<String>,
    },
}
