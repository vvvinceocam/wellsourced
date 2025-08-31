use clap::{ArgAction, Parser, Subcommand};

#[derive(Debug, Clone, Parser)]
pub struct Cli {
    #[arg(short, long, action = ArgAction::Count)]
    pub debug: u8,

    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    Lint {
        #[arg(short, long, default_value_t = false)]
        raw_csp: bool,

        #[arg(short, long, default_value_t = false)]
        follow_redirects: bool,

        #[arg(short = 'H', long)]
        header: Vec<String>,

        source: String,
    },
    /// Run a web server to collect CSP reports
    ///
    /// Reports are logged to stdout and sent to the webhook URL.
    Collector {
        /// Address to bind to the web server.
        #[arg(short, long, default_value_t = String::from("0.0.0.0:8080"))]
        address: String,

        /// Webhook URL to send reports to.
        #[arg(short = 'u', long)]
        webhook_url: String,

        /// Webhook template to use for reports
        ///
        /// Use `{{ variable }}` syntax to insert variables into the template.
        ///
        /// Avalaible variables: blocked-uri, document-uri, effective-directive,
        /// original-policy, referrer, status-code, violated-directive,
        /// source-file, line-number, source-file
        #[arg(short = 't', long)]
        webhook_template: String,
    },
}
