mod cli;
mod collector;
mod display;
mod linter;
mod parser;
mod policy;
mod report;
mod utils;

use std::process::exit;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use clap::Parser;
use color_eyre::{
    Result,
    eyre::{Context, eyre},
};
use report::{Issue, Severity};
use reqwest::redirect::Policy as RedirectPolicy;

use crate::linter::lint;
use crate::parser::parse_policy;
use crate::policy::Disposition;
use crate::report::Report;
use crate::{
    cli::{Cli, Commands},
    utils::collect_headers,
};
use crate::{
    collector::{CollectorConfig, start_server},
    policy::PolicySet,
};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();

    match cli.command {
        Commands::Audit {
            raw,
            source,
            headers,
            follow_redirects,
        } => run_audit(raw, source, headers, follow_redirects).await?,
        Commands::Collect {
            address,
            webhook_url,
            webhook_template,
            webhook_headers,
        } => run_collect(address, webhook_url, webhook_template, webhook_headers).await?,
    }

    Ok(())
}

async fn run_collect(
    address: String,
    webhook_url: String,
    webhook_template: String,
    webhook_headers: Vec<String>,
) -> Result<()> {
    tracing_subscriber::fmt().json().init();

    let webhook_headers = HeaderMap::from_iter(
        webhook_headers
            .iter()
            .map(|header| {
                let (name, value) = header.split_once(':').ok_or(eyre!(
                    "webhook header '{header}' is malformed: expected '<name>:<value>'"
                ))?;
                let name = HeaderName::from_bytes(name.as_bytes())
                    .wrap_err("webhook header '{header}' is malformed: invalid header name")?;
                let value = HeaderValue::from_str(value)
                    .wrap_err("webhook header '{header}' is malformed: invalid header value")?;
                Ok((name, value))
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter(),
    );

    let config = CollectorConfig {
        address,
        webhook_url,
        webhook_template,
        webhook_headers,
    };
    start_server(config).await?;
    Ok(())
}

async fn run_audit(
    raw: bool,
    source: String,
    headers: Vec<String>,
    follow_redirects: bool,
) -> Result<()> {
    let (origin, enforce_set, report_set) = if !raw {
        let response = {
            let mut client = reqwest::Client::builder()
                .redirect(if follow_redirects {
                    RedirectPolicy::default()
                } else {
                    RedirectPolicy::none()
                })
                .build()?
                .get(source);

            for header in headers {
                let (name, value) = header
                    .split_once(':')
                    .ok_or_else(|| eyre!("Invalid header format"))?;
                client = client.header(name, value);
            }

            client.send().await?
        };

        let origin = response.url().host_str().map(str::to_string);
        let enforce_set = collect_headers(&response, "content-security-policy")?;
        let report_set = collect_headers(&response, "content-security-policy-report-only")?;

        (origin, enforce_set, report_set)
    } else {
        (None, vec![source], vec![])
    };

    let mut report = Report::new();

    let policy_set = {
        let policies = enforce_set
            .iter()
            .map(|policy| parse_policy(policy, Disposition::Enforce))
            .chain(
                report_set
                    .iter()
                    .map(|policy| parse_policy(policy, Disposition::Report)),
            )
            .filter_map(|policy| match policy {
                Ok(policy) => Some(policy),
                Err(err) => {
                    report.add_issue(
                        Issue::builder()
                            .severity(Severity::Critical)
                            .description(format!("Invalid CSP policy: {}", err))
                            .build(),
                    );
                    None
                }
            })
            .collect();

        PolicySet { policies }
    };

    lint(&mut report, origin, policy_set);

    report.show();

    if report.reaches_severity(Severity::High) {
        exit(1);
    } else {
        Ok(())
    }
}
