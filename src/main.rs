mod cli;
mod display;
mod linter;
mod parser;
mod policy;
mod report;

use std::process::ExitCode;

use clap::Parser;
use cli::Commands;
use report::{Issue, Severity};
use reqwest::redirect::Policy as RedirectPolicy;

use crate::cli::Cli;
use crate::linter::lint;
use crate::parser::parse_policy;
use crate::policy::{Disposition, Policy};
use crate::report::Report;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Lint {
            raw_csp,
            source,
            header,
            follow_redirects,
        } => {
            let (origin, enforce_set, report_set) = if !raw_csp {
                let response = {
                    let mut client = reqwest::Client::builder()
                        .redirect(if follow_redirects {
                            RedirectPolicy::default()
                        } else {
                            RedirectPolicy::none()
                        })
                        .build()
                        .unwrap()
                        .get(source);

                    for header in header {
                        let (name, value) = header.split_once(':').unwrap();
                        client = client.header(name, value);
                    }

                    client.send().await.unwrap()
                };

                let origin = response.url().host_str().map(str::to_string);

                let enforce_set = response
                    .headers()
                    .get_all("content-security-policy")
                    .iter()
                    .map(|header| header.to_str().unwrap().to_string())
                    .collect::<Vec<_>>();

                let report_set = response
                    .headers()
                    .get_all("content-security-policy-report-only")
                    .iter()
                    .map(|header| header.to_str().unwrap().to_string())
                    .collect::<Vec<_>>();

                (origin, enforce_set, report_set)
            } else {
                (None, vec![source], vec![])
            };

            let mut report = Report::new();

            match (enforce_set.first(), report_set.first()) {
                (None, None) => {
                    report.add_issue(
                        Issue::builder()
                            .severity(Severity::Critical)
                            .description("No Content-Security-Policy header found".to_string())
                            .build(),
                    );
                }
                (None, Some(_)) => {
                    report.add_issue(Issue::builder()
                        .severity(Severity::High)
                        .description("No Content-Security-Policy header found, only CSP-Report-Only header found".to_string())
                        .build());
                }
                (Some(_), Some(_)) => {
                    report.add_issue(
                        Issue::builder()
                            .severity(Severity::Low)
                            .description("Both CSP and CSP-Report-Only headers found".to_string())
                            .build(),
                    );
                }
                (Some(_), None) => {}
            };

            if let Some(csp) = enforce_set.first() {
                let policy = match parse_policy(csp, Disposition::Enforce) {
                    Ok(policy) => policy,
                    Err(err) => {
                        report.add_issue(
                            Issue::builder()
                                .severity(Severity::Critical)
                                .description(format!(
                                    "Malformed Content-Security-Policy header: {}",
                                    err
                                ))
                                .build(),
                        );
                        Policy {
                            disposition: Disposition::Enforce,
                            original: "".to_string(),
                            directives: vec![],
                        }
                    }
                };

                println!("{}", &policy);

                lint(&mut report, origin, policy);
            }

            report.show();

            return if report.reaches_severity(Severity::High) {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            };
        }
    }
}
