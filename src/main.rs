mod cli;
mod parser;
mod report;

use std::{collections::HashSet, process::ExitCode};

use clap::Parser;
use cli::Commands;
use parser::RawPolicy;
use report::{Severity, Smell};
use reqwest::redirect::Policy;

use crate::cli::Cli;
use crate::parser::parse_policy;
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
            let (csp, cspro, origin) = if !raw_csp {
                let response = {
                    let mut client = reqwest::Client::builder()
                        .redirect(if follow_redirects {
                            Policy::default()
                        } else {
                            Policy::none()
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

                let csp = response
                    .headers()
                    .get_all("content-security-policy")
                    .iter()
                    .map(|header| header.to_str().unwrap())
                    .next()
                    .map(str::to_string);

                let cspro = response
                    .headers()
                    .get_all("content-security-policy-report-only")
                    .iter()
                    .map(|header| header.to_str().unwrap())
                    .next()
                    .map(str::to_string);
                (csp, cspro, origin)
            } else {
                (Some(source.clone()), None, None)
            };

            let mut report = Report::new();

            let csp = match (csp, cspro) {
                (None, Some(_)) => {
                    report.add_smell(Smell::builder()
                        .severity(Severity::Critical)
                        .description("No Content-Security-Policy header found, only CSP-Report-Only header found".to_string())
                        .build());
                    None
                }
                (None, None) => {
                    report.add_smell(
                        Smell::builder()
                            .severity(Severity::Critical)
                            .description("No Content-Security-Policy header found".to_string())
                            .build(),
                    );
                    None
                }
                (Some(csp), Some(_)) => {
                    report.add_smell(
                        Smell::builder()
                            .severity(Severity::Medium)
                            .description("Both CSP and CSP-Report-Only headers found".to_string())
                            .build(),
                    );
                    Some(csp)
                }
                (Some(csp), None) => Some(csp),
            };

            if let Some(csp) = csp {
                let policy = match parse_policy(&csp) {
                    Ok(policy) => policy,
                    Err(err) => {
                        report.add_smell(
                            Smell::builder()
                                .severity(Severity::Critical)
                                .description(format!(
                                    "Malformed Content-Security-Policy header: {}",
                                    err
                                ))
                                .build(),
                        );
                        RawPolicy {
                            directives: Vec::new(),
                        }
                    }
                };

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

fn lint(report: &mut Report, origin: Option<String>, policy: RawPolicy) {
    let mut seen_directives = HashSet::new();

    for directive in policy.directives {
        if seen_directives.contains(&directive.name) {
            report.add_smell(
                Smell::builder()
                    .severity(Severity::Medium)
                    .description(format!("Duplicate directive: {}", directive.name))
                    .build(),
            );
        }
        seen_directives.insert(directive.name.clone());

        if directive.sources.is_empty() {
            report.add_smell(
                Smell::builder()
                    .severity(Severity::High)
                    .description(format!("Empty source for directive: {}", &directive.name))
                    .build(),
            );
        }

        for source in directive.sources {
            if source.starts_with("http://") {
                report.add_smell(
                    Smell::builder()
                        .severity(Severity::Medium)
                        .description(format!(
                            "Insecure source for directive \"{}\": {}",
                            &directive.name, &source,
                        ))
                        .build(),
                );
            }

            if origin
                .as_ref()
                .map(|origin| source == *origin)
                .unwrap_or(false)
            {
                report.add_smell(
                    Smell::builder()
                        .severity(Severity::Low)
                        .description(format!(
                            "Source \"{}\" could be replaced by 'self' for directive \"{}\"",
                            &source, &directive.name
                        ))
                        .build(),
                );
            }
        }
    }
}
