use std::collections::HashSet;

use crate::{
    policy::{Host, HostSource, Policy, SchemeSource, SourceExpression},
    report::{Report, Severity, Smell},
};

pub fn lint(report: &mut Report, origin: Option<String>, policy: Policy) {
    let mut seen_directives = HashSet::new();

    for directive in policy.directives {
        if seen_directives.contains(&directive.kind) {
            report.add_smell(
                Smell::builder()
                    .severity(Severity::Medium)
                    .description(format!("Duplicate directive: {}", directive.kind))
                    .build(),
            );
        }
        seen_directives.insert(directive.kind.clone());

        if !directive.kind.must_have_no_policy() && directive.sources.is_empty() {
            report.add_smell(
                Smell::builder()
                    .severity(Severity::High)
                    .description(format!("Empty source for directive: {}", &directive.kind))
                    .build(),
            );
        }

        for source in directive.sources {
            if let SourceExpression::Host(HostSource {
                scheme: Some(SchemeSource::Http),
                ..
            }) = source.expression
            {
                report.add_smell(
                    Smell::builder()
                        .severity(Severity::Medium)
                        .description(format!(
                            "Insecure source for directive \"{}\": {}",
                            &directive.kind, &source,
                        ))
                        .build(),
                );
            }

            if let (
                Some(origin),
                SourceExpression::Host(HostSource {
                    host: Host::Fqdn(fqdn),
                    ..
                }),
            ) = (&origin, &source.expression)
                && fqdn == origin
            {
                report.add_smell(
                    Smell::builder()
                        .severity(Severity::Low)
                        .description(format!(
                            "Source \"{}\" could be replaced by 'self' for directive \"{}\"",
                            &source, &directive.kind
                        ))
                        .build(),
                )
            }
        }
    }
}
