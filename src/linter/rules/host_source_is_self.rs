use crate::{
    linter::{Node, Rule},
    policy::{DirectiveKind, Host, HostSource, SchemeSource, SourceExpression},
    report::{Issue, Report, Severity},
};

pub struct HostSourceIsSelf {}

impl Rule for HostSourceIsSelf {
    fn check(&self, origin: Option<String>, report: &mut Report, node: Node) {
        let Node::Directive(directive) = node else {
            return;
        };

        let Some(ref origin) = origin else {
            return;
        };

        if let DirectiveKind::Unknown(_) = directive.kind {
            return;
        }

        if directive.kind.must_have_no_source() {
            return;
        }

        for source in &directive.sources {
            let SourceExpression::Host(host) = &source.expression else {
                continue;
            };
            let HostSource {
                scheme: Some(SchemeSource::Https),
                host: Host::Fqdn(fqdn),
                port: None,
                path: None,
            } = host
            else {
                continue;
            };

            if fqdn == origin {
                report.add_issue(
                    Issue::builder()
                        .severity(Severity::Low)
                        .description(format!("Host source \"{}\" in directive \"{}\" is the page origin. It can be replaced with 'self'", &fqdn, directive.kind))
                        .build(),
                );
            }
        }
    }
}
