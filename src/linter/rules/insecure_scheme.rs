use crate::{
    linter::{Node, Rule},
    policy::{DirectiveKind, HostSource, SchemeSource, SourceExpression},
    report::{Issue, Report, Severity},
};

pub struct InsecureScheme {}

impl Rule for InsecureScheme {
    fn check(&self, _origin: Option<String>, report: &mut Report, node: Node) {
        let Node::Directive(directive) = node else {
            return;
        };

        if let DirectiveKind::Unknown(_) = directive.kind {
            return;
        }

        if directive.kind.must_have_no_source() {
            return;
        }

        for source in &directive.sources {
            let scheme = match &source.expression {
                SourceExpression::Host(HostSource {
                    scheme: Some(scheme),
                    ..
                }) => scheme,
                SourceExpression::Scheme(scheme) => scheme,
                _ => continue,
            };

            match scheme {
                SchemeSource::Http | SchemeSource::Ws => {
                    report.add_issue(
                        Issue::builder()
                            .severity(Severity::Medium)
                            .description(format!(
                                "Insecure scheme \"{}\" used in directive \"{}\".",
                                &scheme, &directive.kind
                            ))
                            .build(),
                    );
                }
                _ => {}
            }
        }
    }
}
