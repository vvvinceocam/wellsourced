use crate::{
    linter::{Node, Rule},
    policy::DirectiveKind,
    report::{Issue, Report, Severity},
};

pub struct MissingSource {}

impl Rule for MissingSource {
    fn check(&self, _origin: Option<String>, report: &mut Report, node: Node) {
        let Node::Directive(directive) = node else {
            return;
        };

        if let DirectiveKind::Unknown(_) = directive.kind {
            return;
        }

        if !directive.kind.must_have_no_source() && directive.sources.is_empty() {
            report.add_issue(
                Issue::builder()
                    .severity(Severity::High)
                    .description(format!(
                        "Missing source for directive \"{}\". Directive has no effect.",
                        &directive.kind
                    ))
                    .build(),
            );
        }
    }
}
