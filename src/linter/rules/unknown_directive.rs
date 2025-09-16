use crate::{
    linter::{Node, Rule},
    policy::DirectiveKind,
    report::{Issue, Report, Severity},
};

pub struct UnknownDirective {}

impl Rule for UnknownDirective {
    fn check(&self, _origin: Option<String>, report: &mut Report, node: Node) {
        let Node::Directive(directive) = node else {
            return;
        };

        if let DirectiveKind::Unknown(expression) = &directive.kind {
            report.add_issue(
                Issue::builder()
                    .severity(Severity::Low)
                    .description(format!("Invalid directive name: {expression}"))
                    .build(),
            );
        }
    }
}
