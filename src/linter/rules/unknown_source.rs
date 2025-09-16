use crate::{
    linter::{Node, Rule},
    policy::SourceExpression,
    report::{Issue, Report, Severity},
};

pub struct UnknownSource {}

impl Rule for UnknownSource {
    fn check(&self, _origin: Option<String>, report: &mut Report, node: Node) {
        let Node::Source(source) = node else {
            return;
        };

        if let SourceExpression::Unknown(expression) = &source.expression {
            report.add_issue(
                Issue::builder()
                    .severity(Severity::Low)
                    .description(format!("Invalid source expression: {expression}"))
                    .build(),
            );
        }
    }
}
