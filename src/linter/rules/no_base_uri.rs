use crate::{
    linter::{Node, Rule},
    policy::DirectiveKind,
    report::{Issue, Report, Severity},
};

pub struct NoBaseUri {}

impl Rule for NoBaseUri {
    fn check(&self, _origin: Option<String>, report: &mut Report, node: Node) {
        let Node::Policy(policy) = node else {
            return;
        };

        let has_base_uri = policy
            .directives
            .iter()
            .any(|directive| directive.kind == DirectiveKind::BaseUri);

        if !has_base_uri {
            report.add_issue(
                Issue::builder()
                    .severity(Severity::High)
                    .description("No 'base-uri' directive found. Either set it to 'none' if you don't need to use <base> or allow specific sources.".to_string())
                    .build()
            );
        }
    }
}
