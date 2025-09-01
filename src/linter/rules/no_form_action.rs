use crate::{
    linter::{Node, Rule},
    policy::DirectiveKind,
    report::{Issue, Report, Severity},
};

pub struct NoFormAction {}

impl Rule for NoFormAction {
    fn check(&self, _origin: Option<String>, report: &mut Report, node: Node) {
        let Node::Policy(policy) = node else {
            return;
        };

        let has_form_action = policy
            .directives
            .iter()
            .any(|directive| directive.kind == DirectiveKind::FormAction);

        if !has_form_action {
            report.add_issue(
                Issue::builder()
                    .severity(Severity::High)
                    .description("No 'form-action' directive found. Set it to 'self' as minimal restriction. If you don't use any form submissions, set it to 'none'.".to_string())
                    .build()
            );
        }
    }
}
