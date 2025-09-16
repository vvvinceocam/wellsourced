use crate::{
    linter::{Node, Rule},
    policy::Disposition,
    report::{Issue, Report, Severity},
};

pub struct NoEnforcePolicy {}

impl Rule for NoEnforcePolicy {
    fn check(&self, _origin: Option<String>, report: &mut Report, node: Node) {
        let Node::PolicySet(policy_set) = node else {
            return;
        };

        let has_enforce_policy = policy_set
            .policies
            .iter()
            .any(|policy| policy.disposition == Disposition::Enforce);

        if !has_enforce_policy {
            report.add_issue(
                Issue::builder()
                    .severity(Severity::Critical)
                    .description("No Content-Security-Policy header found.".to_string())
                    .build(),
            );
        }
    }
}
