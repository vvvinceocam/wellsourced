use crate::{
    linter::{Node, Rule},
    policy::DirectiveKind,
    report::{Issue, Report, Severity},
};

pub struct NoUpgradeInsecureRequests {}

impl Rule for NoUpgradeInsecureRequests {
    fn check(&self, _origin: Option<String>, report: &mut Report, node: Node) {
        let Node::Policy(policy) = node else {
            return;
        };

        let has_upgrade_insecure_requests = policy
            .directives
            .iter()
            .any(|directive| directive.kind == DirectiveKind::UpgradeInsecureRequests);

        if !has_upgrade_insecure_requests {
            report.add_issue(
                Issue::builder()
                    .severity(Severity::High)
                    .description("No 'upgrade-insecure-requests' directive found. Set it to prevent insecure connections.".to_string())
                    .build()
            );
        }
    }
}
