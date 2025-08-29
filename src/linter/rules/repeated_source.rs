use std::collections::HashSet;

use crate::{
    linter::{Node, Rule},
    report::{Issue, Report, Severity},
};

pub struct RepeatedSource {}

impl Rule for RepeatedSource {
    fn check(&self, _origin: Option<String>, report: &mut Report, node: Node) {
        let Node::Directive(directive) = node else {
            return;
        };

        let mut seen = HashSet::new();

        for source in &directive.sources {
            let source = &source.expression;
            if seen.contains(&source) {
                report.add_issue(
                    Issue::builder()
                        .severity(Severity::Low)
                        .description(format!(
                            "Repeated source \"{}\" in directive \"{}\".",
                            &source, &directive.kind
                        ))
                        .build(),
                );
            } else {
                seen.insert(source);
            }
        }
    }
}
