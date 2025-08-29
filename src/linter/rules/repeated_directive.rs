use std::collections::HashMap;

use crate::{
    linter::{Node, Rule},
    policy::{Directive, DirectiveKind},
    report::{Issue, Report, Severity},
};

pub struct RepeatedDirective {}

impl Rule for RepeatedDirective {
    fn check(&self, _origin: Option<String>, report: &mut Report, node: Node) {
        let Node::Policy(policy) = node else {
            return;
        };

        let mut directives_by_kind = HashMap::<DirectiveKind, Vec<&Directive>>::new();
        for directive in &policy.directives {
            directives_by_kind
                .entry(directive.kind.clone())
                .or_default()
                .push(directive);
        }

        for (kind, directives) in directives_by_kind {
            if directives.len() > 1 {
                report.add_issue(
                    Issue::builder()
                        .severity(Severity::Medium)
                        .description(format!("Repeated directive: \"{}\" is declared {} times. Only the first declaration is applied.", kind, directives.len()))
                        .build(),
                );
            }
        }
    }
}
