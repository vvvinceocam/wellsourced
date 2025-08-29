pub mod rules;

use crate::{
    linter::rules::get_rules,
    policy::{Directive, Policy, Source},
    report::Report,
};

pub enum Node<'a> {
    Policy(&'a Policy),
    Directive(&'a Directive),
    Source(&'a Source),
}

pub trait Rule {
    fn check(&self, origin: Option<String>, report: &mut Report, node: Node);
}

pub fn lint(report: &mut Report, origin: Option<String>, policy: Policy) {
    let rules = get_rules();

    for rule in &rules {
        rule.check(origin.clone(), report, Node::Policy(&policy));
    }

    for directive in &policy.directives {
        for rule in &rules {
            rule.check(origin.clone(), report, Node::Directive(directive));

            for source in &directive.sources {
                for rule in &rules {
                    rule.check(origin.clone(), report, Node::Source(source));
                }
            }
        }
    }
}
