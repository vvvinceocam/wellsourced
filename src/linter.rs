pub mod rules;

use crate::{
    linter::rules::get_rules,
    policy::{Directive, Policy, PolicySet, Source},
    report::Report,
};

pub enum Node<'a> {
    PolicySet(&'a PolicySet),
    Policy(&'a Policy),
    Directive(&'a Directive),
    Source(&'a Source),
}

pub trait Rule {
    fn check(&self, origin: Option<String>, report: &mut Report, node: Node);
}

pub fn lint(report: &mut Report, origin: Option<String>, policy_set: PolicySet) {
    let rules = get_rules();

    for rule in &rules {
        rule.check(origin.clone(), report, Node::PolicySet(&policy_set));
    }

    for policy in &policy_set.policies {
        for rule in &rules {
            rule.check(origin.clone(), report, Node::Policy(policy));
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
}
