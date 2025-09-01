use crate::linter::Rule;

mod host_source_is_self;
mod insecure_scheme;
mod missing_source;
mod no_form_action;
mod no_upgrade_insecure_requests;
mod repeated_directive;
mod repeated_source;

pub fn get_rules() -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(host_source_is_self::HostSourceIsSelf {}),
        Box::new(insecure_scheme::InsecureScheme {}),
        Box::new(missing_source::MissingSource {}),
        Box::new(no_form_action::NoFormAction {}),
        Box::new(no_upgrade_insecure_requests::NoUpgradeInsecureRequests {}),
        Box::new(repeated_directive::RepeatedDirective {}),
        Box::new(repeated_source::RepeatedSource {}),
    ]
}
