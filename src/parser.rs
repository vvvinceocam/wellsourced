use winnow::{
    Parser, Result, ascii,
    combinator::{delimited, opt, separated, separated_pair},
    error::{ContextError, ParseError},
    token::take_while,
};

#[derive(Debug)]
pub(crate) struct RawPolicy {
    pub directives: Vec<RawDirective>,
}

#[derive(Debug)]
pub(crate) struct RawDirective {
    pub name: String,
    pub sources: Vec<String>,
}

pub(crate) fn parse_policy(raw_csp: &str) -> Result<RawPolicy, ParseError<&str, ContextError>> {
    delimited(ascii::multispace0, policy, (opt(';'), ascii::multispace0)).parse(raw_csp)
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

fn is_value_char(c: char) -> bool {
    matches!(c, '\x21'..='\x2B' | '\x2D'..='\x3A' | '\x3C'..='\x7E')
}

fn policy(input: &mut &str) -> Result<RawPolicy> {
    separated(0.., directive, (";", ascii::multispace0))
        .map(|directives| RawPolicy { directives })
        .parse_next(input)
}

fn directive(input: &mut &str) -> Result<RawDirective> {
    separated_pair(
        directive_name,
        ascii::multispace1,
        separated(0.., source, ascii::multispace1),
    )
    .map(|(kind, sources)| RawDirective {
        name: kind,
        sources,
    })
    .parse_next(input)
}

fn directive_name(input: &mut &str) -> Result<String> {
    take_while(1.., is_name_char)
        .map(|kind: &str| kind.to_string())
        .parse_next(input)
}

fn source(input: &mut &str) -> Result<String> {
    take_while(1.., is_value_char)
        .map(str::to_string)
        .parse_next(input)
}
