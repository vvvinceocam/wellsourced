use std::ops::Range;

use winnow::{
    LocatingSlice, Parser, Result,
    ascii::{self, dec_uint},
    combinator::{alt, delimited, empty, opt, preceded, separated, seq, terminated},
    stream::AsChar,
    token::{take_till, take_while},
};

use crate::policy::{
    Directive, DirectiveKind, HashAlgorithm, HashSource, Host, HostSource, KeywordSource,
    NonceSource, Policy, PolicyMode, SchemeSource, Source, SourceExpression,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserError {
    message: String,
}

impl ParserError {
    pub fn new(message: String) -> Self {
        Self { message }
    }
}

impl std::fmt::Display for ParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Parser Error: {}", self.message)
    }
}

impl std::error::Error for ParserError {}

pub fn parse_policy(raw_policy: &str, mode: PolicyMode) -> Result<Policy, ParserError> {
    let original = raw_policy.to_string();
    let directives = delimited(
        ascii::multispace0,
        directives,
        (opt(';'), ascii::multispace0),
    )
    .parse(LocatingSlice::new(raw_policy))
    .map_err(|err| ParserError::new(err.to_string()))?;

    Ok(Policy {
        directives,
        original,
        mode,
    })
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

fn is_base64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || ['-', '_', '%', '/', '=', '+'].contains(&c)
}

fn directives(input: &mut LocatingSlice<&str>) -> Result<Vec<Directive>> {
    separated(
        0..,
        directive,
        (ascii::multispace0, ";", ascii::multispace0),
    )
    .parse_next(input)
}

fn directive(input: &mut LocatingSlice<&str>) -> Result<Directive> {
    (
        terminated(directive_kind, ascii::space0),
        separated(0.., source, ascii::space1),
    )
        .with_span()
        .map(|(((kind, _kind_span), sources), span)| Directive {
            sources,
            kind,
            span,
        })
        .parse_next(input)
}

fn directive_kind(input: &mut LocatingSlice<&str>) -> Result<(DirectiveKind, Range<usize>)> {
    use DirectiveKind::*;
    alt((
        alt([
            "default-src".value(DefaultSrc),
            "font-src".value(FontSrc),
            "script-src".value(ScriptSrc),
            "script-src-attr".value(ScriptSrcAttr),
            "script-src-elem".value(ScriptSrcElem),
            "style-src".value(StyleSrc),
            "style-src-attr".value(StyleSrcAttr),
            "style-src-elem".value(StyleSrcElem),
            "trusted-types".value(TrustedTypes),
            "img-src".value(ImgSrc),
            "child-src".value(ChildSrc),
            "manifest-src".value(ManifestSrc),
            "media-src".value(MediaSrc),
            "object-src".value(ObjectSrc),
            "connect-src".value(ConnectSrc),
            "plugin-types".value(PluginTypes),
            "prefetch-src".value(PrefetchSrc),
            "frame-src".value(FrameSrc),
            "fence-frame-src".value(FenceFrameSrc),
            "worker-src".value(WorkerSrc),
            "report-to".value(ReportTo),
            "report-uri".value(ReportUri),
            "base-uri".value(BaseUri),
            "form-action".value(FormAction),
            "frame-ancestors".value(FrameAncestors),
            "navigation-src".value(NavigationSrc),
            "sandbox".value(Sandbox),
            "upgrade-insecure-requests".value(UpgradeInsecureRequests),
            "require-trusted-types-for".value(RequireTrustedTypesFor),
            "block-all-mixed-content".value(BlockAllMixedContent),
        ]),
        take_while(1.., is_name_char).map(|unknown: &str| Unknown(unknown.to_string())),
    ))
    .with_span()
    .parse_next(input)
}

fn source(input: &mut LocatingSlice<&str>) -> Result<Source> {
    use SourceExpression::*;

    alt((
        keyword_source.map(Keyword),
        nonce_source.map(Nonce),
        hash_source.map(Hash),
        host_source.map(Host),
        scheme_source.map(Scheme),
        take_till(1.., |c: char| c.is_ascii_whitespace() || c == ';')
            .map(|str: &str| Unknown(str.to_string())),
    ))
    .with_span()
    .map(|(expression, span)| Source { expression, span })
    .parse_next(input)
}

fn keyword_source(input: &mut LocatingSlice<&str>) -> Result<KeywordSource> {
    use KeywordSource::*;
    alt([
        "'none'".value(None),
        "'self'".value(Self_),
        "'unsafe-eval'".value(UnsafeEval),
        "'unsafe-inline'".value(UnsafeInline),
        "'wasm-unsafe-eval'".value(WasmUnsafeEval),
        "'unsafe-hashes'".value(UnsafeHashes),
        "'inline-speculation-rules'".value(InlineSpeculationRules),
        "'strict-dynamic'".value(StrictDynamic),
        "'report-sample'".value(ReportSample),
    ])
    .parse_next(input)
}

fn nonce_source(input: &mut LocatingSlice<&str>) -> Result<NonceSource> {
    delimited("'nonce-", nonce, "'")
        .map(NonceSource)
        .parse_next(input)
}

fn nonce(input: &mut LocatingSlice<&str>) -> Result<String> {
    take_while(1.., is_base64_char)
        .map(|nonce: &str| nonce.to_string())
        .parse_next(input)
}

fn hash_source(input: &mut LocatingSlice<&str>) -> Result<HashSource> {
    seq! {HashSource {
        _: '\'',
        algorithm: hash_algorithm,
        _: '-',
        digest: digest,
        _: '\'',
    }}
    .parse_next(input)
}

fn hash_algorithm(input: &mut LocatingSlice<&str>) -> Result<HashAlgorithm> {
    use HashAlgorithm::*;
    alt((
        "sha256".value(Sha256),
        "sha384".value(Sha384),
        "sha512".value(Sha512),
    ))
    .parse_next(input)
}

fn digest(input: &mut LocatingSlice<&str>) -> Result<String> {
    take_while(1.., is_base64_char)
        .map(|digest: &str| digest.to_string())
        .parse_next(input)
}

fn scheme_source(input: &mut LocatingSlice<&str>) -> Result<SchemeSource> {
    use SchemeSource::*;
    alt((
        "http:".value(Http),
        "https:".value(Https),
        "ws:".value(Ws),
        "wss:".value(Wss),
        "data:".value(Data),
        "blob:".value(Blob),
        "filesystem:".value(FileSystem),
        "mediastream:".value(MediaStream),
        terminated(take_while(1.., is_name_char), ':')
            .map(|unknown: &str| Unknown(unknown.to_string())),
    ))
    .parse_next(input)
}

fn host_label(input: &mut LocatingSlice<&str>) -> Result<String> {
    take_while(1.., |c: char| c.is_ascii_alphanumeric() || c == '-')
        .map(|part: &str| part.to_string())
        .parse_next(input)
}

fn host_part(input: &mut LocatingSlice<&str>) -> Result<String> {
    separated(2.., host_label, '.')
        .map(|parts: Vec<String>| parts.join("."))
        .parse_next(input)
}

fn path_part(input: &mut LocatingSlice<&str>) -> Result<String> {
    (
        '/',
        take_till(0.., |c: char| c.is_space() || c == ';' || c == ','),
    )
        .take()
        .map(|path: &str| path.to_string())
        .parse_next(input)
}

fn host_source(input: &mut LocatingSlice<&str>) -> Result<HostSource> {
    alt((
        seq! {HostSource{
            scheme: terminated(scheme_source, "//").map(Some),
            host: alt((
                preceded("*.", host_part).map(Host::Wildcard),
                host_part.map(Host::Fqdn),
            )),
            port: opt(preceded(':', dec_uint)),
            path: opt(path_part),
        }},
        seq! {HostSource{
            scheme: empty.value(None),
            host: alt((
                preceded("*.", host_part).map(Host::Wildcard),
                host_part.map(Host::Fqdn),
            )),
            port: opt(preceded(':', dec_uint)),
            path: opt(path_part),
        }},
    ))
    .parse_next(input)
}

#[cfg(test)]
mod tests {
    use crate::policy::KeywordSource;

    use super::*;

    #[test]
    fn test_parse_policy() {
        let policy = parse_policy(
            "default-src 'self'; script-src 'self' 'unsafe-inline' https: http://example.com:8080/foo/bar",
            PolicyMode::Enforce,
        ).unwrap();
        assert_eq!(policy.directives.len(), 2);
        assert_eq!(policy.directives[0].kind, DirectiveKind::DefaultSrc);
        assert_eq!(policy.directives[0].span, 0..18);
        assert_eq!(policy.directives[0].sources.len(), 1);
        assert_eq!(
            policy.directives[0].sources[0],
            Source {
                expression: SourceExpression::Keyword(KeywordSource::Self_),
                span: 12..18,
            }
        );
        assert_eq!(policy.directives[1].kind, DirectiveKind::ScriptSrc);
        assert_eq!(policy.directives[1].span, 20..92);
        assert_eq!(policy.directives[1].sources.len(), 4);
        assert_eq!(
            policy.directives[1].sources[0],
            Source {
                expression: SourceExpression::Keyword(KeywordSource::Self_),
                span: 31..37,
            }
        );
        assert_eq!(
            policy.directives[1].sources[1],
            Source {
                expression: SourceExpression::Keyword(KeywordSource::UnsafeInline),
                span: 38..53,
            }
        );
        assert_eq!(
            policy.directives[1].sources[2],
            Source {
                expression: SourceExpression::Scheme(SchemeSource::Https),
                span: 54..60,
            }
        );
        assert_eq!(
            policy.directives[1].sources[3],
            Source {
                expression: SourceExpression::Host(HostSource {
                    scheme: Some(SchemeSource::Http),
                    host: Host::Fqdn("example.com".to_string()),
                    port: Some(8080),
                    path: Some("/foo/bar".to_string())
                }),
                span: 61..92,
            }
        );
    }
}
