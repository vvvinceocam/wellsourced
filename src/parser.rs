use std::ops::Range;

use winnow::{
    LocatingSlice, Parser, Result,
    ascii::{self, dec_uint},
    combinator::{alt, delimited, empty, eof, opt, preceded, separated, seq, terminated},
    stream::AsChar,
    token::{rest, take_till, take_while},
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

fn is_source_char(c: char) -> bool {
    !(c.is_ascii_whitespace() || c == ';')
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
    take_while(1.., is_name_char)
        .map(|name: &str| match name {
            "default-src" => DefaultSrc,
            "font-src" => FontSrc,
            "script-src" => ScriptSrc,
            "script-src-attr" => ScriptSrcAttr,
            "script-src-elem" => ScriptSrcElem,
            "style-src" => StyleSrc,
            "style-src-attr" => StyleSrcAttr,
            "style-src-elem" => StyleSrcElem,
            "trusted-types" => TrustedTypes,
            "img-src" => ImgSrc,
            "child-src" => ChildSrc,
            "manifest-src" => ManifestSrc,
            "media-src" => MediaSrc,
            "object-src" => ObjectSrc,
            "connect-src" => ConnectSrc,
            "plugin-types" => PluginTypes,
            "prefetch-src" => PrefetchSrc,
            "frame-src" => FrameSrc,
            "fence-frame-src" => FenceFrameSrc,
            "worker-src" => WorkerSrc,
            "report-to" => ReportTo,
            "report-uri" => ReportUri,
            "base-uri" => BaseUri,
            "form-action" => FormAction,
            "frame-ancestors" => FrameAncestors,
            "navigation-src" => NavigationSrc,
            "sandbox" => Sandbox,
            "upgrade-insecure-requests" => UpgradeInsecureRequests,
            "require-trusted-types-for" => RequireTrustedTypesFor,
            "block-all-mixed-content" => BlockAllMixedContent,
            _ => Unknown(name.to_string()),
        })
        .with_span()
        .parse_next(input)
}

fn source(input: &mut LocatingSlice<&str>) -> Result<Source> {
    use SourceExpression::*;

    take_while(1.., is_source_char)
        .and_then(alt((
            keyword_source.map(Keyword),
            nonce_source.map(Nonce),
            hash_source.map(Hash),
            terminated(scheme_source, eof).map(Scheme),
            terminated(host_source, eof).map(Host),
            rest.map(|str: &str| Unknown(str.to_string())),
        )))
        .with_span()
        .map(|(expression, span)| Source { expression, span })
        .parse_next(input)
}

fn keyword_source(input: &mut &str) -> Result<KeywordSource> {
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

fn nonce_source(input: &mut &str) -> Result<NonceSource> {
    delimited("'nonce-", nonce, "'")
        .map(NonceSource)
        .parse_next(input)
}

fn nonce(input: &mut &str) -> Result<String> {
    take_while(1.., is_base64_char)
        .map(|nonce: &str| nonce.to_string())
        .parse_next(input)
}

fn hash_source(input: &mut &str) -> Result<HashSource> {
    seq! {HashSource {
        _: '\'',
        algorithm: hash_algorithm,
        _: '-',
        digest: digest,
        _: '\'',
    }}
    .parse_next(input)
}

fn hash_algorithm(input: &mut &str) -> Result<HashAlgorithm> {
    use HashAlgorithm::*;
    alt((
        "sha256".value(Sha256),
        "sha384".value(Sha384),
        "sha512".value(Sha512),
    ))
    .parse_next(input)
}

fn digest(input: &mut &str) -> Result<String> {
    take_while(1.., is_base64_char)
        .map(|digest: &str| digest.to_string())
        .parse_next(input)
}

fn scheme_source(input: &mut &str) -> Result<SchemeSource> {
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

fn host_label(input: &mut &str) -> Result<String> {
    take_while(1.., |c: char| c.is_ascii_alphanumeric() || c == '-')
        .map(|part: &str| part.to_string())
        .parse_next(input)
}

fn host_part(input: &mut &str) -> Result<String> {
    separated(1.., host_label, '.')
        .map(|parts: Vec<String>| parts.join("."))
        .parse_next(input)
}

fn path_part(input: &mut &str) -> Result<String> {
    (
        '/',
        take_till(0.., |c: char| c.is_space() || c == ';' || c == ','),
    )
        .take()
        .map(|path: &str| path.to_string())
        .parse_next(input)
}

fn host_source(input: &mut &str) -> Result<HostSource> {
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
    fn parse_source() {
        let cases = [
            ("'self'", SourceExpression::Keyword(KeywordSource::Self_)),
            ("'self';", SourceExpression::Keyword(KeywordSource::Self_)),
            (
                "'self' 'foo'",
                SourceExpression::Keyword(KeywordSource::Self_),
            ),
            ("'none'", SourceExpression::Keyword(KeywordSource::None)),
            (
                "'strict-dynamic'",
                SourceExpression::Keyword(KeywordSource::StrictDynamic),
            ),
            ("wss:", SourceExpression::Scheme(SchemeSource::Wss)),
            ("wss: ", SourceExpression::Scheme(SchemeSource::Wss)),
            ("wss:;", SourceExpression::Scheme(SchemeSource::Wss)),
            (
                "wss: example.com",
                SourceExpression::Scheme(SchemeSource::Wss),
            ),
            ("https:", SourceExpression::Scheme(SchemeSource::Https)),
            ("blob:", SourceExpression::Scheme(SchemeSource::Blob)),
            (
                "'nonce-x1234567890'",
                SourceExpression::Nonce(NonceSource("x1234567890".to_string())),
            ),
            (
                "'sha256-0987654321'",
                SourceExpression::Hash(HashSource {
                    algorithm: HashAlgorithm::Sha256,
                    digest: "0987654321".to_string(),
                }),
            ),
            (
                "https://example.com:8080/some/path",
                SourceExpression::Host(HostSource {
                    scheme: Some(SchemeSource::Https),
                    host: Host::Fqdn("example.com".to_string()),
                    port: Some(8080),
                    path: Some("/some/path".to_string()),
                }),
            ),
            (
                "http://localhost",
                SourceExpression::Host(HostSource {
                    scheme: Some(SchemeSource::Http),
                    host: Host::Fqdn("localhost".to_string()),
                    port: None,
                    path: None,
                }),
            ),
            (
                "localhost/login",
                SourceExpression::Host(HostSource {
                    scheme: None,
                    host: Host::Fqdn("localhost".to_string()),
                    port: None,
                    path: Some("/login".to_string()),
                }),
            ),
            (
                "https:9000/login",
                SourceExpression::Host(HostSource {
                    scheme: None,
                    host: Host::Fqdn("https".to_string()),
                    port: Some(9000),
                    path: Some("/login".to_string()),
                }),
            ),
            (
                "https:/login",
                SourceExpression::Unknown("https:/login".to_string()),
            ),
            (
                "*.other.com",
                SourceExpression::Host(HostSource {
                    scheme: None,
                    host: Host::Wildcard("other.com".to_string()),
                    port: None,
                    path: None,
                }),
            ),
            ("'foo'", SourceExpression::Unknown("'foo'".to_string())),
        ];

        for (input, expected) in cases {
            let input = LocatingSlice::new(input);
            let (_, Source { expression, .. }) = source.parse_peek(input).unwrap();
            assert_eq!(expression, expected);
        }
    }

    #[test]
    fn parse_multi_directive_policy() {
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
