use std::ops::Range;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Disposition {
    Enforce,
    Report,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Policy {
    pub original: String,
    pub disposition: Disposition,
    pub directives: Vec<Directive>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Directive {
    pub kind: DirectiveKind,
    pub sources: Vec<Source>,
    pub span: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DirectiveKind {
    // Fetching Directives
    DefaultSrc,
    FontSrc,
    ScriptSrc,
    ScriptSrcAttr,
    ScriptSrcElem,
    StyleSrc,
    StyleSrcAttr,
    StyleSrcElem,
    TrustedTypes,
    ImgSrc,
    ChildSrc,
    ManifestSrc,
    MediaSrc,
    ObjectSrc,
    ConnectSrc,
    PluginTypes,
    PrefetchSrc,
    FrameSrc,
    FenceFrameSrc,
    WorkerSrc,

    // Reporting Directives
    ReportTo,
    ReportUri,

    // Contextual Directives
    BaseUri,
    FormAction,
    FrameAncestors,
    NavigationSrc,
    Sandbox,
    UpgradeInsecureRequests,
    RequireTrustedTypesFor,
    BlockAllMixedContent,

    // Other
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Source {
    pub expression: SourceExpression,
    pub span: Range<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SourceExpression {
    Keyword(KeywordSource),
    Host(HostSource),
    Scheme(SchemeSource),
    Hash(HashSource),
    Nonce(NonceSource),
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeywordSource {
    None,
    Self_,
    UnsafeEval,
    UnsafeInline,
    WasmUnsafeEval,
    UnsafeHashes,
    InlineSpeculationRules,
    StrictDynamic,
    ReportSample,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostSource {
    pub scheme: Option<SchemeSource>,
    pub host: Host,
    pub port: Option<u16>,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    IpAddress(u8, u8, u8, u8),
    Fqdn(String),
    Wildcard(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SchemeSource {
    Http,
    Https,
    Ws,
    Wss,
    Data,
    Blob,
    FileSystem,
    MediaStream,
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HashSource {
    pub algorithm: HashAlgorithm,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NonceSource(pub String);

impl DirectiveKind {
    pub fn must_have_no_source(&self) -> bool {
        use DirectiveKind::*;

        matches!(
            self,
            UpgradeInsecureRequests | RequireTrustedTypesFor | BlockAllMixedContent
        )
    }
}
