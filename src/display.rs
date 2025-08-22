use std::fmt::Display;

use crate::policy::{
    Directive, DirectiveKind, HashAlgorithm, HashSource, Host, HostSource, KeywordSource,
    NonceSource, Policy, SchemeSource, Source, SourceExpression,
};

impl Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for directive in &self.directives {
            writeln!(f, "\n{}", directive)?;
        }

        Ok(())
    }
}

impl Display for Directive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:", self.kind)?;

        for source in &self.sources {
            write!(f, "\n   {}", source)?;
        }

        Ok(())
    }
}

impl Display for DirectiveKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use DirectiveKind::*;
        let kind = match self {
            DefaultSrc => "default-src",
            FontSrc => "font-src",
            ScriptSrc => "script-src",
            ScriptSrcAttr => "script-src-attr",
            ScriptSrcElem => "script-src-elem",
            StyleSrc => "style-src",
            StyleSrcAttr => "style-src-attr",
            StyleSrcElem => "style-src-elem",
            TrustedTypes => "trusted-types",
            ImgSrc => "img-src",
            ChildSrc => "child-src",
            ManifestSrc => "manifest-src",
            MediaSrc => "media-src",
            ObjectSrc => "object-src",
            ConnectSrc => "connect-src",
            PluginTypes => "plugin-types",
            PrefetchSrc => "prefetch-src",
            FrameSrc => "frame-src",
            FenceFrameSrc => "fence-frame-src",
            WorkerSrc => "worker-src",
            ReportTo => "report-to",
            ReportUri => "report-uri",
            BaseUri => "base-uri",
            FormAction => "form-action",
            FrameAncestors => "frame-ancestors",
            NavigationSrc => "navigation-src",
            Sandbox => "sandbox",
            UpgradeInsecureRequests => "upgrade-insecure-requests",
            RequireTrustedTypesFor => "require-trusted-types-for",
            BlockAllMixedContent => "block-all-mixed-content",
            Unknown(kind) => kind.as_str(),
        };
        write!(f, "{}", kind)
    }
}

impl Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.expression)
    }
}

impl Display for SourceExpression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            SourceExpression::Keyword(keyword_source) => write!(f, "{}", keyword_source),
            SourceExpression::Host(host_source) => write!(f, "{}", host_source),
            SourceExpression::Scheme(scheme_source) => write!(f, "{}", scheme_source),
            SourceExpression::Hash(hash_source) => write!(f, "{}", hash_source),
            SourceExpression::Nonce(nonce_source) => write!(f, "{}", nonce_source),
            SourceExpression::Unknown(source) => write!(f, "{source}"),
        }
    }
}

impl Display for KeywordSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match &self {
                KeywordSource::None => "'none'",
                KeywordSource::Self_ => "'self'",
                KeywordSource::UnsafeEval => "'unsafe-eval'",
                KeywordSource::UnsafeInline => "'unsafe-inline'",
                KeywordSource::WasmUnsafeEval => "'wasm-unsafe-eval'",
                KeywordSource::UnsafeHashes => "'unsafe-hashes'",
                KeywordSource::InlineSpeculationRules => "'inline-speculation-rules'",
                KeywordSource::StrictDynamic => "'strict-dynamic'",
                KeywordSource::ReportSample => "'report-sample'",
            }
        )
    }
}

impl Display for SchemeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match &self {
                SchemeSource::Http => "http:",
                SchemeSource::Https => "https:",
                SchemeSource::Ws => "ws:",
                SchemeSource::Wss => "wss:",
                SchemeSource::Data => "data:",
                SchemeSource::Blob => "blob:",
                SchemeSource::FileSystem => "filesystem:",
                SchemeSource::MediaStream => "mediastream:",
                SchemeSource::Unknown(scheme) => scheme,
            }
        )
    }
}

impl Display for HostSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(scheme) = &self.scheme {
            write!(f, "{}//", scheme)?;
        }

        match &self.host {
            Host::IpAddress(ip) => write!(f, "{ip}"),
            Host::Fqdn(fqdn) => write!(f, "{fqdn}"),
            Host::Wildcard(fqdn) => write!(f, "*.{fqdn}"),
        }?;

        if let Some(port) = &self.port {
            write!(f, ":{}", port)?;
        }

        if let Some(path) = &self.path {
            write!(f, "{}", path)?;
        }

        Ok(())
    }
}

impl Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                HashAlgorithm::Sha256 => "sha256",
                HashAlgorithm::Sha384 => "sha384",
                HashAlgorithm::Sha512 => "sha512",
            }
        )
    }
}

impl Display for HashSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "'{}-{}'", self.algorithm, self.digest)
    }
}

impl Display for NonceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "'nonce-{}'", self.0)
    }
}
