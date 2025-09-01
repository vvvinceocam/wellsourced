<p align="center">
  <img src="./logo.svg" width="250" />
</p>
<h1 align="center">wellsourced</h1>

> Content Security Policy made easy

`wellsourced` is a command-line toolkit designed to simplify working with
[Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP). While CSP is a powerful
mechanism, it can be challenging implementing it correctly. Whether you're implementing CSP for the first time or
maintaining existing policies, `wellsourced` provides tools to simplify CSP implementation.

At its core, CSP is a key *defense-in-depth* security mechanism for modern web applications. It helps mitigate the
impact of [cross-site scripting (XSS) attacks](https://owasp.org/www-community/Types_of_Cross-Site_Scripting) and other
types of injection attacks. CSP allows you to specify which sources of content your website is allowed to load, such as
scripts, stylesheets, images, and fonts, effectively preventing malicious scripts from being executed on your site.

## Features

### 🔍 CSP Auditing

`wellsourced audit`: Comprehensively audit CSP headers of any webpage:

- Identify policy gaps and security vulnerabilities
- Get actionable recommendations for policy improvements

### 📊 Report Collection

`wellsourced collect`: Lightweight microservice to collect CSP violation reports:

- Logging of policy violations
- Webhook integration for real-time notifications and alerting

## Quick Start

### Audit a Website's CSP

```bash
wellsourced audit https://example.com/specific/page
```

### Start collecting CSP reports

```bash
wellsourced collect \
    --webhook-url https://your-webhook.com/api \
    --webhook-template '{
        "channel": "your-channel-id",
        "message": "CSP violation detected\n{{ document-uri }}\n{{ referrer }}\n{{ blocked-uri }}\n{{ violation-type }}\n{{ effective-directive }}\n{{ original-policy }}\n{{ disposition }}"
    }'
```
