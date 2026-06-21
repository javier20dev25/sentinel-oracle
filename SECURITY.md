# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

Sentinel Oracle is a community project with no paid security team. We rely on
the open-source community to help find and fix security issues.

If you discover a security vulnerability, please do **not** open a public
issue. Instead, send a private report to the repository maintainer:

- **GitHub Security Advisory**: Navigate to the repository's Security tab
  and click "Report a vulnerability" to file a private advisory.
- **Direct message**: Contact `@javier20dev25` on GitHub.

We aim to acknowledge receipt within 48 hours and provide an initial assessment
within 5 business days.

### What to Include

- A clear description of the vulnerability and its impact.
- Steps to reproduce (minimal proof of concept preferred).
- Affected versions and components.
- Any suggested fix or mitigation (optional).

### Scope

We are particularly interested in:

- Vulnerabilities in the authorization or cryptographic protocol.
- Bypasses of the three-device trust model.
- Remote code execution paths in the oracle server.
- Authentication or session management flaws.
- Secrets or credential exposure.

### Out of Scope

- Social engineering of repository maintainers.
- Physical attacks requiring theft of the oracle server hardware.
- Vulnerabilities in Tailscale, Node.js, or other third-party dependencies
  (report those to the respective projects).

## Disclosure Policy

We follow Coordinated Vulnerability Disclosure (CVD):

1. Reporter submits vulnerability privately.
2. Maintainer acknowledges and triages.
3. Fix is developed and tested.
4. Fix is released (patch version bump).
5. Vulnerability is publicly disclosed after the fix is available.

We aim for a 30-day maximum disclosure window from confirmation to public
release.

## Security-Related Configuration

See [Security Considerations](README.md#security-considerations) in the
README for recommended operational security practices.
