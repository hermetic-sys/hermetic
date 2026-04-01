# Security Policy

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Email **[security@hermeticsys.com](mailto:security@hermeticsys.com)** with:

- Description of the vulnerability
- Steps to reproduce
- Affected component (e.g., vault, transport, daemon, SDK, MCP bridge)
- Impact assessment (what an attacker could achieve)
- Any suggested fix (optional, always appreciated)

You will receive a response — not an auto-reply.

## Safe Harbor

Hermetic considers security research conducted in good faith to be authorized and will not pursue legal action against researchers who:

- Act in good faith to avoid privacy violations, data destruction, and service disruption
- Report vulnerabilities through this channel before public disclosure
- Allow reasonable time for a fix before any public discussion
- Do not exploit vulnerabilities beyond what is necessary to demonstrate the issue

If you are uncertain whether your research qualifies, contact us first. We would rather hear about a potential issue than have a researcher stay silent out of concern.

## Response Timeline

| Severity | Acknowledgment | Initial Assessment | Fix Target | Disclosure |
|----------|---------------|-------------------|------------|------------|
| Critical | 24 hours | 48 hours | 48 hours | With fix release |
| High | 48 hours | 7 days | 7 days | With fix release |
| Medium | 48 hours | 7 days | 30 days | 90 days or fix release |
| Low | 72 hours | 14 days | Next release | 90 days or fix release |

Public disclosure follows the **90-day** standard: 90 days after the initial report, or when the fix is released, whichever comes first. If we need an extension, we will explain why and agree on a revised date with the reporter.

## What Qualifies

Any issue that undermines Hermetic's security properties is in scope:

- **Agent isolation bypass** — agent process obtains raw secret bytes through any path
- **Python SDK escape-hatch bypass** — circumventing introspection blocking to extract secret material into the Python runtime
- **Handle protocol violations** — replay, cross-process redemption, TTL bypass, or any path to redeem a handle more than once
- **SSRF protection bypass** — reaching private/reserved IP ranges, DNS rebinding, or redirect re-validation bypass
- **Cryptographic weaknesses** — flaws in key derivation, encryption, key hierarchy, or audit chain integrity
- **Memory safety violations** — secret material in unprotected memory (swap, core dumps, /proc)
- **Header injection** — bypassing forbidden header stripping
- **Shell injection** — bypassing the binary blocklist in env_spawn
- **Wire protocol vulnerabilities** — framing bypass, unbounded allocation, or deadline circumvention
- **Authentication bypass** — daemon socket access control failures
- **Audit log tampering** — modifying or replaying audit entries without detection
- **Domain binding bypass** — making an authenticated request to a domain not in the secret's allowed list

## What Does Not Qualify

- Bugs in development tooling, CI configuration, or documentation
- Denial of service via resource exhaustion on localhost (the daemon is local-only in V1)
- Social engineering attacks
- Vulnerabilities in dependencies that do not affect Hermetic's usage of them (please report upstream)
- Issues requiring root or elevated privileges (root bypasses all userspace protections)
- Same-UID process access to the daemon socket — this is a known V1 scoping decision, not a vulnerability
- Theoretical attacks requiring hardware memory forensics, CPU cache inspection, or VM snapshot analysis

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x | Active security support |
| < 1.0 | No support |

## How Security Fixes Are Tracked

Hermetic uses a constitutional governance model. Every security fix is formalized as a constitutional amendment with binding language, enforcement mechanism, and code-level verification.

We fix vulnerabilities — we do not hide them.

## Recognition

Security researchers who report valid vulnerabilities will be credited in the fix commit message, the corresponding constitutional amendment, and the project's security advisories — unless they prefer anonymity.

## Encryption

Reports can be encrypted with our GPG key ([`SIGNING_KEY.pub`](SIGNING_KEY.pub)):

```
Key: The Hermetic Project <dev@hermeticsys.com>
Fingerprint: 1C94 3CA5 FE21 E8CD 8662 AD6D 3B56 253D BD68 9474
Type: RSA 4096
```

If your report contains sensitive material (proof-of-concept exploits, credentials, or customer data), note this in your email subject line and we will establish an encrypted channel before you share details.

---

<p align="center">
<a href="https://hermeticsys.com">hermeticsys.com</a> · AGPL-3.0-or-later
</p>
