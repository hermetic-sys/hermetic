# Hermetic Commercial License

> **This document is a summary of commercial license terms, not the license itself.** The binding commercial license agreement is provided upon purchase. This summary is for evaluation purposes. If you have questions, email [license@hermeticsys.com](mailto:license@hermeticsys.com).

---

## When Do You Need a Commercial License?

Hermetic is distributed as a compiled binary (free for Community, licensed for Pro). The cryptographic core (hermetic-core, hermetic-transport, hermetic-sdk) is open source under [AGPL-3.0-or-later](LICENSE) on GitHub. A commercial license is needed if:

- **You modify the open-source crates and deploy those modifications as a network service** and do not want to publish your source code (the AGPL network clause requires this).
- **Your organization's policy prohibits AGPL software** in production systems.
- **You need more than 1 environment or more than 7 days of audit retention** — these are Community Edition limits. Pro tier expands these.
- **You need priority CVE notifications, signed binary builds, SLA guarantees, or indemnification.**

If none of these apply, the Community Edition is free forever with no registration required.

---

## What the Commercial License Grants

A commercial license grants the licensee:

1. **AGPL obligation waiver.** You may use, modify, and deploy Hermetic without publishing source code or providing AGPL-mandated notices to network users. The waiver applies to the version purchased and all minor/patch releases within that major version.

2. **Expanded operational limits.** The Community Edition limits are lifted or expanded according to your tier.

3. **License key.** An offline HMAC-SHA256 license key file (`license.key`) that unlocks your tier's limits. No phone-home, no activation server, no telemetry.

---

## Tiers

| | Community (Free) | Pro (Coming Soon) |
|---|---|---|
| **Price** | Free forever | Coming soon |
| **License** | Binary: proprietary (free). Core crates: AGPL-3.0-or-later | Commercial (AGPL waived) |
| **Secrets** | 10 | Unlimited |
| **Named environments** | 1 (`default`) | Unlimited |
| **Templates** | 26 | 115 |
| **Audit log retention** | 7 days | Unlimited |
| **OAuth2 lifecycle** | — | ✓ |
| **AWS SigV4 signing** | — | ✓ |
| **TUI + Web dashboards** | — | ✓ |
| **Token monitoring** | — | ✓ |
| **Priority CVE notifications** | — | ✓ |
| **Signed binary builds** | — | ✓ |
| **Support** | Community (GitHub Issues) | Email (SLA-bound) |

---

## Security Is Never Gated

All security features are identical across all tiers. The following are universal and cannot be removed, downgraded, or gated behind a commercial license:

- Vault encryption (Argon2id KDF, AES-256-GCM per-secret, SQLCipher page-level)
- Handle protocol (256-bit CSPRNG, single-use, UID-bound, domain-bound, version-fingerprinted)
- SSRF protection (blocked IP ranges, DNS pinning, per-hop redirect re-validation)
- OS hardening (mlockall, PR_SET_DUMPABLE, privilege restriction — all FATAL)
- MCP bridge (5 tools, stdout purity, no secrets in responses)
- Python SDK (PyO3, escape-hatch blocking)
- All constitutional amendments 
- HMAC-SHA256 tamper-evident audit chain (retention period varies by tier; chain integrity is universal)
- Session persistence (encrypted reboot recovery)
- Terminal output sanitization 

This is a foundational commitment: no security property will ever be used as a commercial differentiator.

---

## Community Edition Limits (CL Amendments)

The Community Edition enforces four limits via constitutional amendments. These limits are designed to be natural upgrade triggers for teams, not punishments for individuals.

**Single named environment.** Only the `default` environment is available. Attempting to create or use a non-default environment returns an error. Enforced at daemon startup.

**7-day audit log retention.** Audit entries older than 7 days are pruned on daemon startup and every 24 hours during operation. The HMAC-SHA256 chain remains intact over the retained window.

**Community Edition banner.** A non-intrusive banner is displayed on daemon stderr and in the MCP `initialize` response identifying the Community Edition. This does not affect functionality.

**10-secret limit.** The Community Edition supports up to 10 secrets. Attempting to add an 11th returns an error with upgrade instructions.

### Fail-Open Behavior

All tier limits fail open:

- A corrupt or missing `license.key` file defaults to Community Edition behavior.
- A limit check failure (e.g., creating a second named environment in Community) returns a clear error message — it never causes a crash, data loss, or vault corruption.
- An expired license key reverts to Community limits. Existing secrets remain accessible; existing environments remain readable. You lose the expanded limits, not your data.

This is intentional. The AGPL is the real enforcement mechanism, not DRM.

---

## License Key

The commercial license is delivered as an offline `license.key` file using HMAC-SHA256. Place it at `~/.hermetic/license.key`.

- No internet connection required for validation.
- No telemetry, phone-home, or activation server.
- No expiry check against an external clock (the key contains its own expiry date, verified locally).
- The license key mechanism is intentionally transparent: the validation logic is in the open-source codebase. We rely on the AGPL for enforcement, not on obfuscation.

---

## What You Are Purchasing

When you purchase a commercial license, you receive:

1. A signed commercial license agreement (PDF) granting AGPL obligation waiver for the specified tier and term.
2. A `license.key` file for offline tier activation.
3. Access to the support channel corresponding to your tier.
4. A named point of contact and SLA agreement (Pro).

The license is per-organization, not per-machine. You may deploy Hermetic on as many machines as needed within your organization.

---

## FAQ

**Can I evaluate Hermetic commercially before purchasing?**
Yes. The Community Edition is fully functional for evaluation with 10 secrets, 1 environment, and 7-day audit retention. No time limit on evaluation.

**What happens if I let my license expire?**
Hermetic reverts to Community Edition limits. Your vault, secrets, and audit log remain intact. You can renew at any time to restore expanded limits.

**Can I use the Community Edition in production?**
Yes. The Community binary is free for any use. The AGPL applies only to the open-source crates (hermetic-core, hermetic-transport, hermetic-sdk). If you modify those crates and deploy the modifications as a network service, you must publish your source code.

**Does the commercial license cover my entire organization?**
The Pro license is per-organization — all employees, contractors, and CI/CD systems within the licensed organization are covered.

**Can I redistribute Hermetic with my product?**
Under the AGPL, yes — with full source disclosure. Under a commercial license, yes — without source disclosure, subject to the terms of your license agreement. If you need to embed or redistribute Hermetic, email [license@hermeticsys.com](mailto:license@hermeticsys.com) to discuss OEM terms.

**Is there a free tier for open-source projects?**
The Community Edition is free forever. Open-source projects can use it without restriction. If your open-source project needs more than 10 secrets or multiple environments, contact us — we offer free Pro licenses for qualifying OSS projects.

---

## Purchase

**Pro (coming soon):** Email [license@hermeticsys.com](mailto:license@hermeticsys.com) to join the waitlist. Pricing and availability will be announced on [hermeticsys.com](https://hermeticsys.com).

---

> **DRAFT — PENDING LEGAL REVIEW**
>
> This document describes intended commercial terms. The binding license agreement will be reviewed by legal counsel before any commercial license is sold. Terms may change. This notice will be removed when the final version is published.
>
> Questions: [license@hermeticsys.com](mailto:license@hermeticsys.com)

---

<p align="center">
<a href="https://hermeticsys.com">hermeticsys.com</a> · AGPL-3.0-or-later
</p>
