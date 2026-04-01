# License FAQ

Hermetic is licensed under the [GNU Affero General Public License v3](../LICENSE) (AGPL-3.0-or-later). Commercial licenses are available for organizations that need AGPL obligation waivers. This page answers the questions we hear most.

---

## Do I need a commercial license?

**Probably not.** Most users don't.

You do **NOT** need a commercial license if you:

- Use Hermetic unmodified, for any purpose, at any scale — personal, startup, enterprise.
- Use Hermetic alongside your application as a separate process (the AGPL applies to Hermetic, not to software that communicates with it over a socket or stdio).
- Contribute to the open-source project under the [CLA](../CONTRIBUTING.md).
- Conduct security research, auditing, or evaluation.

You **DO** need a commercial license if you:

- **Modify Hermetic's source code AND deploy those modifications as part of a network service** without publishing your changes. This is the AGPL network clause — the only AGPL obligation that goes beyond standard GPL.
- **Your organization's legal policy prohibits AGPL software** in production, regardless of how you use it. Some compliance teams blanket-block AGPL. A commercial license resolves this.
- **You need expanded operational limits** — more than 1 named environment or more than 7 days of audit log retention.

---

## What triggers the AGPL network clause?

The AGPL network clause (Section 13) requires that if you modify Hermetic and make it available to users interacting with it over a network, you must offer those users the source code of your modified version.

**"Modify" means changing Hermetic's source code.** Using Hermetic unmodified — even running it as part of a larger system — does not trigger the clause.

**"Network interaction" means users interact with your modified Hermetic over a computer network.** If you run a modified Hermetic daemon that only you access locally, the clause doesn't apply. If you run it as part of a service that external users interact with, it does.

Using Hermetic's MCP tools from an AI agent is not network interaction with Hermetic — the agent communicates via local stdio, not over a network.

---

## Does the AGPL infect my application?

No. The AGPL applies to Hermetic and works derived from it. Your application communicates with Hermetic over a Unix domain socket (daemon) or stdio pipe (MCP). These are standard inter-process communication boundaries — your application is a separate work under copyright law.

If you copy Hermetic's source code into your application, that creates a derivative work and the AGPL applies to the combined work. If you communicate with Hermetic as a separate process, it does not.

---

## What are the Community Edition limits?

The Community Edition is free forever and enforces four limits via constitutional amendments:

| Limit | Amendment | What Happens |
|-------|-----------|-------------|
| 10 secrets | Adding an 11th secret returns an error with upgrade instructions. |
| 1 named environment (`default`) | Creating or using a non-default environment returns an error. |
| 7-day audit log retention | Entries older than 7 days are pruned on daemon startup and every 24 hours. |

A Community Edition banner appears on daemon stderr and in the MCP `initialize` response. This does not affect functionality.

**All limits fail open.** A corrupt or missing license key defaults to Community behavior. An expired license reverts to Community limits. Your vault, secrets, and audit log remain intact. You never lose data — you lose expanded limits.

---

## What does a commercial license include?

1. **AGPL obligation waiver** — use, modify, and deploy without source disclosure.
2. **Expanded limits** — unlimited secrets, unlimited environments, unlimited audit retention.
3. **Offline license key** — HMAC-SHA256 `license.key` file. No internet required, no telemetry, no phone-home.
4. **Support** — SLA-bound email support.

---

## How much does it cost?

| Tier | Price | Secrets | Environments | Audit Retention |
|------|-------|---------|--------------|-----------------|
| Community | Free forever | 10 | 1 | 7 days |
| Pro | Coming soon | Unlimited | Unlimited | Unlimited |

The Pro license is per-organization — all employees, contractors, and CI/CD systems within the licensed organization are covered.

---

## Are any security features gated behind the commercial license?

No. Every security property is identical across all tiers:

- Vault encryption (Argon2id, AES-256-GCM, SQLCipher)
- Handle protocol (256-bit, single-use, UID-bound, domain-bound, version-fingerprinted)
- SSRF protection (blocked IP ranges, DNS pinning, redirect re-validation)
- OS hardening (mlockall, PR_SET_DUMPABLE, privilege restriction — all FATAL)
- All constitutional amendments
- Python SDK with escape-hatch blocking
- MCP bridge with 5 tools and stdout purity
- HMAC-SHA256 tamper-evident audit chain
- Session persistence

This is a permanent commitment. No security feature will ever be used as a commercial differentiator.

---

## What happens if my license expires?

Hermetic reverts to Community Edition limits. Your vault, secrets, and audit log remain intact and accessible. You can renew at any time to restore expanded limits. An expired license never causes data loss, crashes, or vault corruption.

---

## Can I evaluate Hermetic commercially before purchasing?

Yes. The Community Edition is fully functional for evaluation with 10 secrets and 1 environment. No time limit, no registration, no credit card.

---

## Can I use the Community Edition in production?

Yes. The Community binary is free for any use. The AGPL applies only to the open-source crates (hermetic-core, hermetic-transport, hermetic-sdk). If you modify those crates and deploy the modifications as a network service, you must publish your changes.

---

## Is there a free tier for open-source projects?

The Community Edition is free forever. Open-source projects can use it without restriction. If your OSS project needs more than 10 secrets or multiple environments, contact [license@hermeticsys.com](mailto:license@hermeticsys.com) — we offer free Pro licenses for qualifying open-source projects.

---

## Can I redistribute Hermetic with my product?

Under the AGPL: yes, with full source disclosure and AGPL compliance for the Hermetic component. Under a commercial license: yes, without source disclosure, subject to your license agreement. For OEM or embedding use cases, email [license@hermeticsys.com](mailto:license@hermeticsys.com).

---

## Who owns Hermetic?

Hermetic is published by The Hermetic Project. Copyright is held by the project, not by individual contributors (all contributors sign a [CLA](../CONTRIBUTING.md) that assigns copyright).

---

## Where can I get a commercial license?

**Pro (coming soon):** Email [license@hermeticsys.com](mailto:license@hermeticsys.com) to join the waitlist. Pricing and availability will be announced on [hermeticsys.com](https://hermeticsys.com).

**Questions:** If you're not sure whether you need a commercial license, ask. We'll tell you honestly — if you don't need one, we'll say so.
