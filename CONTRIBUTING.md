# Contributing to Hermetic

Thank you for your interest in contributing to Hermetic. This document explains how to contribute and what to expect.

## Contributor License Agreement (CLA)

All contributors must sign the Individual CLA before their first pull request can be merged. This is enforced automatically — when you open a PR, [CLA Assistant](https://cla-assistant.io/) will comment with a link to sign electronically via GitHub. One click, 30 seconds.

If you're contributing on behalf of your employer, your organization needs to execute the Corporate CLA. Email [license@hermeticsys.com](mailto:license@hermeticsys.com) with your organization name and the GitHub usernames of authorized contributors.

The full text of both agreements is published for review: [Individual CLA](docs/legal/ICLA.md) · [Corporate CLA](docs/legal/CCLA.md). The ICLA is signed through CLA Assistant's GitHub integration. The CCLA is signed via email to license@hermeticsys.com.

**Why a CLA?** Hermetic uses AGPL-3.0-or-later with a commercial license option. The CLA ensures the project can continue to offer both open-source and commercial licenses. Without it, external contributions could create copyright ambiguities that block future licensing decisions.

## License

By contributing, you agree that your contributions will be licensed under the [GNU Affero General Public License v3](LICENSE) (AGPL-3.0-or-later).

## Commit Identity

All commits to this project use the project identity:

```
git config user.name "The Hermetic Project"
git config user.email "dev@hermeticsys.com"
```

**No personal names in tracked files.** No personal names in commit messages, no `Co-Authored-By` headers. This is project policy and applies to all contributors. Your contribution is credited through the CLA and GitHub's PR history, not through commit metadata.

Set this config on your fork before your first commit.

## How to Contribute

### The Easiest Contribution: Service Templates

Hermetic ships built-in service templates. Adding a new template is a 7-line JSON addition — no Rust code, no security review, no daemon changes:

```json
{
  "id": "your-service",
  "display_name": "Your Service",
  "allowed_domains": ["api.yourservice.com"],
  "auth_scheme": "bearer",
  "default_secret_name": "your_service_key",
  "test_url": "https://api.yourservice.com/v1/health",
  "hint": "https://yourservice.com/settings/api-keys"
}
```

Submit your template as a PR — template contributions are integrated by maintainers into the binary build. Run the tests and open a PR. This is the fastest path from "I want to contribute" to "merged."

### Bug Reports

Open an issue on GitHub with:

- Hermetic version (`hermetic version`)
- Operating system and kernel version (`uname -a`)
- Steps to reproduce
- Expected vs. actual behavior
- Output of `hermetic doctor` (if relevant)

**Security vulnerabilities:** Do NOT open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure.

### Code Contributions

1. Fork the repository
2. Configure commit identity (see above)
3. Create a feature branch from `main`
4. Make your changes
5. Run the full gate:
   ```bash
   cargo build -p hermetic-core -p hermetic-transport -p hermetic-sdk
   cargo test -p hermetic-core -p hermetic-transport -p hermetic-sdk
   cargo clippy -p hermetic-core -p hermetic-transport -p hermetic-sdk -- -D warnings
   cargo deny check licenses
   ```
7. Open a pull request against `main`

All PRs require CI to pass (build, test, clippy, deny) before merge. Branch protection is enforced — no force pushes to `main`, no merge without CI green.

### What We're Looking For

- Bug fixes with test coverage
- New service templates (see above — the lowest-friction contribution)
- Documentation improvements and typo fixes
- Fuzz target additions (new targets for under-covered code paths)
- Performance improvements backed by benchmarks
- Platform investigation (macOS, BSDs — V1 is Linux-only but we want to understand what's required)

### What Requires Discussion First

Open an issue to discuss **before** writing code for:

- New MCP tools or changes to existing tool schemas
- Changes to the wire protocol (length-prefixed framing, JSON-RPC handling)
- Any cryptographic changes (KDF parameters, encryption schemes, HKDF info strings)
- New external dependencies (we aim for minimal dependency surface)
- Changes to OS hardening behavior (mlockall, privilege restriction, ptrace)
- Constitutional amendment proposals (see below)

These areas affect security invariants that are governed by constitutional amendments. Changes require architectural review and may need formal amendment ratification before implementation.

### Constitutional Amendment Proposals

Hermetic's security decisions are formalized as constitutional amendments (HC-*, MCP-*, CC-*, SM-*, etc.) with binding language and code-level enforcement. The full registry is in [`docs/`](docs/).

If you identify a security gap or want to propose a new security invariant, you can propose a constitutional amendment by opening an issue with:

- The threat or gap the amendment addresses
- Proposed binding language (what must be true)
- Enforcement point (which code enforces it)
- How to verify compliance (test or gate check)

The maintainer reviews proposals and decides on ratification. Ratified amendments become binding on all future code changes.

## Code Standards

**Build gates (enforced in CI — your PR will not merge if any fails):**

- `cargo clippy -p hermetic-core -p hermetic-transport -p hermetic-sdk -- -D warnings` — zero warnings
- `cargo test -p hermetic-core -p hermetic-transport -p hermetic-sdk` — all tests pass
- `cargo deny check licenses` — all dependencies AGPL-compatible
- `RUSTFLAGS='-D warnings' cargo build -p hermetic-core -p hermetic-transport -p hermetic-sdk` — zero compiler warnings

**Code rules:**

- All new code must have tests. Security-critical code must have fuzz targets.
- `hermetic-core` and `hermetic-transport` enforce `#![forbid(unsafe_code)]` at the crate level. No exceptions.
- All other production crates enforce `#![deny(unsafe_code)]`. Any use of `unsafe` requires a documented justification in the PR description explaining why safe alternatives are insufficient, what invariants the unsafe block maintains, and how it is tested.
- Secret-handling code must use `Zeroizing<Vec<u8>>` wrappers. Raw `Vec<u8>` for secret material will be rejected in review.
- No `println!` or `print!` in `hermetic-mcp` — stdout is the JSON-RPC wire. All diagnostics go through `ui::` on stderr.

## Review Process

Pull requests are reviewed by the project maintainer. Expect a response within 7 days for straightforward changes (templates, docs, bug fixes). Changes touching security-critical paths (daemon, transport, core, MCP) may take longer and will receive more thorough review.

Review priorities: correctness first, then security invariant preservation, then style. We will not block a good bug fix over formatting preferences.

## Governance

Hermetic is governed by the **HAIG Framework** (Human-AI Integrated Governance). The Constitutional Authority (human maintainer) has final decision on all architectural and security matters. This is a benevolent-dictator model with formal process: every security decision is traceable to an amendment, every implementation is gated, and every claim is backed by evidence.

See the [governance documentation](docs/) and [amendment registry](docs/) for the full framework.

## Code of Conduct

This project follows the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md). Be respectful, constructive, and professional.

## Questions?

- General questions: Open a GitHub Discussion
- Security issues: [security@hermeticsys.com](mailto:security@hermeticsys.com)
- Licensing and CLA: [license@hermeticsys.com](mailto:license@hermeticsys.com)
- Everything else: [dev@hermeticsys.com](mailto:dev@hermeticsys.com)
