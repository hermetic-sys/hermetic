<div align="center">

<!-- Logo -->
<img alt="Hermetic" src="assets/hermetic-logo.png" width="600">

<br/>
<br/>

**Agent-Isolated Credential Broker for AI Agents**

Your API keys never enter the AI agent's memory. Ever.

<br/>

[![Tests](https://img.shields.io/badge/tests-passing-brightgreen?style=flat-square&logo=rust&logoColor=white)](https://hermeticsys.com)
[![Fuzz](https://img.shields.io/badge/fuzz-0_crashes-blue?style=flat-square&logo=statuspage&logoColor=white)](https://hermeticsys.com)
[![Red Team](https://img.shields.io/badge/red_team-0_breaches-purple?style=flat-square&logo=hackaday&logoColor=white)](https://hermeticsys.com)
[![License](https://img.shields.io/badge/core-AGPL--3.0-orange?style=flat-square&logo=gnu&logoColor=white)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux_x86__64-lightgrey?style=flat-square&logo=linux&logoColor=white)](https://hermeticsys.com)

[Website](https://hermeticsys.com) · [Docs](https://hermeticsys.com/docs) · [Security](SECURITY.md) · [Waitlist](mailto:waitlist@hermeticsys.com)

</div>

<br/>

---

<br/>

## The Problem

Every supply chain attack in 2026 targets the same thing: **credentials stored in environment variables and `.env` files.**

```
# How most developers store API keys today:
export OPENAI_API_KEY=sk-proj-abc123          # ← In process.env. Any malware reads it.
echo "STRIPE_KEY=sk_live_..." >> .env         # ← On disk. Any script reads it.

# The Axios attack (March 31, 2026) stole every credential from 100M+ weekly installs.
# The LiteLLM attack (March 24, 2026) harvested os.environ on every Python startup.
# Your .env files are the target.
```

## The Fix

```
Agent  →  "call Stripe API"  →  Daemon (injects credential)  →  Stripe  →  response  →  Agent
                                  ↑ credential never leaves here
```

Hermetic is a local daemon that makes API calls **on behalf** of AI agents. The agent sends a request with an opaque 256-bit handle. The daemon resolves it to the real credential, makes the HTTPS call with full SSRF protection, and returns **only the API response**. The agent never sees, holds, or transmits the credential.

```bash
# Install (single binary, no dependencies)
curl -sSf https://hermeticsys.com/install.sh | sh

# Setup (60 seconds)
hermetic init                          # Encrypted vault (Argon2id, AES-256-GCM)
hermetic add --wizard                  # Auto-detects service from key prefix
hermetic start                         # Daemon holds keys in mlocked memory
hermetic mcp-config --install          # Configure Claude Code / Cursor / Windsurf
```

Your agent now uses `hermetic_authenticated_request` instead of raw API keys. Your `.env` files can be deleted.

<br/>

## How It Stops Real Attacks

<table>
<tr>
<td width="50%">

### Without Hermetic

```
RAT scans process.env     → ✗ STOLEN
RAT reads ~/.env files    → ✗ STOLEN
RAT reads ~/.aws/creds    → ✗ STOLEN
RAT sends key to C2       → ✗ EXFILTRATED
```

**Every credential exposed.**

</td>
<td width="50%">

### With Hermetic

```
RAT scans process.env     → ✓ Empty
RAT reads ~/.env files    → ✓ Deleted after import
RAT reads ~/.aws/creds    → ✓ In encrypted vault
RAT sends key to C2       → ✓ Domain binding: DENIED
```

**Nothing to steal.**

</td>
</tr>
</table>

> Tested against 10 real-world attacks including the [Axios supply chain compromise](https://hermeticsys.com/blog/axios-defense) (March 2026, North Korean APT), [LiteLLM .pth credential stealer](https://hermeticsys.com/blog/litellm-defense) (March 2026, TeamPCP), and [CVE-2025-6514 mcp-remote RCE](https://hermeticsys.com/blog/mcp-remote-defense) (CVSS 9.6). Full simulation results published.

<br/>

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Agent (Claude Code, Cursor, Windsurf, custom)   UNTRUSTED  │
└──────────────────────────┬──────────────────────────────────┘
                           │ MCP JSON-RPC / Python FFI
┌──────────────────────────┼──────────────────────────────────┐
│  Bridge (hermetic-mcp / hermetic-sdk)        PARTIAL TRUST  │
│  Secret in Zeroizing<Vec<u8>> for ~1ms                      │
└──────────────────────────┬──────────────────────────────────┘
                           │ Unix Domain Socket (4-byte framed)
┌──────────────────────────┼──────────────────────────────────┐
│  Daemon (hermetic-daemon)                        TRUSTED    │
│  Master key in mlocked memory. Never swapped.               │
└─────┬────────────────────┴──────────────┬───────────────────┘
      │                                   │
┌─────┴───────────────┐  ┌───────────────┴───────────────────┐
│  hermetic-core       │  │  hermetic-transport               │
│  Vault + KDF + Audit │  │  HTTPS + SSRF + DNS pin           │
└──────────────────────┘  └───────────────────────────────────┘
```

**Invariant:** No single component holds both the master key AND network exposure.

<br/>

## Open-Source Core

This repository contains the cryptographic foundation — every line of code that touches your secrets:

| Crate | LOC | What You Can Audit | License |
|:------|----:|:-------------------|:--------|
| [`hermetic-core`](crates/hermetic-core) | 5,900 | AES-256-GCM encryption, Argon2id KDF, HKDF key hierarchy, SQLCipher vault, HMAC-SHA256 audit chain | AGPL-3.0 |
| [`hermetic-transport`](crates/hermetic-transport) | 2,400 | SSRF defense with DNS pinning, forbidden header stripping, redirect re-validation | AGPL-3.0 |
| [`hermetic-sdk`](crates/hermetic-sdk) | 1,100 | Python FFI (PyO3), escape-hatch blocking on secret handles | AGPL-3.0 |

The daemon, MCP bridge, and CLI are distributed as **compiled binaries**. The crypto is open for audit. The product is protected.

```bash
# Audit the crypto yourself:
git clone https://github.com/hermetic-sys/hermetic
cargo check                            # Compiles the 3 open-source crates
cargo test -p hermetic-core            # Run crypto tests
```

<br/>

## Security Evidence

Most security tools ask you to trust their claims. We publish the proof.

| What We Publish | Status |
|:----------------|:-------|
| Automated test suite | Passing, 0 failures |
| Fuzz testing (libFuzzer + ASAN) | Billions of inputs, 0 crashes |
| Red team campaigns | Multiple campaigns, 0 breaches |
| Vulnerability history | Found, fixed, and disclosed |
| Threat model | Published in [docs/](docs/) |
| Known limitations | Published in README |
| Cryptographic source | Open (AGPL, this repo) |

<br/>

## Five Defense Layers

| # | Layer | Mechanism | What It Stops |
|:-:|:------|:----------|:--------------|
| 1 | **Agent Isolation** | Daemon makes the HTTP call. Agent gets response only. | RAT scanning `process.env` finds nothing |
| 2 | **Encrypted Vault** | SQLCipher + AES-256-GCM per secret. Memory-hard KDF. | `vault.db` = random bytes without passphrase |
| 3 | **Memory Protection** | Memory locking + dump prevention + zeroizing wrappers | No swap, no core dumps, no `/proc/pid/mem` |
| 4 | **Domain Binding** | Each credential locked to specific API domains at storage time | Credential redirect to attacker C2 → **DENIED** |
| 5 | **Import & Delete** | Quickstart imports `.env` → vault, optionally deletes originals | RAT scanning filesystem finds no `.env` files |

<br/>

## Verify Binary Integrity

```bash
sha256sum hermetic                     # Compare against release SHA256SUMS
gpg --import SIGNING_KEY.pub
gpg --verify hermetic-v1.0.0-linux-x86_64.sig hermetic-v1.0.0-linux-x86_64
```

<br/>

## Community vs Pro

Security is **never** gated behind a license tier.

| | Community | Pro |
|:--|:---------:|:---:|
| **Encrypted vault** | ✓ | ✓ |
| **Handle protocol** | ✓ | ✓ |
| **SSRF protection** | ✓ | ✓ |
| **5 MCP tools** | ✓ | ✓ |
| **Secrets** | 10 | Unlimited |
| **Environments** | 1 | Unlimited |
| **Templates** | 26 | 115 |
| **OAuth2 lifecycle** | — | ✓ |
| **AWS SigV4 signing** | — | ✓ |
| **Dashboards** | — | ✓ |
| | **Free forever** | **Coming soon** |

<br/>

## Scope

Hermetic v1 targets developer workstations where all processes run as the same Unix user. Per-process identity verification is planned for V2 (Gatekeeper).

<br/>

## License

| Component | License |
|:----------|:--------|
| hermetic-core, hermetic-transport, hermetic-sdk | [AGPL-3.0-or-later](LICENSE) |
| Hermetic binary (Community) | Proprietary — free forever |
| Hermetic binary (Pro) | Commercial — [coming soon](mailto:waitlist@hermeticsys.com) |

<br/>

<div align="center">

---

**[hermeticsys.com](https://hermeticsys.com)**

[Install](https://hermeticsys.com/install) · [Docs](https://hermeticsys.com/docs) · [Security](SECURITY.md) · [Waitlist](mailto:waitlist@hermeticsys.com)

<sub>Open-source crypto · Fuzz tested · Adversarially reviewed · Memory-safe Rust · Zero telemetry</sub>

</div>
