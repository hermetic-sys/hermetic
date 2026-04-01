# Getting Started with Hermetic

This guide walks you from zero to your first agent-authenticated API request. By the end, you will have a running Hermetic daemon with your API keys stored in an encrypted vault, and an MCP-connected AI agent making authenticated requests without ever seeing your secrets.

**Time required:** 5–10 minutes (you'll see a progress indicator during key derivation).

**Prerequisites:**
- Linux x86_64 (Ubuntu 24.04 LTS tested; Debian, Fedora, Arch, or any modern distro). Architecture depends on Unix domain sockets, SO_PEERCRED, and /proc — no macOS or Windows support in V1.

---

## 1. Install Hermetic

```bash
curl -sSf https://hermeticsys.com/install.sh | sh
```

This downloads and installs a single binary. Verify the installation:

```bash
hermetic version
```

---

## 2. The Fast Path: Quickstart

If you have a `.env` file with API keys, the quickstart wizard handles everything in one command:

```bash
cd your-project/
hermetic init --quickstart
```

The wizard walks through five steps:

**Step 1 — Create your vault.** You'll be prompted for a passphrase (minimum 12 characters). Hermetic derives the encryption key via Argon2id (memory-hard) — you'll see a progress indicator during key derivation. That deliberate cost is the security: it makes brute-force attacks computationally infeasible.

**Step 2 — Import your API keys.** The wizard detects `.env` files in the current directory, parses them, and matches keys against built-in service templates. For example, `ANTHROPIC_API_KEY` is auto-matched to the Anthropic template (auth scheme: x-api-key, allowed domain: api.anthropic.com). You confirm the import, and each key is encrypted individually with its own HKDF-derived key encryption key. Imported credentials are auto-verified against their service health endpoints so you know immediately if a key is valid.

**Step 3 — Start the daemon.** The daemon applies OS hardening (memory locking, privilege restriction, ptrace protection), binds a Unix domain socket at `~/.hermetic/default/daemon.sock` with 0600 permissions, and enters the accept loop. Your passphrase is reused from Step 1 — no re-entry.

**Step 4 — Verify your credentials.** Each imported key is tested against its service's health endpoint. You'll see a pass/fail status for each one.

**Step 5 — Configure your AI tool.** Choose Claude Code, Cursor, Windsurf, or skip. The wizard generates and optionally installs the MCP server configuration for your chosen platform.

After quickstart completes, you're running. Skip to [Section 5: Use It](#5-use-it).

---

## No .env? No problem

You don't need an existing `.env` file to get started. There are three paths:

**Inline batch wizard during quickstart.** When the quickstart wizard doesn't find a `.env` file, it falls back to an inline batch wizard — "Paste API keys now?" — letting you paste one or more keys directly. Each key is auto-detected against built-in service templates, configured, and encrypted on the spot.

**Scan your project for exposed keys.** *(Pro)*

```bash
hermetic scan .
```

Scans your project files for credentials that are hardcoded, committed, or otherwise exposed. Detected keys are offered for import into the vault so they can be removed from source.

**Manual paste with the batch wizard.**

```bash
hermetic add --wizard --batch
```

Walks you through adding multiple keys in one session. Each key is detected, configured, verified, and encrypted individually.

---

## 3. The Manual Path: Step by Step

If you prefer manual control, or don't have a `.env` file:

### 3.1 Create a vault

```bash
hermetic init
```

Choose a strong passphrase. The vault is created at `~/.hermetic/default/vault.db` with a unique 32-byte CSPRNG salt.

### 3.2 Store a secret

There are three paths for adding keys:

**Interactive wizard (default on TTY):**

```bash
hermetic add
```

On a TTY, the wizard launches automatically — you don't need the `--wizard` flag explicitly. It prompts for a secret name, reads the secret value with no terminal echo, detects the service from known API key prefixes (Stripe `sk_live_`, OpenAI `sk-proj-`, GitHub `ghp_`, Anthropic `key-`, and others), auto-configures the auth scheme and allowed domains, and prompts for tags (e.g. `prod,ai,payments`).

**Batch mode for multiple keys:**

```bash
hermetic add --wizard --batch
```

Walks you through adding multiple keys in one session — paste each one, confirm detection, and move to the next.

**Scan project files for exposed keys:** *(Pro)*

```bash
hermetic scan .
```

Scans your project for hardcoded or committed credentials and offers to import them into the vault.

**Explicit mode via stdin** (for scripting or CI):

```bash
echo -n "sk-proj-your-openai-key" | hermetic add openai-key \
  --allowed-domains api.openai.com \
  --auth-scheme bearer \
  --tags "prod,ai"
```

Secrets are read from stdin — never in shell history, never in process arguments. The `--allowed-domains` flag restricts which hosts the secret can be sent to. This is vault-authoritative: the agent cannot override it.

### 3.3 Import from .env files

If you have an existing `.env` file:

```bash
hermetic import --path .env
```

Each `KEY=value` pair is parsed, matched against service templates where possible, and stored. Use `--dry-run` to preview without storing. Maximum file size: 5 MiB.

### 3.4 Start the daemon

```bash
hermetic start
```

Enter your passphrase when prompted. The daemon starts in the background and applies all OS hardening before accepting any connections.

To preserve your session across reboots:

```bash
hermetic start --remember-session
```

This encrypts your passphrase (not the master key) with a session key derived from machine-specific identifiers. The session expires after 7 days and is destroyed on `hermetic stop` or `hermetic seal`. Note: ACPI S3 sleep preserves the running daemon — session persistence is for reboot and hibernate recovery only.

### 3.5 Verify the daemon is running

```bash
hermetic daemon-status
```

For detailed system diagnostics:

```bash
hermetic doctor
```

The doctor command runs deep checks across vault, daemon process, socket connectivity, and session/integration. It tests actual daemon responsiveness (not just file existence), detects multiple daemon processes, expired sessions, orphaned sockets, and binary mismatches. Every failed check prints the exact command to fix it. Works when the daemon is down — that's when you need diagnostics most.

---

## 4. Connect an MCP Client

### Claude Code

```bash
hermetic mcp-config --target claude-code --install
```

This auto-registers Hermetic as an MCP server in Claude Code. If you prefer manual setup:

```bash
hermetic mcp-config --target claude-code
```

This prints the `claude mcp add` command to run yourself.

### Cursor

```bash
hermetic mcp-config --target cursor
```

Copy the output JSON into `.cursor/mcp.json` in your project root.

### Windsurf

```bash
hermetic mcp-config --target windsurf
```

Copy the output JSON into `.windsurf/mcp.json` in your project root.

### VS Code

```bash
hermetic mcp-config --target vscode
```

Copy the output JSON into `.vscode/mcp.json` in your project root.

### Claude Desktop

```bash
hermetic mcp-config --target claude-desktop
```

Copy the output JSON into your Claude Desktop config file (`~/.config/Claude/` on Linux).

### Any MCP-compatible client

The MCP bridge speaks JSON-RPC 2.0 over stdio:

```bash
hermetic mcp
```

Configure your client to spawn this command as a stdio MCP server.

---

## 5. Use It

Once the daemon is running and your AI tool is configured, the agent has access to five MCP tools:

### Make an authenticated request

The agent calls `hermetic_authenticated_request` with a secret name and URL. Hermetic issues a one-time handle, injects the credential into the HTTP request using the configured auth scheme, executes it with SSRF protection, and returns only the response. The agent never sees the key.

From the CLI, you can do the same:

```bash
hermetic request --secret openai-key \
  --url https://api.openai.com/v1/models \
  --method GET
```

### Run a command with a secret

The agent calls `hermetic_env_spawn` to run a command with a secret injected as an environment variable. The agent receives only the exit code.

From the CLI:

```bash
hermetic exec --secret deploy-token --env-var DEPLOY_TOKEN -- ./deploy.sh
```

Note: `exec` is TRANSIENT tier — the secret exists in the child process environment. The binary blocklist prevents shells and interpreters from being spawned, but the child process can read its own environment.

### List your secrets

```bash
hermetic list
```

Shows names and metadata (domain binding, auth scheme, sensitivity level). Never shows values.

### Verify a credential

```bash
hermetic verify openai-key
```

Makes a probe request to the service's test endpoint using the full agent-isolated pipeline. Reports whether the credential is valid, rejected, or lacks permissions.

### Seal the vault (emergency)

```bash
hermetic seal
```

Immediately zeroizes all key material, invalidates all active handles, and destroys the session file. The vault is locked until the passphrase is re-entered. Use this if you suspect compromise.

---

## 6. What Happens Under the Hood

When your agent calls `hermetic_authenticated_request`:

1. **MCP bridge** receives the JSON-RPC call over stdio. It connects to the daemon via Unix domain socket.
2. **Daemon** verifies the caller's UID via SO_PEERCRED. Issues a 256-bit CSPRNG handle — single-use, UID-bound, domain-bound, short TTL, version-fingerprinted.
3. **MCP bridge** redeems the handle. The daemon atomically removes it from the handle map before validation. Decrypts the secret into `Zeroizing<Vec<u8>>` memory.
4. **Transport layer** parses the URL, resolves DNS, validates all IPs against blocked SSRF ranges, pins the validated IP. Strips forbidden headers. Injects the credential via the configured auth scheme. **Zeroizes the secret before the first `.await` point**.
5. **HTTP request** is sent over HTTPS (HTTPS only). Redirects are re-validated per-hop with DNS re-resolve. Credentials are never resent on redirects.
6. **Response** is returned to the agent. The secret existed in memory for approximately 1 millisecond.

At no point did the agent observe the raw credential.

---

## 7. Environments

Hermetic uses named environments for complete vault isolation:

```bash
# Create a staging environment
hermetic --env staging init

# Store secrets in staging
hermetic --env staging add --wizard

# Start the staging daemon
hermetic --env staging start
```

Each environment has its own passphrase, encryption keys, secrets, audit log, and daemon socket. No cross-environment access. No silent fallback.

```
~/.hermetic/
├── default/         ← vault.db, vault.salt, daemon.sock, .install-secret
├── staging/         ← completely separate encryption
└── production/      ← completely separate encryption
```

Community Edition supports 1 named environment (`default`). [Commercial licenses](https://hermeticsys.com/license) unlock multiple environments.

---

## 8. Daily Workflow

After initial setup, your daily experience:

| Scenario | What Happens |
|----------|-------------|
| Open laptop (sleep resume) | Daemon is still running. Nothing to do. |
| Reboot (with `--remember-session`) | Daemon auto-resumes in ~3 seconds. Nothing to do. |
| Reboot (without session) | Run `hermetic start`, enter passphrase. One step. |
| Add a new API key | `hermetic add --wizard`. One command. |
| Something breaks | `hermetic doctor`. Every error message includes the command to fix it. |
| New machine | `hermetic clone-env --export` on old machine, `hermetic clone-env --import` on new. Metadata transfers safely; you re-enter each secret value. |

---

## 9. Audit Trail

Every operation is logged in a tamper-evident HMAC-SHA256 audit chain:

```bash
# View recent audit entries
hermetic audit

# Verify chain integrity (detects tampering)
hermetic audit --verify

# Filter by secret
hermetic audit --secret openai-key
```

The audit log records handle issuance, handle redemption (success and failure), secret storage, vault seal/unseal, and session events. It records secret *names*, never values.

---

## 10. Shell Integration

### Tab completion

Generate shell completions for your preferred shell:

```bash
# Bash
hermetic completions bash > ~/.local/share/bash-completion/completions/hermetic

# Zsh
hermetic completions zsh > ~/.zfunc/_hermetic

# Fish
hermetic completions fish > ~/.config/fish/completions/hermetic.fish
```

This gives you tab completion for all subcommands, flags, and secret names.

### Prompt integration

Show vault status directly in your shell prompt:

```bash
hermetic shell-prompt
```

Returns a compact status string (e.g., vault state, daemon status) suitable for embedding in your `PS1` or Starship config. Useful for knowing at a glance whether the daemon is running and the vault is unsealed.

---

## 11. Troubleshooting

### Daemon won't start: "mlockall failed"

The daemon requires `RLIMIT_MEMLOCK` to be unlimited. Check with:

```bash
ulimit -l
```

If it shows a limit, add to `/etc/security/limits.conf`:

```
your-username    -    memlock    unlimited
```

Then log out and back in. In containers, add `--cap-add=IPC_LOCK` to your Docker run command.

### Daemon won't start: "socket already exists"

A previous daemon didn't shut down cleanly. The daemon checks for stale sockets, but if it fails:

```bash
hermetic stop
hermetic start
```

### Agent can't connect: "connection refused"

```bash
hermetic daemon-status
hermetic doctor
```

Check that the daemon is running and the socket exists at `~/.hermetic/default/daemon.sock` with 0600 permissions.

### MCP tool returns error: "domain not allowed"

The secret's `allowed_domains` doesn't include the URL's host. Domain binding is vault-authoritative — the agent cannot override it. Update the secret:

```bash
hermetic remove old-secret-name
echo -n "secret-value" | hermetic add new-name \
  --allowed-domains "api.example.com,api2.example.com" \
  --auth-scheme bearer
```

### Slow key derivation

This is intentional. Argon2id with memory-hard parameters makes brute-force attacks on your passphrase computationally infeasible. As of V1.0.0, Hermetic shows a spinner during key derivation so the terminal doesn't appear frozen. It only runs once at vault creation and daemon unlock. Session persistence (`--remember-session`) means you only experience this delay after a reboot.

### Clipboard not working in dashboard

This was a known issue in pre-release builds. It is fixed in V1.0.0 — clipboard operations (copy secret name, copy fix command) work correctly in both the TUI and web dashboards.

### Something else broken?

Most common errors include a fix command in the error output itself. When in doubt, run:

```bash
hermetic doctor
```

The doctor runs deep checks across vault, daemon, socket, and session state. Every failed check prints the exact command to fix it — copy, paste, done.

```bash
hermetic --help           # All subcommands
hermetic <command> --help # Help for a specific command
```

---

## Dashboards

### Terminal UI (TUI) *(Pro)*

```bash
hermetic dashboard
```

Full-screen interactive dashboard with vault/daemon status, secret list, and actions (`a` to add, `d` to delete, `s` to seal). Press `x` for doctor diagnostics with selectable fix commands, `p` for security properties and maturity progression.

### Web Dashboard *(Pro)*

```bash
hermetic web
```

Browser dashboard at `http://127.0.0.1:8742` with 4-tab layout (Overview, Secrets, Security, CLI Reference). Includes a Doctor panel that shows diagnostic issues with click-to-copy fix commands, health scoring, maturity progression, and auto-refresh every 5 seconds.

---

## Community vs Pro

Everything in this guide works with the free Community binary. Security is identical in both editions.

| Feature | Community (Free) | Pro (Coming Soon) |
|---------|:----------------:|:------------------:|
| Encrypted vault (AES-256-GCM + Argon2id) | ✓ | ✓ |
| Handle protocol (opaque, single-use) | ✓ | ✓ |
| SSRF protection + domain binding | ✓ | ✓ |
| 5 MCP tools | ✓ | ✓ |
| Secrets | 10 | Unlimited |
| Environments | 1 | Unlimited |
| Templates | 26 | 115 |
| `hermetic scan` (credential scanner) | — | ✓ |
| OAuth2 lifecycle | — | ✓ |
| AWS SigV4 signing | — | ✓ |
| TUI dashboard (`hermetic dashboard`) | — | ✓ |
| Web dashboard (`hermetic web`) | — | ✓ |
| Token monitoring | — | ✓ |

---

## What's Next

- **[Security Overview](security-overview.md)** — security model and scope
- **[MCP Integration Guide](mcp-integration.md)** — detailed setup for each supported AI platform
- **[Python SDK Guide](python-sdk.md)** — using Hermetic from Python with PyO3 escape-hatch blocking
- **[CLI Reference](cli-reference.md)** — all subcommands with full options and examples
