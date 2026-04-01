# CLI Reference

Single binary. Community Edition subcommands listed below. All commands accept `--env <n>` to select a named environment (default: `default`).

```bash
hermetic [--env <n>] <command> [options]
```

Community Edition supports 1 environment (`default`). Multiple environments require a [commercial license](https://hermeticsys.com/license).

---

## Global Flags

| Flag | Description |
|------|-------------|
| `--env <n>` | Named environment (default: `default`). Each environment has its own vault, daemon, and audit log. |
| `--vault-path <path>` | Legacy: explicit vault path. Deprecated — use `--env` instead. |
| `--socket-path <path>` | Legacy: explicit socket path. Deprecated — use `--env` instead. |

---

## Setup & Vault

### init

Create a new vault.

```bash
hermetic init                    # Standard: create vault, prompt for passphrase
hermetic init --quickstart       # Guided: vault + .env import + daemon + MCP config
```

The `--quickstart` flag orchestrates the full first-time experience in one command: passphrase collection, vault creation (Argon2id ~18s), `.env` file detection with template matching, daemon startup, credential verification, and MCP tool configuration.

**Access pattern:** Direct (no daemon required).

---

### add

Store a secret in the vault.

```bash
hermetic add --wizard                                    # Interactive: auto-detect service, prompt for tags
echo -n "sk-proj-..." | hermetic add openai-key \        # Explicit: from stdin
  --allowed-domains api.openai.com \
  --auth-scheme bearer \
  --sensitivity high \
  --tags "prod,ai"
```

| Flag | Description |
|------|-------------|
| `--wizard` | Interactive mode. Prompts for name, reads secret with no echo, detects service from key prefix patterns, auto-configures domains and auth scheme, prompts for tags. |
| `--allowed-domains <domains>` | Comma-separated list of domains this secret can be sent to. Vault-authoritative — agents cannot override. |
| `--auth-scheme <scheme>` | One of: `bearer`, `basic`, `x-api-key`, `header:<n>`. |
| `--sensitivity <level>` | Metadata tag: `low`, `medium`, `high`. Does not affect encryption (all secrets use AES-256-GCM). |
| `--tags <tags>` | Comma-separated tags for organization (e.g. `prod,ai,payments`). Used by dashboard hygiene scoring and secret filtering. |
| `--batch` | Batch mode for non-interactive secret addition (suppresses prompts). |
| `--raw` | Force raw stdin mode (skip wizard even on TTY). |

When stdin is a terminal, `add` defaults to wizard mode. Piped input uses stdin mode. Use `--raw` to force stdin mode on a terminal.

Secret values are read from stdin. Never passed as command arguments (would appear in `ps`, `/proc/*/cmdline`, shell history).

**Access pattern:** Direct (vault unlocked via passphrase).

---

### remove

Delete a secret from the vault.

```bash
hermetic remove openai-key
```

Removes the secret and its metadata. Active handles for this secret will fail at redemption (fingerprint mismatch).

**Access pattern:** Direct.

---

### list

Show secret metadata.

```bash
hermetic list                    # Full metadata: names, domains, auth schemes
hermetic list --count            # Number only (for shell prompt integration)
```

Never shows secret values.

**Access pattern:** Direct.

---

### import

Import secrets from a `.env` file.

```bash
hermetic import --path .env                              # Import all keys
hermetic import --path .env --dry-run                    # Preview without storing
hermetic import --path .env --allowed-domains api.example.com --auth-scheme bearer
```

| Flag | Description |
|------|-------------|
| `--path <file>` | Path to `.env` file. Maximum 5 MiB. |
| `--dry-run` | Show what would be imported without storing. |
| `--allowed-domains <domains>` | Default domains for keys without template matches. |
| `--auth-scheme <scheme>` | Default auth scheme for keys without template matches. |

Parses `KEY=value` lines. Strips `export` prefix, surrounding quotes, and trailing whitespace (CRLF-safe). Rejects keys containing characters outside `[A-Za-z0-9_]`. Rejects values containing null bytes. Warns and skips duplicates. Auto-matches keys against built-in service templates (e.g., `ANTHROPIC_API_KEY` → Anthropic template).

**Access pattern:** Direct.

---

### templates

List or inspect built-in service templates.

```bash
hermetic templates                    # List available templates
hermetic templates anthropic          # Show details for one template
```

Each template provides: `display_name`, `allowed_domains`, `auth_scheme`, `default_secret_name`, `test_url`, `test_method`, and `hint` (URL where the user can find their API key). Templates are embedded at compile time via `include_str!` — no runtime file access.

**Available services:** built-in templates covering AI/ML, cloud providers, payment processors, communication, DevOps, databases, and more. 29 auto-detection key prefixes for wizard mode.

---

### status

Show vault and daemon information.

```bash
hermetic status                  # One-time status
hermetic status --watch          # Continuous refresh (5-second interval)
hermetic status --watch --interval 10
```

Displays: vault state, daemon PID, secret count, memory locked status, hardening state, last request summary, audit chain status.

---

## Daemon & Session

### start

Start the daemon in the background.

```bash
hermetic start                           # Standard: prompt for passphrase
hermetic start --remember-session        # Save encrypted session for reboot recovery
```

Applies OS hardening (mlockall, privilege restriction, ptrace protection) before accepting connections. Writes PID file to `~/.hermetic/<env>/daemon.pid`.

The `--remember-session` flag encrypts the passphrase (not the master key) with a session key derived from `install_secret + machine_id + boot_id + hostname + UID`. Session expires after 7 days. Destroyed on `hermetic stop` or `hermetic seal`.

**Access pattern:** Interactive (passphrase from /dev/tty).

---

### stop

Stop the daemon and destroy the session file.

```bash
hermetic stop
```

Sends SIGTERM to the daemon process. Destroys the session file (zero-overwrite + delete). All active handles are invalidated.

---

### restart

Stop and start the daemon.

```bash
hermetic restart
hermetic restart --remember-session
```

Equivalent to `hermetic stop` followed by `hermetic start`.

---

### daemon

Run the daemon in the foreground (for debugging).

```bash
hermetic daemon
```

Same behavior as `start` but does not daemonize. Output goes to the terminal. Ctrl+C to stop. Useful for debugging socket and hardening issues.

**Access pattern:** Interactive (passphrase from /dev/tty).

---

### daemon-status

Check if the daemon is running.

```bash
hermetic daemon-status               # Human-readable output
hermetic daemon-status --quiet       # Exit code only (for scripts)
```

Exit codes: `0` = running, `1` = not running. The `--quiet` flag suppresses all output — designed for shell prompt integration and health checks.

---

### seal

Lock the vault and destroy all session material.

```bash
hermetic seal
```

Immediately zeroizes all key material in the daemon's memory, invalidates all active handles, and destroys the session file. The daemon remains running but all operations return denial responses until the vault is re-unlocked. Requires an interactive terminal.

Use this if you suspect compromise.

**Access pattern:** Interactive (requires terminal).

---

## Operations

### request

Make an authenticated HTTP request via the daemon.

```bash
hermetic request --secret openai-key \
  --url https://api.openai.com/v1/models \
  --method GET

hermetic request --secret stripe-key \
  --url https://api.stripe.com/v1/charges \
  --method POST \
  --body '{"amount": 2000, "currency": "usd"}' \
  --header "Content-Type: application/json"
```

| Flag | Description |
|------|-------------|
| `--secret <n>` | Secret to use for authentication. |
| `--url <url>` | Target URL (must be HTTPS). |
| `--method <method>` | HTTP method (default: GET). |
| `--body <data>` | Request body. |
| `--header <key: value>` | Additional header (repeatable). forbidden headers stripped. |
| `--auto-start` | Offer to start daemon if not running (interactive only). Only prompts when flag is passed AND stdin is a TTY. |

Uses the full handle protocol: issue → redeem → inject → transport → zeroize. BROKERED tier. SSRF protection and domain binding enforced.

**Access pattern:** Daemon (UDS handle protocol).

---

### verify

Test whether a stored credential is valid.

```bash
hermetic verify openai-key                    # Use template test_url
hermetic verify openai-key --url https://api.openai.com/v1/models
```

Makes a probe request to the service's test endpoint using the full handle protocol pipeline. Reports:

- `✓ HTTP 200` — credential is valid
- `✗ HTTP 401` — credential rejected
- `✗ HTTP 403` — credential lacks permissions

Uses the same transport pipeline as `request` (shared internal helper) — SSRF protection cannot be accidentally bypassed.

**Access pattern:** Daemon.

---

### exec

Run a command with a secret injected as an environment variable.

```bash
hermetic exec --secret deploy-token -- ./deploy.sh
hermetic exec --secret db-password --env-var DATABASE_URL -- ./migrate.sh
```

| Flag | Description |
|------|-------------|
| `--secret <n>` | Secret to inject. |
| `--env-var <n>` | Environment variable name (default: secret name uppercased). |
| `--auto-start` | Offer to start daemon if not running (interactive only). Only prompts when flag is passed AND stdin is a TTY. |
| `-- <command> [args...]` | Command and arguments to execute. |

**Security tier:** TRANSIENT. The secret exists in the child process environment for its lifetime.

**Differences from MCP env_spawn:** `exec` inherits the parent environment. MCP `env_spawn` uses `env_clear` (untrusted agent environment). binary blocklist applies to both.

Blocked binaries now explain WHY they're blocked and suggest the direct alternative command.

**Access pattern:** Daemon.

---

## Integration & Tools

### mcp

Run the MCP JSON-RPC bridge over stdio.

```bash
hermetic mcp
```

Speaks JSON-RPC 2.0 on stdin/stdout. All diagnostics go to stderr. Exposes 5 tools: `hermetic_authenticated_request`, `hermetic_suggest_add`, `hermetic_list_secrets`, `hermetic_env_spawn`, `hermetic_seal_vault`.

Typically launched by an MCP client (Claude Code, Cursor, Windsurf), not run directly. See the [MCP Integration Guide](mcp-integration.md).

**Access pattern:** Daemon (UDS connection to running daemon).

---

### mcp-config

Generate MCP server configuration for AI platforms.

```bash
hermetic mcp-config --target claude-code                 # Print command
hermetic mcp-config --target claude-code --install       # Auto-register
hermetic mcp-config --target cursor                      # JSON for .cursor/mcp.json
hermetic mcp-config --target windsurf                    # JSON for .windsurf/mcp.json
hermetic mcp-config --target vscode                      # JSON for .vscode/mcp.json
hermetic mcp-config --target claude-desktop              # JSON for Claude Desktop config
```

| Target | Output | Config Location |
|--------|--------|-----------------|
| `claude-code` | `claude mcp add` command | Claude Code internal registry |
| `cursor` | `mcpServers` JSON | `.cursor/mcp.json` |
| `windsurf` | `mcpServers` JSON | `.windsurf/mcp.json` |
| `vscode` | `servers` JSON (type: stdio) | `.vscode/mcp.json` |
| `claude-desktop` | `mcpServers` JSON | `~/.config/Claude/` (Linux) |

JSON goes to stdout (machine-parseable). Instructions go to stderr (human-readable). The `--install` flag (Claude Code only) auto-registers via `claude mcp add`.

---

### onboard

Generate agent integration documentation.

```bash
hermetic onboard                                         # Output to current directory
hermetic onboard --output-dir ./docs                     # Custom output directory
hermetic onboard --target openclaw --output-dir .        # OpenClaw-specific files
```

**Default output:** `CLAUDE.md`, `AGENTS.md`, `SKILL.md` — integration guides for Claude Code, MCP-compatible agents, and agent skill registries.

**OpenClaw output:** `.agent/skills/hermetic/SKILL.md` and `openclaw.secrets.yaml` — exec provider config pointing to `hermetic request` as the credential resolver.

---

### clone-env

Export or import environment metadata for machine migration.

```bash
# On old machine:
hermetic clone-env --export > hermetic-manifest.json

# On new machine:
hermetic clone-env --import hermetic-manifest.json
```

The export manifest contains secret names, domains, auth schemes, and template references — **never secret values**. The manifest is safe to transfer via email, Slack, or any channel. On import, the user is guided through pasting each secret value.

---

### doctor

Run deep system diagnostics with actionable remediation.

```bash
hermetic doctor
hermetic --env prod doctor
```

Runs 15 checks across 4 categories:

| Category | Checks |
|----------|--------|
| **Vault** | Environment directory, vault database exists, file permissions (0o600) |
| **Daemon Process** | PID liveness, multiple daemon detection, CLI/daemon binary mismatch, lock file state (flock probe) |
| **Socket & Connectivity** | Socket file type, connection test, wire protocol status probe (detects sealed vault / expired session), socket permissions |
| **Session & Integration** | Install-secret exists, session.dat expiry (days remaining), MCP config detection (Claude Code, Cursor, Windsurf, Claude Desktop), template registry |

Every failed check prints: what's wrong, why it matters, and the exact command to fix it. Works when the daemon is down — that's when you need diagnostics most.

Exit codes: `0` = all checks pass (or warnings only), `1` = issues found.

---

### dashboard *(Pro)*

Interactive terminal UI (TUI) dashboard.

```bash
hermetic dashboard
hermetic dashboard --tick-rate 2      # Refresh every 2 seconds (default: 1)
```

Full-screen terminal interface with live-updating vault and daemon status panels, secret list with filtering and tag grouping, and interactive actions.

| Key | Action |
|-----|--------|
| `a` | Add secret (suspends TUI, prompts for name + value + tags) |
| `d` | Delete selected secret (with confirmation) |
| `s` | Seal vault (with confirmation) |
| `/` | Filter secrets by tag |
| `Tab` | Toggle tag grouping |
| `x` | Doctor diagnostics view (10 checks, select + Enter to run fix) |
| `p` | Security properties view (maturity, hygiene grade, 12 checks, limitations) |
| `Enter` | Secret detail + MCP config |
| `c` | Copy MCP config to clipboard (in detail view) |
| `?` | Help overlay |
| `q` | Quit |

**Access pattern:** Daemon must be running. No passphrase needed (reads via UDS).

---

### web *(Pro)*

Browser-based dashboard.

```bash
hermetic web                         # Default: port 8742
hermetic web --port 9000             # Custom port
```

Opens a localhost-only web dashboard at `http://127.0.0.1:<port>/?token=<session>`. Token is printed to stderr and stripped from URL history on page load.

Features: 4-tab layout (Overview, Secrets, Security, CLI Reference), Hermetic Doctor panel with click-to-copy fix commands, health/maturity/hygiene scoring, interactive secret table with sort/filter/group/export, security properties checklist, known limitations, and 5-second auto-refresh.

**Access pattern:** Daemon must be running. Token-gated, localhost-only, CSP-hardened.

---

### scan

Scan files and directories for exposed credentials.

```bash
hermetic scan [PATH]           # Scan path (default: current directory)
hermetic scan . --report-only  # Print findings without import prompt
```

Detects API keys using pattern matching against built-in service templates. Shows file, line number, service name, and auth scheme for each match.

**Access pattern:** Direct (no daemon required).

---

### audit

View and verify the tamper-evident audit log.

```bash
hermetic audit                           # Recent entries
hermetic audit --verify                  # Verify HMAC-SHA256 chain integrity
hermetic audit --secret openai-key       # Filter by secret name
```

Records handle issuance, redemption (success and failure), secret storage, vault seal/unseal, and session events. Records secret *names*, never values. The audit log is CLI-only — deliberately not exposed as an MCP tool (prevents agents from observing credential usage patterns).

**Access pattern:** Direct.

---

### shell-prompt

Output a shell function for prompt integration.

```bash
eval "$(hermetic shell-prompt bash)"     # Bash
eval "$(hermetic shell-prompt zsh)"      # Zsh
eval "$(hermetic shell-prompt fish)"     # Fish
```

Adds a prompt segment: `(hermetic:✓ 5)` when the daemon is running with 5 secrets, `(hermetic:✗)` when down. Uses `hermetic daemon-status --quiet` internally — exit code only, no stdout.

---

### completions

Generate shell completions.

```bash
hermetic completions bash   # Bash completions
hermetic completions zsh    # Zsh completions
hermetic completions fish   # Fish completions
```

Usage: `eval "$(hermetic completions bash)"`

Does not require vault or daemon — generates the completion script only.

---

### migrate

Migrate a legacy vault to a named environment.

```bash
hermetic migrate --from ./old-vault-dir
```

Copies vault data from a legacy `--path`-based layout to the `~/.hermetic/<env>/` structure. Use this when upgrading from the pre-unified-binary era.

---

### version

Print version information.

```bash
hermetic version
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error (check stderr for details) |
| `2` | Usage error (invalid flags or arguments) |

Every error message includes a fix hint — the command to resolve the issue. See `hermetic doctor` for comprehensive diagnostics.

---

## Environment Variables

Hermetic does not read secrets from environment variables. The daemon collects passphrases from `/dev/tty` only — never from stdin, env, or arguments.

The following environment variables affect behavior:

| Variable | Effect |
|----------|--------|
| `HERMETIC_ENV` | Default environment name (overridden by `--env`). |
| `NO_COLOR` | Disable colored terminal output (per [no-color.org](https://no-color.org)). |
| `RUST_LOG` | Tracing filter (development/debugging only). |
