# MCP Integration Guide

This guide covers connecting Hermetic to AI agents via the Model Context Protocol (MCP). By the end, your AI agent will make authenticated API requests through Hermetic without ever seeing your credentials.

**Prerequisites:** Hermetic installed, vault initialized with at least one secret, daemon running. If you haven't done this yet, see the [Getting Started guide](getting-started.md).

---

## How It Works

Hermetic ships an MCP server (`hermetic mcp`) that speaks JSON-RPC 2.0 over stdio. When an AI agent needs to make an authenticated API request, the flow is:

1. Agent calls `hermetic_authenticated_request` via MCP.
2. The MCP bridge connects to the Hermetic daemon via Unix domain socket.
3. The daemon issues a 256-bit single-use handle, UID-bound and domain-locked.
4. The bridge redeems the handle — the daemon decrypts the secret into `Zeroizing` memory.
5. The transport layer injects the credential, sends the HTTPS request, zeroizes the secret before the first `.await`.
6. The agent receives the HTTP response. It never observed the credential.

The MCP bridge is a thin routing layer. It holds no key material, stores no state, and its stdout is exclusively JSON-RPC wire protocol.

---

## Platform Setup

### Claude Code

**Automatic (recommended):**

```bash
hermetic mcp-config --target claude-code --install
```

This runs `claude mcp add` to register Hermetic directly in Claude Code's MCP server registry. Done — Claude Code will spawn `hermetic mcp` automatically when it needs credential access.

**Manual:**

```bash
hermetic mcp-config --target claude-code
```

This prints the `claude mcp add` command to stderr and the config JSON to stdout. Run the printed command yourself.

**Verify it's working:**

Open Claude Code and ask it to list your secrets:

```
List my Hermetic secrets.
```

The agent should call `hermetic_list_secrets` and return secret names and metadata — never values.

---

### Cursor

```bash
hermetic mcp-config --target cursor
```

This outputs a JSON block. Add it to `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "hermetic": {
      "command": "hermetic",
      "args": ["mcp", "--env", "default"]
    }
  }
}
```

If `.cursor/mcp.json` doesn't exist, create it with exactly this content. If it exists, merge the `hermetic` entry into the existing `mcpServers` object.

Restart Cursor after editing the config file.

---

### Windsurf

```bash
hermetic mcp-config --target windsurf
```

Add the output to `.windsurf/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "hermetic": {
      "command": "hermetic",
      "args": ["mcp", "--env", "default"]
    }
  }
}
```

Restart Windsurf after editing.

---

### VS Code

```bash
hermetic mcp-config --target vscode
```

Add the output to `.vscode/mcp.json` in your project root:

```json
{
  "servers": {
    "hermetic": {
      "type": "stdio",
      "command": "hermetic",
      "args": ["mcp", "--env", "default"]
    }
  }
}
```

Note: VS Code uses `servers` with a `type` field, not `mcpServers`. The config format differs from Cursor and Windsurf.

---

### Claude Desktop

```bash
hermetic mcp-config --target claude-desktop
```

Add the output to your Claude Desktop config file:

- Linux: `~/.config/Claude/claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "hermetic": {
      "command": "hermetic",
      "args": ["mcp", "--env", "default"]
    }
  }
}
```

Restart Claude Desktop after editing.

---

### Any MCP-Compatible Client

The MCP bridge is a standard stdio server. Any client that supports the MCP protocol can use it:

```bash
hermetic mcp --env default
```

The bridge reads JSON-RPC 2.0 from stdin, writes JSON-RPC 2.0 to stdout, and sends all diagnostics to stderr. Configure your client to spawn this command as a stdio MCP server process.

---

## Using a Non-Default Environment

All examples above use `--env default`. To use a different named environment:

```json
{
  "mcpServers": {
    "hermetic-staging": {
      "command": "hermetic",
      "args": ["mcp", "--env", "staging"]
    }
  }
}
```

You can register multiple environments as separate MCP servers. Each connects to its own daemon instance with its own vault, secrets, and audit log.

Community Edition supports 1 environment (`default`). Multiple environments require a [commercial license](https://hermeticsys.com/license).

---

## MCP Tools Reference

The bridge exposes 4 operational tools + 1 read-only setup helper. No secret value ever appears in any response, error message, notification, or log output.

### hermetic_authenticated_request

Make an HTTP request with injected credentials. This is the primary tool agents use.

**Sees Secret? No.** The daemon injects the credential into the outgoing request. The agent receives only the HTTP response.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `secret_name` | string | Yes | Name of the secret to use for authentication |
| `url` | string | Yes | Target URL (must be HTTPS) |
| `method` | string | No | HTTP method (default: GET) |
| `headers` | object | No | Additional headers (forbidden headers are stripped) |
| `body` | string | No | Request body |

**What the agent receives:**

- HTTP status code
- Response headers
- Response body (size-capped to prevent memory exhaustion)

**What the agent does NOT receive:**

- The secret value
- Which auth scheme was used
- The raw Authorization/X-Api-Key header value

**Security enforcements:**

- Domain binding: the URL's host must match the secret's `allowed_domains`. The agent cannot override this.
- SSRF protection: private/reserved IP ranges blocked, DNS resolved and validated before connection.
- Redirect re-validation: max 3 hops, per-hop DNS re-resolve, credentials never resent.
- Credential zeroization: secret is wiped from memory before the HTTP request enters the async runtime.

---

### hermetic_suggest_add

Get the CLI command to securely add a secret. The agent never handles the secret value. This is the read-only setup helper.

**Sees Secret? No.** This tool returns a CLI command for the user to run. The secret value never enters the agent's context.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `service` | string | Yes | Service name or template ID (e.g. "stripe", "openai") |
| `name` | string | No | Custom secret name (defaults to template default) |

**Response format:**

```json
{
  "command": "hermetic add stripe_key --wizard",
  "service": "stripe",
  "instructions": "Run this command in your terminal. Hermetic will prompt for the API key — the agent never handles the value."
}
```

The agent should relay the `command` and `instructions` to the user. The user runs the command in their terminal, where `rpassword` reads the secret with no echo.

---

### hermetic_list_secrets

List secret names and metadata.

**Sees Secret? No.** Returns metadata only — names, auth schemes, domains, and sensitivity labels. Never returns secret values.

**Returns:** Array of objects with `name`, `auth_scheme`, `allowed_domains`, and `sensitivity`. Never returns secret values.

---

### hermetic_env_spawn

Spawn a child process with a secret injected as an environment variable.

**Sees Secret? No.** The daemon sets the environment variable in the child process. The agent receives only the exit code.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `secret_name` | string | Yes | Secret to inject |
| `command` | string | Yes | Command to run (must not be a blocked binary) |
| `args` | array | No | Command arguments |
| `env_var` | string | No | Environment variable name (default: secret name uppercased) |

**Returns:** Exit code only. stdout and stderr from the child process are discarded by default.

**Security enforcements:**

- binary blocklist: shells (sh, bash, zsh, etc.), interpreters (python, node, ruby, etc.), and wrappers (env, xargs, nohup, etc.) are blocked.
- Environment is sanitized via `env_clear` (MCP env_spawn uses a clean environment, unlike CLI `hermetic exec` which inherits parent env).

**Trust tier:** TRANSIENT. The secret exists in the child process's environment for the duration of execution. This is a lower security tier than `authenticated_request` (BROKERED).

---

### hermetic_seal_vault

Emergency seal — immediately zeroizes all key material and invalidates all active handles.

**Sees Secret? No.** This tool destroys key material. It never outputs secret values.

**Parameters:** None.

**Returns:** Confirmation that the vault is sealed.

**Note:** This is destructive. The daemon remains running but the vault is locked. All subsequent handle operations return denial responses until the vault is unlocked again. This tool exists for "I think I'm compromised" scenarios.

**Tool annotations:** `destructiveHint: true`, `idempotentHint: true`.

---

## Tools That Don't Exist (By Design)

The following tools are intentionally absent from the MCP surface:

| Excluded Tool | Why |
|---------------|-----|
| `get_secret_value` | Would directly violate agent isolation. The entire point of Hermetic is that agents can't read secrets. |
| `export_secrets` | Bulk secret extraction would defeat the handle protocol. |
| `unlock_vault` | Agents must not control vault lifecycle. Unlocking requires a passphrase from /dev/tty. |
| `delete_secret` | Agents should not be able to destroy credentials. Deletion is a CLI-only operator action. |
| `update_policy` | Domain binding and auth scheme are vault-authoritative. Agents cannot modify security policy. |

If an AI framework requests any of these capabilities, that framework is asking to bypass the security model. Hermetic will never provide them.

---

## Why There Is No store_secret Tool

Secrets never enter the agent's address space — not even during setup. There is no `store_secret` tool because accepting a secret value over MCP would mean the credential passes through the agent's context window, memory, and potentially logs before reaching the vault.

Instead, the agent helps the user set up secrets by providing the CLI command via `hermetic_suggest_add`. The value flows directly from the user's keyboard to the encrypted vault:

1. Agent calls `hermetic_suggest_add` to get the CLI command.
2. User runs the command in their terminal.
3. `rpassword` reads the secret with no echo — the value goes straight into the vault.
4. The agent never observes the secret at any point.

This is a deliberate architectural constraint, not a missing feature. See the [Security Overview](security-overview.md) for more.

---

## Proactive Secret Listing

On MCP connect, the server sends a `notifications/message` notification listing available secret names (up to 100). This means the agent knows which secrets are available immediately — it doesn't need to call `hermetic_list_secrets` first.

If the vault has more than 100 secrets, the list is truncated. The agent can call `hermetic_list_secrets` to retrieve the full list when needed.

---

## Error Recovery

MCP errors include structured fix suggestions in the JSON-RPC `data` field. The agent can relay these to the user for quick resolution.

**Daemon not running:**

```json
{
  "code": -32000,
  "message": "daemon not running",
  "data": {
    "fix": "hermetic start",
    "check": "hermetic daemon-status"
  }
}
```

**Secret not found:**

The error auto-suggests the setup command:

```json
{
  "code": -32001,
  "message": "secret 'stripe_key' not found",
  "data": {
    "fix": "hermetic add stripe_key --wizard"
  }
}
```

**Secret name too long:**

Names longer than 128 characters are rejected:

```json
{
  "code": -32002,
  "message": "secret name exceeds 128 characters"
}
```

**Blocked binary:**

When `hermetic_env_spawn` rejects a command on the binary blocklist, the error explains why and suggests the direct alternative:

```json
{
  "code": -32003,
  "message": "blocked binary: python is on the binary blocklist",
  "data": {
    "reason": "Shells and interpreters can leak secrets via subshells, history, or debug output. The binary blocklist prevents this.",
    "fix": "Call the target script directly (e.g., './myscript.py' instead of 'python myscript.py'), or use hermetic_authenticated_request if making an HTTP call."
  }
}
```

---

## OpenClaw Integration

[OpenClaw](https://github.com/openclaw) supports external credential brokers via SecretRef and an exec provider interface. Hermetic generates the integration files:

```bash
hermetic onboard --target openclaw --output-dir .
```

This creates:

| File | Purpose |
|------|---------|
| `.agent/skills/hermetic/SKILL.md` | Agent integration documentation — available tools, usage examples |
| `openclaw.secrets.yaml` | Exec provider config pointing to `hermetic request` as the credential resolver |

The exec provider calls the `hermetic` binary directly via `execve` — not through a shell. The generated config includes a comment warning about this requirement. If the exec provider passes template variables through shell expansion, they become a command injection vector.

---

## Troubleshooting

### "Connection refused" or "daemon not running"

The MCP bridge connects to the daemon via Unix domain socket. The daemon must be running:

```bash
hermetic daemon-status
hermetic start
```

### "Domain not allowed"

The secret's `allowed_domains` doesn't include the target URL's host. Domain binding is vault-authoritative — the agent cannot override it. Check the secret's domains:

```bash
hermetic list
```

Update the secret if needed (remove and re-add with correct domains).

### Agent sees "tool not found"

The MCP client may not have loaded the Hermetic server configuration. Verify:

1. Config file is in the correct location for your platform.
2. The `command` path points to the `hermetic` binary (try the full path: `which hermetic`).
3. You restarted the client after editing the config.
4. The daemon is running (`hermetic daemon-status`).

### "Secret not found"

The secret name in the MCP call must exactly match the name stored in the vault. Names are case-sensitive. Check with `hermetic list`.

### Bridge produces no output

The MCP bridge sends all diagnostics to stderr, not stdout. If your client captures stderr, check there for startup messages and errors. Stdout is exclusively JSON-RPC wire protocol — any non-JSON-RPC output on stdout would break the protocol.

### Community Edition banner in MCP responses

The Community Edition banner appears in the MCP `initialize` response. It does not affect functionality. It is removed with a [commercial license](https://hermeticsys.com/license).

---

## Security Model for MCP Surface

The MCP bridge operates at **PARTIAL TRUST** tier. It is the component most exposed to agent-controlled input. Key invariants:

- **No secrets in responses.** No secret value in any MCP response, tool result, error message, notification, or panic payload.
- **Stdout purity.** Zero `println!`/`print!` in production code. All diagnostics via stderr.
- **Domain binding.** Read from vault, not from caller. The agent cannot override `allowed_domains`.
- **Fail-closed.** Malformed JSON-RPC produces an error response with no vault state change.
- **Accurate tool annotations.** `readOnlyHint`, `destructiveHint`, `idempotentHint` are correct on all tools.

The audit log (CLI-only, `hermetic audit`) records all MCP operations including handle issuance, redemption, and denial. The audit log is deliberately not exposed as an MCP tool — this prevents agents from observing credential usage patterns.

---

## Next Steps

- **[Getting Started](getting-started.md)** — if you haven't set up Hermetic yet
- **[Python SDK Guide](python-sdk.md)** — using Hermetic from Python scripts and frameworks
- **[CLI Reference](cli-reference.md)** — all subcommands
- **[Security Overview](security-overview.md)** — security model and scope
