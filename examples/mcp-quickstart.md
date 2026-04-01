# MCP Integration Quick Start

## 1. Setup

```bash
hermetic init --quickstart
```

## 2. Configure Your AI Tool

```bash
# Claude Code (auto-install)
hermetic mcp-config --target claude-code --install

# Cursor (copy JSON to .cursor/mcp.json)
hermetic mcp-config --target cursor

# Windsurf (copy JSON to .windsurf/mcp.json)
hermetic mcp-config --target windsurf
```

## 3. Use It

Open your AI tool and ask:

> "List my Hermetic secrets."

The agent calls `hermetic_list_secrets` and returns names and metadata — never values.

> "Use my OpenAI key to list available models."

The agent calls `hermetic_authenticated_request`. It receives the API response. It never sees the key.

## Available MCP Tools

| Tool | Description |
|------|-------------|
| `hermetic_authenticated_request` | HTTP request with injected credentials |
| `hermetic_suggest_add` | Get CLI command to securely add a secret |
| `hermetic_list_secrets` | List secret names and metadata |
| `hermetic_env_spawn` | Run command with secret in environment |
| `hermetic_seal_vault` | Emergency seal — zeroize all keys |
