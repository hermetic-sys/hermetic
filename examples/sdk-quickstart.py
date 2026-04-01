#!/usr/bin/env python3
"""Hermetic Python SDK Quick Start.

Prerequisites:
  1. hermetic init --quickstart (vault + daemon running)
  2. At least one secret stored (e.g., via .env import)
  3. SDK installed: cd crates/hermetic-sdk && maturin develop --release
"""

from hermetic import HermeticClient

# Connect to the daemon
client = HermeticClient()

# List stored secrets (names and metadata only — never values)
secrets = client.list_secrets()
print(f"Stored secrets: {len(secrets)}")
for s in secrets:
    print(f"  {s['name']} → {s['auth_scheme']} → {s['allowed_domains']}")

# Get an opaque handle to a secret
# The secret bytes stay in Rust memory — never enter Python
handle = client.get_secret("openai-key")  # Replace with your secret name

# Make an authenticated request
# The credential is injected by Rust, not Python
response = handle.authenticated_request(
    url="https://api.openai.com/v1/models",
    method="GET"
)

print(f"Status: {response.status}")
print(f"Body: {response.body[:200]}...")

# Clean up — zeroize the secret in Rust memory
handle.destroy()
