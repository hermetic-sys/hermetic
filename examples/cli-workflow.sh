#!/bin/bash
# Hermetic CLI Workflow Example
# Run each section interactively — not as a single script.

# === 1. Initialize ===
hermetic init --quickstart
# Follow the interactive prompts.

# === 2. Add a secret manually (if not imported via .env) ===
echo -n "your-api-key" | hermetic add my-key \
  --allowed-domains api.example.com \
  --auth-scheme bearer

# === 3. List secrets ===
hermetic list

# === 4. Verify a credential ===
hermetic verify --secret my-key

# === 5. Make an authenticated request ===
hermetic request --secret my-key \
  --url https://api.example.com/v1/health \
  --method GET

# === 6. Check system health ===
hermetic doctor

# === 7. View audit trail ===
hermetic audit
hermetic audit --verify  # Verify HMAC chain integrity

# === 8. Seal the vault (emergency) ===
# hermetic seal  # Uncomment to test — zeroizes all keys
