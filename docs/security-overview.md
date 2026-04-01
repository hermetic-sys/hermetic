# Security Overview

Hermetic uses agent-isolated credential brokering: the daemon holds credentials in memory-locked pages and makes API calls on behalf of AI agents. Agents receive HTTP responses but never observe the credentials used to obtain them.

## Cryptographic Foundation

The open-source `hermetic-core` crate implements:

- **AES-256-GCM** authenticated encryption (per-secret)
- **Argon2id** key derivation (memory-hard)
- **HKDF-SHA256** key hierarchy
- **SQLCipher** encrypted vault
- **HMAC-SHA256** audit chain

## Transport Security

The open-source `hermetic-transport` crate implements:

- SSRF defense with DNS pinning
- Forbidden header stripping
- Redirect re-validation per hop

## Memory Protection

- Memory locking (secrets never swapped to disk)
- Core dump prevention
- Zeroizing wrappers (secrets zeroed after use)

## Testing

Hermetic is continuously fuzz tested with libFuzzer and AddressSanitizer, and has undergone multiple adversarial review campaigns during development. Vulnerabilities discovered during development were fixed and the defenses verified.

## Scope

Hermetic v1 targets developer workstations where all processes run as the same Unix user. Per-process identity verification is planned for V2.

## Vulnerability Disclosure

See [SECURITY.md](../SECURITY.md).
