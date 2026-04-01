# Python SDK Guide

The Hermetic Python SDK (`hermetic-sdk`) is a native extension built with [PyO3](https://pyo3.rs) and [maturin](https://www.maturin.rs). It provides Python developers with agent-isolated credential brokering — secrets stay in Rust `Zeroizing` memory and never enter the Python runtime.

**Prerequisites:** Hermetic daemon running with at least one stored secret. Python 3.12+. See the [Getting Started guide](getting-started.md) if you need to set up Hermetic first.

---

## Installation

The SDK is built as a native Python extension via maturin:

```bash
# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Build and install from the Hermetic source tree
cd crates/hermetic-sdk
pip install maturin
maturin develop --release
```

After installation:

```python
from hermetic import HermeticClient, SecretHandle, HttpResponse
```

---

## Quick Example

```python
from hermetic import HermeticClient

# Connect to the daemon
client = HermeticClient()

# Get an opaque handle to a secret (secret bytes never enter Python)
handle = client.get_secret("openai-key")

# Make an authenticated request — credential injected on the Rust side
response = handle.authenticated_request(
    url="https://api.openai.com/v1/models",
    method="GET"
)

print(response.status)   # 200
print(response.body)     # JSON response body

# When you're done with the handle
handle.destroy()
```

At no point in this flow does the secret exist as a Python string, bytes object, or any Python-visible value.

---

## API Reference

### HermeticClient

Connects to the Hermetic daemon via Unix domain socket.

```python
client = HermeticClient()                              # Default environment
client = HermeticClient(env="staging")                 # Named environment
client = HermeticClient(socket="/path/to/daemon.sock") # Explicit socket
```

**Methods:**

| Method | Returns | Description |
|--------|---------|-------------|
| `get_secret(name)` | `SecretHandle` | Request a handle from the daemon. The daemon issues a 256-bit handle, the SDK redeems it, and the secret bytes are stored in Rust `Zeroizing<Vec<u8>>` memory. The Python `SecretHandle` object is opaque — it contains no secret data accessible to Python. |
| `list_secrets()` | `list[dict]` | List secret names and metadata (names, auth schemes, domains). Never returns values. |

---

### SecretHandle

An opaque reference to a secret. The secret bytes live in Rust memory behind a mutex-protected zeroizing buffer. The handle is reusable until explicitly destroyed — each call to `authenticated_request` clones the secret for the duration of the HTTP request.

**Methods:**

| Method | Returns | Description |
|--------|---------|-------------|
| `authenticated_request(url, method="GET", headers=None, body=None)` | `HttpResponse` | Make an authenticated HTTP request. The credential is injected by the Rust transport layer using the secret's configured auth scheme. Full SSRF protection, forbidden headers stripped, credential zeroized before the HTTP request enters the async runtime. |
| `hmac_sign(data)` | `bytes` | Compute HMAC-SHA256 of `data` using the secret as key. The secret never leaves Rust. Uses ring for constant-time operations. |
| `hmac_verify(data, signature)` | `bool` | Verify an HMAC-SHA256 signature. Constant-time comparison via ring. |
| `destroy()` | `None` | Explicitly zeroize the secret and invalidate the handle. Safe to call multiple times. After destruction, all methods raise `HandleError`. |

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `bool(handle)` | `bool` | `True` if the handle holds a live secret, `False` after `destroy()`. |

---

### HttpResponse

Returned by `authenticated_request`.

| Property | Type | Description |
|----------|------|-------------|
| `status` | `int` | HTTP status code |
| `headers` | `list[tuple[str, str]]` | Response headers as name-value pairs |
| `body` | `str` | Response body (UTF-8 decoded) |

---

### Exceptions

All exceptions inherit from `HermeticError`:

| Exception | Raised When |
|-----------|-------------|
| `HermeticError` | Base exception for all Hermetic SDK errors |
| `ConnectionError` | Daemon socket not found, connection refused, daemon not running |
| `HandleError` | Handle already destroyed, secret not found, daemon denied request |
| `TransportError` | SSRF blocked, HTTPS-only violation, timeout, DNS resolution failure |

```python
from hermetic import HermeticClient, HermeticError, ConnectionError, HandleError, TransportError

try:
    client = HermeticClient()
    handle = client.get_secret("my-key")
    response = handle.authenticated_request(url="https://api.example.com/v1/data")
except ConnectionError:
    print("Daemon not running. Run: hermetic start")
except HandleError as e:
    print(f"Handle error: {e}")
except TransportError as e:
    print(f"Transport error: {e}")  # SSRF blocked, HTTPS required, etc.
```

No exception message ever contains secret material.

---

## Escape-Hatch Blocking

Python's introspection system is powerful — `str()`, `repr()`, `pickle`, `getattr()`, and many other paths can extract data from objects. The SDK blocks all known introspection paths at the Rust/PyO3 level:

| Python Operation | Result | Why Blocked |
|-----------------|--------|-------------|
| `str(handle)` | `'[SecretHandle: OPAQUE]'` | Prevents accidental logging or string interpolation leaking secret bytes |
| `repr(handle)` | `'SecretHandle(opaque, id=...)'` | Same as `str` — repr is used in debuggers and error messages |
| `format(handle)` | `'[SecretHandle: OPAQUE]'` | f-strings and `.format()` would otherwise call `__format__` |
| `bytes(handle)` | `TypeError` | Direct byte extraction blocked |
| `iter(handle)` | `TypeError` | Iteration over secret bytes blocked |
| `pickle.dumps(handle)` | `TypeError` | Serialization would write secret to disk/network |
| `copy.copy(handle)` | `TypeError` | Shallow copy could create untracked secret references |
| `copy.deepcopy(handle)` | `TypeError` | Deep copy same as above |
| `handle.__getstate__()` | `TypeError` | Pickle protocol hook blocked |
| `handle.__dict__` | `AttributeError` | No attribute dictionary — prevents dynamic attribute inspection |
| `handle.__sizeof__()` | `64` (fixed) | Returns constant — prevents size-based information leakage |
| `dir(handle)` | Whitelisted methods only | Only approved method names visible — no internal attributes exposed |
| `bool(handle)` | `True` / `False` | Allowed — returns liveness state, not secret data |
| `json.dumps(handle)` | `TypeError` | JSON serialization blocked |
| `int(handle)` | `TypeError` | Numeric conversion blocked |
| `float(handle)` | `TypeError` | Numeric conversion blocked |

If you discover an introspection path not on this list that leaks secret material, please report it via [SECURITY.md](../SECURITY.md).

---

## Usage Patterns

### Basic API call

```python
from hermetic import HermeticClient

client = HermeticClient()
handle = client.get_secret("anthropic-key")

response = handle.authenticated_request(
    url="https://api.anthropic.com/v1/messages",
    method="POST",
    headers={"Content-Type": "application/json"},
    body='{"model": "claude-sonnet-4-20250514", "max_tokens": 1024, "messages": [{"role": "user", "content": "Hello"}]}'
)

if response.status == 200:
    print(response.body)
else:
    print(f"API returned {response.status}")
```

### HMAC signing

```python
handle = client.get_secret("webhook-secret")

# Sign a payload
payload = b'{"event": "payment.completed", "amount": 4999}'
signature = handle.hmac_sign(payload)

# Verify a signature (constant-time comparison)
is_valid = handle.hmac_verify(payload, signature)
```

The secret never leaves Rust memory. The HMAC computation happens entirely on the Rust side using ring's constant-time implementation.

### Listing secrets

```python
client = HermeticClient()
secrets = client.list_secrets()

for s in secrets:
    print(f"{s['name']} → {s['auth_scheme']} → {s['allowed_domains']}")
```

Returns metadata only. Never returns secret values.

### Handle lifecycle

```python
handle = client.get_secret("my-key")

# Handle is reusable — make multiple requests
r1 = handle.authenticated_request(url="https://api.example.com/v1/users")
r2 = handle.authenticated_request(url="https://api.example.com/v1/orders")

# Explicit cleanup (zeroizes secret in Rust memory)
handle.destroy()

# After destroy, all operations raise HandleError
try:
    handle.authenticated_request(url="https://api.example.com/v1/data")
except HandleError:
    print("Handle is destroyed")

# Safe to call destroy again — no-op, no error
handle.destroy()
```

If you don't call `destroy()`, Rust's `Drop` implementation zeroizes the secret when the Python object is garbage collected. Explicit `destroy()` is preferred for deterministic cleanup.

### Multiple environments

```python
default_client = HermeticClient()
staging_client = HermeticClient(env="staging")

prod_handle = default_client.get_secret("stripe-key")
staging_handle = staging_client.get_secret("stripe-test-key")
```

Each client connects to its own daemon instance. Environments are fully isolated.

---

## Architectural Constraint

The SDK does not depend on `hermetic-core`. This is a constitutional design decision : the SDK cannot decrypt the vault, access encryption keys, or bypass daemon policy. The daemon is the single trust root.

The SDK's dependency chain:

```
hermetic-sdk
├── hermetic-transport  (HTTP execution, SSRF protection, credential injection)
├── pyo3               (Rust ↔ Python FFI)
├── tokio              (async runtime bridge — block_on internally)
├── ring               (HMAC-SHA256, constant-time operations)
├── serde + serde_json (daemon wire protocol serialization)
├── base64             (secret bytes decoding from daemon)
└── url                (domain extraction for validation)

NOT linked: hermetic-core, hermetic-daemon, hermetic-mcp, hermetic-cli
```

This means the SDK cannot perform any vault operation that the daemon doesn't explicitly authorize through the handle protocol. Even if the SDK code were compromised, it could not extract secrets without the daemon's cooperation.

---

## Security Model

The Python SDK achieves the highest security tier security tier — the same as MCP `authenticated_request`. Secret bytes exist only in Rust `Zeroizing<Vec<u8>>` memory for approximately 1ms during HTTP request execution.

| Invariant | Status | Enforcement |
|-----------|--------|-------------|
| Secret bytes never cross FFI boundary: Secret bytes never cross FFI boundary | Enforced | No `PyBytes`/`PyString` created from secret material in any `#[pymethod]` |
| No Python-visible secret representation: No Python-visible secret representation | Enforced | escape-hatch blocking, all tested |
| HTTPS-only: HTTPS-only  | Enforced | `hermetic-transport` rejects non-HTTPS URLs |
| SSRF protection: SSRF protection  | Enforced | blocked IP ranges via transport layer |
| Zeroize before await: Zeroize before await  | Enforced | Transport zeroizes credential before async runtime |
| Single-use handle redemption: Single-use handle redemption  | Enforced | Daemon atomic atomic consumption |
| Process UID validation | Enforced | Daemon verifies SDK process UID |
| No secrets in error messages: No secrets in error messages | Enforced | All error paths audited |

---

## Troubleshooting

### `ModuleNotFoundError: No module named 'hermetic'`

The SDK isn't installed in your active Python environment. Make sure you're in the correct virtualenv and run `maturin develop --release` from the `crates/hermetic-sdk` directory.

### `ConnectionError: daemon not running`

Start the daemon: `hermetic start`. The SDK connects via Unix domain socket at `~/.hermetic/<env>/daemon.sock`.

### `TransportError: SSRF blocked`

The target URL resolved to a private/reserved IP range. This is the SSRF protection working correctly. If you need to reach a local development API, the URL must resolve to a public IP.

### `HandleError: secret not found`

The secret name doesn't exist in the vault. Check with `hermetic list`. Names are case-sensitive.

### `TypeError` on any handle operation

You're hitting an escape-hatch block. This is intentional — the operation you're attempting would expose secret material to the Python runtime. Use `authenticated_request()` or `hmac_sign()` instead.

---

## Next Steps

- **[MCP Integration Guide](mcp-integration.md)** — connecting AI agents via MCP
- **[CLI Reference](cli-reference.md)** — all 31 subcommands
- **[Security Model](security-model.md)** — full threat model and known limitations
- **[Getting Started](getting-started.md)** — initial Hermetic setup
