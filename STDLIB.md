# STDLIB Log

This document is the audit trail for every package-shaped problem sealbox replaces.

| Would normally reach for | sealbox uses | Reason |
|---|---|---|
| `cryptography` / AES-GCM / Fernet | `hashlib`, `hmac`, `secrets`, native `int`/`pow()` | The event explicitly requires composed stdlib crypto rather than a third-party cipher. |
| `PyNaCl` | RFC 3526 DH + HKDF + HMAC counter keystream + encrypt-then-MAC | Provides authenticated encryption composition without a package, within the event's Track E rule. |
| `pyotp` | `hmac`, `struct`, `base64`, `time` | RFC 6238 is small enough to implement directly. |
| `bcrypt` / `argon2-cffi` | `hashlib.scrypt` | Password stretching is available in Python's stdlib. |
| `click` / `typer` | `argparse` | The CLI only needs standard subcommands/options. |
| `pytest` | `unittest` | Python includes a standard test framework. |
| `gitleaks` / `detect-secrets` | `re`, `pathlib`, a Shannon-entropy calculation | The scanner is intentionally a small, heuristic reimplementation rather than a wrapper around an external tool. |
| `gmpy2` / bignum helpers | Python arbitrary-precision `int` + three-argument `pow()` | RFC 3526 DH modular exponentiation needs no numeric package. |
| `protobuf` / `msgpack` | `struct` length-prefixed framing | The share protocol has a tiny fixed envelope; a serializer would add unnecessary dependency surface. |
| `keyring` | `pathlib`, `tempfile`, `os.replace()`, `os.fsync()` | A small local file store is enough for the defined single-user scope. |
| `colorama` | raw terminal output only | sealbox does not require color for correctness. |
| `tqdm` | ordinary progress-free scanning output | Scanner output is small enough to avoid a progress package. |
| `python-dotenv` | `os.environ` | The configuration surface is one optional vault-path variable. |
| `requests` / `httpx` | no HTTP client at all | The product uses raw `socket` for its intentionally minimal P2P share protocol. |

## Crypto-specific stdlib choices

### Password KDF

`hashlib.scrypt` accepts explicit `n`, `r`, `p`, `dklen`, and `maxmem`. The release configuration is N=32768, r=8, p=1, dklen=32 and maxmem=64 MiB. The salt is random 16 bytes per vault. The explicit memory limit is retained because OpenSSL-backed scrypt has conservative defaults.

### Key separation

A single derived input is passed through HKDF, then separate information strings produce independent encryption and MAC keys. The strings include `sealbox/v1/` domain separation to avoid cross-protocol reuse.

### Authentication ordering

The receiver computes and constant-time compares the authentication tag before invoking the keystream/XOR decryption path. This is an explicit fail-closed property.

## Source originality

The implementation in this repository is written for the event. No third-party source is vendored into `sealbox.py`.

## Performance disclosure

This design deliberately favors readability, bounded scope and judge-auditable correctness over throughput. A real audited AEAD library is generally preferable outside this event. The point here is to demonstrate what Python's standard library can compose while respecting the event rule.
