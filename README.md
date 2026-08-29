# sealbox

**Track E — Security & Crypto Utilities**

sealbox is a single-file, standard-library-only security utility for local secret storage, RFC 6238 TOTP generation, one-shot authenticated file/message sharing, and heuristic secret scanning.

**Release:** 1.3.0

> **Security status:** This is a hackathon security-engineering implementation, not professionally audited cryptographic software. Outside the event, use established audited cryptographic libraries and protocols.

## Why this project

The event rewards usefulness (35%), zero-dependency craft (30%), code quality (25%), and innovation (10%), with optional Single File, Reproducible Build, Package Killer, and STDLIB Log bonuses. The project is designed around all four bonuses.

## Zero-dependency contract

`requirements.txt` is empty. Runtime code imports only Python standard-library modules. sealbox does not shell out to third-party programs, require a database service, or require a cloud API.

The runtime target is Python 3.14.x.

## Capabilities

| Capability | Purpose | Standard library core |
|---|---|---|
| Vault | Authenticated encrypted local secret storage | `hashlib`, `hmac`, `secrets`, `pathlib`, `os`, `struct` |
| Verify | Password + whole-vault integrity verification | vault crypto core |
| TOTP | RFC 6238 codes | `hmac`, `hashlib`, `base64`, `struct`, `time` |
| Share | One-shot encrypted message/file transport | `socket`, `hashlib`, `hmac`, `secrets` |
| Fingerprint | Human-checkable DH session identity | `hashlib`, `re`, `hmac` |
| Scan | Heuristic leaked-secret detection | `re`, `pathlib`, `math`, `fnmatch` |
| Bench | Local performance measurements | `time`, `statistics` |
| CLI | Machine-checkable command surface | `argparse` |
| Tests | RFC vectors and adversarial tests | `unittest` |

## Crypto construction

The event permits composition of standard-library primitives rather than implementing a new cipher. sealbox uses:

```text
Vault password
    -> scrypt
    -> HKDF-SHA256
    -> separate vault encryption/MAC keys
    -> HMAC-counter keystream
    -> XOR encryption
    -> encrypt-then-MAC

Share peer keys
    -> RFC 3526 Group 14 DH
    -> transcript-bound HKDF-SHA256
    -> separate encryption/MAC keys
    -> HMAC-counter keystream
    -> encrypt-then-MAC
```

RFC 3526 specifies Group 14 as the 2048-bit MODP group with generator 2. urlRFC 3526 §3https://www.rfc-editor.org/rfc/rfc3526.html

HKDF follows RFC 5869. urlRFC 5869https://www.rfc-editor.org/rfc/rfc5869.html

TOTP follows RFC 6238, including the standard dynamic truncation construction and SHA-1 default, with SHA-256/SHA-512 options. urlRFC 6238https://www.rfc-editor.org/rfc/rfc6238.html

## Password KDF

The event specification selects:

```text
n = 2**15
r = 8
p = 1
dklen = 32
maxmem = 64 MiB
salt = 16 random bytes
```

Python 3.14 documents `hashlib.scrypt` and recommends a salt of about 16 bytes or more. urlPython hashlib.scrypt documentationhttps://docs.python.org/3/library/hashlib.html

This parameter choice is **event-compatible**, not a universal production recommendation. OWASP currently lists stronger scrypt configurations, including `N=2^17, r=8, p=1`, so a general-purpose password manager should tune the work factor to its deployment rather than copy this hackathon setting blindly. urlOWASP Password Storage Cheat Sheethttps://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

Vault version 1 accepts only the event-selected parameter tuple. This is deliberate: an attacker cannot rewrite `n`, `r`, or `p` in a corrupted header and force an unbounded KDF workload before authentication.

## Vault authentication and integrity

Exactly two reserved records exist:

```text
__sealbox_verify__
__sealbox_integrity__
```

The verifier proves the supplied password derived the correct keys. The integrity record authenticates the canonical vault representation excluding itself. Duplicate, missing, or unknown duplicate records fail closed.

```text
password
  -> scrypt
  -> vault keys
       -> verify record
       -> integrity record
       -> recompute canonical digest
  -> trusted vault
```

Mutations are written to a private temporary file, fsynced, atomically replaced, and the parent directory is fsynced on POSIX. The vault is owner-only (`0600`) where POSIX mode bits apply, and symlink vault paths are rejected.

## Share protocol

A share invocation establishes an ephemeral DH secret over raw TCP. Both DH public values are included in the HKDF context, so session keys and fingerprints are bound to the exact two-key transcript.

The application frame is authenticated before decryption. Oversized and truncated frames are rejected before plaintext is materialized.

### Fingerprint verification

`--show-fingerprint` prints a 128-bit session fingerprint. `--expect-fingerprint` requires a previously trusted value supplied by another authenticated channel. Because the DH keys are ephemeral, the fingerprint **changes every session**. Reusing an old session fingerprint is expected to fail.

For interactive human comparison use:

```bash
python3 sealbox.py share listen --port 47821 --confirm-fingerprint
python3 sealbox.py share connect 127.0.0.1 47821 "hello" --confirm-fingerprint
```

Each side displays the current fingerprint; the user enters the fingerprint observed on the peer terminal. If the values differ, the payload is not accepted. This provides human key confirmation but does not itself create cryptographic identity authentication. NIST defines key confirmation as assurance that the other party possesses the same keying material. urlNIST key confirmation glossaryhttps://csrc.nist.gov/glossary/term/Key_confirmation

TLS 1.3 similarly binds authentication and key confirmation to the handshake transcript, which is the design inspiration for transcript-bound derivation here; sealbox is not TLS and does not claim TLS security. urlRFC 8446https://www.rfc-editor.org/rfc/rfc8446.html

## Scanner

The scanner detects AWS-style access keys, private-key headers, generic secret assignments, and high-entropy hex/base64-like strings. Findings are masked.

Repository scans automatically respect `.sealboxignore` and ignore common generated directories. The test corpus is scanned separately so the repository itself can demonstrate a clean scan while still proving that detection works.

## CLI

```text
sealbox init
sealbox add <name>
sealbox get <name>
sealbox rm <name>
sealbox ls
sealbox verify
sealbox stats
sealbox totp add <name> <base32-secret>
sealbox totp code <name>
sealbox share listen --port N [fingerprint options]
sealbox share connect <host> <port> <file-or-message> [fingerprint options]
sealbox scan <path>
sealbox bench
```

Exit codes:

```text
0 success
1 I/O or generic application failure
2 requested entry not found
3 authentication, integrity, or tamper failure
4 reserved for future explicit usage errors
```

## Testing

The suite covers RFC known-answer vectors, authenticated-encryption round trips and tampering, DH validation, transcript binding, KDF bounds, vault corruption/duplicates/reserved names/permissions/symlink behavior, fingerprint agreement, share tamper behavior, scanner fixtures and repository scanning.

Run:

```bash
python3 -m unittest discover -s tests -v
```

## Reproducible build

Build:

```bash
./build.sh
```

The deterministic builder fixes archive metadata and file ordering. The release gate builds twice and compares both SHA-256 digests and the bytes.

## Release verification

```bash
./release_check.sh
```

It verifies:

```text
Python 3.14.x
empty dependency manifest
Git tracked-file hygiene
syntax
unit tests
stdlib-only imports
isolated -I -S zipapp execution
repository scanner proof
reproducible artifact
artifact smoke tests
```

## Threat model

In scope: local encrypted-at-rest secrets against an attacker who lacks the master password; passive network eavesdropping against share traffic; accidental and malicious vault corruption; common source-code secret leaks.

Out of scope: malware/keyloggers on the host; an unauthenticated active MITM who is not detected by human fingerprint verification; OS compromise; multi-user/cloud synchronization; side-channel resistance beyond constant-time tag comparison.

## Honest limitations

- The composed HMAC-counter keystream is not AES-GCM or ChaCha20-Poly1305 and has not received an independent cryptographic review.
- Ephemeral DH provides no permanent peer identity. Fingerprint comparison is an out-of-band human control, not a certificate system.
- The vault is a small single-user file, not a multi-process database.
- The scanner is heuristic and can produce false positives and false negatives.
- Password KDF parameters are selected for the event specification and should be independently tuned for a real deployment.

## Package-killer / stdlib story

See `STDLIB.md` for the detailed substitutions. The strongest concrete replacement is the RFC 6238 TOTP workflow normally provided by `pyotp`; authenticated encryption and key agreement workflows normally provided by packages are also implemented entirely from stdlib primitives.

## Five-minute demo

See `DEMO.md`. The intended sequence is: empty manifest -> vault -> tamper rejection -> TOTP -> encrypted share -> fingerprint verification -> scanner -> reproducible build -> test gate.
