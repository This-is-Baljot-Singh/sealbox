# sealbox Architecture

## Overview

sealbox is deliberately built as one runtime module:

```text
sealbox.py
```

Tests, documentation, build tooling and release proof live outside the runtime file.

The runtime architecture is:

```text
                         sealbox CLI
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
        VAULT                TOTP               SHARE
          │                   │                   │
       scrypt             RFC 6238            RFC 3526
          │                   │                   │
         HKDF                HMAC          transcript-bound HKDF
          │                                       │
      vault keys                              session keys
          │                                       │
   ┌──────┴──────┐                         ┌──────┴──────┐
   │             │                         │             │
verifier     integrity                  HMAC PRF      HMAC MAC
   │             │                         │             │
   └──────┬──────┘                         └──────┬──────┘
          │                                       │
          ▼                                       ▼
     trusted vault                        authenticated frame

                              │
                              ▼
                           SCANNER
                              │
                        regex + entropy
```

---

# Module boundaries inside `sealbox.py`

Although the implementation is a single file, the code is organized into logical layers.

## 1. Primitive helpers

Responsibilities:

- byte XOR
- HMAC-SHA256
- HKDF
- constant-time comparisons
- secure random generation

These functions have no knowledge of the CLI or vault.

---

## 2. Diffie-Hellman

Responsibilities:

- Group 14 parameters
- ephemeral keypair generation
- peer public-value validation
- shared-secret computation

The public value is validated before use.

---

## 3. Session key derivation

The secure-share key schedule incorporates both public DH values into the HKDF context.

Conceptually:

```text
DH shared secret
       +
session transcript
       │
       ▼
HKDF-SHA256
       │
  ┌────┴────┐
  ▼         ▼
K_enc     K_mac
```

The session fingerprint is derived from the same authenticated session state.

---

## 4. Authenticated encryption

Encryption is:

```text
nonce
  │
  ├── HMAC(K_enc, nonce || counter)
  │
  ▼
keystream
  │
  ▼
plaintext XOR keystream
  │
  ▼
ciphertext

tag = HMAC(K_mac, nonce || ciphertext)
```

Decryption is intentionally ordered:

```text
validate framing
      ↓
validate tag
      ↓
decrypt
      ↓
release plaintext
```

This prevents unauthenticated ciphertext from entering the plaintext path.

---

# Vault architecture

## Header

Version-1 vaults contain:

```text
magic      4 bytes
version    uint16
salt       16 bytes
n          uint32
r          uint32
p          uint32
```

Records contain:

```text
name_len       uint16
name           UTF-8 bytes
nonce          16 bytes
ciphertext_len uint32
ciphertext
tag            32 bytes
```

The format is intentionally compact and self-describing enough for strict parsing without a serialization dependency.

---

## Internal records

Two names are reserved:

```text
__sealbox_verify__
__sealbox_integrity__
```

Exactly one of each is required.

The user namespace cannot contain those names.

### Verifier

The verifier authenticates the master password.

### Integrity record

The integrity record authenticates the canonical representation of the vault.

The open sequence is:

```text
raw file
  ↓
parse
  ↓
validate structure
  ↓
validate KDF parameters
  ↓
derive keys
  ↓
verify password record
  ↓
verify integrity record
  ↓
trusted vault
```

No application secret is released before the vault is authenticated.

---

# Persistence model

The vault is not append-only.

A mutation rewrites the complete file:

```text
current vault
     │
     ▼
serialize new state
     │
     ▼
temporary file
     │
     ▼
fsync
     │
     ▼
os.replace()
     │
     ▼
directory fsync
```

This trades write amplification for a much smaller implementation and predictable correctness at the intended scale.

The expected workload is tens to hundreds of entries, not thousands of writes per second.

---

# TOTP architecture

The TOTP path is intentionally independent of vault storage.

```text
Base32 secret
      │
      ▼
decode
      │
      ▼
counter = floor(timestamp / step)
      │
      ▼
HMAC(secret, counter)
      │
      ▼
dynamic truncation
      │
      ▼
decimal code
```

The implementation supports SHA-1, SHA-256 and SHA-512.

The default timestep is 30 seconds.

---

# Share architecture

Share is a one-shot raw TCP protocol.

```text
connect/listen
      │
      ▼
DH public exchange
      │
      ▼
peer validation
      │
      ▼
shared secret
      │
      ▼
transcript-bound HKDF
      │
      ├─────────────┐
      ▼             ▼
   K_enc          K_mac
      │             │
      └──────┬──────┘
             ▼
       encrypted frame
```

The frame contains:

```text
nonce
ciphertext length
ciphertext
authentication tag
```

Payloads are length-bounded before allocation.

A receiving endpoint writes an accepted file only after successful authentication.

---

# Fingerprint architecture

The fingerprint belongs to the current ephemeral session.

```text
public A
   +
public B
   +
domain separator
   │
   ▼
session transcript
   │
   ▼
hash
   │
   ▼
human-readable fingerprint
```

The fingerprint is intended for out-of-band peer confirmation.

It does not replace certificates, signatures, or a persistent trust database.

---

# Scanner architecture

The scanner consists of:

```text
filesystem traversal
       │
       ├── ignore policy
       ├── binary detection
       └── text decoding
               │
               ▼
        detector pipeline
          ┌────┼────┐
          │    │    │
        regex regex entropy
          │    │    │
          └────┼────┘
               ▼
             finding
               │
               ▼
          masked output
```

The detector pipeline is intentionally heuristic and extensible without external packages.

---

# CLI architecture

The CLI uses `argparse`.

Command groups:

```text
init
add
get
rm
ls
totp add
totp code
share listen
share connect
scan
bench
verify
stats
```

The CLI separates:

- user-visible results on stdout
- diagnostics/errors on stderr
- machine-checkable exit codes

---

# Release architecture

The release process treats the artifact and source provenance as separate concerns.

```text
Git tracked source
       │
       ├───────────────┐
       ▼               ▼
source archive       zipapp build
       │               │
archive checker    deterministic builder
       │               │
       ▼               ▼
source PASS       byte-identical artifact
```

The release gate then verifies both paths independently.

This prevents local runtime state from becoming part of the published source tree.

---

# Design decisions

The runtime intentionally excludes:

- network daemons
- cloud synchronization
- databases
- web frameworks
- plugin loading
- account management
- remote service dependencies

These would enlarge the trust boundary and operational surface without supporting the primary use cases.

---

# External standards

Core references:

- RFC 2104 — HMAC
- RFC 3526 — MODP Diffie-Hellman Groups
- RFC 4226 — HOTP
- RFC 5869 — HKDF
- RFC 6238 — TOTP
- RFC 8446 — TLS 1.3 transcript/key-confirmation design principles

sealbox is not an implementation of TLS 1.3.
