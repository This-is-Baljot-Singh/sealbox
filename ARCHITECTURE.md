# sealbox architecture

## Runtime shape

The entire runtime lives in `sealbox.py` to target the Single File bonus while keeping tests, documentation and release tooling outside the runtime artifact.

```text
                         sealbox CLI
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
       VAULT                 TOTP                SHARE
         │                    │                    │
       scrypt              RFC 6238            RFC 3526 DH
         │                    │                    │
       HKDF                 HMAC             transcript-bound HKDF
         │                    │                    │
   enc key / MAC key          │           enc key / MAC key
         │                                         │
 HMAC keystream + ETM                   HMAC keystream + ETM
         │                                         │
         └────────────────────┬────────────────────┘
                              │
                           SCANNER
                              │
                       regex + entropy
```

## Vault trust boundary

```text
file bytes
   │
   ▼
strict parser
   │
   ├── header/version/length validation
   ├── exact reserved-record cardinality
   ├── duplicate name rejection
   └── bounded scrypt parameters
          │
          ▼
      scrypt keys
          │
     ┌────┴────┐
     ▼         ▼
  verifier   integrity
     │         │
     └────┬────┘
          ▼
      trusted vault
```

## Share trust boundary

```text
TCP
 │
 ├── length-prefixed DH public value
 │
 ├── peer public value validation
 │
 ├── shared secret
 │
 ├── transcript hash = domain || sorted(public-A, public-B)
 │
 ├── HKDF-SHA256(shared secret, transcript context)
 │
 ├── session fingerprint
 │
 └── authenticated encrypted frame
```

The fingerprint is derived from the same transcript-bound session state used for key derivation.

## Why transcript binding matters

A raw DH shared secret is not a complete protocol transcript. The two public values are part of the negotiated session. Binding them into the KDF context means the derived traffic keys are specific to that exact pair of public values, rather than being derived solely from the mathematical shared secret. TLS 1.3 uses transcript hashing and key confirmation for a much more complete version of the same general protocol property. urlRFC 8446https://www.rfc-editor.org/rfc/rfc8446.html

## Persistence

Vault mutations are whole-file rewrites because the expected scale is dozens to hundreds of entries, not a high-throughput storage workload. The implementation uses a temporary file, writes and fsyncs its contents, atomically replaces the vault, and fsyncs the parent directory on POSIX.

## Concurrency

The vault is intentionally single-user and single-process. Share listeners accept one connection and exit. There is no background daemon and no concurrent writer protocol.

## Release architecture

The release path is itself tested:

```text
Python 3.14.x
   │
empty manifest
   │
stdlib import audit
   │
unittest adversarial suite
   │
scanner proof
   │
deterministic zip build #1
   │
deterministic zip build #2
   │
byte comparison + SHA-256
   │
isolated artifact smoke test
   ▼
RELEASE CHECK: PASS
```

## 1.3.0 hardening changes

Version 1.3.0 adds a strict vault KDF parameter policy before any expensive password derivation, transcript-bound share key derivation, interactive fingerprint confirmation, repository scanner hygiene controls, and release automation that does not depend on an interactive Git pager.
