# Security Model

## Status

sealbox is a hackathon security-engineering artifact. It is intentionally constrained by the event's standard-library-only rule. It is **not** a replacement for an audited password manager, cryptographic library, or standardized secure transport.

## Design principles

1. Compose standard-library primitives; do not invent a standalone cipher.
2. Authenticate before decrypting.
3. Use separate keys for encryption and MAC.
4. Bind share key derivation to the exact DH transcript.
5. Bound all attacker-controlled lengths and KDF parameters.
6. Avoid secret disclosure in scanner output and logs.
7. Fail closed on corruption and authentication failure.
8. Keep release evidence reproducible and independently inspectable.

## Vault

Master passwords are processed by `hashlib.scrypt` with a random 16-byte salt. The event-selected tuple is fixed for vault version 1. `hashlib.scrypt` is the standard-library implementation of scrypt and is documented in Python 3.14. urlPython hashlib documentationhttps://docs.python.org/3/library/hashlib.html

The password verifier and whole-vault integrity record must both authenticate. Duplicate or missing reserved records fail closed.

The vault path itself is rejected when it is a symlink. Vault writes use a private temporary file, fsync, atomic rename, and directory fsync on POSIX. POSIX vault permissions are `0600`.

## Share

Share uses RFC 3526 Group 14 DH, HKDF-SHA256, separate encryption and MAC keys, an HMAC-generated keystream, and encrypt-then-MAC. The event explicitly permits this construction.

The share key schedule hashes the two DH public values into the HKDF context, so the working keys and displayed fingerprint commit to the same exact handshake transcript. This follows the general protocol-design principle of transcript binding seen in TLS 1.3; sealbox does not claim to implement TLS. urlRFC 8446https://www.rfc-editor.org/rfc/rfc8446.html

The network channel still has no cryptographic identity authentication. NIST describes key confirmation as assurance that the other entity possesses the same shared keying material; sealbox's interactive fingerprint mode is a human out-of-band approximation of that control. urlNIST key confirmation glossaryhttps://csrc.nist.gov/glossary/term/Key_confirmation

## Password-strength note

The event's `n=2**15,r=8,p=1` setting is deliberately retained. OWASP's current password-storage guidance recommends stronger scrypt choices, including `N=2**17,r=8,p=1`, or equivalent tradeoffs, when scrypt is used for general applications. urlOWASP Password Storage Cheat Sheethttps://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

This difference is documented rather than hidden.

## Secret disclosure

Secrets are never intentionally printed by scan results; matches are partially masked. This follows the normal security practice of not writing access tokens, authentication passwords, encryption keys, and other primary secrets directly into logs. urlOWASP Logging Cheat Sheethttps://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

## Limitations

- No cryptographic audit.
- No permanent peer identity.
- No host-malware protection.
- No multi-device sync.
- No claimed side-channel hardening beyond constant-time MAC comparison.
- Heuristic secret detection.

## 1.3.0 hardening rationale

The vault parser validates the complete version-1 scrypt parameter tuple before invoking scrypt. This prevents attacker-controlled KDF work factors from turning a corrupted header into an unbounded local denial-of-service condition.

The share handshake now binds both public DH values into the HKDF context and fingerprint. This is transcript binding, not identity authentication.
