# Security Model

## Scope

sealbox is a local security utility intended for development workflows, small-scale secret storage, secure one-shot transfers, and auditable standard-library cryptographic composition.

It is **not** an externally audited cryptographic library or a replacement for mature password managers, OS credential stores, or standardized secure transport protocols.

The security model is intentionally narrow.

---

## Assets

The primary assets are:

- secrets stored in `sealbox.vault`
- TOTP seeds stored in the vault
- plaintexts supplied to the share command
- files transferred through the share channel
- master passwords
- derived session keys
- scanner output that could otherwise disclose matched secrets

---

## Protected properties

### Confidentiality at rest

A vault entry cannot be recovered from the vault file without the correct master password, subject to the password strength and the security limitations described below.

### Integrity at rest

The vault contains:

```text
__sealbox_verify__
__sealbox_integrity__
```

The verifier authenticates the supplied master password.

The integrity record authenticates a canonical representation of the complete vault structure and user records.

The parser additionally rejects:

- missing reserved records
- duplicate reserved records
- duplicate user names
- malformed lengths
- unsupported versions
- invalid KDF parameters
- reserved user names
- control characters in names

### Confidentiality in transit

The share channel uses ephemeral DH to establish a shared secret and then derives independent encryption and MAC keys through HKDF.

The payload is authenticated with encrypt-then-MAC before plaintext is released.

### Scanner confidentiality

Scanner results partially mask detected material. The scanner therefore does not intentionally become a secondary secret-disclosure mechanism.

---

# Cryptographic construction

## Diffie-Hellman

The share channel uses RFC 3526 Group 14, a 2048-bit MODP group with generator 2.

Each process creates a fresh ephemeral private value using Python's `secrets` module.

The peer public value is validated before modular exponentiation.

This gives:

```text
A = g^a mod p
B = g^b mod p
Z = A^b = B^a mod p
```

The shared secret is never used directly as an encryption key.

Reference:

https://www.rfc-editor.org/rfc/rfc3526

---

## HKDF

The shared secret is encoded as big-endian bytes and passed through HKDF-SHA256.

sealbox uses separate derivation contexts for separate purposes.

For secure sharing, the derivation is also bound to the two DH public values so the traffic keys are specific to the exact session transcript.

Reference:

https://www.rfc-editor.org/rfc/rfc5869

---

## Authenticated encryption

Python's standard library does not provide AES-GCM or ChaCha20-Poly1305.

sealbox therefore follows the explicitly selected standard-library composition:

```text
HMAC-SHA256 PRF
      │
      ▼
nonce + counter
      │
      ▼
keystream
      │
      ▼
plaintext XOR keystream
      │
      ▼
ciphertext
      │
      ▼
HMAC-SHA256(MAC key, nonce || ciphertext)
```

The construction uses:

- a fresh nonce for every encryption
- a separate encryption key and MAC key
- encrypt-then-MAC
- constant-time tag comparison
- authentication before decryption

The implementation does not claim to have invented a new cipher. It composes existing cryptographic primitives.

It also does not claim the assurance level of an externally reviewed AEAD implementation.

---

# Vault password derivation

The vault derives keys using `hashlib.scrypt`.

The version-1 vault format stores:

- KDF salt
- `n`
- `r`
- `p`

in the header.

The implementation validates those parameters before performing the expensive KDF operation.

This prevents a corrupted vault header from directly choosing an arbitrarily expensive local derivation.

The current version-1 parameters are intentionally fixed:

```text
n = 32768
r = 8
p = 1
dklen = 32
maxmem = 64 MiB
salt = 16 bytes
```

These parameters are part of the current file format and should not be silently changed for an existing vault format.

For general password-storage deployments, KDF cost should be tuned against the actual environment and current security guidance. sealbox documents its current parameters explicitly rather than presenting them as universal recommendations.

References:

https://docs.python.org/3/library/hashlib.html

https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

---

# Vault persistence

Writes use a temporary file followed by atomic replacement.

The sequence is:

```text
serialize
   ↓
temporary file
   ↓
write
   ↓
flush
   ↓
fsync
   ↓
atomic replace
   ↓
directory fsync on POSIX
```

The vault path itself is rejected if it is a symlink.

On POSIX systems, the vault file is written with owner-only permissions (`0600`).

These controls are intended to reduce:

- partial-write corruption
- accidental world-readable storage
- symlink redirection
- crash-window exposure

They do not protect against an attacker who already controls the process, the user's account, the filesystem permissions, or the host operating system.

---

# Share fingerprint

The share channel exposes an ephemeral session fingerprint derived from the session's DH state.

Modes:

```text
--show-fingerprint
--expect-fingerprint
--confirm-fingerprint
```

The fingerprint is **not** a certificate and is not a permanent identity.

Interactive confirmation is an out-of-band human check:

```text
Endpoint A
   │
   │ display fingerprint
   ▼
human comparison
   ▲
   │ display fingerprint
Endpoint B
```

A user should compare the fingerprint through an independent channel before trusting an unfamiliar peer.

The fingerprint does not make the raw TCP channel a fully authenticated secure transport protocol.

---

# Threat model

## In scope

sealbox is intended to resist:

- accidental secret disclosure through plaintext vault storage
- casual inspection of vault contents without the password
- passive observation of an authenticated share session
- ciphertext or tag modification in transit
- basic vault file corruption
- obvious leaked credentials inside text trees

---

## Out of scope

### Host compromise

A process running as the same user can read:

- passwords entered into the terminal
- plaintext returned by `get`
- files supplied for sharing
- temporary runtime state

Malware, keyloggers, compromised shells, kernel compromise, or privileged attackers are outside the model.

### Active network attacker without fingerprint verification

DH provides key agreement but no permanent identity.

A capable active MITM can establish separate sessions with both endpoints unless the users authenticate the peer through the out-of-band fingerprint mechanism.

### Side-channel resistance

The implementation uses constant-time comparison for MAC tags, but it does not claim complete side-channel resistance.

### Long-term key lifecycle

Share sessions are one-shot and use fresh ephemeral DH values. There is no persistent peer identity or long-running rekey protocol.

### Large-scale storage

The vault is designed for small local collections of secrets. It is not a database or high-throughput storage engine.

### Secret detection completeness

The scanner is heuristic.

A clean scan does not prove that a repository contains no secret.

---

# Failure behavior

The tool fails closed on security-critical failures.

Relevant categories include:

```text
0  success
1  I/O or operational failure
2  requested entry not found
3  authentication or integrity failure
```

Examples of security failures:

```text
wrong password
invalid authentication tag
vault corruption
duplicate internal record
missing internal record
invalid share fingerprint
tampered share frame
```

No plaintext is intentionally emitted after an authentication failure.

---

# Secure-use guidance

Use a strong, unique master password.

Do not:

- commit `sealbox.vault`
- place real production secrets in demo fixtures
- use the scanner as proof of absence
- treat an ephemeral fingerprint as a permanent identity
- expose an unauthenticated share listener to an untrusted network and assume the peer is authenticated
- treat this implementation as a drop-in replacement for a reviewed cryptographic library

---

# Security review checklist

Before a release:

```text
[ ] Unit tests pass
[ ] RFC vectors pass
[ ] tamper tests pass
[ ] vault corruption tests pass
[ ] KDF bounds are tested
[ ] share framing limits are tested
[ ] fingerprint mismatch is tested
[ ] scanner output is masked
[ ] scanner repository proof is clean
[ ] requirements.txt is empty
[ ] stdlib import audit passes
[ ] isolated artifact execution passes
[ ] reproducible build passes
[ ] source archive provenance check passes
```

---

# Disclosure policy

Security bugs in sealbox should be reported privately to the project maintainer before public disclosure when practical.

Security reports should include:

- affected command or code path
- reproducible input
- expected behavior
- observed behavior
- impact assessment

Do not include real secrets in bug reports.
