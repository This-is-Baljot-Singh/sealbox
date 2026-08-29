# sealbox

**Track E — Security & Crypto Utilities**

sealbox is a single-file, standard-library-only local secrets vault with four capabilities:

- encrypted-at-rest secrets with an atomic single-file vault
- RFC 6238 TOTP generation
- one-shot authenticated encrypted file/message sharing over raw TCP
- a heuristic secret scanner that never prints full matches

## Zero-dependency guarantee

`requirements.txt` is intentionally empty. The runtime imports only Python's standard library. No third-party runtime process is required, and sealbox does not shell out to installed tools.

The implementation is deliberately one file (`sealbox.py`) for the Single File bonus. The build script produces a reproducible `build/sealbox.pyz` using `zipfile` with fixed timestamps and a fixed entry order.

## Supported toolchain

Python 3.14.x, matching the hackathon's published environment guidance.

## Quick start

```text
python3 sealbox.py init
python3 sealbox.py add github
python3 sealbox.py get github
python3 sealbox.py ls
python3 sealbox.py stats
```

Use `--vault /path/to/sealbox.vault` when you want an explicit vault path. `SEALBOX_VAULT` is also accepted.

### TOTP

```text
python3 sealbox.py totp add github 6JX...BASE32...
python3 sealbox.py totp code github
```

### Secure share

Terminal A:

```text
python3 sealbox.py share listen --port 47821
```

Terminal B:

```text
python3 sealbox.py share connect 127.0.0.1 47821 "hello over the wire"
```

For a file:

```text
python3 sealbox.py share connect 127.0.0.1 47821 ./report.pdf
```

The receive side accepts exactly one connection and then exits. It writes received files through a temporary file and atomic rename.

### Secret scan

```text
python3 sealbox.py scan .
python3 sealbox.py scan . --fail-on-findings
```

The scanner is intentionally heuristic. Findings show only a masked value.

## Cryptographic construction

The event brief explicitly permits a composed construction consisting of Diffie-Hellman, an actual KDF, a non-reused HMAC-derived keystream, and encrypt-then-MAC. sealbox uses:

1. RFC 3526 Group 14 (2048-bit MODP), generator 2.
2. RFC 5869 HKDF using HMAC-SHA256.
3. HMAC-SHA256(K_enc, nonce || counter) for a counter-mode keystream.
4. AES-free XOR of the plaintext with the keystream.
5. HMAC-SHA256(K_mac, nonce || ciphertext), checked with `hmac.compare_digest` before decryption.
6. `hashlib.scrypt` for the local master password, with a random 16-byte salt and parameters N=2^15, r=8, p=1, plus an explicit 64 MiB memory ceiling.

The vault has a password-verifier record so an empty vault and all header/KDF tampering still fail closed on open.

## Vault durability

The vault is intentionally small and is rewritten as a complete file on every mutation. The writer creates a private temporary file, writes and fsyncs it, atomically replaces the live file, sets restrictive permissions where supported, and fsyncs the containing directory on POSIX systems.

This is not a database and does not target concurrent writers or millions of mutations.

## Threat model

In scope:

- vault contents at rest from an attacker who does not know the master password, subject to password strength
- passive eavesdropping of one share invocation
- corruption/tampering detection through authenticated records

Out of scope:

- active man-in-the-middle attacks during the unauthenticated DH handshake
- malware or keyloggers on an endpoint
- multi-user or multi-device synchronization
- side-channel resistance beyond constant-time authentication-tag comparison
- audited, production-grade cryptographic assurance

## Honest limitations

- No identity authentication in v1. The DH handshake establishes a shared secret but does not prove the peer's identity. An out-of-band fingerprint comparison is a named v2 improvement, not silently included in v1.
- Each share invocation uses fresh ephemeral DH material, but there is no long-lived rekeying protocol.
- The keystream construction is a composed PRF/ETM construction accepted by the event rules, but it is not a standardized AEAD such as AES-GCM or ChaCha20-Poly1305 and has not received external cryptographic review.
- The scanner can produce false positives and false negatives.
- Passwords remain human secrets. scrypt makes guessing more expensive; it cannot rescue a weak password.

## Tests

Run:

```text
python3 -m unittest discover -s tests -v
```

The suite includes RFC HMAC/HKDF/TOTP vectors, DH agreement, empty and randomized encryption round trips, ciphertext/tag tampering, vault restart/corruption behavior, local TCP share behavior, and scanner fixtures.

## Reproducible build

```text
./build.sh
cp build/sealbox.pyz build/sealbox.first.pyz
./build.sh
sha256sum build/sealbox.first.pyz build/sealbox.pyz
```

The two hashes must match on the same machine and toolchain.

## Five-minute demo script

1. Show `requirements.txt` empty and `python3 --version`.
2. Run vault init/add/get/ls.
3. Flip one vault byte and demonstrate exit code 3 / no plaintext.
4. Add a TOTP secret and show the current code plus remaining seconds.
5. Start a local share listener and send a file/message from a second terminal.
6. Run `scan testdata/` and show masked fake findings.
7. Run the reproducible build twice and show identical SHA-256 hashes.
8. Run the stdlib import audit and tests.

## License

MIT.
# sealbox
