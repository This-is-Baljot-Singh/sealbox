# sealbox

**sealbox** is a single-file, standard-library-only security utility for local secret storage, RFC 6238 TOTP generation, authenticated one-shot file/message sharing, and heuristic secret detection.

It is designed around a deliberately small trust boundary:

- one Python runtime file: `sealbox.py`
- no third-party runtime packages
- encrypted local storage with authenticated integrity
- ephemeral Diffie-Hellman key agreement for sharing
- transcript-bound session key derivation
- encrypt-then-MAC authenticated encryption
- RFC 6238 TOTP generation
- masked secret-scanning output
- deterministic, reproducible release artifacts
- a browser-friendly GitHub Codespaces development environment

The project is intentionally explicit about where its guarantees end. The cryptographic construction is composed from standard-library primitives and has not received an external cryptographic audit. It should be treated as a security-engineering project and reference implementation, not as a replacement for an audited password manager or cryptographic library.

---

## Features

### Local vault

The vault stores secrets such as credentials, API tokens, notes, and TOTP seeds in a single local file.

Properties:

- password-derived keys using `hashlib.scrypt`
- 16-byte random KDF salt
- authenticated encryption for every stored value
- password verification record
- whole-vault integrity record
- strict binary parsing and length validation
- duplicate and reserved-name rejection
- atomic replacement writes
- POSIX `0600` file permissions
- symlink rejection for the vault path
- fail-closed authentication and corruption handling

### TOTP

TOTP secrets are stored inside the encrypted vault.

Supported features:

- RFC 6238 compatible generation
- SHA-1, SHA-256 and SHA-512
- configurable digit count
- configurable timestep
- remaining-seconds display
- Base32 secret input

### Secure share

Two sealbox processes can exchange one encrypted message or file over a raw TCP connection.

The session uses:

1. ephemeral Diffie-Hellman
2. transcript-bound HKDF-SHA256
3. separate encryption and MAC keys
4. HMAC-derived keystream
5. encrypt-then-MAC authentication
6. optional human-verifiable session fingerprint

The share channel is deliberately one-shot: one connection, one authenticated payload, then exit.

### Secret scanner

The scanner walks a file or directory and detects likely secrets using:

- AWS-style access-key patterns
- PEM private-key headers
- generic secret/token assignments
- high-entropy hexadecimal and Base64-like material

Matches are always partially masked.

Scanner output is intended for triage, not as proof of absence. False positives and false negatives are expected.

---

## Quick start

Requires Python 3.14.x.

```bash
python3 --version
python3 sealbox.py --help
```

No installation is required:

```bash
python3 sealbox.py init
```

The repository's runtime dependency manifest is intentionally empty:

```text
requirements.txt
```

---

## Vault usage

Create a new vault:

```bash
python3 sealbox.py init
```

Add a secret:

```bash
python3 sealbox.py add github
```

Read it:

```bash
python3 sealbox.py get github
```

List entry names without revealing values:

```bash
python3 sealbox.py ls
```

Verify the password and complete vault integrity state:

```bash
python3 sealbox.py verify
```

Remove an entry:

```bash
python3 sealbox.py rm github
```

Show metadata:

```bash
python3 sealbox.py stats
```

The internal records

```text
__sealbox_verify__
__sealbox_integrity__
```

are reserved implementation records and are never exposed as ordinary user entries.

---

## TOTP usage

Store a Base32 TOTP seed:

```bash
python3 sealbox.py totp add demo JBSWY3DPEHPK3PXP
```

Generate the current code:

```bash
python3 sealbox.py totp code demo
```

Available options:

```bash
python3 sealbox.py totp code demo --digits 6 --step 30 --algorithm sha1
```

---

## Secure share

### Message mode

Receiver:

```bash
python3 sealbox.py share listen \
  --port 47821 \
  --confirm-fingerprint
```

Sender:

```bash
python3 sealbox.py share connect \
  127.0.0.1 47821 \
  "hello from sealbox" \
  --confirm-fingerprint
```

Each endpoint displays the ephemeral session fingerprint. Compare the fingerprints out-of-band before accepting the session.

### File mode

Receiver:

```bash
python3 sealbox.py share listen \
  --port 47821 \
  --confirm-fingerprint
```

Sender:

```bash
python3 sealbox.py share connect \
  127.0.0.1 47821 \
  ./report.pdf \
  --confirm-fingerprint
```

The receiver writes the authenticated file only after successful verification.

### Fingerprints

`--show-fingerprint` displays the current session fingerprint.

`--confirm-fingerprint` displays it and asks the operator to enter the peer's fingerprint.

`--expect-fingerprint` enforces a supplied fingerprint and rejects the session if it does not match.

A fingerprint belongs to one ephemeral session. It is not a permanent device identity.

---

## Scanner usage

Scan one directory:

```bash
python3 sealbox.py scan .
```

Fail a script when findings exist:

```bash
python3 sealbox.py scan . --fail-on-findings
```

Add an exclusion:

```bash
python3 sealbox.py scan . --exclude build --exclude '*.pyc'
```

Repository-local ignore rules are read from `.sealboxignore`.

A normal source-tree scan is configured to exclude generated artifacts and deliberately planted scanner fixtures. The fixture corpus remains available separately:

```bash
python3 sealbox.py scan testdata/
```

---

## Benchmarking

A small local benchmark is included to make performance trade-offs visible:

```bash
python3 sealbox.py bench --size 1 --iterations 3
```

The benchmark reports:

- scrypt timing
- DH shared-secret timing
- authenticated-encryption throughput

Benchmark figures are machine- and workload-dependent and should not be treated as universal performance guarantees.

---

## Build and test

Run the unit suite:

```bash
python3 -m unittest discover -s tests -v
```

The current repository contains 41 tests covering RFC vectors, cryptographic boundaries, vault corruption, network framing, fingerprint handling, scanner behavior, and release-archive verification.

Build the deterministic zipapp:

```bash
./build.sh
```

Run it in isolated mode:

```bash
python3 -I -S build/sealbox.pyz --version
```

Run the full release gate:

```bash
./release_check.sh
```

The release gate checks:

- Python 3.14 compatibility
- required repository files
- empty runtime manifest
- Git hygiene
- syntax and unit tests
- standard-library-only imports
- isolated artifact execution
- repository scanner cleanliness
- deterministic rebuilds
- byte-for-byte artifact equality
- artifact smoke tests

---

## Release artifacts

There are two distinct release artifacts.

### Runnable artifact

```text
build/sealbox.pyz
```

This is the deterministic, executable zipapp.

### Source archive

```text
sealbox-source.zip
```

This is a clean source snapshot generated from Git:

```bash
git archive --format=zip --output=sealbox-source.zip HEAD
```

Validate it with:

```bash
python3 release_archive_check.py sealbox-source.zip
```

The source checker rejects accidental inclusion of:

- local vaults
- demo output
- Python caches
- generated runtime artifacts
- other local-only files

---

## Repository layout

```text
sealbox/
├── .devcontainer/
│   └── devcontainer.json
├── tests/
│   ├── test_release_archive.py
│   └── test_sealbox.py
├── testdata/
│   └── fake_secrets.txt
├── sealbox.py
├── README.md
├── SECURITY.md
├── ARCHITECTURE.md
├── DEMO.md
├── PLAYGROUND.md
├── STDLIB.md
├── LICENSE
├── Makefile
├── build.sh
├── build_repro.py
├── release_archive_check.py
├── release_check.sh
├── deps-proof.txt
├── requirements.txt
├── .sealboxignore
├── .zero-dep.toml
└── .gitignore
```

Local state such as `sealbox.vault`, `.venv`, `__pycache__`, and generated demo files is deliberately excluded from version control.

---

## Security model at a glance

```text
Local password
     │
     ▼
   scrypt
     │
     ▼
 vault keys
     │
 ┌───┴─────────────────┐
 ▼                     ▼
verifier          integrity record
 └────────────┬────────┘
              ▼
          trusted vault


Ephemeral DH
    │
    ▼
shared secret
    │
    ▼
transcript-bound HKDF
    │
 ┌──┴──────────┐
 ▼             ▼
K_enc        K_mac
 │             │
 ▼             ▼
HMAC          HMAC
keystream      tag
 │             │
 └──────┬──────┘
        ▼
encrypt-then-MAC
```

For the complete model, see [`SECURITY.md`](SECURITY.md) and [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Design boundaries

sealbox deliberately does not provide:

- cloud synchronization
- multi-user vaults
- a network daemon
- browser-based secret storage
- permanent peer identity
- account management
- a database-backed control plane

Those features would expand the trust boundary without improving the core purpose of the project.

---

## References

- Diffie-Hellman Group 14: RFC 3526
- HKDF: RFC 5869
- TOTP: RFC 6238
- HMAC: RFC 2104
- Python `hashlib`, `hmac`, `secrets`, `socket`, `pathlib`, and `unittest` documentation
- OWASP Password Storage Cheat Sheet
- OWASP Logging Cheat Sheet

The project-specific limitations in [`SECURITY.md`](SECURITY.md) take precedence over any implied security guarantee from these references.

---

## License

MIT. See [`LICENSE`](LICENSE).
