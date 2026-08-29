# Changelog

## 1.5.0

### Security and correctness

- Strengthened vault structural validation.
- Require exactly one password verifier record.
- Require exactly one whole-vault integrity record.
- Reject duplicate user entries.
- Reject reserved internal record names.
- Reject control characters in entry names.
- Validate scrypt parameters before expensive derivation.
- Reject vault symlinks.
- Enforce owner-only vault permissions on POSIX.
- Bind secure-share key derivation to the exact DH public transcript.
- Add interactive secure-share fingerprint confirmation.
- Add fingerprint expectation enforcement.
- Bound share file reads and frame sizes.
- Reject malformed and oversized network input.
- Mask scanner findings.

### Verification and release engineering

- Expanded the suite to 41 tests.
- Added release-archive verification.
- Added repository scanner proof.
- Added isolated `python -I -S` artifact proof.
- Added deterministic zipapp verification.
- Added Git tracked-file hygiene validation.
- Added clean source-archive generation.

### Developer experience

- Added GitHub Codespaces configuration.
- Added benchmark command.
- Added complete architecture, security, operations, playground, demo and standard-library documentation.

## 1.4.0

- Added release artifact completeness checks.
- Added scanner fixture packaging proof.
- Added MIT license and release hygiene improvements.
- Hardened bounded share file handling.

## 1.3.0

- Added KDF parameter bounds.
- Added transcript-bound share derivation.
- Added fingerprint display/confirmation flow.
- Expanded adversarial tests.

## 1.2.0

- Added vault structural-record validation.
- Added explicit vault verification command.
- Added secure-share fingerprints.
- Added repository scanner ignore controls.
- Expanded tamper and corruption tests.

## 1.1.0

- Added whole-vault password verification.
- Added whole-vault integrity protection.
- Improved scanner repository hygiene.
- Added reproducible artifact verification.

## 1.0.0

Initial integrated implementation of:

- local encrypted vault
- RFC 6238 TOTP
- one-shot authenticated file/message sharing
- heuristic secret scanner
- deterministic zipapp packaging
