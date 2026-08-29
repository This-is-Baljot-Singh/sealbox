# Operations Guide

## Installation model

sealbox does not require installation into a Python environment.

Run directly:

```bash
python3 sealbox.py ...
```

or build and run the deterministic artifact:

```bash
./build.sh
python3 -I -S build/sealbox.pyz ...
```

---

## Vault lifecycle

A vault is created with:

```bash
python3 sealbox.py init
```

The default file is:

```text
sealbox.vault
```

A different path can be selected by commands that expose the `--vault` option.

### Backup

For a small local vault, a normal filesystem backup is sufficient provided the backup is protected to the same standard as the primary file.

Recommended procedure:

```bash
cp --preserve=mode,timestamps sealbox.vault sealbox.vault.backup
```

Do not commit either file to Git.

### Restore

Restore only to a trusted local path:

```bash
mv sealbox.vault.backup sealbox.vault
chmod 600 sealbox.vault
```

Then verify:

```bash
python3 sealbox.py verify
```

---

## TOTP seed handling

TOTP seeds are secrets.

Treat them like passwords:

- do not publish them
- do not place them in README examples as real credentials
- do not record them in video
- do not paste them into issue trackers

Use synthetic seeds in tests and demos.

---

## Secure share

The share listener is transient and serves one connection.

Use a known port:

```bash
python3 sealbox.py share listen --port 47821
```

For human verification:

```bash
python3 sealbox.py share listen \
  --port 47821 \
  --confirm-fingerprint
```

Do not assume that a successful TCP connection means peer identity has been authenticated.

---

## Scanner operation

The scanner is intended for repositories and text trees.

Use:

```bash
python3 sealbox.py scan path/
```

Use:

```bash
python3 sealbox.py scan path/ --fail-on-findings
```

in CI-like workflows when findings should produce a non-zero exit status.

Maintain `.sealboxignore` as part of repository policy.

Do not exclude important source trees merely to force a clean scan.

---

## Release procedure

Run:

```bash
python3 -m unittest discover -s tests -v
./build.sh
python3 -I -S build/sealbox.pyz --version
./release_check.sh
```

Then:

```bash
git diff --check
git status --short
```

Generate the source archive only from Git:

```bash
git archive \
  --format=zip \
  --output=sealbox-source.zip \
  HEAD
```

Validate:

```bash
python3 release_archive_check.py sealbox-source.zip
```

---

## Files that should never be committed

```text
sealbox.vault
*.vault
demo.txt
received_*
__pycache__/
*.pyc
.venv/
build/*.pyz
sealbox-source.zip
```

The repository's `.gitignore` and `.sealboxignore` encode these policies.

---

## Release verification record

For each release, record:

```text
Python version
test count
release-check result
artifact SHA-256
source-archive SHA-256
Git commit
```

This creates a compact provenance record without requiring an external build service.
