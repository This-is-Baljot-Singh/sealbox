# Five-minute judging demo

## 1. Zero dependency receipt

```bash
python3 --version
cat requirements.txt
./release_check.sh
```

Say: “The runtime has an empty dependency manifest and the release script proves the standard-library import boundary.”

## 2. Vault

```bash
python3 sealbox.py init
python3 sealbox.py add github
python3 sealbox.py ls
python3 sealbox.py verify
```

Show that only the public entry name appears and `verify` reports `Vault integrity: PASS`.

## 3. Tamper

Copy the vault, flip one byte, and rerun `verify`. The expected result is exit code 3 with an authentication/integrity failure. Restore the backup.

## 4. TOTP

```bash
python3 sealbox.py totp add demo JBSWY3DPEHPK3PXP
python3 sealbox.py totp code demo
```

Explain that the implementation follows RFC 6238 with only `hmac`, `hashlib`, `base64`, `struct` and `time`.

## 5. Secure share + fingerprint

Terminal A:

```bash
python3 sealbox.py share listen --port 47821 --show-fingerprint
```

Terminal B:

```bash
python3 sealbox.py share connect 127.0.0.1 47821 "hello from sealbox" --show-fingerprint
```

Show that both sides report the same fingerprint for the same ephemeral session.

For the stronger human-confirmation demo, use `--confirm-fingerprint` on both sides and enter the fingerprint observed on the peer terminal.

## 6. Scanner

Repository proof:

```bash
python3 sealbox.py scan . --fail-on-findings
```

Expected: `0 finding(s)`.

Detection corpus:

```bash
python3 sealbox.py scan testdata/
```

Show the three masked findings.

## 7. Reproducible artifact

```bash
./build.sh
python3 -I -S build/sealbox.pyz --version
./release_check.sh
```

Finish on the identical SHA-256 values and `RELEASE CHECK: PASS`.

## Judge message

The strongest closing line is:

> “The constraint was zero dependencies. We did not remove security engineering to satisfy it; we made the security construction explicit, testable, reproducible, and honest about its limits.”
