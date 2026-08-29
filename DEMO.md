# Five-Minute Product Demo

The demo should present sealbox as a real security utility, with the zero-dependency architecture as a property of the implementation rather than the entire story.

## 0:00 — What is sealbox?

Show:

```bash
python3 sealbox.py --help
```

Say:

> “sealbox is a local secrets vault, TOTP generator, authenticated one-shot sharing tool, and secret scanner, implemented in a single Python runtime file.”

---

## 0:20 — Prove the runtime is self-contained

Show:

```bash
python3 --version
cat requirements.txt
```

Then:

```bash
python3 -I -S build/sealbox.pyz --version
```

Say:

> “The runtime does not need third-party packages or the normal Python site-packages environment.”

---

## 0:40 — Vault

Create or use a disposable demo vault:

```bash
python3 sealbox.py init
python3 sealbox.py add github
python3 sealbox.py ls
python3 sealbox.py verify
```

Show:

```text
github
Vault integrity: PASS
```

Do not use a real production credential in the recording.

---

## 1:30 — Tamper detection

Make a disposable copy:

```bash
cp sealbox.vault demo-vault.backup
```

Flip a byte in the demo copy and demonstrate:

```bash
python3 sealbox.py verify
echo $?
```

Expected:

```text
authentication/integrity failure
3
```

Restore:

```bash
mv demo-vault.backup sealbox.vault
```

---

## 2:00 — TOTP

Use the published RFC example seed or another fake demonstration seed:

```bash
python3 sealbox.py totp add demo JBSWY3DPEHPK3PXP
python3 sealbox.py totp code demo
```

Explain:

> “The TOTP implementation follows RFC 6238 directly using HMAC, Base32 decoding, `struct`, and time handling.”

---

## 2:30 — Secure share

Use two terminals.

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

Show that:

- both sides derive the same session fingerprint
- the peer comparison succeeds
- plaintext is delivered only after authentication

For a file demonstration:

```bash
printf 'hello from sealbox\n' > demo.txt
```

and send `demo.txt` instead.

Do not commit demo files.

---

## 3:30 — Secret scanner

Detection corpus:

```bash
python3 sealbox.py scan testdata/
```

Show masked findings.

Then:

```bash
python3 sealbox.py scan . --fail-on-findings
```

Show:

```text
0 finding(s)
```

Explain:

> “The scanner is heuristic and masks its own findings so the discovery process does not become a secret-disclosure channel.”

---

## 4:00 — Tests and release proof

Show:

```bash
python3 -m unittest discover -s tests -v
```

Then:

```bash
./release_check.sh
```

Finish on:

```text
RELEASE CHECK: PASS
```

Show the reproducibility section:

```text
build #1 SHA-256
build #2 SHA-256
same hash
byte-for-byte reproducibility: PASS
```

---

## 4:40 — Closing

Use this closing message:

> “sealbox keeps the trust boundary small: local encrypted storage, standards-based TOTP, one-shot authenticated sharing, and secret detection. The implementation is self-contained, the release is reproducible, and the limitations are documented rather than hidden.”

---

## Demo safety

Never record or publish:

- a real password
- a real API key
- a real TOTP seed
- a real private key
- a personal vault
- personal files
- real production data

Use only synthetic demonstration material.
