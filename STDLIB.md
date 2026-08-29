# Standard Library Design Log

sealbox deliberately replaces common third-party dependencies with Python standard-library facilities or project-owned code.

The goal is not to reproduce entire external ecosystems. The goal is to keep the runtime small, inspectable, and independently runnable.

| Typical dependency | sealbox implementation | Reason |
|---|---|---|
| `cryptography` / PyNaCl | `hashlib`, `hmac`, `secrets`, native `int`/`pow` | Provides the required primitive building blocks without a runtime package |
| `pyotp` | `hmac`, `hashlib`, `base64`, `struct`, `time` | RFC 6238 is compact enough to implement and test directly |
| `bcrypt` / `argon2-cffi` | `hashlib.scrypt` | Memory-hard KDF in the standard library |
| `click` / `typer` | `argparse` | The CLI grammar fits the standard parser |
| `pytest` | `unittest` | Built-in test framework |
| `gitleaks` / `detect-secrets` | `re`, `pathlib`, entropy calculations | Scanner is implemented directly and does not invoke an external tool |
| `gmpy2` | Python arbitrary-precision `int` + three-argument `pow` | Sufficient for DH modular arithmetic |
| protobuf / msgpack | `struct` length-prefix framing | Share wire format is intentionally small |
| keyring | authenticated local vault | No daemon or platform-specific credential bridge is required |
| colorama | raw ANSI output where needed | Avoids a terminal-color runtime package |
| python-dotenv | `os.environ` | Configuration surface is intentionally small |
| tqdm | simple progress/output logic | Scanner does not need a progress framework |
| rich | structured stdout/stderr | Predictable CLI output is preferable for a security utility |
| requests / httpx | `socket` | Share protocol intentionally operates over raw TCP |
| serialization helpers | project-owned binary format | The vault format is fixed and small |
| external ZIP tooling | `zipfile` | Deterministic artifact construction stays within the Python runtime |

---

# Cryptography policy

sealbox does not attempt to invent a new standalone cipher.

The implementation composes existing primitives:

```text
DH
+
HKDF
+
HMAC
+
fresh nonce
+
XOR keystream
+
encrypt-then-MAC
```

The construction is intentionally documented as a composition rather than presented as an original cryptosystem.

---

# Why a standard-library project can still be useful

Removing dependencies is not the point by itself.

The useful engineering properties are:

- a single source file that can be audited top-to-bottom
- no package installation before first use
- no service to configure
- reproducible packaging
- deterministic release evidence
- explicit crypto boundaries
- a local, inspectable storage format
- a CLI that is easy to script

---

# KDF note

The current vault format uses:

```text
n = 2**15
r = 8
p = 1
```

These parameters are deliberately retained for vault-format stability.

They should not be generalized as the strongest possible scrypt settings for every deployment. Password-KDF cost should be benchmarked for the actual target machine and adjusted in a future format revision when compatibility permits.

Reference:

https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

---

# Runtime dependency boundary

`requirements.txt` is intentionally empty.

`sealbox.py` imports only modules from the Python standard library.

The development environment under `.devcontainer/` is not packaged into the runtime artifact and does not constitute a sealbox runtime dependency.
