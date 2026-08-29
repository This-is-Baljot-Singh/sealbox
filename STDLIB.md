# STDLIB Log

The event asks for concrete stdlib-for-package substitutions. The following are the project substitutions actually used or intentionally avoided.

| Normally reach for | sealbox uses | Rationale |
|---|---|---|
| `cryptography` / PyNaCl | `hashlib` + `hmac` + `secrets` + native `pow` | Event permits composed primitives; no third-party runtime dependency |
| `pyotp` | `hmac` + `hashlib` + `base64` + `struct` + `time` | RFC 6238 is small enough to implement and test directly |
| bcrypt / argon2-cffi | `hashlib.scrypt` | Standard-library memory-hard password KDF |
| click / typer | `argparse` | CLI parsing is sufficient and auditable |
| pytest | `unittest` | Standard-library test runner |
| gitleaks / detect-secrets | `re` + `pathlib` + entropy math | Heuristic scanner is part of the project rather than an invoked dependency |
| gmpy2 | native `int` + 3-argument `pow` | Python provides arbitrary-precision integers and modular exponentiation |
| protobuf / msgpack | `struct` length-prefix framing | Wire format is intentionally tiny |
| keyring | local authenticated vault over `pathlib`/`os` | Persistent local storage without a package or daemon |
| colorama | raw ANSI / stderr | No runtime dependency for optional terminal presentation |
| python-dotenv | `os.environ` | Configuration surface is intentionally tiny |
| tqdm | simple loop/progress output | Scanner does not need a progress-bar package |
| rich | plain structured stdout/stderr | Predictable machine-readable output is preferable for a security CLI |
| psutil | `resource`/`time` only where measurement is actually needed | Benchmark avoids another runtime package |
| requests/httpx | `socket` for share transport | Share is intentionally a raw TCP protocol |

## Important boundary

The event's Track E rule is not “never write cryptographic code.” It says not to roll an original cipher; compose the standard library correctly. The project therefore uses RFC-specified DH, HKDF, HMAC and TOTP constructions and documents the composition explicitly.

## Password KDF disclosure

Python 3.14 exposes `hashlib.scrypt`. The event specification selects `n=2**15, r=8, p=1, maxmem=64 MiB`. OWASP currently publishes stronger scrypt choices for general password storage, including `N=2^17,r=8,p=1`; sealbox intentionally retains the event setting and documents the tradeoff rather than presenting it as universal guidance. urlOWASP Password Storage Cheat Sheethttps://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

## Release dependency evidence

`requirements.txt` is empty. `release_check.sh` parses `sealbox.py` with the Python AST and compares imported top-level modules with `sys.stdlib_module_names`, then runs the artifact under `python -I -S`.
