#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"

printf '%s\n' '== toolchain =='
"$PYTHON" --version

printf '%s\n' '== manifest =='
if [[ -s requirements.txt ]]; then
  echo 'ERROR: requirements.txt is not empty' >&2
  exit 1
fi
echo 'requirements.txt: EMPTY'

printf '%s\n' '== syntax/tests =='
"$PYTHON" -m py_compile sealbox.py build_repro.py tests/test_sealbox.py
"$PYTHON" -m unittest discover -s tests -q

printf '%s\n' '== stdlib import audit =='
"$PYTHON" - <<'PY'
import ast
from pathlib import Path

stdlib_roots = {'__future__',
    'abc','argparse','base64','collections','contextlib','dataclasses','functools',
    'getpass','hashlib','hmac','itertools','math','os','pathlib','re','secrets',
    'socket','stat','struct','sys','tempfile','time','typing','unittest','zipfile',
}
tree = ast.parse(Path('sealbox.py').read_text(encoding='utf-8'), 'sealbox.py')
imports = []
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        imports.extend(alias.name.split('.')[0] for alias in node.names)
    elif isinstance(node, ast.ImportFrom) and node.module:
        imports.append(node.module.split('.')[0])
unknown = sorted(set(imports) - stdlib_roots)
if unknown:
    raise SystemExit('non-stdlib imports: ' + ', '.join(unknown))
print('sealbox.py: stdlib-only imports')
PY

printf '%s\n' '== reproducible build =='
rm -f build/sealbox.first.pyz
"$PYTHON" build_repro.py
cp build/sealbox.pyz build/sealbox.first.pyz
"$PYTHON" build_repro.py
sha256sum build/sealbox.first.pyz build/sealbox.pyz
cmp -s build/sealbox.first.pyz build/sealbox.pyz

echo 'RELEASE CHECK: PASS'
