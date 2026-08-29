#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export GIT_PAGER=cat
export GIT_TERMINAL_PROMPT=0

PYTHON="${PYTHON:-python3}"

printf '%s\n' '== toolchain =='
"$PYTHON" --version
"$PYTHON" - <<'PY'
import sys
if sys.version_info[:2] != (3, 14):
    raise SystemExit(f"ERROR: Python 3.14.x required; got {sys.version}")
PY

printf '%s\n' '== manifest =='
if [[ -s requirements.txt ]]; then
  echo 'ERROR: requirements.txt is not empty' >&2
  exit 1
fi
echo 'requirements.txt: EMPTY'

printf '%s\n' '== repository hygiene =='
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if git --no-pager diff --check; then
    echo 'git --no-pager diff --check: PASS'
  fi
  forbidden=$(git --no-pager ls-files | grep -E '(^|/)(sealbox\.vault|__pycache__|.*\.pyc$|.*\.tmp$|.*\.part$|.*\.venv/.*)' || true)
  if [[ -n "$forbidden" ]]; then
    echo 'ERROR: forbidden generated/secret files are tracked:' >&2
    echo "$forbidden" >&2
    exit 1
  fi
  echo 'tracked-file hygiene: PASS'
else
  echo 'git hygiene: SKIPPED (not inside a Git work tree)'
fi

printf '%s\n' '== syntax/tests =='
"$PYTHON" -m py_compile sealbox.py build_repro.py tests/test_sealbox.py
"$PYTHON" -m unittest discover -s tests -q

echo 'unit tests: PASS'

printf '%s\n' '== stdlib import audit =='
"$PYTHON" - <<'PY'
import ast
import sys
from pathlib import Path

stdlib = set(sys.stdlib_module_names) | {'__future__'}
tree = ast.parse(Path('sealbox.py').read_text(encoding='utf-8'), 'sealbox.py')
imports = []
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        imports.extend(alias.name.split('.')[0] for alias in node.names)
    elif isinstance(node, ast.ImportFrom) and node.module:
        imports.append(node.module.split('.')[0])
unknown = sorted(set(imports) - stdlib)
if unknown:
    raise SystemExit('non-stdlib imports: ' + ', '.join(unknown))
print('sealbox.py: stdlib-only imports')
PY

printf '%s\n' '== isolated runtime proof =='
"$PYTHON" -I -S build/sealbox.pyz --version
"$PYTHON" -I -S build/sealbox.pyz verify --help >/dev/null
echo 'isolated zipapp execution: PASS'

printf '%s\n' '== scanner source proof =='
"$PYTHON" sealbox.py scan . --fail-on-findings
printf '%s\n' 'repository scanner proof: PASS'

printf '%s\n' '== reproducible build =='
rm -f build/sealbox.first.pyz
"$PYTHON" build_repro.py
cp build/sealbox.pyz build/sealbox.first.pyz
"$PYTHON" build_repro.py
sha256sum build/sealbox.first.pyz build/sealbox.pyz
cmp -s build/sealbox.first.pyz build/sealbox.pyz
echo 'byte-for-byte reproducibility: PASS'

printf '%s\n' '== artifact smoke test =='
"$PYTHON" -I -S build/sealbox.pyz --help >/dev/null
"$PYTHON" -I -S build/sealbox.pyz bench --size 1 --iterations 1 >/dev/null
echo 'artifact smoke test: PASS'

echo 'RELEASE CHECK: PASS'
