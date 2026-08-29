PYTHON ?= python3

.PHONY: test build clean proof check

test:
	$(PYTHON) -m unittest discover -s tests -v

build:
	$(PYTHON) build_repro.py

check:
	$(PYTHON) -m py_compile sealbox.py build_repro.py tests/test_sealbox.py
	$(PYTHON) -m unittest discover -s tests -q

proof: check
	./build.sh > /tmp/sealbox-build-1.txt
	cp build/sealbox.pyz build/sealbox.first.pyz
	./build.sh > /tmp/sealbox-build-2.txt
	sha256sum build/sealbox.first.pyz build/sealbox.pyz
	printf '\nPython:\n'
	$(PYTHON) --version
	printf '\nInstalled third-party packages (environment evidence only):\n'
	$(PYTHON) -m pip list --format=freeze 2>/dev/null || true

clean:
	rm -rf build/*.pyz build/sealbox.first.pyz __pycache__ tests/__pycache__
