PYTHON ?= python3

.PHONY: test build check proof release source-archive clean

test:
	$(PYTHON) -m unittest discover -s tests -v

build:
	$(PYTHON) build_repro.py

check:
	./release_check.sh

proof: check
	printf "\nPython:\n"
	$(PYTHON) --version
	printf "\nRuntime manifest:\n"
	@if [ -s requirements.txt ]; then echo "ERROR: requirements.txt is not empty"; exit 1; else echo "EMPTY"; fi
	printf "\nEnvironment packages (evidence only):\n"
	$(PYTHON) -m pip list --format=freeze 2>/dev/null || true

release:
	./release_check.sh
	printf "\nFinal artifact SHA-256:\n"
	sha256sum build/sealbox.pyz

source-archive:
	git archive --format=zip --output=sealbox-source.zip HEAD
	@echo "created sealbox-source.zip from Git HEAD"

clean:
	rm -rf build/*.pyz __pycache__ tests/__pycache__
