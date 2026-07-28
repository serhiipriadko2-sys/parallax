.PHONY: test test-core test-runtime test-openai eval-validate verify-core verify-runtime verify-openai release clean

PYTHON ?= python
RELEASE_ZIP ?= ../parallax-omega-agent-stack-rc2.zip
RELEASE_MANIFEST ?= ../PARALLAX_OMEGA_RC2_MANIFEST.json

test: test-core

test-core:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/run_tests.py --profile core --verbose

test-runtime:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/run_tests.py --profile runtime --verbose

test-openai:
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/run_tests.py --profile openai --verbose
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/verify_optional_surfaces.py --require all

eval-validate:
	$(PYTHON) scripts/run_evals.py

verify-core: clean test-core eval-validate
	$(PYTHON) scripts/secret_scan.py
	$(PYTHON) scripts/validate_package.py --skip-ledger

verify-runtime: test-runtime verify-core

verify-openai: test-openai verify-runtime

release: verify-runtime clean
	$(PYTHON) scripts/build_release.py --output $(RELEASE_ZIP)
	$(PYTHON) scripts/validate_package.py
	$(PYTHON) scripts/release_manifest.py build $(RELEASE_ZIP) --output $(RELEASE_MANIFEST)
	$(PYTHON) scripts/release_manifest.py verify $(RELEASE_ZIP) --manifest $(RELEASE_MANIFEST)

clean:
	rm -rf build .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name '*.egg-info' -prune -exec rm -rf {} +
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
