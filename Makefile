.PHONY: help install install-full dev test lint format clean build publish docker

VERSION := $(shell python3 -c "from core.__version__ import __version__; print(__version__)" 2>/dev/null || echo "5.0.3")
PY := python3

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install minimal (click + rich)
	$(PY) -m pip install -e .

install-full: ## Install full with all optional deps
	$(PY) -m pip install -e ".[full]"

dev: ## Install dev dependencies
	$(PY) -m pip install -e ".[dev,full]"
	pre-commit install 2>/dev/null || true

test: ## Run tests
	$(PY) -m pytest tests/ -q --ignore=tests/test_cli_theme.py -v

test-cov: ## Run tests with coverage
	$(PY) -m pytest tests/ --cov=core --cov=modules --cov-report=term-missing --ignore=tests/test_cli_theme.py

lint: ## Lint with ruff + pyflakes + bandit
	ruff check core cli modules layers || true
	pyflakes core cli layers modules || true
	bandit -r core cli layers modules -lll -q || true

format: ## Format with black
	black core cli modules layers tests --line-length 100

clean: ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ .ruff_cache/ .mypy_cache/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

build: clean ## Build wheel + sdist
	$(PY) -m build

check-build: build ## Check build with twine
	$(PY) -m twine check dist/*

publish-test: check-build ## Publish to TestPyPI
	$(PY) -m twine upload --repository testpypi dist/*

publish: check-build ## Publish to PyPI (requires TWINE_USERNAME + TWINE_PASSWORD)
	$(PY) -m twine upload dist/*

docker: ## Build Docker image
	docker build -t r3con:$(VERSION) -t r3con:latest .

docker-run: ## Run Docker image
	docker run --rm -it r3con:latest r3con --help

version: ## Show version
	@echo $(VERSION)

bump-patch: ## Bump patch version
	$(PY) scripts/bump_version.py patch

bump-minor: ## Bump minor version
	$(PY) scripts/bump_version.py minor

security: ## Security audit
	bandit -r core cli modules -f json -o bandit-report.json || true
	$(PY) -m pip audit 2>/dev/null || echo "pip-audit not installed, run: pip install pip-audit"

install-hooks: ## Install git hooks
	@echo "#!/bin/sh\nmake lint test -q" > .git/hooks/pre-push
	@chmod +x .git/hooks/pre-push
	@echo "Pre-push hook installed"
