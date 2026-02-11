SHELL := /bin/bash
# =============================================================================
# litestar-api-auth Makefile
# =============================================================================

.DEFAULT_GOAL := help
.ONESHELL:
UV_OPTS ?=
UV     ?= uv $(UV_OPTS)

.EXPORT_ALL_VARIABLES:

.PHONY: help install dev clean lint fmt test docs
.PHONY: fmt-fix fmt-check type-check ruff ruff-check security
.PHONY: docs-serve docs-clean
.PHONY: install-uv install-prek upgrade lock
.PHONY: wt worktree wt-ls worktree-list wt-j worktree-jump worktree-prune
.PHONY: example-minimal example-full
.PHONY: ci ci-install
.PHONY: act act-ci act-docs act-list
.PHONY: test-cov test-fast test-parallel test-debug test-failed

help: ## Display this help text for Makefile
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

# =============================================================================
# Setup & Installation
# =============================================================================

##@ Setup & Installation

install-uv: ## Install latest version of UV
	@echo "=> Installing uv"
	@curl -LsSf https://astral.sh/uv/install.sh | sh
	@echo "=> uv installed"

install-prek: ## Install prek and install hooks
	@echo "=> Installing prek hooks"
	@$(UV) run prek install
	@$(UV) run prek install --hook-type commit-msg
	@$(UV) run prek install --hook-type pre-push
	@echo "=> prek hooks installed"
	@$(UV) run prek autoupdate
	@echo "=> prek installed"

install: ## Install package (production mode)
	@echo "=> Installing package (production mode)"
	@$(UV) sync --no-dev
	@echo "=> Installation complete"

dev: ## Install package with all development dependencies
	@echo "=> Installing package with dev dependencies"
	@$(UV) sync
	@echo "=> Dev installation complete"

upgrade: ## Upgrade all dependencies to the latest stable versions
	@echo "=> Upgrading prek"
	@$(UV) run prek autoupdate
	@$(UV) lock --upgrade
	@echo "=> Dependencies upgraded"

lock: ## Update lock file
	@$(UV) lock

# =============================================================================
# Code Quality
# =============================================================================

##@ Code Quality

lint: ## Runs prek hooks (includes ruff, codespell, etc.)
	@$(UV) run --no-sync prek run --all-files

fmt: ## Runs Ruff format, makes changes where necessary
	@$(UV) run --no-sync ruff format .

fmt-check: ## Runs Ruff format in check mode (no changes)
	@$(UV) run --no-sync ruff format --check .

fmt-fix: ## Runs Ruff with auto-fix
	@$(UV) run --no-sync ruff check --fix .

ruff: ## Runs Ruff with unsafe fixes
	@$(UV) run --no-sync ruff check . --unsafe-fixes --fix

ruff-check: ## Runs Ruff without changing files
	@$(UV) run --no-sync ruff check .

type-check: ## Run ty type checker
	@$(UV) run --no-sync ty check

# =============================================================================
# Security
# =============================================================================

##@ Security

security: ## Run zizmor GitHub Actions security scanner
	@echo "=> Running zizmor security scan on GitHub Actions workflows"
	@uvx zizmor .github/workflows/

# =============================================================================
# Testing
# =============================================================================

##@ Testing

test: ## Run the tests
	@PYTHONDONTWRITEBYTECODE=1 $(UV) run --no-sync pytest

test-cov: ## Run tests with coverage report
	@PYTHONDONTWRITEBYTECODE=1 $(UV) run --no-sync pytest --cov=src/litestar_api_auth --cov-report=html --cov-report=term-missing --cov-report=xml

test-fast: ## Run tests without coverage (faster)
	@PYTHONDONTWRITEBYTECODE=1 $(UV) run --no-sync pytest -x -q

test-parallel: ## Run tests in parallel with pytest-xdist
	@PYTHONDONTWRITEBYTECODE=1 $(UV) run --no-sync pytest -n auto

test-parallel-fast: ## Run unit tests in parallel
	@PYTHONDONTWRITEBYTECODE=1 $(UV) run --no-sync pytest -n auto -m "not integration"

test-debug: ## Run tests with verbose output and no capture
	@PYTHONDONTWRITEBYTECODE=1 $(UV) run --no-sync pytest -vv -s

test-failed: ## Re-run only failed tests from last run
	@PYTHONDONTWRITEBYTECODE=1 $(UV) run --no-sync pytest --lf

# =============================================================================
# Documentation
# =============================================================================

##@ Documentation

docs: docs-clean ## Build documentation
	@echo "=> Building documentation"
	@$(UV) sync --group docs
	@$(UV) run sphinx-build -M html docs docs/_build/ -E -a -j auto --keep-going

docs-serve: docs-clean ## Serve documentation with live reload
	@echo "=> Serving documentation"
	@$(UV) sync --group docs
	@$(UV) run sphinx-autobuild docs docs/_build/ -j auto --port 8001

docs-clean: ## Clean built documentation
	@echo "=> Cleaning documentation build assets"
	@rm -rf docs/_build
	@echo "=> Removed existing documentation build assets"

# =============================================================================
# Build & Release
# =============================================================================

##@ Build & Release

build: ## Build package
	@$(UV) build

clean: ## Autogenerated file cleanup
	@echo "=> Cleaning up autogenerated files"
	@rm -rf .pytest_cache .ruff_cache .hypothesis build/ dist/ .eggs/
	@find . -name '*.egg-info' -exec rm -rf {} + 2>/dev/null || true
	@find . -name '*.egg' -exec rm -rf {} + 2>/dev/null || true
	@find . -name '*.pyc' -exec rm -rf {} + 2>/dev/null || true
	@find . -name '*.pyo' -exec rm -rf {} + 2>/dev/null || true
	@find . -name '*~' -exec rm -rf {} + 2>/dev/null || true
	@find . -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	@rm -rf .coverage coverage.xml coverage.json htmlcov/
	$(MAKE) docs-clean

destroy: ## Destroy the virtual environment
	@rm -rf .venv

# =============================================================================
# Git Worktrees
# =============================================================================

##@ Git Worktrees

wt: worktree ## Alias for worktree
worktree: ## Create a new git worktree for feature branch (Usage: make wt NAME=my-feature)
	@echo "=> Creating git worktree"
	@if [ -z "$(NAME)" ]; then \
		read -p "Feature name: " name; \
	else \
		name="$(NAME)"; \
	fi; \
	if [ -z "$$name" ]; then \
		echo "ERROR: Feature name cannot be empty"; \
		echo "Usage: make wt NAME=my-feature"; \
		exit 1; \
	fi; \
	mkdir -p .worktrees && \
	git checkout main && git pull && \
	git worktree add .worktrees/$$name -b $$name && \
	echo "=> Worktree created at .worktrees/$$name on branch $$name"

wt-ls: worktree-list ## Alias for worktree-list
worktree-list: ## List all git worktrees
	@git worktree list

wt-j: worktree-jump ## Alias for worktree-jump
worktree-jump: ## Jump to a worktree (Usage: cd $(make wt-j NAME=foo) or make wt-j to list)
	@if [ -z "$(NAME)" ]; then \
		echo "Available worktrees:"; \
		git worktree list --porcelain | grep "^worktree" | cut -d' ' -f2; \
		echo ""; \
		echo "Usage: cd \$$(make wt-j NAME=<name>)"; \
	else \
		path=".worktrees/$(NAME)"; \
		if [ -d "$$path" ]; then \
			echo "$$path"; \
		else \
			echo "Worktree not found: $$path" >&2; \
			exit 1; \
		fi; \
	fi

worktree-prune: ## Clean up stale git worktrees
	@echo "=> Pruning stale git worktrees"
	@git worktree prune -v
	@echo "=> Stale worktrees pruned"

# =============================================================================
# Examples
# =============================================================================

##@ Examples

example-minimal: ## Run the minimal example app (port 8005)
	@echo "=> Running minimal example at http://127.0.0.1:8005"
	@$(UV) run uvicorn examples.minimal.app:app --reload --port 8005

example-full: ## Run the full example app (port 8001)
	@echo "=> Running full example at http://127.0.0.1:8001"
	@$(UV) run uvicorn examples.full.app:app --reload --port 8001

# =============================================================================
# CI Helpers
# =============================================================================

##@ CI Helpers

ci: lint type-check fmt test ## Run all CI checks locally

ci-install: ## Install for CI (frozen dependencies)
	@echo "=> Installing dependencies for CI"
	@$(UV) sync --frozen
	@echo "=> CI installation complete"

# =============================================================================
# Local GitHub Actions
# =============================================================================

##@ Local GitHub Actions (act)

act: ## Run all CI workflows locally with act
	@echo "=> Running CI workflows locally with act"
	@act -l 2>/dev/null || (echo "Error: 'act' not installed. Install with: brew install act" && exit 1)
	@act push --container-architecture linux/amd64

act-ci: ## Run CI workflow locally
	@echo "=> Running CI workflow locally"
	@act push -W .github/workflows/ci.yml --container-architecture linux/amd64

act-docs: ## Run docs workflow locally
	@echo "=> Running docs workflow locally"
	@act push -W .github/workflows/docs.yml --container-architecture linux/amd64

act-list: ## List available act jobs
	@act -l
