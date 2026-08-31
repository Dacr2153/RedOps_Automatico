.PHONY: install venv test test-unit test-integration run health lint format clean report setup-arch

# ── Virtualenv management ──────────────────────────────────────────
# On Arch Linux (externally-managed Python), always work inside .venv
VENV        := .venv
PYTHON      := $(VENV)/bin/python
PIP         := $(VENV)/bin/pip
PYTEST      := $(VENV)/bin/pytest
RUFF        := $(VENV)/bin/ruff
MYPY        := $(VENV)/bin/mypy
BLACK       := $(VENV)/bin/black
ISORT       := $(VENV)/bin/isort

$(VENV)/bin/activate:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip setuptools wheel

venv: $(VENV)/bin/activate

install: venv
	$(PIP) install -e ".[dev]"

# ── Arch Linux system prerequisites ───────────────────────────────
# Run once as root to install nmap and other system-level tools.
# Metasploit must be installed separately via AUR: yay -S metasploit
# Ollama: curl -fsSL https://ollama.com/install.sh | sh
setup-arch:
	@echo "Installing system packages for Arch Linux..."
	sudo pacman -Sy --noconfirm python python-pip nmap net-tools iproute2
	@echo ""
	@echo "Next steps:"
	@echo "  1. Install Metasploit:  yay -S metasploit"
	@echo "  2. Install Ollama:      curl -fsSL https://ollama.com/install.sh | sh"
	@echo "  3. Pull Mistral model:  ollama pull mistral"
	@echo "  4. Install RedOps:      make install"
	@echo "  5. Configure .env:      cp .env.example .env && \$$EDITOR .env"

# ── Testing ────────────────────────────────────────────────────────
test: install
	$(PYTEST) tests/ -v --cov=src/redops --cov-report=term-missing

test-unit: install
	$(PYTEST) tests/unit/ -v --cov=src/redops --cov-report=term-missing

test-integration: install
	$(PYTEST) tests/integration/ -v -m integration

# ── Code quality ───────────────────────────────────────────────────
lint: install
	$(RUFF) check src/ tests/
	$(MYPY) src/

format: install
	$(BLACK) src/ tests/
	$(ISORT) src/ tests/

# ── Runtime ────────────────────────────────────────────────────────
run: install
	$(PYTHON) -m redops run --target 192.168.56.0/24 --profile balanced

health: install
	$(PYTHON) -m redops health

report: install
	$(PYTHON) -m redops report --checkpoint $(CHECKPOINT)

# ── Housekeeping ───────────────────────────────────────────────────
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage

