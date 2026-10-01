# Developer Setup

This guide covers the commands required to configure a local development environment for the project.

## Clone and create a virtual environment

```bash
git clone https://github.com/Balancebreaker-13/bitcoin-wallet-post-quantum-migration.git
cd bitcoin-wallet-post-quantum-migration
python3 -m venv .venv
source .venv/bin/activate
```

## Install dependencies

```bash
pip install -U pip
pip install -r requirements.txt
```

## Optional PQC backend

If the liboqs backend is unavailable, install the liboqs native library used by the Python bindings. The code intentionally fails closed rather than silently falling back to insecure primitives.

## Validate install

```bash
python -c "from src.pqc.core import backend_available; print(backend_available())"
python -c "from src.hybrid import HybridWallet; print(HybridWallet().generate_hybrid_keypair().key_id)"
```

## Recommended tooling

```bash
pip install black flake8 pytest pytest-cov mypy
```

## Common commands

```bash
pytest -q
pytest tests/test_integration.py -q
pytest tests/test_performance.py -q
```
