# Installation and Setup Guide

## Prerequisites

- Python 3.8 or higher
- pip package manager
- C compiler (gcc, clang, or MSVC) for compiling native extensions
- git for version control

## System Dependencies

### macOS

```bash
brew install python3 gcc liboqs
```

### Ubuntu/Debian

```bash
sudo apt-get install python3 python3-pip build-essential liboqs-dev
```

### Windows

Download and install:
- Python from https://www.python.org
- Microsoft C++ Build Tools
- liboqs from https://github.com/open-quantum-safe/liboqs/wiki/Windows

## Installation Steps

### 1. Clone Repository

```bash
git clone https://github.com/Balancebreaker-13/bitcoin-wallet-post-quantum-migration.git
cd bitcoin-wallet-post-quantum-migration
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Verify Installation

```bash
python3 -c "import oqs; print('liboqs-python:', oqs.OQS_VERSION)"
python3 -c "from src.pqc.core import DilithiumSigner; print('PQC module OK')"
python3 -c "from src.hybrid import HybridWallet; print('Hybrid wallet OK')"
```

## Development Setup

For development, install additional testing and linting tools:

```bash
pip install pytest pytest-cov black flake8 mypy isort
```

Run tests to verify everything works:

```bash
pytest tests/ -v
```

## Troubleshooting

### liboqs Backend Unavailable

If you see: `PQCBackendUnavailable: The liboqs backend is unavailable`

**Solution:**

1. Ensure liboqs is installed system-wide
2. Reinstall liboqs-python:
   ```bash
   pip install --force-reinstall liboqs-python
   ```
3. Verify native backend:
   ```bash
   python3 -c "import oqs; print(oqs.lib)"
   ```

### Import Errors

If you see module import errors:

```bash
# Reinstall in development mode
pip install -e .

# Verify paths
python3 -c "import sys; print('\n'.join(sys.path))"
```

### ECDSA Module Issues

If ECDSA tests fail:

```bash
pip install --upgrade ecdsa
python3 -c "from ecdsa import SigningKey; print('ecdsa OK')"
```

### Windows Specific Issues

For native compilation issues on Windows:

```bash
# Use pre-built wheels
pip install --only-binary :all: liboqs-python

# Or build with MSVC
set VCINSTALLDIR=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community
pip install liboqs-python
```

## Next Steps

After successful installation:

1. Review the [README.md](../README.md) for project overview
2. Check [ROADMAP.md](../ROADMAP.md) for development phases
3. Explore example code in `poc/` directory
4. Run tests: `pytest tests/ -v`
5. Review contributing guidelines in [CONTRIBUTING.md](./CONTRIBUTING.md)

## Environment Variables

Optional configuration via environment variables:

```bash
# Enable verbose PQC logging
export OQS_DEBUG=1

# Set custom key storage location
export HYBRID_KEYS_FILE=/path/to/keys.encrypted.json

# Enable test mode (skip network operations)
export TEST_MODE=1
```

## Documentation

For detailed documentation:

- **API Docs**: See docstrings in source files
- **Architecture**: [docs/ARCHITECTURE.md](./ARCHITECTURE.md)
- **PoC Guide**: [poc/README.md](../poc/README.md)
- **Roadmap**: [ROADMAP.md](../ROADMAP.md)
