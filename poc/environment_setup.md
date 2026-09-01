# Proof of Concept - Environment Setup

## Overview
This document provides step-by-step instructions for setting up the development environment for the Bitcoin Wallet Post-Quantum Migration Proof of Concept.

## Prerequisites

- Python 3.8+
- pip package manager
- git
- C compiler (gcc/clang)
- liboqs development libraries

## Installation Steps

### 1. Clone the Repository

```bash
git clone https://github.com/Balancebreaker-13/bitcoin-wallet-post-quantum-migration.git
cd bitcoin-wallet-post-quantum-migration
git checkout phase-2-poc-implementation
```

### 2. Install System Dependencies

#### On Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev libffi-dev python3-dev
```

#### On macOS:
```bash
brew install liboqs
brew install openssl
```

#### On Windows (with MSVC):
```bash
# Download and install Visual Studio Build Tools
# Install Python 3.8+ with pip
```

### 3. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 4. Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 5. Install liboqs Python Bindings

```bash
pip install liboqs-python
```

Or build from source:
```bash
git clone https://github.com/open-quantum-safe/liboqs-python.git
cd liboqs-python
pip install .
cd ..
```

### 6. Verify Installation

```bash
python3 -c "import oqs; print(oqs.OQS_VERSION)"
```

## Dependencies Overview

- **liboqs-python**: Post-Quantum Cryptography library bindings
- **cryptography**: General cryptography utilities
- **pytest**: Testing framework
- **pytest-cov**: Code coverage reporting

## Project Structure for PoC

```
poc/
├── environment_setup.md          # This file
├── requirements_poc.txt          # PoC-specific dependencies
├── dilithium_demo.py            # Dilithium signature demo
├── kyber_demo.py                # Kyber KEM demo
├── hybrid_key_demo.py           # Hybrid key generation demo
└── test_poc.py                  # PoC tests
```

## Troubleshooting

### Issue: liboqs not found
**Solution**: Make sure liboqs is installed system-wide or set `LD_LIBRARY_PATH`:
```bash
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

### Issue: Python version mismatch
**Solution**: Ensure Python 3.8+ is being used:
```bash
python3 --version
```

### Issue: Permission denied during pip install
**Solution**: Use `pip install --user` or activate virtual environment properly

## Testing Environment

Run the following to verify your setup:

```bash
cd poc
python3 test_poc.py
```

## Next Steps

1. Run `dilithium_demo.py` to test Dilithium signatures
2. Run `kyber_demo.py` to test Kyber KEM
3. Run `hybrid_key_demo.py` to test hybrid key generation
4. Review `test_poc.py` for comprehensive tests

## References

- [liboqs Documentation](https://liboqs.org/)
- [liboqs-python GitHub](https://github.com/open-quantum-safe/liboqs-python)
- [NIST PQC](https://csrc.nist.gov/projects/post-quantum-cryptography/)

---

**Created:** September 1, 2026
**Status:** PoC - Phase 2
