# Testing Strategy & Best Practices

## Overview

This document outlines the testing strategy for the Bitcoin Wallet Post-Quantum Cryptography Migration project.

## Testing Levels

### 1. Unit Tests

**Purpose:** Test individual components in isolation

**Coverage:**
- PQC algorithm implementations
- ECDSA operations
- Signature encoding/decoding
- Key serialization
- Input validation

**Files:**
- `tests/test_pqc_core.py` - PQC algorithms
- `tests/test_hybrid_wallet.py` - Hybrid wallet
- `tests/test_bitcoin_integration.py` - Bitcoin transactions

**Execution:**
```bash
pytest tests/test_*.py -v
```

### 2. Integration Tests

**Purpose:** Test workflows combining multiple components

**Coverage:**
- Wallet creation and key generation
- Transaction signing and verification
- Key storage and retrieval
- Cross-wallet compatibility
- End-to-end workflows

**Files:**
- `tests/test_integration.py` - Integration workflows

**Execution:**
```bash
pytest tests/test_integration.py -v
```

### 3. Performance Tests

**Purpose:** Benchmark critical operations

**Coverage:**
- Keypair generation timing
- Signing performance
- Verification performance
- Key size analysis
- Stress tests

**Files:**
- `tests/test_performance.py` - Performance benchmarks

**Execution:**
```bash
pytest tests/test_performance.py -v -s
```

### 4. Security Tests

**Purpose:** Verify security properties

**Coverage:**
- Tamper detection
- Error handling
- Input validation
- Key protection
- Backend availability checks

**Files:**
- Throughout all test files

**Execution:**
```bash
pytest tests/ -k "tamper or error or validation" -v
```

## Test Environment Setup

### Prerequisites

```bash
# Install dependencies
pip install -r requirements.txt

# Verify backend
python3 -c "from src.pqc.core import backend_available; assert backend_available()"
```

### Running All Tests

```bash
# Run full test suite
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Run specific test file
pytest tests/test_integration.py -v

# Run specific test
pytest tests/test_integration.py::TestWalletCreationWorkflow::test_create_wallet_and_generate_keypair -v
```

## Test Coverage Goals

| Module | Target | Status |
|--------|--------|--------|
| PQC Core | 95%+ | ✅ |
| Hybrid Wallet | 90%+ | ✅ |
| Bitcoin Integration | 85%+ | ✅ |
| Key Management | 80%+ | ⏳ |
| **Overall** | **80%+** | ✅ |

## Continuous Integration

### GitHub Actions Workflow

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run tests
        run: pytest tests/ -v --cov=src
      - name: Upload coverage
        uses: codecov/codecov-action@v2
```

## Manual Testing Checklist

### Wallet Creation
- [ ] Create new wallet
- [ ] Generate hybrid keypair
- [ ] Verify key ID
- [ ] Check key sizes
- [ ] Serialize/deserialize keys

### Transaction Signing
- [ ] Build transaction
- [ ] Sign with hybrid key
- [ ] Verify signature
- [ ] Check signature size (~3500 bytes)
- [ ] Tamper with signature (should fail)

### Key Storage
- [ ] Store encrypted key
- [ ] List stored keys
- [ ] Retrieve key
- [ ] Verify retrieved matches stored
- [ ] Delete key
- [ ] Confirm deletion

### Error Cases
- [ ] Invalid security level
- [ ] Missing backend
- [ ] Malformed keys
- [ ] Truncated signatures
- [ ] Non-existent keys

## Testing Best Practices

### Do's
✅ Use fixtures for common setup  
✅ Test edge cases and error paths  
✅ Use descriptive test names  
✅ Parametrize similar tests  
✅ Mock external dependencies  
✅ Clear test data after tests  
✅ Document complex test logic  

### Don'ts
❌ Don't write untestable code  
❌ Don't test implementation details  
❌ Don't use hardcoded test data  
❌ Don't skip security tests  
❌ Don't leave temporary files  
❌ Don't test random behavior (use seeds)  

## Debugging Tests

### Verbose Output
```bash
pytest tests/test_integration.py -v -s  # Show print statements
```

### Debug Mode
```bash
pytest tests/test_integration.py --pdb  # Drop to debugger on failure
```

### Specific Test
```bash
pytest tests/test_integration.py::TestWalletCreationWorkflow::test_create_wallet_and_generate_keypair -v
```

### Show Coverage Report
```bash
pytest tests/ --cov=src --cov-report=term-missing
```

## Test Metrics

### Key Metrics
- **Code Coverage:** Target 80%+
- **Test Pass Rate:** 100%
- **Performance:** All ops complete in acceptable time
- **Security:** No known vulnerabilities

### Monitoring
```bash
# Coverage report
pytest tests/ --cov=src --cov-report=html
open htmlcov/index.html

# Performance benchmarks
pytest tests/test_performance.py -v -s
```

## Known Limitations

1. **Backend Dependency:** Tests skip if liboqs not available
2. **File System:** Tests use tmp_path fixture (requires write access)
3. **Performance:** Benchmarks vary by hardware
4. **Randomness:** Some tests are non-deterministic

## Future Testing Enhancements

- [ ] Formal cryptographic verification
- [ ] Fuzzing for input validation
- [ ] Network protocol testing
- [ ] Long-running stability tests
- [ ] Hardware-specific benchmarks
- [ ] Compatibility with Bitcoin Core

## References

- Pytest: https://docs.pytest.org/
- Coverage.py: https://coverage.readthedocs.io/
- Bitcoin Test Documentation: https://developer.bitcoin.org/reference/
