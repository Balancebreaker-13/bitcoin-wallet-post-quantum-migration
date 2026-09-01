# Post-Quantum Cryptography - Bitcoin Wallet Migration PoC

## Overview

This Proof of Concept (PoC) demonstrates the integration of post-quantum cryptography (PQC) algorithms into Bitcoin wallet infrastructure. The PoC showcases:

- **Dilithium**: NIST-standardized post-quantum digital signature scheme
- **Kyber**: NIST-standardized post-quantum key encapsulation mechanism
- **Hybrid Approach**: Combining traditional ECC (secp256k1) with PQC for transitional security

## Phase 2: PoC Implementation

### Objectives

✓ Validate PQC algorithm implementations
✓ Demonstrate hybrid key generation and management
✓ Test transaction signing with quantum-resistant algorithms
✓ Establish baseline performance metrics
✓ Provide migration pathway documentation

### Key Components

#### 1. Environment Setup (`environment_setup.md`)
Complete guide for setting up the development environment with:
- System dependencies
- Python virtual environment
- liboqs library installation
- Troubleshooting guide

#### 2. Dilithium Demo (`dilithium_demo.py`)
Demonstrates the Dilithium signature scheme:
- Keypair generation at multiple security levels (2, 3, 5)
- Message signing
- Signature verification
- Key import/export with JSON serialization

**Key Features:**
- NIST Security Level 2, 3, and 5 support
- Deterministic signing
- ~2420 bytes public key size (Level 3)
- ~2544 bytes private key size (Level 3)
- Signature size: ~2420 bytes (Level 3)

#### 3. Kyber Demo (`kyber_demo.py`)
Demonstrates the Kyber KEM algorithm:
- Keypair generation at multiple security levels (512, 768, 1024)
- Encapsulation (shared secret generation)
- Decapsulation (shared secret recovery)
- Verified secret synchronization between parties

**Key Features:**
- NIST Security Level 1, 3, and 5 support
- IND-CCA2 security
- ~1184 bytes public key (Level 3)
- ~2400 bytes secret key (Level 3)
- Ciphertext size: ~1088 bytes (Level 3)
- Shared secret size: 32 bytes

#### 4. Hybrid Key Generation (`hybrid_key_demo.py`)
Demonstrates hybrid ECC+PQC approach:
- Combines secp256k1 (ECC) with Dilithium (PQC signatures)
- Combines ECC with Kyber (PQC key exchange)
- Hybrid key management and serialization
- Transaction signing with dual cryptography

**Benefits:**
- Backward compatibility with Bitcoin infrastructure
- Quantum-resistant signatures for future security
- Transitional migration pathway
- No breaking changes to existing systems

#### 5. Comprehensive Test Suite (`test_poc.py`)
Full test coverage including:
- Unit tests for each algorithm
- Integration tests for complete workflows
- Key import/export validation
- Shared secret verification
- Error handling and edge cases

**Test Statistics:**
- 30+ test cases
- Covers all security levels
- Integration workflow tests
- PoC artifact validation

## Quick Start

### Prerequisites
- Python 3.8+
- pip package manager
- C compiler (gcc/clang)

### Installation

```bash
# 1. Navigate to PoC directory
cd poc

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements_poc.txt

# 4. Verify installation
python3 -c "import oqs; print(oqs.OQS_VERSION)"
```

### Running PoC Demos

```bash
# Run Dilithium demo
python3 dilithium_demo.py

# Run Kyber demo
python3 kyber_demo.py

# Run Hybrid key generation demo
python3 hybrid_key_demo.py

# Run comprehensive test suite
python3 test_poc.py
```

## Architecture

### Hybrid Key Structure

```
HybridPublicKey
├── ecc_pubkey_hex (secp256k1)
├── pqc_pubkey_hex (Dilithium)
├── kyber_pubkey_hex (Kyber)
├── key_id (SHA256 hash)
└── security_levels

HybridPrivateKey
├── ecc_privkey_hex (secp256k1)
├── pqc_privkey_hex (Dilithium)
├── kyber_privkey_hex (Kyber)
└── key_id (reference)
```

### Hybrid Signature Format

```
[Version: 1 byte]
[ECC Sig Length: 2 bytes]
[ECC Signature: variable]
[PQC Sig Length: 2 bytes]
[PQC Signature: variable]
```

## Performance Characteristics

### Key Sizes (Level 3)

| Algorithm | Component | Size (bytes) |
|-----------|-----------|--------------|
| Dilithium3 | Public Key | 2420 |
| Dilithium3 | Private Key | 2544 |
| Dilithium3 | Signature | 2420 |
| Kyber768 | Public Key | 1184 |
| Kyber768 | Secret Key | 2400 |
| Kyber768 | Ciphertext | 1088 |
| Kyber768 | Shared Secret | 32 |

### Size Comparison

- **Traditional Bitcoin Signature (ECDSA)**: ~71 bytes
- **Hybrid Signature (ECC + Dilithium3)**: ~2491+ bytes
- **Increase Factor**: ~35x (manageable for blockchain integration)

## Migration Pathway

### Phase 1: Hybrid Wallets (Current PoC)
- Deploy wallets supporting both ECC and PQC
- Dual signing for all transactions
- Backward compatible with legacy systems
- No protocol changes required

### Phase 2: Transitional Validation
- Gradually increase PQC signature weight
- Monitor network adoption
- Performance optimization
- Security analysis and hardening

### Phase 3: Full PQC Migration
- Primary signature scheme becomes PQC
- Legacy ECC signatures phased out
- Optimized key and signature sizes
- Blockchain protocol update (if needed)

## Security Considerations

### NIST Standardization
- All algorithms passed NIST PQC standardization process
- Rigorous security analysis by cryptographic community
- Resistant to known quantum computing attacks
- Conservative parameter selection

### Quantum Resistance
- Dilithium: lattice-based signatures
- Kyber: lattice-based key encapsulation
- Both resistant to Shor's algorithm and variants
- No known polynomial-time quantum attacks

### Implementation Security
- Uses official liboqs library (Open Quantum Safe project)
- Well-tested and actively maintained
- Compatible with cryptographic standards
- Regular security updates

## File Structure

```
poc/
├── environment_setup.md           # Setup instructions
├── requirements_poc.txt           # Python dependencies
├── dilithium_demo.py             # Dilithium PoC
├── kyber_demo.py                 # Kyber PoC
├── hybrid_key_demo.py            # Hybrid key generation
├── test_poc.py                   # Test suite
├── README.md                      # This file
└── keys/                          # Generated keys (not in repo)
    ├── dilithium_keys.json
    ├── kyber_keys.json
    └── hybrid_keys.json
```

## Testing

### Run All Tests
```bash
python3 test_poc.py
```

### Run Specific Test Class
```bash
python3 -m unittest test_poc.TestDilithiumPoC
python3 -m unittest test_poc.TestKyberPoC
python3 -m unittest test_poc.TestHybridKeyGenerator
```

### Test Coverage
```bash
pytest --cov=. test_poc.py
```

## Results & Findings

### Successful PoC Achievements

✓ Dilithium signature generation and verification working
✓ Kyber key encapsulation and decapsulation synchronized
✓ Hybrid keypair generation functional
✓ Key serialization and deserialization reliable
✓ Transaction signing with dual cryptography demonstrated
✓ All test cases passing (30+ tests)

### Key Observations

1. **Performance**: PQC algorithms execute in milliseconds on modern hardware
2. **Key Sizes**: ~35x larger than traditional ECC, acceptable for blockchain use
3. **Compatibility**: Hybrid approach maintains full backward compatibility
4. **Security**: No known vulnerabilities in NIST-standardized algorithms
5. **Integration**: Ready for blockchain integration with minimal protocol changes

## Next Steps (Phase 3)

1. **Blockchain Integration**
   - Modify Bitcoin Core to support hybrid signatures
   - Create transaction format extensions
   - Implement validation rules

2. **Performance Optimization**
   - Signature aggregation techniques
   - Batch verification methods
   - Hardware acceleration exploration

3. **Network Deployment**
   - Testnet rollout
   - Performance monitoring
   - Security audits

4. **Migration Timeline**
   - Staged rollout plan
   - Legacy support duration
   - Protocol upgrade coordination

## References

- [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography/)
- [liboqs Documentation](https://liboqs.org/)
- [liboqs-python GitHub](https://github.com/open-quantum-safe/liboqs-python)
- [Dilithium Specification](https://pq-crystals.org/dilithium/)
- [Kyber Specification](https://pq-crystals.org/kyber/)
- [Bitcoin Developer Guide](https://developer.bitcoin.org/reference/block_chain.html)

## Contributors

- Phase 2 PoC Implementation: Team

## License

See repository LICENSE file for details

---

**Status**: Phase 2 - PoC Implementation Complete
**Last Updated**: September 1, 2026
**Next Phase**: Phase 3 - Blockchain Integration
