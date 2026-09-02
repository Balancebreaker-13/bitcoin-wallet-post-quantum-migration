# Bitcoin Wallet Post-Quantum Cryptography Migration Roadmap

## Overview
This roadmap outlines the comprehensive plan for migrating Bitcoin wallets from traditional elliptic curve cryptography (ECC) to post-quantum cryptography (PQC) algorithms. The project encompasses a phased approach from research through production deployment.

---

## Phase 1: Research & Analysis (Q1 2026) - ✅ COMPLETED

### 1.1 Post-Quantum Cryptography Research
**Documentation Tasks:**
- [x] Study NIST PQC standardization process and finalists
- [x] Analyze Lattice-based cryptography (Kyber, Dilithium)
- [x] Evaluate Hash-based signatures (XMSS, LMS)
- [x] Compare Code-based cryptography (Classic McEliece)
- [x] Document quantum threat timeline for Bitcoin
- [x] Create threat assessment report

**Research Documentation File:** `docs/research/pqc_analysis.md`

### 1.2 Bitcoin Cryptography Deep Dive
**Documentation Tasks:**
- [x] Document current Bitcoin ECDSA (secp256k1) implementation
- [x] Analyze Schnorr signatures in Bitcoin
- [x] Study BIP340, BIP341, BIP342 Taproot specifications
- [x] Research key derivation methods (BIP32, BIP44)
- [x] Document transaction signing process

**Research Documentation File:** `docs/research/bitcoin_cryptography.md`

### 1.3 Migration Strategy Analysis
**Documentation Tasks:**
- [x] Analyze hybrid cryptography approaches
- [x] Study key agility mechanisms
- [x] Design wallet backward compatibility strategies
- [x] Evaluate performance/size trade-offs
- [x] Create migration timeline proposal

**Migration Strategy File:** `docs/research/migration_strategy.md`

---

## Phase 2: Design & Planning (Q2 2026) - ✅ COMPLETED

### 2.1 Architecture Design
**Documentation:**
- [x] Design hybrid wallet architecture
- [x] Create data flow diagrams
- [x] Define API specifications
- [x] Document key storage improvements
- [x] Create security requirements document

**Design Documentation:** `docs/design/architecture.md`

### 2.2 Implementation Planning
**Documentation:**
- [x] Create detailed implementation plan
- [x] Define testing strategy
- [x] Plan integration approach
- [x] Document deployment strategy
- [x] Create risk mitigation plan

**Planning Document:** `docs/design/implementation_plan.md`

### 2.3 Proof of Concept (PoC)
**Tasks:**
- [x] Set up development environment with liboqs
- [x] Create basic Dilithium signature implementation
- [x] Create basic Kyber KEM implementation
- [x] Build simple hybrid key generation demo
- [x] Document PoC results

**PoC Files:** `poc/dilithium_demo.py`, `poc/kyber_demo.py`

---

## Phase 3: Core Implementation (Q3-Q4 2026) - ✅ COMPLETED

### 3.1 Post-Quantum Cryptography Library Setup - ✅ COMPLETE

**Implementation Details:**
- [x] Set up liboqs-python dependency and native backend loading
- [x] Implement ML-DSA (Dilithium) signer wrapper with multi-level support
- [x] Implement ML-KEM (Kyber) wrapper with multi-level support
- [x] Create version-compatible wrapper classes (ML-DSA vs Dilithium)
- [x] Write unit tests for backend availability, validation, and round trips
- [x] Support both legacy (Dilithium/Kyber) and standardized (ML-DSA/ML-KEM) names

**Key Features:**
- Explicit error handling: `PQCBackendUnavailable` if liboqs not available
- No cryptographic fallbacks - fails fast and clearly
- Supports all NIST security levels (2, 3, 5 for signatures; 512, 768, 1024 for KEM)
- Deterministic key size validation
- Version-aware algorithm selection

**File:** `src/pqc/core.py`

### 3.2 Hybrid Cryptography Module - ✅ COMPLETE

**Implementation Details:**
- [x] Implement HybridWallet class coordinating ECC and PQC
- [x] Create versioned signature combination logic (TLV format)
- [x] Implement strict dual-signature verification (both must be valid)
- [x] Add public/private key serialization methods (hex encoding)
- [x] Write comprehensive hybrid wallet tests
- [x] Support key rotation via key_id tracking

**Key Features:**
- Deterministic signature encoding: `[version:1][ecc_len:2][ecc_sig][pqc_len:2][pqc_sig]`
- Backward compatibility via ECC signature (legacy systems can verify)
- Future-proofing via PQC signature (quantum-resistant)
- Immutable key dataclasses with validation
- Complete serialization/deserialization support

**Files:** `src/hybrid/hybrid_wallet.py`, `src/hybrid/__init__.py`

### 3.3 ECDSA Implementation - ✅ COMPLETE

**Implementation Details:**
- [x] Implement ECDSAModule with secp256k1 support
- [x] Create deterministic keypair generation
- [x] Implement RFC 6979 deterministic signing
- [x] Support compressed public key format (33 bytes)
- [x] Implement signature verification with tampering detection
- [x] Handle public key decompression for validation

**Key Features:**
- Deterministic ECDSA signing (RFC 6979)
- Compressed public keys (33 bytes) for efficiency
- SHA256 message hashing
- Compatible with Bitcoin transaction signing
- Error handling for malformed keys

**File:** `src/crypto/ecdsa_module.py`

### 3.4 Bitcoin Integration - ✅ COMPLETE

**Implementation Details:**
- [x] Implement deterministic transaction builder
- [x] Add consensus-compatible transaction serialization (legacy, SegWit, Taproot)
- [x] Create Bitcoin script helpers (P2PKH, P2WPKH, P2TR)
- [x] Add CompactSize encoding for variable-length fields
- [x] Implement transaction digest calculation (double SHA256)
- [x] Add transaction fee estimation
- [x] Write transaction serialization tests
- [x] Implement hybrid-signing tests

**Key Features:**
- Deterministic transaction encoding per Bitcoin spec
- Support for legacy, SegWit, and Taproot formats
- Bitcoin script construction (P2PKH, P2WPKH, P2TR)
- Transaction ID generation and verification
- Fee calculation utilities
- Explicit broadcasting boundary (raises NotImplementedError)

**Files:** `src/bitcoin/integration.py`, `src/bitcoin/__init__.py`

### 3.5 Key Management & Storage - ✅ COMPLETE

**Implementation Details:**
- [x] Implement SecureKeyStore class with encrypted storage
- [x] Add PBKDF2 key derivation (100k iterations)
- [x] Implement Fernet encryption for at-rest keys
- [x] Create key listing and deletion functionality
- [x] Add JSON serialization for encrypted storage
- [x] Write key storage tests

**Key Features:**
- Master password protected encryption
- PBKDF2 key derivation with 100,000 iterations
- Fernet symmetric encryption (AES-128)
- Multiple key storage in single file
- Secure key deletion support
- Complete error handling

**File:** `src/key_management/key_store.py`

### 3.6 Testing Suite - ✅ COMPLETE

**Unit Tests:**
- [x] PQC core tests (`tests/test_pqc_core.py`)
  - Security level validation
  - Backend availability checks
  - Dilithium round-trip signing/verification
  - Kyber encapsulation/decapsulation
  - Malformed key rejection

- [x] Hybrid wallet tests (`tests/test_hybrid_wallet.py`)
  - ECDSA keypair generation and signing
  - Hybrid keypair generation
  - Signature encoding/decoding
  - Signature verification with tampering detection
  - Malformed signature rejection
  - Key serialization/deserialization

- [x] Bitcoin integration tests (`tests/test_bitcoin_integration.py`)
  - CompactSize encoding
  - Legacy transaction serialization
  - SegWit serialization with witness
  - Taproot transaction format
  - Script helpers (P2PKH, P2WPKH, P2TR)
  - Transaction signing and verification
  - Broadcasting disabled checks

**Test Coverage:** 30+ test cases across all modules

### 3.7 API Documentation - ✅ COMPLETE

**Documentation Files:**
- [x] `docs/api/pqc_module.md` - PQC algorithms and usage
- [x] `docs/api/hybrid_wallet.md` - Hybrid wallet API
- [x] `docs/api/bitcoin_integration.md` - Transaction building and signing
- [x] `docs/api/key_management.md` - Secure key storage

**Content Includes:**
- Complete API reference with examples
- Error handling guidance
- Security considerations
- Performance characteristics
- Usage workflows
- Integration patterns

### 3.8 Developer Resources - ✅ COMPLETE

**Documentation Files:**
- [x] `CONTRIBUTING.md` - Contributing guidelines and code standards
- [x] `docs/INSTALLATION.md` - Setup and troubleshooting guide

**Content Includes:**
- Development environment setup
- Code style and testing requirements
- Git workflow and commit message standards
- PQC and ECDSA specific guidelines
- Troubleshooting common issues
- Security vulnerability reporting

---

## Phase 4: Testing & Validation (Q4 2026) - ⏳ IN PROGRESS

### 4.1 Unit Tests - ✅ COMPLETE

**Implementation Code:** See tests/ directory

**Tasks:**
- [x] Write unit tests for PQC core
- [x] Write tests for hybrid wallet
- [x] Write tests for Bitcoin integration
- [x] Write tests for key management
- [x] Achieve 80%+ code coverage

**Test Results:**
- 30+ test cases passing
- All critical paths covered
- Edge cases validated
- Error handling tested

**File:** `tests/`

### 4.2 Integration Tests - ⏳ UPCOMING

**Tasks:**
- [ ] Test end-to-end wallet creation
- [ ] Test transaction signing and verification
- [ ] Test key storage and retrieval
- [ ] Test Bitcoin network integration
- [ ] Performance benchmarking

**File:** `tests/test_integration.py`

### 4.3 Security Audit - ⏳ UPCOMING

**Tasks:**
- [ ] Code security review
- [ ] Cryptographic review
- [ ] Key storage vulnerability assessment
- [ ] Side-channel attack analysis
- [ ] Document audit findings

**File:** `docs/security/audit_report.md`

---

## Phase 5: Documentation (Ongoing) - 🔄 IN PROGRESS

### 5.1 API Documentation - ✅ COMPLETE

**Files Created:**
- [x] `docs/api/pqc_module.md` - PQC algorithms
- [x] `docs/api/hybrid_wallet.md` - Hybrid wallet
- [x] `docs/api/bitcoin_integration.md` - Bitcoin integration
- [x] `docs/api/key_management.md` - Key management

### 5.2 User Guide - ⏳ UPCOMING

**Files to Create:**
- [ ] `docs/user_guide/getting_started.md` - Quick start guide
- [ ] `docs/user_guide/creating_wallet.md` - Wallet creation guide
- [ ] `docs/user_guide/key_management.md` - Key management guide
- [ ] `docs/user_guide/transaction_signing.md` - Transaction signing guide

### 5.3 Developer Guide - ⏳ UPCOMING

**Files to Create:**
- [ ] `docs/developer_guide/setup.md` - Development setup
- [ ] `docs/developer_guide/architecture.md` - Architecture overview
- [ ] `docs/developer_guide/contributing.md` - Contributing guidelines
- [ ] `docs/developer_guide/testing.md` - Testing guide

---

## Phase 6: Deployment & Maintenance (Q1 2027) - ⏳ PLANNED

### 6.1 Beta Release

**Tasks:**
- [ ] Create beta release package
- [ ] Deploy to test network
- [ ] Gather user feedback
- [ ] Fix critical issues
- [ ] Release v1.0-beta

### 6.2 Production Release

**Tasks:**
- [ ] Final security review
- [ ] Production deployment
- [ ] Setup monitoring and logging
- [ ] Create incident response plan
- [ ] Release v1.0-stable

### 6.3 Ongoing Maintenance

**Tasks:**
- [ ] Monitor PQC algorithm standardization
- [ ] Update to latest NIST standards
- [ ] Security patches
- [ ] Performance optimization
- [ ] Community support

---

## Directory Structure

```
bitcoin-wallet-post-quantum-migration/
├── src/
│   ├── pqc/
│   │   ├── __init__.py
│   │   └── core.py              # ✅ ML-DSA & ML-KEM adapters
│   ├── hybrid/
│   │   ├── __init__.py
│   │   └── hybrid_wallet.py     # ✅ Hybrid ECC+PQC wallet
│   ├── crypto/
│   │   ├── __init__.py
│   │   └── ecdsa_module.py      # ✅ secp256k1 ECDSA implementation
│   ├── bitcoin/
│   │   ├── __init__.py
│   │   └── integration.py       # ✅ Bitcoin transaction builder
│   └── key_management/
│       ├── __init__.py
│       └── key_store.py         # ✅ Encrypted key storage
├── tests/
│   ├── __init__.py
│   ├── test_pqc_core.py         # ✅ PQC tests
│   ├── test_hybrid_wallet.py    # ✅ Hybrid wallet tests
│   ├── test_bitcoin_integration.py  # ✅ Bitcoin integration tests
│   └── test_integration.py      # ⏳ End-to-end tests
├── docs/
│   ├── api/
│   │   ├── pqc_module.md        # ✅ PQC API docs
│   │   ├── hybrid_wallet.md     # ✅ Hybrid wallet API
│   │   ├── bitcoin_integration.md # ✅ Bitcoin integration API
│   │   └── key_management.md    # ✅ Key management API
│   ├── design/
│   │   ├── architecture.md      # ✅ Architecture overview
│   │   └── implementation_plan.md # ✅ Implementation details
│   ├── research/
│   │   ├── pqc_analysis.md
│   │   ├── bitcoin_cryptography.md
│   │   └── migration_strategy.md
│   ├── user_guide/              # ⏳ User documentation
│   ├── developer_guide/         # ⏳ Developer guides
│   ├── security/                # ⏳ Security audit report
│   └── INSTALLATION.md          # ✅ Setup guide
├── poc/
│   ├── dilithium_demo.py
│   ├── kyber_demo.py
│   ├── hybrid_key_demo.py
│   ├── test_poc.py
│   └── README.md
├── requirements.txt             # ✅ Dependencies
├── CONTRIBUTING.md              # ✅ Contribution guidelines
├── README.md
└── ROADMAP.md (this file)
```

---

## Key Milestones

| Milestone | Date | Status |
|-----------|------|--------|
| Research Phase Complete | Q1 2026 | ✅ Complete |
| Design & Planning Complete | Q2 2026 | ✅ Complete |
| Proof of Concept Complete | Q2 2026 | ✅ Complete |
| Core Implementation Complete | Q4 2026 | ✅ Complete |
| Unit Tests Complete | Q4 2026 | ✅ Complete |
| API Documentation Complete | Q4 2026 | ✅ Complete |
| Integration Tests Complete | Q4 2026 | ⏳ In Progress |
| Security Audit Complete | Q4 2026 | ⏳ Upcoming |
| Beta Release | Q4 2026 | ⏳ Planned |
| v1.0 Production Release | Q1 2027 | ⏳ Planned |

---

## Technologies & Dependencies

### Cryptography
- **liboqs-python** (>=0.16.0) - Post-quantum cryptography backend
- **ecdsa** (>=0.18.0) - ECDSA implementation for secp256k1
- **cryptography** (>=41.0.0) - Key encryption and hashing

### Bitcoin
- **python-bitcoinlib** (>=0.12.0) - Bitcoin protocol utilities
- **pybitcoinlib** (>=0.6.0) - Bitcoin operations

### Testing
- **pytest** (>=7.4.0) - Test framework
- **pytest-cov** (>=4.1.0) - Code coverage

### Development
- **black** (>=23.0.0) - Code formatting
- **flake8** (>=6.0.0) - Linting
- **mypy** (>=1.5.0) - Type checking
- **isort** (>=5.12.0) - Import sorting

### Documentation
- **Sphinx** (>=7.0.0) - Documentation generator
- **sphinx-rtd-theme** (>=1.3.0) - ReadTheDocs theme

---

## Contributing

To contribute to this project:

1. Review the relevant phase documentation
2. Check existing issues and PRs
3. Follow the code style guidelines (see CONTRIBUTING.md)
4. Write tests for new code
5. Submit a PR with detailed description

See `CONTRIBUTING.md` for detailed guidelines.

---

## License

This project is licensed under the Apache License 2.0. See LICENSE file for details.

---

## References

- NIST PQC Standardization: https://csrc.nist.gov/projects/post-quantum-cryptography/
- ML-DSA (FIPS 204): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
- ML-KEM (FIPS 203): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
- Bitcoin BIPs: https://github.com/bitcoin/bips
- liboqs Documentation: https://liboqs.org/
- PQC Security Considerations: https://pqcrypto.org/

---

**Last Updated:** September 2, 2026  
**Maintained By:** Balancebreaker-13  
**Current Phase:** Phase 3 - Core Implementation (COMPLETE)  
**Next Phase:** Phase 4 - Testing & Validation  
**Status:** ✅ Phase 3 Complete | 🔄 Phase 4 In Progress
