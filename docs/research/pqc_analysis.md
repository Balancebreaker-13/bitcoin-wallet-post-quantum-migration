# Post-Quantum Cryptography Analysis

## Overview
This document provides a comprehensive analysis of post-quantum cryptographic algorithms and their suitability for Bitcoin wallet migration.

## 1. NIST PQC Standardization Process

### Background
- NIST initiated the PQC standardization project in 2016 in response to the threat of quantum computers
- The project aims to develop cryptographic standards resistant to both classical and quantum attacks
- Final standards were announced in August 2022

### NIST-Standardized Algorithms (FIPS 203, 204, 205)

#### Finalists Selected:
1. **Digital Signatures:**
   - ML-DSA (Dilithium)
   - SLH-DSA (SPHINCS+)

2. **Key Encapsulation Mechanism (KEM):**
   - ML-KEM (Kyber)

3. **Public-Key Encryption:**
   - ML-KEM (also used for encryption)

## 2. Lattice-Based Cryptography (Kyber, Dilithium)

### Dilithium (ML-DSA)

**What it is:**
Dilithium is a post-quantum digital signature algorithm based on the hardness of the Module Learning With Errors (MLWE) problem.

**Key Characteristics:**
- **Security Levels:** 2, 3, 5 (corresponding to NIST Security Levels 2, 3, 5)
- **Public Key Size:** ~1,312 bytes (Level 2) to 2,544 bytes (Level 5)
- **Signature Size:** ~2,420 bytes (Level 2) to 4,595 bytes (Level 5)
- **Performance:** Microseconds for signing/verification
- **Quantum Security:** Resistant to Shor's algorithm and other quantum attacks

**Advantages for Bitcoin:**
- Deterministic signatures (no randomness needed)
- Fast verification compared to other PQC schemes
- Moderate signature sizes
- Well-studied security foundation (MLWE)

**Implementation:**
```python
from liboqs.oqs import Signature

# Initialize Dilithium Level 3
sig = Signature("ML-DSA-65")  # ML-DSA-44, ML-DSA-65, ML-DSA-87

# Generate keypair
public_key, secret_key = sig.generate_keypair()

# Sign message
message = b"Bitcoin transaction data"
signature = sig.sign(message, secret_key)

# Verify signature
is_valid = sig.verify(message, signature, public_key)
```

### Kyber (ML-KEM)

**What it is:**
Kyber is a post-quantum key encapsulation mechanism (KEM) based on the Module Learning With Errors (MLWE) problem.

**Key Characteristics:**
- **Security Levels:** 512, 768, 1024 (corresponding to NIST Security Levels 1, 3, 5)
- **Public Key Size:** 800 bytes to 1,568 bytes
- **Ciphertext Size:** 768 bytes to 1,568 bytes
- **Shared Secret Size:** 32 bytes (constant)
- **Performance:** Microseconds for encapsulation/decapsulation

**Advantages for Bitcoin:**
- Efficient key agreement protocol
- Constant shared secret size (ideal for key derivation)
- Resistance to quantum attacks
- Suitable for hybrid key exchange

**Implementation:**
```python
from liboqs.oqs import KeyEncapsulation

# Initialize Kyber Level 3
kem = KeyEncapsulation("ML-KEM-768")  # ML-KEM-512, ML-KEM-768, ML-KEM-1024

# Generate keypair
public_key, secret_key = kem.generate_keypair()

# Encapsulate (sender side)
ciphertext, shared_secret = kem.encaps(public_key)

# Decapsulate (receiver side)
shared_secret_recovered = kem.decaps(ciphertext, secret_key)
```

## 3. Hash-Based Signatures (XMSS, LMS)

### XMSS (eXtended Merkle Signature Scheme)

**What it is:**
XMSS is a stateful hash-based digital signature algorithm with strong quantum-resistant security.

**Characteristics:**
- **Security:** Proven secure under any secure hash function (SHA-256, SHA-3)
- **Signature Size:** Small (~2,500 bytes)
- **Public Key Size:** Very small (~32 bytes)
- **Performance:** Fast verification
- **Drawback:** Stateful (must track signed messages)

**Comparison to Dilithium:**
| Property | XMSS | Dilithium |
|----------|------|----------|
| Signature Size | Small | Larger |
| Security Proof | Proven | Conjectured (MLWE) |
| Stateful | Yes | No |
| Verification Speed | Fast | Faster |
| Key Size | Small | Moderate |

### LMS (Leighton-Micali Signature)

**Similar to XMSS but:**
- NIST-approved (RFC 8554)
- Less efficient than XMSS
- Also stateful

**Recommendation:** For Bitcoin wallets, stateless schemes like Dilithium are preferred.

## 4. Code-Based Cryptography (Classic McEliece)

### Classic McEliece

**What it is:**
A public-key encryption algorithm based on the hardness of decoding random linear codes.

**Characteristics:**
- **Security:** Very well-studied (30+ years)
- **Public Key Size:** 261,120 bytes (very large)
- **Ciphertext Size:** 32 bytes
- **Performance:** Very fast decryption
- **Drawback:** Extremely large public keys unsuitable for blockchain

**Why not for Bitcoin:**
- Public key sizes are prohibitively large
- Would bloat the Bitcoin blockchain significantly
- Not practical for widespread wallet deployment

**Use Case:** Suitable for one-time encryption scenarios where storage size is not critical.

## 5. Quantum Threat Timeline for Bitcoin

### Current Threat Assessment

**Timeline Estimates:**

| Year Range | Quantum Computer Status | Bitcoin Threat Level |
|------------|------------------------|----------------------|
| 2026-2030 | Theoretical threat, maybe NISQ | Low |
| 2030-2035 | Early practical quantum computers | Medium |
| 2035-2045 | Advanced quantum computers capable of breaking RSA-2048 | High |
| 2045+ | Mature quantum computers (1000+ logical qubits) | Critical |

### Specific Threats to Bitcoin

#### ECDSA Vulnerability
- **Current key:** secp256k1 (256-bit elliptic curve)
- **Quantum threat:** Shor's algorithm can break ECDSA in polynomial time
- **Timeline:** When quantum computer has ~1500-2000 logical qubits
- **Current estimate:** 15-20+ years before practical threat

#### SHA-256 Vulnerability
- **Current use:** Mining (proof-of-work), hashing
- **Quantum threat:** Grover's algorithm reduces effective strength from 256 to 128 bits
- **Impact:** Less critical than ECDSA, still significant
- **Timeline:** Later than ECDSA threat (needs ~5 million qubits)

### Attack Scenarios

**Scenario 1: Harvest Now, Decrypt Later**
- Attackers record encrypted Bitcoin transactions today
- When quantum computer becomes available, decrypt old transactions
- Steal bitcoins from addresses that have exposed public keys
- **Current exposed public keys:** ~20-40% of all bitcoins (common in older wallets)

**Scenario 2: Active Attack on Network**
- Quantum-capable attacker signs invalid transactions
- Creates 51% attack on confirmation
- Doubles spends or censors transactions
- **Bitcoin protection:** Network consensus mechanism

### Bitcoin's Current Defenses

1. **Address Reuse Avoidance:** Modern wallets use HD-wallets (BIP32/44) with new addresses
2. **Compressed Public Keys:** Reduces exposure from 65 to 33 bytes
3. **P2PKH → P2SH → Taproot:** Each upgrade reduces exposed public key material
4. **Taproot (BIP340/341):** Schnorr signatures + key aggregation further reduces exposure

## 6. Threat Assessment Report

### Executive Summary

**Current Risk Level:** Medium (15-20 years before critical threat)

**Recommended Actions:**
1. **Immediate (2026-2027):** Begin hybrid migration infrastructure
2. **Short-term (2027-2030):** Integrate PQC into Bitcoin Core and wallets
3. **Medium-term (2030-2035):** Encourage wallet migration to hybrid or PQC-only
4. **Long-term (2035+):** Full PQC enforcement

### Key Findings

1. **Dilithium (ML-DSA) is the optimal choice for Bitcoin:**
   - Stateless (important for blockchain)
   - Fast verification
   - NIST-standardized
   - Moderate signature sizes
   - Well-suited for hybrid approaches

2. **Kyber (ML-KEM) is excellent for key establishment:**
   - Efficient encapsulation/decapsulation
   - Small constant shared secret size
   - Can be used for hybrid key agreement

3. **Hybrid approach is recommended:**
   - Maintain ECDSA for backward compatibility
   - Add Dilithium for quantum resistance
   - Transition over time to PQC-only
   - Reduces risk of PQC algorithm compromise

4. **"Harvest Now, Decrypt Later" is the primary concern:**
   - Even with 15-20 year timeline, sensitive data is at risk
   - Proactive migration recommended
   - Focus on wallets with exposed public keys first

### Implementation Recommendations

**For Bitcoin Wallet Developers:**

1. **Phase 1 (2026-2027):**
   - Research and development of hybrid wallets
   - Integration with liboqs library
   - Test with testnet

2. **Phase 2 (2027-2028):**
   - Beta releases with hybrid signatures
   - Community testing and feedback
   - Security audits

3. **Phase 3 (2028-2030):**
   - Production deployment
   - Gradual migration of user base
   - Monitoring and support

## 7. References

- NIST Post-Quantum Cryptography Project: https://csrc.nist.gov/projects/post-quantum-cryptography/
- NIST FIPS 203 (ML-KEM): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
- NIST FIPS 204 (ML-DSA): https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
- liboqs Documentation: https://liboqs.org/
- Grover's Algorithm: https://en.wikipedia.org/wiki/Grover%27s_algorithm
- Shor's Algorithm: https://en.wikipedia.org/wiki/Shor%27s_algorithm

---
**Status:** ✅ Research Complete  
**Last Updated:** 2026-08-29  
**Next Phase:** Phase 1.2 - Bitcoin Cryptography Deep Dive
