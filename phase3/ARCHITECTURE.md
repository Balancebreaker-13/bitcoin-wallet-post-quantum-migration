# Phase 3: Blockchain Integration - Architecture & Design

## Overview

Phase 3 focuses on integrating post-quantum cryptography into Bitcoin Core, enabling quantum-resistant transactions while maintaining backward compatibility. This document outlines the technical architecture and integration strategy.

## Objectives

1. **Core Integration**: Modify Bitcoin Core to support hybrid PQC signatures
2. **Transaction Format**: Define new transaction types supporting PQC
3. **Validation Rules**: Implement quantum-resistant signature verification
4. **Backward Compatibility**: Ensure seamless coexistence with legacy transactions
5. **Network Upgrade**: Coordinated soft-fork deployment strategy
6. **Performance Optimization**: Minimize blockchain size impact

## Architecture Overview

### Layer Structure

```
┌─────────────────────────────────────────────────┐
│         Application Layer                       │
│    (Wallet, RPC, User Interface)               │
└────────────────┬────────────────────────────────┘
                 │
┌─────────────────────────────────────────────────┐
│      Transaction Processing Layer               │
│  (PQC Signature Validation, Serialization)     │
└────────────────┬────────────────────────────────┘
                 │
┌─────────────────────────────────────────────────┐
│       Cryptographic Operations Layer            │
│  (Dilithium, Kyber, ECDSA, Hybrid Signing)    │
└────────────────┬────────────────────────────────┘
                 │
┌─────────────────────────────────────────────────┐
│      liboqs Binding Layer                       │
│  (C bindings to PQC libraries)                 │
└─────────────────────────────────────────────────┘
```

## Transaction Format Modifications

### Legacy Transaction (Current)

```
Version (4 bytes)
Input Count (varint)
Inputs
  ├─ Previous Output (32 + 4 bytes)
  ├─ Script Length (varint)
  ├─ Signature Script
  └─ Sequence (4 bytes)
Output Count (varint)
Outputs
  ├─ Value (8 bytes)
  ├─ Script Length (varint)
  └─ PubKey Script
Locktime (4 bytes)
```

### Hybrid PQC Transaction Format

```
Version (4 bytes) [enhanced]
├─ Legacy bit: 0
├─ Hybrid bit: 1
├─ PQC Algorithm: 2 bits
└─ Reserved: 13 bits

Input Count (varint)
Inputs
  ├─ Previous Output (32 + 4 bytes)
  ├─ Signature Type (1 byte)
  │   ├─ 0x00: Legacy ECDSA
  │   ├─ 0x01: Hybrid (ECC + Dilithium)
  │   ├─ 0x02: Pure PQC (Dilithium)
  │   └─ 0x03: Reserved
  ├─ Script Length (varint)
  ├─ ECC Signature (71 bytes or 0 if PQC-only)
  ├─ PQC Signature Length (varint)
  ├─ PQC Signature (2420 bytes for Dilithium3)
  └─ Sequence (4 bytes)

Output Count (varint)
Outputs [unchanged]

Witness Data [optional, for Segwit compatibility]

Locktime (4 bytes)
```

### Key Structure Modifications

**Legacy Address (P2PKH)**
```
Version + Hash160(PublicKey) → Base58Check
```

**Hybrid Address (P2PQH - Pay to PQC Hash)**
```
Version + Hash256(ECC_PubKey || PQC_PubKey) → Base58Check Extended
```

**New Address Format Examples**
```
Legacy:   1A1z7agoat7PNW33YW3c2iNYjiHaap4qda
Hybrid:   hq1x8z9k2m5n7vp3q1r9w2e4t6y8u0i2j4k
PQC-only: pq2d4f6h8j0l2n4p6r8t0v2x4z6a8c0e
```

## Implementation Components

### 1. Cryptographic Backend (`crypto/pqc/`)

```
crypto/pqc/
├── pqc.h              # PQC interface definitions
├── pqc.cpp            # PQC core implementations
├── dilithium.h        # Dilithium wrapper
├── dilithium.cpp      # Dilithium implementation
├── kyber.h            # Kyber wrapper
├── kyber.cpp          # Kyber implementation
├── hybrid.h           # Hybrid ECC+PQC
├── hybrid.cpp         # Hybrid implementation
└── test/
    ├── pqc_tests.cpp
    ├── dilithium_tests.cpp
    ├── kyber_tests.cpp
    └── hybrid_tests.cpp
```

### 2. Transaction Format (`primitives/transaction.h/cpp`)

```
Modifications to CTxIn:
├── signatureType: uint8_t  // 0=Legacy, 1=Hybrid, 2=PQC
├── pqcSignature: std::vector<uint8_t>  // PQC signature data
└── eccSignature: std::vector<uint8_t>  // Traditional signature

Modifications to CTransaction:
├── nVersion (enhanced with PQC bits)
├── IsPQCTransaction(): bool
├── GetPQCAlgorithm(): int
└── EstimatePQCSize(): size_t
```

### 3. Script Validation (`script/interpreter.h/cpp`)

```
New opcodes:
├── OP_CHECKSIG_PQC      (0xAE)
├── OP_CHECKSIGVERIFY_PQC (0xAF)
├── OP_CHECKMULTISIG_PQC  (0xB0)
└── OP_CHECKHYBRID_VERIFY (0xB1)

Modified validation functions:
├── CheckPQCSignature()
├── CheckHybridSignature()
├── EvalScript() [enhanced]
└── VerifyScript() [enhanced]
```

### 4. Wallet Integration (`wallet/`)

```
wallet/
├── wallet.h/cpp
│   └─ AddPQCKey()
│   └─ GetPQCAddress()
│   └─ SignPQCTransaction()
├── keystore.h/cpp
│   └─ StorePQCKey()
│   └─ RetrievePQCKey()
└── scriptpubkeyman.h/cpp
    └─ ManagePQCKeys()
    └─ GeneratePQCAddress()
```

### 5. RPC Enhancements (`rpc/`)

```
New RPC Commands:
├─ genpqckey [label]
│  └─ Generates new PQC keypair
├─ gethybridkey [label]
│  └─ Generates hybrid ECC+PQC keypair
├─ signpqctransaction <tx> <inputs>
│  └─ Signs transaction with PQC algorithm
├─ verifypqcsignature <sig> <tx> <pubkey>
│  └─ Verifies PQC signature
└─ getpqcaddress [type]
   └─ Lists PQC addresses in wallet
```

## Integration Strategy

### Phase 3.1: Core Infrastructure (Weeks 1-4)

**Tasks:**
- [ ] Set up liboqs integration in Bitcoin Core
- [ ] Implement PQC cryptographic primitives
- [ ] Add hybrid signing support
- [ ] Create unit tests for crypto layer
- [ ] Document API interfaces

**Deliverables:**
- PQC crypto module with full test coverage
- Hybrid key generation and signing
- Performance benchmarks

### Phase 3.2: Transaction Format (Weeks 5-8)

**Tasks:**
- [ ] Define new transaction serialization format
- [ ] Implement dual-format support (legacy + PQC)
- [ ] Add transaction deserialization
- [ ] Create transaction validation rules
- [ ] Implement size estimation

**Deliverables:**
- Transaction format specification (BIP-like)
- Dual-format transaction handling
- Complete test suite

### Phase 3.3: Consensus Rules (Weeks 9-12)

**Tasks:**
- [ ] Implement script opcodes for PQC verification
- [ ] Create consensus rules engine
- [ ] Add soft-fork activation logic
- [ ] Version bit management
- [ ] Backward compatibility testing

**Deliverables:**
- Consensus rule implementation
- Soft-fork deployment mechanism
- Activation timeline

### Phase 3.4: Wallet Integration (Weeks 13-16)

**Tasks:**
- [ ] Extend wallet to support PQC keys
- [ ] Implement PQC address generation
- [ ] Add key management functions
- [ ] Create backup/recovery mechanisms
- [ ] Update wallet serialization

**Deliverables:**
- PQC-enabled wallet
- Address management tools
- Backup procedures

### Phase 3.5: Testing & Optimization (Weeks 17-20)

**Tasks:**
- [ ] Integration testing
- [ ] Performance optimization
- [ ] Security audit preparation
- [ ] Testnet deployment
- [ ] Network simulation

**Deliverables:**
- Optimized implementation
- Test results and metrics
- Deployment readiness

## Key Design Decisions

### 1. Hybrid vs. Pure PQC Approach

**Decision: Hybrid (ECC + PQC)**

**Rationale:**
- Maintains backward compatibility
- Reduces risk during transition
- Allows gradual adoption
- Proven security model

### 2. Signature Algorithm Selection

**Decision: Dilithium3 for signatures**

**Rationale:**
- NIST standardized
- Smaller signatures than alternatives
- Proven security
- Efficient verification

### 3. Key Encapsulation

**Decision: Kyber768 for key exchange**

**Rationale:**
- NIST standardized
- Good performance/security balance
- Efficient encapsulation/decapsulation
- Suitable for blockchain use

### 4. Address Format Extension

**Decision: New address type with version byte**

**Rationale:**
- User can distinguish PQC addresses
- Compatible with existing Base58Check
- Extensible for future algorithms
- Prevents accidental misuse

### 5. Deployment Strategy

**Decision: Soft-fork with version bits**

**Rationale:**
- No consensus rule break
- Miners don't need immediate upgrade
- Gradual activation
- Fallback mechanisms

## Backward Compatibility

### Transaction Processing

```
if (tx.nVersion & PQC_FLAG) {
    // New PQC transaction format
    validate_pqc_signatures();
    validate_hybrid_scripts();
} else {
    // Legacy transaction format
    validate_legacy_signatures();
    // Existing validation logic
}
```

### Address Compatibility

```
switch (address.version) {
    case LEGACY_VERSION:        // 0x00
        return ParseLegacyAddress(address);
    case HYBRID_VERSION:        // 0x20
        return ParseHybridAddress(address);
    case PQC_VERSION:          // 0x40
        return ParsePQCAddress(address);
    default:
        return InvalidAddress();
}
```

### Script Compatibility

```
Existing scripts continue to validate normally
New OP_CHECKSIG_PQC for PQC-only validation
New OP_CHECKHYBRID_VERIFY for hybrid validation
Version bits control activation
```

## Performance Targets

### Block Processing

- **Legacy transactions**: No impact (< 1% overhead)
- **Hybrid transactions**: 5-10ms overhead per transaction
- **PQC transactions**: 10-15ms overhead per transaction
- **Block validation**: < 5% increase for mixed blocks

### Network Impact

- **Transaction size increase**: 2-3x (manageable with Segwit)
- **Bandwidth**: 10-20% increase (acceptable for long-term migration)
- **Storage**: +30% for PQC-heavy blocks (within historical growth)

### Memory Usage

- **Signature cache**: Additional 2-5MB per 10M transactions
- **Key storage**: +500MB per 10M PQC keys (manageable)
- **Runtime memory**: < 50MB increase for validation

## Security Considerations

### Attack Vectors

1. **Signature Forgery**
   - Mitigation: Use NIST-standardized algorithms
   - Validation: Comprehensive testing
   - Monitoring: Network-wide signature validation

2. **Private Key Theft**
   - Mitigation: Secure key storage
   - Monitoring: Key backup procedures
   - Recovery: Multi-sig recovery options

3. **Replay Attacks**
   - Mitigation: Transaction ID includes signature type
   - Validation: Different validation for each type
   - Testing: Replay attack test cases

4. **Downgrade Attacks**
   - Mitigation: Version bits enforce algorithm choice
   - Validation: No mixing of types within transaction
   - Rules: Consensus rules prevent downgrades

### Cryptographic Assumptions

- Dilithium remains secure for 20+ years
- Kyber remains secure for 20+ years
- No efficient quantum computer in next decade
- Hash functions (SHA-256) remain secure

## Deployment Roadmap

### Mainnet Deployment Timeline

**Q4 2026:**
- Code review and security audit
- Testnet integration
- Performance testing
- Community feedback period

**Q1 2027:**
- Soft-fork activation vote
- Miner signaling
- Network activation

**Q2-Q4 2027:**
- Gradual wallet upgrades
- PQC transaction adoption
- Monitoring and optimization

**2028+:**
- Legacy support continues (5+ years)
- Pure PQC adoption increases
- Protocol optimization based on data

## Next Steps

1. **Implementation**: Begin core crypto module development
2. **Testing**: Create comprehensive test framework
3. **Review**: Code review and security analysis
4. **Documentation**: Finalize BIP and technical specs
5. **Community**: Engage Bitcoin community and miners

---

**Phase**: 3 - Blockchain Integration
**Status**: Architecture & Design Complete
**Next**: Core Implementation Begins
