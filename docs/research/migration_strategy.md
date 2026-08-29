# Bitcoin Wallet Post-Quantum Cryptography Migration Strategy

## Executive Summary

This document outlines the comprehensive strategy for migrating existing Bitcoin wallets from ECDSA to post-quantum cryptography (PQC) while maintaining backward compatibility, security, and user experience.

**Key Principles:**
1. **Non-disruptive:** Gradual migration, not forced
2. **Backward compatible:** Old wallets continue to function
3. **Hybrid approach:** ECC + PQC coexistence
4. **User-centric:** Easy opt-in for migration
5. **Security-first:** No compromise on cryptography

## 1. Hybrid Cryptography Approaches

### Approach 1: Dual Signing (Recommended)

**Concept:** Every transaction signed with both ECDSA and Dilithium

**Signature Structure:**
```
[ECDSA Sig (71-72 bytes)] + [Dilithium Sig (2,420-4,595 bytes)]
Total: ~2,500-4,700 bytes per input
```

**Verification Requirements:**
Both signatures must verify successfully.

**Advantages:**
✅ Quantum resistance + backward compatibility
✅ ECDSA fails → Dilithium still valid
✅ Dilithium breaks → ECDSA still valid
✅ Maximum security (defense in depth)

**Disadvantages:**
❌ Larger transaction size (~3-5KB per input)
❌ Slower verification (need to verify both)
❌ Higher network bandwidth

**Bitcoin Integration:**
```
Script Format (Tapscript):
  <sig_ecdsa> <sig_dilithium> OP_2CHECK_HYBRID_SIG

Where OP_2CHECK_HYBRID_SIG verifies both signatures
```

### Approach 2: Key Encapsulation with Hybrid Key Derivation

**Concept:** Use Kyber KEM to derive shared secrets for transaction keys

**Key Derivation:**
```
1. Generate Kyber keypair (public, private)
2. ECDSA creates ephemeral key
3. Kyber encapsulates to create shared secret
4. Shared secret used to derive transaction key
5. Transaction key signs with Schnorr
```

**Advantages:**
✅ Smaller signature overhead
✅ Leverages existing Schnorr infrastructure
✅ PQC-hardened key derivation

**Disadvantages:**
❌ More complex key management
❌ Requires Kyber setup per transaction
❌ Less backward compatible

### Approach 3: Progressive Migration (Recommended Path)

**Phase Timeline:**

**Phase A (2026-2027): Adoption Phase**
- Enable hybrid wallets with dual signing
- Opt-in for new users
- Maintain full ECDSA compatibility
- Goal: 5-10% adoption

**Phase B (2027-2030): Growth Phase**
- Hybrid becomes standard
- Legacy ECDSA wallets encouraged to upgrade
- Network supports both
- Goal: 50%+ adoption

**Phase C (2030-2035): Transition Phase**
- PQC becomes primary
- ECDSA maintained for interoperability
- Migration tools widely available
- Goal: 80%+ adoption

**Phase D (2035+): Post-Quantum Era**
- ECDSA deprecated in new wallets
- Legacy support maintained
- Full PQC network

## 2. Key Agility Mechanisms

### Key Rotation Strategy

**For HD Wallets (BIP32/44):**

```python
# Original BIP44 path:
m/44'/0'/0'/0/0  # Bitcoin, account 0, receiving, index 0

# Extended for PQC (new BIP):
m/44'/0'/0'/pqc/0  # PQC variant
m/44'/0'/0'/hybrid/0  # Hybrid variant
```

**Key Derivation for Hybrid Keys:**
```
1. Derive ECDSA key from path: m/44'/0'/0'/0/0
   ecdsa_privkey = derive_bip44(seed, path)

2. Derive PQC seed from same BIP39 seed
   pqc_seed = HMAC-SHA512("PQC", bip39_seed)
   pqc_privkey = derive_dilithium_key(pqc_seed, path)

3. Create Hybrid Key
   hybrid_key = (ecdsa_privkey, pqc_privkey)
   hybrid_pubkey = (ecdsa_pubkey, pqc_pubkey)
```

### Algorithm Rotation

**Future-proofing Against PQC Compromise:**

If Dilithium becomes vulnerable:

```
Key Versioning:
  Version 1: ECDSA + Dilithium
  Version 2: ECDSA + FALCON (alternative PQC)
  Version 3: Schnorr + SPHINCS+
```

**Migration Path:**
```
1. User wallet contains Version 1 hybrid keys
2. If Dilithium compromised:
   - Generate new Version 2 keys
   - Transfer UTXO to new Version 2 addresses
   - Maintain old keys for backward compatibility
```

## 3. Wallet Backward Compatibility Strategies

### Strategy 1: Parallel Address Derivation

**All wallets support both:**

```python
class HybridHDWallet:
    def __init__(self, seed):
        self.bip44_path = "m/44'/0'/0'/0/{i}"
        self.hybrid_path = "m/44'/0'/0'/hybrid/{i}"
        
    def get_receiving_addresses(self, index):
        # Legacy ECDSA only (P2PKH, P2WPKH)
        ecdsa_addr = self.derive_ecdsa_address(
            self.bip44_path.format(i=index)
        )
        
        # Hybrid PQC (Taproot-compatible)
        hybrid_addr = self.derive_hybrid_address(
            self.hybrid_path.format(i=index)
        )
        
        return {
            'ecdsa': ecdsa_addr,      # bc1q... (ECDSA only)
            'hybrid': hybrid_addr      # bc1p... (ECDSA + Dilithium)
        }
```

**User Experience:**
- Existing wallets continue to work
- Users can opt-in to hybrid addresses
- Both can be used simultaneously
- Gradual migration path

### Strategy 2: Version Negotiation

**Wallet Software Support Matrix:**

```
Version 1.0 (2026):  ECDSA only
Version 2.0 (2027):  ECDSA + Hybrid support (opt-in)
Version 3.0 (2028):  ECDSA + Hybrid (default) + PQC-only (option)
Version 4.0 (2030):  Hybrid (default) + PQC-only + Legacy support
Version 5.0 (2035):  PQC-only + Legacy interop
```

**Network Message Format:**
```protobuf
message Transaction {
    required int32 version = 1;  // 1 = legacy, 2 = segwit, 3 = hybrid
    repeated Input inputs = 2;
    repeated Output outputs = 3;
    required uint32 locktime = 4;
}

message Input {
    required bytes previous_hash = 1;
    required uint32 previous_index = 2;
    required bytes script_sig = 3;
    required uint32 sequence = 4;
    optional bytes hybrid_sig_extension = 5;  // Version 3+
}
```

### Strategy 3: Scriptless Scripts (Future)

**Concept:** Use adaptor signatures to hide script complexity

```
Adaptor Signature allows:
- Threshold cryptography (multisig)
- Atomic swaps
- Payment channels

For PQC:
- Adaptor-friendly: Dilithium supports
- Taproot compatible
- Privacy-preserving
```

## 4. Performance & Size Trade-offs

### Transaction Size Comparison

**Legacy P2PKH:**
```
Input size: ~148 bytes (scriptSig + input overhead)
Signature: 71-72 bytes (ECDSA DER)
Total input: ~220 bytes
```

**Hybrid (Dual Signature):**
```
Input size: ~200 bytes (base)
ECDSA signature: 71-72 bytes
Dilithium signature: 2,420 bytes (Level 3)
Total input: ~2,700 bytes

Increase: ~12x (220 → 2,700 bytes)
```

**Impact Analysis:**

```
Current Bitcoin Block Size: 4 MB (SegWit limit)
Average Transaction: 250 bytes
Current TPS: ~7

With Hybrid Signatures:
Average Transaction: ~3,000 bytes
Estimated TPS: ~0.6 (significant reduction)

Mitigation Strategies:
1. Increase block size (soft fork)
2. Layer 2 solutions (Lightning Network)
3. Signature compression techniques
4. Gradual adoption (not all tx are hybrid)
```

### Verification Performance

**Benchmarks (per signature):**

| Operation | Time | Notes |
|-----------|------|-------|
| ECDSA Sign | ~100 μs | Deterministic |
| ECDSA Verify | ~150 μs | Fast |
| Dilithium Sign | ~200 μs | Slightly slower |
| Dilithium Verify | ~300 μs | Acceptable |
| Hybrid Verify | ~450 μs | Sum of both |

**For 3,000 input transaction:**
- ECDSA only: 450 ms
- Hybrid: 1,350 ms (~3x slower)
- Still acceptable for network consensus

## 5. Implementation Timeline

### Q1 2026 (Current): Research Phase
- ✅ Analyze PQC algorithms
- ✅ Study Bitcoin cryptography
- ⏳ Complete migration strategy
- **Deliverables:** Research docs, feasibility report

### Q2 2026: Design & Planning
- Design hybrid wallet architecture
- Create detailed implementation plan
- Define API specifications
- Start proof-of-concept

### Q3-Q4 2026: Core Implementation
- Implement PQC core (Dilithium, Kyber)
- Build hybrid wallet module
- Bitcoin transaction integration
- Key management system
- Alpha testing

### Q1 2027: Testing & Validation
- Comprehensive test suite
- Security audit
- Mainnet compatibility testing
- Beta release

### Q2-Q3 2027: Production Release
- v1.0 stable release
- Mainnet deployment
- Gradual adoption
- Community engagement

## 6. Risk Mitigation

### Risk 1: PQC Algorithm Compromise
**Mitigation:**
- Dual algorithms (ECDSA + PQC)
- Monitor algorithm research
- Key rotation capability
- Quarterly security reviews

### Risk 2: Network Congestion
**Mitigation:**
- Layer 2 integration (Lightning)
- Signature compression
- Gradual adoption timeline
- Parallel mainnet-sidechain approach

### Risk 3: Wallet Fragmentation
**Mitigation:**
- Standardized BIP for PQC migration
- Reference implementation provided
- Backward compatibility guaranteed
- Cross-wallet testing

### Risk 4: User Adoption
**Mitigation:**
- Education campaign
- Simple UI for hybrid wallets
- Incentivize early migration
- Integration with major exchanges

## 7. Recommended Approach Summary

**Best Strategy: Progressive Hybrid Migration**

1. **Immediate (2026-2027):**
   - Deploy hybrid wallet infrastructure
   - Opt-in for new wallets
   - Maintain ECDSA compatibility
   - Target: 5-10% adoption

2. **Short-term (2027-2030):**
   - Hybrid becomes standard
   - Tools for legacy migration
   - Full network support
   - Target: 50%+ adoption

3. **Medium-term (2030-2035):**
   - PQC primary, ECDSA secondary
   - Algorithm rotation capability
   - Target: 80%+ adoption

4. **Long-term (2035+):**
   - Post-quantum world
   - Legacy interoperability
   - New threats addressed

## 8. References

- NIST PQC Status: https://csrc.nist.gov/projects/post-quantum-cryptography/
- Bitcoin Core Development: https://github.com/bitcoin/bitcoin
- BIP Development Process: https://github.com/bitcoin/bips
- Threshold Cryptography: https://en.wikipedia.org/wiki/Threshold_cryptography

---
**Status:** ✅ Phase 1 Research Complete  
**Last Updated:** 2026-08-29  
**Next Phase:** Phase 2 - Design & Planning  
**Recommended Action:** Proceed with Phase 2 implementation
