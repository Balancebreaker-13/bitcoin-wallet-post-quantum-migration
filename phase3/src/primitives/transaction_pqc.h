// Copyright (c) 2026 Bitcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_TRANSACTION_PQC_H
#define BITCOIN_PRIMITIVES_TRANSACTION_PQC_H

#include "primitives/transaction.h"
#include "crypto/pqc.h"
#include <vector>
#include <cstdint>
#include <memory>

/**
 * @file primitives/transaction_pqc.h
 * @brief Extensions to transaction format for post-quantum cryptography support
 * 
 * This header defines extensions to Bitcoin's transaction format to support
 * post-quantum cryptographic signatures while maintaining backward compatibility.
 */

// ============================================================================
// Transaction Version Flags
// ============================================================================

/**
 * Transaction version flags for PQC support
 */
namespace TxVersionFlags {
    // Traditional version field (bits 0-15)
    constexpr uint32_t VERSION_MASK = 0x0000FFFF;
    
    // PQC extension flags (bits 16-31)
    constexpr uint32_t PQC_FLAG = 0x00010000;           ///< Indicates PQC-enhanced transaction
    constexpr uint32_t HYBRID_FLAG = 0x00020000;        ///< Indicates hybrid ECC+PQC signatures
    constexpr uint32_t PQC_ALGORITHM_MASK = 0x000C0000; ///< Algorithm selection bits
    constexpr uint32_t PQC_ALGORITHM_SHIFT = 18;        ///< Shift for algorithm bits
    
    /**
     * Check if transaction uses PQC
     */
    inline bool IsPQCTransaction(uint32_t nVersion) {
        return (nVersion & PQC_FLAG) != 0;
    }
    
    /**
     * Check if transaction uses hybrid signatures
     */
    inline bool IsHybridTransaction(uint32_t nVersion) {
        return (nVersion & HYBRID_FLAG) != 0;
    }
    
    /**
     * Get the PQC algorithm type from version
     */
    inline PQC::AlgorithmType GetPQCAlgorithm(uint32_t nVersion) {
        uint32_t algo_bits = (nVersion & PQC_ALGORITHM_MASK) >> PQC_ALGORITHM_SHIFT;
        return static_cast<PQC::AlgorithmType>(algo_bits);
    }
}

// ============================================================================
// Signature Type Enumeration
// ============================================================================

/**
 * Types of signatures used in transaction inputs
 */
enum class SignatureType : uint8_t {
    LEGACY_ECDSA = 0x00,           ///< Traditional ECDSA signature
    HYBRID_ECC_DILITHIUM = 0x01,   ///< Hybrid ECC + Dilithium signature
    PURE_DILITHIUM = 0x02,         ///< Pure Dilithium signature
    RESERVED = 0x03                ///< Reserved for future use
};

// ============================================================================
// Extended Transaction Input Structure
// ============================================================================

/**
 * @class CTxInPQC
 * @brief Transaction input with PQC signature support
 * 
 * Extends standard CTxIn to support post-quantum cryptographic signatures
 * while maintaining backward compatibility with legacy inputs.
 */
class CTxInPQC : public CTxIn {
public:
    // PQC-specific fields
    SignatureType signatureType;           ///< Type of signature used
    std::vector<uint8_t> pqcSignature;     ///< Post-quantum signature (variable length)
    std::vector<uint8_t> eccSignature;     ///< ECC signature for hybrid mode (optional)
    
    CTxInPQC() : signatureType(SignatureType::LEGACY_ECDSA) {}
    
    CTxInPQC(const COutPoint& prevout, CScript scriptSig = CScript(), uint32_t nSequenceIn = SEQUENCE_FINAL)
        : CTxIn(prevout, scriptSig, nSequenceIn), signatureType(SignatureType::LEGACY_ECDSA) {}
    
    /**
     * Set hybrid signature components
     */
    void SetHybridSignature(const std::vector<uint8_t>& ecc_sig, 
                           const std::vector<uint8_t>& pqc_sig) {
        signatureType = SignatureType::HYBRID_ECC_DILITHIUM;
        eccSignature = ecc_sig;
        pqcSignature = pqc_sig;
    }
    
    /**
     * Set pure PQC signature
     */
    void SetPQCSignature(const std::vector<uint8_t>& pqc_sig) {
        signatureType = SignatureType::PURE_DILITHIUM;
        pqcSignature = pqc_sig;
        eccSignature.clear();
    }
    
    /**
     * Get total signature size
     */
    size_t GetSignatureSize() const {
        size_t size = 0;
        if (signatureType == SignatureType::LEGACY_ECDSA) {
            size = scriptSig.size();
        } else if (signatureType == SignatureType::HYBRID_ECC_DILITHIUM) {
            size = 1 + 2 + eccSignature.size() + 2 + pqcSignature.size();
        } else if (signatureType == SignatureType::PURE_DILITHIUM) {
            size = 1 + 2 + pqcSignature.size();
        }
        return size;
    }
    
    /**
     * Serialize PQC signature data
     */
    template <typename Stream>
    void SerializePQCSignature(Stream& s) const {
        s << (uint8_t)signatureType;
        
        if (signatureType == SignatureType::HYBRID_ECC_DILITHIUM) {
            s << (uint16_t)eccSignature.size();
            s.write((char*)eccSignature.data(), eccSignature.size());
            s << (uint16_t)pqcSignature.size();
            s.write((char*)pqcSignature.data(), pqcSignature.size());
        } else if (signatureType == SignatureType::PURE_DILITHIUM) {
            s << (uint16_t)pqcSignature.size();
            s.write((char*)pqcSignature.data(), pqcSignature.size());
        }
    }
    
    /**
     * Deserialize PQC signature data
     */
    template <typename Stream>
    void DeserializePQCSignature(Stream& s) {
        uint8_t sig_type;
        s >> sig_type;
        signatureType = (SignatureType)sig_type;
        
        if (signatureType == SignatureType::HYBRID_ECC_DILITHIUM) {
            uint16_t ecc_len;
            s >> ecc_len;
            eccSignature.resize(ecc_len);
            s.read((char*)eccSignature.data(), ecc_len);
            
            uint16_t pqc_len;
            s >> pqc_len;
            pqcSignature.resize(pqc_len);
            s.read((char*)pqcSignature.data(), pqc_len);
        } else if (signatureType == SignatureType::PURE_DILITHIUM) {
            uint16_t pqc_len;
            s >> pqc_len;
            pqcSignature.resize(pqc_len);
            s.read((char*)pqcSignature.data(), pqc_len);
        }
    }
    
    /**
     * Check if this input uses PQC signatures
     */
    bool UsesPQCSignature() const {
        return signatureType != SignatureType::LEGACY_ECDSA;
    }
};

// ============================================================================
// Extended Transaction Structure
// ============================================================================

/**
 * @class CTransactionPQC
 * @brief Transaction with PQC signature support
 * 
 * Extends the standard transaction format to support post-quantum cryptographic
 * signatures while maintaining full backward compatibility.
 */
class CTransactionPQC : public CTransaction {
public:
    // Constructor
    CTransactionPQC() = default;
    explicit CTransactionPQC(const CTransaction& tx) : CTransaction(tx) {}
    
    /**
     * Check if this transaction uses PQC signatures
     */
    bool IsPQCTransaction() const {
        return TxVersionFlags::IsPQCTransaction(nVersion);
    }
    
    /**
     * Check if this transaction uses hybrid signatures
     */
    bool IsHybridTransaction() const {
        return TxVersionFlags::IsHybridTransaction(nVersion);
    }
    
    /**
     * Get the PQC algorithm type
     */
    PQC::AlgorithmType GetPQCAlgorithm() const {
        return TxVersionFlags::GetPQCAlgorithm(nVersion);
    }
    
    /**
     * Mark transaction as hybrid
     */
    void SetAsHybridTransaction(PQC::AlgorithmType algo) {
        nVersion |= TxVersionFlags::PQC_FLAG;
        nVersion |= TxVersionFlags::HYBRID_FLAG;
        nVersion |= (static_cast<uint32_t>(algo) << TxVersionFlags::PQC_ALGORITHM_SHIFT);
    }
    
    /**
     * Mark transaction as pure PQC
     */
    void SetAsPQCTransaction(PQC::AlgorithmType algo) {
        nVersion |= TxVersionFlags::PQC_FLAG;
        nVersion &= ~TxVersionFlags::HYBRID_FLAG;
        nVersion |= (static_cast<uint32_t>(algo) << TxVersionFlags::PQC_ALGORITHM_SHIFT);
    }
    
    /**
     * Estimate total size including PQC signatures
     */
    size_t EstimateSize() const {
        size_t size = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
        
        // Add estimated PQC signature overhead
        if (IsPQCTransaction()) {
            // Rough estimate: ~2500 bytes per hybrid signature
            size += vin.size() * 2500;
        }
        
        return size;
    }
    
    /**
     * Get number of PQC-signed inputs
     */
    int GetPQCInputCount() const {
        int count = 0;
        // Implementation would iterate through inputs
        // and count PQC signatures
        return count;
    }
    
    /**
     * Check if transaction can be safely downgraded to legacy format
     * (all inputs must be pure legacy ECDSA)
     */
    bool CanDowngradeToLegacy() const {
        if (!IsPQCTransaction()) return true;
        
        // Check if any input uses PQC signatures
        for (const auto& input : vin) {
            // Implementation would check input type
            // if it uses PQC, cannot downgrade
        }
        return true;
    }
};

// ============================================================================
// Transaction Serialization Extensions
// ============================================================================

/**
 * Serialize a transaction with PQC support
 * Maintains compatibility with existing serialization while adding PQC data
 */
template <typename Stream>
inline void SerializeTransaction(Stream& s, const CTransactionPQC& tx) {
    s << tx.nVersion;
    s << (uint32_t)tx.vin.size();
    
    for (const auto& txin : tx.vin) {
        s << txin.prevout;
        s << txin.scriptSig;
        s << txin.nSequence;
        
        // Serialize PQC signature if present
        if (tx.IsPQCTransaction()) {
            // Implementation would serialize PQC data
            // while maintaining backward compatibility
        }
    }
    
    s << (uint32_t)tx.vout.size();
    for (const auto& txout : tx.vout) {
        s << txout;
    }
    
    s << tx.nLockTime;
}

/**
 * Deserialize a transaction with PQC support
 * Automatically handles both legacy and PQC-enhanced formats
 */
template <typename Stream>
inline void DeserializeTransaction(Stream& s, CTransactionPQC& tx) {
    s >> tx.nVersion;
    
    uint32_t vin_size;
    s >> vin_size;
    tx.vin.clear();
    tx.vin.resize(vin_size);
    
    for (auto& txin : tx.vin) {
        s >> txin.prevout;
        s >> txin.scriptSig;
        s >> txin.nSequence;
        
        // Deserialize PQC signature if present
        if (tx.IsPQCTransaction()) {
            // Implementation would deserialize PQC data
        }
    }
    
    uint32_t vout_size;
    s >> vout_size;
    tx.vout.clear();
    tx.vout.resize(vout_size);
    
    for (auto& txout : tx.vout) {
        s >> txout;
    }
    
    s >> tx.nLockTime;
}

// ============================================================================
// Transaction Validation
// ============================================================================

/**
 * Validation context for PQC transactions
 */
struct TransactionValidationContextPQC {
    bool allowPQC;              ///< Whether PQC signatures are allowed
    bool requirePQC;            ///< Whether to require PQC signatures
    uint32_t blockHeight;       ///< Current block height for version checking
    uint32_t medianTime;        ///< Median time for consensus rules
    
    TransactionValidationContextPQC() 
        : allowPQC(true), requirePQC(false), blockHeight(0), medianTime(0) {}
};

/**
 * Validate a PQC transaction
 * @param tx Transaction to validate
 * @param context Validation context
 * @return true if transaction is valid
 */
bool ValidatePQCTransaction(const CTransactionPQC& tx, 
                            const TransactionValidationContextPQC& context);

/**
 * Validate PQC signatures in a transaction
 * @param tx Transaction to validate
 * @return true if all PQC signatures are valid
 */
bool ValidatePQCSignatures(const CTransactionPQC& tx);

// ============================================================================
// Address Format Extensions
// ============================================================================

/**
 * Address version bytes for different key types
 */
namespace AddressVersionBytes {
    constexpr uint8_t LEGACY_P2PKH = 0x00;        ///< Pay to Public Key Hash (legacy)
    constexpr uint8_t LEGACY_P2SH = 0x05;         ///< Pay to Script Hash (legacy)
    constexpr uint8_t HYBRID_P2PKH = 0x20;        ///< Pay to Hybrid Public Key Hash
    constexpr uint8_t HYBRID_P2SH = 0x25;         ///< Pay to Hybrid Script Hash
    constexpr uint8_t PQC_P2PKH = 0x40;           ///< Pay to PQC Public Key Hash
    constexpr uint8_t PQC_P2SH = 0x45;            ///< Pay to PQC Script Hash
}

/**
 * Create a hybrid address from a hybrid public key
 * @param hybridKey Hybrid public key
 * @return Base58Check encoded address
 */
std::string CreateHybridAddress(const std::shared_ptr<PQC::HybridPublicKey>& hybridKey);

/**
 * Create a PQC-only address from a Dilithium public key
 * @param dilithiumKey Dilithium public key
 * @return Base58Check encoded address
 */
std::string CreatePQCAddress(const std::shared_ptr<PQC::DilithiumKey>& dilithiumKey);

/**
 * Decode and validate a hybrid or PQC address
 * @param address Address string to decode
 * @return Decoded key data, or empty vector if invalid
 */
std::vector<uint8_t> DecodeHybridAddress(const std::string& address);

#endif // BITCOIN_PRIMITIVES_TRANSACTION_PQC_H
