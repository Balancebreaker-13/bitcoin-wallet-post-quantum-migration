// Copyright (c) 2026 Bitcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_PQC_H
#define BITCOIN_CRYPTO_PQC_H

#include <vector>
#include <string>
#include <cstddef>
#include <cstdint>
#include <memory>

/**
 * @file crypto/pqc.h
 * @brief Post-Quantum Cryptography (PQC) interface for Bitcoin Core
 * 
 * This header defines the interface for post-quantum cryptographic operations
 * including Dilithium signatures and Kyber key encapsulation.
 */

namespace PQC {

// ============================================================================
// Constants and Configuration
// ============================================================================

/**
 * PQC Algorithm Types
 */
enum class AlgorithmType : uint8_t {
    LEGACY_ECDSA = 0x00,      ///< Traditional ECDSA (secp256k1)
    HYBRID_ECDSA_DILITHIUM = 0x01,  ///< Hybrid ECC + Dilithium
    PURE_DILITHIUM = 0x02,    ///< Pure Dilithium signatures
    RESERVED = 0x03           ///< Reserved for future use
};

/**
 * Dilithium Security Levels
 */
enum class DilithiumSecurityLevel : uint8_t {
    LEVEL2 = 2,  ///< NIST Security Level 2 (~128-bit)
    LEVEL3 = 3,  ///< NIST Security Level 3 (~192-bit)
    LEVEL5 = 5   ///< NIST Security Level 5 (~256-bit)
};

/**
 * Kyber Security Levels
 */
enum class KyberSecurityLevel : uint8_t {
    LEVEL512 = 512,  ///< NIST Security Level 1 (~128-bit)
    LEVEL768 = 768,  ///< NIST Security Level 3 (~192-bit)
    LEVEL1024 = 1024 ///< NIST Security Level 5 (~256-bit)
};

/**
 * Default security levels for production
 */
constexpr DilithiumSecurityLevel DEFAULT_DILITHIUM_LEVEL = DilithiumSecurityLevel::LEVEL3;
constexpr KyberSecurityLevel DEFAULT_KYBER_LEVEL = KyberSecurityLevel::LEVEL768;

/**
 * Key sizes (in bytes) for different security levels
 */
constexpr size_t DILITHIUM2_PUBKEY_SIZE = 1312;
constexpr size_t DILITHIUM2_PRIVKEY_SIZE = 2544;
constexpr size_t DILITHIUM2_SIG_SIZE = 2420;

constexpr size_t DILITHIUM3_PUBKEY_SIZE = 1952;
constexpr size_t DILITHIUM3_PRIVKEY_SIZE = 4000;
constexpr size_t DILITHIUM3_SIG_SIZE = 3293;

constexpr size_t DILITHIUM5_PUBKEY_SIZE = 2592;
constexpr size_t DILITHIUM5_PRIVKEY_SIZE = 4864;
constexpr size_t DILITHIUM5_SIG_SIZE = 4595;

constexpr size_t KYBER512_PUBKEY_SIZE = 800;
constexpr size_t KYBER512_PRIVKEY_SIZE = 1632;
constexpr size_t KYBER512_CIPHERTEXT_SIZE = 768;

constexpr size_t KYBER768_PUBKEY_SIZE = 1184;
constexpr size_t KYBER768_PRIVKEY_SIZE = 2400;
constexpr size_t KYBER768_CIPHERTEXT_SIZE = 1088;

constexpr size_t KYBER1024_PUBKEY_SIZE = 1568;
constexpr size_t KYBER1024_PRIVKEY_SIZE = 3168;
constexpr size_t KYBER1024_CIPHERTEXT_SIZE = 1568;

constexpr size_t SHARED_SECRET_SIZE = 32;  ///< Shared secret size (bytes)

// ============================================================================
// Exceptions and Error Handling
// ============================================================================

/**
 * Exception thrown for PQC operation failures
 */
class PQCException : public std::exception {
private:
    std::string message;
public:
    explicit PQCException(const std::string& msg) : message(msg) {}
    const char* what() const noexcept override { return message.c_str(); }
};

// ============================================================================
// Dilithium Signature Scheme
// ============================================================================

/**
 * @class DilithiumKey
 * @brief Represents a Dilithium keypair
 */
class DilithiumKey {
public:
    /**
     * Generate a new Dilithium keypair
     * @param level Security level (2, 3, or 5)
     * @return Newly generated DilithiumKey
     * @throws PQCException if key generation fails
     */
    static std::shared_ptr<DilithiumKey> Generate(DilithiumSecurityLevel level = DEFAULT_DILITHIUM_LEVEL);

    /**
     * Create a DilithiumKey from raw key material
     * @param pubkey Raw public key bytes
     * @param privkey Raw private key bytes (optional for verification-only keys)
     * @return DilithiumKey instance
     * @throws PQCException if keys are invalid
     */
    static std::shared_ptr<DilithiumKey> FromRaw(const std::vector<uint8_t>& pubkey,
                                                  const std::vector<uint8_t>* privkey = nullptr);

    /**
     * Get the public key
     * @return Public key as bytes
     */
    const std::vector<uint8_t>& GetPublicKey() const;

    /**
     * Get the private key
     * @return Private key as bytes
     */
    const std::vector<uint8_t>& GetPrivateKey() const;

    /**
     * Get the security level
     * @return Security level (2, 3, or 5)
     */
    DilithiumSecurityLevel GetSecurityLevel() const;

    /**
     * Check if this key has a private component
     * @return true if private key is available, false otherwise
     */
    bool HasPrivateKey() const;

    /**
     * Get the key ID (hash of public key)
     * @return 32-byte key identifier
     */
    std::vector<uint8_t> GetKeyID() const;

    virtual ~DilithiumKey() = default;

private:
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    DilithiumSecurityLevel level;
    std::vector<uint8_t> key_id;

    DilithiumKey() = default;
};

/**
 * @class DilithiumSignature
 * @brief Represents a Dilithium signature
 */
class DilithiumSignature {
public:
    /**
     * Create a signature from raw bytes
     * @param sig_data Raw signature bytes
     * @return DilithiumSignature instance
     */
    static std::shared_ptr<DilithiumSignature> FromRaw(const std::vector<uint8_t>& sig_data);

    /**
     * Get the signature bytes
     * @return Signature as bytes
     */
    const std::vector<uint8_t>& GetSignatureData() const;

    /**
     * Get the size of the signature
     * @return Size in bytes
     */
    size_t GetSize() const;

    virtual ~DilithiumSignature() = default;

private:
    std::vector<uint8_t> sig_data;

    DilithiumSignature() = default;
};

/**
 * Sign a message with a Dilithium private key
 * @param message Message bytes to sign
 * @param key Dilithium key (must have private component)
 * @return Signature object
 * @throws PQCException if signing fails
 */
std::shared_ptr<DilithiumSignature> DilithiumSign(const std::vector<uint8_t>& message,
                                                   const std::shared_ptr<DilithiumKey>& key);

/**
 * Verify a Dilithium signature
 * @param message Original message bytes
 * @param signature Signature to verify
 * @param pubkey Public key
 * @return true if signature is valid, false otherwise
 * @throws PQCException if verification fails
 */
bool DilithiumVerify(const std::vector<uint8_t>& message,
                     const std::shared_ptr<DilithiumSignature>& signature,
                     const std::vector<uint8_t>& pubkey);

// ============================================================================
// Kyber Key Encapsulation Mechanism
// ============================================================================

/**
 * @class KyberKey
 * @brief Represents a Kyber keypair
 */
class KyberKey {
public:
    /**
     * Generate a new Kyber keypair
     * @param level Security level (512, 768, or 1024)
     * @return Newly generated KyberKey
     * @throws PQCException if key generation fails
     */
    static std::shared_ptr<KyberKey> Generate(KyberSecurityLevel level = DEFAULT_KYBER_LEVEL);

    /**
     * Create a KyberKey from raw key material
     * @param pubkey Raw public key bytes
     * @param privkey Raw private key bytes (optional for encapsulation-only keys)
     * @return KyberKey instance
     * @throws PQCException if keys are invalid
     */
    static std::shared_ptr<KyberKey> FromRaw(const std::vector<uint8_t>& pubkey,
                                              const std::vector<uint8_t>* privkey = nullptr);

    /**
     * Get the public key
     * @return Public key as bytes
     */
    const std::vector<uint8_t>& GetPublicKey() const;

    /**
     * Get the private key
     * @return Private key as bytes
     */
    const std::vector<uint8_t>& GetPrivateKey() const;

    /**
     * Get the security level
     * @return Security level (512, 768, or 1024)
     */
    KyberSecurityLevel GetSecurityLevel() const;

    /**
     * Check if this key has a private component
     * @return true if private key is available, false otherwise
     */
    bool HasPrivateKey() const;

    /**
     * Get the key ID (hash of public key)
     * @return 32-byte key identifier
     */
    std::vector<uint8_t> GetKeyID() const;

    virtual ~KyberKey() = default;

private:
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    KyberSecurityLevel level;
    std::vector<uint8_t> key_id;

    KyberKey() = default;
};

/**
 * @class KyberEncapsulation
 * @brief Result of Kyber encapsulation containing ciphertext and shared secret
 */
class KyberEncapsulation {
public:
    /**
     * Create an encapsulation from raw components
     * @param ciphertext Encapsulated key
     * @param shared_secret Shared secret
     * @return KyberEncapsulation instance
     */
    static std::shared_ptr<KyberEncapsulation> FromComponents(const std::vector<uint8_t>& ciphertext,
                                                               const std::vector<uint8_t>& shared_secret);

    /**
     * Get the ciphertext (encapsulated key)
     * @return Ciphertext bytes
     */
    const std::vector<uint8_t>& GetCiphertext() const;

    /**
     * Get the shared secret
     * @return Shared secret bytes (32 bytes)
     */
    const std::vector<uint8_t>& GetSharedSecret() const;

    virtual ~KyberEncapsulation() = default;

private:
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> shared_secret;

    KyberEncapsulation() = default;
};

/**
 * Encapsulate with a Kyber public key (key establishment initiator)
 * @param pubkey Kyber public key to encapsulate for
 * @return Encapsulation containing ciphertext and shared secret
 * @throws PQCException if encapsulation fails
 */
std::shared_ptr<KyberEncapsulation> KyberEncapsulate(const std::vector<uint8_t>& pubkey);

/**
 * Decapsulate with a Kyber private key (key establishment responder)
 * @param ciphertext Encapsulated key from initiator
 * @param key Kyber key (must have private component)
 * @return Shared secret bytes (should match initiator's shared secret)
 * @throws PQCException if decapsulation fails
 */
std::vector<uint8_t> KyberDecapsulate(const std::vector<uint8_t>& ciphertext,
                                      const std::shared_ptr<KyberKey>& key);

// ============================================================================
// Hybrid ECC + PQC Operations
// ============================================================================

/**
 * @class HybridPublicKey
 * @brief Represents a hybrid public key (ECC + PQC)
 */
class HybridPublicKey {
public:
    /**
     * Create a hybrid public key from components
     * @param ecc_pubkey ECC public key (secp256k1, 33 bytes compressed)
     * @param dilithium_pubkey Dilithium public key
     * @param kyber_pubkey Kyber public key
     * @return HybridPublicKey instance
     */
    static std::shared_ptr<HybridPublicKey> FromComponents(const std::vector<uint8_t>& ecc_pubkey,
                                                            const std::vector<uint8_t>& dilithium_pubkey,
                                                            const std::vector<uint8_t>& kyber_pubkey);

    /**
     * Get ECC public key component
     * @return ECC public key bytes
     */
    const std::vector<uint8_t>& GetECCPublicKey() const;

    /**
     * Get Dilithium public key component
     * @return Dilithium public key bytes
     */
    const std::vector<uint8_t>& GetDilithiumPublicKey() const;

    /**
     * Get Kyber public key component
     * @return Kyber public key bytes
     */
    const std::vector<uint8_t>& GetKyberPublicKey() const;

    /**
     * Get the hybrid key ID
     * @return 32-byte hybrid key identifier
     */
    std::vector<uint8_t> GetKeyID() const;

    /**
     * Serialize the hybrid public key
     * @return Serialized bytes
     */
    std::vector<uint8_t> Serialize() const;

    /**
     * Deserialize a hybrid public key
     * @param data Serialized data
     * @return HybridPublicKey instance
     * @throws PQCException if deserialization fails
     */
    static std::shared_ptr<HybridPublicKey> Deserialize(const std::vector<uint8_t>& data);

    virtual ~HybridPublicKey() = default;

private:
    std::vector<uint8_t> ecc_pubkey;
    std::vector<uint8_t> dilithium_pubkey;
    std::vector<uint8_t> kyber_pubkey;
    std::vector<uint8_t> key_id;

    HybridPublicKey() = default;
};

/**
 * @class HybridPrivateKey
 * @brief Represents a hybrid private key (ECC + PQC)
 */
class HybridPrivateKey {
public:
    /**
     * Generate a new hybrid keypair
     * @param dilithium_level Dilithium security level
     * @param kyber_level Kyber security level
     * @return Newly generated HybridPrivateKey
     * @throws PQCException if generation fails
     */
    static std::shared_ptr<HybridPrivateKey> Generate(
        DilithiumSecurityLevel dilithium_level = DEFAULT_DILITHIUM_LEVEL,
        KyberSecurityLevel kyber_level = DEFAULT_KYBER_LEVEL);

    /**
     * Create a hybrid private key from components
     * @param ecc_privkey ECC private key (secp256k1, 32 bytes)
     * @param dilithium_privkey Dilithium private key
     * @param kyber_privkey Kyber private key
     * @return HybridPrivateKey instance
     */
    static std::shared_ptr<HybridPrivateKey> FromComponents(const std::vector<uint8_t>& ecc_privkey,
                                                             const std::vector<uint8_t>& dilithium_privkey,
                                                             const std::vector<uint8_t>& kyber_privkey);

    /**
     * Get the public key portion
     * @return HybridPublicKey instance
     */
    std::shared_ptr<HybridPublicKey> GetPublicKey() const;

    /**
     * Get ECC private key component
     * @return ECC private key bytes
     */
    const std::vector<uint8_t>& GetECCPrivateKey() const;

    /**
     * Get Dilithium private key component
     * @return Dilithium private key bytes
     */
    const std::vector<uint8_t>& GetDilithiumPrivateKey() const;

    /**
     * Get Kyber private key component
     * @return Kyber private key bytes
     */
    const std::vector<uint8_t>& GetKyberPrivateKey() const;

    /**
     * Serialize the hybrid private key
     * @return Serialized bytes
     */
    std::vector<uint8_t> Serialize() const;

    /**
     * Deserialize a hybrid private key
     * @param data Serialized data
     * @return HybridPrivateKey instance
     * @throws PQCException if deserialization fails
     */
    static std::shared_ptr<HybridPrivateKey> Deserialize(const std::vector<uint8_t>& data);

    virtual ~HybridPrivateKey() = default;

private:
    std::vector<uint8_t> ecc_privkey;
    std::vector<uint8_t> dilithium_privkey;
    std::vector<uint8_t> kyber_privkey;
    std::shared_ptr<HybridPublicKey> pubkey;

    HybridPrivateKey() = default;
};

/**
 * @class HybridSignature
 * @brief Represents a hybrid signature (ECC + PQC)
 */
class HybridSignature {
public:
    /**
     * Create a hybrid signature from components
     * @param ecc_signature ECC signature (variable length, typically 71 bytes)
     * @param dilithium_signature Dilithium signature
     * @return HybridSignature instance
     */
    static std::shared_ptr<HybridSignature> FromComponents(const std::vector<uint8_t>& ecc_signature,
                                                            const std::vector<uint8_t>& dilithium_signature);

    /**
     * Get ECC signature component
     * @return ECC signature bytes
     */
    const std::vector<uint8_t>& GetECCSignature() const;

    /**
     * Get Dilithium signature component
     * @return Dilithium signature bytes
     */
    const std::vector<uint8_t>& GetDilithiumSignature() const;

    /**
     * Get total signature size
     * @return Size in bytes
     */
    size_t GetSize() const;

    /**
     * Serialize the hybrid signature
     * @return Serialized bytes
     */
    std::vector<uint8_t> Serialize() const;

    /**
     * Deserialize a hybrid signature
     * @param data Serialized data
     * @return HybridSignature instance
     * @throws PQCException if deserialization fails
     */
    static std::shared_ptr<HybridSignature> Deserialize(const std::vector<uint8_t>& data);

    virtual ~HybridSignature() = default;

private:
    std::vector<uint8_t> ecc_signature;
    std::vector<uint8_t> dilithium_signature;

    HybridSignature() = default;
};

/**
 * Sign a message with a hybrid private key
 * @param message Message bytes to sign
 * @param key Hybrid key (must have private components)
 * @return Hybrid signature
 * @throws PQCException if signing fails
 */
std::shared_ptr<HybridSignature> HybridSign(const std::vector<uint8_t>& message,
                                            const std::shared_ptr<HybridPrivateKey>& key);

/**
 * Verify a hybrid signature
 * @param message Original message bytes
 * @param signature Hybrid signature to verify
 * @param pubkey Hybrid public key
 * @return true if both ECC and Dilithium signatures are valid, false otherwise
 * @throws PQCException if verification fails
 */
bool HybridVerify(const std::vector<uint8_t>& message,
                  const std::shared_ptr<HybridSignature>& signature,
                  const std::shared_ptr<HybridPublicKey>& pubkey);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Initialize the PQC library (must be called once at startup)
 * @throws PQCException if initialization fails
 */
void Initialize();

/**
 * Get version information for PQC algorithms
 * @return Version string
 */
std::string GetVersion();

/**
 * Get information about supported algorithms
 * @return Algorithm info string
 */
std::string GetAlgorithmInfo();

} // namespace PQC

#endif // BITCOIN_CRYPTO_PQC_H
