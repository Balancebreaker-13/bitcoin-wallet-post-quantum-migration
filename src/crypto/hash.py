"""
Cryptographic Hash Utilities

Provides:
- SHA-256 hashing
- HMAC-SHA512 for key derivation
- PBKDF2 for password hashing
"""

import hashlib
import hmac
from typing import Optional


class SHA256Hash:
    """
    SHA-256 cryptographic hash function
    
    Used for:
    - Transaction hashing
    - Address generation
    - Merkle tree construction
    """
    
    HASH_SIZE = 32  # 256 bits
    
    @staticmethod
    def hash(data: bytes) -> bytes:
        """
        Compute SHA-256 hash
        
        Args:
            data: Data to hash
        
        Returns:
            bytes: 32-byte hash
        """
        return hashlib.sha256(data).digest()
    
    @staticmethod
    def double_hash(data: bytes) -> bytes:
        """
        Compute SHA-256(SHA-256(data))
        
        Used in Bitcoin for transaction and block hashing
        to prevent length extension attacks.
        
        Args:
            data: Data to hash
        
        Returns:
            bytes: 32-byte double hash
        """
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()


class HMACUtility:
    """
    HMAC-SHA512 for key derivation
    
    Used in:
    - BIP32 key derivation
    - PQC seed generation
    - Domain-separated key material
    """
    
    @staticmethod
    def hmac_sha512(key: bytes, data: bytes) -> bytes:
        """
        Compute HMAC-SHA512
        
        Args:
            key: HMAC key
            data: Data to process
        
        Returns:
            bytes: 64-byte HMAC value
        """
        return hmac.new(key, data, hashlib.sha512).digest()
    
    @staticmethod
    def derive_key(
        master_key: bytes,
        domain: bytes,
        index: int = 0
    ) -> bytes:
        """
        Derive a key using HMAC-SHA512 with domain separation
        
        Args:
            master_key: Master key material
            domain: Domain identifier (e.g., b"Bitcoin seed", b"Bitcoin PQC seed")
            index: Index for key derivation chain
        
        Returns:
            bytes: 64-byte derived key material
        """
        data = domain + index.to_bytes(4, byteorder='big')
        return HMACUtility.hmac_sha512(master_key, data)


class PBKDF2Utility:
    """
    PBKDF2 key derivation function
    
    Used for:
    - Password-based key derivation
    - Key encryption key generation
    - Wallet encryption
    """
    
    DEFAULT_ITERATIONS = 100000
    DEFAULT_HASH_NAME = 'sha256'
    DEFAULT_DK_LEN = 32  # 256 bits
    
    @staticmethod
    def derive(
        password: str,
        salt: bytes,
        iterations: int = DEFAULT_ITERATIONS,
        dklen: int = DEFAULT_DK_LEN
    ) -> bytes:
        """
        Derive a key from password using PBKDF2
        
        Args:
            password: Password string
            salt: Random salt (at least 16 bytes recommended)
            iterations: Number of iterations (default: 100,000)
            dklen: Desired key length (default: 32 bytes)
        
        Returns:
            bytes: Derived key material
        
        Security Notes:
            - Use at least 16 bytes of random salt
            - Use at least 100,000 iterations
            - For high-security applications, consider higher iteration counts
        """
        if len(salt) < 8:
            raise ValueError("Salt must be at least 8 bytes")
        
        if iterations < 100000:
            raise ValueError("Iterations should be at least 100,000")
        
        derived = hashlib.pbkdf2_hmac(
            PBKDF2Utility.DEFAULT_HASH_NAME,
            password.encode('utf-8'),
            salt,
            iterations,
            dklen
        )
        
        return derived
    
    @staticmethod
    def verify(
        password: str,
        salt: bytes,
        stored_hash: bytes,
        iterations: int = DEFAULT_ITERATIONS
    ) -> bool:
        """
        Verify a password against stored hash
        
        Args:
            password: Password to verify
            salt: Salt used in original derivation
            stored_hash: Stored hash to compare against
            iterations: Iterations used in original derivation
        
        Returns:
            bool: True if password matches, False otherwise
        """
        derived = PBKDF2Utility.derive(
            password,
            salt,
            iterations,
            len(stored_hash)
        )
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(derived, stored_hash)
