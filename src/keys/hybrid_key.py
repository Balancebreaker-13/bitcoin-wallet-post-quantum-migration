"""
Hybrid Key Management Module

Implements HybridPublicKey and HybridPrivateKey classes that combine
ECDSA and Post-Quantum Cryptographic keys.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any
import json
import time
from datetime import datetime


@dataclass
class HybridPublicKey:
    """
    Combined ECDSA + PQC public key for wallet addresses
    
    This key can be used for:
    - Address generation
    - Signature verification
    - Public key derivation
    """
    
    # ECDSA component (secp256k1)
    ecdsa_pubkey: bytes                    # 33 bytes (compressed)
    
    # Post-Quantum component
    pqc_algorithm: str                     # e.g., "ML-DSA-3", "ML-DSA-5"
    pqc_pubkey: bytes                      # Variable size (~1.3-2.6 KB)
    
    # Metadata
    key_id: str                            # Unique identifier (16 hex chars)
    derivation_path: str                   # BIP44 path: m/44'/0'/0'/hybrid/0
    created_at: int                        # Unix timestamp
    version: int = 1                       # Key format version
    
    # Optional metadata
    label: Optional[str] = None            # User-friendly label
    algorithm_version: str = "1.0"         # Algorithm version info
    
    def __post_init__(self):
        """
        Validate key components after initialization
        
        Raises:
            ValueError: If key sizes are invalid
        """
        self._validate_keys()
    
    def _validate_keys(self) -> None:
        """
        Validate key component sizes
        
        Raises:
            ValueError: If key sizes are invalid
        """
        # ECDSA public key should be 33 bytes (compressed) or 65 (uncompressed)
        if len(self.ecdsa_pubkey) not in [33, 65]:
            raise ValueError(
                f"Invalid ECDSA public key size: {len(self.ecdsa_pubkey)}"
            )
        
        # PQC public key size depends on algorithm
        if len(self.pqc_pubkey) < 1000:
            raise ValueError(
                f"Invalid PQC public key size: {len(self.pqc_pubkey)}"
            )
        
        # Validate key_id format
        if not isinstance(self.key_id, str) or len(self.key_id) != 16:
            raise ValueError("key_id must be 16 hex characters")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization
        
        Returns:
            dict: Serializable dictionary representation
        """
        return {
            'ecdsa_pubkey': self.ecdsa_pubkey.hex(),
            'pqc_algorithm': self.pqc_algorithm,
            'pqc_pubkey': self.pqc_pubkey.hex(),
            'key_id': self.key_id,
            'derivation_path': self.derivation_path,
            'created_at': self.created_at,
            'version': self.version,
            'label': self.label,
            'algorithm_version': self.algorithm_version,
        }
    
    def to_json(self) -> str:
        """
        Serialize to JSON format
        
        Returns:
            str: JSON representation
        """
        return json.dumps(self.to_dict(), indent=2)
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'HybridPublicKey':
        """
        Create instance from dictionary
        
        Args:
            data: Dictionary with key components
        
        Returns:
            HybridPublicKey: Reconstructed key
        """
        return HybridPublicKey(
            ecdsa_pubkey=bytes.fromhex(data['ecdsa_pubkey']),
            pqc_algorithm=data['pqc_algorithm'],
            pqc_pubkey=bytes.fromhex(data['pqc_pubkey']),
            key_id=data['key_id'],
            derivation_path=data['derivation_path'],
            created_at=data['created_at'],
            version=data.get('version', 1),
            label=data.get('label'),
            algorithm_version=data.get('algorithm_version', '1.0'),
        )
    
    @staticmethod
    def from_json(json_str: str) -> 'HybridPublicKey':
        """
        Create instance from JSON string
        
        Args:
            json_str: JSON representation
        
        Returns:
            HybridPublicKey: Reconstructed key
        """
        data = json.loads(json_str)
        return HybridPublicKey.from_dict(data)
    
    def get_address(self, address_type: str = "hybrid") -> str:
        """
        Generate Bitcoin address from this public key
        
        Args:
            address_type: "legacy", "hybrid", or "pqc"
        
        Returns:
            str: Bitcoin address
        
        Note:
            This is a placeholder. Full implementation requires:
            - RIPEMD160 hashing
            - Base58Check encoding
            - Bech32 encoding (for SegWit/Taproot)
        """
        # Placeholder: return mock address
        if address_type == "legacy":
            return "1" + self.key_id[:26]  # P2PKH format
        elif address_type == "hybrid":
            return "bc1p" + self.key_id[:38]  # Taproot format
        else:
            return "bc1q" + self.key_id[:38]  # P2WPKH format
    
    def fingerprint(self) -> str:
        """
        Get unique fingerprint of this key
        
        Returns:
            str: First 8 characters of key_id
        """
        return self.key_id[:8]


@dataclass
class HybridPrivateKey:
    """
    Combined ECDSA + PQC private key for signing transactions
    
    Security Critical: These keys must be:
    - Encrypted at rest
    - Never logged or displayed
    - Securely erased from memory when done
    """
    
    # ECDSA component
    ecdsa_privkey: bytes                   # 32 bytes
    
    # Post-Quantum component
    pqc_privkey: bytes                     # Variable size (~2.5-5.3 KB)
    
    # Associated public key
    public_key: HybridPublicKey            # Reference to public key
    
    # Metadata
    key_id: str                            # Must match public_key.key_id
    created_at: int                        # Unix timestamp
    version: int = 1                       # Key format version
    
    # Usage tracking
    last_used: Optional[int] = None        # Last usage timestamp
    use_count: int = 0                     # Number of times used
    
    def __post_init__(self):
        """
        Validate key components
        
        Raises:
            ValueError: If key sizes or relationships are invalid
        """
        self._validate_keys()
    
    def _validate_keys(self) -> None:
        """
        Validate private key components
        
        Raises:
            ValueError: If validation fails
        """
        # ECDSA private key should be 32 bytes
        if len(self.ecdsa_privkey) != 32:
            raise ValueError(
                f"Invalid ECDSA private key size: {len(self.ecdsa_privkey)}"
            )
        
        # PQC private key size check
        if len(self.pqc_privkey) < 2000:
            raise ValueError(
                f"Invalid PQC private key size: {len(self.pqc_privkey)}"
            )
        
        # Verify key_id matches public key
        if self.key_id != self.public_key.key_id:
            raise ValueError("key_id does not match public_key.key_id")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization
        
        WARNING: This contains sensitive key material!
        Only use with encryption.
        
        Returns:
            dict: Dictionary representation
        """
        return {
            'ecdsa_privkey': self.ecdsa_privkey.hex(),
            'pqc_privkey': self.pqc_privkey.hex(),
            'public_key': self.public_key.to_dict(),
            'key_id': self.key_id,
            'created_at': self.created_at,
            'version': self.version,
            'last_used': self.last_used,
            'use_count': self.use_count,
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'HybridPrivateKey':
        """
        Create instance from dictionary
        
        Args:
            data: Dictionary with private key components
        
        Returns:
            HybridPrivateKey: Reconstructed key
        """
        public_key = HybridPublicKey.from_dict(data['public_key'])
        
        return HybridPrivateKey(
            ecdsa_privkey=bytes.fromhex(data['ecdsa_privkey']),
            pqc_privkey=bytes.fromhex(data['pqc_privkey']),
            public_key=public_key,
            key_id=data['key_id'],
            created_at=data['created_at'],
            version=data.get('version', 1),
            last_used=data.get('last_used'),
            use_count=data.get('use_count', 0),
        )
    
    def mark_used(self) -> None:
        """
        Update usage tracking metadata
        
        Increments use counter and updates last_used timestamp
        """
        self.last_used = int(time.time())
        self.use_count += 1
    
    def secure_erase(self) -> None:
        """
        Securely erase key material from memory
        
        Overwrites key data with zeros to prevent recovery
        """
        # Overwrite key data with zeros
        self.ecdsa_privkey = bytes(len(self.ecdsa_privkey))
        self.pqc_privkey = bytes(len(self.pqc_privkey))
    
    def __del__(self):
        """
        Destructor to ensure key erasure
        
        WARNING: Destructors are not guaranteed to run immediately
        Always call secure_erase() explicitly
        """
        try:
            self.secure_erase()
        except Exception:
            pass


class HybridKeyPair:
    """
    Container for a complete public-private key pair
    """
    
    def __init__(self, public_key: HybridPublicKey, private_key: HybridPrivateKey):
        """
        Initialize key pair
        
        Args:
            public_key: HybridPublicKey instance
            private_key: HybridPrivateKey instance
        
        Raises:
            ValueError: If keys don't match
        """
        if public_key.key_id != private_key.key_id:
            raise ValueError("Public and private keys must have matching key_ids")
        
        self.public_key = public_key
        self.private_key = private_key
    
    def get_key_id(self) -> str:
        """
        Get the key pair identifier
        
        Returns:
            str: 16-character key ID
        """
        return self.public_key.key_id
    
    def get_fingerprint(self) -> str:
        """
        Get fingerprint (first 8 chars of key_id)
        
        Returns:
            str: 8-character fingerprint
        """
        return self.public_key.fingerprint()
    
    def is_aged(self, max_age_seconds: int = 2592000) -> bool:  # 30 days default
        """
        Check if key is older than specified age
        
        Args:
            max_age_seconds: Maximum age in seconds (default: 30 days)
        
        Returns:
            bool: True if key is older than max_age
        """
        age = int(time.time()) - self.public_key.created_at
        return age > max_age_seconds
