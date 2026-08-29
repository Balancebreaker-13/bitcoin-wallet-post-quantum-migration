"""
Hybrid Transaction Signing Pipeline

Implements dual-signature mechanism for Bitcoin transactions:
- ECDSA signatures (backward compatibility)
- Dilithium signatures (quantum resistance)
"""

from dataclasses import dataclass
from typing import Tuple, Optional
import hashlib
import time

from src.crypto import ECDSAModule, PQCModule
from src.keys import HybridPrivateKey, HybridPublicKey


@dataclass
class HybridSignature:
    """
    Combined ECDSA + Dilithium signature for transaction
    """
    
    # Signature components
    ecdsa_signature: bytes                 # 71-72 bytes
    pqc_signature: bytes                   # 2,420-4,595 bytes (depending on level)
    
    # Associated public key
    public_key: HybridPublicKey
    
    # Metadata
    timestamp: int                         # Signature creation time
    version: int = 1                       # Signature format version
    
    def get_total_size(self) -> int:
        """
        Get total signature size in bytes
        
        Returns:
            int: Total size including all components
        """
        # Format overhead: 1 (version) + 2 (ecdsa len) + 2 (pqc len)
        overhead = 5
        return overhead + len(self.ecdsa_signature) + len(self.pqc_signature)
    
    def serialize(self) -> bytes:
        """
        Serialize signature to bytes
        
        Format:
        [1 byte version][2 bytes ecdsa_sig_len][ecdsa_sig][2 bytes pqc_sig_len][pqc_sig]
        
        Returns:
            bytes: Serialized signature
        """
        data = bytes([self.version])
        data += len(self.ecdsa_signature).to_bytes(2, 'big')
        data += self.ecdsa_signature
        data += len(self.pqc_signature).to_bytes(2, 'big')
        data += self.pqc_signature
        return data
    
    @staticmethod
    def deserialize(data: bytes) -> 'HybridSignature':
        """
        Deserialize signature from bytes
        
        Args:
            data: Serialized signature bytes
        
        Returns:
            HybridSignature: Reconstructed signature
        
        Raises:
            ValueError: If deserialization fails
        """
        if len(data) < 5:
            raise ValueError("Invalid signature format")
        
        version = data[0]
        ecdsa_len = int.from_bytes(data[1:3], 'big')
        ecdsa_sig = data[3:3+ecdsa_len]
        pqc_start = 3 + ecdsa_len
        pqc_len = int.from_bytes(data[pqc_start:pqc_start+2], 'big')
        pqc_sig = data[pqc_start+2:pqc_start+2+pqc_len]
        
        # Note: public_key needs to be set separately
        sig = HybridSignature(
            ecdsa_signature=ecdsa_sig,
            pqc_signature=pqc_sig,
            public_key=None,  # Will be set later
            timestamp=int(time.time()),
            version=version
        )
        return sig


class HybridSigningPipeline:
    """
    Multi-stage transaction signing process
    
    Pipeline:
    1. Hash transaction data (SHA256)
    2. Sign with ECDSA (secp256k1)
    3. Sign with Dilithium (ML-DSA)
    4. Combine signatures
    """
    
    def __init__(self):
        """
        Initialize signing pipeline with crypto modules
        """
        self.ecdsa = ECDSAModule()
        self.pqc = PQCModule()
    
    def sign_transaction(
        self,
        tx_data: bytes,
        private_key: HybridPrivateKey
    ) -> HybridSignature:
        """
        Sign transaction with both ECDSA and Dilithium
        
        Args:
            tx_data: Raw transaction data
            private_key: HybridPrivateKey for signing
        
        Returns:
            HybridSignature: Combined signature
        
        Raises:
            ValueError: If private key is invalid
            RuntimeError: If signing fails
        """
        # Stage 1: Hash transaction
        tx_hash = self._hash_transaction(tx_data)
        
        # Stage 2: ECDSA signature (backward compatibility)
        try:
            ecdsa_sig = self.ecdsa.sign(tx_hash, private_key.ecdsa_privkey)
        except Exception as e:
            raise RuntimeError(f"ECDSA signing failed: {str(e)}")
        
        # Stage 3: Dilithium signature (quantum resistance)
        try:
            dilithium_sig = self.pqc.dilithium.sign(
                tx_hash,
                private_key.pqc_privkey
            )
        except Exception as e:
            raise RuntimeError(f"Dilithium signing failed: {str(e)}")
        
        # Stage 4: Combine signatures
        combined_sig = HybridSignature(
            ecdsa_signature=ecdsa_sig,
            pqc_signature=dilithium_sig,
            public_key=private_key.public_key,
            timestamp=int(time.time()),
            version=1
        )
        
        # Update key usage tracking
        private_key.mark_used()
        
        return combined_sig
    
    def verify_hybrid_signature(
        self,
        tx_data: bytes,
        signature: HybridSignature
    ) -> bool:
        """
        Verify transaction signature (both ECDSA and PQC must be valid)
        
        Args:
            tx_data: Original transaction data
            signature: HybridSignature to verify
        
        Returns:
            bool: True only if both signatures verify
        """
        tx_hash = self._hash_transaction(tx_data)
        
        # Verify ECDSA
        try:
            ecdsa_valid = self.ecdsa.verify(
                tx_hash,
                signature.ecdsa_signature,
                signature.public_key.ecdsa_pubkey
            )
        except Exception:
            return False
        
        # Verify Dilithium
        try:
            pqc_valid = self.pqc.dilithium.verify(
                tx_hash,
                signature.pqc_signature,
                signature.public_key.pqc_pubkey
            )
        except Exception:
            return False
        
        # Both must be valid
        return ecdsa_valid and pqc_valid
    
    def verify_ecdsa_only(
        self,
        tx_data: bytes,
        signature: HybridSignature
    ) -> bool:
        """
        Verify only ECDSA signature (for legacy compatibility)
        
        Args:
            tx_data: Transaction data
            signature: HybridSignature to verify
        
        Returns:
            bool: True if ECDSA signature is valid
        """
        tx_hash = self._hash_transaction(tx_data)
        
        try:
            return self.ecdsa.verify(
                tx_hash,
                signature.ecdsa_signature,
                signature.public_key.ecdsa_pubkey
            )
        except Exception:
            return False
    
    def verify_pqc_only(
        self,
        tx_data: bytes,
        signature: HybridSignature
    ) -> bool:
        """
        Verify only PQC signature (for quantum-safe verification)
        
        Args:
            tx_data: Transaction data
            signature: HybridSignature to verify
        
        Returns:
            bool: True if PQC signature is valid
        """
        tx_hash = self._hash_transaction(tx_data)
        
        try:
            return self.pqc.dilithium.verify(
                tx_hash,
                signature.pqc_signature,
                signature.public_key.pqc_pubkey
            )
        except Exception:
            return False
    
    @staticmethod
    def _hash_transaction(tx_data: bytes) -> bytes:
        """
        Compute transaction hash for signing
        
        Uses double SHA-256 (Bitcoin standard)
        
        Args:
            tx_data: Raw transaction data
        
        Returns:
            bytes: 32-byte transaction hash
        """
        return hashlib.sha256(
            hashlib.sha256(tx_data).digest()
        ).digest()
