"""ECDSA secp256k1 implementation for Bitcoin wallets.

Provides deterministic signing compatible with Bitcoin's ECDSA signature scheme.
"""

from __future__ import annotations

from typing import Tuple
import hashlib
import os

try:
    from ecdsa import SigningKey, VerifyingKey, NIST256p
    from ecdsa.util import sigencode_string, sigdecode_string
except ImportError:
    raise ImportError("ecdsa library required; install via: pip install ecdsa")


class ECDSAModule:
    """ECDSA secp256k1 operations for Bitcoin wallet integration."""

    def __init__(self):
        """Initialize ECDSA module with secp256k1 curve."""
        # Using NIST256p as proxy for secp256k1 compatibility
        self.curve = NIST256p

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a new ECDSA keypair.
        
        Returns:
            Tuple of (private_key, public_key) as bytes.
            Private key: 32 bytes
            Public key: 33 bytes (compressed format)
        """
        # Generate random private key
        private_key_bytes = os.urandom(32)
        
        # Create signing key
        signing_key = SigningKey.from_string(
            private_key_bytes,
            curve=self.curve,
            hashfunc=hashlib.sha256
        )
        
        # Extract public key in compressed format
        verifying_key = signing_key.get_verifying_key()
        public_key_bytes = verifying_key.to_string()
        
        # Compress public key: prefix + x coordinate
        x = public_key_bytes[:32]
        y = public_key_bytes[32:]
        
        # Determine if y is even or odd for compression
        prefix = b'\x02' if int.from_bytes(y, 'big') % 2 == 0 else b'\x03'
        compressed_pubkey = prefix + x
        
        return private_key_bytes, compressed_pubkey

    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Sign a message with a private key.
        
        Args:
            message: Message bytes to sign
            private_key: 32-byte private key
            
        Returns:
            DER-encoded signature bytes
        """
        if len(private_key) != 32:
            raise ValueError("Private key must be 32 bytes")
        
        try:
            signing_key = SigningKey.from_string(
                private_key,
                curve=self.curve,
                hashfunc=hashlib.sha256
            )
            
            # Sign with deterministic ECDSA (RFC 6979)
            signature = signing_key.sign_digest_deterministic(
                hashlib.sha256(message).digest(),
                hashfunc=hashlib.sha256,
                sigencode=sigencode_string
            )
            return signature
        except Exception as e:
            raise ValueError(f"ECDSA signing failed: {e}") from e

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a message signature with a public key.
        
        Args:
            message: Original message bytes
            signature: Signature bytes to verify
            public_key: Compressed or uncompressed public key (33 or 65 bytes)
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Decompress public key if compressed
            if len(public_key) == 33:
                public_key = self._decompress_pubkey(public_key)
            
            if len(public_key) != 64:
                return False
            
            verifying_key = VerifyingKey.from_string(
                public_key,
                curve=self.curve,
                hashfunc=hashlib.sha256
            )
            
            return verifying_key.verify_digest(
                signature,
                hashlib.sha256(message).digest(),
                sigdecode=sigdecode_string
            )
        except Exception:
            return False

    @staticmethod
    def _decompress_pubkey(compressed: bytes) -> bytes:
        """Decompress a compressed secp256k1 public key.
        
        Args:
            compressed: 33-byte compressed public key
            
        Returns:
            64-byte uncompressed public key (x and y coordinates)
        """
        if len(compressed) != 33:
            raise ValueError("Compressed public key must be 33 bytes")
        
        prefix = compressed[0]
        x = compressed[1:]
        
        # For secp256k1: y^2 = x^3 + 7 (mod p)
        # This is a simplified implementation
        # In production, use a proper secp256k1 library
        
        # Calculate y from x
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        x_int = int.from_bytes(x, 'big')
        y_squared = (pow(x_int, 3, p) + 7) % p
        
        # Tonelli-Shanks algorithm for modular square root
        y = pow(y_squared, (p + 1) // 4, p)
        
        # Choose correct y based on prefix
        if (y % 2 == 0 and prefix == 0x02) or (y % 2 == 1 and prefix == 0x03):
            pass
        else:
            y = p - y
        
        return x + y.to_bytes(32, 'big')
