#!/usr/bin/env python3
"""
Dilithium Post-Quantum Signature Scheme - Proof of Concept Demo

This module demonstrates the Dilithium digital signature algorithm,
one of the NIST-standardized post-quantum cryptography algorithms.

Dilithium provides:
- Quantum-resistant digital signatures
- Deterministic signing
- High performance
- Small signature sizes

Security Levels:
- Level 2: NIST Security Level 2 (AES-128 equivalent)
- Level 3: NIST Security Level 3 (SHA3-256 equivalent)
- Level 5: NIST Security Level 5 (AES-256 equivalent)
"""

import oqs
import os
import hashlib
import json
from typing import Tuple, Dict, Optional
from datetime import datetime


class DilithiumPoC:
    """Proof of Concept implementation for Dilithium signatures"""
    
    # Supported Dilithium variants
    VARIANTS = {
        2: "Dilithium2",    # NIST Level 2
        3: "Dilithium3",    # NIST Level 3
        5: "Dilithium5",    # NIST Level 5
    }
    
    def __init__(self, security_level: int = 3):
        """
        Initialize Dilithium PoC
        
        Args:
            security_level: 2, 3, or 5 (default: 3)
            
        Raises:
            ValueError: If invalid security level
        """
        if security_level not in self.VARIANTS:
            raise ValueError(f"Invalid security level. Must be one of {list(self.VARIANTS.keys())}")
        
        self.security_level = security_level
        self.algorithm_name = self.VARIANTS[security_level]
        self.sig = None
        self.public_key = None
        self.private_key = None
        self.key_generated_at = None
        
    def generate_keypair(self) -> Dict[str, str]:
        """
        Generate a new Dilithium keypair
        
        Returns:
            Dictionary with public_key_hex and private_key_hex
        """
        try:
            self.sig = oqs.Signature(self.algorithm_name)
            self.public_key = self.sig.generate_keyset()
            self.private_key = self.sig.secret_key()
            self.key_generated_at = datetime.now().isoformat()
            
            return {
                "status": "success",
                "algorithm": self.algorithm_name,
                "security_level": self.security_level,
                "public_key_size": len(self.public_key),
                "private_key_size": len(self.private_key),
                "generated_at": self.key_generated_at,
                "public_key_hex": self.public_key.hex()[:64] + "...",  # Truncate for display
                "private_key_hex": self.private_key.hex()[:64] + "..."  # Truncate for display
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def sign_message(self, message: str) -> Dict[str, any]:
        """
        Sign a message with the private key
        
        Args:
            message: Message to sign (string)
            
        Returns:
            Dictionary with signature and metadata
        """
        if self.sig is None or self.private_key is None:
            return {
                "status": "error",
                "message": "Keypair not generated. Call generate_keypair() first."
            }
        
        try:
            message_bytes = message.encode('utf-8')
            signature = self.sig.sign(message_bytes)
            
            return {
                "status": "success",
                "message_hash": hashlib.sha256(message_bytes).hexdigest(),
                "message_length": len(message_bytes),
                "signature_size": len(signature),
                "signature_hex": signature.hex()[:64] + "...",  # Truncate for display
                "algorithm": self.algorithm_name,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def verify_signature(self, message: str, signature_hex: str) -> Dict[str, any]:
        """
        Verify a signature with the public key
        
        Args:
            message: Original message (string)
            signature_hex: Signature in hexadecimal format
            
        Returns:
            Dictionary with verification result
        """
        if self.sig is None or self.public_key is None:
            return {
                "status": "error",
                "message": "Public key not available."
            }
        
        try:
            message_bytes = message.encode('utf-8')
            signature_bytes = bytes.fromhex(signature_hex)
            
            # Verify signature
            self.sig.public_key = self.public_key
            is_valid = self.sig.verify(message_bytes, signature_bytes)
            
            return {
                "status": "success",
                "is_valid": is_valid,
                "message": "Signature valid" if is_valid else "Signature invalid",
                "algorithm": self.algorithm_name,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def export_keys(self, filepath: str) -> Dict[str, any]:
        """
        Export keys to file (encrypted storage recommended in production)
        
        Args:
            filepath: Path to save keys
            
        Returns:
            Status dictionary
        """
        if self.public_key is None or self.private_key is None:
            return {
                "status": "error",
                "message": "Keypair not generated."
            }
        
        try:
            keys_data = {
                "algorithm": self.algorithm_name,
                "security_level": self.security_level,
                "public_key": self.public_key.hex(),
                "private_key": self.private_key.hex(),  # WARNING: Store securely in production!
                "generated_at": self.key_generated_at,
                "exported_at": datetime.now().isoformat()
            }
            
            os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
            
            with open(filepath, 'w') as f:
                json.dump(keys_data, f, indent=2)
            
            return {
                "status": "success",
                "filepath": filepath,
                "message": "Keys exported successfully (store securely!)"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def import_keys(self, filepath: str) -> Dict[str, any]:
        """
        Import keys from file
        
        Args:
            filepath: Path to keys file
            
        Returns:
            Status dictionary
        """
        try:
            with open(filepath, 'r') as f:
                keys_data = json.load(f)
            
            self.algorithm_name = keys_data["algorithm"]
            self.security_level = keys_data["security_level"]
            self.public_key = bytes.fromhex(keys_data["public_key"])
            self.private_key = bytes.fromhex(keys_data["private_key"])
            self.key_generated_at = keys_data["generated_at"]
            
            # Reinitialize signature object
            self.sig = oqs.Signature(self.algorithm_name)
            
            return {
                "status": "success",
                "algorithm": self.algorithm_name,
                "security_level": self.security_level,
                "message": "Keys imported successfully"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def get_algorithm_info(self) -> Dict[str, any]:
        """Get information about the algorithm"""
        if self.sig is None:
            self.sig = oqs.Signature(self.algorithm_name)
        
        return {
            "algorithm": self.algorithm_name,
            "security_level": self.security_level,
            "alg_details": str(self.sig.details)
        }


def demo():
    """Run Dilithium PoC demo"""
    print("=" * 70)
    print("Dilithium Post-Quantum Signature Scheme - PoC Demo")
    print("=" * 70)
    print()
    
    # Initialize Dilithium with security level 3
    print("1. Initializing Dilithium with Security Level 3...")
    dilithium = DilithiumPoC(security_level=3)
    print(json.dumps(dilithium.get_algorithm_info(), indent=2))
    print()
    
    # Generate keypair
    print("2. Generating keypair...")
    keypair_result = dilithium.generate_keypair()
    print(json.dumps(keypair_result, indent=2))
    print()
    
    # Sign a message
    message = "Bitcoin wallet migration to post-quantum cryptography"
    print(f"3. Signing message: '{message}'")
    sign_result = dilithium.sign_message(message)
    signature_hex = sign_result.get("signature_hex")
    print(json.dumps(sign_result, indent=2))
    print()
    
    # For full verification, we need the complete signature
    # In production, store and transmit the actual signature
    print("4. PoC Summary:")
    print(f"   - Algorithm: {dilithium.algorithm_name}")
    print(f"   - Public Key Size: {keypair_result['public_key_size']} bytes")
    print(f"   - Private Key Size: {keypair_result['private_key_size']} bytes")
    print(f"   - Message: {message}")
    print(f"   - Signature Size: {sign_result['signature_size']} bytes")
    print()
    
    # Export keys
    print("5. Exporting keys to file...")
    export_result = dilithium.export_keys("poc/keys/dilithium_keys.json")
    print(json.dumps(export_result, indent=2))
    print()
    
    print("=" * 70)
    print("Dilithium PoC Demo Complete!")
    print("=" * 70)


if __name__ == "__main__":
    demo()
