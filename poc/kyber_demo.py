#!/usr/bin/env python3
"""
Kyber Key Encapsulation Mechanism - Proof of Concept Demo

This module demonstrates the Kyber KEM algorithm,
one of the NIST-standardized post-quantum cryptography algorithms.

Kyber provides:
- Quantum-resistant key encapsulation
- IND-CCA2 security
- Efficient shared secret generation
- High performance

Security Levels:
- Level 1: NIST Security Level 1 (AES-128 equivalent)
- Level 3: NIST Security Level 3 (SHA3-256 equivalent)
- Level 5: NIST Security Level 5 (AES-256 equivalent)
"""

import oqs
import os
import hashlib
import json
from typing import Tuple, Dict, Optional
from datetime import datetime


class KyberPoC:
    """Proof of Concept implementation for Kyber KEM"""
    
    # Supported Kyber variants
    VARIANTS = {
        512: "Kyber512",    # NIST Level 1
        768: "Kyber768",    # NIST Level 3
        1024: "Kyber1024",  # NIST Level 5
    }
    
    def __init__(self, security_level: int = 768):
        """
        Initialize Kyber PoC
        
        Args:
            security_level: 512, 768, or 1024 (default: 768)
            
        Raises:
            ValueError: If invalid security level
        """
        if security_level not in self.VARIANTS:
            raise ValueError(f"Invalid security level. Must be one of {list(self.VARIANTS.keys())}")
        
        self.security_level = security_level
        self.algorithm_name = self.VARIANTS[security_level]
        self.kem = None
        self.public_key = None
        self.secret_key = None
        self.key_generated_at = None
        
    def generate_keypair(self) -> Dict[str, any]:
        """
        Generate a new Kyber keypair
        
        Returns:
            Dictionary with public_key_hex and secret_key_hex
        """
        try:
            self.kem = oqs.KeyEncapsulation(self.algorithm_name)
            self.public_key = self.kem.generate_keyset()
            self.secret_key = self.kem.secret_key()
            self.key_generated_at = datetime.now().isoformat()
            
            return {
                "status": "success",
                "algorithm": self.algorithm_name,
                "security_level": self.security_level,
                "public_key_size": len(self.public_key),
                "secret_key_size": len(self.secret_key),
                "generated_at": self.key_generated_at,
                "public_key_hex": self.public_key.hex()[:64] + "...",  # Truncate for display
                "secret_key_hex": self.secret_key.hex()[:64] + "..."   # Truncate for display
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def encapsulate(self) -> Dict[str, any]:
        """
        Encapsulate: generate shared secret and ciphertext
        
        Returns:
            Dictionary with ciphertext, shared_secret, and metadata
        """
        if self.kem is None or self.public_key is None:
            return {
                "status": "error",
                "message": "Keypair not generated. Call generate_keypair() first."
            }
        
        try:
            # Set public key for encapsulation
            self.kem.public_key = self.public_key
            
            # Encapsulate to generate shared secret and ciphertext
            ciphertext, shared_secret = self.kem.encap_secret()
            
            return {
                "status": "success",
                "ciphertext_size": len(ciphertext),
                "shared_secret_size": len(shared_secret),
                "shared_secret_hash": hashlib.sha256(shared_secret).hexdigest(),
                "ciphertext_hex": ciphertext.hex()[:64] + "...",  # Truncate for display
                "shared_secret_hex": shared_secret.hex()[:64] + "...",  # Truncate for display
                "algorithm": self.algorithm_name,
                "timestamp": datetime.now().isoformat(),
                # Store for verification
                "_ciphertext": ciphertext.hex(),
                "_shared_secret": shared_secret.hex()
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def decapsulate(self, ciphertext_hex: str) -> Dict[str, any]:
        """
        Decapsulate: recover shared secret from ciphertext
        
        Args:
            ciphertext_hex: Ciphertext in hexadecimal format
            
        Returns:
            Dictionary with recovered shared secret and metadata
        """
        if self.kem is None or self.secret_key is None:
            return {
                "status": "error",
                "message": "Secret key not available."
            }
        
        try:
            ciphertext_bytes = bytes.fromhex(ciphertext_hex)
            
            # Decapsulate to recover shared secret
            shared_secret = self.kem.decap_secret(ciphertext_bytes)
            
            return {
                "status": "success",
                "shared_secret_size": len(shared_secret),
                "shared_secret_hash": hashlib.sha256(shared_secret).hexdigest(),
                "shared_secret_hex": shared_secret.hex()[:64] + "...",  # Truncate for display
                "algorithm": self.algorithm_name,
                "timestamp": datetime.now().isoformat(),
                # Store for verification
                "_shared_secret": shared_secret.hex()
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
        if self.public_key is None or self.secret_key is None:
            return {
                "status": "error",
                "message": "Keypair not generated."
            }
        
        try:
            keys_data = {
                "algorithm": self.algorithm_name,
                "security_level": self.security_level,
                "public_key": self.public_key.hex(),
                "secret_key": self.secret_key.hex(),  # WARNING: Store securely in production!
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
            self.secret_key = bytes.fromhex(keys_data["secret_key"])
            self.key_generated_at = keys_data["generated_at"]
            
            # Reinitialize KEM object
            self.kem = oqs.KeyEncapsulation(self.algorithm_name)
            
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
        if self.kem is None:
            self.kem = oqs.KeyEncapsulation(self.algorithm_name)
        
        return {
            "algorithm": self.algorithm_name,
            "security_level": self.security_level,
            "alg_details": str(self.kem.details)
        }


def demo():
    """Run Kyber PoC demo"""
    print("=" * 70)
    print("Kyber Key Encapsulation Mechanism - PoC Demo")
    print("=" * 70)
    print()
    
    # Initialize Kyber with security level 768
    print("1. Initializing Kyber with Security Level 768...")
    kyber = KyberPoC(security_level=768)
    print(json.dumps(kyber.get_algorithm_info(), indent=2))
    print()
    
    # Generate keypair
    print("2. Generating keypair...")
    keypair_result = kyber.generate_keypair()
    print(json.dumps(keypair_result, indent=2))
    print()
    
    # Encapsulate (Alice side)
    print("3. Encapsulating shared secret (Alice side)...")
    encap_result = kyber.encapsulate()
    print(json.dumps({k: v for k, v in encap_result.items() if k != "_ciphertext" and k != "_shared_secret"}, indent=2))
    alice_shared_secret = encap_result.get("_shared_secret")
    alice_ciphertext = encap_result.get("_ciphertext")
    print()
    
    # Decapsulate (Bob side)
    print("4. Decapsulating ciphertext to recover shared secret (Bob side)...")
    decap_result = kyber.decapsulate(alice_ciphertext)
    print(json.dumps({k: v for k, v in decap_result.items() if k != "_shared_secret"}, indent=2))
    bob_shared_secret = decap_result.get("_shared_secret")
    print()
    
    # Verify shared secrets match
    print("5. Verification:")
    secrets_match = alice_shared_secret == bob_shared_secret
    print(f"   - Shared secrets match: {secrets_match}")
    print(f"   - Alice's secret hash: {hashlib.sha256(bytes.fromhex(alice_shared_secret)).hexdigest()[:32]}...")
    print(f"   - Bob's secret hash:   {hashlib.sha256(bytes.fromhex(bob_shared_secret)).hexdigest()[:32]}...")
    print()
    
    # PoC Summary
    print("6. PoC Summary:")
    print(f"   - Algorithm: {kyber.algorithm_name}")
    print(f"   - Public Key Size: {keypair_result['public_key_size']} bytes")
    print(f"   - Secret Key Size: {keypair_result['secret_key_size']} bytes")
    print(f"   - Ciphertext Size: {encap_result['ciphertext_size']} bytes")
    print(f"   - Shared Secret Size: {encap_result['shared_secret_size']} bytes")
    print(f"   - Secrets Synchronized: {secrets_match}")
    print()
    
    # Export keys
    print("7. Exporting keys to file...")
    export_result = kyber.export_keys("poc/keys/kyber_keys.json")
    print(json.dumps(export_result, indent=2))
    print()
    
    print("=" * 70)
    print("Kyber PoC Demo Complete!")
    print("=" * 70)


if __name__ == "__main__":
    demo()
