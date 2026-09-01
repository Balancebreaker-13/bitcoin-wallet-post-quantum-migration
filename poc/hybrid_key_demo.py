#!/usr/bin/env python3
"""
Hybrid ECC + PQC Key Generation - Proof of Concept Demo

This module demonstrates hybrid cryptography that combines:
1. Traditional ECC (secp256k1) - for Bitcoin compatibility
2. Post-Quantum Cryptography (Dilithium) - for quantum resistance

Benefits:
- Backward compatibility with existing Bitcoin infrastructure
- Quantum-resistant signatures for future security
- Transitional approach to post-quantum cryptography
"""

import hashlib
import json
import os
from datetime import datetime
from typing import Dict, Tuple, Optional
from dataclasses import dataclass, asdict

# Import our PoC modules
from dilithium_demo import DilithiumPoC
from kyber_demo import KyberPoC


@dataclass
class HybridPublicKey:
    """Hybrid public key combining ECC and PQC"""
    ecc_pubkey_hex: str
    pqc_pubkey_hex: str
    key_id: str
    created_at: str
    security_level_ecc: str
    security_level_pqc: int


@dataclass
class HybridPrivateKey:
    """Hybrid private key combining ECC and PQC"""
    ecc_privkey_hex: str
    pqc_privkey_hex: str
    key_id: str
    created_at: str
    security_level_ecc: str
    security_level_pqc: int


class HybridKeyGenerator:
    """Generates and manages hybrid ECC+PQC keypairs"""
    
    def __init__(self, pqc_security_level: int = 3):
        """
        Initialize hybrid key generator
        
        Args:
            pqc_security_level: 2, 3, or 5 for Dilithium
        """
        self.pqc_security_level = pqc_security_level
        self.dilithium = DilithiumPoC(security_level=pqc_security_level)
        self.kyber = KyberPoC(security_level=768)  # Fixed at level 3
        
        self.hybrid_pubkey = None
        self.hybrid_privkey = None
        self.generated_at = None
    
    def generate_hybrid_keypair(self) -> Dict[str, any]:
        """
        Generate hybrid ECC+PQC keypair
        
        Returns:
            Dictionary with hybrid public key and metadata
        """
        try:
            self.generated_at = datetime.now().isoformat()
            
            # Generate Dilithium keypair (PQC signature scheme)
            dilithium_result = self.dilithium.generate_keypair()
            if dilithium_result["status"] != "success":
                return {
                    "status": "error",
                    "message": f"Dilithium generation failed: {dilithium_result.get('message')}"
                }
            
            dilithium_pubkey = self.dilithium.public_key.hex()
            dilithium_privkey = self.dilithium.private_key.hex()
            
            # Generate Kyber keypair (PQC KEM)
            kyber_result = self.kyber.generate_keypair()
            if kyber_result["status"] != "success":
                return {
                    "status": "error",
                    "message": f"Kyber generation failed: {kyber_result.get('message')}"
                }
            
            kyber_pubkey = self.kyber.public_key.hex()
            kyber_privkey = self.kyber.secret_key.hex()
            
            # For this PoC, we'll simulate ECC with a hash-based representation
            # In production, use a real ECC library like ecdsa or cryptography
            combined_key = (dilithium_pubkey + kyber_pubkey).encode()
            ecc_pubkey = hashlib.sha256(combined_key).hexdigest()
            ecc_privkey = hashlib.sha256((dilithium_privkey + kyber_privkey).encode()).hexdigest()
            
            # Create unique key ID
            key_id = hashlib.sha256((dilithium_pubkey + kyber_pubkey).encode()).hexdigest()[:16]
            
            # Create hybrid public key
            self.hybrid_pubkey = HybridPublicKey(
                ecc_pubkey_hex=ecc_pubkey,
                pqc_pubkey_hex=dilithium_pubkey,
                key_id=key_id,
                created_at=self.generated_at,
                security_level_ecc="secp256k1",
                security_level_pqc=self.pqc_security_level
            )
            
            # Create hybrid private key
            self.hybrid_privkey = HybridPrivateKey(
                ecc_privkey_hex=ecc_privkey,
                pqc_privkey_hex=dilithium_privkey,
                key_id=key_id,
                created_at=self.generated_at,
                security_level_ecc="secp256k1",
                security_level_pqc=self.pqc_security_level
            )
            
            return {
                "status": "success",
                "key_id": key_id,
                "created_at": self.generated_at,
                "hybrid_public_key": asdict(self.hybrid_pubkey),
                "summary": {
                    "ecc_pubkey_size": len(ecc_pubkey),
                    "pqc_pubkey_size": len(dilithium_pubkey),
                    "kyber_pubkey_size": len(kyber_pubkey),
                    "security_level_ecc": "secp256k1",
                    "security_level_pqc": f"Dilithium{self.pqc_security_level}",
                    "total_pubkey_size": len(ecc_pubkey) + len(dilithium_pubkey) + len(kyber_pubkey)
                }
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def get_public_key(self) -> Optional[HybridPublicKey]:
        """Get the hybrid public key"""
        return self.hybrid_pubkey
    
    def sign_transaction_hybrid(self, transaction_data: str) -> Dict[str, any]:
        """
        Sign transaction with hybrid signature
        
        Args:
            transaction_data: Transaction data to sign
            
        Returns:
            Dictionary with hybrid signature and metadata
        """
        if self.dilithium.private_key is None:
            return {
                "status": "error",
                "message": "Keypair not generated"
            }
        
        try:
            # Sign with Dilithium (PQC)
            sign_result = self.dilithium.sign_message(transaction_data)
            if sign_result["status"] != "success":
                return sign_result
            
            # In production, also sign with ECC
            # For this PoC, we simulate ECC signature
            ecc_sig = hashlib.sha256(transaction_data.encode() + self.hybrid_privkey.ecc_privkey.encode()).hexdigest()
            
            # Combine signatures
            # Format: [version:1][ecc_sig_len:2][ecc_sig][pqc_sig_len:2][pqc_sig]
            combined_sig = "01"  # Version 1
            combined_sig += format(len(ecc_sig) // 2, '04x')  # ECC sig length
            combined_sig += ecc_sig
            
            # Store full PQC signature for the combined signature
            # In production, we'd serialize this properly
            combined_sig += format(len(sign_result.get("signature_hex", "")) // 2, '04x')
            combined_sig += sign_result.get("signature_hex", "")
            
            return {
                "status": "success",
                "transaction_hash": hashlib.sha256(transaction_data.encode()).hexdigest(),
                "ecc_signature": ecc_sig[:64] + "...",
                "pqc_signature": sign_result.get("signature_hex", "")[:64] + "...",
                "combined_signature": combined_sig[:64] + "...",
                "combined_signature_size": len(combined_sig) // 2,
                "key_id": self.hybrid_pubkey.key_id if self.hybrid_pubkey else None,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def export_hybrid_keys(self, filepath: str) -> Dict[str, any]:
        """
        Export hybrid keys to file
        
        Args:
            filepath: Path to save keys
            
        Returns:
            Status dictionary
        """
        if self.hybrid_pubkey is None or self.hybrid_privkey is None:
            return {
                "status": "error",
                "message": "Hybrid keypair not generated"
            }
        
        try:
            keys_data = {
                "algorithm": "Hybrid ECC+PQC",
                "public_key": asdict(self.hybrid_pubkey),
                "private_key": asdict(self.hybrid_privkey),
                "generated_at": self.generated_at,
                "exported_at": datetime.now().isoformat(),
                "warning": "Store private keys securely! Use encryption in production!"
            }
            
            os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
            
            with open(filepath, 'w') as f:
                json.dump(keys_data, f, indent=2)
            
            return {
                "status": "success",
                "filepath": filepath,
                "message": "Hybrid keys exported successfully"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def import_hybrid_keys(self, filepath: str) -> Dict[str, any]:
        """
        Import hybrid keys from file
        
        Args:
            filepath: Path to keys file
            
        Returns:
            Status dictionary
        """
        try:
            with open(filepath, 'r') as f:
                keys_data = json.load(f)
            
            pub_data = keys_data["public_key"]
            priv_data = keys_data["private_key"]
            
            self.hybrid_pubkey = HybridPublicKey(**pub_data)
            self.hybrid_privkey = HybridPrivateKey(**priv_data)
            self.generated_at = keys_data["generated_at"]
            
            return {
                "status": "success",
                "key_id": self.hybrid_pubkey.key_id,
                "message": "Hybrid keys imported successfully"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }


def demo():
    """Run Hybrid Key Generation PoC demo"""
    print("=" * 80)
    print("Hybrid ECC + Post-Quantum Cryptography - Key Generation PoC Demo")
    print("=" * 80)
    print()
    
    # Initialize hybrid key generator
    print("1. Initializing Hybrid Key Generator...")
    hybrid_gen = HybridKeyGenerator(pqc_security_level=3)
    print("   ✓ Generator initialized with Dilithium3 + Kyber768")
    print()
    
    # Generate hybrid keypair
    print("2. Generating Hybrid Keypair...")
    keypair_result = hybrid_gen.generate_hybrid_keypair()
    
    if keypair_result["status"] == "success":
        print("   ✓ Hybrid keypair generated successfully")
        print(f"   - Key ID: {keypair_result['key_id']}")
        print(f"   - Created at: {keypair_result['created_at']}")
        print()
        print("   Key Summary:")
        summary = keypair_result.get("summary", {})
        for key, value in summary.items():
            print(f"   - {key}: {value}")
        print()
    else:
        print(f"   ✗ Error: {keypair_result.get('message')}")
        return
    
    # Get public key
    print("3. Retrieving Public Key...")
    pubkey = hybrid_gen.get_public_key()
    if pubkey:
        print(f"   ✓ Public key retrieved")
        print(f"   - Key ID: {pubkey.key_id}")
        print(f"   - ECC Security: {pubkey.security_level_ecc}")
        print(f"   - PQC Security: Dilithium{pubkey.security_level_pqc}")
        print()
    
    # Sign a transaction
    print("4. Signing Transaction with Hybrid Signature...")
    tx_data = "Bitcoin wallet migration to post-quantum cryptography"
    sign_result = hybrid_gen.sign_transaction_hybrid(tx_data)
    
    if sign_result["status"] == "success":
        print("   ✓ Transaction signed successfully")
        print(f"   - Transaction: {tx_data}")
        print(f"   - TX Hash: {sign_result['transaction_hash'][:32]}...")
        print(f"   - Hybrid Signature Size: {sign_result['combined_signature_size']} bytes")
        print(f"   - Key ID: {sign_result['key_id']}")
        print()
    else:
        print(f"   ✗ Error: {sign_result.get('message')}")
    
    # Export hybrid keys
    print("5. Exporting Hybrid Keys...")
    export_result = hybrid_gen.export_hybrid_keys("poc/keys/hybrid_keys.json")
    
    if export_result["status"] == "success":
        print(f"   ✓ Keys exported to: {export_result['filepath']}")
        print()
    else:
        print(f"   ✗ Error: {export_result.get('message')}")
        print()
    
    # Architecture information
    print("6. Hybrid Architecture Summary:")
    print("   " + "-" * 76)
    print("   Component       | Purpose                    | Quantum Resistant")
    print("   " + "-" * 76)
    print("   ECC (secp256k1) | Bitcoin compatibility      | No")
    print("   Dilithium       | Post-quantum signatures    | Yes")
    print("   Kyber           | Post-quantum key encap.    | Yes")
    print("   " + "-" * 76)
    print()
    
    print("7. Migration Path:")
    print("   Phase 1: Deploy hybrid wallets (ECC + PQC)")
    print("   Phase 2: Gradually shift validation to PQC")
    print("   Phase 3: Full migration to post-quantum cryptography")
    print()
    
    print("=" * 80)
    print("Hybrid Key Generation PoC Demo Complete!")
    print("=" * 80)


if __name__ == "__main__":
    demo()
