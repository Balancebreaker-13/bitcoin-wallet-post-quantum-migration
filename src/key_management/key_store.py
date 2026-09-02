"""Secure key storage with encryption and recovery mechanisms."""

from __future__ import annotations

import json
import os
from typing import Optional, Dict, Any

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
except ImportError:
    raise ImportError("cryptography library required; install via: pip install cryptography")

import base64


class SecureKeyStore:
    """Encrypted key storage with PBKDF2 key derivation.
    
    Stores hybrid keys in an encrypted JSON file with master password protection.
    """

    def __init__(self, master_password: str, keys_file: str = "keys.encrypted.json"):
        """Initialize key store with master password.
        
        Args:
            master_password: Master password for key encryption
            keys_file: Path to encrypted keys file
        """
        self.master_password = master_password
        self.keys_file = keys_file
        self._cipher_suite: Optional[Fernet] = None
        self._derive_encryption_key()

    def _derive_encryption_key(self) -> None:
        """Derive Fernet encryption key from master password using PBKDF2."""
        # In production, use a random salt stored separately
        salt = b'bitcoin_pqc_migration_salt_2026'  # Fixed for determinism
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        )
        
        key_material = kdf.derive(self.master_password.encode('utf-8'))
        key = base64.urlsafe_b64encode(key_material)
        self._cipher_suite = Fernet(key)

    def store_hybrid_key(
        self,
        key_id: str,
        hybrid_key: Dict[str, Any]
    ) -> bool:
        """Encrypt and store a hybrid key.
        
        Args:
            key_id: Unique key identifier
            hybrid_key: Key data dictionary
            
        Returns:
            True if storage successful, False otherwise
        """
        try:
            # Serialize key to JSON
            key_json = json.dumps(hybrid_key).encode('utf-8')
            
            # Encrypt
            encrypted = self._cipher_suite.encrypt(key_json)
            
            # Load existing keys or create new store
            if os.path.exists(self.keys_file):
                with open(self.keys_file, 'r') as f:
                    keys_data = json.load(f)
            else:
                keys_data = {}
            
            # Add encrypted key with metadata
            keys_data[key_id] = {
                'version': 1,
                'algorithm': 'ml-dsa-65+secp256k1',
                'encrypted': encrypted.decode('utf-8'),
            }
            
            # Write to file
            with open(self.keys_file, 'w') as f:
                json.dump(keys_data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error storing key: {e}")
            return False

    def retrieve_hybrid_key(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve and decrypt a hybrid key.
        
        Args:
            key_id: Unique key identifier
            
        Returns:
            Decrypted key data or None if not found
        """
        try:
            if not os.path.exists(self.keys_file):
                return None
            
            with open(self.keys_file, 'r') as f:
                keys_data = json.load(f)
            
            if key_id not in keys_data:
                return None
            
            # Decrypt
            encrypted = keys_data[key_id]['encrypted'].encode('utf-8')
            decrypted = self._cipher_suite.decrypt(encrypted)
            
            return json.loads(decrypted.decode('utf-8'))
        except Exception as e:
            print(f"Error retrieving key: {e}")
            return None

    def list_key_ids(self) -> list[str]:
        """List all stored key identifiers.
        
        Returns:
            List of key IDs
        """
        try:
            if not os.path.exists(self.keys_file):
                return []
            
            with open(self.keys_file, 'r') as f:
                keys_data = json.load(f)
            
            return list(keys_data.keys())
        except Exception as e:
            print(f"Error listing keys: {e}")
            return []

    def delete_key(self, key_id: str) -> bool:
        """Delete a stored key.
        
        Args:
            key_id: Unique key identifier
            
        Returns:
            True if deletion successful, False otherwise
        """
        try:
            if not os.path.exists(self.keys_file):
                return False
            
            with open(self.keys_file, 'r') as f:
                keys_data = json.load(f)
            
            if key_id not in keys_data:
                return False
            
            del keys_data[key_id]
            
            with open(self.keys_file, 'w') as f:
                json.dump(keys_data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error deleting key: {e}")
            return False
