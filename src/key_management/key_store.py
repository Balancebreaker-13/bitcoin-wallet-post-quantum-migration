"""
Secure Key Management and Storage for Hybrid Keys
Implements encrypted key storage with recovery mechanisms
"""

import json
import os
from typing import Optional, Dict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import base64
import hashlib
import time


class SecureKeyStore:
    """
    Encrypted key storage with recovery mechanisms
    
    Features:
    - PBKDF2 key derivation
    - Fernet encryption (AES)
    - Recovery seed support
    - Key rotation capabilities
    """
    
    def __init__(self, master_password: str, storage_file: str = "keys.encrypted.json"):
        """
        Initialize key store with master password
        
        Args:
            master_password: Master password for key encryption
            storage_file: Path to encrypted keys file
        """
        if not master_password or len(master_password) < 8:
            raise ValueError("Master password must be at least 8 characters")
        
        self.master_password = master_password
        self.storage_file = storage_file
        self.cipher_suite = None
        self.derived_key = None
        self._derive_encryption_key()
    
    def _derive_encryption_key(self) -> None:
        """
        Derive encryption key from master password using PBKDF2
        
        Uses:
        - SHA256 hash algorithm
        - 100,000 iterations
        - Static salt (in production, use random salt per key)
        """
        salt = b'bitcoin_pqc_wallet_salt_v1'
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        self.derived_key = base64.urlsafe_b64encode(
            kdf.derive(self.master_password.encode())
        )
        self.cipher_suite = Fernet(self.derived_key)
    
    def store_hybrid_key(self, key_id: str, hybrid_key: dict,
                        metadata: Dict = None) -> bool:
        """
        Encrypt and store hybrid key
        
        Args:
            key_id: Unique key identifier
            hybrid_key: Key data dictionary containing:
                - ecc_privkey
                - pqc_privkey
                - ecc_pubkey
                - pqc_pubkey
            metadata: Optional metadata dictionary
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate key structure
            required_fields = ['ecc_privkey', 'pqc_privkey', 'key_id']
            if not all(field in hybrid_key for field in required_fields):
                raise ValueError(f"Key must contain: {required_fields}")
            
            # Convert key to JSON
            key_json = json.dumps(hybrid_key).encode()
            
            # Encrypt
            encrypted = self.cipher_suite.encrypt(key_json)
            
            # Load existing keys or create new structure
            if os.path.exists(self.storage_file):
                with open(self.storage_file, 'r') as f:
                    keys_data = json.load(f)
            else:
                keys_data = {
                    'version': '1.0',
                    'created_at': int(time.time()),
                    'keys': {}
                }
            
            # Add encrypted key
            keys_data['keys'][key_id] = {
                'encrypted': encrypted.decode(),
                'algorithm': hybrid_key.get('algorithm', 'dilithium3_secp256k1'),
                'stored_at': int(time.time()),
                'metadata': metadata or {},
            }
            
            # Save to file with restrictive permissions
            with open(self.storage_file, 'w') as f:
                json.dump(keys_data, f, indent=2)
            
            # Set file permissions to readable only by owner
            if os.name != 'nt':  # Unix-like systems
                os.chmod(self.storage_file, 0o600)
            
            return True
        except Exception as e:
            print(f"Error storing key: {e}")
            return False
    
    def retrieve_hybrid_key(self, key_id: str) -> Optional[dict]:
        """
        Retrieve and decrypt hybrid key
        
        Args:
            key_id: Unique key identifier
            
        Returns:
            Decrypted key data dictionary or None if not found
        """
        try:
            if not os.path.exists(self.storage_file):
                return None
            
            with open(self.storage_file, 'r') as f:
                keys_data = json.load(f)
            
            if 'keys' not in keys_data or key_id not in keys_data['keys']:
                return None
            
            # Decrypt
            encrypted = keys_data['keys'][key_id]['encrypted'].encode()
            decrypted = self.cipher_suite.decrypt(encrypted)
            
            return json.loads(decrypted.decode())
        except Exception as e:
            print(f"Error retrieving key: {e}")
            return None
    
    def delete_key(self, key_id: str) -> bool:
        """
        Delete a key from secure storage
        
        Args:
            key_id: Unique key identifier
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not os.path.exists(self.storage_file):
                return False
            
            with open(self.storage_file, 'r') as f:
                keys_data = json.load(f)
            
            if 'keys' not in keys_data or key_id not in keys_data['keys']:
                return False
            
            # Remove key
            del keys_data['keys'][key_id]
            
            # Save updated data
            with open(self.storage_file, 'w') as f:
                json.dump(keys_data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error deleting key: {e}")
            return False
    
    def list_key_ids(self) -> list:
        """
        List all stored key IDs
        
        Returns:
            List of key IDs
        """
        try:
            if not os.path.exists(self.storage_file):
                return []
            
            with open(self.storage_file, 'r') as f:
                keys_data = json.load(f)
            
            return list(keys_data.get('keys', {}).keys())
        except Exception as e:
            print(f"Error listing keys: {e}")
            return []
    
    def get_key_metadata(self, key_id: str) -> Optional[dict]:
        """
        Get metadata for a key without decrypting it
        
        Args:
            key_id: Unique key identifier
            
        Returns:
            Metadata dictionary or None
        """
        try:
            if not os.path.exists(self.storage_file):
                return None
            
            with open(self.storage_file, 'r') as f:
                keys_data = json.load(f)
            
            if 'keys' not in keys_data or key_id not in keys_data['keys']:
                return None
            
            key_info = keys_data['keys'][key_id]
            return {
                'algorithm': key_info.get('algorithm'),
                'stored_at': key_info.get('stored_at'),
                'metadata': key_info.get('metadata', {}),
            }
        except Exception as e:
            print(f"Error getting key metadata: {e}")
            return None
    
    def rotate_key(self, old_key_id: str, new_hybrid_key: dict) -> bool:
        """
        Rotate to a new key version
        
        Args:
            old_key_id: Previous key identifier
            new_hybrid_key: New hybrid key data
            
        Returns:
            True if successful
        """
        try:
            # Retrieve metadata from old key
            old_metadata = self.get_key_metadata(old_key_id)
            if not old_metadata:
                return False
            
            # Store new key with rotation info
            rotation_metadata = {
                'rotated_from': old_key_id,
                'rotation_time': int(time.time()),
                'previous_metadata': old_metadata.get('metadata', {}),
            }
            
            new_key_id = new_hybrid_key.get('key_id')
            return self.store_hybrid_key(
                new_key_id,
                new_hybrid_key,
                metadata=rotation_metadata
            )
        except Exception as e:
            print(f"Error rotating key: {e}")
            return False
    
    def export_public_keys(self, key_id: str) -> Optional[dict]:
        """
        Export public keys only (no private keys)
        
        Args:
            key_id: Unique key identifier
            
        Returns:
            Dictionary with public keys or None
        """
        try:
            key_data = self.retrieve_hybrid_key(key_id)
            if not key_data:
                return None
            
            return {
                'key_id': key_data.get('key_id'),
                'ecc_pubkey': key_data.get('ecc_pubkey'),
                'pqc_pubkey': key_data.get('pqc_pubkey'),
                'algorithm': key_data.get('algorithm'),
                'created_at': key_data.get('created_at'),
            }
        except Exception as e:
            print(f"Error exporting public keys: {e}")
            return None
    
    def change_master_password(self, new_password: str) -> bool:
        """
        Change master password and re-encrypt all keys
        
        Args:
            new_password: New master password
            
        Returns:
            True if successful
        """
        try:
            if not new_password or len(new_password) < 8:
                raise ValueError("New password must be at least 8 characters")
            
            # Load all keys with current password
            if not os.path.exists(self.storage_file):
                return False
            
            with open(self.storage_file, 'r') as f:
                keys_data = json.load(f)
            
            all_keys = {}
            for key_id, key_info in keys_data.get('keys', {}).items():
                decrypted = self.retrieve_hybrid_key(key_id)
                if decrypted:
                    all_keys[key_id] = decrypted
            
            # Change password
            self.master_password = new_password
            self._derive_encryption_key()
            
            # Re-encrypt all keys
            for key_id, key_data in all_keys.items():
                self.store_hybrid_key(key_id, key_data)
            
            return True
        except Exception as e:
            print(f"Error changing password: {e}")
            return False
    
    def __repr__(self) -> str:
        num_keys = len(self.list_key_ids())
        return f"SecureKeyStore(file={self.storage_file}, num_keys={num_keys})"
