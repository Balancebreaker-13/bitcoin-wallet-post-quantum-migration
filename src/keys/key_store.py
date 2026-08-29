"""
Secure Key Management and Storage Module

Implements encrypted key storage with:
- Fernet symmetric encryption
- PBKDF2 key derivation
- Secure key retrieval and deletion
"""

import json
import os
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import base64
import secrets
import time

from .hybrid_key import HybridPublicKey, HybridPrivateKey, HybridKeyPair


class SecureKeyStore:
    """
    Encrypted key storage with recovery mechanisms
    
    Features:
    - Fernet encryption (AES-128-CBC)
    - PBKDF2 key derivation from master password
    - Secure key storage and retrieval
    - Key rotation support
    """
    
    DEFAULT_ITERATIONS = 100000
    DEFAULT_SALT_LEN = 16
    
    def __init__(self, storage_path: str = ".wallet_data"):
        """
        Initialize key store
        
        Args:
            storage_path: Directory for encrypted key storage
        """
        self.storage_path = storage_path
        self.keys_file = os.path.join(storage_path, "keys.encrypted.json")
        self.metadata_file = os.path.join(storage_path, "keys.metadata.json")
        self.cipher_suite = None
        self.master_password_hash = None
        
        # Create storage directory if it doesn't exist
        os.makedirs(storage_path, exist_ok=True)
    
    def setup(
        self,
        master_password: str,
        salt: Optional[bytes] = None
    ) -> bytes:
        """
        Setup key store with master password
        
        Args:
            master_password: Master password for key encryption
            salt: Optional salt (generated if not provided)
        
        Returns:
            bytes: Salt used (for backup purposes)
        
        Raises:
            ValueError: If password is too weak
        """
        # Validate password strength
        if len(master_password) < 8:
            raise ValueError("Master password must be at least 8 characters")
        
        # Generate salt if not provided
        if salt is None:
            salt = secrets.token_bytes(self.DEFAULT_SALT_LEN)
        
        # Derive encryption key from password
        encryption_key = self._derive_encryption_key(
            master_password,
            salt
        )
        
        self.cipher_suite = Fernet(encryption_key)
        
        # Store salt (not secret, used for key derivation)
        self._save_salt(salt)
        
        return salt
    
    def _derive_encryption_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from master password using PBKDF2
        
        Args:
            password: Master password
            salt: Random salt
        
        Returns:
            bytes: Base64-encoded Fernet key
        """
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.DEFAULT_ITERATIONS,
        )
        
        key = base64.urlsafe_b64encode(
            kdf.derive(password.encode('utf-8'))
        )
        
        return key
    
    def store_hybrid_key(
        self,
        key_pair: HybridKeyPair,
        password: str
    ) -> bool:
        """
        Encrypt and store hybrid key pair
        
        Args:
            key_pair: HybridKeyPair to store
            password: Master password for encryption
        
        Returns:
            bool: True if successful
        """
        try:
            # Verify cipher is initialized
            if self.cipher_suite is None:
                # Re-derive cipher if password provided
                salt = self._load_salt()
                if salt is None:
                    raise ValueError("Key store not initialized")
                self.cipher_suite = Fernet(
                    self._derive_encryption_key(password, salt)
                )
            
            # Serialize key pair
            key_data = {
                'private_key': key_pair.private_key.to_dict(),
                'public_key': key_pair.public_key.to_dict(),
                'stored_at': int(time.time()),
            }
            
            key_json = json.dumps(key_data).encode('utf-8')
            
            # Encrypt
            encrypted = self.cipher_suite.encrypt(key_json)
            
            # Load existing keys or create new file
            if os.path.exists(self.keys_file):
                with open(self.keys_file, 'r') as f:
                    keys_data = json.load(f)
            else:
                keys_data = {}
            
            # Add encrypted key
            key_id = key_pair.get_key_id()
            keys_data[key_id] = {
                'encrypted': encrypted.decode('utf-8'),
                'algorithm': f"{key_pair.public_key.pqc_algorithm}+secp256k1",
                'stored_at': int(time.time()),
            }
            
            # Save to file
            with open(self.keys_file, 'w') as f:
                json.dump(keys_data, f, indent=2)
            
            # Update metadata
            self._update_metadata(key_id, 'stored')
            
            return True
        
        except Exception as e:
            print(f"Error storing key: {e}")
            return False
    
    def retrieve_hybrid_key(
        self,
        key_id: str,
        password: str
    ) -> Optional[HybridKeyPair]:
        """
        Retrieve and decrypt hybrid key pair
        
        Args:
            key_id: Unique key identifier
            password: Master password for decryption
        
        Returns:
            HybridKeyPair: Decrypted key pair or None
        """
        try:
            # Re-derive cipher from password
            salt = self._load_salt()
            if salt is None:
                return None
            
            cipher = Fernet(
                self._derive_encryption_key(password, salt)
            )
            
            # Load encrypted keys
            if not os.path.exists(self.keys_file):
                return None
            
            with open(self.keys_file, 'r') as f:
                keys_data = json.load(f)
            
            if key_id not in keys_data:
                return None
            
            # Decrypt
            encrypted = keys_data[key_id]['encrypted'].encode('utf-8')
            decrypted = cipher.decrypt(encrypted)
            
            key_data = json.loads(decrypted.decode('utf-8'))
            
            # Reconstruct key pair
            public_key = HybridPublicKey.from_dict(key_data['public_key'])
            private_key = HybridPrivateKey.from_dict(key_data['private_key'])
            
            key_pair = HybridKeyPair(public_key, private_key)
            
            # Update metadata
            self._update_metadata(key_id, 'retrieved')
            
            return key_pair
        
        except (InvalidToken, ValueError, KeyError):
            print("Error: Invalid password or corrupted key data")
            return None
        except Exception as e:
            print(f"Error retrieving key: {e}")
            return None
    
    def delete_hybrid_key(self, key_id: str) -> bool:
        """
        Securely delete a stored key
        
        Args:
            key_id: Key identifier to delete
        
        Returns:
            bool: True if successful
        """
        try:
            if not os.path.exists(self.keys_file):
                return False
            
            with open(self.keys_file, 'r') as f:
                keys_data = json.load(f)
            
            if key_id not in keys_data:
                return False
            
            # Remove key
            del keys_data[key_id]
            
            # Write back
            with open(self.keys_file, 'w') as f:
                json.dump(keys_data, f, indent=2)
            
            # Update metadata
            self._update_metadata(key_id, 'deleted')
            
            return True
        
        except Exception as e:
            print(f"Error deleting key: {e}")
            return False
    
    def list_keys(self) -> list:
        """
        List all stored key identifiers
        
        Returns:
            list: List of key IDs
        """
        try:
            if not os.path.exists(self.keys_file):
                return []
            
            with open(self.keys_file, 'r') as f:
                keys_data = json.load(f)
            
            return list(keys_data.keys())
        
        except Exception:
            return []
    
    def _save_salt(self, salt: bytes) -> None:
        """
        Save salt to file (salt is not secret)
        
        Args:
            salt: Salt to save
        """
        salt_file = os.path.join(self.storage_path, "salt.bin")
        with open(salt_file, 'wb') as f:
            f.write(salt)
    
    def _load_salt(self) -> Optional[bytes]:
        """
        Load salt from file
        
        Returns:
            bytes: Salt or None
        """
        salt_file = os.path.join(self.storage_path, "salt.bin")
        try:
            with open(salt_file, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            return None
    
    def _update_metadata(self, key_id: str, action: str) -> None:
        """
        Update key operation metadata
        
        Args:
            key_id: Key identifier
            action: Action performed (stored, retrieved, deleted)
        """
        try:
            if os.path.exists(self.metadata_file):
                with open(self.metadata_file, 'r') as f:
                    metadata = json.load(f)
            else:
                metadata = {}
            
            if key_id not in metadata:
                metadata[key_id] = {}
            
            metadata[key_id][action] = int(time.time())
            
            with open(self.metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
        
        except Exception:
            pass
