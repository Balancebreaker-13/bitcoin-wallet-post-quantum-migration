"""
Unit Tests for Hybrid Key Management

Tests for HybridPublicKey, HybridPrivateKey, and SecureKeyStore
"""

import pytest
import secrets
import time
import json
import os
import shutil
from src.keys import HybridPublicKey, HybridPrivateKey, HybridKeyPair, SecureKeyStore


class TestHybridPublicKey:
    """
    Unit tests for HybridPublicKey
    """
    
    @pytest.fixture
    def sample_public_key(self):
        """Create a sample hybrid public key"""
        return HybridPublicKey(
            ecdsa_pubkey=secrets.token_bytes(33),
            pqc_algorithm="ML-DSA-3",
            pqc_pubkey=secrets.token_bytes(1952),
            key_id="a1b2c3d4e5f6g7h8",
            derivation_path="m/44'/0'/0'/hybrid/0",
            created_at=int(time.time()),
            version=1,
        )
    
    def test_hybrid_public_key_creation(self, sample_public_key):
        """Test HybridPublicKey instantiation"""
        assert sample_public_key.key_id == "a1b2c3d4e5f6g7h8"
        assert sample_public_key.version == 1
        assert len(sample_public_key.ecdsa_pubkey) == 33
    
    def test_hybrid_public_key_invalid_ecdsa_size(self):
        """Test that invalid ECDSA key sizes are rejected"""
        with pytest.raises(ValueError):
            HybridPublicKey(
                ecdsa_pubkey=secrets.token_bytes(32),  # Wrong size
                pqc_algorithm="ML-DSA-3",
                pqc_pubkey=secrets.token_bytes(1952),
                key_id="a1b2c3d4e5f6g7h8",
                derivation_path="m/44'/0'/0'/hybrid/0",
                created_at=int(time.time()),
            )
    
    def test_hybrid_public_key_invalid_pqc_size(self):
        """Test that invalid PQC key sizes are rejected"""
        with pytest.raises(ValueError):
            HybridPublicKey(
                ecdsa_pubkey=secrets.token_bytes(33),
                pqc_algorithm="ML-DSA-3",
                pqc_pubkey=secrets.token_bytes(100),  # Too small
                key_id="a1b2c3d4e5f6g7h8",
                derivation_path="m/44'/0'/0'/hybrid/0",
                created_at=int(time.time()),
            )
    
    def test_hybrid_public_key_serialization(self, sample_public_key):
        """Test HybridPublicKey serialization to dictionary"""
        key_dict = sample_public_key.to_dict()
        
        assert isinstance(key_dict, dict)
        assert key_dict['key_id'] == "a1b2c3d4e5f6g7h8"
        assert key_dict['pqc_algorithm'] == "ML-DSA-3"
    
    def test_hybrid_public_key_json_roundtrip(self, sample_public_key):
        """Test JSON serialization and deserialization"""
        json_str = sample_public_key.to_json()
        assert isinstance(json_str, str)
        
        # Parse and verify it's valid JSON
        parsed = json.loads(json_str)
        assert parsed['key_id'] == "a1b2c3d4e5f6g7h8"
        
        # Reconstruct from JSON
        restored_key = HybridPublicKey.from_json(json_str)
        assert restored_key.key_id == sample_public_key.key_id
    
    def test_hybrid_public_key_address_generation(self, sample_public_key):
        """Test Bitcoin address generation from public key"""
        # Legacy address
        legacy_addr = sample_public_key.get_address("legacy")
        assert legacy_addr.startswith("1")
        
        # Hybrid address (Taproot)
        hybrid_addr = sample_public_key.get_address("hybrid")
        assert hybrid_addr.startswith("bc1p")
        
        # SegWit address
        segwit_addr = sample_public_key.get_address()
        assert segwit_addr.startswith("bc1q")
    
    def test_hybrid_public_key_fingerprint(self, sample_public_key):
        """Test key fingerprint generation"""
        fingerprint = sample_public_key.fingerprint()
        assert len(fingerprint) == 8
        assert fingerprint == "a1b2c3d4"


class TestHybridPrivateKey:
    """
    Unit tests for HybridPrivateKey
    """
    
    @pytest.fixture
    def sample_keypair(self):
        """Create sample public and private keys"""
        public_key = HybridPublicKey(
            ecdsa_pubkey=secrets.token_bytes(33),
            pqc_algorithm="ML-DSA-3",
            pqc_pubkey=secrets.token_bytes(1952),
            key_id="a1b2c3d4e5f6g7h8",
            derivation_path="m/44'/0'/0'/hybrid/0",
            created_at=int(time.time()),
        )
        
        private_key = HybridPrivateKey(
            ecdsa_privkey=secrets.token_bytes(32),
            pqc_privkey=secrets.token_bytes(4000),
            public_key=public_key,
            key_id="a1b2c3d4e5f6g7h8",
            created_at=int(time.time()),
        )
        
        return public_key, private_key
    
    def test_hybrid_private_key_creation(self, sample_keypair):
        """Test HybridPrivateKey instantiation"""
        _, private_key = sample_keypair
        
        assert private_key.use_count == 0
        assert private_key.last_used is None
        assert len(private_key.ecdsa_privkey) == 32
    
    def test_hybrid_private_key_usage_tracking(self, sample_keypair):
        """Test usage tracking"""
        _, private_key = sample_keypair
        
        initial_time = int(time.time())
        private_key.mark_used()
        
        assert private_key.use_count == 1
        assert private_key.last_used >= initial_time
        
        private_key.mark_used()
        assert private_key.use_count == 2
    
    def test_hybrid_private_key_mismatch_rejected(self):
        """Test that mismatched key_ids are rejected"""
        public_key = HybridPublicKey(
            ecdsa_pubkey=secrets.token_bytes(33),
            pqc_algorithm="ML-DSA-3",
            pqc_pubkey=secrets.token_bytes(1952),
            key_id="a1b2c3d4e5f6g7h8",
            derivation_path="m/44'/0'/0'/hybrid/0",
            created_at=int(time.time()),
        )
        
        with pytest.raises(ValueError):
            HybridPrivateKey(
                ecdsa_privkey=secrets.token_bytes(32),
                pqc_privkey=secrets.token_bytes(4000),
                public_key=public_key,
                key_id="different_id_xyz",  # Doesn't match public_key.key_id
                created_at=int(time.time()),
            )


class TestSecureKeyStore:
    """
    Unit tests for SecureKeyStore
    """
    
    @pytest.fixture
    def key_store(self, tmp_path):
        """Create temporary key store for testing"""
        store_path = str(tmp_path / "keys")
        store = SecureKeyStore(storage_path=store_path)
        yield store
        # Cleanup
        if os.path.exists(store_path):
            shutil.rmtree(store_path)
    
    @pytest.fixture
    def sample_keypair(self):
        """Create sample key pair"""
        public_key = HybridPublicKey(
            ecdsa_pubkey=secrets.token_bytes(33),
            pqc_algorithm="ML-DSA-3",
            pqc_pubkey=secrets.token_bytes(1952),
            key_id="test_key_12345678",
            derivation_path="m/44'/0'/0'/hybrid/0",
            created_at=int(time.time()),
        )
        
        private_key = HybridPrivateKey(
            ecdsa_privkey=secrets.token_bytes(32),
            pqc_privkey=secrets.token_bytes(4000),
            public_key=public_key,
            key_id="test_key_12345678",
            created_at=int(time.time()),
        )
        
        return HybridKeyPair(public_key, private_key)
    
    def test_key_store_setup(self, key_store):
        """Test key store initialization"""
        master_password = "secure_password_123"
        salt = key_store.setup(master_password)
        
        assert isinstance(salt, bytes)
        assert len(salt) == SecureKeyStore.DEFAULT_SALT_LEN
        assert key_store.cipher_suite is not None
    
    def test_key_store_weak_password_rejected(self, key_store):
        """Test that weak passwords are rejected"""
        with pytest.raises(ValueError):
            key_store.setup("weak")  # Too short
    
    def test_key_store_encrypt_decrypt(self, key_store, sample_keypair):
        """Test key encryption and decryption"""
        master_password = "secure_password_123"
        key_store.setup(master_password)
        
        # Store key
        stored = key_store.store_hybrid_key(sample_keypair, master_password)
        assert stored is True
        
        # Retrieve key
        retrieved = key_store.retrieve_hybrid_key(
            sample_keypair.get_key_id(),
            master_password
        )
        
        assert retrieved is not None
        assert retrieved.get_key_id() == sample_keypair.get_key_id()
    
    def test_key_store_wrong_password_rejected(self, key_store, sample_keypair):
        """Test that wrong password is rejected"""
        key_store.setup("correct_password_123")
        key_store.store_hybrid_key(sample_keypair, "correct_password_123")
        
        # Try with wrong password
        retrieved = key_store.retrieve_hybrid_key(
            sample_keypair.get_key_id(),
            "wrong_password_456"
        )
        
        assert retrieved is None
    
    def test_key_store_list_keys(self, key_store, sample_keypair):
        """Test listing stored keys"""
        master_password = "secure_password_123"
        key_store.setup(master_password)
        
        # Initially empty
        assert len(key_store.list_keys()) == 0
        
        # Store key
        key_store.store_hybrid_key(sample_keypair, master_password)
        
        # Should appear in list
        keys = key_store.list_keys()
        assert len(keys) == 1
        assert sample_keypair.get_key_id() in keys
    
    def test_key_store_delete_key(self, key_store, sample_keypair):
        """Test key deletion"""
        master_password = "secure_password_123"
        key_store.setup(master_password)
        
        # Store and verify
        key_store.store_hybrid_key(sample_keypair, master_password)
        assert len(key_store.list_keys()) == 1
        
        # Delete
        deleted = key_store.delete_hybrid_key(sample_keypair.get_key_id())
        assert deleted is True
        assert len(key_store.list_keys()) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
