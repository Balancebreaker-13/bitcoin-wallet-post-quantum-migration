"""
Unit Tests for Cryptographic Modules

Tests for ECDSA and Post-Quantum Cryptography implementations
"""

import pytest
import secrets
from src.crypto import ECDSAModule, DilithiumSigner, KyberKEM, SHA256Hash, HMACUtility, PBKDF2Utility


class TestECDSAModule:
    """
    Unit tests for ECDSA (secp256k1) module
    """
    
    @pytest.fixture
    def ecdsa(self):
        """Create ECDSA module instance"""
        return ECDSAModule()
    
    def test_ecdsa_keypair_generation(self, ecdsa):
        """Test ECDSA keypair generation"""
        private_key, public_key = ecdsa.generate_keypair()
        
        # Validate key sizes
        assert len(private_key) == 32, "Private key should be 32 bytes"
        assert len(public_key) in [33, 65], "Public key should be 33 or 65 bytes"
        
        # Keys should not be zero
        assert private_key != bytes(32), "Private key should not be all zeros"
        assert public_key != bytes(33), "Public key should not be all zeros"
    
    def test_ecdsa_multiple_keypairs_unique(self, ecdsa):
        """Test that multiple keypair generations produce different keys"""
        keys1 = ecdsa.generate_keypair()
        keys2 = ecdsa.generate_keypair()
        
        assert keys1[0] != keys2[0], "Generated private keys should be unique"
        assert keys1[1] != keys2[1], "Generated public keys should be unique"
    
    def test_ecdsa_sign_and_verify(self, ecdsa):
        """Test ECDSA signing and verification"""
        private_key, public_key = ecdsa.generate_keypair()
        message = b"Test message for signing"
        
        # Sign message
        signature = ecdsa.sign(message, private_key)
        assert isinstance(signature, bytes), "Signature should be bytes"
        assert len(signature) > 0, "Signature should not be empty"
        
        # Verify signature
        is_valid = ecdsa.verify(message, signature, public_key)
        assert is_valid, "Signature should verify correctly"
    
    def test_ecdsa_invalid_signature_rejected(self, ecdsa):
        """Test that invalid signatures are rejected"""
        private_key, public_key = ecdsa.generate_keypair()
        message = b"Original message"
        
        signature = ecdsa.sign(message, private_key)
        
        # Modify message
        tampered_message = b"Tampered message"
        
        # Verification should fail
        is_valid = ecdsa.verify(tampered_message, signature, public_key)
        assert not is_valid, "Tampered signature should not verify"
    
    def test_ecdsa_invalid_private_key_rejected(self, ecdsa):
        """Test that invalid private keys are rejected"""
        invalid_key = bytes(31)  # Too short
        message = b"Test message"
        
        with pytest.raises(ValueError):
            ecdsa.sign(message, invalid_key)


class TestDilithiumSigner:
    """
    Unit tests for Dilithium (ML-DSA) post-quantum signer
    """
    
    @pytest.fixture(params=[2, 3, 5])
    def dilithium(self, request):
        """Create Dilithium signer with different security levels"""
        return DilithiumSigner(security_level=request.param)
    
    def test_dilithium_invalid_security_level(self):
        """Test that invalid security levels are rejected"""
        with pytest.raises(ValueError):
            DilithiumSigner(security_level=4)  # Invalid level
    
    def test_dilithium_keypair_generation(self, dilithium):
        """Test Dilithium keypair generation"""
        public_key, private_key = dilithium.generate_keypair()
        
        # Validate key sizes
        expected_pub_size = dilithium.key_sizes['pub']
        expected_priv_size = dilithium.key_sizes['priv']
        
        assert len(public_key) == expected_pub_size, \
            f"Public key should be {expected_pub_size} bytes"
        assert len(private_key) == expected_priv_size, \
            f"Private key should be {expected_priv_size} bytes"
    
    def test_dilithium_sign_and_verify(self, dilithium):
        """Test Dilithium signing and verification"""
        public_key, private_key = dilithium.generate_keypair()
        message = b"Test message for PQC signing"
        
        # Sign message
        signature = dilithium.sign(message, private_key)
        
        # Validate signature size
        expected_sig_size = dilithium.key_sizes['sig']
        assert len(signature) == expected_sig_size, \
            f"Signature should be {expected_sig_size} bytes"
        
        # Verify signature
        is_valid = dilithium.verify(message, signature, public_key)
        assert is_valid, "Dilithium signature should verify correctly"
    
    def test_dilithium_tampered_signature_rejected(self, dilithium):
        """Test that tampered Dilithium signatures are rejected"""
        public_key, private_key = dilithium.generate_keypair()
        message = b"Original message"
        
        signature = dilithium.sign(message, private_key)
        
        # Tamper with signature
        tampered_sig = bytearray(signature)
        tampered_sig[100] ^= 0xFF  # Flip bits
        tampered_sig = bytes(tampered_sig)
        
        # Verification should fail
        is_valid = dilithium.verify(message, tampered_sig, public_key)
        assert not is_valid, "Tampered Dilithium signature should be rejected"
    
    def test_dilithium_invalid_private_key_size(self, dilithium):
        """Test that invalid private key sizes are rejected"""
        invalid_key = secrets.token_bytes(1000)  # Wrong size
        message = b"Test message"
        
        with pytest.raises(ValueError):
            dilithium.sign(message, invalid_key)


class TestKyberKEM:
    """
    Unit tests for Kyber (ML-KEM) key encapsulation mechanism
    """
    
    @pytest.fixture(params=[512, 768, 1024])
    def kyber(self, request):
        """Create Kyber KEM with different security levels"""
        return KyberKEM(security_level=request.param)
    
    def test_kyber_invalid_security_level(self):
        """Test that invalid security levels are rejected"""
        with pytest.raises(ValueError):
            KyberKEM(security_level=256)  # Invalid level
    
    def test_kyber_keypair_generation(self, kyber):
        """Test Kyber keypair generation"""
        public_key, private_key = kyber.generate_keypair()
        
        expected_pub_size = kyber.key_sizes['pub']
        expected_priv_size = kyber.key_sizes['priv']
        
        assert len(public_key) == expected_pub_size
        assert len(private_key) == expected_priv_size
    
    def test_kyber_encapsulation_decapsulation(self, kyber):
        """Test Kyber key encapsulation and decapsulation"""
        public_key, private_key = kyber.generate_keypair()
        
        # Encapsulate
        ciphertext, shared_secret = kyber.encapsulate(public_key)
        
        # Validate sizes
        assert len(ciphertext) == kyber.key_sizes['ct']
        assert len(shared_secret) == kyber.SHARED_SECRET_SIZE
        
        # Decapsulate
        recovered_secret = kyber.decapsulate(ciphertext, private_key)
        
        assert len(recovered_secret) == kyber.SHARED_SECRET_SIZE
        assert recovered_secret == shared_secret, \
            "Decapsulated shared secret should match original"
    
    def test_kyber_invalid_public_key_size(self, kyber):
        """Test that invalid public key sizes are rejected"""
        invalid_key = secrets.token_bytes(100)
        
        with pytest.raises(ValueError):
            kyber.encapsulate(invalid_key)
    
    def test_kyber_sign_not_supported(self, kyber):
        """Test that KEM doesn't support signing"""
        with pytest.raises(NotImplementedError):
            kyber.sign(b"message", b"key")
        
        with pytest.raises(NotImplementedError):
            kyber.verify(b"message", b"sig", b"pubkey")


class TestHashUtilities:
    """
    Unit tests for cryptographic hash functions
    """
    
    def test_sha256_hash(self):
        """Test SHA-256 hashing"""
        data = b"Test data for hashing"
        hash_result = SHA256Hash.hash(data)
        
        assert len(hash_result) == 32, "SHA-256 hash should be 32 bytes"
        assert isinstance(hash_result, bytes)
    
    def test_sha256_double_hash(self):
        """Test double SHA-256 (Bitcoin standard)"""
        data = b"Test data"
        double_hash = SHA256Hash.double_hash(data)
        
        assert len(double_hash) == 32
        assert double_hash != SHA256Hash.hash(data), \
            "Double hash should differ from single hash"
    
    def test_hmac_sha512(self):
        """Test HMAC-SHA512"""
        key = b"secret_key"
        data = b"data to authenticate"
        
        hmac_result = HMACUtility.hmac_sha512(key, data)
        
        assert len(hmac_result) == 64, "HMAC-SHA512 should be 64 bytes"
        assert isinstance(hmac_result, bytes)
    
    def test_hmac_deterministic(self):
        """Test that HMAC is deterministic"""
        key = b"key"
        data = b"data"
        
        hmac1 = HMACUtility.hmac_sha512(key, data)
        hmac2 = HMACUtility.hmac_sha512(key, data)
        
        assert hmac1 == hmac2, "HMAC should be deterministic"
    
    def test_pbkdf2_derivation(self):
        """Test PBKDF2 key derivation"""
        password = "test_password"
        salt = secrets.token_bytes(16)
        
        key = PBKDF2Utility.derive(password, salt, iterations=100000)
        
        assert len(key) == 32, "Derived key should be 32 bytes"
        assert isinstance(key, bytes)
    
    def test_pbkdf2_password_verification(self):
        """Test PBKDF2 password verification"""
        password = "correct_password"
        salt = secrets.token_bytes(16)
        
        hash_result = PBKDF2Utility.derive(password, salt, iterations=100000)
        
        # Correct password should verify
        assert PBKDF2Utility.verify(password, salt, hash_result, iterations=100000)
        
        # Wrong password should not verify
        assert not PBKDF2Utility.verify("wrong_password", salt, hash_result, iterations=100000)
    
    def test_pbkdf2_weak_password_rejected(self):
        """Test that weak passwords are rejected"""
        weak_password = "weak"
        salt = secrets.token_bytes(16)
        
        with pytest.raises(ValueError):
            PBKDF2Utility.derive(weak_password, salt, iterations=10000)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
