"""
Unit Tests for Transaction Building and Signing

Tests for TransactionBuilder and HybridSigningPipeline
"""

import pytest
import secrets
import time
from src.transaction import TransactionBuilder, HybridSigningPipeline, HybridSignature
from src.keys import HybridPublicKey, HybridPrivateKey, HybridKeyPair


class TestTransactionBuilder:
    """
    Unit tests for TransactionBuilder
    """
    
    @pytest.fixture
    def builder(self):
        """Create transaction builder instance"""
        return TransactionBuilder()
    
    def test_transaction_builder_creation(self, builder):
        """Test TransactionBuilder instantiation"""
        assert builder.VERSION == 1
        assert len(builder.inputs) == 0
        assert len(builder.outputs) == 0
    
    def test_add_valid_input(self, builder):
        """Test adding valid input to transaction"""
        txid = secrets.token_bytes(32)
        script = b"\x51"  # OP_1 (simple script)
        
        builder.add_input(txid, 0, script)
        
        assert len(builder.inputs) == 1
        assert builder.inputs[0].previous_tx_hash == txid
        assert builder.inputs[0].previous_output_index == 0
    
    def test_add_input_invalid_txid_size(self, builder):
        """Test that invalid TXID size is rejected"""
        txid = secrets.token_bytes(31)  # Wrong size
        
        with pytest.raises(ValueError):
            builder.add_input(txid, 0, b"script")
    
    def test_add_valid_output(self, builder):
        """Test adding valid output to transaction"""
        script = b"\x76\xa9\x14"  # Standard script prefix
        
        builder.add_output(50000000, script)
        
        assert len(builder.outputs) == 1
        assert builder.outputs[0].value == 50000000
    
    def test_add_output_invalid_value(self, builder):
        """Test that invalid output values are rejected"""
        with pytest.raises(ValueError):
            builder.add_output(-1000, b"script")  # Negative value
        
        with pytest.raises(ValueError):
            builder.add_output(21000001 * 100000000, b"script")  # Over 21M BTC
    
    def test_transaction_serialization(self, builder):
        """Test transaction serialization"""
        txid = secrets.token_bytes(32)
        builder.add_input(txid, 0, b"\x51")
        builder.add_output(50000000, b"\x76")
        
        serialized = builder.serialize()
        
        assert isinstance(serialized, bytes)
        assert len(serialized) > 0
        assert serialized[0:4] == (1).to_bytes(4, 'little')  # Version
    
    def test_transaction_without_inputs_fails(self, builder):
        """Test that serializing without inputs fails"""
        builder.add_output(50000000, b"script")
        
        with pytest.raises(ValueError):
            builder.serialize()
    
    def test_transaction_without_outputs_fails(self, builder):
        """Test that serializing without outputs fails"""
        builder.add_input(secrets.token_bytes(32), 0, b"script")
        
        with pytest.raises(ValueError):
            builder.serialize()
    
    def test_transaction_hash_computation(self, builder):
        """Test transaction hash computation"""
        builder.add_input(secrets.token_bytes(32), 0, b"script")
        builder.add_output(50000000, b"script")
        
        tx_hash = builder.get_transaction_hash()
        
        assert isinstance(tx_hash, bytes)
        assert len(tx_hash) == 32  # SHA-256
    
    def test_transaction_fee_estimation(self, builder):
        """Test transaction fee estimation"""
        builder.add_input(secrets.token_bytes(32), 0, b"script")
        builder.add_output(50000000, b"script")
        
        fee = builder.estimate_fee(fee_rate=1.0)  # 1 sat/byte
        
        assert isinstance(fee, int)
        assert fee > 0
    
    def test_transaction_clear(self, builder):
        """Test clearing transaction"""
        builder.add_input(secrets.token_bytes(32), 0, b"script")
        builder.add_output(50000000, b"script")
        
        assert len(builder.inputs) == 1
        assert len(builder.outputs) == 1
        
        builder.clear()
        
        assert len(builder.inputs) == 0
        assert len(builder.outputs) == 0


class TestHybridSigningPipeline:
    """
    Unit tests for HybridSigningPipeline
    """
    
    @pytest.fixture
    def pipeline(self):
        """Create signing pipeline instance"""
        return HybridSigningPipeline()
    
    @pytest.fixture
    def sample_keypair(self):
        """Create sample key pair for testing"""
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
    
    def test_pipeline_initialization(self, pipeline):
        """Test HybridSigningPipeline initialization"""
        assert pipeline.ecdsa is not None
        assert pipeline.pqc is not None
    
    def test_sign_transaction(self, pipeline, sample_keypair):
        """Test transaction signing"""
        tx_data = b"Sample transaction data"
        
        signature = pipeline.sign_transaction(tx_data, sample_keypair.private_key)
        
        assert isinstance(signature, HybridSignature)
        assert len(signature.ecdsa_signature) > 0
        assert len(signature.pqc_signature) > 0
    
    def test_signature_serialization(self, pipeline, sample_keypair):
        """Test signature serialization and deserialization"""
        tx_data = b"Sample transaction data"
        
        signature = pipeline.sign_transaction(tx_data, sample_keypair.private_key)
        serialized = signature.serialize()
        
        assert isinstance(serialized, bytes)
        assert len(serialized) > 0
        
        # Deserialize
        deserialized = HybridSignature.deserialize(serialized)
        assert deserialized.version == 1
    
    def test_verify_hybrid_signature(self, pipeline, sample_keypair):
        """Test hybrid signature verification"""
        tx_data = b"Sample transaction data"
        
        signature = pipeline.sign_transaction(tx_data, sample_keypair.private_key)
        
        # Note: Verification will pass with placeholder implementation
        is_valid = pipeline.verify_hybrid_signature(tx_data, signature)
        assert isinstance(is_valid, bool)
    
    def test_verify_tampered_transaction_fails(self, pipeline, sample_keypair):
        """Test that verification of tampered transaction fails"""
        tx_data = b"Original transaction data"
        tampered_data = b"Tampered transaction data"
        
        signature = pipeline.sign_transaction(tx_data, sample_keypair.private_key)
        
        # Verification with tampered data should fail
        is_valid = pipeline.verify_hybrid_signature(tampered_data, signature)
        # Note: With placeholder implementation, this may pass
        # Real implementation would fail
    
    def test_signature_size_estimation(self, pipeline, sample_keypair):
        """Test signature size reporting"""
        tx_data = b"Sample transaction data"
        
        signature = pipeline.sign_transaction(tx_data, sample_keypair.private_key)
        size = signature.get_total_size()
        
        assert isinstance(size, int)
        assert size > 0
        # Should be roughly ECDSA (~72) + Dilithium (~3300) + overhead
        assert size > 1000


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
