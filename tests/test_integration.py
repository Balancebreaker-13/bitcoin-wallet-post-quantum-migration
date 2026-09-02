"""End-to-end integration tests for hybrid wallet workflows."""

import pytest
from src.hybrid import HybridWallet, HybridPublicKey
from src.bitcoin.integration import (
    BitcoinTransactionBuilder,
    TransactionInput,
    TransactionOutput,
)
from src.key_management import SecureKeyStore
from src.pqc.core import backend_available


class TestWalletCreationWorkflow:
    """Test complete wallet creation and key generation workflow."""

    def test_create_wallet_and_generate_keypair(self):
        """Test wallet creation and hybrid keypair generation."""
        wallet = HybridWallet()
        public_key = wallet.generate_hybrid_keypair()
        private_key = wallet.get_private_key(public_key.key_id)

        assert public_key is not None
        assert private_key is not None
        assert public_key.key_id == private_key.key_id
        assert len(public_key.ecc_pubkey) == 33
        assert len(public_key.pqc_pubkey) > 1000
        assert len(private_key.ecc_privkey) == 32
        assert len(private_key.pqc_privkey) > 2000

    def test_generate_multiple_keypairs(self):
        """Test generating multiple keypairs in one wallet."""
        wallet = HybridWallet()
        keys = []

        for _ in range(5):
            public_key = wallet.generate_hybrid_keypair()
            keys.append(public_key)

        # All keys should be unique
        key_ids = [k.key_id for k in keys]
        assert len(set(key_ids)) == 5

        # All keys should be retrievable
        for key in keys:
            retrieved = wallet.get_public_key(key.key_id)
            assert retrieved == key

    @pytest.mark.skipif(not backend_available(), reason="liboqs not available")
    def test_key_serialization_and_restoration(self):
        """Test serializing and restoring keys."""
        wallet = HybridWallet()
        public_key = wallet.generate_hybrid_keypair()
        private_key = wallet.get_private_key(public_key.key_id)

        # Serialize
        pub_dict = public_key.to_dict()
        priv_dict = private_key.to_dict()

        # Restore
        restored_pub = HybridPublicKey.from_dict(pub_dict)
        restored_priv = type(private_key).from_dict(priv_dict)

        assert restored_pub == public_key
        assert restored_priv == private_key


class TestTransactionSigningWorkflow:
    """Test transaction signing and verification workflow."""

    @pytest.mark.skipif(not backend_available(), reason="liboqs not available")
    def test_sign_and_verify_transaction(self):
        """Test signing a transaction and verifying the signature."""
        wallet = HybridWallet()
        builder = BitcoinTransactionBuilder(wallet)
        public_key = wallet.generate_hybrid_keypair()

        # Create transaction
        tx_bytes = builder.create_transaction(
            [
                TransactionInput(
                    previous_tx_hash=bytes(32),
                    previous_output_index=0,
                    script_pubkey=b"\x51",
                )
            ],
            [TransactionOutput(value=50_000, script_pubkey=b"\x51")],
        )

        # Sign transaction
        signature = builder.sign_transaction(tx_bytes, public_key.key_id)
        assert len(signature) > 3000  # Hybrid signature is large

        # Verify signature
        assert builder.verify_transaction_signature(
            tx_bytes, signature, public_key.key_id
        )

    @pytest.mark.skipif(not backend_available(), reason="liboqs not available")
    def test_sign_multiple_transactions_with_same_key(self):
        """Test signing multiple transactions with the same key."""
        wallet = HybridWallet()
        builder = BitcoinTransactionBuilder(wallet)
        public_key = wallet.generate_hybrid_keypair()

        # Create and sign multiple transactions
        for i in range(5):
            tx_bytes = builder.create_transaction(
                [
                    TransactionInput(
                        previous_tx_hash=bytes(32),
                        previous_output_index=i,
                        script_pubkey=b"\x51",
                    )
                ],
                [TransactionOutput(value=10_000 + i * 1000, script_pubkey=b"\x51")],
            )

            signature = builder.sign_transaction(tx_bytes, public_key.key_id)
            assert builder.verify_transaction_signature(
                tx_bytes, signature, public_key.key_id
            )

    @pytest.mark.skipif(not backend_available(), reason="liboqs not available")
    def test_signature_tamper_detection(self):
        """Test that tampered signatures are rejected."""
        wallet = HybridWallet()
        builder = BitcoinTransactionBuilder(wallet)
        public_key = wallet.generate_hybrid_keypair()

        tx_bytes = builder.create_transaction(
            [
                TransactionInput(
                    previous_tx_hash=bytes(32),
                    previous_output_index=0,
                    script_pubkey=b"\x51",
                )
            ],
            [TransactionOutput(value=50_000, script_pubkey=b"\x51")],
        )

        signature = builder.sign_transaction(tx_bytes, public_key.key_id)

        # Tamper with signature
        tampered_sig = bytearray(signature)
        tampered_sig[100] ^= 0xFF  # Flip bits
        tampered_sig = bytes(tampered_sig)

        # Should fail verification
        assert not builder.verify_transaction_signature(
            tx_bytes, tampered_sig, public_key.key_id
        )


class TestKeyStorageWorkflow:
    """Test key storage and retrieval workflow."""

    def test_store_and_retrieve_keys(self, tmp_path):
        """Test storing and retrieving keys from encrypted storage."""
        wallet = HybridWallet()
        key_file = tmp_path / "keys.encrypted.json"
        key_store = SecureKeyStore(
            master_password="test-password", keys_file=str(key_file)
        )

        # Generate and store key
        public_key = wallet.generate_hybrid_keypair()
        private_key = wallet.get_private_key(public_key.key_id)

        key_data = {
            "public": public_key.to_dict(),
            "private": private_key.to_dict(),
        }

        assert key_store.store_hybrid_key(public_key.key_id, key_data)

        # Retrieve key
        retrieved = key_store.retrieve_hybrid_key(public_key.key_id)
        assert retrieved is not None
        assert retrieved["public"] == key_data["public"]
        assert retrieved["private"] == key_data["private"]

    def test_store_multiple_keys_and_list(self, tmp_path):
        """Test storing multiple keys and listing them."""
        wallet = HybridWallet()
        key_file = tmp_path / "keys.encrypted.json"
        key_store = SecureKeyStore(
            master_password="test-password", keys_file=str(key_file)
        )

        # Generate and store multiple keys
        stored_ids = []
        for i in range(3):
            public_key = wallet.generate_hybrid_keypair()
            private_key = wallet.get_private_key(public_key.key_id)

            key_data = {
                "public": public_key.to_dict(),
                "private": private_key.to_dict(),
            }
            key_store.store_hybrid_key(public_key.key_id, key_data)
            stored_ids.append(public_key.key_id)

        # List all keys
        listed_ids = key_store.list_key_ids()
        assert len(listed_ids) == 3
        assert set(listed_ids) == set(stored_ids)

    def test_delete_key_from_storage(self, tmp_path):
        """Test deleting a key from storage."""
        wallet = HybridWallet()
        key_file = tmp_path / "keys.encrypted.json"
        key_store = SecureKeyStore(
            master_password="test-password", keys_file=str(key_file)
        )

        # Store key
        public_key = wallet.generate_hybrid_keypair()
        private_key = wallet.get_private_key(public_key.key_id)

        key_data = {
            "public": public_key.to_dict(),
            "private": private_key.to_dict(),
        }
        key_store.store_hybrid_key(public_key.key_id, key_data)

        # Verify key exists
        assert key_store.retrieve_hybrid_key(public_key.key_id) is not None

        # Delete key
        assert key_store.delete_key(public_key.key_id)

        # Verify key is gone
        assert key_store.retrieve_hybrid_key(public_key.key_id) is None


class TestMultipleWalletIntegration:
    """Test integration between multiple wallet instances."""

    @pytest.mark.skipif(not backend_available(), reason="liboqs not available")
    def test_cross_wallet_signature_verification(self):
        """Test that signatures from one wallet can be verified by another."""
        # Wallet A generates keypair
        wallet_a = HybridWallet()
        pub_key_a = wallet_a.generate_hybrid_keypair()

        # Wallet A signs transaction
        tx_bytes = b"transaction data"
        sig_a = wallet_a.sign_transaction_hybrid(tx_bytes, pub_key_a.key_id)

        # Wallet B verifies signature
        wallet_b = HybridWallet()
        is_valid = wallet_b.verify_transaction_hybrid(tx_bytes, sig_a, pub_key_a)
        assert is_valid

    @pytest.mark.skipif(not backend_available(), reason="liboqs not available")
    def test_key_sharing_between_wallets(self):
        """Test sharing public keys between wallet instances."""
        wallet_a = HybridWallet()
        wallet_b = HybridWallet()

        # Wallet A creates key
        pub_key_a = wallet_a.generate_hybrid_keypair()
        pub_key_dict = pub_key_a.to_dict()

        # Wallet B imports key
        imported_key = HybridPublicKey.from_dict(pub_key_dict)
        assert imported_key == pub_key_a

        # Both can work with the same key
        tx_bytes = b"test transaction"
        sig = wallet_a.sign_transaction_hybrid(tx_bytes, pub_key_a.key_id)
        assert wallet_b.verify_transaction_hybrid(tx_bytes, sig, imported_key)
