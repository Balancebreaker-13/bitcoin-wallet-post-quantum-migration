"""End-to-end wallet, storage, and transaction integration tests."""

import pytest

from src.bitcoin.integration import (
    BitcoinTransactionBuilder,
    TransactionInput,
    TransactionOutput,
)
from src.hybrid import HybridPrivateKey, HybridPublicKey, HybridWallet
from src.key_management import SecureKeyStore
from src.pqc.core import backend_available


@pytest.mark.skipif(not backend_available(), reason="liboqs is not available")
def test_wallet_transaction_and_encrypted_restore_flow(tmp_path):
    wallet = HybridWallet()
    public_key = wallet.generate_hybrid_keypair()
    builder = BitcoinTransactionBuilder(wallet)
    transaction = builder.create_transaction(
        [
            TransactionInput(
                previous_tx_hash=bytes.fromhex("11" * 32),
                previous_output_index=0,
                script_pubkey=b"\x51",
            )
        ],
        [TransactionOutput(100_000, b"\x51")],
    )

    signature = builder.sign_transaction(transaction, public_key.key_id)
    assert builder.verify_transaction_signature(
        transaction,
        signature,
        public_key.key_id,
    )

    private_key = wallet.get_private_key(public_key.key_id)
    assert private_key is not None
    store = SecureKeyStore("integration password", str(tmp_path / "wallet.json"))
    assert store.store_hybrid_keypair(public_key, private_key)
    stored = store.retrieve_hybrid_key(public_key.key_id)
    assert stored is not None

    restored_public = HybridPublicKey.from_dict(stored)
    restored_private = HybridPrivateKey.from_dict(stored)
    restored_wallet = HybridWallet()
    restored_wallet.import_keypair(restored_public, restored_private)
    restored_builder = BitcoinTransactionBuilder(restored_wallet)
    restored_signature = restored_builder.sign_transaction(
        transaction,
        restored_public.key_id,
    )
    assert restored_builder.verify_transaction_signature(
        transaction,
        restored_signature,
        restored_public.key_id,
    )