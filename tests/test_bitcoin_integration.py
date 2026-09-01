"""Tests for deterministic transaction encoding and hybrid signing."""

import pytest

from src.bitcoin.integration import (
    BitcoinTransactionBuilder,
    TransactionInput,
    TransactionOutput,
    encode_compact_size,
)
from src.hybrid import HybridWallet
from src.pqc.core import backend_available


def _input(script=b"\x51", witness=()):
    return TransactionInput(
        previous_tx_hash=bytes(range(32)),
        previous_output_index=1,
        script_pubkey=script,
        witness=witness,
    )


def test_compact_size_uses_bitcoin_wire_encoding():
    assert encode_compact_size(252) == b"\xfc"
    assert encode_compact_size(253) == b"\xfd\xfd\x00"
    assert encode_compact_size(65_536) == b"\xfe\x00\x00\x01\x00"


def test_transaction_serialization_uses_compact_size_and_locktime():
    builder = BitcoinTransactionBuilder()
    transaction = builder.create_transaction(
        [_input()],
        [TransactionOutput(1_000, b"\x51")],
    )

    assert transaction[:4] == b"\x02\x00\x00\x00"
    assert transaction[4] == 1
    assert transaction[-4:] == b"\x00\x00\x00\x00"
    assert len(transaction) == 4 + 1 + (32 + 4 + 1 + 1 + 4) + 1 + 10 + 4


def test_segwit_serialization_includes_marker_flag_and_witness_stack():
    builder = BitcoinTransactionBuilder()
    transaction = builder.create_transaction(
        [_input(witness=(b"witness",))],
        [TransactionOutput(2_000, b"\x51")],
        tx_type="segwit",
    )

    assert transaction[:6] == b"\x02\x00\x00\x00\x00\x01"
    assert b"\x01\x07witness" in transaction


def test_script_helpers_validate_hash_lengths():
    builder = BitcoinTransactionBuilder()
    assert builder.create_p2pkh_script(bytes(20)) == b"\x76\xa9\x14" + bytes(20) + b"\x88\xac"
    assert builder.create_p2wpkh_script(bytes(20)) == b"\x00\x14" + bytes(20)
    assert builder.create_p2tr_script(bytes(32)) == b"\x51\x20" + bytes(32)

    with pytest.raises(ValueError):
        builder.create_p2pkh_script(bytes(19))
    with pytest.raises(ValueError):
        builder.create_p2tr_script(bytes(31))


def test_transaction_signing_verifies_and_rejects_tampering():
    if not backend_available():
        pytest.skip("liboqs is not available")
    wallet = HybridWallet()
    public_key = wallet.generate_hybrid_keypair()
    builder = BitcoinTransactionBuilder(wallet)
    transaction = builder.create_transaction(
        [_input()],
        [TransactionOutput(50_000, b"\x51")],
    )

    signature = builder.sign_transaction(transaction, public_key.key_id)
    assert builder.verify_transaction_signature(
        transaction,
        signature,
        public_key.key_id,
    )
    assert not builder.verify_transaction_signature(
        transaction + b"\x00",
        signature,
        public_key.key_id,
    )
    assert BitcoinTransactionBuilder.transaction_id(transaction)


def test_broadcasting_is_explicitly_disabled_without_node_adapter():
    with pytest.raises(NotImplementedError):
        BitcoinTransactionBuilder().broadcast_transaction(b"signed")