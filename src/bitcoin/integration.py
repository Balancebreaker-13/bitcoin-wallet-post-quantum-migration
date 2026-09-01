"""Deterministic Bitcoin transaction serialization and hybrid signing helpers.

This module handles transaction bytes and signature verification locally. A
hybrid ML-DSA signature is not currently a Bitcoin consensus script, so the
module does not pretend to broadcast it to the network. Network submission is
an explicit integration boundary and fails closed until a node/RPC adapter is
configured.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import List, Optional, Sequence


MAX_MONEY = 21_000_000 * 100_000_000
MAX_UINT32 = 0xFFFFFFFF
MAX_UINT64 = 0xFFFFFFFFFFFFFFFF


def encode_compact_size(value: int) -> bytes:
    """Encode a Bitcoin CompactSize integer."""
    if not isinstance(value, int) or value < 0:
        raise ValueError("CompactSize value must be a non-negative integer")
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= MAX_UINT32:
        return b"\xfe" + value.to_bytes(4, "little")
    if value <= MAX_UINT64:
        return b"\xff" + value.to_bytes(8, "little")
    raise ValueError("CompactSize value is too large")


def _bytes(value: bytes, name: str, *, allow_empty: bool = True) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    value = bytes(value)
    if not allow_empty and not value:
        raise ValueError(f"{name} must not be empty")
    return value


def _length_prefixed(value: bytes, name: str) -> bytes:
    value = _bytes(value, name)
    return encode_compact_size(len(value)) + value


@dataclass(frozen=True)
class TransactionInput:
    """A Bitcoin transaction input without its unlocking script."""

    previous_tx_hash: bytes
    previous_output_index: int
    script_pubkey: bytes
    sequence: int = MAX_UINT32
    witness: Sequence[bytes] = ()

    def __post_init__(self) -> None:
        tx_hash = _bytes(self.previous_tx_hash, "previous_tx_hash")
        script = _bytes(self.script_pubkey, "script_pubkey")
        if len(tx_hash) != 32:
            raise ValueError("previous_tx_hash must be exactly 32 bytes")
        if not 0 <= self.previous_output_index <= MAX_UINT32:
            raise ValueError("previous_output_index must fit in uint32")
        if not 0 <= self.sequence <= MAX_UINT32:
            raise ValueError("sequence must fit in uint32")
        if len(script) > MAX_UINT64:
            raise ValueError("script_pubkey is too large")
        for item in self.witness:
            if len(_bytes(item, "witness item")) > MAX_UINT64:
                raise ValueError("witness item is too large")

    def serialize(self) -> bytes:
        """Serialize the non-witness portion of the input."""
        return (
            bytes(self.previous_tx_hash)
            + self.previous_output_index.to_bytes(4, "little")
            + _length_prefixed(self.script_pubkey, "script_pubkey")
            + self.sequence.to_bytes(4, "little")
        )

    def serialize_witness(self) -> bytes:
        """Serialize this input's SegWit witness stack."""
        result = encode_compact_size(len(self.witness))
        for item in self.witness:
            result += _length_prefixed(item, "witness item")
        return result


@dataclass(frozen=True)
class TransactionOutput:
    """A Bitcoin transaction output."""

    value: int
    script_pubkey: bytes

    def __post_init__(self) -> None:
        script = _bytes(self.script_pubkey, "script_pubkey")
        if not 0 <= self.value <= MAX_MONEY:
            raise ValueError("value must be between 0 and the Bitcoin money limit")
        if len(script) > MAX_UINT64:
            raise ValueError("script_pubkey is too large")

    def serialize(self) -> bytes:
        return (
            self.value.to_bytes(8, "little")
            + _length_prefixed(self.script_pubkey, "script_pubkey")
        )


class BitcoinTransactionBuilder:
    """Build deterministic legacy or SegWit transaction bytes."""

    OP_DUP = 0x76
    OP_HASH160 = 0xA9
    OP_EQUALVERIFY = 0x88
    OP_CHECKSIG = 0xAC
    SUPPORTED_TYPES = frozenset(("legacy", "segwit", "taproot"))

    def __init__(self, hybrid_wallet=None):
        self.wallet = hybrid_wallet
        self.version = 2
        self.locktime = 0

    @staticmethod
    def _validate_script_hash(value: bytes, expected_size: int, name: str) -> bytes:
        value = _bytes(value, name)
        if len(value) != expected_size:
            raise ValueError(f"{name} must be exactly {expected_size} bytes")
        return value

    def create_p2pkh_script(self, pubkey_hash: bytes) -> bytes:
        pubkey_hash = self._validate_script_hash(pubkey_hash, 20, "pubkey_hash")
        return bytes(
            [self.OP_DUP, self.OP_HASH160, len(pubkey_hash)]
        ) + pubkey_hash + bytes([self.OP_EQUALVERIFY, self.OP_CHECKSIG])

    def create_p2wpkh_script(self, pubkey_hash: bytes) -> bytes:
        pubkey_hash = self._validate_script_hash(pubkey_hash, 20, "pubkey_hash")
        return b"\x00\x14" + pubkey_hash

    def create_p2tr_script(self, taproot_key: bytes) -> bytes:
        taproot_key = self._validate_script_hash(taproot_key, 32, "taproot_key")
        return b"\x51\x20" + taproot_key

    def create_transaction(
        self,
        inputs: List[TransactionInput],
        outputs: List[TransactionOutput],
        tx_type: str = "legacy",
    ) -> bytes:
        """Serialize an unsigned transaction using Bitcoin wire encoding."""
        if tx_type not in self.SUPPORTED_TYPES:
            raise ValueError(f"Unsupported transaction type: {tx_type}")
        if not inputs or not outputs:
            raise ValueError("Transaction must have inputs and outputs")
        if not 0 <= self.version <= MAX_UINT32:
            raise ValueError("version must fit in uint32")
        if not 0 <= self.locktime <= MAX_UINT32:
            raise ValueError("locktime must fit in uint32")

        result = self.version.to_bytes(4, "little")
        if tx_type in ("segwit", "taproot"):
            result += b"\x00\x01"
        result += encode_compact_size(len(inputs))
        result += b"".join(tx_input.serialize() for tx_input in inputs)
        result += encode_compact_size(len(outputs))
        result += b"".join(tx_output.serialize() for tx_output in outputs)
        if tx_type in ("segwit", "taproot"):
            result += b"".join(tx_input.serialize_witness() for tx_input in inputs)
        return result + self.locktime.to_bytes(4, "little")

    @staticmethod
    def transaction_digest(tx_data: bytes) -> bytes:
        """Return the conventional double-SHA256 transaction digest."""
        tx_data = _bytes(tx_data, "tx_data", allow_empty=False)
        return hashlib.sha256(hashlib.sha256(tx_data).digest()).digest()

    def sign_transaction(self, tx_data: bytes, key_id: str) -> bytes:
        """Return a versioned hybrid signature over the transaction digest."""
        if self.wallet is None:
            raise RuntimeError("Wallet not initialized")
        return self.wallet.sign_transaction_hybrid(
            self.transaction_digest(tx_data),
            key_id,
        )

    def verify_transaction_signature(
        self,
        tx_data: bytes,
        signature: bytes,
        key_id: str,
    ) -> bool:
        """Verify a hybrid signature over the transaction digest."""
        if self.wallet is None:
            raise RuntimeError("Wallet not initialized")
        public_key = self.wallet.get_public_key(key_id)
        if public_key is None:
            return False
        return self.wallet.verify_transaction_hybrid(
            self.transaction_digest(tx_data),
            signature,
            public_key,
        )

    def estimate_transaction_size(
        self,
        num_inputs: int,
        num_outputs: int,
        tx_type: str = "legacy",
    ) -> int:
        """Estimate the unsigned skeleton size with standard 25-byte outputs."""
        if not isinstance(num_inputs, int) or num_inputs < 1:
            raise ValueError("num_inputs must be a positive integer")
        if not isinstance(num_outputs, int) or num_outputs < 1:
            raise ValueError("num_outputs must be a positive integer")
        if tx_type not in self.SUPPORTED_TYPES:
            raise ValueError(f"Unsupported transaction type: {tx_type}")
        # A typical P2PKH script is used only as an estimate; callers with
        # exact scripts should serialize the transaction and use len().
        size = 4 + len(encode_compact_size(num_inputs))
        size += num_inputs * (32 + 4 + 1 + 25 + 4)
        size += len(encode_compact_size(num_outputs))
        size += num_outputs * (8 + 1 + 25)
        if tx_type in ("segwit", "taproot"):
            size += 2 + num_inputs
        return size + 4

    def calculate_transaction_fee(
        self,
        num_inputs: int,
        num_outputs: int,
        fee_rate: int,
        tx_type: str = "legacy",
    ) -> int:
        if not isinstance(fee_rate, int) or fee_rate < 0:
            raise ValueError("fee_rate must be a non-negative integer")
        return self.estimate_transaction_size(
            num_inputs,
            num_outputs,
            tx_type,
        ) * fee_rate

    @staticmethod
    def transaction_id(transaction: bytes) -> str:
        """Return the display-form TXID for serialized transaction bytes."""
        digest = BitcoinTransactionBuilder.transaction_digest(transaction)
        return digest[::-1].hex()

    def broadcast_transaction(self, signed_tx: bytes) -> str:
        """Reject network submission until a configured node adapter exists."""
        _bytes(signed_tx, "signed_tx", allow_empty=False)
        raise NotImplementedError(
            "Bitcoin broadcasting requires an explicit node/RPC integration; "
            "hybrid signatures are not broadcast as consensus scripts"
        )

    def __repr__(self) -> str:
        return f"BitcoinTransactionBuilder(version={self.version})"