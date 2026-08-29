"""
Bitcoin Transaction Builder

Builds and manages Bitcoin transactions with support for:
- Input/output selection
- Fee calculation
- Change address handling
- Script creation
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple
import hashlib


@dataclass
class TransactionInput:
    """
    Bitcoin transaction input
    """
    previous_tx_hash: bytes                # 32 bytes (TXID)
    previous_output_index: int             # Output index (0-4294967295)
    script_pubkey: bytes                   # Locking script
    sequence: int = 0xffffffff             # Sequence number
    witness_data: Optional[bytes] = None   # SegWit witness data


@dataclass
class TransactionOutput:
    """
    Bitcoin transaction output
    """
    value: int                             # Amount in satoshis
    script_pubkey: bytes                   # Locking script


class TransactionBuilder:
    """
    Build Bitcoin transactions with hybrid key support
    
    Supports:
    - Legacy (P2PKH)
    - SegWit (P2WPKH)
    - Taproot (P2TR) with hybrid keys
    """
    
    VERSION = 1                            # Bitcoin transaction version
    LOCKTIME = 0                           # No locktime by default
    
    def __init__(self):
        """
        Initialize transaction builder
        """
        self.inputs: List[TransactionInput] = []
        self.outputs: List[TransactionOutput] = []
    
    def add_input(
        self,
        txid: bytes,
        output_index: int,
        script_pubkey: bytes,
        sequence: int = 0xffffffff
    ) -> None:
        """
        Add input to transaction
        
        Args:
            txid: Previous transaction hash (32 bytes)
            output_index: Output index to spend
            script_pubkey: Locking script
            sequence: Sequence number (default: 0xffffffff)
        """
        if len(txid) != 32:
            raise ValueError("TXID must be 32 bytes")
        
        input_obj = TransactionInput(
            previous_tx_hash=txid,
            previous_output_index=output_index,
            script_pubkey=script_pubkey,
            sequence=sequence
        )
        self.inputs.append(input_obj)
    
    def add_output(
        self,
        value: int,
        script_pubkey: bytes
    ) -> None:
        """
        Add output to transaction
        
        Args:
            value: Output value in satoshis
            script_pubkey: Locking script
        
        Raises:
            ValueError: If value is invalid
        """
        if value < 0 or value > 21_000_000 * 100_000_000:  # Max 21M BTC
            raise ValueError(f"Invalid output value: {value}")
        
        output_obj = TransactionOutput(
            value=value,
            script_pubkey=script_pubkey
        )
        self.outputs.append(output_obj)
    
    def serialize(self) -> bytes:
        """
        Serialize transaction to bytes
        
        Format:
        [4 bytes version][input count][inputs][output count][outputs][4 bytes locktime]
        
        Returns:
            bytes: Serialized transaction
        
        Raises:
            ValueError: If transaction is invalid
        """
        if not self.inputs or not self.outputs:
            raise ValueError("Transaction must have at least 1 input and 1 output")
        
        data = self.VERSION.to_bytes(4, 'little')
        
        # Serialize inputs
        data += len(self.inputs).to_bytes(1, 'little')  # Simplified varint
        for inp in self.inputs:
            data += inp.previous_tx_hash
            data += inp.previous_output_index.to_bytes(4, 'little')
            data += len(inp.script_pubkey).to_bytes(1, 'little')
            data += inp.script_pubkey
            data += inp.sequence.to_bytes(4, 'little')
        
        # Serialize outputs
        data += len(self.outputs).to_bytes(1, 'little')
        for out in self.outputs:
            data += out.value.to_bytes(8, 'little')
            data += len(out.script_pubkey).to_bytes(1, 'little')
            data += out.script_pubkey
        
        # Locktime
        data += self.LOCKTIME.to_bytes(4, 'little')
        
        return data
    
    def get_transaction_hash(self) -> bytes:
        """
        Compute transaction hash (TXID)
        
        Uses double SHA-256
        
        Returns:
            bytes: 32-byte transaction hash
        """
        tx_data = self.serialize()
        return hashlib.sha256(
            hashlib.sha256(tx_data).digest()
        ).digest()
    
    def estimate_size(self) -> int:
        """
        Estimate final transaction size in bytes
        
        Returns:
            int: Estimated size with hybrid signatures
        """
        base_size = len(self.serialize())
        
        # Add hybrid signature sizes per input
        # ECDSA: 72 bytes + overhead
        # Dilithium: 3300 bytes (average level 3)
        # Total per input: ~3400 bytes
        hybrid_overhead = len(self.inputs) * 3400
        
        return base_size + hybrid_overhead
    
    def estimate_fee(
        self,
        fee_rate: float  # satoshis per byte
    ) -> int:
        """
        Estimate transaction fee
        
        Args:
            fee_rate: Fee rate in satoshis per byte
        
        Returns:
            int: Estimated fee in satoshis
        """
        size = self.estimate_size()
        return int(size * fee_rate)
    
    def clear(self) -> None:
        """
        Clear all inputs and outputs
        """
        self.inputs.clear()
        self.outputs.clear()
