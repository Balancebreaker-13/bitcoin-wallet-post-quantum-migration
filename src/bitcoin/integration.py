"""
Bitcoin Transaction Integration for Post-Quantum Wallets
Handles BIP compatibility and transaction encoding
"""

from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
import hashlib
import struct


@dataclass
class TransactionInput:
    """
    Bitcoin transaction input
    
    Attributes:
        previous_tx_hash: Hash of previous transaction
        previous_output_index: Index of output in previous transaction
        script_pubkey: Locking script
        sequence: Sequence number (4 bytes)
    """
    previous_tx_hash: bytes
    previous_output_index: int
    script_pubkey: bytes
    sequence: int = 0xffffffff
    
    def serialize(self) -> bytes:
        """Serialize transaction input to bytes"""
        result = self.previous_tx_hash
        result += self.previous_output_index.to_bytes(4, 'little')
        result += len(self.script_pubkey).to_bytes(1, 'little')
        result += self.script_pubkey
        result += self.sequence.to_bytes(4, 'little')
        return result


@dataclass
class TransactionOutput:
    """
    Bitcoin transaction output
    
    Attributes:
        value: Amount in satoshis
        script_pubkey: Unlocking script
    """
    value: int  # satoshis
    script_pubkey: bytes
    
    def serialize(self) -> bytes:
        """Serialize transaction output to bytes"""
        result = self.value.to_bytes(8, 'little')
        result += len(self.script_pubkey).to_bytes(1, 'little')
        result += self.script_pubkey
        return result


class BitcoinTransactionBuilder:
    """
    Build and sign Bitcoin transactions with hybrid keys
    
    Supports:
    - Legacy (P2PKH, P2SH)
    - SegWit v0 (P2WPKH, P2WSH)
    - Taproot (P2TR) with PQC compatibility
    """
    
    # Bitcoin script opcodes
    OP_DUP = 0x76
    OP_HASH160 = 0xa9
    OP_EQUALVERIFY = 0x88
    OP_CHECKSIG = 0xac
    
    def __init__(self, hybrid_wallet=None):
        """
        Initialize Bitcoin transaction builder
        
        Args:
            hybrid_wallet: HybridWallet instance for signing
        """
        self.wallet = hybrid_wallet
        self.version = 2  # Bitcoin transaction version
        self.locktime = 0
    
    def create_p2pkh_script(self, pubkey_hash: bytes) -> bytes:
        """
        Create Pay-to-Public-Key-Hash (P2PKH) script
        
        Args:
            pubkey_hash: 20-byte hash160 of public key
            
        Returns:
            Script bytes
        """
        # OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
        script = bytes([self.OP_DUP, self.OP_HASH160])
        script += bytes([len(pubkey_hash)]) + pubkey_hash
        script += bytes([self.OP_EQUALVERIFY, self.OP_CHECKSIG])
        return script
    
    def create_p2wpkh_script(self, pubkey_hash: bytes) -> bytes:
        """
        Create Pay-to-Witness-Public-Key-Hash (P2WPKH) script
        SegWit v0
        
        Args:
            pubkey_hash: 20-byte hash160 of public key
            
        Returns:
            Script bytes
        """
        # OP_0 <20-byte-hash>
        script = bytes([0x00, 0x14]) + pubkey_hash
        return script
    
    def create_p2tr_script(self, taproot_key: bytes) -> bytes:
        """
        Create Pay-to-Taproot (P2TR) script
        SegWit v1 - suitable for quantum-resistant keys
        
        Args:
            taproot_key: 32-byte taproot output key
            
        Returns:
            Script bytes
        """
        # OP_1 <32-byte-key>
        script = bytes([0x51, 0x20]) + taproot_key
        return script
    
    def create_transaction(self, inputs: List[TransactionInput],
                          outputs: List[TransactionOutput],
                          tx_type: str = "legacy") -> bytes:
        """
        Create unsigned transaction
        
        Args:
            inputs: List of transaction inputs
            outputs: List of transaction outputs
            tx_type: Transaction type ('legacy', 'segwit', 'taproot')
            
        Returns:
            Serialized transaction bytes
        """
        if not inputs or not outputs:
            raise ValueError("Transaction must have inputs and outputs")
        
        result = self.version.to_bytes(4, 'little')
        
        # Add witness marker for SegWit (0x00 0x01)
        if tx_type in ("segwit", "taproot"):
            result += bytes([0x00, 0x01])
        
        # Add inputs
        result += len(inputs).to_bytes(1, 'little')
        for tx_input in inputs:
            result += tx_input.serialize()
        
        # Add outputs
        result += len(outputs).to_bytes(1, 'little')
        for tx_output in outputs:
            result += tx_output.serialize()
        
        # Add locktime
        result += self.locktime.to_bytes(4, 'little')
        
        return result
    
    def sign_transaction(self, tx_data: bytes, key_id: str) -> bytes:
        """
        Sign transaction with hybrid key
        
        Args:
            tx_data: Unsigned transaction data
            key_id: Key identifier to use for signing
            
        Returns:
            Signed transaction bytes
        """
        if not self.wallet:
            raise RuntimeError("Wallet not initialized")
        
        # Get transaction hash for signing
        tx_hash = hashlib.sha256(hashlib.sha256(tx_data).digest()).digest()
        
        # Sign with hybrid wallet
        signature = self.wallet.sign_transaction_hybrid(tx_hash, key_id)
        
        return signature
    
    def verify_transaction_signature(self, tx_data: bytes, signature: bytes,
                                     key_id: str) -> bool:
        """
        Verify transaction signature
        
        Args:
            tx_data: Transaction data
            signature: Transaction signature
            key_id: Key identifier for verification
            
        Returns:
            True if signature is valid
        """
        if not self.wallet:
            raise RuntimeError("Wallet not initialized")
        
        pubkey = self.wallet.get_public_key(key_id)
        if not pubkey:
            return False
        
        # Get transaction hash
        tx_hash = hashlib.sha256(hashlib.sha256(tx_data).digest()).digest()
        
        # Verify signature
        return self.wallet.verify_transaction_hybrid(tx_hash, signature, pubkey)
    
    def estimate_transaction_size(self, num_inputs: int, num_outputs: int,
                                  tx_type: str = "legacy") -> int:
        """
        Estimate transaction size in bytes
        
        Args:
            num_inputs: Number of inputs
            num_outputs: Number of outputs
            tx_type: Transaction type ('legacy', 'segwit', 'taproot')
            
        Returns:
            Estimated size in bytes
        """
        size = 4  # version
        
        if tx_type in ("segwit", "taproot"):
            size += 2  # witness marker
        
        # Inputs
        size += 1  # input count
        size += num_inputs * 32  # previous tx hash
        size += num_inputs * 4   # output index
        size += num_inputs * 1   # script length
        size += num_inputs * 71  # approximate signature size
        size += num_inputs * 4   # sequence
        
        # Outputs
        size += 1  # output count
        size += num_outputs * 8  # value
        size += num_outputs * 1  # script length
        size += num_outputs * 25 # approximate script size
        
        size += 4  # locktime
        
        return size
    
    def calculate_transaction_fee(self, num_inputs: int, num_outputs: int,
                                  fee_rate: int, tx_type: str = "legacy") -> int:
        """
        Calculate transaction fee
        
        Args:
            num_inputs: Number of inputs
            num_outputs: Number of outputs
            fee_rate: Fee rate in satoshis per byte
            tx_type: Transaction type
            
        Returns:
            Fee in satoshis
        """
        tx_size = self.estimate_transaction_size(num_inputs, num_outputs, tx_type)
        return tx_size * fee_rate
    
    def broadcast_transaction(self, signed_tx: bytes) -> str:
        """
        Broadcast signed transaction to Bitcoin network
        
        Note: This is a placeholder. In production, use:
        - python-bitcoinlib
        - bitcoind RPC
        - blockchain.info API
        - Electrum protocol
        
        Args:
            signed_tx: Signed transaction bytes
            
        Returns:
            Transaction ID (TXID)
        """
        # Calculate TXID
        tx_hash = hashlib.sha256(hashlib.sha256(signed_tx).digest()).digest()
        txid = tx_hash.hex()[::-1]  # Reverse for display format
        
        # TODO: Implement actual broadcasting to Bitcoin network
        print(f"[PLACEHOLDER] Broadcasting transaction: {txid}")
        
        return txid
    
    def __repr__(self) -> str:
        return f"BitcoinTransactionBuilder(version={self.version})"
