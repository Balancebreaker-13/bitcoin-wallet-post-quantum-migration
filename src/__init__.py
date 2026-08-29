"""
Bitcoin Wallet Post-Quantum Cryptography Migration

A hybrid Bitcoin wallet implementation supporting both ECDSA and post-quantum
cryptographic algorithms for quantum-resistant digital signatures.

Version: 1.0-alpha
Author: Balancebreaker-13
License: Apache 2.0
"""

__version__ = "1.0.0-alpha"
__author__ = "Balancebreaker-13"
__license__ = "Apache 2.0"

from .wallet import HybridBitcoinWallet
from .crypto import ECDSAModule, PQCModule
from .keys import HybridPublicKey, HybridPrivateKey, SecureKeyStore
from .transaction import TransactionBuilder, HybridSigningPipeline

__all__ = [
    'HybridBitcoinWallet',
    'ECDSAModule',
    'PQCModule',
    'HybridPublicKey',
    'HybridPrivateKey',
    'SecureKeyStore',
    'TransactionBuilder',
    'HybridSigningPipeline',
]
