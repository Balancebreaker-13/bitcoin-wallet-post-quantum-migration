"""Bitcoin Wallet Post-Quantum Cryptography Migration."""

__version__ = "1.0.0-alpha"
__author__ = "Balancebreaker-13"
__license__ = "Apache 2.0"

from .crypto import (
    DilithiumSigner,
    ECDSAModule,
    KyberKEM,
    PQCModule,
)
from .hybrid import (
    HybridPrivateKey,
    HybridPublicKey,
    HybridSignature,
    HybridWallet,
)

__all__ = [
    'ECDSAModule',
    'PQCModule',
    'DilithiumSigner',
    'KyberKEM',
    'HybridPrivateKey',
    'HybridPublicKey',
    'HybridSignature',
    'HybridWallet',
]
