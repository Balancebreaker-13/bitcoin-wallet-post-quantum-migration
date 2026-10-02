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
from .bitcoin import (
    BitcoinCoreRpcClient,
    BitcoinRpcError,
    BitcoinTransactionBuilder,
    TaprootOutputKey,
    TransactionInput,
    TransactionOutput,
    schnorr_sign,
    schnorr_verify,
    taproot_keypath_sign,
    taproot_control_block,
    taproot_scriptpath_sign,
    taproot_scriptpath_witness,
    taproot_sighash,
    tapbranch_hash,
    tapleaf_hash,
    taproot_tweak_private_key,
    taproot_tweak_pubkey,
    verify_taproot_control_block,
    xonly_public_key,
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
    'BitcoinTransactionBuilder',
    'BitcoinCoreRpcClient',
    'BitcoinRpcError',
    'TaprootOutputKey',
    'TransactionInput',
    'TransactionOutput',
    'schnorr_sign',
    'schnorr_verify',
    'taproot_keypath_sign',
    'taproot_control_block',
    'taproot_scriptpath_sign',
    'taproot_scriptpath_witness',
    'taproot_sighash',
    'tapbranch_hash',
    'tapleaf_hash',
    'taproot_tweak_private_key',
    'taproot_tweak_pubkey',
    'verify_taproot_control_block',
    'xonly_public_key',
]
