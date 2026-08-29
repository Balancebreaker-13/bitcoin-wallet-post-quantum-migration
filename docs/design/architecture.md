# Hybrid Bitcoin Wallet Architecture

## System Overview

This document outlines the complete architecture for a post-quantum cryptography-enabled Bitcoin wallet.

## 1. High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    USER INTERFACE LAYER                  │
│          (CLI / Web / Mobile Wallet Application)         │
└────────────────┬────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────┐
│              WALLET MANAGEMENT LAYER                     │
│  ┌──────────────────────────────────────────────────┐   │
│  │ • Seed/Mnemonic Management (BIP39)               │   │
│  │ • HD Wallet (BIP32/44) - Hybrid paths            │   │
│  │ • Account Management                             │   │
│  │ • Address Book & Labels                          │   │
│  └──────────────────────────────────────────────────┘   │
└────────────────┬────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────┐
│            TRANSACTION MANAGEMENT LAYER                  │
│  ┌───────────────────────────────────────────��──────┐   │
│  │ Transaction Builder                              │   │
│  │  ├─ Input Selection (UTXO Management)           │   │
│  │  ├─ Output Creation                             │   │
│  │  └─ Fee Calculation                             │   │
│  │                                                   │   │
│  │ Transaction Signing                              │   │
│  │  ├─ ECDSA Signing (Legacy)                      │   │
│  │  ├─ Dilithium PQC Signing                       │   │
│  │  └─ Signature Combination                       │   │
│  │                                                   │   │
│  │ Transaction Verification                         │   │
│  │  ├─ Dual Signature Verification                 │   │
│  │  └─ Script Validation                           │   │
│  └──────────────────────────────────────────────────┘   │
└────────────────┬────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────┐
│         CRYPTOGRAPHIC CORE LAYER                        │
│  ┌──────────────────────────────────────────────────┐   │
│  │ ECDSA Module (secp256k1)                         │   │
│  │  ├─ Key Generation                              │   │
│  │  ├─ ECDSA Signing                               │   │
│  │  └─ Signature Verification                      │   │
│  │                                                   │   │
│  │ Post-Quantum Cryptography Module                │   │
│  │  ├─ Dilithium (ML-DSA)                          │   │
│  │  │  ├─ Key Generation                           │   │
│  │  │  ├─ Signing                                  │   │
│  │  │  └─ Verification                             │   │
│  │  │                                               │   │
│  │  └─ Kyber (ML-KEM)                              │   │
│  │     ├─ Key Encapsulation                        │   │
│  │     ├─ Decapsulation                            │   │
│  │     └─ Shared Secret Derivation                 │   │
│  │                                                   │   │
│  │ Cryptographic Utilities                          │   │
│  │  ├─ SHA256 Hashing                              │   │
│  │  ├─ HMAC-SHA512 (Key Derivation)                │   │
│  │  ├─ PBKDF2 (Password Hashing)                   │   │
│  │  └─ Random Number Generation                    │   │
│  └──────────────────────────────────────────────────┘   │
└────────────────┬────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────┐
│          KEY MANAGEMENT & STORAGE LAYER                  │
│  ┌──────────────────────────────────────────────────┐   │
│  │ Secure Key Store                                 │   │
│  │  ├─ Encrypted Key Storage (Fernet)              │   │
│  │  ├─ Hardware Wallet Support (Future)            │   │
│  │  └─ Key Rotation Mechanisms                     │   │
│  │                                                   │   │
│  │ Recovery & Backup                                │   │
│  │  ├─ BIP39 Seed Phrases                          │   │
│  │  ├─ PQC Seed Generation                         │   │
│  │  ├─ Encrypted Backups                           │   │
│  │  └─ Recovery Procedures                         │   │
│  └──────────────────────────────────────────────────┘   │
└────────────────┬────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────┐
│           BITCOIN NETWORK LAYER                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │ Bitcoin Node Interface                           │   │
│  │  ├─ Full Node Connection (Bitcoin Core)         │   │
│  │  ├─ SPV (Simplified Payment Verification)       │   │
│  │  └─ Public API Fallback (Blockchain.com, etc)  │   │
│  │                                                   │   │
│  │ Transaction Broadcasting                         │   │
│  │  ├─ Mempool Monitoring                          │   │
│  │  ├─ Fee Estimation                              │   │
│  │  └─ Confirmation Tracking                       │   │
│  │                                                   │   │
│  │ UTXO Management                                  │   │
│  │  ├─ Balance Tracking                            │   │
│  │  ├─ Address Indexing                            │   │
│  │  └─ Unspent Output Discovery                    │   │
│  └──────────────────────────────────────────────────┘   │
└────────────────┬────────────────────────────────────────┘
                 │
┌────────────────▼────────────────────────────────────────┐
│        PERSISTENT STORAGE LAYER (DATABASE)             │
│  ┌──────────────────────────────────────────────────┐   │
│  │ • Encrypted Private Keys                         │   │
│  │ • Public Key Information                         │   │
│  │ • Transaction History                           │   │
│  │ • Address Metadata                              │   │
│  │ • Settings & Preferences                        │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## 2. Key Components Detail

### 2.1 Wallet Core Module

```python
class HybridBitcoinWallet:
    """
    Main wallet class managing all operations
    """
    def __init__(self, config: WalletConfig):
        self.bip39_manager = BIP39Manager()           # Seed management
        self.hd_wallet = HDWalletManager()            # BIP32/44 derivation
        self.ecdsa_module = ECDSAModule()             # Traditional crypto
        self.pqc_module = PQCModule()                 # Post-quantum crypto
        self.key_store = SecureKeyStore()             # Encrypted storage
        self.tx_builder = TransactionBuilder()        # Build transactions
        self.bitcoin_interface = BitcoinNodeInterface() # Network layer
        self.db = WalletDatabase()                    # Persistent storage
    
    # Core operations
    def create_wallet(self) -> Wallet:
        """Create new wallet with BIP39 seed"""
        pass
    
    def restore_wallet(self, seed_phrase: str) -> Wallet:
        """Restore wallet from seed phrase"""
        pass
    
    def generate_address(self, address_type: str) -> Address:
        """Generate new address (legacy, hybrid, etc)"""
        pass
    
    def get_balance(self) -> Balance:
        """Get wallet balance from UTXO set"""
        pass
    
    def send_transaction(self, tx_info: TransactionInfo) -> TransactionHash:
        """Create, sign, and broadcast transaction"""
        pass
```

### 2.2 Hybrid Key Structure

```python
from dataclasses import dataclass
from typing import Optional
import time

@dataclass
class HybridPublicKey:
    """Combined ECDSA + PQC public key"""
    # ECDSA component
    ecdsa_pubkey: bytes          # 33 bytes (compressed secp256k1)
    
    # Post-Quantum component
    pqc_algorithm: str           # "dilithium-3" or similar
    pqc_pubkey: bytes            # Variable size (~1,312 bytes for Dilithium)
    
    # Metadata
    key_id: str                  # Unique identifier
    derivation_path: str         # BIP44 path (e.g., "m/44'/0'/0'/hybrid/0")
    created_at: int              # Timestamp
    version: int                 # Key format version
    
    def serialize(self) -> bytes:
        """Serialize public key for storage/transmission"""
        # Format: [version][ecdsa_key][pqc_algo_len][pqc_algo][pqc_key][timestamp]
        pass
    
    @staticmethod
    def deserialize(data: bytes) -> 'HybridPublicKey':
        """Deserialize from bytes"""
        pass

@dataclass
class HybridPrivateKey:
    """Combined ECDSA + PQC private key"""
    # ECDSA component
    ecdsa_privkey: bytes         # 32 bytes
    
    # Post-Quantum component  
    pqc_privkey: bytes           # Variable size (~2,544 bytes for Dilithium)
    
    # Associated public key
    public_key: HybridPublicKey
    
    # Security metadata
    key_id: str
    created_at: int
    last_used: Optional[int]
    use_count: int
```

### 2.3 Transaction Signing Pipeline

```python
class HybridSigningPipeline:
    """
    Multi-stage transaction signing process
    """
    
    def sign_transaction(
        self,
        tx_data: bytes,
        hybrid_key: HybridPrivateKey
    ) -> HybridSignature:
        """
        Sign transaction with both ECDSA and Dilithium
        """
        # Stage 1: Hash transaction
        tx_hash = self._hash_transaction(tx_data)
        
        # Stage 2: ECDSA signature (for backward compatibility)
        ecdsa_sig = self._sign_ecdsa(
            tx_hash,
            hybrid_key.ecdsa_privkey
        )
        
        # Stage 3: Dilithium signature (for quantum resistance)
        dilithium_sig = self._sign_dilithium(
            tx_hash,
            hybrid_key.pqc_privkey
        )
        
        # Stage 4: Combine signatures
        combined_sig = HybridSignature(
            ecdsa_signature=ecdsa_sig,
            pqc_signature=dilithium_sig,
            public_key=hybrid_key.public_key,
            timestamp=int(time.time())
        )
        
        return combined_sig
    
    def verify_hybrid_signature(
        self,
        tx_data: bytes,
        signature: HybridSignature
    ) -> bool:
        """
        Verify both ECDSA and PQC signatures
        Both must verify successfully
        """
        tx_hash = self._hash_transaction(tx_data)
        
        # Verify ECDSA
        ecdsa_valid = self._verify_ecdsa(
            tx_hash,
            signature.ecdsa_signature,
            signature.public_key.ecdsa_pubkey
        )
        
        # Verify Dilithium
        pqc_valid = self._verify_pqc(
            tx_hash,
            signature.pqc_signature,
            signature.public_key.pqc_pubkey
        )
        
        # Both must be valid
        return ecdsa_valid and pqc_valid
```

### 2.4 HD Wallet Derivation

```python
class HybridHDWallet:
    """
    Hierarchical Deterministic wallet supporting hybrid keys
    """
    
    # Updated BIP44 paths for hybrid
    BIP44_ECDSA_PATH = "m/44'/0'/0'/0/{index}"      # Legacy
    BIP44_HYBRID_PATH = "m/44'/0'/0'/hybrid/{index}" # Hybrid
    BIP44_PQC_PATH = "m/44'/0'/0'/pqc/{index}"     # Future PQC-only
    
    def derive_hybrid_keypair(
        self,
        account: int,
        index: int
    ) -> HybridPublicKey:
        """
        Derive both ECDSA and PQC keys from same seed
        """
        # Derive ECDSA key via BIP32
        ecdsa_path = f"m/44'/0'/0'/0/{index}"
        ecdsa_key = self._derive_bip32_key(ecdsa_path)
        
        # Derive PQC key from seed
        pqc_seed = self._derive_pqc_seed()
        pqc_key = self._derive_pqc_key(pqc_seed, index)
        
        # Combine into hybrid key
        hybrid_key = HybridPublicKey(
            ecdsa_pubkey=ecdsa_key.public_key,
            pqc_pubkey=pqc_key.public_key,
            key_id=self._generate_key_id(),
            derivation_path=f"hybrid/{account}/{index}",
            created_at=int(time.time()),
            version=1
        )
        
        return hybrid_key
    
    def _derive_pqc_seed(self) -> bytes:
        """
        Derive PQC-specific seed from BIP39 master seed
        Uses HMAC-SHA512 with domain separation
        """
        master_seed = self.bip39_manager.get_master_seed()
        pqc_seed = hmac.new(
            b"Bitcoin PQC seed",
            master_seed,
            hashlib.sha512
        ).digest()
        return pqc_seed
```

## 3. Data Flow Diagrams

### 3.1 Wallet Creation Flow

```
┌─ User generates new wallet
│
├─ BIP39Manager generates 12/24 word seed phrase
│  └─ Validates against BIP39 word list
│
├─ Derive master key from seed
│  ├─ BIP32: HMAC-SHA512("Bitcoin seed", seed)
│  └─ PQC: HMAC-SHA512("Bitcoin PQC seed", seed)
│
├─ Generate initial address set
│  ├─ ECDSA key (legacy): m/44'/0'/0'/0/0
│  └─ Hybrid key (PQC): m/44'/0'/0'/hybrid/0
│
├─ Encrypt and store keys
│  ├─ Master seed → PBKDF2 encryption key
│  └─ Store in encrypted database
│
└─ Display seed phrase to user
   └─ User backs up seed phrase
```

### 3.2 Transaction Signing Flow

```
User initiates send transaction
│
├─ Input Selection
│  ├─ Gather available UTXOs
│  ├─ Select UTXOs matching amount
│  └─ Calculate change
│
├─ Create unsigned transaction
│  ├─ Serialize inputs (previous TX, index)
│  ├─ Serialize outputs (address, amount)
│  └─ Set locktime
│
├─ Hash transaction
│  └─ SHA256(SHA256(tx_serialized))
│
├─ Retrieve private keys
│  ├─ Decrypt from key store
│  ├─ Validate key ownership
│  └─ Get hybrid keypair
│
├─ Sign with both algorithms
│  ├─ ECDSA sign (secp256k1)
│  ├─ Dilithium sign (ML-DSA)
│  └─ Combine signatures
│
├─ Create scriptSig/witness
│  ├─ Insert signatures
│  ├─ Insert public keys
│  └─ Build complete script
│
├─ Verify signatures
│  ├─ Self-verify before broadcast
│  └─ Check script execution
│
└─ Broadcast transaction
   ├─ Send to Bitcoin network
   ├─ Monitor mempool
   └─ Track confirmations
```

## 4. API Specifications

### 4.1 Wallet API

```python
class WalletAPI:
    """Public API for wallet operations"""
    
    # Wallet Management
    def create_wallet(self, password: str, language: str = "english") -> Wallet:
        """Create new wallet"""
    
    def restore_wallet(self, seed_phrase: str, password: str) -> Wallet:
        """Restore from seed phrase"""
    
    def export_seed_phrase(self, password: str) -> str:
        """Export seed phrase (after password verification)"""
    
    # Address Management
    def generate_address(
        self,
        address_type: str = "hybrid",  # "legacy", "hybrid", "pqc"
        account: int = 0
    ) -> Address:
        """Generate new address"""
    
    def get_addresses(
        self,
        account: int = 0,
        limit: int = 10
    ) -> List[Address]:
        """Get addresses for account"""
    
    # Transaction Operations
    def get_balance(self) -> Balance:
        """Get total wallet balance"""
    
    def send(
        self,
        to_address: str,
        amount: int,  # satoshis
        fee_rate: Optional[int] = None,  # sat/vB
        password: Optional[str] = None
    ) -> TransactionHash:
        """Send transaction"""
    
    def get_transaction_history(
        self,
        limit: int = 50,
        offset: int = 0
    ) -> List[Transaction]:
        """Get transaction history"""
```

## 5. Security Requirements Document

### 5.1 Threat Model

**Threats Addressed:**
- Quantum computers (future)
- Private key theft
- Signature forgery
- Transaction tampering
- Seed phrase exposure
- Side-channel attacks

### 5.2 Security Controls

**Key Storage:**
- Fernet encryption (AES-128-CBC)
- PBKDF2 key derivation (100,000 iterations)
- In-memory key protection
- Secure random number generation

**Cryptographic:**
- ECDSA (secp256k1) - proven secure
- Dilithium (ML-DSA) - NIST-standardized PQC
- SHA-256 for hashing
- HMAC-SHA512 for key derivation

**Authentication:**
- Password protection with entropy check
- Seed phrase validation
- Multi-factor recovery (seed + password)

## 6. File Organization

```
src/
├── wallet/
│   ├── __init__.py
│   ├── wallet.py              # Main HybridBitcoinWallet class
│   ├── hd_wallet.py          # BIP32/44 derivation
│   └── config.py             # Wallet configuration
├── crypto/
│   ├── __init__.py
│   ├── ecdsa_module.py       # secp256k1 wrapper
│   ├── pqc_module.py         # PQC algorithms (Dilithium, Kyber)
│   └── hash.py               # SHA-256, HMAC utilities
├── transaction/
│   ├── __init__.py
│   ├── builder.py            # Transaction building
│   ├── signer.py             # Hybrid signing
│   └── validator.py          # Script validation
├── keys/
│   ├── __init__.py
│   ├── key_store.py          # Encrypted key storage
│   ├── recovery.py           # Backup/recovery
│   └── hybrid_key.py         # HybridPublicKey/PrivateKey classes
├── bitcoin/
│   ├── __init__.py
│   ├── node.py               # Bitcoin Core interface
│   ├── rpc.py                # RPC client
│   └── spv.py                # SPV implementation
└── database/
    ├── __init__.py
    └── wallet_db.py          # SQLite wallet database
```

---
**Status:** Design Phase  
**Last Updated:** 2026-08-29  
**Next:** Implementation Planning
