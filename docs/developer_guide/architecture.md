# Architecture Overview

The project keeps a clear separation between cryptographic primitives, wallet logic, and Bitcoin serialization behavior.

## Core layers

### 1. PQC layer
Location: `src/pqc/core.py`

This layer exposes:

- `DilithiumSigner` for ML-DSA signatures
- `KyberKEM` for ML-KEM encapsulation
- `PQCModule` as a convenience facade

It handles backend loading and validates key and signature lengths before use.

### 2. ECDSA compatibility layer
Location: `src/crypto/ecdsa_module.py`

This module provides secp256k1-specific operations that match the Bitcoin ecosystem's expectations, including deterministic signing.

### 3. Hybrid wallet
Location: `src/hybrid/hybrid_wallet.py`

`HybridWallet` coordinates ECC and PQC operations and verifies both signatures before accepting a result. It keeps in-memory key material and exposes public metadata for callers.

### 4. Bitcoin transaction layer
Location: `src/bitcoin/integration.py`

This module builds deterministic transaction bytes, encodes compact-size values, and provides helpers for scripts and fee estimation. It intentionally refuses to broadcast transactions without an explicit node integration layer.

### 5. Key store
Location: `src/key_management/key_store.py`

Encrypted key storage protects recovery data and allows the wallet to persist keys across sessions without exposing raw material in plain text.

## Data flow

1. A caller requests a hybrid keypair from `HybridWallet`
2. The wallet generates ECC and PQC material
3. The wallet stores key material in memory
4. Transaction bytes are hashed and signed with both algorithms
5. Verification requires both signatures to validate
6. The signed payload can be serialized and handed to an external RPC or wallet integration layer

## Design principles

- Fail closed when cryptographic backends are unavailable
- Prefer explicit validation over silent fallback
- Keep algorithm logic isolated from Bitcoin transaction logic
- Preserve backward compatibility while preparing for PQC migration
