# Hybrid Wallet API

## Overview

The HybridWallet coordinates ECDSA (secp256k1) and ML-DSA (Dilithium) signatures for backward-compatible post-quantum Bitcoin wallets.

## Module Structure

```python
from src.hybrid.hybrid_wallet import (
    HybridWallet,
    HybridPublicKey,
    HybridPrivateKey,
    HybridSignature,
)
```

## HybridWallet

Main wallet class coordinating hybrid signing.

### Initialization

```python
from src.hybrid import HybridWallet
from src.pqc.core import DilithiumSigner
from src.crypto.ecdsa_module import ECDSAModule

# With defaults
wallet = HybridWallet()

# With custom components
wallet = HybridWallet(
    pqc_signer=DilithiumSigner(security_level=3),
    ecdsa=ECDSAModule(),
    clock=time.time  # For testing
)
```

### Keypair Generation

```python
public_key = wallet.generate_hybrid_keypair()

# Returns: HybridPublicKey
# public_key.ecc_pubkey: 33 bytes (compressed secp256k1)
# public_key.pqc_pubkey: 1952 bytes (ML-DSA-65)
# public_key.key_id: str (SHA256 hash)
# public_key.created_at: int (Unix timestamp)
# public_key.pqc_algorithm: str ("ML-DSA-65")
```

### Key Retrieval

```python
# Get public key
public_key = wallet.get_public_key(key_id)

# Get private key
private_key = wallet.get_private_key(key_id)

# List all stored public keys
for key_id, pubkey in wallet.public_keys.items():
    print(f"Key {key_id}: {pubkey.created_at}")
```

### Transaction Signing

```python
tx_data = b"Bitcoin transaction bytes"

# Sign transaction
signature = wallet.sign_transaction_hybrid(tx_data, key_id)

# Returns: bytes
# Format: [version:1][ecc_len:2][ecc_sig][pqc_len:2][pqc_sig]
# Typical size: ~3500 bytes for ML-DSA-65 + ECDSA
```

### Signature Verification

```python
# Verify hybrid signature
is_valid = wallet.verify_transaction_hybrid(
    tx_data,
    signature,
    public_key
)

# Returns: bool (True only if BOTH signatures verify)
```

### Key Management

```python
# Remove key
removed = wallet.remove_key(key_id)

# Alias for transaction signing (shorthand)
signature = wallet.sign(tx_data, key_id)

# Alias for transaction verification (shorthand)
is_valid = wallet.verify(tx_data, signature, public_key)
```

## HybridPublicKey

Immutable public key dataclass.

### Properties

```python
public_key = wallet.generate_hybrid_keypair()

print(public_key.ecc_pubkey)      # bytes (33)
print(public_key.pqc_pubkey)      # bytes (1952)
print(public_key.key_id)          # str
print(public_key.created_at)      # int
print(public_key.pqc_algorithm)   # str
```

### Serialization

```python
# Serialize to dictionary
key_dict = public_key.to_dict()
# {
#     'version': 1,
#     'ecc_pubkey': 'hex-encoded-string',
#     'pqc_pubkey': 'hex-encoded-string',
#     'key_id': 'string-id',
#     'created_at': timestamp,
#     'pqc_algorithm': 'ML-DSA-65'
# }

# Deserialize from dictionary
restored = HybridPublicKey.from_dict(key_dict)
assert restored == public_key
```

## HybridPrivateKey

Immutable private key dataclass.

### Properties

```python
private_key = wallet.get_private_key(key_id)

print(private_key.ecc_privkey)    # bytes (32)
print(private_key.pqc_privkey)    # bytes (4032)
print(private_key.key_id)         # str
print(private_key.created_at)     # int
print(private_key.pqc_algorithm)  # str
```

### Serialization

```python
# Serialize to dictionary (for encrypted storage)
key_dict = private_key.to_dict()

# Deserialize
restored = HybridPrivateKey.from_dict(key_dict)
assert restored == private_key
```

## HybridSignature

Decoded hybrid signature with version and components.

### Properties

```python
from src.hybrid import HybridWallet

signature_bytes = wallet.sign_transaction_hybrid(tx_data, key_id)
decoded = HybridWallet.decode_signature(signature_bytes)

print(decoded.version)         # int (1)
print(decoded.ecc_signature)   # bytes (~71)
print(decoded.pqc_signature)   # bytes (~3309)
```

### Re-encoding

```python
# Re-encode decoded signature
encoded = decoded.encode()
assert encoded == signature_bytes
```

## Static Methods

### Signature Encoding

```python
# Manually encode two signatures
ecc_sig = b"..."  # ~71 bytes
pqc_sig = b"..."  # ~3309 bytes

encoded = HybridWallet.encode_signature(
    ecc_sig,
    pqc_sig,
    version=1
)
# Format: [version:1][ecc_len:2][ecc_sig][pqc_len:2][pqc_sig]
```

### Signature Decoding

```python
# Manually decode signature
hybrid_sig = HybridWallet.decode_signature(encoded)

# Returns: HybridSignature with strict validation
# Raises: ValueError if truncated or malformed
```

## Error Handling

```python
try:
    wallet.sign_transaction_hybrid(tx_data, "unknown-key-id")
except KeyError:
    print("Key not found in wallet")

try:
    HybridWallet.decode_signature(b"truncated")
except ValueError as e:
    print(f"Invalid signature format: {e}")
```

## Usage Examples

### Complete Workflow

```python
from src.hybrid import HybridWallet
import json

# Create wallet
wallet = HybridWallet()

# Generate keypair
public_key = wallet.generate_hybrid_keypair()
print(f"Generated key: {public_key.key_id}")

# Sign transaction
tx_data = b"Bitcoin transaction data"
signature = wallet.sign_transaction_hybrid(tx_data, public_key.key_id)
print(f"Signature size: {len(signature)} bytes")

# Verify signature
is_valid = wallet.verify_transaction_hybrid(tx_data, signature, public_key)
print(f"Signature valid: {is_valid}")

# Store keys securely
from src.key_management import SecureKeyStore

key_store = SecureKeyStore(master_password="secure-password")
key_store.store_hybrid_key(public_key.key_id, private_key.to_dict())
```

### Signature Size Analysis

```python
from src.hybrid import HybridWallet

wallet = HybridWallet()
public_key = wallet.generate_hybrid_keypair()

# Size breakdown
signature = wallet.sign_transaction_hybrid(b"test", public_key.key_id)
decoded = HybridWallet.decode_signature(signature)

print(f"Version: 1 byte")
print(f"ECC sig length field: 2 bytes")
print(f"ECC signature: {len(decoded.ecc_signature)} bytes")
print(f"PQC sig length field: 2 bytes")
print(f"PQC signature: {len(decoded.pqc_signature)} bytes")
print(f"Total: {len(signature)} bytes")
```

## Security Considerations

1. **Private Keys**: Store HybridPrivateKey objects only in encrypted storage
2. **Signature Verification**: Always verify BOTH ECC and PQC signatures
3. **Key Rotation**: Use key_id for tracking key age and rotation
4. **Backward Compatibility**: ECC signature allows validation by legacy systems
5. **Future-Proofing**: PQC signature protects against quantum threats

## Performance Characteristics

- **Key Generation**: ~5-10ms per hybrid keypair
- **Signing**: ~10-20ms per transaction
- **Verification**: ~10-20ms per transaction
- **Signature Size**: ~3500 bytes (35x larger than ECDSA alone)

## References

- [Hybrid Cryptography](../design/architecture.md)
- [Bitcoin Integration](bitcoin_integration.md)
- [Key Management](key_management.md)
