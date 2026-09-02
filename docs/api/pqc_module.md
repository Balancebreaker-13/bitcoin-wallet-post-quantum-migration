# Post-Quantum Cryptography Module API

## Overview

The PQC module provides NIST-standardized post-quantum cryptography algorithms wrapped around the liboqs library. It supports ML-DSA (Dilithium) for signatures and ML-KEM (Kyber) for key encapsulation.

## Module Structure

```python
from src.pqc.core import (
    DilithiumSigner,
    KyberKEM,
    PQCModule,
    PQCBackendUnavailable,
    PQCBackendError,
    backend_available,
)
```

## DilithiumSigner

ML-DSA (formerly Dilithium) post-quantum signature scheme.

### Initialization

```python
from src.pqc.core import DilithiumSigner

# Create signer with security level 3 (default)
signer = DilithiumSigner(security_level=3)

# Security levels: 2 (ML-DSA-44), 3 (ML-DSA-65), 5 (ML-DSA-87)
```

### Key Generation

```python
public_key, private_key = signer.generate_keypair()

# Returns:
# public_key: bytes (1952 bytes for level 3)
# private_key: bytes (4032 bytes for level 3)
```

### Message Signing

```python
message = b"Bitcoin transaction data"
signature = signer.sign(message, private_key)

# Returns:
# signature: bytes (3309 bytes for level 3)
```

### Signature Verification

```python
is_valid = signer.verify(message, signature, public_key)
# Returns: bool
```

### Key Sizes

```python
print(signer.key_sizes)
# Output:
# {
#     'pub': 1952,      # Public key size in bytes
#     'priv': 4032,     # Private key size in bytes
#     'sig': 3309       # Signature size in bytes
# }
```

## KyberKEM

ML-KEM (formerly Kyber) key encapsulation mechanism for post-quantum key exchange.

### Initialization

```python
from src.pqc.core import KyberKEM

# Create KEM with security level 768 (default)
kem = KyberKEM(security_level=768)

# Security levels: 512 (ML-KEM-512), 768 (ML-KEM-768), 1024 (ML-KEM-1024)
```

### Key Generation

```python
public_key, private_key = kem.generate_keypair()

# Returns:
# public_key: bytes (1184 bytes for level 768)
# private_key: bytes (2400 bytes for level 768)
```

### Encapsulation (Sender Side)

```python
ciphertext, shared_secret = kem.encapsulate(public_key)

# Returns:
# ciphertext: bytes (1088 bytes for level 768) - send to recipient
# shared_secret: bytes (32 bytes) - use for symmetric encryption
```

### Decapsulation (Recipient Side)

```python
recovered_secret = kem.decapsulate(ciphertext, private_key)

# Returns:
# recovered_secret: bytes (32 bytes) - matches shared_secret from sender
```

### Key Sizes

```python
print(kem.key_sizes)
# Output:
# {
#     'pub': 1184,      # Public key size in bytes
#     'priv': 2400,     # Private key size in bytes
#     'ct': 1088        # Ciphertext size in bytes
# }

print(kem.SHARED_SECRET_SIZE)  # 32 bytes
```

## PQCModule

Convenience facade combining DilithiumSigner and KyberKEM.

### Initialization

```python
from src.pqc.core import PQCModule

pqc = PQCModule(dilithium_level=3, kyber_level=768)
```

### Access Algorithms

```python
# Access individual components
signer = pqc.dilithium
kem = pqc.kyber

# Use as normal
pub, priv = signer.generate_keypair()
signature = signer.sign(message, priv)
```

### Algorithm Information

```python
info = pqc.get_algorithm_info()

print(info)
# Output:
# {
#     'backend': 'liboqs',
#     'dilithium': {
#         'name': 'ML-DSA-65',
#         'level': 3,
#         'pubkey_size': 1952,
#         'privkey_size': 4032,
#         'signature_size': 3309
#     },
#     'kyber': {
#         'name': 'ML-KEM-768',
#         'level': 768,
#         'pubkey_size': 1184,
#         'privkey_size': 2400,
#         'ciphertext_size': 1088,
#         'shared_secret_size': 32
#     }
# }
```

## Error Handling

### Backend Availability

```python
from src.pqc.core import backend_available, PQCBackendUnavailable

if backend_available():
    signer = DilithiumSigner()
else:
    raise RuntimeError("liboqs not available")
```

### Exception Types

```python
try:
    signer = DilithiumSigner(4)  # Invalid security level
except ValueError:
    print("Invalid security level")

try:
    pqc = DilithiumSigner()
except PQCBackendUnavailable as e:
    print(f"liboqs not available: {e}")

try:
    signature = signer.sign(message, wrong_key)
except PQCBackendError as e:
    print(f"Signing failed: {e}")
```

## Security Levels

### Dilithium (ML-DSA)

| Level | NIST Category | Algorithm | Public Key | Private Key | Signature |
|-------|---------------|-----------|------------|-------------|----------|
| 2 | 1 | ML-DSA-44 | 1312 | 2560 | 2420 |
| 3 | 3 | ML-DSA-65 | 1952 | 4032 | 3309 |
| 5 | 5 | ML-DSA-87 | 2592 | 4896 | 4627 |

### Kyber (ML-KEM)

| Level | NIST Category | Algorithm | Public Key | Private Key | Ciphertext |
|-------|---------------|-----------|------------|-------------|------------|
| 512 | 1 | ML-KEM-512 | 800 | 1632 | 768 |
| 768 | 3 | ML-KEM-768 | 1184 | 2400 | 1088 |
| 1024 | 5 | ML-KEM-1024 | 1568 | 3168 | 1568 |

## Usage Examples

### Complete Signing Workflow

```python
from src.pqc.core import DilithiumSigner

# Initialize
signer = DilithiumSigner(security_level=3)

# Generate keypair
pub_key, priv_key = signer.generate_keypair()

# Sign message
message = b"Important transaction"
signature = signer.sign(message, priv_key)

# Verify signature
if signer.verify(message, signature, pub_key):
    print("Signature valid!")
else:
    print("Signature invalid!")
```

### Complete KEM Workflow

```python
from src.pqc.core import KyberKEM

# Sender and recipient both have KyberKEM instance
sender_kem = KyberKEM(security_level=768)
recipient_kem = KyberKEM(security_level=768)

# Recipient generates keypair
recipient_pub, recipient_priv = recipient_kem.generate_keypair()

# Sender encapsulates shared secret
ciphertext, sender_secret = sender_kem.encapsulate(recipient_pub)

# Sender sends ciphertext to recipient
# Recipient decapsulates
recipient_secret = recipient_kem.decapsulate(ciphertext, recipient_priv)

# Both parties have the same shared secret
assert sender_secret == recipient_secret
```

## Performance Considerations

- **Key Generation**: ~1-2ms per keypair
- **Signing**: ~2-5ms per message
- **Verification**: ~2-5ms per signature
- **KEM Operations**: ~0.5-1ms per operation
- **Key Sizes**: 35x larger than traditional ECDSA (manageable for blockchain)

## References

- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography/)
- [ML-DSA Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- [ML-KEM Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [liboqs Documentation](https://liboqs.org/)
