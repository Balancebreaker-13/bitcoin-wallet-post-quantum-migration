# Key Management API

## Overview

The key management module provides secure storage and retrieval of hybrid cryptographic keys with encryption and recovery mechanisms.

## SecureKeyStore

Encrypted key storage with PBKDF2 key derivation.

### Initialization

```python
from src.key_management import SecureKeyStore

# Create or open key store
key_store = SecureKeyStore(
    master_password="my-secure-password",
    keys_file="keys.encrypted.json"  # Optional, defaults to shown
)
```

### Storing Keys

```python
from src.hybrid import HybridWallet

wallet = HybridWallet()
public_key = wallet.generate_hybrid_keypair()
private_key = wallet.get_private_key(public_key.key_id)

# Prepare key dictionary
key_data = {
    'public': public_key.to_dict(),
    'private': private_key.to_dict(),
    'backup': None  # For seed phrase in future
}

# Store encrypted key
success = key_store.store_hybrid_key(
    key_id=public_key.key_id,
    hybrid_key=key_data
)

assert success
```

### Retrieving Keys

```python
# Retrieve and decrypt key
key_data = key_store.retrieve_hybrid_key(key_id)

if key_data:
    public_key_dict = key_data['public']
    private_key_dict = key_data['private']
    
    # Reconstruct key objects
    from src.hybrid import HybridPublicKey, HybridPrivateKey
    
    public_key = HybridPublicKey.from_dict(public_key_dict)
    private_key = HybridPrivateKey.from_dict(private_key_dict)
else:
    print(f"Key {key_id} not found")
```

### Listing Keys

```python
# List all stored key IDs
key_ids = key_store.list_key_ids()

for key_id in key_ids:
    key_data = key_store.retrieve_hybrid_key(key_id)
    created_at = key_data['public']['created_at']
    print(f"Key {key_id}: created at {created_at}")
```

### Deleting Keys

```python
# Delete a key
success = key_store.delete_key(key_id)

if success:
    print(f"Key {key_id} deleted")
else:
    print(f"Could not delete key {key_id}")
```

## Usage Examples

### Complete Key Management Workflow

```python
from src.hybrid import HybridWallet, HybridPublicKey, HybridPrivateKey
from src.key_management import SecureKeyStore

# Initialize
wallet = HybridWallet()
key_store = SecureKeyStore(master_password="secure-password")

# Generate and store key
public_key = wallet.generate_hybrid_keypair()
private_key = wallet.get_private_key(public_key.key_id)

key_data = {
    'public': public_key.to_dict(),
    'private': private_key.to_dict(),
    'created_by': 'test-wallet',
    'version': 1
}

key_store.store_hybrid_key(public_key.key_id, key_data)
print(f"Stored key: {public_key.key_id}")

# Later: retrieve and use
retrieved = key_store.retrieve_hybrid_key(public_key.key_id)
public_key_restored = HybridPublicKey.from_dict(retrieved['public'])
private_key_restored = HybridPrivateKey.from_dict(retrieved['private'])

# Sign with restored key
tx_data = b"transaction"
signature = wallet.sign_transaction_hybrid(tx_data, public_key_restored.key_id)
print(f"Signature created: {len(signature)} bytes")
```

### Multiple Key Management

```python
from src.key_management import SecureKeyStore

key_store = SecureKeyStore(master_password="password")

# Store multiple keys
for i in range(3):
    public_key = wallet.generate_hybrid_keypair()
    private_key = wallet.get_private_key(public_key.key_id)
    
    key_data = {
        'public': public_key.to_dict(),
        'private': private_key.to_dict(),
        'purpose': f'transaction-{i}'
    }
    
    key_store.store_hybrid_key(public_key.key_id, key_data)

# List and work with all keys
for key_id in key_store.list_key_ids():
    key_data = key_store.retrieve_hybrid_key(key_id)
    purpose = key_data.get('purpose')
    print(f"Key: {key_id}, Purpose: {purpose}")
```

## Error Handling

```python
try:
    key_data = key_store.retrieve_hybrid_key("invalid-key-id")
    if key_data is None:
        print("Key not found")
except Exception as e:
    print(f"Error retrieving key: {e}")

try:
    success = key_store.store_hybrid_key(key_id, {})
    if not success:
        print("Failed to store key")
except Exception as e:
    print(f"Error storing key: {e}")
```

## Security Considerations

### Password Security

1. **Strong Password**: Use at least 16 characters with mixed case, numbers, symbols
2. **Unique Password**: Don't reuse passwords from other systems
3. **Secure Storage**: Consider using environment variables or secure key managers

### File Security

1. **Permissions**: Restrict `keys.encrypted.json` to user-only access (chmod 600)
2. **Backup**: Encrypt backups with the same master password
3. **Deletion**: Use secure deletion tools to remove old key files
4. **Location**: Store on encrypted filesystem when possible

### Key Rotation

```python
# Generate new key when old one expires
old_key_id = "old-key-id"
new_key = wallet.generate_hybrid_keypair()
new_private_key = wallet.get_private_key(new_key.key_id)

# Store new key
key_store.store_hybrid_key(
    new_key.key_id,
    {'public': new_key.to_dict(), 'private': new_private_key.to_dict()}
)

# Keep old key for verification of past signatures
# Delete only after confirmation period
key_store.delete_key(old_key_id)
```

## Implementation Details

### Encryption Scheme

- **KDF**: PBKDF2 with SHA256
- **Iterations**: 100,000
- **Key Length**: 32 bytes
- **Cipher**: Fernet (AES-128-CBC with HMAC)
- **Encoding**: Base64 (UTF-8)

### File Format

```json
{
  "key-id-1": {
    "version": 1,
    "algorithm": "ml-dsa-65+secp256k1",
    "encrypted": "base64-encoded-ciphertext"
  }
}
```

## Performance

- **Storage**: ~50ms per key
- **Retrieval**: ~50ms per key
- **Listing**: O(n) where n = number of keys
- **Deletion**: ~50ms per key

## References

- [PBKDF2 RFC 2898](https://tools.ietf.org/html/rfc2898)
- [Fernet (cryptography.io)](https://cryptography.io/en/latest/fernet/)
- [Key Derivation Functions](https://cryptography.io/en/latest/hazmat/primitives/kdf/)
