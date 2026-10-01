# Key Management

The project includes an encrypted key store for retaining hybrid keys outside of the in-memory wallet state.

## SecureKeyStore usage

```python
from pathlib import Path
from src.key_management import SecureKeyStore
from src.hybrid import HybridWallet

wallet = HybridWallet()
public_key = wallet.generate_hybrid_keypair()
private_key = wallet.get_private_key(public_key.key_id)

key_file = Path('wallet_keys.json')
store = SecureKeyStore(master_password='strong-master-password', keys_file=str(key_file))

store.store_hybrid_key(
    public_key.key_id,
    {
        'public': public_key.to_dict(),
        'private': private_key.to_dict(),
    },
)

retrieved = store.retrieve_hybrid_key(public_key.key_id)
assert retrieved is not None
print(retrieved['public']['key_id'])
```

## What is protected

`SecureKeyStore` uses:

- PBKDF2 key derivation
- Fernet authenticated encryption
- a separate encrypted JSON store for key material

## Listing keys

```python
key_ids = store.list_key_ids()
print(key_ids)
```

## Delete keys

```python
store.delete_key(public_key.key_id)
assert store.retrieve_hybrid_key(public_key.key_id) is None
```

## Operational guidance

- Use a strong master password
- Keep the key file on an encrypted filesystem or device
- Back up the key file and master password separately
- Verify permissions on the key file at the OS level

## Related docs

- `creating_wallet.md`
- `transaction_signing.md`
- `docs/security/audit_report.md`
