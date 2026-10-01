# Transaction Signing

The `BitcoinTransactionBuilder` uses the wallet to sign transaction bytes using a hybrid signature: ECDSA + ML-DSA.

## Create a transaction

```python
from src.hybrid import HybridWallet
from src.bitcoin.integration import BitcoinTransactionBuilder, TransactionInput, TransactionOutput

wallet = HybridWallet()
public_key = wallet.generate_hybrid_keypair()

builder = BitcoinTransactionBuilder(wallet)
raw_tx = builder.create_transaction(
    [
        TransactionInput(
            previous_tx_hash=bytes(32),
            previous_output_index=0,
            script_pubkey=b"\x51",
        )
    ],
    [
        TransactionOutput(value=50_000, script_pubkey=b"\x51")
    ],
)
```

## Sign and verify

```python
signature = builder.sign_transaction(raw_tx, public_key.key_id)
verified = builder.verify_transaction_signature(raw_tx, signature, public_key.key_id)
assert verified is True
```

## Transaction digest

`BitcoinTransactionBuilder.transaction_digest(tx_data)` computes the standard double-SHA256 transaction hash before hybrid signing.

```python
from src.bitcoin.integration import BitcoinTransactionBuilder

digest = BitcoinTransactionBuilder.transaction_digest(raw_tx)
print(digest.hex())
```

## Hybrid signature format

The hybrid signature is stored as a versioned byte stream:

```text
[version: 1 byte][ecc_signature_length: 2 bytes][ecc_signature][pqc_signature_length: 2 bytes][pqc_signature]
```

This ensures both signatures are carried together and validated together.

## Security note

This repository intentionally does not broadcast transactions to the Bitcoin network from the wallet code. Broadcasting requires an explicit node/RPC integration boundary.

## Related docs

- `creating_wallet.md`
- `getting_started.md`
- `docs/security/audit_report.md`
