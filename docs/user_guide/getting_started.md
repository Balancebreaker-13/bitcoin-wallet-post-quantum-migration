# Getting Started

This guide shows the fastest path to running the hybrid Bitcoin wallet prototype and exercising the post-quantum wallet flow.

## Prerequisites

- Python 3.10+
- `pip`
- A local checkout of this repository
- Optional: `liboqs-python` and native liboqs runtime for PQC operations

## Install

```bash
git clone https://github.com/Balancebreaker-13/bitcoin-wallet-post-quantum-migration.git
cd bitcoin-wallet-post-quantum-migration
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Verify the environment

```bash
python -c "from src.pqc.core import backend_available; print('backend_available=', backend_available())"
python -c "from src.hybrid import HybridWallet; print(HybridWallet())"
```

If `backend_available()` is `False`, install the liboqs native backend before continuing.

## Quick wallet flow

```python
from src.hybrid import HybridWallet
from src.bitcoin.integration import BitcoinTransactionBuilder, TransactionInput, TransactionOutput

wallet = HybridWallet()
public_key = wallet.generate_hybrid_keypair()
private_key = wallet.get_private_key(public_key.key_id)

assert private_key is not None
assert public_key.key_id == private_key.key_id

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

signature = builder.sign_transaction(raw_tx, public_key.key_id)
print('signature length:', len(signature))
print('verified:', builder.verify_transaction_signature(raw_tx, signature, public_key.key_id))
```

## Run the tests

```bash
pytest tests/test_integration.py -q
pytest tests/test_performance.py -q
```

## Project layout

- `src/pqc/` contains ML-DSA and ML-KEM adapters
- `src/hybrid/` contains the hybrid wallet logic
- `src/crypto/` contains secp256k1 ECDSA support
- `src/bitcoin/` contains transaction serialization utilities
- `src/key_management/` contains encrypted key storage

## Next steps

- Review the wallet creation guide
- Review the transaction signing guide
- Review the security documentation in `docs/security/audit_report.md`
