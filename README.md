# Bitcoin Wallet Post-Quantum Migration

A hybrid Bitcoin wallet prototype that combines a Bitcoin-compatible secp256k1 ECDSA layer with NIST-standardized post-quantum cryptography to provide a practical migration path for quantum-resistant wallet operations.

Status: Beta-ready
Current phase: Documentation and beta release preparation complete

## Overview

This project demonstrates a migration strategy for Bitcoin wallets that must stay compatible with existing systems while moving toward post-quantum cryptographic protections. The implementation includes:

- secp256k1 ECDSA for Bitcoin-compatible signing
- ML-DSA (Dilithium) for quantum-resistant signatures
- ML-KEM (Kyber) for KEM-based flows
- encrypted key storage for wallet persistence
- deterministic transaction serialization helpers

The project is designed as a research, prototype, and validation framework rather than a production network broadcaster.

## Key goals

- Provide a hybrid wallet model that preserves Bitcoin compatibility
- Demonstrate a migration path from legacy ECC to PQC
- Validate deterministic transaction behavior and signature workflows
- Ship a documentation set covering setup, usage, architecture, and security
- Prepare the repository for controlled beta use

## Repository layout

```text
bitcoin-wallet-post-quantum-migration/
├── src/
│   ├── pqc/
│   │   └── core.py
│   ├── crypto/
│   │   └── ecdsa_module.py
│   ├── hybrid/
│   │   └── hybrid_wallet.py
│   ├── bitcoin/
│   │   └── integration.py
│   └── key_management/
│       └── key_store.py
├── tests/
│   ├── test_pqc_core.py
│   ├── test_hybrid_wallet.py
│   ├── test_bitcoin_integration.py
│   ├── test_integration.py
│   └── test_performance.py
├── docs/
│   ├── api/
│   ├── design/
│   ├── research/
│   ├── security/
│   ├── user_guide/
│   └── developer_guide/
├── poc/
├── requirements.txt
├── CONTRIBUTING.md
├── ROADMAP.md
├── RELEASE_NOTES.md
├── BETA_RELEASE_CHECKLIST.md
├── SECURITY_SIGNOFF.md
├── PHASE3_COMPLETION_SUMMARY.md
├── PHASE4_COMPLETION_SUMMARY.md
├── LICENSE
└── README.md
```

## Installation

```bash
git clone https://github.com/Balancebreaker-13/bitcoin-wallet-post-quantum-migration.git
cd bitcoin-wallet-post-quantum-migration
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If the liboqs backend is not available, install the native liboqs runtime and Python bindings required by the PQC adapters before continuing.

## Quickstart

```python
from src.hybrid import HybridWallet
from src.bitcoin.integration import (
    BitcoinTransactionBuilder,
    TransactionInput,
    TransactionOutput,
)

wallet = HybridWallet()
public_key = wallet.generate_hybrid_keypair()

builder = BitcoinTransactionBuilder(wallet)
tx = builder.create_transaction(
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

signature = builder.sign_transaction(tx, public_key.key_id)
verified = builder.verify_transaction_signature(tx, signature, public_key.key_id)

print("key_id:", public_key.key_id)
print("signature_valid:", verified)
```

## Tests

Run the full suite:

```bash
pytest -q
```

Run focused suites:

```bash
pytest tests/test_pqc_core.py -q
pytest tests/test_hybrid_wallet.py -q
pytest tests/test_bitcoin_integration.py -q
pytest tests/test_integration.py -q
pytest tests/test_performance.py -q
```

## Security model

This project intentionally follows a fail-closed security model.

Important behavior:
- missing PQC backend support raises explicit errors
- wallet verification requires both signatures to validate
- transaction broadcasting is intentionally not implemented in the core wallet library
- key storage uses encrypted persistence and separation of private material from public metadata

The project includes a documented security review in `docs/security/audit_report.md`.

## Documentation

User guides:
- `docs/user_guide/getting_started.md`
- `docs/user_guide/creating_wallet.md`
- `docs/user_guide/key_management.md`
- `docs/user_guide/transaction_signing.md`

Developer guides:
- `docs/developer_guide/setup.md`
- `docs/developer_guide/architecture.md`
- `docs/developer_guide/contributing.md`
- `docs/developer_guide/testing.md`

Project planning:
- `ROADMAP.md`
- `PHASE3_COMPLETION_SUMMARY.md`
- `PHASE4_COMPLETION_SUMMARY.md`

Release and security:
- `RELEASE_NOTES.md`
- `BETA_RELEASE_CHECKLIST.md`
- `SECURITY_SIGNOFF.md`

## Current status

The project has completed:
- Phase 1: research and analysis
- Phase 2: design and planning
- Phase 3: core implementation
- Phase 4: testing and validation
- Phase 5: documentation and release preparation

The repository is now ready for a controlled beta rollout with documented operational safeguards.

## Known limitations

- Broadcasting to the Bitcoin network remains intentionally unimplemented
- PQC signatures are larger than legacy ECDSA signatures
- Real-world deployment requires an explicit node/RPC integration boundary
- Additional operational and production hardening should occur before broad public release

## Contributing

Please see `CONTRIBUTING.md` for contribution guidelines.

## License

This project is licensed under the Apache License 2.0. See `LICENSE` for details.

## References

- NIST PQC Project
- ML-DSA (FIPS 204)
- ML-KEM (FIPS 203)
- Bitcoin BIPs
- liboqs Documentation

## Maintainer

Balancebreaker-13
