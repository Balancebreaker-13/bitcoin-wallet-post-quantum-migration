# Bitcoin Wallet Post-Quantum Migration

A research and prototyping project for exploring Bitcoin-compatible wallet
primitives alongside post-quantum cryptography.

**Status: research prototype. It is not ready for beta deployment, mainnet use,
or handling real funds.**

## Implemented

- secp256k1 ECDSA and BIP340 Schnorr operations
- BIP341 key tweaks, TapLeaf/TapBranch hashing, control-block verification,
  sighash construction, and witness helpers
- Hybrid wallet envelopes using ML-DSA alongside the legacy signature path
- Encrypted key storage and deterministic transaction serialization
- Opt-in, cookie-authenticated Bitcoin Core JSON-RPC with chain and mempool
  checks before explicit broadcast

The hybrid ML-DSA envelope is **not** a Bitcoin consensus script. The RPC
client has only been tested with mocked node responses; no live regtest
verification has been completed.

## Validation and open requirements

The latest full test run passed 55 tests and skipped 1 backend-dependent test,
with 80% statement coverage on Python 3.13.11. The wallet benchmark harness is
repeatable but requires a working native liboqs backend; no representative
deployment-hardware performance result is claimed.

Before any beta or production use, the project still needs live Bitcoin Core
regtest validation, authoritative BIP341 sighash-vector cross-checking, a
consensus-compatible post-quantum spending design, full Tapscript integration,
and independent cryptographic and side-channel review. See
[`ROADMAP.md`](ROADMAP.md) and
[`docs/security/audit_report.md`](docs/security/audit_report.md).

## Development

Run the test suite from this directory:

```bash
python -m pytest -q tests
python -m pytest --cov=src --cov-report=term-missing -q tests
```

Run the cryptography and key-store microbenchmarks after confirming the real
native liboqs backend is available:

```bash
python benchmarks/benchmark_wallet.py
```

See [`docs/api/bitcoin_integration.md`](docs/api/bitcoin_integration.md) for
the transaction, Taproot, and RPC interfaces.